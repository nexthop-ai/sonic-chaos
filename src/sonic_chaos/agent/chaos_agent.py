#!/usr/bin/env python3
"""sonic-chaos Squeeze agent -- the DUT-side half of the ``cpu`` and ``mem`` injectors.

Pushed to ``/tmp/sonic-chaos/chaos_agent.py`` and driven over ssh. Stdlib only, because the box
has python 3.13.5 and nothing else is guaranteed. Every command prints exactly one JSON object
on stdout, so the harness never parses prose.

    chaos_agent.py apply     --kind cpu --target orchagent --container swss --share 30 --ttl 900
    chaos_agent.py apply     --kind mem --target swss --container swss --steps 80,60,40 --period 20
    chaos_agent.py status    --kind cpu --target orchagent
    chaos_agent.py release   --kind cpu --target orchagent
    chaos_agent.py calibrate --share 30 --seconds 6

Why an agent at all, when ``docker update --cpus`` is one command
----------------------------------------------------------------
* **Nothing may outlive the session.** Every apply writes a deadline and spawns two independent
  dead-men -- a watcher loop, and a bare ``sleep N; release`` that needs no python to survive.
  A dropped ssh session, a killed pytest, or a crashed watcher all still leave the box clean.
  A throttled shared switch nobody remembers throttling is the worst thing this lane can produce.
* **The PID moves.** Spine's ``kill`` injector restarts swss: the old orchagent PID is gone and
  the new one is born outside our cgroup, silently un-throttled. The watcher re-resolves and
  re-attaches, and records that it had to -- so "the fault was applied" is never an assumption.
* **A number nobody measured is worthless.** The cgroup's own ``cpu.stat`` carries cumulative
  ``usage_usec`` plus ``nr_throttled``, so every result carries the share the daemon actually
  got and whether the cap ever bit. A cap that never bit means the fault was a no-op -- that has
  to be visible, not reported as a pass under pressure.

Release always **lifts the limit first** and moves processes second. If anything later in the
teardown fails, the box is already unthrottled.

Platform facts this relies on, measured on a lab switch (202511.2, kernel 6.12, 16 cores)
-----------------------------------------------------------------------------------------------
* cgroup **v2 unified**; docker cgroup driver ``systemd``; container cgroup is
  ``/sys/fs/cgroup/system.slice/docker-<id>.scope``.
* That scope is a **leaf with processes in it**, so cgroup v2's no-internal-processes rule
  forbids nesting under it. We create a *sibling* tree at ``/sys/fs/cgroup/sonic-chaos/<proc>/``.
* Root ``cgroup.subtree_control`` already lists ``cpu``, so the sibling needs no delegation setup.
"""
import argparse
import glob
import json
import os
import signal
import subprocess
import sys
import time

STATE_DIR = "/tmp/sonic-chaos"
LOG = os.path.join(STATE_DIR, "agent.log")

CG_ROOT = "/sys/fs/cgroup"
CG_BASE = os.path.join(CG_ROOT, "sonic-chaos")
PERIOD_US = 100000

# docker refuses a memory limit below 6 MiB; clamp rather than fail, and say we clamped.
DOCKER_MIN_MEM = 6 * 1024 * 1024

# Calibration passes when the measured share is within max(5 points, 20% relative) of the ask.
# CFS budget enforcement is good to a few percent; anything looser than this is not a measurement.
CALIB_ABS_TOLERANCE = 5.0
CALIB_REL_TOLERANCE = 0.20


class AgentError(Exception):
    """Something on the box refused. Reported as JSON with a non-zero exit."""


# ------------------------------------------------------------------------------ tiny fs helpers

def read(path, default=None):
    try:
        with open(path) as fh:
            return fh.read()
    except (IOError, OSError):
        return default


def try_write(path, text):
    """Write and swallow the error, returning it. cgroup writes fail for mundane reasons -- a
    process exited between the read and the write -- and none of them should abort a release."""
    try:
        with open(path, "w") as fh:
            fh.write(text)
        return None
    except (IOError, OSError) as err:
        return "{}: {}".format(path, err)


def write(path, text):
    err = try_write(path, text)
    if err:
        raise AgentError(err)


def run(argv, timeout=120):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as err:      # missing binary, timeout -- caller decides if it matters
        return 127, "", repr(err)


def docker(*args):
    return run(["docker"] + list(args))


def now():
    return time.time()


# ------------------------------------------------------------- container / cgroup / pid discovery

def container_id(name):
    rc, out, _ = docker("inspect", "-f", "{{.Id}}", name)
    return out if rc == 0 and out else None


def container_cgroup(name):
    """Absolute cgroup v2 path of a container, or None if it is not running.

    Re-resolved rather than cached: ``docker restart`` keeps the id but recreates the directory,
    and a recreated container changes the id outright.
    """
    cid = container_id(name)
    if not cid:
        return None
    for path in (os.path.join(CG_ROOT, "system.slice", "docker-{}.scope".format(cid)),
                 os.path.join(CG_ROOT, "docker", cid)):
        if os.path.isdir(path):
            return path
    for pattern in ("*{}*", "*/*{}*"):
        for hit in glob.glob(os.path.join(CG_ROOT, pattern.format(cid[:24]))):
            if os.path.isdir(hit):
                return hit
    return None


def cgroup_procs(cgroup):
    if not cgroup:
        return []
    return [int(line) for line in (read(os.path.join(cgroup, "cgroup.procs")) or "").split()
            if line.isdigit()]


def proc_cgroup(pid):
    """Where a pid lives now, as an absolute path -- recorded so release can put it back exactly."""
    for line in (read("/proc/{}/cgroup".format(pid)) or "").splitlines():
        if line.startswith("0::"):
            return os.path.join(CG_ROOT, line[3:].lstrip("/"))
    return None


def _is_process(pid, process):
    """``/proc/<pid>/comm`` first, argv[0] as the fallback.

    Deliberately not ``docker top ... | grep``: orchagent's argv ends in ``tcp://127.0.0.1``, so
    naive column matching picks up the wrong field. Every daemon in targets.yml fits inside
    comm's 15-character limit.
    """
    if (read("/proc/{}/comm".format(pid), "") or "").strip() == process:
        return True
    argv0 = (read("/proc/{}/cmdline".format(pid), "") or "").split("\0")[0]
    return bool(argv0) and os.path.basename(argv0) == process


def pids_for(process, container, also=()):
    """Host-side pids of ``process`` inside ``container``, plus any already in our own cgroups.

    Works off cgroup membership rather than ``docker top`` so a pid we have already moved into
    the sonic-chaos cgroup is still found -- it has left the container's scope by then.
    """
    found, seen = [], set()
    for cgroup in [container_cgroup(container)] + list(also):
        for pid in cgroup_procs(cgroup):
            if pid in seen:
                continue
            seen.add(pid)
            if _is_process(pid, process):
                found.append(pid)
    return sorted(found)


def ensure_controller(cgroup, controller="cpu"):
    """Enable a controller in a cgroup's subtree, so its children get the knob. None on success."""
    if controller not in (read(os.path.join(cgroup, "cgroup.controllers")) or "").split():
        return "{}: controller {!r} not available".format(cgroup, controller)
    path = os.path.join(cgroup, "cgroup.subtree_control")
    if controller in (read(path) or "").split():
        return None
    return try_write(path, "+" + controller)


def cgroup_v2():
    return os.path.isfile(os.path.join(CG_ROOT, "cgroup.controllers"))


def mkcgroup(path):
    """Create a cgroup. cgroupfs populates the new directory's interface files itself."""
    os.makedirs(path, exist_ok=True)
    return path


def rmcgroup(path):
    """Remove a cgroup. Interface files never block the rmdir -- a process still inside does."""
    os.rmdir(path)


# ------------------------------------------------------------------------------ counters

def cpu_stat(cgroup):
    """``usage_usec`` / ``nr_throttled`` / ``throttled_usec``. Empty dict when the cgroup is gone."""
    out = {}
    text = read(os.path.join(cgroup, "cpu.stat")) if cgroup else None
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("-").isdigit():
            out[parts[0]] = int(parts[1])
    return out


def mem_current(cgroup):
    text = (read(os.path.join(cgroup, "memory.current")) if cgroup else None) or ""
    return int(text.strip()) if text.strip().isdigit() else None


def mem_events(cgroup):
    """``oom_kill`` is the one that matters: with no swap a capped container is killed, not slowed,
    so an OOM kill must never be mistaken for graceful degradation under pressure."""
    out = {}
    for name in ("memory.events", "memory.events.local"):
        text = read(os.path.join(cgroup, name)) if cgroup else None
        for line in (text or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                out[parts[0]] = max(out.get(parts[0], 0), int(parts[1]))
    return out


# ------------------------------------------------------------------------------ state file

def state_path(kind, target):
    return os.path.join(STATE_DIR, "{}-{}.json".format(kind, target))


def released_flag(kind, target):
    """Touched by ``release``. The watcher checks it every tick, so an explicit release from the
    harness can never be clobbered by a sample the watcher was midway through writing."""
    return state_path(kind, target) + ".released"


def load_state(kind, target):
    try:
        with open(state_path(kind, target)) as fh:
            return json.load(fh)
    except (IOError, OSError, ValueError):
        return None


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    path = state_path(state["kind"], state["target"])
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)      # atomic: status never reads a half-written file


def emit(payload, rc=0):
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return rc


# ------------------------------------------------------------------------------ cpu

def cpu_attach(state):
    """Move every matching pid into our leaf cgroup. Idempotent: already-there pids are skipped.

    This is also the PID watcher's whole job -- after a swss restart the daemon is reborn in the
    container's own scope, and this is what drags it back under the cap.
    """
    leaf, moved, failed = state["cgroup"], [], []
    already = set(cgroup_procs(leaf))
    for pid in pids_for(state["target"], state["container"], also=[leaf]):
        if pid in already:
            continue
        origin = proc_cgroup(pid)
        err = try_write(os.path.join(leaf, "cgroup.procs"), str(pid))
        if err:
            failed.append([pid, err])
        else:
            moved.append(pid)
            if origin:
                state["origin"][str(pid)] = origin
    state["pids"] = sorted(cgroup_procs(leaf))
    return moved, failed


def cpu_apply(state):
    if state["how"] == "docker":
        rc, out, _ = docker("inspect", "-f", "{{.HostConfig.NanoCpus}}", state["container"])
        state["baseline_nanocpus"] = int(out) if rc == 0 and out.lstrip("-").isdigit() else 0
        cpus = "{:.3f}".format(state["share"] / 100.0)
        rc, _, err = docker("update", "--cpus=" + cpus, state["container"])
        if rc != 0:
            raise AgentError("docker update --cpus={} {}: {}".format(cpus, state["container"], err))
        state["accounting_cgroup"] = container_cgroup(state["container"])
        state["applied"] = {"cpus": cpus}
    else:
        if not cgroup_v2():
            raise AgentError("{} is not cgroup v2; Tier 1 needs unified hierarchy".format(CG_ROOT))
        mkcgroup(CG_BASE)
        for cgroup in (CG_ROOT, CG_BASE):
            err = ensure_controller(cgroup, "cpu")
            if err:
                raise AgentError("cannot enable cpu controller on {} -- {}".format(cgroup, err))
        scope = container_cgroup(state["container"])
        resident = cgroup_procs(scope)
        if resident and all(_is_process(pid, state["target"]) for pid in resident):
            # Moving a scope's *last* process out makes it empty, and systemd collects an empty
            # scope: `docker top` and `docker stats` then report nothing for a container that is
            # still running, and release has nowhere to put the pid back. Measured, not feared.
            # Never true for swss/syncd/bgp, which each run a supervisord and several daemons.
            raise AgentError(
                "cpu Tier 1 on {!r} would move every process out of container {!r} and systemd "
                "would collect the emptied scope. Use how=docker to throttle the whole "
                "container instead.".format(state["target"], state["container"]))
        mkcgroup(state["cgroup"])
        quota = "{} {}".format(state["quota_us"], PERIOD_US)
        write(os.path.join(state["cgroup"], "cpu.max"), quota)
        moved, failed = cpu_attach(state)
        if not state["pids"]:
            raise AgentError("no pid matched {!r} in container {!r}{}".format(
                state["target"], state["container"],
                " (writes failed: {})".format(failed) if failed else ""))
        state["accounting_cgroup"] = state["cgroup"]
        state["applied"] = {"cpu.max": quota, "moved": moved, "failed": failed}


def cpu_release(state):
    """Lift the cap first, unwind the cgroup second. Order is the safety property."""
    notes = []
    if state["how"] == "docker":
        baseline = state.get("baseline_nanocpus") or 0
        cpus = "{:.3f}".format(baseline / 1e9) if baseline else "0"
        rc, _, err = docker("update", "--cpus=" + cpus, state["container"])
        if rc != 0:
            notes.append("docker update --cpus={}: {}".format(cpus, err))
            # Authoritative fallback: the running container's own knob, regardless of what
            # docker's bookkeeping thinks. An unthrottled box matters more than a tidy record.
            scope = container_cgroup(state["container"])
            if scope:
                notes.append(try_write(os.path.join(scope, "cpu.max"),
                                       "max {}".format(PERIOD_US)) or "forced cpu.max=max")
    else:
        leaf = state["cgroup"]
        if os.path.isdir(leaf):
            # 1. unthrottle everything still inside, even if step 2 fails entirely
            err = try_write(os.path.join(leaf, "cpu.max"), "max {}".format(PERIOD_US))
            if err:
                notes.append(err)
            # 2. put each pid back where it came from
            scope = container_cgroup(state["container"])
            for pid in cgroup_procs(leaf):
                dest = state.get("origin", {}).get(str(pid)) or scope
                if not dest or not os.path.isdir(dest):
                    notes.append(
                        "pid {} left in {} -- cap already lifted, so it is NOT throttled, but its "
                        "container cgroup is gone (container recreated, or systemd collected an "
                        "emptied scope)".format(pid, leaf))
                    continue
                err = try_write(os.path.join(dest, "cgroup.procs"), str(pid))
                if err and os.path.exists("/proc/{}".format(pid)):
                    notes.append(err)
            # 3. tidy up; a pid that exited mid-move can hold the directory for a moment
            for _ in range(10):
                try:
                    rmcgroup(leaf)
                    break
                except OSError:
                    time.sleep(0.2)
            else:
                notes.append("{} not removed (still populated)".format(leaf))
        try:
            rmcgroup(CG_BASE)
        except OSError:
            pass          # other targets still throttled, or already gone
    return notes


def cpu_sample(state):
    """Accumulate achieved share from the cgroup's own accounting.

    Cumulative-from-first rather than a rolling mean: a long test under a cap should report the
    share over the whole window, not over the last five seconds.
    """
    cgroup = state.get("accounting_cgroup")
    if not cgroup or not os.path.isdir(cgroup):
        cgroup = state["cgroup"] if state["how"] == "cgroup" else container_cgroup(state["container"])
        state["accounting_cgroup"] = cgroup
    stat = cpu_stat(cgroup) if cgroup else {}
    if not stat:
        return
    point = {"t": now(),
             "usage_usec": stat.get("usage_usec", 0),
             "nr_periods": stat.get("nr_periods", 0),
             "nr_throttled": stat.get("nr_throttled", 0),
             "throttled_usec": stat.get("throttled_usec", 0)}
    first = state.get("first")
    if not first or point["usage_usec"] < first["usage_usec"]:
        # no baseline yet, or the cgroup was recreated and the counters restarted
        state["first"] = point
        return
    span = point["t"] - first["t"]
    if span <= 0:
        return
    measure = state["measure"]
    previous = state.get("last") or first
    window = point["t"] - previous["t"]
    # A sub-second window reads high: a task moved into the cgroup can run one full CFS slice
    # before the first period boundary, which is a measurement artifact and not a breached cap.
    if window >= 1.0:
        instant = (point["usage_usec"] - previous["usage_usec"]) / (window * 1e6) * 100.0
        measure["peak"] = round(max(measure.get("peak") or 0.0, instant), 2)
    state["last"] = point
    measure["n"] += 1
    measure["window_s"] = round(span, 1)
    measure["achieved"] = round((point["usage_usec"] - first["usage_usec"]) / (span * 1e6) * 100.0, 2)
    measure["nr_periods"] = point["nr_periods"] - first["nr_periods"]
    measure["nr_throttled"] = point["nr_throttled"] - first["nr_throttled"]
    measure["throttled_ms"] = (point["throttled_usec"] - first["throttled_usec"]) // 1000
    measure["bit"] = measure["nr_throttled"] > 0
    if measure["nr_periods"] > 0:
        measure["throttled_pct"] = round(measure["nr_throttled"] * 100.0 / measure["nr_periods"], 1)


# ------------------------------------------------------------------------------ mem

def mem_cap(state, pct):
    """Cap the container at ``pct`` of the RSS it had before we touched it."""
    want = int(state["baseline_rss"] * pct / 100.0)
    clamped = max(want, DOCKER_MIN_MEM)
    rc, _, err = docker("update", "--memory={}".format(clamped),
                        "--memory-swap={}".format(clamped), state["container"])
    step = {"pct": pct, "bytes": clamped, "t": round(now(), 1)}
    if clamped != want:
        step["clamped_from"] = want
    if rc != 0:
        step["error"] = err
    state["applied"].append(step)
    return rc == 0


def mem_apply(state):
    scope = container_cgroup(state["container"])
    if not scope:
        raise AgentError("container {!r} is not running".format(state["container"]))
    state["accounting_cgroup"] = scope
    baseline = mem_current(scope)
    if not baseline:
        raise AgentError("cannot read memory.current under {}".format(scope))
    state["baseline_rss"] = baseline
    for field, key in (("{{.HostConfig.Memory}}", "baseline_limit"),
                       ("{{.HostConfig.MemorySwap}}", "baseline_swap")):
        rc, out, _ = docker("inspect", "-f", field, state["container"])
        state[key] = int(out) if rc == 0 and out.lstrip("-").isdigit() else 0
    if not mem_cap(state, state["steps"][0]):
        raise AgentError("docker update --memory failed: {}".format(state["applied"][-1]))
    state["step"] = 0
    state["next_at"] = now() + state["period"]


def mem_tick(state):
    """Walk one rung down the ramp when its turn comes. A fixed cap is a one-rung ramp."""
    if state["step"] + 1 >= len(state["steps"]) or now() < state.get("next_at", 0):
        return False
    state["step"] += 1
    mem_cap(state, state["steps"][state["step"]])
    state["next_at"] = now() + state["period"]
    return True


def mem_sample(state):
    scope = state.get("accounting_cgroup")
    if not scope or not os.path.isdir(scope):
        scope = container_cgroup(state["container"])
        state["accounting_cgroup"] = scope
    if not scope:
        return
    measure = state["measure"]
    measure["n"] += 1
    measure["rss"] = mem_current(scope)
    events = mem_events(scope)
    measure["oom"] = events.get("oom", 0)
    measure["oom_kill"] = events.get("oom_kill", 0)
    measure["at_limit"] = events.get("max", 0)


def mem_release(state):
    """Raise the ceiling, settle, then answer the only question that matters: did RSS come back?

    Memory returned is not memory recovered. A daemon that stays fat once the pressure lifts is
    holding state it never freed -- that is the leak, and it is invisible unless you look after.
    """
    notes = []
    baseline_limit = state.get("baseline_limit") or 0
    if baseline_limit > 0:
        swap = state.get("baseline_swap") or baseline_limit
        rc, _, err = docker("update", "--memory={}".format(baseline_limit),
                            "--memory-swap={}".format(swap), state["container"])
    else:
        rc, _, err = docker("update", "--memory=0", "--memory-swap=-1", state["container"])
    if rc != 0:
        notes.append("docker update --memory: {}".format(err))
    scope = container_cgroup(state["container"])
    if scope and baseline_limit <= 0:
        # Authoritative for the LIVE container even when `docker update --memory=0` is refused:
        # the kernel knob wins.
        for knob in ("memory.max", "memory.swap.max"):
            err = try_write(os.path.join(scope, knob), "max")
            if err:
                notes.append(err)
        # ...but only for this life of the container. Docker 28.2.2 accepts `update --memory=0`,
        # exits 0, prints the container name -- and leaves HostConfig.Memory exactly as it was.
        # The next restart recreates the cgroup FROM that stored value and the cap comes back,
        # silently, on a box everyone believes was released. Measured on a lab switch: released to
        # memory.max=max, then a syncd/swss restart 50 minutes later brought 330625024 back.
        # Docker will not forget it, so say so rather than report a clean release.
        rc, out, _err = docker("inspect", "--format", "{{.HostConfig.Memory}}", state["container"])
        stored = (out or "").strip()
        if rc == 0 and stored.isdigit() and int(stored) > 0:
            notes.append(
                "docker still records a {} MB memory limit for {} and will not clear it "
                "(`update --memory=0` is accepted and ignored). The kernel cap is off now, but it "
                "WILL come back the next time this container restarts. Recreate the container, or "
                "expect a capped {} after any restart.".format(
                    int(stored) // 1048576, state["container"], state["container"]))
    settle = state.get("settle", 5)
    if settle:
        time.sleep(settle)
    after = mem_current(scope) if scope else None
    before = state.get("baseline_rss")
    state["rss_before"] = before
    state["rss_after"] = after
    if after and before:
        tolerance = state.get("recover_tolerance", 0.10)
        state["recovered"] = after <= before * (1.0 + tolerance)
        state["rss_delta_pct"] = round((after - before) * 100.0 / before, 1)
    mem_sample(state)
    return notes


# ------------------------------------------------------------------------------ lifecycle

def unit_name(state, role):
    """Transient systemd unit for one dead-man. Deliberately greppable: anyone auditing a box can
    run ``systemctl list-units 'sonic-chaos-*'`` and see exactly what we left running on it."""
    return "sonic-chaos-{}-{}-{}".format(state["kind"], state["target"], role)


def systemd_run(unit, argv, on_active=None):
    """Hand a job to systemd. Returns None on success, else the error text.

    The dead-man is this lane's most important safety property, and it must not depend on a
    process *we* spawned staying alive. A detached child looks durable and is not: an ssh session
    teardown, sudo reaping its descendants, or any supervisor sweeping a session takes it with
    them -- measured, not assumed. A transient unit is owned by pid 1 and outlives all of that.
    """
    cmd = ["systemd-run", "--collect", "--unit", unit]
    if on_active is not None:
        cmd += ["--on-active", str(int(on_active)), "--timer-property", "AccuracySec=1s"]
    rc, out, err = run(cmd + list(argv))
    return None if rc == 0 else (err or out or "systemd-run {} failed".format(unit))


def spawn(argv, label):
    """Detach a child completely: new session, stdin closed, output to the agent log.

    Only the fallback for a box without systemd. Nothing may hold the ssh channel open -- an
    ansible shell call waits on the pipes, so a child that inherits them hangs the harness.
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(LOG, "a") as log, open(os.devnull) as null:
            log.write("[{}] spawn {}: {}\n".format(time.strftime("%H:%M:%S"), label, " ".join(argv)))
            proc = subprocess.Popen(argv, stdin=null, stdout=log, stderr=log, start_new_session=True)
        return proc.pid
    except Exception as err:
        return "failed to spawn {}: {!r}".format(label, err)


def arm_deadmen(state):
    """Two of them, on purpose, because they fail in different ways.

    The **timer** is the one that matters: it does nothing but release at the deadline, and being
    a systemd unit it survives anything that happens to this ssh session. The **watcher** does the
    useful work -- re-attach after a restart, sample, walk the mem ramp -- but it is a python loop
    and it can die. Release is idempotent, so both firing is a no-op; neither firing is the one
    outcome this lane may never have.
    """
    me = os.path.abspath(__file__)
    ident = ["--kind", state["kind"], "--target", state["target"]]
    # --reason ttl so the record can tell "the fault expired mid-run" from "teardown released
    # it cleanly". They are very different results and the report must not conflate them.
    release_cmd = [sys.executable, me, "release"] + ident + ["--reason", "ttl"]
    watch_cmd = [sys.executable, me, "watch"] + ident

    stop_deadmen(state)      # a stale unit of the same name would refuse the new one
    state["units"] = []
    for role, argv, on_active, suffix in (("deadman", release_cmd, int(state["ttl"]), ".timer"),
                                          ("watch", watch_cmd, None, ".service")):
        unit = unit_name(state, role)
        err = systemd_run(unit, argv, on_active=on_active)
        if not err:
            state["units"].append(unit + suffix)
            continue
        # No systemd, or it refused. Fall back to a detached child and say so: the box is now
        # relying on something weaker than it should be, and that belongs in the record.
        state["notes"].append("{}: {} -- falling back to a detached process".format(unit, err))
        if role == "deadman":
            argv = ["/bin/sh", "-c", "sleep {}; exec {}".format(
                int(state["ttl"]), " ".join(release_cmd))]
        result = spawn(argv, role)
        state["watch_pid" if role == "watch" else "deadman_pid"] = (
            result if isinstance(result, int) else None)
        if not isinstance(result, int):
            state["notes"].append(result)


def stop_deadmen(state):
    for unit in state.get("units") or []:
        run(["systemctl", "stop", unit])
    for key in ("watch_pid", "deadman_pid"):
        pid = state.get(key)
        if isinstance(pid, int) and pid > 0:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass


def do_apply(args):
    os.makedirs(STATE_DIR, exist_ok=True)
    existing = load_state(args.kind, args.target)
    if existing and not existing.get("released"):
        # Idempotent by contract: applying twice is applying once. Re-arm and report what is live.
        if args.kind == "cpu" and existing["how"] == "cgroup":
            cpu_attach(existing)
        existing["reapplied"] = existing.get("reapplied", 0) + 1
        existing["deadline"] = now() + existing["ttl"]
        save_state(existing)
        return emit(summary(existing))

    state = {
        "kind": args.kind, "target": args.target, "container": args.container,
        "ttl": args.ttl, "started": now(), "deadline": now() + args.ttl,
        "interval": args.interval, "settle": args.settle,
        "released": False, "expired": False, "origin": {}, "notes": [],
        "measure": {"n": 0},
    }
    if args.kind == "cpu":
        state.update({"how": args.how, "share": args.share,
                      "quota_us": args.share * PERIOD_US // 100,
                      "cgroup": os.path.join(CG_BASE, args.target),
                      "pids": [], "reattach": []})
    else:
        state.update({"how": "docker", "steps": [int(s) for s in args.steps.split(",") if s],
                      "period": args.period, "step": -1, "applied": []})

    try:
        if os.path.exists(released_flag(args.kind, args.target)):
            os.remove(released_flag(args.kind, args.target))
        (cpu_apply if args.kind == "cpu" else mem_apply)(state)
    except AgentError as err:
        state["error"] = str(err)
        save_state(state)
        # Never leave a half-applied fault behind: unwind whatever did land.
        (cpu_release if args.kind == "cpu" else mem_release)(state)
        return emit(summary(state), rc=1)

    if args.kind == "cpu":
        cpu_sample(state)
    else:
        mem_sample(state)
    arm_deadmen(state)
    save_state(state)
    return emit(summary(state))


def do_release(args):
    state = load_state(args.kind, args.target)
    open(released_flag(args.kind, args.target), "w").close()
    if state is None:
        return emit({"kind": args.kind, "target": args.target, "released": True,
                     "active": False, "note": "nothing applied"})
    if state.get("released"):
        return emit(summary(state))
    # Lift the fault and record it first, disarm second. This may be running *inside* the watch
    # unit, and stopping that unit signals us -- by then the box is already clean and saved.
    if args.kind == "cpu":
        cpu_sample(state)
        notes = cpu_release(state)
    else:
        notes = mem_release(state)
    state["notes"] = (state.get("notes") or []) + [n for n in notes if n]
    state["released"] = True
    state["released_at"] = now()
    state["reason"] = args.reason
    state["expired"] = bool(state.get("expired")) or args.reason == "ttl"
    save_state(state)
    stop_deadmen(state)
    return emit(summary(state))


def do_status(args):
    state = load_state(args.kind, args.target)
    if state is None:
        return emit({"kind": args.kind, "target": args.target, "active": False,
                     "achieved": None, "note": "nothing applied"})
    if not state.get("released"):
        (cpu_sample if args.kind == "cpu" else mem_sample)(state)
        save_state(state)
    return emit(summary(state))


def do_watch(args):
    """The useful dead-man: re-attach after a restart, sample, walk the mem ramp, release at TTL."""
    state = load_state(args.kind, args.target)
    if state is None:
        return emit({"error": "no state for {}-{}".format(args.kind, args.target)}, rc=1)
    flag = released_flag(args.kind, args.target)
    while True:
        if os.path.exists(flag):
            return 0
        fresh = load_state(args.kind, args.target)
        if fresh is None or fresh.get("released"):
            return 0
        state = fresh
        if now() >= state["deadline"]:
            state["expired"] = True
            # Drop our own unit before releasing: stopping the unit we run inside would signal
            # us mid-release. Systemd reaps the service on its own once we exit.
            own = unit_name(state, "watch") + ".service"
            state["units"] = [u for u in (state.get("units") or []) if u != own]
            state["watch_pid"] = None
            save_state(state)
            args.reason = "ttl"
            return do_release(args)
        if args.kind == "cpu":
            moved, _ = cpu_attach(state) if state["how"] == "cgroup" else ([], [])
            if moved:
                # The PID moved under us -- almost always Spine's kill injector restarting swss.
                state["reattach"].append({"t": round(now(), 1), "pids": moved})
                if state["how"] == "cgroup":
                    try_write(os.path.join(state["cgroup"], "cpu.max"),
                              "{} {}".format(state["quota_us"], PERIOD_US))
            cpu_sample(state)
        else:
            mem_tick(state)
            mem_sample(state)
        save_state(state)
        time.sleep(state["interval"])


# ------------------------------------------------------------------------------ calibration

def do_calibrate(args):
    """Cap a synthetic spinner at a known share and check the measured value lands in tolerance.

    Without this, every achieved-share number in the report is unfalsifiable: we would be
    reporting the cgroup's own arithmetic back to ourselves. The spinners are pure ``sh`` busy
    loops, so a miss is the kernel's enforcement or our measurement -- never the workload.
    """
    if not cgroup_v2():
        return emit({"error": "{} is not cgroup v2".format(CG_ROOT)}, rc=1)
    leaf = os.path.join(CG_BASE, "_calibrate")
    result = {"requested": args.share, "seconds": args.seconds, "workers": args.workers,
              "achieved": None, "ok": False}
    spinners = []
    try:
        mkcgroup(CG_BASE)
        for cgroup in (CG_ROOT, CG_BASE):
            err = ensure_controller(cgroup, "cpu")
            if err:
                return emit(dict(result, error=err), rc=1)
        mkcgroup(leaf)
        write(os.path.join(leaf, "cpu.max"),
              "{} {}".format(args.share * PERIOD_US // 100, PERIOD_US))
        for _ in range(args.workers):
            proc = subprocess.Popen(["/bin/sh", "-c", "while :; do :; done"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True)
            spinners.append(proc)
            err = try_write(os.path.join(leaf, "cgroup.procs"), str(proc.pid))
            if err:
                return emit(dict(result, error=err), rc=1)
        # Baseline *after* placement: cgroup accounting starts when the pid enters, so whatever
        # a spinner burned before the move is not counted and cannot skew the measurement.
        start, first = now(), cpu_stat(leaf)
        time.sleep(args.seconds)
        span, last = now() - start, cpu_stat(leaf)
        used = last.get("usage_usec", 0) - first.get("usage_usec", 0)
        result["achieved"] = round(used / (span * 1e6) * 100.0, 2)
        result["nr_throttled"] = last.get("nr_throttled", 0) - first.get("nr_throttled", 0)
        result["tolerance"] = round(max(CALIB_ABS_TOLERANCE, args.share * CALIB_REL_TOLERANCE), 2)
        result["error_points"] = round(result["achieved"] - args.share, 2)
        result["ok"] = abs(result["error_points"]) <= result["tolerance"]
    finally:
        for proc in spinners:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        for _ in range(10):
            try:
                rmcgroup(leaf)
                break
            except OSError:
                time.sleep(0.2)
        try:
            rmcgroup(CG_BASE)
        except OSError:
            pass
    return emit(result, rc=0 if result["ok"] else 1)


# ------------------------------------------------------------------------------ reporting

def summary(state):
    """The dict the injector's ``status()`` returns. Flat, because it lands in a junit property."""
    measure = state.get("measure") or {}
    out = {
        "kind": state["kind"], "target": state["target"], "container": state.get("container"),
        "how": state.get("how"), "active": not state.get("released", False),
        "released": state.get("released", False), "expired": state.get("expired", False),
        "samples": measure.get("n", 0), "state_file": state_path(state["kind"], state["target"]),
        "reason": state.get("reason"),
        "remaining_s": round(max(0.0, state.get("deadline", 0) - now()), 1),
    }
    if state.get("error"):
        out["error"] = state["error"]
    if state.get("notes"):
        out["notes"] = state["notes"]
    if state["kind"] == "cpu":
        out.update({
            "requested": state.get("share"),
            "achieved": measure.get("achieved"),
            "peak": measure.get("peak"),
            "bit": measure.get("bit"),
            "throttled_pct": measure.get("throttled_pct"),
            "throttled_ms": measure.get("throttled_ms"),
            "window_s": measure.get("window_s"),
            "pids": state.get("pids"),
            "reattached": len(state.get("reattach") or []),
        })
    else:
        applied = state.get("applied") or []
        out.update({
            "steps": state.get("steps"),
            "step": state.get("step"),
            "cap_bytes": applied[-1]["bytes"] if applied else None,
            "cap_pct": applied[-1]["pct"] if applied else None,
            "rss": measure.get("rss"),
            "rss_before": state.get("rss_before", state.get("baseline_rss")),
            "rss_after": state.get("rss_after"),
            "rss_delta_pct": state.get("rss_delta_pct"),
            "recovered": state.get("recovered"),
            "oom_kill": measure.get("oom_kill"),
            "at_limit": measure.get("at_limit"),
        })
    return out


# ------------------------------------------------------------------------------ CLI

def parse_args(argv):
    parser = argparse.ArgumentParser(description="sonic-chaos Squeeze agent (DUT side)")
    sub = parser.add_subparsers(dest="command", required=True)

    def ident(p):
        p.add_argument("--kind", choices=("cpu", "mem"), required=True)
        p.add_argument("--target", required=True, help="process (cpu Tier 1) or container")
        return p

    apply_p = ident(sub.add_parser("apply"))
    apply_p.add_argument("--container", required=True)
    apply_p.add_argument("--how", choices=("cgroup", "docker"), default="cgroup")
    apply_p.add_argument("--share", type=int, default=50, help="cpu: percent of one core")
    apply_p.add_argument("--steps", default="", help="mem: comma-separated cap percentages")
    apply_p.add_argument("--period", type=int, default=30, help="mem: seconds between ramp steps")
    apply_p.add_argument("--ttl", type=int, default=900)
    apply_p.add_argument("--interval", type=int, default=5, help="watcher tick, seconds")
    apply_p.add_argument("--settle", type=int, default=5, help="mem: seconds to wait before rss_after")

    release_p = ident(sub.add_parser("release"))
    release_p.add_argument("--reason", default="harness")

    ident(sub.add_parser("status"))
    watch_p = ident(sub.add_parser("watch"))
    watch_p.add_argument("--reason", default="ttl")

    calib = sub.add_parser("calibrate")
    calib.add_argument("--share", type=int, default=30)
    calib.add_argument("--seconds", type=int, default=6)
    calib.add_argument("--workers", type=int, default=2)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    handler = {"apply": do_apply, "release": do_release, "status": do_status,
               "watch": do_watch, "calibrate": do_calibrate}[args.command]
    try:
        return handler(args)
    except AgentError as err:
        return emit({"error": str(err), "command": args.command}, rc=1)


if __name__ == "__main__":
    sys.exit(main())
