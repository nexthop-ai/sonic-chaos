"""The run loop: drive faults against a switch without a pytest session.

    sonic-chaos run --dut ssh://admin@10.0.0.5 --chaos-file orchagent-restart.yml --chaos-seed 20260911
    sonic-chaos run --dut ssh://admin@10.0.0.5 --chaos pause=orchagent:10 --chaos-repeat 5
    sonic-chaos run --dut ssh://admin@10.0.0.5 --chaos-dry-run --chaos-file ...
    sonic-chaos run --dut ssh://admin@10.0.0.5 --probe          # connect + steady state only

Runs a schedule exactly the way the pytest plugin does: steady-state gate, seeded fault order,
settle, consistency check, recovery poll, LIFO release on every exit path. The switch is any
``sonic_chaos.transport`` URL; a traffic peer for PTF-driven faults is ``--ptf <url>``.

Exit codes (``EXIT_*`` below): 0 every fault engaged and all invariants held, 1 at least one
verdict flipped, 5 no verdict flipped but a fault never engaged (INCONCLUSIVE -- proved nothing),
3 the run was INVALID (steady state failed before any fault), 4 a DUT-side error outside a fault,
6 a release failed, so a fault may still be applied (outranks every verdict), 2 usage error,
130 interrupted.
"""
import argparse
import json
import logging
import shlex
import os
import re
import signal
import sys
import time

from .. import injectors as _registered                   # noqa: F401  registers them
from .. import oracle as consistency
from ..experiment import Experiment
from ..injector import ChaosPlan, ChaosSession, ChaosUsageError
from ..transport import open_dut

EXIT_HELD, EXIT_BROKE, EXIT_USAGE, EXIT_INVALID, EXIT_DUT_ERROR, EXIT_INCONCLUSIVE = 0, 1, 2, 3, 4, 5
EXIT_RELEASE_FAILED = 6   # outranks every verdict: a fault may still be applied on the box
EXIT_INTERRUPTED = 130
RELEASE_FAILURES = []     # every release that raised during this run
PTF_URL = [None]     # set from --ptf; the traffic peer PTF-driven faults send from


def ptf_for(dut):
    """The traffic peer as a host object, or None when the run was given none.

    Probed once: a testbed whose topology was never deployed has no PTF at all, and the storm
    injector's own error explains that far better than an ssh failure in the middle of apply.
    """
    if not PTF_URL[0]:
        return None
    ptf = open_dut(PTF_URL[0])
    try:
        res = ptf.shell("true", module_ignore_errors=True)
    except Exception as err:
        say("PTF at {} unreachable ({}); traffic storms will refuse to run".format(PTF_URL[0], str(err)[:120]))
        return None
    if res.get("rc", 1) != 0:
        say("PTF at {} unreachable ({}); traffic storms will refuse to run".format(
            PTF_URL[0], (res.get("stderr") or res.get("stdout") or "").strip()[:120]))
        return None
    return ptf


T0 = time.time()
SNAPSHOTS = [False]     # a full DB dump is the slowest thing a run does; opt in with --snapshot


def say(msg):
    print("T+{:d}:{:02d}  {}".format(int((time.time() - T0) // 60), int((time.time() - T0) % 60), msg), flush=True)


def fmt_divs(divs):
    return "; ".join("{} {} {} {}".format(d.kind, d.db, d.key, (d.detail or "")[:160].replace("\n", " ")) for d in divs)


BASELINE = set()   # (kind, db, key) divergences that were already present before the first fault


def key_of(d):
    return consistency.finding_key(d)


SWSS_UNITS = ("swss", "syncd", "bgp", "teamd")


def swss_starts_spent(dut):
    """``(starts, burst)``: swss starts that count against systemd's limit right now, and the limit.

    systemd counts starts inside StartLimitIntervalSec and `reset-failed` clears that counter --
    but nothing exposes the counter, and the journal keeps every start. Counting the whole window
    refused a single kill on a box that had a fresh budget (6 old starts in the log, 2 real ones
    left). After a start-limit-hit nothing starts until someone resets, so starts AFTER the last
    start-limit-hit line are the ones systemd is still counting. No lock in the window: count all.
    """
    res = dut.shell("journalctl -u swss --since '-20 min' --no-pager -o short-iso 2>/dev/null | "
                    "grep -E 'Started swss.service|start-limit-hit' | awk '{print $NF}'; "
                    "echo BURST=$(systemctl show swss.service -p StartLimitBurst --value)",
                    module_ignore_errors=True)
    starts, burst = 0, 3
    for line in (res.get("stdout") or "").splitlines():
        line = line.strip()
        if line.startswith("BURST="):
            burst = int(line[6:] or 3)
        elif line == "service.":          # the awk $NF of "Started swss.service - switch state service."
            starts += 1
        elif "start-limit-hit" in line:
            starts = 0                    # everything before this needed a reset to get past
    return starts, burst


def preflight(dut):
    """Refuse to start on a switch whose services are already failed.

    Arming the SAI interposer restarts swss, and systemd allows three starts in twenty minutes.
    Spend that budget and the restart fails with start-limit-hit, taking swss, syncd, bgp and
    teamd down until someone clears it. A run that begins on a box already in that state cannot
    produce a finding, only a second outage, so it stops here and prints the way back.
    """
    res = dut.shell("systemctl is-active {} 2>&1".format(" ".join(SWSS_UNITS)),
                    module_ignore_errors=True)
    states = (res.get("stdout") or "").split()
    bad = [u for u, st in zip(SWSS_UNITS, states) if st.strip() != "active"]
    if not bad:
        # Healthy, but how much of the restart budget is left? A kill of any swss critical process
        # (orchagent is one of fourteen) restarts the whole container, and systemd stops it after
        # StartLimitBurst starts in StartLimitIntervalUSec. On a lab switch that is 3 in 20 min; a run
        # that lands on a box already at 2 becomes the outage, not the finding.
        # The limit is on STARTS, manual ones included; NRestarts only counts the automatic
        # ones and read 1 while a lab switch sat at start-limit-hit. Count what systemd counts.
        spent, burst = swss_starts_spent(dut)
        if spent >= burst - 1:
            say("WARN swss has been started {} of the {} times systemd allows in its current 20-minute window "
                "(counted since the last start-limit-hit, so a reset-failed is respected). One more -- and "
                "killing any swss critical process is one -- locks the box.".format(spent, burst))
        return None
    say("pre-flight FAILED on {}: {} not active ({})".format(
        dut.hostname, ", ".join(bad), " ".join(states)))
    hit = dut.shell("systemctl show swss.service -p Result --value", module_ignore_errors=True)
    if "start-limit" in (hit.get("stdout") or ""):
        say("swss is at its systemd start limit: three starts in twenty minutes, and this box has "
            "spent them. Nothing comes back on its own.")
    say("recover with: systemctl reset-failed {}; systemctl start swss".format(" ".join(SWSS_UNITS)))
    say("run INVALID: the switch was already down. Not a finding.")
    return 3


def gate(dut, names, args):
    """Steady-state gate. Returns None to proceed, or an exit code. With --baseline, pre-existing
    divergences are recorded and filtered out of every later check instead of invalidating the run."""
    if not names:
        return None
    divs, _, ran = check(dut, names, "steady state")
    if not divs:
        if not ran:
            say("steady_state: nothing ran, so the gate proved nothing. Everything asked for needs "
                "a database snapshot; use --snapshot, or gate on a check that does not.")
            return None
        for n in ran:
            say("steady_state {}: pass".format(n))
        skipped = [n for n in names if n not in ran]
        if skipped:
            say("steady_state: {} did not run, so nothing is claimed about {}".format(
                ", ".join(skipped), "them" if len(skipped) > 1 else "it"))
        return None
    if args.baseline:
        BASELINE.update(key_of(d) for d in divs)
        say("steady_state: {} pre-existing divergence(s) recorded as baseline and ignored from here on: {}".format(
            len(divs), fmt_divs(divs)))
        return None
    say("steady_state FAILED before any fault: {}".format(fmt_divs(divs)))
    say("run INVALID: the box was already diverged. Not a finding. (--baseline ignores what was already there)")
    return 3


_NEEDS_TABLES = {}


def needs_tables(name):
    """Does this invariant read the snapshot, or does it just run a command on the switch?

    Read from the registered function's own source rather than a list here, so a check added to
    the plugin is classified correctly without this file being edited.
    """
    if name not in _NEEDS_TABLES:
        fn = consistency.INVARIANTS.get(name)
        try:
            import inspect
            src = inspect.getsource(fn)
        except Exception:
            src = "snap.keys("        # unknown: assume it needs one, the safe direction
        _NEEDS_TABLES[name] = bool(re.search(r"snap\.(keys|get|tables)\b", src))
    return _NEEDS_TABLES[name]


def check(dut, names, label):
    """Snapshot and run the named invariants. Returns (divergences, snapshot); baseline divergences removed."""
    known = set(consistency.INVARIANTS)
    missing = [n for n in names if n not in known]
    if missing:
        say("WARN invariant(s) not registered on this branch, skipped: {} -- this run verifies "
            "less than the contract claims".format(", ".join(missing)))
    use = [n for n in names if n in known]
    wants = [n for n in use if needs_tables(n)]
    if wants and not SNAPSHOTS[0]:
        say("skipping {} for {}: {} a database snapshot, and snapshots are off "
            "(--snapshot turns them back on)".format(
                ", ".join(wants), label, "they need" if len(wants) > 1 else "it needs"))
        use = [n for n in use if n not in wants]
    if not use:
        return [], consistency.DbSnapshot({}, hostname=dut.hostname, duthost=dut), []
    if wants and SNAPSHOTS[0]:
        say("check: snapshot APPL_DB + ASIC_DB + STATE_DB for {} (the slow part)".format(label))
        snap = consistency.snapshot(dut)
    else:
        # nothing here reads a table, so the checks run straight on the switch
        snap = consistency.DbSnapshot({}, hostname=dut.hostname, duthost=dut)
    divs = consistency.check(snap, only=use) if use else []
    # "could not be checked" is not "is broken", and the oracle already draws that line:
    # split_unchecked() separates real findings from notices. Treating a notice as a divergence
    # made the steady-state gate refuse to start at all on a box whose syncd lists dsserve in
    # critical_processes without supervisor knowing it -- every run came back INVALID on a
    # perfectly healthy switch.
    notices = []
    if hasattr(consistency, "split_unchecked"):
        divs, notices = consistency.split_unchecked(divs)
    for n in notices:
        say("{}: {} could not be checked -- {}".format(label, getattr(n, "kind", "?"),
                                                       str(getattr(n, "detail", ""))[:160]))
    if BASELINE:
        divs = [d for d in divs if key_of(d) not in BASELINE]
    return divs, snap, use


# What the console needs to decide whether a fault actually bit. Both run paths forward these;
# the flags path used to keep eight of them and silently drop exhaust's leaked/refused and
# storm's flaps -- the very numbers that separate "tested nothing" from "tested and held".
STATUS_KEYS = ("active", "achieved", "requested", "bit", "throttled_pct", "pids", "state", "frozen",
               "baseline", "peak", "pushed", "accepted", "refused", "leaked", "after_release",
               "flaps", "enobufs_new", "neighbours_lost",
               "loaded", "hooked", "mode", "load", "cpu_max", "oom_kill")


def settle_with_telemetry(dut, inj, seconds, every=5):
    """Sleep out the settle, emitting `telemetry <container>: {...}` lines the console graphs.

    Reads the target container's cgroup cpu.stat and memory.current, so the page can show the
    fault actually biting (a hog plateauing at its cap) instead of asking the operator to trust a
    log line. The scope path is resolved ONCE to a literal path: embedding the docker-inspect
    substitution inside a quoted sh -c is how an earlier injector silently wrote nothing.
    """
    container = (getattr(inj, "params", {}) or {}).get("container")
    if not container or seconds < every * 2:
        time.sleep(seconds)
        return
    res = dut.shell("docker inspect --format '{{{{.Id}}}}' {}".format(container), module_ignore_errors=True)
    cid = (res.get("stdout") or "").strip().splitlines()[-1] if res.get("stdout") else ""
    if res.get("rc") or not cid:
        time.sleep(seconds)
        return
    scope = "/sys/fs/cgroup/system.slice/docker-{}.scope".format(cid)
    # dbsize is O(1) on both. CPU alone cannot tell "busy and working" from "busy and
    # stuck": the pair can. A stalled orchagent shows ASIC flat while APPL climbs.
    read = ("awk '/^usage_usec/{{print $2}}' {s}/cpu.stat; cat {s}/memory.current; "
            "sonic-db-cli ASIC_DB dbsize; sonic-db-cli APPL_DB dbsize; "
            "date +%s%N").format(s=scope)
    prev = None
    t_end = time.time() + seconds
    while True:
        res = dut.shell("sh -c {}".format(shlex.quote(read)), module_ignore_errors=True)
        parts = (res.get("stdout") or "").split()
        if len(parts) >= 5:
            try:
                usec, mem = int(parts[-5]), int(parts[-4])
                asic, appl, now_ns = int(parts[-3]), int(parts[-2]), int(parts[-1])
                if prev:
                    dt = (now_ns - prev[1]) / 1e9
                    if dt > 0:
                        cpu = round((usec - prev[0]) / 1e6 / dt * 100.0, 1)
                        say("telemetry {}: {}".format(container, json.dumps(
                            {"cpu_pct": cpu, "mem_mb": round(mem / 1048576.0, 1),
                             "asic": asic, "asic_delta": asic - prev[2], "appl": appl})))
                prev = (usec, now_ns, asic)
            except (ValueError, IndexError):
                pass
        left = t_end - time.time()
        if left <= 0:
            break
        time.sleep(min(every, left))


def not_back(inj, status, spec):
    """1 if an event fault's target never came back, else 0 -- and say so as a failed invariant.

    kill logs "did NOT recover -- that is the finding" and the run then graded itself PASSED
    with the swss container down (a lab switch). A finding that never counts is not a finding.
    """
    ach = (status or {}).get("achieved") or {}
    if ach.get("recovered_now") is False:
        if ach.get("start_limit_hit"):
            say("invariant recovery FAILED after {}: {} did not come back -- systemd hit its start "
                "limit and has stopped trying. Recover with: systemctl reset-failed swss; "
                "systemctl start swss".format(spec, inj.params.get("process") or inj.name))
        else:
            say("invariant recovery FAILED after {}: {} did not come back within the settle and is "
                "still down at check time".format(spec, inj.params.get("process") or inj.name))
        return 1
    return 0


def settle_of(injector):
    p = injector.params
    # `settle` is the hold: how long the fault stays up before the invariants are read. `ttl` is a
    # separate switch-side dead-man, never the hold -- each injector that wants a longer hold
    # declares a settle (sai does; the rest take it from the spec), and the injector refuses a
    # settle that outlives its ttl so the fault cannot be lifted before the check reads it.
    for key in ("settle", "seconds"):
        if key in p:
            try:
                return max(5, int(p[key]))
            except ValueError:
                pass
    return 20


def recover(dut, names, budget, first_divs):
    """Poll the invariants until they hold or the budget passes. Returns seconds taken, or None."""
    start = time.time()
    while time.time() - start < budget:
        time.sleep(min(10, budget))
        try:
            divs, _, _ = check(dut, names, "recovery poll")
        except RuntimeError as err:
            # The box going away mid-poll is a worse state than "still diverged", not a crash.
            say("contract: DUT unreachable after {}s: {}".format(round(time.time() - start), str(err)[:160]))
            continue
        if not divs:
            return round(time.time() - start)
        say("contract: still diverged after {}s: {}".format(round(time.time() - start), fmt_divs(divs)[:200]))
    return None


def boot_id(dut):
    """The kernel's boot id, or None when the box cannot answer. Changes exactly when the box reboots."""
    try:
        res = dut.shell("cat /proc/sys/kernel/random/boot_id", module_ignore_errors=True)
    except Exception:
        return None
    return (res.get("stdout") or "").strip() if res.get("rc", 1) == 0 else None


def wait_reachable(dut, budget):
    """Poll until the box answers over ssh AND redis answers. Returns seconds taken, or None."""
    start = time.time()
    while True:
        try:
            res = dut.shell("sonic-db-cli APPL_DB PING", module_ignore_errors=True)
            if res.get("rc", 1) == 0 and "PONG" in (res.get("stdout") or ""):
                return round(time.time() - start)
        except Exception:
            pass
        if time.time() - start >= budget:
            return None
        say("waiting for {} to come back ({}s)".format(dut.hostname, round(time.time() - start)))
        time.sleep(10)


def release_guarded(session, dut, label="release_all"):
    """Release every applied fault with signals held off, then prove the box is not frozen.

    Release is the one part of a run that must finish. SIGINT used to be able to land inside
    release_all -- between the thaw of one fault and the next -- and leave a container paused
    on a shared box. Signals are blocked for the duration and restored afterwards.
    """
    prev = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            prev[sig] = signal.signal(sig, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    try:
        session.release_all()
        say("chaos: {} done (LIFO)".format(label))
    except Exception as err:
        RELEASE_FAILURES.append("{}: {!r}".format(label, err))
        say("RELEASE FAILED: {!r} -- checking the box directly".format(err))
    finally:
        sweep_frozen(dut)
        for sig, handler in prev.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass


def release_failed(dut):
    """A release raised: whatever the verdicts say, the box may still be under a fault."""
    for failure in RELEASE_FAILURES:
        say("RELEASE FAILED -- {}".format(failure))
    say("exit {}: a fault may still be applied on {}; check it before handing the box back".format(
        EXIT_RELEASE_FAILED, dut.hostname))
    return EXIT_RELEASE_FAILED


def sweep_frozen(dut):
    """Last line of defence: nothing may be left paused or stopped because we are leaving.

    Cheap, read-mostly, and it runs even when release raised. A container left paused is the
    failure mode that pages someone, so it is worth one extra round trip on the way out.
    """
    try:
        res = dut.shell("docker ps -a --filter status=paused --format '{{.Names}}'",
                        module_ignore_errors=True)
    except Exception as err:
        say("could not check for paused containers: {!r}".format(err))
        return
    names = [n for n in (res.get("stdout") or "").split() if n]
    if not names:
        say("box check: no paused containers left")
        return
    say("BOX LEFT PAUSED: {} -- unpausing".format(", ".join(names)))
    for name in names:
        out = dut.shell("docker unpause {}".format(name), module_ignore_errors=True)
        ok = out.get("rc", 1) == 0
        say("  docker unpause {}: {}".format(name, "done" if ok else "FAILED, run it by hand"))


def make_session(dut, ptf=None):
    """ChaosSession, with ptfhost only if this generation of the plugin takes it.

    The driver and the plugin move separately: a console that can run against either checkout is
    worth more than one that dies with a TypeError after a two-minute snapshot.
    """
    import inspect
    kwargs = {}
    if ptf is not None and "ptfhost" in inspect.signature(ChaosSession.__init__).parameters:
        kwargs["ptfhost"] = ptf
    elif ptf is not None:
        say("note: this plugin's ChaosSession takes no ptfhost, so PTF-driven faults "
            "(storm from the peer) will not have one")
    return ChaosSession([dut], **kwargs)


def write_bundle(out, tag, before, after, divs, extra):
    d = os.path.join(out, tag)
    os.makedirs(d, exist_ok=True)
    if before is not None:
        before.save(os.path.join(d, "before.json"))
    if after is not None:
        after.save(os.path.join(d, "after.json"))
    with open(os.path.join(d, "result.json"), "w") as fh:
        json.dump(dict(extra, divergences=[d_.__dict__ for d_ in divs]), fh, indent=1, default=str)
    return d


def preload_interposers(dut, injectors, names, budget=180):
    """Load every interposer the plan needs before the baseline is taken.

    Loading a shim re-execs swss/syncd once; done here, that happens up front rather than inside a
    measurement slot (where on a lab switch it made route_check read FAILED for the reconvergence, not
    the fault). Each shim is loaded then disarmed -- a disarmed shim is a straight passthrough --
    so a later per-slot apply finds it hooked and only writes the control file. Then wait for
    ``names`` to hold again, so the baseline reflects the settled box.
    """
    done = []
    for inj in injectors:
        if not _will_restart(inj, dut):
            continue
        say("pre-load: {} loads its interposer now (once)".format(inj.name))
        inj.apply(dut)
        inj.release(dut)
        done.append(inj.name)
    if done:
        took = recover(dut, names, budget, [])
        say("pre-load: {} ready; box settled after {}".format(
            ", ".join(done), "{}s".format(took) if took is not None else "the budget"))
    return done


def _will_restart(injector, dut):
    """Whether arming this injector restarts the swss container, tolerant of a flaky probe."""
    try:
        return bool(injector.will_restart(dut))
    except Exception:
        return False


def run_experiment(dut, exp, seed, args):
    sched = exp.schedule(seed)
    say("plan: {}".format(exp.describe().replace("\n", " | ")))
    say("schedule: {} faults over {}s, min_gap {}s, seed {}".format(len(sched), exp.duration, exp.min_gap, seed))
    # A kill of a swss critical process is a container restart, and systemd allows three swss
    # starts per twenty minutes -- manual recoveries included. A file that repeats one every 90 s
    # for ten minutes is six. This used to WARN and carry on, and the box locked at the second kill
    # because it already had starts in the window. A warning that lets that happen is worthless:
    # refuse, count what is already spent, and say exactly which knob to turn.
    kills = [off for off, fault in sched
             if fault.injector.name == "kill" and fault.injector.params.get("how") != "container"
             and fault.injector.params.get("container") == "swss"]
    if kills:
        burst, spent = 3, 0
        try:
            spent, burst = swss_starts_spent(dut)
        except Exception:
            pass
        worst = max(sum(1 for o2 in kills if o <= o2 < o + 1200) for o in kills)
        if worst + spent >= burst:
            say("{} {} kills of a swss daemon are scheduled, {} inside one 20-minute window, and the box has "
                "already started swss {} time(s) in its current window (since the last start-limit-hit) against a "
                "limit of {}. Each kill "
                "restarts the whole swss container; the box will hit start-limit-hit and stay down. Raise "
                "min_gap to 7m, shorten duration so at most {} land in twenty minutes, run the fault once with "
                "--chaos, or pass --allow-start-limit if downing the box is the experiment.".format(
                    "WARN (proceeding, --allow-start-limit)" if args.allow_start_limit else "REFUSED:",
                    len(kills), worst, spent, burst, max(0, burst - 1 - spent)))
            if not args.allow_start_limit:
                say("run INVALID: this schedule would lock the switch. Not a finding.")
                return 2
    # An interposer (sai/spin) restarts the swss container to load its shim. Arming one on a box
    # already near its systemd start-limit is what bricks a testbed mid-run -- refuse before the
    # restart, not after. will_restart() mirrors each lane's own apply() condition.
    if not args.allow_start_limit and any(_will_restart(fa.injector, dut) for _o, fa in sched):
        spent, burst = 0, 3
        try:
            spent, burst = swss_starts_spent(dut)
        except Exception:
            pass
        if spent >= burst - 1:
            say("REFUSED: this schedule arms an interposer (sai/spin), which restarts the swss "
                "container to load its shim, and the box has already started swss {}/{} in its "
                "current 20-minute window. One more restart may hit the start-limit and leave the "
                "box down. Wait for the window to clear, or pass --allow-start-limit if a restart "
                "here is intended.".format(spent, burst))
            say("run INVALID: arming would risk locking the switch. Not a finding.")
            return 2
    for off, f in sched:
        say("  T+{:d}:{:02d}  {}".format(off // 60, off % 60, f.injector.describe()))
    if args.chaos_dry_run:
        say("dry run complete; nothing applied")
        return 0

    if not exp.invariants:
        say("WARNING the contract lists no invariants, so nothing is checked after a fault and this "
            "run cannot produce a verdict. Add invariants under contract.invariants.")
    code = preflight(dut)
    if code:
        return code
    # Load interposers before the baseline, not inside the first slot: see preload_interposers.
    preload_interposers(dut, [f.injector for _o, f in sched], exp.steady_state, exp.recover_within)
    code = gate(dut, exp.steady_state, args)
    if code:
        return code

    fails = 0
    inconclusive = 0
    session = make_session(dut, lambda: ptf_for(dut))
    started = time.time()
    boot0 = boot_id(dut)
    try:
        for i, (off, fault) in enumerate(sched):
            wait = started + off - time.time()
            if wait > 0:
                say("waiting {}s for the next slot".format(int(wait)))
                time.sleep(wait)
            inj = fault.injector
            spec = inj.describe()
            before = None
            if args.no_before or not SNAPSHOTS[0]:
                pass
            elif not exp.invariants:
                say("skipping the pre-fault snapshot: the contract lists no invariants, so there is "
                    "nothing to compare it against")
            else:
                _, before, _ = check(dut, [], "before {}".format(inj.name))
            for w in inj.warnings():
                say("note: {}".format(w))
            say("chaos: apply {} on {}".format(spec, dut.hostname))
            session.apply(inj)
            settle = settle_of(inj)
            say("settle {}s".format(settle))
            settle_with_telemetry(dut, inj, settle)
            outage = None
            try:
                divs, after, ran = check(dut, exp.invariants, "after {}".format(inj.name))
            except RuntimeError as err:
                # The box vanished after the fault. That is the headline result of this slot, not a
                # harness error: wait for it inside the recovery budget, note whether it rebooted,
                # and only then decide whether anything else can be checked.
                say("DUT unreachable after {}: {}".format(spec, str(err)[:200]))
                took = wait_reachable(dut, exp.recover_within)
                boot1 = boot_id(dut)
                rebooted = bool(boot0 and boot1 and boot0 != boot1)
                outage = {"seconds": took, "rebooted": rebooted, "error": str(err)[:400]}
                fails += 1
                if took is None:
                    say("invariant reachability FAILED after {}: DUT unreachable for the whole {}s recovery "
                        "budget".format(spec, exp.recover_within))
                    path = write_bundle(args.out, "{:02d}-{}".format(i, inj.name), before, None, [], {
                        "spec": spec, "offset": off, "settle": settle, "outage": outage, "seed": seed,
                        "experiment": exp.name, "dut": dut.hostname,
                        "repro": "--chaos-file {} --chaos-seed {}".format(exp.path, seed)})
                    say("bundle {}".format(path))
                    say("aborting the remaining {} slot(s): nothing can be checked on a box that is not "
                        "answering".format(len(sched) - i - 1))
                    break
                say("invariant reachability FAILED after {}: DUT unreachable for {}s{}".format(
                    spec, took, " and it REBOOTED (boot id changed)" if rebooted else ""))
                if rebooted:
                    say("note: a reboot mid-run is not necessarily the fault's doing -- run `show reboot-cause` on {} "
                        "before filing; a power loss or a re-image by someone else looks identical from "
                        "here".format(dut.hostname))
                    if boot1:
                        boot0 = boot1
                divs, after, ran = check(dut, exp.invariants, "after {} (post-outage)".format(inj.name))
            status = {}
            try:
                status = inj.status(dut)
                brief = {k: status[k] for k in STATUS_KEYS if k in status}
                say("status {}: {}".format(inj.name, json.dumps(brief, default=str)))
                fails += not_back(inj, status, spec)
                if ((status or {}).get("achieved") or {}).get("start_limit_hit"):
                    say("aborting the remaining {} slot(s): swss is at systemd's start limit and will not "
                        "restart on its own, so nothing further can be applied or checked. Recover with: "
                        "systemctl reset-failed swss; systemctl start swss".format(len(sched) - i - 1))
                    break
                if status.get("bit") is False:
                    say("note: cap bit is False -- {} never wanted more CPU than the cap allowed, so this fault "
                        "was a no-op. "
                        "Lower the share or give the daemon work.".format(inj.params.get("process", inj.name)))
            except Exception as err:  # diagnostics only
                status = {"error": repr(err)}
            engaged = None
            try:
                engaged = inj.fired(status)
            except Exception:  # a status shape the injector can't read is not a verdict
                pass
            if divs:
                say("invariant {} FAILED after {}: {}".format(divs[0].kind, spec, fmt_divs(divs)))
                took = recover(dut, exp.invariants, exp.recover_within, divs)
                if took is None:
                    say("contract: not recovered within {}s FAILED".format(exp.recover_within))
                    fails += 1
                else:
                    say("contract: recovered after {}s (budget {}s) -- transient, still a verdict flip".format(
                        took, exp.recover_within))
                    fails += 1
            elif engaged is False:
                say("INCONCLUSIVE after {}: the fault armed but never engaged (nothing was "
                    "intercepted or affected) -- an idle box, or a target nothing on the box "
                    "exercised. The invariants held, but over a fault that did not happen, so "
                    "nothing is proven. This is NOT a pass.".format(spec))
                inconclusive += 1
            else:
                say("consistent after {} ({} pass)".format(spec, ", ".join(ran) or "nothing ran"))
            # state faults are released between slots; event faults' release is a no-op by contract
            say("chaos: release {} on {}".format(spec, dut.hostname))
            release_guarded(session, dut, "release {}".format(spec))
            tag = "{:02d}-{}".format(i, inj.name)
            path = write_bundle(args.out, tag, before, after, divs, {
                "spec": spec, "offset": off, "settle": settle, "status": status, "outage": outage,
                "engaged": engaged, "seed": seed, "experiment": exp.name, "dut": dut.hostname,
                "repro": "--chaos-file {} --chaos-seed {}".format(exp.path, seed)})
            say("bundle {}".format(path))
    finally:
        release_guarded(session, dut)
    say("verdict: {} faults / {} FAIL / {} inconclusive{}".format(
        len(sched), fails, inconclusive,
        "  repro: --chaos-seed {}".format(seed) if fails else ""))
    if RELEASE_FAILURES:
        return release_failed(dut)
    if fails:
        return 1
    # Green only when every fault both engaged and held. A run whose faults never fired proved
    # nothing, and must not exit 0 -- that is the false-confidence a test tool cannot ship.
    return 5 if inconclusive else 0


def run_flags(dut, plan, args):
    say("plan:\n{}".format(plan.describe()))
    if args.chaos_dry_run:
        say("dry run complete; nothing applied")
        return 0
    # A group, resolved from the plugin, so this default never goes stale when a check is added.
    names = consistency.resolve(args.invariant or "parity")
    # Same refusal as the schedule path: an interposer (sai/spin) restarts swss to load, and on a
    # box already at its start-limit that locks it. Measured on a lab switch: preflight WARNed
    # "5 of the 3 starts" and this path carried on and restarted anyway.
    if not args.allow_start_limit and any(_will_restart(inj, dut) for inj in plan.injectors):
        spent, burst = 0, 3
        try:
            spent, burst = swss_starts_spent(dut)
        except Exception:
            pass
        if spent >= burst - 1:
            say("REFUSED: this plan arms an interposer (sai/spin), which restarts the swss container "
                "to load its shim, and the box has already started swss {}/{} in its current "
                "20-minute window. One more restart may hit the start-limit and leave the box down. "
                "Wait for the window to clear, or pass --allow-start-limit if a restart here is "
                "intended.".format(spent, burst))
            say("run INVALID: arming would risk locking the switch. Not a finding.")
            return 2
    code = preflight(dut)
    if code:
        return code
    # Load interposers before the baseline, not inside a run: see preload_interposers.
    preload_interposers(dut, plan.injectors, names)
    code = gate(dut, names, args)
    if code:
        return code
    session = make_session(dut, lambda: ptf_for(dut))
    flips = 0
    inconclusive = 0
    try:
        for inj in plan.injectors:
            for w in inj.warnings():
                say("note: {}".format(w))
            say("chaos: apply {} on {}".format(inj.describe(), dut.hostname))
            session.apply(inj)
        settle = max(settle_of(i) for i in plan.injectors)
        tele_inj = next((i for i in plan.injectors
                         if (getattr(i, "params", {}) or {}).get("container")), None)
        for run in range(1, args.chaos_repeat + 1):
            say("settle {}s".format(settle))
            if tele_inj is not None:
                settle_with_telemetry(dut, tele_inj, settle)
            else:
                time.sleep(settle)
            fired_flags = []
            for inj in plan.injectors:
                try:
                    st = inj.status(dut)
                    brief = {k: st[k] for k in STATUS_KEYS if k in st}
                    say("status {}: {}".format(inj.name, json.dumps(brief, default=str)))
                    try:
                        fired_flags.append(inj.fired(st))
                    except Exception:
                        fired_flags.append(None)
                    flips += not_back(inj, st, inj.describe())
                    if ((st or {}).get("achieved") or {}).get("start_limit_hit"):
                        say("aborting the remaining {} repeat(s): swss is at systemd's start limit".format(
                            args.chaos_repeat - run))
                        break
                    if st.get("bit") is False:
                        say("note: cap bit is False -- the target never wanted more CPU than the cap allowed; this "
                            "fault was a no-op")
                except Exception as err:
                    say("status {}: unavailable ({!r})".format(inj.name, err))
            divs, after, ran = check(dut, names, "run{}".format(run))
            # Engaged unless every injector we could read says it did not fire; an unreadable
            # (None) status does not downgrade a run, only a definite no-op does.
            determinable = [f for f in fired_flags if f is not None]
            run_engaged = not determinable or any(determinable)
            if divs:
                flips += 1
                say("run{} FAILED  -- {}".format(run, fmt_divs(divs)))
            elif not run_engaged:
                inconclusive += 1
                say("run{} INCONCLUSIVE -- no fault engaged, so the parity pass proves nothing".format(run))
            else:
                say("run{} PASSED".format(run))
    finally:
        release_guarded(session, dut)
    say("verdict: {} runs / {} FAIL / {} inconclusive".format(args.chaos_repeat, flips, inconclusive))
    if RELEASE_FAILURES:
        return release_failed(dut)
    if flips:
        return 1
    return 5 if inconclusive else 0


def build_parser(prog="sonic-chaos run"):
    ap = argparse.ArgumentParser(prog=prog, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dut", default=os.environ.get("SONIC_CHAOS_DUT"),
                    help="the switch: ssh://user@host, local://, cmd:<prefix>, or a site scheme "
                         "(default: $SONIC_CHAOS_DUT)")
    ap.add_argument("--ptf", default=os.environ.get("SONIC_CHAOS_PTF"),
                    help="traffic peer for PTF-driven faults, same URL forms (default: $SONIC_CHAOS_PTF)")
    ap.add_argument("--profile", action="append", default=[], metavar="FILE|NAME",
                    help="target profile laid over the default (containers, daemons); repeatable")
    ap.add_argument("--chaos", action="append", default=[], metavar="INJECTOR=SPEC")
    ap.add_argument("--chaos-file", metavar="PATH",
                    help="experiment YAML, or the name of one shipped with sonic-chaos")
    ap.add_argument("--chaos-seed", type=int)
    ap.add_argument("--chaos-repeat", type=int, default=1)
    ap.add_argument("--allow-start-limit", action="store_true",
                    help="run a schedule of swss-daemon kills even though it will exceed systemd's start "
                         "limit and leave the switch down (default: refuse)")
    ap.add_argument("--chaos-dry-run", action="store_true")
    ap.add_argument("--invariant", action="append",
                    help="flags mode: invariant group (parity, health, signal, all) or an "
                         "explicit name. Repeatable. Default: parity")
    ap.add_argument("--probe", action="store_true", help="connect and run the steady-state check only")
    ap.add_argument("--baseline", action="store_true",
                    help="divergences present at steady state are recorded and ignored instead of making the "
                         "run INVALID")
    ap.add_argument("--no-before", action="store_true", help="skip the pre-fault snapshot (faster)")
    ap.add_argument("--snapshot", action="store_true",
                    help="dump APPL_DB, ASIC_DB and STATE_DB so the table-reading invariants "
                         "(lag, lag_member, neighbor, vlan_member, key_set_backlog) can run. Off "
                         "by default: it is ~40s per check, and the rest run straight on the box")
    ap.add_argument("--out", default=os.path.join("out", "chaos"), help="repro bundle directory")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not args.dut:
        ap.error("no switch given: pass --dut (or set SONIC_CHAOS_DUT), e.g. --dut ssh://admin@10.0.0.5")

    SNAPSHOTS[0] = args.snapshot
    PTF_URL[0] = args.ptf
    from ..injector import set_profiles
    set_profiles(args.profile)
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    try:
        dut = open_dut(args.dut)
    except ValueError as err:
        ap.error(str(err))
    say("sonic-chaos run -> {} ({})".format(dut.hostname, args.dut))

    def on_int(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGINT, on_int)
    signal.signal(signal.SIGTERM, on_int)

    try:
        if args.probe:
            res = dut.shell("hostname; show version | head -2", module_ignore_errors=True)
            say("dut: {}".format(" ".join(res["stdout"].split())))
            divs, snap, ran = check(dut, ["route_check", "key_set_backlog"], "probe")
            say("snapshot: {} keys".format(len(snap)) if SNAPSHOTS[0] else
                "snapshot: skipped, the checks that ran need no database dump")
            say("steady state: {}".format("pass" if not divs else "FAILED " + fmt_divs(divs)))
            return EXIT_HELD if not divs else EXIT_INVALID
        if args.chaos_file:
            exp = Experiment.from_file(resolve_experiment(args.chaos_file))
            seed = args.chaos_seed if args.chaos_seed is not None else (
                exp.seed if exp.seed is not None else int(time.time()))
            return run_experiment(dut, exp, seed, args)
        if args.chaos:
            plan = ChaosPlan.from_args(args.chaos, dry_run=args.chaos_dry_run)
            for inj in plan.injectors:
                inj.validate()
            return run_flags(dut, plan, args)
        ap.error("give --chaos-file, --chaos, or --probe")
    except ChaosUsageError as err:
        say("usage error: {}".format(err))
        return EXIT_USAGE
    except KeyboardInterrupt:
        say("interrupted: faults were released on the way out")
        return EXIT_INTERRUPTED
    except RuntimeError as err:
        # Something on the DUT side failed outside a fault slot (gate, pre-fault snapshot,
        # release). One line, not a traceback: the message already names the command and host.
        say("dut error: {}".format(err))
        return EXIT_DUT_ERROR


SHIPPED_EXPERIMENTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments")


def resolve_experiment(name):
    """A path as given, or the name of an experiment shipped in sonic_chaos/experiments/."""
    if os.path.isfile(name):
        return name
    for candidate in (name, name + ".yml"):
        path = os.path.join(SHIPPED_EXPERIMENTS, candidate)
        if os.path.isfile(path):
            return path
    raise ChaosUsageError("no experiment file {!r} (and no shipped experiment by that name: {})".format(
        name, ", ".join(sorted(f[:-4] for f in os.listdir(SHIPPED_EXPERIMENTS) if f.endswith(".yml")))))


if __name__ == "__main__":
    sys.exit(main())
