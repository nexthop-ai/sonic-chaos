"""Squeeze lane -- HOG: hold a container at X% CPU, or at a memory ceiling it is already touching.

    --chaos hog=swss:cpu=40               swss is held at 40% of one core
    --chaos hog=orchagent:cpu=40          names a process -> hogs the container it lives in
    --chaos hog=swss:cpu=40:cores=2       the budget is 2 cores, so 40% of them = 80% of one core
    --chaos hog=swss:mem=30               a balloon holds 30% more than the container's own usage
    --chaos hog=bgp:cpu=50:mem=25         both at once

The difference from ``cpu`` and ``mem``, which are CAPS
------------------------------------------------------
A cap says *you may use at most X*. On an idle switch that changes nothing: orchagent was not
asking for more than X anyway, so the test passes and reports a fault that never bit. Measured on
a lab switch: orchagent under ``cpu.max=50000 100000`` sat at 0.0%, because it was idle. A ceiling
cannot make a process spend.

A hog says *X is already spent*. Two knobs, and each is useless without the other:

**1. Bound the budget** -- ``cpu.max`` on the container's scope, so there is a fixed pool to fight
over. Without it a spinner on a 16-core box just takes an idle core and nothing contends.

**2. Spend it** -- a load process inside the container that keeps the budget pinned at its
ceiling. Now ``docker stats`` reads X%, the kernel's ``nr_throttled`` climbs, and every daemon in
the container queues behind the load for each slice.

Why the load runs *inside* the container
----------------------------------------
It would be simpler to spawn the spinners on the host and write their PIDs into the container's
``cgroup.procs``. That throttles correctly -- but cgroup membership and the PID namespace are
independent, so the load is **invisible** to ``top`` inside the container and ``docker top`` never
lists it. Found exactly that way on a lab switch: the container measured 40% while ``top`` in swss
showed nothing above 0.5%, which reads as a measurement bug rather than as a fault.

``docker exec -d`` puts the load in both the cgroup *and* the namespace, so the three views agree::

    inside swss:  top -o %CPU     ->  two bash at 19.9 + 19.4   = 39.3%
    inside swss:  cpu.stat delta  ->  1989 ms / 5000 ms         = 39%
    on the host:  docker stats    ->  39.93%

``exec -a`` is a bash builtin: the container's ``/bin/sh`` is dash and drops it silently, leaving
processes that ``release`` cannot find by name. Always ``bash -c``.

No cpuset pinning
-----------------
An earlier cut of this injector pinned the container to N cores and put the parasites in a sibling
cgroup on the same cores. It worked, but the pin is a perturbation in its own right -- orchagent
normally has all 16 -- so every finding had to be read knowing the target had been moved. Worse,
a container's ``cpuset.cpus`` is normally *empty* (meaning "inherit"), and writing an empty string
back fails with ENOSPC, so release left the container pinned to one core. Bounding with ``cpu.max``
alone needs no pin and no restore, and the share is enforced by the kernel either way.

Why ``memory.high`` and not ``memory.max``
------------------------------------------
This platform has **no swap** (verified on a lab switch: ``Swap: 0``). Under ``memory.max`` a cgroup
that hits the wall is OOM-killed, not slowed -- so the "fault" would be an execution, and every
result would read as a crash rather than as pressure. ``memory.high`` throttles the allocator and
forces reclaim instead: the daemon stays alive and gets slower, which is the thing worth testing.
``memory.events``'s ``high`` counter climbing is the proof it bit.

Safety: a DUT-side dead-man kills the load and restores both knobs if we never come back.
``release`` is idempotent, and restores ``cpu.max``/``memory.high`` even if a kill fails.
"""
import logging
import math

from ..injector import (
    Injector, ChaosUsageError, register, require_target, as_bool, run, quote, deadman_tag,
    sudo_prefix,
)

logger = logging.getLogger(__name__)

SCOPE_FMT = "/sys/fs/cgroup/system.slice/docker-{}.scope"
PERIOD_US = 100000
MARKER = "sonic-chaos-hog"      # argv[0] of every load process, so release can find them all
# `pgrep -f sonic-chaos-hog` also matches the shell that is running the pgrep, and the dead-man,
# whose own command line quotes the marker. That inflated status()["load"] to 6 for two spinners
# on a lab switch, and it means a `pkill -f` can shoot the shell issuing it. The bracket makes the
# pattern match the argv of a real load process and nothing that merely mentions it.
PATTERN = "[{}]{}".format(MARKER[0], MARKER[1:])
MAX_SPINNERS = 16


@register
class HogInjector(Injector):
    name = "hog"
    lane = "squeeze"
    positional = ("process", "cpu")
    defaults = {"cpu": "0", "mem": "0", "cores": "1", "ttl": "900", "settle": "20"}

    def validate(self):
        p = self.params
        if "process" not in p:
            raise ChaosUsageError("hog: needs a process or container, e.g. hog=swss:cpu=40")
        for key, lo, hi in (("cpu", 0, 100), ("mem", 0, 95), ("cores", 1, 16), ("ttl", 30, 7200),
                            ("settle", 0, 7200)):
            try:
                value = int(p[key])
            except ValueError:
                raise ChaosUsageError("hog: {} must be an integer, got {!r}".format(key, p[key]))
            if not lo <= value <= hi:
                raise ChaosUsageError("hog: {} must be {}..{}, got {}".format(key, lo, hi, value))
        # settle is the hold; ttl is the dead-man that must outlast it, or the hog is lifted before
        # the check reads it and the run passes without testing anything.
        if int(p["settle"]) >= int(p["ttl"]):
            raise ChaosUsageError(
                "hog: settle={}s is not shorter than ttl={}s, so the hog is lifted before the check "
                "reads it. ttl is a dead-man, not the hold -- raise ttl above the settle, or lower "
                "the settle.".format(p["settle"], p["ttl"]))
        if not int(p["cpu"]) and not int(p["mem"]):
            raise ChaosUsageError(
                "hog: nothing to hog -- give cpu=<pct>, mem=<pct>, or both. A hog with no load "
                "would report a fault that never happened.")
        if int(p["mem"]) > 80:
            raise ChaosUsageError(
                "hog: mem above 80% leaves a container almost nothing and reads as a crash, not "
                "as pressure. Use a cap (--chaos mem=...) if an OOM is what you actually want.")
        p["container"] = require_target(
            p["process"], as_bool(p.get("force", False), "hog: force"), "hog")
        self._scopes = {}       # hostname -> the container's resolved cgroup scope path
        self._baseline = {}     # hostname -> cgroup counters as they were before apply()

    # -- shape of the fault -------------------------------------------------------------------

    @property
    def tag(self):
        return deadman_tag("hog", self.params["container"])

    def quota(self):
        """``cpu.max`` for the container: ``cpu``% of ``cores`` cores.

        ``cpu=40 cores=1`` -> ``40000 100000``, which ``docker stats`` reports as 40%.
        """
        share = int(self.params["cores"]) * PERIOD_US * int(self.params["cpu"]) // 100
        return "{} {}".format(max(1000, share), PERIOD_US)

    def spinners(self):
        """Busy threads, enough to keep the budget pinned at its ceiling.

        The threads do not set the share -- ``cpu.max`` on the container does. They only have to
        ask for more than the quota, or the quota is never reached. One per core of quota, plus
        one so a partial core is still saturated: 40% of one core needs two.
        """
        if not int(self.params["cpu"]):
            return 0
        cores_of_quota = int(self.params["cores"]) * int(self.params["cpu"]) / 100.0
        return max(1, min(MAX_SPINNERS, int(math.ceil(cores_of_quota)) + 1))

    def scope(self, duthost):
        """The container's cgroup scope, resolved on the DUT once and cached per host.

        Resolved to a *literal path* rather than left as a ``$(docker inspect ...)`` substitution.
        The inspect format string contains single quotes, and every knob write goes through
        ``sh -c '...'``; embedding one in the other terminates the outer quote early, so the writes
        silently never happened while the load still spawned. That is a runaway on a live switch,
        and it is the reason this is a separate round-trip.
        """
        host = getattr(duthost, "hostname", str(duthost))
        if host not in self._scopes:
            sudo = sudo_prefix(duthost)
            rc, out, err = run(duthost, "{}docker inspect --format '{{{{.Id}}}}' {}".format(
                sudo, quote(self.params["container"])))
            cid = (out or "").strip()
            if rc != 0 or not cid:
                raise RuntimeError("hog: cannot resolve container {}: {}".format(
                    self.params["container"], (err or out)[:200]))
            path = SCOPE_FMT.format(cid)
            rc, _, _ = run(duthost, "test -d {}".format(quote(path)))
            if rc != 0:
                raise RuntimeError(
                    "hog: {} has no cgroup v2 scope at {} -- this platform is not on the unified "
                    "hierarchy, so the budget cannot be bounded".format(
                        self.params["container"], path))
            self._scopes[host] = path
        return self._scopes[host]

    # -- lifecycle ----------------------------------------------------------------------------

    def _sh(self, duthost, script):
        """Run one shell script on the DUT. ``script`` is quoted whole, so it may contain anything."""
        return run(duthost, "{}sh -c {}".format(sudo_prefix(duthost), quote(script)))

    def apply(self, duthost, **params):
        p = self.params
        sudo, scope, events = sudo_prefix(duthost), self.scope(duthost), []
        # nr_throttled and memory.events' `high` are CUMULATIVE for the life of the cgroup, so
        # comparing them against zero says "the fault bit" on any container that was ever
        # throttled -- including by a previous run of this very injector. Only the delta since
        # apply() is evidence, so record where the counters started.
        self._baseline[getattr(duthost, "hostname", str(duthost))] = self._counters(duthost, scope)

        if int(p["cpu"]):
            # 1. bound the budget.
            rc, _, err = self._sh(duthost, "echo '{}' > {}/cpu.max".format(self.quota(), scope))
            if rc != 0:
                raise RuntimeError("hog: could not bound {}: {}".format(p["container"], err[:200]))
            # 2. spend it, from inside the container's own PID namespace so the load is visible
            #    to `top` in there and counted by `docker stats`.
            load = ("for i in $(seq 1 {n}); do (exec -a {m} bash -c \"while :; do :; done\") & "
                    "done".format(n=self.spinners(), m=MARKER))
            rc, _, err = run(duthost, "{}docker exec -d {} bash -c {}".format(
                sudo, quote(p["container"]), quote(load)))
            if rc != 0:
                self._sh(duthost, "echo max > {}/cpu.max".format(scope))     # do not leave it bounded
                raise RuntimeError("hog: could not start the load in {}: {}".format(
                    p["container"], err[:200]))
            events.append("cpu: {} bounded at cpu.max={} ({}% of {} core(s)) and held there by {} "
                          "in-container spinner(s)".format(
                              p["container"], self.quota(), p["cpu"], p["cores"], self.spinners()))

        if int(p["mem"]):
            # memory.high (soft) not memory.max: no swap on this platform, so max kills.
            rc, _, _ = run(duthost, "{}docker exec {} sh -c 'command -v python3 >/dev/null'".format(
                sudo, quote(p["container"])))
            if rc != 0:
                raise RuntimeError(
                    "hog: {} has no python3, so the balloon cannot run inside it. Use a cap "
                    "(--chaos mem=...) on this container instead.".format(p["container"]))
            rc, base, _ = self._sh(duthost, "cat {}/memory.current".format(scope))
            baseline = int((base or "0").strip() or 0)
            if not baseline:
                raise RuntimeError("hog: could not read memory.current for {}".format(p["container"]))
            self._sh(duthost, "echo {} > {}/memory.high".format(baseline, scope))
            eat_mb = max(1, baseline * int(p["mem"]) // 100 // (1024 * 1024))
            # bytearray(b'\xa5' * 1MB) faults every page in. bytes(n) would be calloc'd from fresh
            # zero pages and never touched, so RSS would not move and the balloon would hold nothing.
            balloon = ("import time; h=[bytearray(b'\\xa5'*(1<<20)) for _ in range({})]; "
                       "time.sleep({})".format(eat_mb, int(p["ttl"])))
            load = "(exec -a {m} python3 -c {py}) &".format(m=MARKER, py=quote(balloon))
            run(duthost, "{}docker exec -d {} bash -c {}".format(
                sudo, quote(p["container"]), quote(load)))
            events.append("mem: {} bounded at {}M (memory.high), balloon holding ~{}M".format(
                p["container"], baseline // (1024 * 1024), eat_mb))

        # 3. dead-man: a lost session must not leave a switch hogged.
        self._arm_deadman(duthost, scope)
        logger.info("[hog] %s on %s: %s", self.describe(), duthost.hostname, "; ".join(events))
        return self.record(duthost, action="hog", container=p["container"],
                           cpu_pct=int(p["cpu"]), mem_pct=int(p["mem"]),
                           cores=int(p["cores"]), spinners=self.spinners(), events=events)

    def release(self, duthost):
        """Kill the load and put both knobs back. Safe to call twice."""
        p = self.params
        # Host-side pkill: the container's processes are visible in the host PID namespace, so this
        # works even when the container is too wedged to accept a `docker exec`.
        run(duthost, "{}pkill -9 -f {} || true".format(sudo_prefix(duthost), quote(PATTERN)))
        self._cancel_deadman(duthost)
        try:
            scope = self.scope(duthost)
        except RuntimeError as exc:              # container already gone: nothing left to restore
            logger.warning("[hog] no scope to restore for %s: %s", p["container"], exc)
            return
        # Restore unconditionally: a failed kill must not leave the budget bounded as well.
        for knob in ("cpu.max", "memory.high"):
            rc, _, err = self._sh(duthost, "echo max > {}/{}".format(scope, knob))
            if rc != 0:
                logger.error("[hog] could not restore %s on %s: %s", knob, p["container"], err[:150])
        logger.info("[hog] released %s on %s", self.describe(), duthost.hostname)

    def _counters(self, duthost, scope):
        """``nr_throttled`` and ``memory.events``'s ``high``, the two cumulative "it bit" counters."""
        rc, out, _ = self._sh(duthost, (
            "grep -E '^nr_throttled ' {s}/cpu.stat; grep -E '^high ' {s}/memory.events").format(
                s=scope))
        got = {"nr_throttled": 0, "high": 0}
        for line in (out or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in got:
                got[parts[0]] = int(parts[1] or 0)
        return got

    def status(self, duthost):
        """``achieved`` is measured, never the number that was requested.

        A hog that did not bite means the test ran without a fault, and reporting that as a pass
        under pressure is the easiest way to ship a false negative.
        """
        p = self.params
        scope = self.scope(duthost)
        rc, out, _ = self._sh(duthost, (
            # `pgrep -c` prints 0 AND exits 1 when nothing matches, so `|| echo 0` appends a
            # second 0 and status() used to int("0 0") -- i.e. it raised exactly when the hog was
            # not running. `| wc -l` always prints one number and always succeeds.
            "echo LOAD=$(pgrep -f {m} | wc -l); echo CPUMAX=$(cat {s}/cpu.max); "
            "grep -E '^(usage_usec|nr_throttled|throttled_usec)' {s}/cpu.stat; "
            "echo CUR=$(cat {s}/memory.current); echo HIGH=$(cat {s}/memory.high); "
            "grep -E '^(high|max|oom_kill) ' {s}/memory.events").format(m=quote(PATTERN), s=scope))
        fields = {}
        for line in (out or "").splitlines():
            # `cpu.max` is two words ("40000 100000"), so split on the first = and keep the rest
            # whole; splitting on whitespace dropped it entirely and reported cpu_max=None.
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key.strip()] = value.strip()
                continue
            parts = line.split()
            if len(parts) == 2:
                fields[parts[0]] = parts[1]
        alive = int(fields.get("LOAD", 0) or 0)
        base = self._baseline.get(getattr(duthost, "hostname", str(duthost)))
        throttled = int(fields.get("nr_throttled", 0) or 0)
        high = int(fields.get("high", 0) or 0)
        # None, not False: "we never took a baseline" is a different answer from "it did not bite",
        # and reporting the second when we mean the first is how a false negative ships.
        bit = None if base is None else (throttled > base["nr_throttled"] or high > base["high"])
        return {
            "active": alive > 0,
            "requested": {"cpu": int(p["cpu"]), "mem": int(p["mem"]), "cores": int(p["cores"])},
            "load": alive,
            "cpu_max": fields.get("CPUMAX"),
            # the DELTA in nr_throttled is the proof the budget was actually saturated
            "bit": bit,
            "achieved": {"throttled_usec": fields.get("throttled_usec"),
                         "memory_current_mb": int(int(fields.get("CUR", 0) or 0) / 1048576),
                         "throttles_since_apply": None if base is None else throttled - base["nr_throttled"],
                         "memory_high_since_apply": None if base is None else high - base["high"]},
            "oom_kill": int(fields.get("oom_kill", 0) or 0),
        }

    def observe(self, duthost, seconds=5):
        """Measured CPU percentage over a window -- the number ``docker stats`` would show.

        Reads the container's own ``cpu.stat`` twice. Reported as a share of one core, so a
        ``cpu=40 cores=1`` hog reads ~40 and a ``cpu=100 cores=2`` hog reads ~200.
        """
        scope = self.scope(duthost)
        rc, out, _ = self._sh(duthost, (
            "a=$(awk '/^usage_usec/{{print $2}}' {s}/cpu.stat); sleep {t}; "
            "b=$(awk '/^usage_usec/{{print $2}}' {s}/cpu.stat); echo $((b-a))").format(
                s=scope, t=int(seconds)))
        used_us = int((out or "0").strip() or 0)
        return round(used_us * 100.0 / (int(seconds) * 1000000.0), 1)

    # -- dead-man ------------------------------------------------------------------------------

    def _arm_deadman(self, duthost, scope):
        cleanup = "pkill -9 -f {}; echo max > {}/cpu.max; echo max > {}/memory.high".format(
            quote(PATTERN), scope, scope)
        timer = "sleep {}; {}".format(int(self.params["ttl"]), cleanup)
        # The tag is argv[0] of the sleeping shell, so _cancel_deadman can find exactly this one.
        self._sh(duthost, "setsid nohup sh -c {} {} >/dev/null 2>&1 &".format(
            quote(timer), quote(self.tag)))

    def _cancel_deadman(self, duthost):
        tag = self.tag
        run(duthost, "{}pkill -f '[{}]{}' || true".format(sudo_prefix(duthost), tag[0], tag[1:]))

    def expected_syslog(self):
        """A hogged container logs nothing by construction -- the pressure is in the counters,
        not the log. Anything a daemon says under it is the finding, so nothing is ignored."""
        return ()
