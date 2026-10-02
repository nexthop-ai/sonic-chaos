"""Spine lane -- lifecycle faults.

    --chaos kill=orchagent                  kill -9 the process; supervisor decides what follows
    --chaos kill=orchagent:how=restart      docker exec swss supervisorctl restart orchagent  (cold, no warm-start)
    --chaos kill=swss:how=container         docker restart swss

This is an *event* fault: ``apply`` fires once per call and ``release`` is a no-op by design.
Recovery is the system's job and is exactly the thing under test -- see DNX cold-restart / cold-restart route-loss,
both "orchagent-only restart leaves APPL_DB and ASIC_DB disagreeing". Pair with
``oracle.assert_consistent`` after a settle.

``apply`` does not raise when the daemon fails to come back. A box that does not recover is the
*finding*, and a fixture that raises turns a finding into a pytest ERROR with a stack trace
pointing at our own harness instead of at the bug. So a failed recovery is recorded, logged at
WARNING, and reported by ``status()`` -- the test's own assertions and the oracle's invariants
are what turn it into a verdict.

Hardware: ``settle=20`` is a VS number. A syncd container restart on a real ASIC re-inits the
chip and can take minutes; ``how=restart`` on orchagent with a DNX SAI is the DNX cold-restart repro
and the box may not come back on its own. Run those last, on a reserved testbed, with
``config reload`` / reboot as the recovery plan.
"""
import logging

from ..injector import (
    sudo_prefix,
    Injector, ChaosUsageError, register, require_target, as_bool, is_container,
    run, quote, supervisor_status, container_running, poll,
)

logger = logging.getLogger(__name__)


# Teardown of swss after a critical-process exit took 33 s on a lab switch before systemd began the
# restart, and the daemons need time to come up after that. Below this, "did not recover" is
# guaranteed and means nothing.
CONTAINER_RECOVERY_FLOOR_S = 90


@register
class KillInjector(Injector):
    name = "kill"
    lane = "spine"
    positional = ("process",)
    defaults = {"how": "sigkill", "signal": "9", "settle": "20"}

    HOWS = ("sigkill", "restart", "container")

    def validate(self):
        p = self.params
        if p["how"] not in self.HOWS:
            raise ChaosUsageError("kill: how must be one of {}, got {!r}".format("/".join(self.HOWS), p["how"]))
        for k in ("signal", "settle"):
            try:
                int(p[k])
            except ValueError:
                raise ChaosUsageError("kill: {} must be an integer, got {!r}".format(k, p[k]))

        force = as_bool(p.get("force", False), "kill: force")
        process, container = p.get("process"), p.get("container")
        if not process and not container:
            raise ChaosUsageError(
                "kill: needs a process or a container, e.g. kill=orchagent or "
                "kill=container=swss:how=container")

        # The positional slot is named `process`, but a container name may arrive through it
        # (`kill=swss:how=container`). Sorting that out here is what stops `pkill -x swss` from
        # matching nothing and reporting a kill that never happened.
        if process and is_container(process) and not container:
            container, process = process, None

        if process:
            owning = require_target(process, force, "kill")
            if container and require_target(container, force, "kill") != owning:
                raise ChaosUsageError(
                    "kill: process {!r} runs in container {!r}, not {!r}. Drop the container "
                    "parameter, or name a process that lives in it.".format(
                        process, owning, container))
            container = owning
        else:
            container = require_target(container, force, "kill")

        if p["how"] != "container" and not process:
            raise ChaosUsageError(
                "kill: how={} acts on a daemon, but only the container {!r} was named. Give a "
                "process (kill=orchagent:how={}), or use how=container to restart the whole "
                "container.".format(p["how"], container, p["how"]))

        p["process"], p["container"] = process, container

    def command(self):
        p = self.params
        if p["how"] == "container":
            return "docker restart {}".format(p["container"])
        if p["how"] == "restart":
            return "docker exec {} supervisorctl restart {}".format(p["container"], quote(p["process"]))
        return "docker exec {} pkill -{} -x {}".format(p["container"], p["signal"], quote(p["process"]))

    # -- lifecycle ---------------------------------------------------------------------------

    def apply(self, duthost, **params):
        p = dict(self.params, **params)
        container, process, how = p["container"], p.get("process"), p["how"]
        settle = int(p["settle"])

        before = self._probe(duthost, container, process)
        # A fresh container restarts its pid space, so after a critical-process kill orchagent
        # comes back with the SAME in-container pid (191 on a lab switch) and the "different pid"
        # heuristic reports "did NOT recover" against a daemon that is RUNNING. The container's
        # StartedAt cannot lie about a restart, so record it and judge recovery by it.
        before["started_at"] = self._started_at(duthost, container)
        cmd = self.command()
        logger.info("[kill] %s on %s: %s (was %s)", self.describe(), duthost.hostname, cmd, before)

        critical = how != "container" and self._critical(duthost, container, process)
        if critical:
            # Not a daemon restart: supervisor-proc-exit-listener treats an unexpected exit of a
            # critical process as fatal for the whole container. Measured on a lab switch -- SIGKILL to
            # orchagent, one second later "Terminating supervisor 'swss'", and the container came
            # back through systemd, which allows StartLimitBurst starts per interval. Say so, so a
            # kill that lands on a box near the limit reads as what it is.
            logger.warning("[kill] %s is listed in %s's critical_processes: killing it restarts the "
                           "WHOLE %s container (syncd, bgp, teamd follow), and spends one of "
                           "systemd's swss starts", process, container, container)
            # The recovery being measured is therefore a CONTAINER restart, and that has a floor:
            # the teardown alone took 33 s on a lab switch before systemd even began the restart. A 20 s
            # settle cannot see it come back, and reported "did NOT recover" against a daemon that
            # was RUNNING by the time status() ran. Wait at least the floor, and say so.
            if settle < CONTAINER_RECOVERY_FLOOR_S:
                logger.info("[kill] settle raised %ss -> %ss: a critical-process kill is a container "
                            "restart, and that takes at least that long to come back",
                            settle, CONTAINER_RECOVERY_FLOOR_S)
                settle = CONTAINER_RECOVERY_FLOOR_S
        rc, out, err = run(duthost, cmd)
        if rc != 0:
            # A failed *injection* is our bug, not the DUT's -- surface it rather than silently
            # reporting "no divergence found" for a fault that never happened.
            raise RuntimeError("kill: injection command failed on {} (rc={}): {}\n  {}".format(
                duthost.hostname, rc, (err or out).strip()[:300], cmd))

        recovered, elapsed = self._await_recovery(duthost, container, process, how, before, settle)
        if not recovered:
            logger.warning("[kill] %s on %s did NOT recover within %ss -- that is the finding, not an "
                           "error; status() and the repro bundle carry it", process, duthost.hostname, settle)

        return self.record(
            duthost, action="kill", command=cmd, how=how, process=process, container=container,
            pid_before=before.get("pid"), pid_after=self._probe(duthost, container, process).get("pid"),
            started_before=before.get("started_at"), started_after=self._started_at(duthost, container),
            recovered=recovered, recovered_after_s=elapsed, settle_budget_s=settle,
            start_limit_hit=bool(getattr(self, "_start_limit_hit", False)))

    def release(self, duthost):
        # No-op by design: an event fault has nothing to undo. Recovery is the system's job and
        # is the thing under test; status() reports whether the process came back.
        logger.info("[kill] release is a no-op for event faults (%s on %s)", self.describe(), duthost.hostname)

    def status(self, duthost):
        p = self.params
        state = self._probe(duthost, p["container"], p.get("process"))
        last = (self.events() or [{}])[-1]
        # "recovered" at apply time and "recovered" now are different questions. The first says
        # whether it came back inside the settle budget; the second is whether it is back at all
        # -- RUNNING with a pid that is not the one we killed. Reporting only the first produced
        # {"recovered": false, "state": "RUNNING"}, which reads as a contradiction.
        before = last.get("pid_before")
        now_pid = state.get("pid")
        started_before = last.get("started_before")
        if started_before:
            # container restart: back means RUNNING inside a container with a newer start time
            started_now = self._started_at(duthost, p["container"])
            back_now = bool(state.get("running")) and started_now not in ("", started_before)
        else:
            back_now = bool(state.get("running")) and (before is None or now_pid is None or now_pid != before)
        return {
            "active": bool(state.get("running")),
            "state": state.get("state"),
            "pid": now_pid,
            "achieved": {"recovered": last.get("recovered"), "after_s": last.get("recovered_after_s"),
                         "recovered_now": back_now, "within_settle": last.get("recovered"),
                         "start_limit_hit": last.get("start_limit_hit", False)},
        }

    # -- helpers -----------------------------------------------------------------------------

    def _started_at(self, duthost, container):
        """The container's StartedAt, or '' -- the one thing a container restart cannot hide."""
        rc, out, _ = run(duthost, "{}docker inspect --format '{{{{.State.StartedAt}}}}' {}".format(
            sudo_prefix(duthost), quote(container)))
        return (out or "").strip() if rc == 0 else ""

    def _critical(self, duthost, container, process):
        """Is ``process`` in the container's supervisor critical_processes list?"""
        if not process:
            return False
        rc, out, _ = run(duthost, "{}docker exec {} cat /etc/supervisor/critical_processes 2>/dev/null"
                         .format(sudo_prefix(duthost), quote(container)))
        return rc == 0 and ("program:" + process) in (out or "").split()

    def _probe(self, duthost, container, process):
        """Current liveness of the target: ``{"running": bool, "state": str, "pid": int|None}``.

        For a container target, ``docker inspect`` is the truth. For a daemon, supervisor's own
        view is -- it is what decides whether to restart it, so it is the view that matters.
        """
        if self.params["how"] == "container" or not process or process == container:
            up = container_running(duthost, container)
            return {"running": up, "state": "RUNNING" if up else "DOWN", "pid": None}
        if not container_running(duthost, container):
            return {"running": False, "state": "CONTAINER_DOWN", "pid": None}
        entry = supervisor_status(duthost, container, process)
        return {"running": entry.get("state") == "RUNNING", "state": entry.get("state"), "pid": entry.get("pid")}

    def _await_recovery(self, duthost, container, process, how, before, settle):
        """Poll until the target is back. Returns ``(recovered, seconds_elapsed)``.

        "Back" means RUNNING *with a different pid* than before: supervisor restarts fast enough
        that a status check right after the kill can still show the old, already-dead process.
        When we never saw a pid to begin with (container restarts, or a process that was already
        down) RUNNING alone is the best signal available.
        """
        old_pid, old_start = before.get("pid"), before.get("started_at")
        critical = how != "container" and self._critical(duthost, container, process)

        def up():
            now = self._probe(duthost, container, process)
            if not now.get("running"):
                return False
            if critical and old_start:
                # the whole container went down: it is back when it has a NEW start time and
                # the daemon is RUNNING inside it -- the pid will very likely be the same
                return self._started_at(duthost, container) not in ("", old_start)
            if old_pid is None or now.get("pid") is None:
                return True
            return now["pid"] != old_pid

        # systemd's start limit counts STARTS, manual recoveries included: on a lab switch a
        # `systemctl start swss` plus two kill-induced restarts inside 20 minutes was the third.
        # Once it has given up there is nothing to wait for; the daemon will not come back on its
        # own, and spending the rest of the settle proves only that.
        self._start_limit_hit = False

        def up_or_given_up():
            if up():
                return True
            rc, out, _ = run(duthost, "{}systemctl show {} -p Result --value".format(
                sudo_prefix(duthost), quote(container)))
            if rc == 0 and "start-limit" in (out or ""):
                self._start_limit_hit = True
                return True          # stop polling; `recovered` is decided below
            return False
        recovered, elapsed = poll(up_or_given_up, timeout=settle, interval=2)
        if self._start_limit_hit:
            recovered = False
            logger.error("[kill] %s hit systemd's start limit on %s after this kill: swss, syncd, "
                         "bgp and teamd stay down until `systemctl reset-failed %s && systemctl "
                         "start %s`. Not a slow recovery -- systemd has stopped trying.",
                         container, duthost.hostname, container, container)
        if recovered and how == "container":
            # A container that is "running" still has to bring its daemons up; give the
            # supervisor tree the rest of the budget before we call the box settled.
            procs, extra = poll(
                lambda: all(e.get("state") in ("RUNNING", "EXITED")
                            for e in (supervisor_status(duthost, container) or {"_": {}}).values()),
                timeout=max(0, settle - elapsed), interval=3)
            elapsed = round(elapsed + extra, 1)
        return recovered, elapsed

    def expected_syslog(self):
        """Supervisor's exit/spawn chatter for a process we killed on purpose.

        Only the *injection's own* noise is listed. The daemon's own errors are deliberately not
        here: those are the finding, and an ignore rule that swallowed them would defeat the
        whole exercise.
        """
        p = self.params
        process, container = p.get("process"), p["container"]
        if p["how"] == "container":
            return (
                r".* INFO exited: .* \(terminated by SIGTERM.*\).*",
                r".* WARNING exited: .* \(terminated by SIGTERM.*\).*",
                r".* ERR monit.*Expected containers not running: {}.*".format(container),
                r".* ERR .*#supervisor-proc-exit-listener: Process .* exited unexpectedly.*",
            )
        return (
            r".* INFO exited: {} \(terminated by SIG.*\).*".format(process),
            r".* WARNING exited: {} \(terminated by SIG.*\).*".format(process),
            r".* INFO spawned: '{}' with pid.*".format(process),
            r".* ERR .*#supervisor-proc-exit-listener: Process {} exited unexpectedly.*".format(process),
            r".* ERR .*#supervisor-proc-exit-listener: Process {} is not running.*".format(process),
        )
