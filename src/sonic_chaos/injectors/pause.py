"""Spine lane -- freeze a daemon or a whole container for N seconds, then thaw it.

    --chaos pause=orchagent:10              SIGSTOP orchagent for 10 s, then SIGCONT
    --chaos pause=syncd:5                   every SAI call blocks for 5 s (the Shim bail-out)
    --chaos pause=swss:10:how=docker        docker pause the whole container

Why this earns its place next to ``cpu``: a budget cap only bites while the target is busy, so
an idle daemon never notices it. A freeze bites immediately and deterministically, needs no
cgroup, and is the cheapest way to blow a fixed timeout on purpose -- wpa_cli gives orchagent
10 s, sairedis gives syncd 60 s, LACP gives teamd 3 s x3.

On thaw the daemon finds a redis backlog waiting for it, which is the interesting half: the
freeze creates the backlog, the thaw tests whether it drains correctly. Pair with
``oracle.key_set_backlog`` and a settle.

Safety, in two layers. ``apply`` freezes and returns immediately -- it does not block the test
for ``seconds`` -- and arms a **dead-man timer on the DUT** that thaws unconditionally after the
budget expires. ``release`` thaws on the normal path and disarms the timer. Either path alone
restores the daemon, so an SSH drop, a killed harness, or a Ctrl-C cannot leave a daemon
SIGSTOPped on a shared box. ``docker pause`` on the database container stays refused via
targets.yml -- that cascades with no clean recovery path.
"""
import logging

from ..injector import (
    Injector, ChaosUsageError, register, require_target, as_bool, is_container,
    run, quote, arm_deadman, disarm_deadman, deadman_tag,
)

logger = logging.getLogger(__name__)


@register
class PauseInjector(Injector):
    name = "pause"
    lane = "spine"
    positional = ("process", "seconds")
    defaults = {"seconds": "10", "how": "signal"}

    HOWS = ("signal", "docker")
    # The dead-man fires a little after the requested freeze, so the normal release wins the race
    # on a healthy run and the timer only ever fires when we really are gone.
    DEADMAN_GRACE = 10

    def validate(self):
        p = self.params
        if p["how"] not in self.HOWS:
            raise ChaosUsageError("pause: how must be one of {}, got {!r}".format(
                "/".join(self.HOWS), p["how"]))
        try:
            seconds = int(p["seconds"])
        except ValueError:
            raise ChaosUsageError("pause: seconds must be an integer, got {!r}".format(p["seconds"]))
        if not 1 <= seconds <= 300:
            raise ChaosUsageError("pause: seconds must be 1..300, got {}".format(seconds))

        force = as_bool(p.get("force", False), "pause: force")
        process, container = p.get("process"), p.get("container")
        if not process and not container:
            raise ChaosUsageError(
                "pause: needs a process or a container, e.g. pause=orchagent:10 or "
                "pause=10:container=swss:how=docker")

        # The positional slot is named `process` for backwards compatibility, but a container
        # name may legitimately arrive through it (`pause=swss:10:how=docker`). Sort that out
        # here rather than letting `pkill -STOP -x swss` match nothing and report a freeze that
        # never happened.
        if process and is_container(process) and not container:
            container, process = process, None

        if process:
            owning = require_target(process, force, "pause")
            if container and require_target(container, force, "pause") != owning:
                raise ChaosUsageError(
                    "pause: process {!r} runs in container {!r}, not {!r}. Drop the container "
                    "parameter, or name a process that lives in it.".format(
                        process, owning, container))
            container = owning
        else:
            container = require_target(container, force, "pause")

        if p["how"] == "signal" and not process:
            raise ChaosUsageError(
                "pause: how=signal freezes a daemon, but only the container {!r} was named. Give "
                "a process (pause=orchagent:{}), or use how=docker to freeze the whole "
                "container.".format(container, seconds))

        p["process"], p["container"] = process, container
        self._frozen = set()   # hostnames currently frozen by us

    def freeze_cmd(self):
        p = self.params
        if p["how"] == "docker":
            return "docker pause {}".format(p["container"])
        return "docker exec {} pkill -STOP -x {}".format(p["container"], quote(p["process"]))

    def thaw_cmd(self):
        p = self.params
        if p["how"] == "docker":
            return "docker unpause {}".format(p["container"])
        return "docker exec {} pkill -CONT -x {}".format(p["container"], quote(p["process"]))

    def deadman_name(self):
        return deadman_tag("pause", self.params["container"], self.params.get("process") or "container")

    # -- lifecycle ---------------------------------------------------------------------------

    def apply(self, duthost, **params):
        """Freeze the target and arm the DUT-side thaw. Returns immediately -- it does not sleep.

        Not sleeping is deliberate: the fault's whole purpose is to be in place *while the test
        runs*, so the test is what experiences the freeze. The freeze is bounded by the dead-man
        timer on the box and by ``release``, never by us blocking here.
        """
        p = dict(self.params, **params)
        seconds = int(p["seconds"])
        cmd = self.freeze_cmd()

        rc, out, err = run(duthost, cmd)
        if rc != 0:
            raise RuntimeError("pause: freeze failed on {} (rc={}): {}\n  {}".format(
                duthost.hostname, rc, (err or out).strip()[:300], cmd))

        # Dead-man first-class: if we never come back, the box thaws itself. The timer runs the
        # same thaw command release() does, and both are safe to run twice.
        pid = arm_deadman(duthost, self.deadman_name(), seconds + self.DEADMAN_GRACE, [self.thaw_cmd()])
        self._frozen.add(duthost.hostname)

        frozen = self._is_frozen(duthost)
        logger.info("[pause] %s on %s: %s (thaws by itself in %ss)",
                    self.describe(), duthost.hostname, cmd, seconds + self.DEADMAN_GRACE)
        return self.record(duthost, action="pause", command=cmd, thaw_command=self.thaw_cmd(),
                           seconds=seconds, how=p["how"], deadman_pid=pid, verified_frozen=frozen)

    def release(self, duthost):
        """Thaw unconditionally and cancel the dead-man. Safe to call twice."""
        cmd = self.thaw_cmd()
        run(duthost, cmd)   # thawing a running process is harmless, so this needs no guard
        disarm_deadman(duthost, self.deadman_name())
        self._frozen.discard(duthost.hostname)
        logger.info("[pause] release on %s: %s", duthost.hostname, cmd)

    def status(self, duthost):
        frozen = self._is_frozen(duthost)
        return {
            "active": bool(frozen),
            "frozen": frozen,
            "achieved": {"frozen": frozen, "seconds": int(self.params["seconds"])},
        }

    # -- helpers -----------------------------------------------------------------------------

    def _is_frozen(self, duthost):
        """Is the target actually stopped right now? ``None`` when we cannot tell.

        For a signal freeze the truth is process state ``T`` (stopped) in ``/proc/<pid>/stat``;
        ``ps`` inside the container reports it without needing a PID lookup. For a container
        freeze, ``docker inspect`` reports the paused state directly.
        """
        p = self.params
        if p["how"] == "docker":
            rc, out, _ = run(duthost, "docker inspect -f '{{{{.State.Paused}}}}' {}".format(p["container"]))
            return out.strip() == "true" if rc == 0 else None
        rc, out, _ = run(duthost, "docker exec {} ps -o stat=,comm= -C {} 2>/dev/null".format(
            p["container"], quote(p["process"])))
        if rc != 0 or not out.strip():
            return None
        # A stopped process shows state 'T'; the flag letters that may follow it are irrelevant.
        return any(line.strip().startswith("T") for line in out.strip().splitlines())

    def expected_syslog(self):
        """A frozen daemon misses its heartbeats, and the watchdogs say so.

        These are the supervisor/monit complaints the freeze necessarily causes. The *timeouts*
        it provokes in other daemons (sairedis 60 s, LACP, wpa_cli) are deliberately absent --
        those are precisely what this fault exists to find.
        """
        p = self.params
        patterns = [r".* ERR monit.*Expected containers not running: {}.*".format(p["container"])]
        process = p.get("process")
        if process:
            patterns += [
                r".* ERR monit.*'{}' process is not running.*".format(process),
                r".* INFO monit.*'{}'.*".format(process),
            ]
        else:
            # A whole frozen container: every daemon in it stops answering at once, so the
            # complaint names the container rather than any one process.
            patterns.append(r".* ERR .*{}.*not running.*".format(p["container"]))
        return tuple(patterns)
