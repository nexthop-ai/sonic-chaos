"""Shim lane -- SPIN: peg a daemon's event loop at 100% CPU while it services nothing.

    --chaos spin=orchagent:95           orchagent's dispatch thread is held at 95%
    --chaos spin=orchagent:100          pinned; the loop barely turns
    --chaos spin=orchagent:95:ttl=120   released unconditionally after two minutes

The state this exists for
-------------------------
RouteOrch-livelock and an RFC5549 case are the same shape: RouteOrch reprocessing a retry set
that never shrinks, pegging orchagent's one thread. Nothing else in the catalogue produces it::

    cpu=orchagent:3     descheduled. Loop intact, every consumer still serviced, CPU reads LOW.
    hog=swss:cpu=90     same, contention from other processes in the cgroup.
    pause=orchagent:10  services nothing, CPU reads ZERO, and it is total rather than partial.
    spin=orchagent:70   the thread spends 70 ms of every 100 spinning, 30 working. CPU reads high,
                        and it drains in bursts: late, not gone.
    spin=orchagent:100  the thread burns CPU inside one call. CPU reads 100%, nothing serviced.

The difference is not academic. orchagent dispatches every orch from a single
``m_select->select()`` loop (orchdaemon.cpp:1276), so a stuck handler starves PortOrch,
NeighOrch, FdbOrch and CoppOrch as well. A test asserting "a LAG member change is still
processed while routes churn" *passes* under a cap and *fails* under the real bug -- so the cap
is not a weaker version of this fault, it is a different one.

Measured with the stand-in daemon in ``shim/test/``: at 100, a loop draining a backlog went from
3,680,266 iterations in two seconds to **0**, while CPU read 100% both times. That is the whole
point -- ``top`` cannot tell "busy and productive" from "live-locked", which is exactly why this
bug is hard to catch in the field.

Below 100, ``percent`` is a share of wall time, charged per 100 ms period rather than per call:
measured under load it held at 31 / 51.7 / 72.3 / 93.0 % for 30 / 50 / 70 / 90. It used to be
charged per call, which let a daemon draining a backlog burn back to back -- on a lab switch a
requested 70 ran at 93%. An earlier version of this docstring quoted "22 iterations at 95" as
the live-lock; that was the per-call charging, and the live-lock is 100.

What it does not reproduce
--------------------------
The retry set growing, the O(K**2) cost, the memory growth, or the fact that the real live-lock
never recovers. This one disarms in 250 ms. It reproduces the *state*, not the root cause: right
for "what breaks downstream when orchagent live-locks", wrong for "does the RouteOrch fix work".

Cost: the first arm restarts swss, because ``LD_PRELOAD`` only takes effect at process start.
After that, arming and disarming are file writes the interposer notices within 250 ms.
"""
import logging
import os
import time

from ..injector import (
    Injector, ChaosUsageError, register, require_target, as_bool, run, poll, sudo_prefix,
    arm_deadman, disarm_deadman, deadman_tag,
)
from ..preload import Preload

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
SPIN_BINARY = os.path.normpath(os.path.join(_HERE, os.pardir, "shim", "build",
                                            "sonic_chaos_spin.so"))

CONTROL_FILE = "/sonic-chaos/spin_control.json"
STATS_FILE = "/sonic-chaos/spin_stats.json"
RESTART_TIMEOUT = 300
SETTLE_TIMEOUT = 300     # a restarted orchagent rebuilds its view; do not arm into that
SETTLE_PCT = 20
RELOAD_SETTLE = 1.0      # the interposer re-reads the control file at most every 250 ms

# Where spin is validated end-to-end today. orchagent (launcher edit) and vlanmgrd (binary
# swap) are proven on hardware; portsyncd and neighsyncd share vlanmgrd's swss/epoll path.
# Everything else is deferred, not broken: FRR (bgpd, zebra, fpmsyncd, bfdd) lives in the bgp
# container whose supervisord.conf regenerates on restart, and lldpd blocks in read(), not a
# pollable wait. The interposer already handles epoll/poll/ppoll; the remaining work is proving
# the wiring survives each container, so these are gated behind an allowlist with a "coming
# soon" message rather than allowed to arm and silently do nothing.
SPIN_SUPPORTED = ("orchagent", "vlanmgrd", "portsyncd")

FREEZE_HINT = ("\nOr use the fault that needs no build, if the CPU signature does not matter to "
               "you: --chaos pause=orchagent:10")


@register
class SpinInjector(Injector):
    name = "spin"
    lane = "shim"
    positional = ("process", "percent")
    defaults = {"percent": "95", "ttl": "300", "settle": "20"}

    def validate(self):
        p = self.params
        if "process" not in p:
            raise ChaosUsageError("spin: needs a process, e.g. spin=orchagent:95")
        for key, lo, hi in (("percent", 1, 100), ("ttl", 30, 3600), ("settle", 0, 3600)):
            try:
                value = int(p[key])
            except ValueError:
                raise ChaosUsageError("spin: {} must be an integer, got {!r}".format(key, p[key]))
            if not lo <= value <= hi:
                raise ChaosUsageError("spin: {} must be {}..{}, got {}".format(key, lo, hi, value))
        # settle is the hold; ttl is the dead-man that must outlast it, or the spin is lifted before
        # the check reads it and the run passes without testing anything.
        if int(p["settle"]) >= int(p["ttl"]):
            raise ChaosUsageError(
                "spin: settle={}s is not shorter than ttl={}s, so the spin is lifted before the "
                "check reads it. ttl is a dead-man, not the hold -- raise ttl above the settle, or "
                "lower the settle.".format(p["settle"], p["ttl"]))
        p["container"] = require_target(
            p["process"], as_bool(p.get("force", False), "spin: force"), "spin")
        if p["process"] not in SPIN_SUPPORTED:
            raise ChaosUsageError(
                "spin on {} is not supported yet -- coming soon. For now spin works on: {}.".format(
                    p["process"], ", ".join(SPIN_SUPPORTED)))

    @property
    def preload(self):
        # Wired into orchagent.sh, not supervisord: the swss container re-renders
        # supervisord.conf from a j2 on every start, so that edit is wiped by the very restart
        # meant to activate it. See preload.py.
        return Preload("spin", self.params["container"], self.params["process"],
                       "sonic_chaos_spin.so", SPIN_BINARY,
                       launcher="/usr/bin/{}.sh".format(self.params["process"]))

    def _deadman_tag(self):
        return deadman_tag("spin", self.params["process"])

    def _stats(self, duthost):
        return self.preload.read_json(duthost, STATS_FILE)

    def _restart(self, duthost):
        """Restart the whole container so the daemon comes up with the interposer.

        Not ``supervisorctl restart orchagent``, tempting as it is: that restarts orchagent
        while syncd keeps its ASIC view, so orchagent comes up empty and reconciles against
        it. On a settled, near-empty box that finishes in seconds; on a lab switch with real
        state it left orchagent pegged at 100% and silent in syslog for minutes, with
        ASIC_DB shrinking under it -- indistinguishable from the fault we are here to
        inject, and it never settled. Restarting the container bounces syncd too, so both
        sides cold-start and there is nothing to reconcile.

        This is the expensive half of the lane: it re-initialises the ASIC. apply() only
        gets here when the interposer is not already loaded, so it is once per box.
        """
        container = self.params["container"]
        logger.warning("[spin] restarting %s on %s to load the interposer into %s (this "
                       "disrupts the data plane and re-initialises the ASIC)",
                       container, duthost.hostname, self.params["process"])
        rc, _out, err = run(duthost, "{}systemctl restart {}".format(
            sudo_prefix(duthost), container))
        if rc != 0:
            raise RuntimeError("[spin] systemctl restart {} failed on {}: {}".format(
                container, duthost.hostname, err.strip()))

        back, elapsed = poll(lambda: self.preload.loaded(duthost),
                             timeout=RESTART_TIMEOUT, interval=5)
        if not back:
            raise RuntimeError(
                "[spin] {} did not come back with the interposer loaded on {} within {}s. "
                "Recover with `config reload -y -f` before trying again.".format(
                    self.params["process"], duthost.hostname, RESTART_TIMEOUT))
        logger.info("[spin] %s is back on %s with the interposer loaded after %ss",
                    self.params["process"], duthost.hostname, elapsed)

    def _cpu_pct(self, duthost, seconds=3):
        """The daemon's own CPU over a short window, as a percentage of one core."""
        script = ("p=$(pgrep -x {proc} | head -1); hz=$(getconf CLK_TCK); "
                  "a=$(awk '{{print $14+$15}}' /proc/$p/stat); sleep {t}; "
                  "b=$(awk '{{print $14+$15}}' /proc/$p/stat); "
                  "awk -v a=$a -v b=$b -v hz=$hz 'BEGIN{{printf \"%d\", (b-a)/hz/{t}*100}}'").format(
            proc=self.params["process"], t=seconds)
        _rc, out, _err = run(duthost, self.preload.in_container(duthost, script))
        try:
            return int((out or "").strip() or 0)
        except ValueError:
            return 0

    def _settle(self, duthost):
        """Wait for the daemon to finish its post-restart work before arming.

        A restarted orchagent rebuilds its whole view and syncd compares it against the live ASIC
        state, which is minutes of real work on a populated box. Arming into that window is how
        this injector shipped its worst measurement: the fault went on top of a rebuild, so the
        100% reading could not be attributed, and lifting the fault did *not* bring the daemon
        back -- it sat at 100% until it was restarted again. Measured on a lab switch.

        Once settled, the same fault arms and releases cleanly: 0.0% -> 98.1% -> 0.2%.
        """
        settled, elapsed = poll(lambda: self._cpu_pct(duthost) < SETTLE_PCT,
                                timeout=SETTLE_TIMEOUT, interval=5)
        if not settled:
            raise RuntimeError(
                "[spin] {} was still above {}% CPU {}s after its restart on {}, so the fault "
                "would land on top of its rebuild and neither the measurement nor the release "
                "would mean anything. Let the box settle and try again.".format(
                    self.params["process"], SETTLE_PCT, SETTLE_TIMEOUT, duthost.hostname))
        logger.info("[spin] %s settled on %s after %ss", self.params["process"],
                    duthost.hostname, elapsed)

    def will_restart(self, duthost):
        # Mirrors apply(): the container restarts only to load the interposer when it is not
        # already loaded.
        return not self.preload.loaded(duthost)

    def apply(self, duthost, **params):
        p = self.params
        pre = self.preload
        pre.deploy(duthost, FREEZE_HINT)

        if not pre.loaded(duthost):
            self._restart(duthost)
        # Always, not just after a restart: arming onto a daemon that is already busy for its own
        # reasons gives a reading that cannot be attributed to the fault.
        self._settle(duthost)

        # seq is the clock: the interposer reloads on any mtime/size change, and a monotonic
        # seq makes "did it pick up my write" answerable from the stats file.
        seq = int(time.time())
        pre.write_file(duthost, CONTROL_FILE,
                       '{{"seq":{},"percent":{}}}'.format(seq, int(p["percent"])))
        time.sleep(RELOAD_SETTLE)

        arm_deadman(duthost, self._deadman_tag(), int(p["ttl"]),
                    pre.in_container(duthost, "rm -f {}".format(CONTROL_FILE)))
        logger.info("[spin] %s on %s: %s's dispatch loop held at %s%%, ttl %ss",
                    self.describe(), duthost.hostname, p["process"], p["percent"], p["ttl"])
        return self.record(duthost, action="spin", seq=seq, percent=int(p["percent"]),
                           container=p["container"])

    def release(self, duthost):
        """Disarm. Safe to call twice.

        The .so and the supervisord line stay: an unarmed interposer is a direct call through,
        and removing it would cost another swss restart on a box we are handing back. Call
        ``SpinInjector.uninstall(duthost)`` to take it off entirely.
        """
        # The control file first, the dead-man only once it is provably gone. The other order left
        # a crash loop behind: with swss down at release the rm failed silently, the dead-man was
        # already disarmed, and every swss restart re-read the file and re-armed the fault until
        # systemd hit start-limit-hit.
        rc, _out, err = self.preload.remove_file(duthost, CONTROL_FILE)
        _rc, left, _err = run(duthost, self.preload.in_container(
            duthost, "[ -e {} ] && echo present || echo gone".format(CONTROL_FILE)))
        if rc != 0 or (left or "").strip() != "gone":
            raise RuntimeError(
                "[spin] could not remove {} in the {} container on {} ({}): the fault may still be "
                "armed. The dead-man stays armed and removes it at ttl; check the container before "
                "relying on this box.".format(CONTROL_FILE, self.params["container"], duthost.hostname,
                                              (err or left or "no answer").strip()[:200]))
        disarm_deadman(duthost, self._deadman_tag())
        logger.info("[spin] disarmed %s on %s", self.describe(), duthost.hostname)

    def status(self, duthost):
        """``achieved`` is the interposer's own count of what it burned, not what was asked for."""
        pre = self.preload
        stats = self._stats(duthost)
        if stats is None:
            return {"active": False, "loaded": pre.loaded(duthost), "requested": int(self.params["percent"]),
                    "reason": "no stats file; the interposer has not run yet"}
        return {
            "active": bool(stats.get("percent")),
            "loaded": True,
            "requested": int(self.params["percent"]),
            "seq": stats.get("seq"),
            "achieved": {
                "percent": stats.get("percent"),
                "cycles": stats.get("cycles"),
                "spun_ms": stats.get("spun_ms"),
            },
            "pid": stats.get("pid"),
        }

    @classmethod
    def uninstall(cls, duthost, process="orchagent", container="swss"):
        """Take the interposer off the box entirely, and re-exec the daemon without it."""
        pre = Preload("spin", container, process, "sonic_chaos_spin.so", SPIN_BINARY,
                      launcher="/usr/bin/{}.sh".format(process))
        pre.remove_file(duthost, CONTROL_FILE)
        pre.uninstall(duthost)
        run(duthost, "{}systemctl restart {}".format(sudo_prefix(duthost), container))
        # After the restart, not before: the still-running daemon's interposer flushes its stats
        # every 250 ms, so a file removed first is simply written again before the restart lands.
        pre.remove_file(duthost, STATS_FILE)
        logger.info("[spin] uninstalled from %s on %s", container, duthost.hostname)
