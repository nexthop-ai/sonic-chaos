"""Squeeze lane -- cap a daemon's CPU share.

    --chaos cpu=orchagent:30            orchagent gets at most 30% of one core   (Tier 1, cgroup)
    --chaos cpu=swss:50                 the whole swss container gets 50%        (Tier 0, docker)
    --chaos cpu=orchagent:30:how=docker throttle the container orchagent lives in
    --chaos cpu=orchagent:30:ttl=300    release unconditionally after 5 minutes

The number is always the share the target *gets*. Budget mode is a hard ceiling that only bites
while the target is busy, which is deterministic and what we want first. Contend and load modes
are cut from the 24h scope; the validator says so rather than silently accepting them.

Two tiers, picked automatically from the target
-----------------------------------------------
**Tier 0 (``how=docker``)** -- ``docker update --cpus=0.5 swss``. One command, no cgroup work,
throttles every process in the container together. This is what a container target gets.

**Tier 1 (``how=cgroup``)** -- a *sibling* cgroup at ``/sys/fs/cgroup/sonic-chaos/<process>/``
with ``cpu.max`` set, and the daemon's pid moved into it. This is what a process target gets,
and it is the interesting one: starving orchagent alone, while every daemon that waits on it
runs at full speed, is what turns a fixed timeout into a failed test.

The sibling is not a preference. The container's own cgroup is a leaf *with processes in it*, so
cgroup v2's no-internal-processes rule forbids nesting a child under it. Root
``cgroup.subtree_control`` already lists ``cpu`` on a lab switch, so the sibling needs no delegation.

What the DUT-side agent adds
----------------------------
``chaos_agent.py`` owns the three things that make a number trustworthy and a box safe:

* **TTL dead-man.** Two independent timers per apply, so a dropped ssh session, a killed pytest
  or a crashed watcher still leave the switch unthrottled. Nothing this lane does outlives it.
* **PID watcher.** Spine's ``kill`` injector restarts swss and the new orchagent is born outside
  our cgroup. The watcher re-attaches it and counts how often it had to -- ``reattached`` in the
  status dict. Without it, a fault silently stops being applied halfway through a run.
* **Measurement.** ``achieved`` is the share the daemon actually got, from the cgroup's own
  ``cpu.stat``, and ``bit`` says whether the cap was ever hit at all. A cap that never bit means
  the daemon never wanted that much CPU and the test passed *without a fault* -- reporting that
  as a pass under pressure is the single easiest way to ship a false negative.

Calibrate before trusting any of it::

    sonic-chaos tool calibrate --dut ssh://admin@<switch>

``redis-server`` and ``database`` are refused via targets.yml: starving redis trips supervisor
health checks and restarts containers, which is a lost testbed rather than a finding.
"""
import logging

from ..injector import Injector, ChaosUsageError, register, require_target, as_bool, targets
from ..squeeze import SqueezeError, agent, flags

# Sibling cgroup under the v2 root. Not under the docker scope: that is a leaf with processes.
CGROUP_ROOT = "/sys/fs/cgroup/sonic-chaos"
CGROUP_PERIOD_US = 100000

logger = logging.getLogger(__name__)


@register
class CpuInjector(Injector):
    name = "cpu"
    lane = "squeeze"
    positional = ("process", "share")
    defaults = {"share": "50", "mode": "budget", "how": "auto", "ttl": "900", "interval": "5",
                "settle": "20"}

    HOWS = ("auto", "docker", "cgroup")

    def validate(self):
        p = self.params
        if "process" not in p:
            raise ChaosUsageError("cpu: needs a process or container, e.g. cpu=orchagent:30")
        try:
            share = int(p["share"])
        except ValueError:
            raise ChaosUsageError("cpu: share must be an integer percent, got {!r}".format(p["share"]))
        if not 1 <= share <= 100:
            raise ChaosUsageError("cpu: share must be 1..100, got {}".format(share))
        if p["mode"] != "budget":
            raise ChaosUsageError(
                "cpu: only mode=budget is in scope; contend/load are cut (got {!r})".format(p["mode"]))
        if p["how"] not in self.HOWS:
            raise ChaosUsageError("cpu: how must be one of {}, got {!r}".format(
                "/".join(self.HOWS), p["how"]))
        for key, lo, hi in (("ttl", 30, 7200), ("interval", 1, 60), ("settle", 0, 7200)):
            try:
                value = int(p[key])
            except ValueError:
                raise ChaosUsageError("cpu: {} must be an integer, got {!r}".format(key, p[key]))
            if not lo <= value <= hi:
                raise ChaosUsageError("cpu: {} must be {}..{} seconds, got {}".format(key, lo, hi, value))
        # settle is the hold; ttl is the dead-man that must outlast it, or the cap is lifted before
        # the check reads it and the run passes without testing anything.
        if int(p["settle"]) >= int(p["ttl"]):
            raise ChaosUsageError(
                "cpu: settle={}s is not shorter than ttl={}s, so the cap is lifted before the check "
                "reads it. ttl is a dead-man, not the hold -- raise ttl above the settle, or lower "
                "the settle.".format(p["settle"], p["ttl"]))
        p["container"] = require_target(p["process"], as_bool(p.get("force", False), "cpu: force"), "cpu")

    @property
    def how(self):
        """Tier 0 for a whole container, Tier 1 for a single daemon -- unless told otherwise."""
        if self.params["how"] != "auto":
            return self.params["how"]
        return "docker" if self.params["process"] in targets().get("containers", []) else "cgroup"

    def quota_us(self):
        """cpu.max numerator for the requested share of one core."""
        return int(self.params["share"]) * CGROUP_PERIOD_US // 100

    def cgroup(self):
        """Where the daemon is moved to in Tier 1. Nothing else may create cgroups under here."""
        return "{}/{}".format(CGROUP_ROOT, self.params["process"])

    # -- the three contract methods ---------------------------------------------------------

    def apply(self, duthost, **params):
        """Idempotent: a second apply re-attaches whatever moved and pushes the deadline out."""
        p = self.params
        result = agent(duthost, "apply", *flags(
            kind="cpu", target=p["process"], container=p["container"], how=self.how,
            share=int(p["share"]), ttl=int(p["ttl"]), interval=int(p["interval"])))
        logger.info("[cpu] %s on %s: %s cap live, %s%% of one core, pids %s, ttl %ss",
                    self.describe(), duthost.hostname, self.how, p["share"],
                    result.get("pids"), p["ttl"])
        return result

    def release(self, duthost):
        """Lifts the cap first and unwinds the cgroup second, so a later failure leaves it lifted."""
        result = agent(duthost, "release", *flags(kind="cpu", target=self.params["process"]),
                       ignore_errors=True)
        if result.get("notes"):
            logger.error("[cpu] release of %s on %s reported: %s",
                         self.describe(), duthost.hostname, result["notes"])
        if result.get("error") or not result.get("released"):
            raise SqueezeError("[cpu] {} may still be throttled on {}: {}".format(
                self.params["process"], duthost.hostname, result.get("error") or result))
        logger.info("[cpu] released %s on %s: achieved %s%% of a requested %s%%, cap bit: %s, "
                    "reattached %s time(s)", self.describe(), duthost.hostname,
                    result.get("achieved"), result.get("requested"), result.get("bit"),
                    result.get("reattached"))
        return result

    def status(self, duthost):
        """``achieved`` is measured, not requested. ``bit`` False means the fault was a no-op."""
        result = agent(duthost, "status", *flags(kind="cpu", target=self.params["process"]),
                       ignore_errors=True)
        result.setdefault("active", False)
        result.setdefault("achieved", None)
        result["requested"] = int(self.params["share"])
        return result

    # -- self-calibration -------------------------------------------------------------------

    @staticmethod
    def calibrate(duthost, share=30, seconds=6, workers=2):
        """Cap a synthetic spinner at ``share`` and check the measured value lands in tolerance.

        Do not skip this on a new platform. Every ``achieved`` number the lane reports comes from
        cgroup accounting; if that accounting and the enforcement disagree, the whole lane is
        reporting its own arithmetic back to itself and no result in the report is falsifiable.
        """
        return agent(duthost, "calibrate",
                     *flags(share=share, seconds=seconds, workers=workers), ignore_errors=True)
