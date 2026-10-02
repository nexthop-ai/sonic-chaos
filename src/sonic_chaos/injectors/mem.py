"""Squeeze lane -- memory pressure, held or ramped.

    --chaos mem=swss:70                     cap the container at 70% of its current RSS
    --chaos mem=swss:40:ramp=10:period=20   walk the cap down to 40% in 10-point steps, 20 s apart
    --chaos mem=swss:70:ttl=300             release unconditionally after 5 minutes

Two shapes, because they find different bugs. A **fixed** cap answers "what happens at the
limit": the allocator fails, and the question is whether the daemon degrades or dies. A **ramp**
answers "what happens on the way there", which is where leak-shaped bugs and OOM-killer races
live -- a daemon that survives an instant squeeze often dies during a slow one because it is
holding a partially built object when the wall arrives.

Ramping back up matters as much as down: **memory returned is not memory recovered**. A daemon
that never releases its cached state stays fat after the pressure lifts, and that is the leak.
So ``release`` raises the ceiling, waits ``settle`` seconds, re-reads ``memory.current``, and
reports ``recovered`` -- the whole point of the injector is the number it takes *after* the
fault, not during it.

Mechanism is ``docker update --memory``, driven by ``chaos_agent.py`` so the ramp has something
to walk it and the cap has a TTL dead-man behind it. Per-process pressure would need a balloon
allocator inside the container; not in the 24h scope, so this is always whole-container --
naming a process just resolves to the container it lives in, and apply says so out loud.

Careful: with no swap, a container that hits its cap gets OOM-killed rather than slowed, which
makes this an *event* fault wearing a *state* fault's clothes. ``status()`` therefore carries
``oom_kill`` straight from ``memory.events``: an OOM kill must never be read as graceful
degradation. Pair it with a critical-process invariant.
"""
import logging

from ..injector import Injector, ChaosUsageError, register, require_target, as_bool, targets
from ..squeeze import SqueezeError, agent, flags

logger = logging.getLogger(__name__)


@register
class MemInjector(Injector):
    name = "mem"
    lane = "squeeze"
    positional = ("process", "share")
    defaults = {"share": "70", "ramp": "0", "period": "30", "ttl": "900",
                "interval": "5", "settle": "5"}

    def validate(self):
        p = self.params
        if "process" not in p:
            raise ChaosUsageError("mem: needs a container, e.g. mem=swss:70")
        for key, lo, hi in (("share", 5, 100), ("ramp", 0, 50), ("period", 1, 600),
                            ("ttl", 30, 7200), ("interval", 1, 60), ("settle", 0, 120)):
            try:
                value = int(p[key])
            except ValueError:
                raise ChaosUsageError("mem: {} must be an integer, got {!r}".format(key, p[key]))
            if not lo <= value <= hi:
                raise ChaosUsageError("mem: {} must be {}..{}, got {}".format(key, lo, hi, value))
        p["container"] = require_target(p["process"], as_bool(p.get("force", False), "mem: force"), "mem")
        if int(p["ttl"]) < self.ramp_seconds():
            raise ChaosUsageError(
                "mem: ttl {}s is shorter than the ramp it has to walk ({}s for {} steps of "
                "{}s) -- the dead-man would fire mid-ramp".format(
                    p["ttl"], self.ramp_seconds(), len(self.steps()), p["period"]))

    @property
    def is_ramp(self):
        return int(self.params["ramp"]) > 0

    def steps(self):
        """Cap percentages from 100 down to ``share``. A fixed cap is a one-element ramp."""
        target, step = int(self.params["share"]), int(self.params["ramp"])
        if not step:
            return [target]
        return list(range(100 - step, target - 1, -step)) or [target]

    def ramp_seconds(self):
        """How long the walk down takes. The TTL has to outlast it or the ramp never finishes."""
        return (len(self.steps()) - 1) * int(self.params["period"])

    @property
    def whole_container(self):
        """mem is always container-wide. True when the spec named a daemon and got its container."""
        return self.params["process"] not in targets().get("containers", [])

    # -- the three contract methods ---------------------------------------------------------

    def apply(self, duthost, **params):
        """Sets the first rung synchronously; the agent's watcher walks the rest on ``period``."""
        p = self.params
        if self.whole_container:
            logger.warning("[mem] %s names a process but memory pressure is container-wide: "
                           "capping all of %s", p["process"], p["container"])
        result = agent(duthost, "apply", *flags(
            kind="mem", target=p["container"], container=p["container"],
            steps=",".join(str(s) for s in self.steps()), period=int(p["period"]),
            ttl=int(p["ttl"]), interval=int(p["interval"]), settle=int(p["settle"])))
        logger.info("[mem] %s on %s: baseline RSS %s, cap steps %s%% over %ss, first rung %s bytes",
                    self.describe(), duthost.hostname, result.get("rss_before"), self.steps(),
                    self.ramp_seconds(), result.get("cap_bytes"))
        return result

    def release(self, duthost):
        """Raises the ceiling, settles, and re-reads RSS. ``recovered`` False is the finding."""
        result = agent(duthost, "release", *flags(kind="mem", target=self.params["container"]),
                       ignore_errors=True)
        if result.get("notes"):
            logger.error("[mem] release of %s on %s reported: %s",
                         self.describe(), duthost.hostname, result["notes"])
        if result.get("error") or not result.get("released"):
            raise SqueezeError("[mem] {} may still be capped on {}: {}".format(
                self.params["container"], duthost.hostname, result.get("error") or result))
        if result.get("oom_kill"):
            logger.error("[mem] %s on %s: %s OOM kill(s) under the cap -- this is an event fault, "
                         "not graceful degradation; check the critical-process invariant",
                         self.describe(), duthost.hostname, result["oom_kill"])
        if result.get("recovered") is False:
            logger.error("[mem] %s on %s did NOT recover: RSS %s -> %s (%s%%). Memory returned is "
                         "not memory recovered -- this is the leak signal.",
                         self.describe(), duthost.hostname, result.get("rss_before"),
                         result.get("rss_after"), result.get("rss_delta_pct"))
        else:
            logger.info("[mem] released %s on %s: RSS %s -> %s, recovered %s, oom_kill %s",
                        self.describe(), duthost.hostname, result.get("rss_before"),
                        result.get("rss_after"), result.get("recovered"), result.get("oom_kill"))
        return result

    def status(self, duthost):
        """``recovered`` is only meaningful after release; before that it is None, not True."""
        result = agent(duthost, "status", *flags(kind="mem", target=self.params["container"]),
                       ignore_errors=True)
        result.setdefault("active", False)
        result.setdefault("steps", self.steps())
        result.setdefault("recovered", None)
        return result
