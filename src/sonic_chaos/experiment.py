"""Experiment files: a whole chaos run described in one YAML, replayable by seed.

    pytest ... --chaos-file experiments/bgp-disruptions.yml

Why a file instead of more flags: a run is a *schedule*, not a setting. Which faults, how
often relative to each other, how far apart, what must be true before we start, and how long
recovery may take -- that does not fit on a command line, and it needs to be committed next to
the ticket it reproduces.

Why a seed: four of fifteen restart tickets in the last year were closed unreproducible. A
seeded schedule replays the same faults in the same order, so a failing run becomes a repro
command instead of a story.

Schema
------
    experiment: bgp-control-plane-disruptions
    seed: 20260910              # same seed -> same fault order, every time
    duration: 10m               # total chaos window
    min_gap: 60s                # never inject twice inside this
    steady_state: parity        # must ALL pass before the first fault, or the run is INVALID
                                #   (invalid is not the same as failed -- it blames the box, not a fault)
    faults:                     # weighted pool; one active at a time
      - kill:   {process: bgpd, how: restart, weight: 3, tag: supported-op}
      - pause:  {process: orchagent, seconds: 30, weight: 1, tag: unsupported-op}
      - redis:  {action: client_kill, target: orchagent, weight: 2}
    contract:
      recover_within: 180s      # budget for every invariant to pass again after a fault
      invariants: parity        # or health / signal / all, or an explicit list of names

Every fault entry is ``{<injector name>: {<its spec params>, weight, tag}}``. The params are
exactly the injector's own, so anything expressible as ``--chaos name=spec`` is expressible
here and validated by the same code.

``steady_state`` and ``contract.invariants`` take a GROUP -- ``parity`` (the default: do the
databases agree), ``health`` (is the box up), ``signal`` (is something falling behind), or
``all`` -- or an explicit list of invariant names when you really want a subset. Prefer the
group: an enumerated list is one more thing that goes stale.

``tag`` is ``supported-op`` or ``unsupported-op``. It changes nothing at runtime; it goes in
the report, so a finding from an operation the team already calls unsupported is read as such
instead of being argued about. Restarting a single daemon is the standing example.
"""
import logging
import random
import re

import yaml

from .injector import ChaosUsageError, get as get_injector

logger = logging.getLogger(__name__)

TAGS = ("supported-op", "unsupported-op")
# Consumed by the scheduler, never forwarded to an injector. No injector may use these names.
RESERVED_KEYS = frozenset(["weight", "tag"])
SCHEMA_VERSION = 1
TOP_LEVEL_KEYS = ("version", "experiment", "seed", "duration", "min_gap", "steady_state", "faults",
                  "contract", "count")
DEFAULT_TAG = "unsupported-op"   # conservative: assume unsupported unless the author says otherwise

_DURATION = re.compile(r"^\s*(\d+)\s*([smh]?)\s*$")
_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600}


def resolve_invariants(selector, field, where):
    """``parity`` / ``health`` / ``signal`` / ``all`` / a name / a list of either -> real names.

    Groups exist so a config never has to enumerate nine checks to get the obvious behaviour --
    and so it does not silently go stale when a tenth is added. Explicit names still work.

    A name nothing implements is rejected here, at load time. Left alone it would load fine and
    then quietly never run, and the report would say "all invariants passed" having verified less
    than it claims -- the same failure UNCHECKED exists to prevent, one layer up.
    """
    from . import oracle   # lazy, so import order never matters
    try:
        return oracle.resolve(selector)
    except ValueError as err:
        raise ChaosUsageError("{}: {}: {}".format(where, field, err))


def parse_duration(value, field):
    """``"10m"`` / ``"60s"`` / ``180`` -> seconds."""
    match = _DURATION.match(str(value))
    if not match:
        raise ChaosUsageError("{}: expected a duration like 30s / 10m / 2h, got {!r}".format(field, value))
    return int(match.group(1)) * _SECONDS[match.group(2)]


class ScheduledFault(object):
    """One entry from the pool: a built injector plus its scheduling metadata."""

    def __init__(self, injector, weight=1, tag=DEFAULT_TAG):
        self.injector = injector
        self.weight = weight
        self.tag = tag

    def describe(self):
        return "{} weight={} [{}]".format(self.injector.describe(), self.weight, self.tag)


class Experiment(object):
    """A parsed experiment file. ``schedule()`` turns the seed into a concrete fault order."""

    def __init__(self, name, faults, seed=None, duration=600, min_gap=60,
                 steady_state=(), recover_within=180, invariants=(), path="", count=None):
        self.name = name
        self.faults = list(faults)
        self.seed = seed
        self.duration = duration
        self.min_gap = min_gap
        # How many faults to schedule. Default: one per pool entry. Filling `duration` with
        # `min_gap` slots regardless of pool size turned one kill into six on a lab switch and locked
        # the switch; nobody who writes one fault means "repeat it until the clock runs out".
        # Set count explicitly to repeat.
        self.count = int(count) if count is not None else len(self.faults)
        self.steady_state = list(steady_state)
        self.recover_within = recover_within
        self.invariants = list(invariants)
        self.path = path

    # ----------------------------------------------------------------- loading

    @classmethod
    def from_file(cls, path):
        with open(path) as handle:
            try:
                raw = yaml.safe_load(handle)
            except yaml.YAMLError as err:
                raise ChaosUsageError("{}: not valid YAML: {}".format(path, err))
        if not isinstance(raw, dict):
            raise ChaosUsageError("{}: expected a mapping at the top level".format(path))
        return cls.from_dict(raw, path=path)

    @classmethod
    def from_dict(cls, raw, path=""):
        where = path or "experiment"
        unknown = set(raw) - set(TOP_LEVEL_KEYS)
        if unknown:
            raise ChaosUsageError("{}: unknown key(s) {}".format(where, ", ".join(sorted(unknown))))
        if raw.get("version", SCHEMA_VERSION) != SCHEMA_VERSION:
            raise ChaosUsageError("{}: version {!r} is not one this sonic-chaos reads (it reads {})".format(
                where, raw.get("version"), SCHEMA_VERSION))

        name = raw.get("experiment")
        if not name:
            raise ChaosUsageError("{}: needs an 'experiment' name".format(where))

        entries = raw.get("faults")
        if not entries:
            raise ChaosUsageError("{}: needs at least one entry under 'faults'".format(where))
        if not isinstance(entries, list):
            raise ChaosUsageError("{}: 'faults' must be a list of {{injector: {{params}}}}".format(where))

        faults = []
        for index, entry in enumerate(entries):
            faults.append(cls._build_fault(entry, "{} faults[{}]".format(where, index)))

        contract = raw.get("contract") or {}
        if not isinstance(contract, dict):
            raise ChaosUsageError("{}: 'contract' must be a mapping".format(where))

        # Both default to the parity group: the databases agreeing is what Oracle is for, and a
        # run with no steady-state gate blames the first fault for a box that was already broken.
        steady_state = resolve_invariants(
            raw.get("steady_state") or "parity", "steady_state", where)
        invariants = resolve_invariants(
            contract.get("invariants") or "parity", "contract.invariants", where)

        return cls(
            name=name,
            faults=faults,
            seed=raw.get("seed"),
            duration=parse_duration(raw.get("duration", "10m"), "{} duration".format(where)),
            count=raw.get("count"),
            min_gap=parse_duration(raw.get("min_gap", "60s"), "{} min_gap".format(where)),
            steady_state=steady_state,
            recover_within=parse_duration(contract.get("recover_within", "180s"),
                                          "{} contract.recover_within".format(where)),
            invariants=invariants,
            path=path,
        )

    @staticmethod
    def _build_fault(entry, where):
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ChaosUsageError(
                "{}: each fault is a single-key mapping like "
                "{{kill: {{process: bgpd, weight: 2}}}}, got {!r}".format(where, entry))
        [(name, params)] = entry.items()
        params = dict(params or {})

        # `weight` and `tag` are scheduling metadata, consumed here and never passed to the
        # injector. An injector that also had a parameter by one of those names could never
        # receive it from an experiment file: both keys are in the same YAML mapping, PyYAML
        # keeps the last, and the injector would silently fall back to its default -- a fault
        # that runs with settings nobody chose. Refuse instead of losing the value quietly.
        # (Found when syslog's own `tag` param, since renamed to `ident`, was unreachable.)
        clashes = RESERVED_KEYS & set(get_injector(name).defaults)
        if clashes:
            raise ChaosUsageError(
                "{}: injector {!r} has parameter(s) {} whose name(s) are reserved for scheduling "
                "metadata here, so a value set in this file would be silently discarded. Rename "
                "the injector's parameter.".format(where, name, ", ".join(sorted(clashes))))

        weight = params.pop("weight", 1)
        tag = params.pop("tag", DEFAULT_TAG)
        if tag not in TAGS:
            raise ChaosUsageError("{}: tag must be one of {}, got {!r}".format(where, "/".join(TAGS), tag))
        try:
            weight = int(weight)
        except (TypeError, ValueError):
            raise ChaosUsageError("{}: weight must be an integer, got {!r}".format(where, weight))
        if weight < 1:
            raise ChaosUsageError("{}: weight must be >= 1, got {}".format(where, weight))

        try:
            # Same validators as the CLI: a bad param fails here, before any DUT is touched.
            injector = get_injector(name).from_spec("", **params)
        except ChaosUsageError as err:
            raise ChaosUsageError("{}: {}".format(where, err))
        return ScheduledFault(injector, weight=weight, tag=tag)

    # ----------------------------------------------------------------- scheduling

    def schedule(self, seed=None):
        """Seeded weighted fault order: ``[(offset_seconds, ScheduledFault), ...]``.

        One fault at a time, never closer together than ``min_gap``, filling ``duration``.
        Deterministic: the same seed always produces the same list, which is what makes a
        failing run replayable.
        """
        seed = self.seed if seed is None else seed
        rng = random.Random(seed)
        pool = [f for f in self.faults for _ in range(f.weight)]
        out, offset = [], 0
        if self.count <= len(self.faults):
            # each fault once (the default), in seeded order, min_gap apart -- no fault is
            # drawn twice unless the operator asked for more slots than there are faults
            order = list(self.faults)
            rng.shuffle(order)
            for f in order[:self.count]:
                out.append((offset, f))
                offset += self.min_gap
            return out
        while len(out) < self.count and offset + self.min_gap <= self.duration + self.min_gap:
            out.append((offset, rng.choice(pool)))
            offset += self.min_gap
        return out

    def describe(self):
        lines = ["experiment {} (seed={}, {} fault(s) scheduled{}, min_gap={}s, duration={}s)".format(
            self.name, self.seed, self.count,
            " -- each once" if self.count <= len(self.faults) else " from a pool of {}".format(len(self.faults)),
            self.min_gap, self.duration)]
        if self.steady_state:
            lines.append("  steady_state: {}".format(", ".join(self.steady_state)))
        for fault in self.faults:
            lines.append("  fault: {}".format(fault.describe()))
        lines.append("  contract: recover_within={}s invariants={}".format(
            self.recover_within, ", ".join(self.invariants) or "none"))
        return "\n".join(lines)

    def summary(self):
        return "{}(seed={}, {} faults)".format(self.name, self.seed, len(self.faults))


def json_schema():
    """The experiment file format as JSON Schema (draft 2020-12), built from the live registry.

    Injector names and their parameters come from what is registered right now, so a site's own
    injectors show up and a renamed parameter can never drift from the schema. Parameter values
    stay loosely typed because specs are strings on the command line; ``Experiment.from_dict``
    remains the authority and says exactly what is wrong.
    """
    from . import injectors  # noqa: F401  registers the built-ins
    from .injector import REGISTRY
    from .oracle import GROUPS, INVARIANTS
    from .plugins import load_entry_points
    load_entry_points()
    duration = {"type": ["string", "integer"], "pattern": r"^\d+[smh]?$"}
    selector = {"oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                "description": "a group ({}), 'all', or invariant names ({})".format(
                    ", ".join(GROUPS), ", ".join(sorted(INVARIANTS)))}
    scalar = {"type": ["string", "integer", "number", "boolean"]}
    fault_variants = []
    for name in sorted(REGISTRY):
        cls = REGISTRY[name]
        params = {key: scalar for key in list(cls.positional) + list(cls.defaults)}
        params["weight"] = {"type": "integer", "minimum": 1}
        params["tag"] = {"enum": list(TAGS)}
        fault_variants.append({
            "type": "object", "additionalProperties": False, "required": [name],
            "properties": {name: {"type": "object", "properties": params,
                                  "description": "{} lane".format(cls.lane)}}})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:sonic-chaos:experiment:{}".format(SCHEMA_VERSION),
        "title": "sonic-chaos experiment",
        "type": "object",
        "additionalProperties": False,
        "required": ["experiment", "faults"],
        "properties": {
            "version": {"const": SCHEMA_VERSION},
            "experiment": {"type": "string"},
            "seed": {"type": "integer"},
            "duration": duration,
            "min_gap": duration,
            "count": {"type": "integer", "minimum": 1},
            "steady_state": selector,
            "faults": {"type": "array", "minItems": 1, "items": {"oneOf": fault_variants}},
            "contract": {"type": "object", "additionalProperties": False, "properties": {
                "recover_within": duration, "invariants": selector}},
        },
    }
