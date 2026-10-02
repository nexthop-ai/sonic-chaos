"""A JSON matrix of conditions: named lists of faults that are applied together.

    {
      "conditions": [
        {"name": "baseline",  "faults": []},
        {"name": "restart",   "faults": ["kill=orchagent:how=restart:settle=60"]},
        {"name": "starved",   "faults": ["cpu=orchagent:30", "pause=orchagent:10"],
         "note": "a cap only bites while the daemon is busy; the freeze makes sure it is"},
        ["syslog=1000:seconds=10"]
      ]
    }

``pytest ... --chaos-conditions matrix.json`` runs every collected test once per condition,
module by module: a module runs to completion under one condition before the next is applied,
so a condition with a kill in it is applied once per module, not once per test. Test ids carry
the condition name (``test_po_update[restart]``), and the summary counts per condition.

A fault is a ``--chaos`` spec string, or the experiment-file shape ``{"kill": {"process":
"orchagent"}}``. A condition is an object with ``faults`` or a bare list; ``name`` is optional
and defaults to the injector names joined with ``+``. An empty ``faults`` list is a control run.
The file is validated in full at configure time, so a typo in the fourth condition fails before
the first test, not after three conditions have already been paid for on the switch.

No pytest here: the selftest exercises this module without one.
"""
import json
import re

from .injector import ChaosPlan, ChaosUsageError, get as get_injector

_ID_OK = re.compile(r"^[A-Za-z0-9_.+-]+$")


class ChaosCondition(object):
    def __init__(self, name, plan, specs, note=""):
        self.name = name
        self.plan = plan
        self.specs = list(specs)      # the --chaos strings, for the repro line
        self.note = note

    def summary(self):
        return self.plan.summary() if self.plan.injectors else "no fault (control)"

    def describe(self):
        line = "{:<20} {}".format(self.name, self.summary())
        return line + ("   # " + self.note if self.note else "")


def _fault_to_spec(entry, where):
    """One fault entry -> a ``--chaos`` string. Dicts use the experiment-file shape."""
    if isinstance(entry, str):
        if "=" not in entry:
            raise ChaosUsageError("{}: {!r} is not an INJECTOR=SPEC string".format(where, entry))
        return entry
    if isinstance(entry, dict) and len(entry) == 1:
        name, params = next(iter(entry.items()))
        if not isinstance(params, dict):
            raise ChaosUsageError("{}: {!r} must map to a dict of parameters".format(where, name))
        get_injector(name)   # raises with the known names if it is a typo
        # A value holding ':' (a redis key, a MAC, an IPv6 address) travels in [...] so the
        # spec grammar does not split it.
        spec = ":".join("{}={}".format(k, "[{}]".format(v) if ":" in str(v) else v)
                        for k, v in params.items())
        return "{}={}".format(name, spec)
    raise ChaosUsageError("{}: a fault is an INJECTOR=SPEC string or a one-key dict, got {!r}"
                          .format(where, entry))


def _default_name(plan):
    if not plan.injectors:
        return "baseline"
    return "+".join(i.name for i in plan.injectors)


def load_conditions(path, dry_run=False, only=None):
    """Parse and validate the file. Returns ``[ChaosCondition]`` in file order.

    ``only`` keeps just the named conditions (``--chaos-condition NAME``), and a name that is
    not in the file is an error rather than a silent empty run.
    """
    with open(path) as fh:
        try:
            doc = json.load(fh)
        except ValueError as err:
            raise ChaosUsageError("{}: not valid JSON: {}".format(path, err))
    return parse_conditions(doc, dry_run=dry_run, only=only, where=path)


def parse_conditions(doc, dry_run=False, only=None, where="conditions"):
    if isinstance(doc, dict):
        raw = doc.get("conditions")
        if raw is None:
            raise ChaosUsageError("{}: expected a top-level \"conditions\" list".format(where))
    else:
        raw = doc
    if not isinstance(raw, list) or not raw:
        raise ChaosUsageError("{}: \"conditions\" must be a non-empty list".format(where))

    out, seen = [], set()
    for index, item in enumerate(raw, 1):
        label = "{}: condition {}".format(where, index)
        if isinstance(item, list):
            item = {"faults": item}
        if not isinstance(item, dict):
            raise ChaosUsageError("{}: expected an object or a list of faults, got {!r}".format(label, item))
        faults = item.get("faults")
        if not isinstance(faults, list):
            raise ChaosUsageError("{}: needs a \"faults\" list (empty for a control run)".format(label))
        specs = [_fault_to_spec(f, label) for f in faults]
        try:
            plan = ChaosPlan.from_args(specs, dry_run=dry_run)
            for injector in plan.injectors:
                injector.validate()
        except ChaosUsageError as err:
            raise ChaosUsageError("{}: {}".format(label, err))

        name = str(item.get("name") or _default_name(plan))
        if not _ID_OK.match(name):
            raise ChaosUsageError("{}: name {!r} may only use letters, digits, . _ + -".format(label, name))
        if name in seen:
            raise ChaosUsageError("{}: name {!r} is used twice".format(label, name))
        seen.add(name)
        out.append(ChaosCondition(name, plan, specs, note=str(item.get("note") or "")))

    if only:
        missing = [n for n in only if n not in seen]
        if missing:
            raise ChaosUsageError("{}: no condition named {}; the file has: {}".format(
                where, ", ".join(missing), ", ".join(c.name for c in out)))
        out = [c for c in out if c.name in only]
    return out
