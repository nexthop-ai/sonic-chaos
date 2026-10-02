"""Oracle: cross-database consistency.

The one part of sonic-chaos that needs no injector to be useful. A divergence between what
APPL_DB asked for and what ASIC_DB holds is an invariant violation -- objectively a bug, with
no argument to have about whether some timeout was too tight.

Contract
--------
    snapshot(duthost)                -> DbSnapshot            APPL_DB + ASIC_DB + STATE_DB, now
    diff(before, after)              -> [Divergence]          same-DB: what a fault changed
    assert_consistent(duthost, ...)  -> DbSnapshot | raises   cross-DB: every registered invariant
    @invariant("lag_member")         registers fn(snapshot) -> [Divergence]

Nothing here imports pytest. ``diff`` and ``check`` run on plain dicts (see selftest.py).

Oracle lane fills in INVARIANTS. Until it does, ``assert_consistent`` is vacuous and logs a
warning saying so rather than passing silently.
"""
import json
import logging
import re
import time
from collections import namedtuple

logger = logging.getLogger(__name__)

DBS = ("APPL_DB", "ASIC_DB", "STATE_DB")

# ASIC_DB refers to ports, LAGs and RIFs only by OID, so a snapshot without these maps cannot be
# checked for cross-database consistency -- offline least of all. They are small (one hash each)
# and pulled with a -k glob, so carrying them costs one extra round trip and makes a saved bundle
# self-contained. Verified present on a lab switch; COUNTERS_VLAN_NAME_MAP is NOT (no VLANs on a t2
# box), and invariants report "cannot check" rather than guessing when a map is missing.
NAME_MAP_DB = "COUNTERS_DB"
NAME_MAPS = ("COUNTERS_PORT_NAME_MAP", "COUNTERS_LAG_NAME_MAP", "COUNTERS_RIF_NAME_MAP",
             "COUNTERS_VLAN_NAME_MAP")

# ---------------------------------------------------------------------------------------------
# Noise floor, measured on a lab switch (202511.2, t2-single-node-min, idle):
# two back-to-back snapshots of 5314 keys differ in 270 places. Every one is kind="changed" --
# the key SET is stable on an idle box, only telemetry field values churn. So denoising is exact,
# not heuristic: drop these tables and fields and an idle diff is empty, which is what makes a
# real divergence visible.
#
#   STATE_DB TEMPERATURE_INFO            156   timestamp, temperature, minimum_temperature
#   STATE_DB THERMAL_SENSOR_PID_INFO      84   timestamp, error, temperature
#   STATE_DB FAN_INFO                     10   timestamp
#   STATE_DB TRANSCEIVER_{DOM_TEMPERATURE,DOM_SENSOR,DOM_FLAG,STATUS,STATUS_FLAG}
#                                        8ea   last_update_time
#   APPL_DB  LLDP_ENTRY_TABLE              6   lldp_rem_time_mark
#   STATE_DB PSU_INFO                      2   voltage, power, current, input_current
#   STATE_DB THERMAL_PID_INFO              2   timestamp
#   STATE_DB ASIC_TEMPERATURE_INFO         1
#   APPL_DB  GEARBOX_TABLE_KEY_SET         1   (ProducerStateTable work queue)
#   STATE_DB PROCESS_STATS|<pid>               per-PID stats; keys come and go with PIDs
#
# Two layers on purpose: a whole-table rule for pure telemetry, plus a field rule that catches
# tables we have not enumerated. The TRANSCEIVER_* family proved the point -- three of them were
# not in VOLATILE_TABLES but their `last_update_time` field caught them anyway. With both layers
# an idle diff on a lab switch is 0.
#
# Re-measure with scripts/noise.py when the platform or branch changes -- this list is evidence,
# not doctrine, and a wrong entry here hides real bugs.
# ---------------------------------------------------------------------------------------------


VOLATILE_TABLES = frozenset([
    "TEMPERATURE_INFO", "ASIC_TEMPERATURE_INFO", "THERMAL_SENSOR_PID_INFO", "THERMAL_PID_INFO",
    "FAN_INFO", "PSU_INFO", "TRANSCEIVER_DOM_TEMPERATURE", "TRANSCEIVER_DOM_SENSOR",
    "PROCESS_STATS", "SYSTEM_HEALTH_INFO", "LLDP_ENTRY_TABLE",
])

VOLATILE_FIELDS = frozenset([
    "timestamp", "last_update_time", "lldp_rem_time_mark", "expireat", "ttl",
])

# ProducerStateTable work queues: transient by construction. A *_KEY_SET that is non-empty at
# rest is itself a finding (backlog), but its churn is not a divergence.
VOLATILE_SUFFIXES = ("_KEY_SET", "_DEL_SET")


def table_of(key):
    """``"LLDP_ENTRY_TABLE:Ethernet0"`` / ``"PROCESS_STATS|104557"`` -> the table name."""
    return re.split(r"[:|]", key, 1)[0]


def is_volatile_key(key):
    return table_of(key) in VOLATILE_TABLES or key.endswith(VOLATILE_SUFFIXES)


# kind: "missing" | "extra" | "changed" for diff(); the invariant's name for check().
Divergence = namedtuple("Divergence", "kind db key detail")

# An invariant that cannot run (a name map the platform does not have, a command that failed)
# reports with this suffix instead of returning nothing. Silently passing an un-runnable check is
# how a suite convinces itself a box is healthy; failing the run because the platform has no VLANs
# is equally wrong. So: always visible, never fatal.
UNCHECKED = ":unchecked"


def is_unchecked(divergence):
    return str(divergence.kind).endswith(UNCHECKED)


def split_unchecked(divergences):
    """``([real findings], [unchecked notices])``."""
    real = [d for d in divergences if not is_unchecked(d)]
    notices = [d for d in divergences if is_unchecked(d)]
    return real, notices


class DbSnapshot(object):
    """``tables[db][key] == {field: value}`` for every key dumped."""

    def __init__(self, tables, taken_at=None, hostname="", duthost=None):
        self.tables = tables
        self.taken_at = taken_at or time.time()
        self.hostname = hostname
        # Invariants that need an on-box command (route_check, supervisor status) use this.
        # Not serialised: a snapshot loaded from disk has duthost=None.
        self.duthost = duthost

    def keys(self, db, prefix=""):
        return sorted(k for k in self.tables.get(db, {}) if k.startswith(prefix))

    def get(self, db, key, default=None):
        return self.tables.get(db, {}).get(key, default)

    def __len__(self):
        return sum(len(v) for v in self.tables.values())

    def save(self, path):
        with open(path, "w") as fh:
            json.dump({"hostname": self.hostname, "taken_at": self.taken_at, "tables": self.tables}, fh, indent=1)

    @classmethod
    def load(cls, path):
        with open(path) as fh:
            raw = json.load(fh)
        return cls(raw["tables"], taken_at=raw.get("taken_at"), hostname=raw.get("hostname", ""))


# ----------------------------------------------------------------------------- snapshot

def snapshot(duthost, dbs=DBS, prefixes=None, name_maps=True):
    """Dump ``dbs`` on the DUT with ``sonic-db-dump`` and return a DbSnapshot.

    ``prefixes`` filters keys per DB and is pushed to the DUT as a ``-k`` glob, so a narrow
    snapshot costs a fraction of a full one::

        snapshot(dut, dbs=("APPL_DB",), prefixes={"APPL_DB": ["LAG_MEMBER_TABLE:"]})

    Verified on a lab switch (202511.2): a full three-DB snapshot is 5314 keys in ~14 s
    over ssh; the LAG-only one above is 4 keys in ~4 s. The dump shape is
    ``{key: {"type": "hash", "value": {...}, "ttl": ..., "expireat": ...}}`` -- ``ttl`` and
    ``expireat`` sit outside ``value``, so they never reach the diff.
    """
    tables = {}
    for db in dbs:
        globs = [p if "*" in p else p + "*" for p in (prefixes or {}).get(db, [])] or [None]
        merged = {}
        for glob in globs:
            cmd = "sonic-db-dump -n {}".format(db)
            if glob:
                cmd += " -k '{}'".format(glob)
            res = duthost.shell(cmd, module_ignore_errors=True)
            if res.get("rc", 1) != 0:
                raise RuntimeError("{} failed on {}: {}".format(
                    cmd, duthost.hostname, (res.get("stderr") or res.get("stdout") or "").strip()[:400]))
            merged.update(_parse_dump(res["stdout"]))
        tables[db] = merged

    if name_maps:
        # One dump for all of them: the glob matches every *NAME_MAP key, and we keep the ones
        # we know about. Missing maps are simply absent, which invariants handle explicitly.
        res = duthost.shell("sonic-db-dump -n {} -k '*NAME_MAP*'".format(NAME_MAP_DB),
                            module_ignore_errors=True)
        if res.get("rc", 1) == 0:
            everything = _parse_dump(res["stdout"])
            tables[NAME_MAP_DB] = {k: v for k, v in everything.items() if k in NAME_MAPS}
        else:
            logger.warning("[oracle] could not read %s name maps on %s: cross-DB invariants "
                           "will report 'cannot check'", NAME_MAP_DB, duthost.hostname)
            tables[NAME_MAP_DB] = {}

    return DbSnapshot(tables, hostname=duthost.hostname, duthost=duthost)


def _parse_dump(text):
    # Some transports print a login banner before the command's output; the dump starts at "{".
    start = (text or "").find("{")
    raw = json.loads(text[start:]) if start >= 0 else {}
    out = {}
    for key, entry in raw.items():
        value = entry.get("value", entry) if isinstance(entry, dict) else entry
        out[key] = dict(value) if isinstance(value, dict) else {"_": value}
    return out


# ----------------------------------------------------------------------------- diff (same DB, before/after)

def diff(before, after, dbs=None, ignore_fields=(), denoise=True):
    """Key-by-key difference between two snapshots of the same DUT. What a fault changed.

    ``denoise=True`` (the default) drops the platform-telemetry churn measured in
    VOLATILE_TABLES / VOLATILE_FIELDS, which is what makes an idle diff empty. Pass
    ``denoise=False`` to see the raw difference, e.g. when re-measuring the noise floor.
    """
    skip_fields = set(ignore_fields) | (VOLATILE_FIELDS if denoise else frozenset())
    out = []
    for db in dbs or sorted(set(before.tables) | set(after.tables)):
        b, a = before.tables.get(db, {}), after.tables.get(db, {})
        for key in sorted(set(b) - set(a)):
            if denoise and is_volatile_key(key):
                continue
            out.append(Divergence("missing", db, key, "present before, gone after"))
        for key in sorted(set(a) - set(b)):
            if denoise and is_volatile_key(key):
                continue
            out.append(Divergence("extra", db, key, "absent before, present after"))
        for key in sorted(set(a) & set(b)):
            if denoise and is_volatile_key(key):
                continue
            changed = {}
            for field in set(b[key]) | set(a[key]):
                if field in skip_fields:
                    continue
                if b[key].get(field) != a[key].get(field):
                    changed[field] = (b[key].get(field), a[key].get(field))
            if changed:
                out.append(Divergence("changed", db, key, changed))
    return out


# ----------------------------------------------------------------------------- invariants (cross DB, now)

# Three groups, because "do the databases agree?" and "is the switch alive?" are different
# questions. An end user picks a GROUP, never a name -- the names exist so a failure can say
# which parity broke, not so anyone has to learn nine of them.
#
#   parity  APPL_DB vs ASIC_DB vs STATE_DB. This is Oracle's actual job, and the default.
#   health  is the box up at all. Useful as a steady-state gate; not a parity statement.
#   signal  early warning that something is falling behind, before anything has diverged yet.
GROUPS = ("parity", "health", "signal")
DEFAULT_GROUP = "parity"

INVARIANTS = {}          # name -> fn
INVARIANT_GROUP = {}     # name -> one of GROUPS
# name -> {db: [glob]} the invariant reads. Lets snapshot_for() fetch only those rows: on a box
# carrying 100k routes that is the difference between a per-test check costing seconds and one
# costing a minute. Empty means the invariant reads nothing from a snapshot (it asks the DUT).
INVARIANT_PREFIXES = {}


def group_members(group):
    return sorted(n for n, g in INVARIANT_GROUP.items() if g == group)


def resolve(selector):
    """``"parity"`` / ``"all"`` / a name / a list of either -> a sorted list of invariant names.

    Accepting group names is the whole point: nobody should have to enumerate nine checks to get
    the obvious behaviour, and a config that lists them by hand silently goes stale when a tenth
    is added.
    """
    if selector is None:
        selector = "all"
    if isinstance(selector, str):
        selector = [selector]
    if any(item not in INVARIANTS and item not in GROUPS and item != "all" for item in selector):
        from .plugins import load_entry_points
        load_entry_points()
    out = []
    for item in selector:
        if item == "all":
            out.extend(INVARIANTS)
        elif item in GROUPS:
            out.extend(group_members(item))
        elif item in INVARIANTS:
            out.append(item)
        else:
            raise ValueError(
                "unknown invariant or group {!r} -- groups: {}; invariants: {}".format(
                    item, ", ".join(GROUPS), ", ".join(sorted(INVARIANTS))))
    return sorted(set(out))


def prefixes_for(selector):
    """The narrowest snapshot that still feeds every selected invariant, as ``{db: [globs]}``."""
    out = {}
    for name in resolve(selector):
        for db, globs in INVARIANT_PREFIXES.get(name, {}).items():
            bucket = out.setdefault(db, [])
            for glob in globs:
                if glob not in bucket:
                    bucket.append(glob)
    return out


def snapshot_for(duthost, only=DEFAULT_GROUP):
    """Snapshot only the rows ``only`` needs, plus the name maps. See INVARIANT_PREFIXES."""
    prefixes = prefixes_for(only)
    dbs = tuple(db for db in DBS if db in prefixes)
    return snapshot(duthost, dbs=dbs, prefixes=prefixes)


_OID = re.compile(r"oid:0x[0-9a-fA-F]+")


def finding_key(d):
    """The identity of a finding: ``(kind, db, key)``, with SAI object ids masked.

    An OID is not an identity across a restart: loading an interposer restarts swss, orchagent
    re-creates every object, and the same neighbour comes back under a new RIF OID. Keyed on the
    raw OID, a divergence present at baseline would reappear as a "new" finding after any fault
    that restarts swss. The object it names is still told apart by everything else in the key.
    """
    return (d.kind, d.db, _OID.sub("oid:*", d.key or ""))


def finding_keys(divergences):
    """``{finding_key}`` for each divergence: its identity, without its detail."""
    return {finding_key(d) for d in divergences}


def subtract(divergences, baseline_keys):
    """Drop findings that were already present at baseline.

    What a fault *changed* is the finding. What was already wrong when the box was handed to us
    is the box's problem, reported once as an invalid baseline and never blamed on a fault.
    """
    if not baseline_keys:
        return list(divergences)
    return [d for d in divergences if finding_key(d) not in baseline_keys]


def gate(duthost, only=DEFAULT_GROUP):
    """The steady-state gate: ``(violations, unchecked, snapshot)`` right now, no waiting."""
    snap = snapshot_for(duthost, only)
    real, notices = split_unchecked(check(snap, only=only))
    return real, notices, snap


def wait_consistent(duthost, only=DEFAULT_GROUP, timeout=60, interval=5, baseline=None,
                    sleep=time.sleep, clock=time.time):
    """Poll ``only`` until it holds (minus ``baseline``) or ``timeout`` passes.

    Recovery is a window, not an instant: orchagent replaying APPL_DB after a restart is
    legitimately inconsistent for a while. A single sample right after release would flag that
    every time. Returns ``(violations, unchecked, seconds_elapsed, last_snapshot)``; empty
    violations means the contract held within budget.
    """
    start = clock()
    while True:
        snap = snapshot_for(duthost, only)
        real, notices = split_unchecked(check(snap, only=only))
        real = subtract(real, baseline)
        elapsed = round(clock() - start, 1)
        if not real or elapsed >= timeout:
            return real, notices, elapsed, snap
        logger.info("[oracle] %s: %d divergence(s) %ss after release, %ss of budget left",
                    duthost.hostname, len(real), elapsed, round(timeout - elapsed, 1))
        sleep(max(0.0, min(interval, timeout - elapsed)))


def invariant(name, group=DEFAULT_GROUP, prefixes=None):
    """Register a cross-DB check: ``fn(snapshot) -> [Divergence]``. Use ``name`` as the Divergence kind.

    The first one to write (Oracle lane, hour 1):

        @invariant("lag_member")
        def lag_member(snap):
            # APPL_DB  LAG_MEMBER_TABLE:PortChannel12:Ethernet48   {status: enabled}
            # ASIC_DB  ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:oid:0x...  {SAI_LAG_MEMBER_ATTR_LAG_ID: oid:0x...,
            #                                                            SAI_LAG_MEMBER_ATTR_PORT_ID: oid:0x...}
            # oid -> name via COUNTERS_DB COUNTERS_PORT_NAME_MAP / COUNTERS_LAG_NAME_MAP
            # STATE_DB LAG_MEMBER_TABLE|PortChannel12|Ethernet48   {status: enabled}
    """
    def deco(fn):
        if name in INVARIANTS:
            raise TypeError("invariant {!r} already registered".format(name))
        if group not in GROUPS:
            raise TypeError("invariant {!r}: group must be one of {}, got {!r}".format(
                name, "/".join(GROUPS), group))
        INVARIANTS[name] = fn
        INVARIANT_GROUP[name] = group
        INVARIANT_PREFIXES[name] = {db: list(globs) for db, globs in (prefixes or {}).items()}
        return fn
    return deco


def check(snap, only=None, ignore=None):
    """Run registered invariants against a snapshot. Empty list means consistent -- or nothing registered."""
    if not INVARIANTS:
        logger.warning("[oracle] no invariants registered: assert_consistent is vacuous until Oracle lane lands")
        return []
    selected = set(resolve(only))
    if ignore:
        selected -= set(resolve(ignore))
    out = []
    for name in sorted(selected):
        out.extend(INVARIANTS[name](snap))
    return out


def assert_consistent(duthost, only=DEFAULT_GROUP, ignore=None, snap=None):
    """Do the databases agree? Raises AssertionError naming what diverged.

        oracle.assert_consistent(duthost)                  # parity: the answer you almost always want
        oracle.assert_consistent(duthost, only="all")      # parity + health + signal
        oracle.assert_consistent(duthost, only="health")   # is the box even up

    ``only`` takes a group, an invariant name, or a list of either. It defaults to ``parity``
    because that is Oracle's job: health checks answer a different question and belong in a
    steady-state gate, not in a statement about whether APPL_DB and ASIC_DB agree.

    Pass ``snap`` to check a snapshot you already took rather than paying for another. Invariants
    that could not run are logged, never raised on -- see UNCHECKED.
    """
    snap = snap if snap is not None else snapshot(duthost)
    real, notices = split_unchecked(check(snap, only=only, ignore=ignore))
    for notice in notices:
        logger.warning("[oracle] %s could not run: %s", notice.kind, notice.detail)
    if real:
        raise AssertionError(format_divergences(
            real, header="{}: {} invariant violation(s)".format(duthost.hostname, len(real))))
    return snap


def format_divergences(divs, header=""):
    lines = [header] if header else []
    for d in divs:
        lines.append("  {:<10} {:<9} {}  {}".format(d.kind, d.db, d.key, d.detail))
    return "\n".join(lines)


# ----------------------------------------------------------------------------- built-in invariants

# route_check.py's own failure modes, as opposed to its verdicts. Matched against its output.
TOOL_ERROR = re.compile(r"Failed to parse FRR|premature EOF|Error processing namespace|Traceback \(most recent|"
                        r"No such file|Connection refused|Could not connect|command not found", re.I)


@invariant("route_check", group="parity")
def route_check(snap):
    """SONiC's own APPL_DB vs ASIC_DB vs FRR route checker, already on the box.

    ``/usr/local/bin/route_check.py`` (verified present on a lab switch) is the route invariant we
    would otherwise have written by hand, maintained upstream and aware of every exception the
    platform legitimately has. Non-zero exit means the three views disagree; it prints the
    missing/extra sets as JSON.

    This is the invariant most likely to catch the cold-restart route-loss family, where a cold orchagent
    restart removes ASIC state that APPL_DB still holds.
    """
    if snap.duthost is None:
        return []   # snapshot loaded from disk: nothing to shell out to
    res = snap.duthost.shell("route_check.py", module_ignore_errors=True)
    if res.get("rc", 0) == 0:
        return []
    detail = (res.get("stdout") or res.get("stderr") or "").strip()
    # route_check.py exits 1 for two different reasons, and only one of them is a finding. A real
    # mismatch prints the missing/extra route sets as JSON. A TOOL failure -- it could not read
    # FRR because bgp was mid-restart and `show ip route json` came back truncated -- raises
    # "Failed to parse FRR route JSON: parse error: premature EOF" and also exits 1. Reporting
    # that as "APPL_DB/ASIC_DB diverged" made a kill of orchagent (which restarts the whole swss
    # container, taking bgp with it) read as a route divergence that "stayed diverged" for the
    # entire recovery budget, when the checker simply had nothing to read yet. Seen on a lab switch;
    # the same box passed rc=0 with 37 MB of FRR JSON the moment bgp was back.
    if TOOL_ERROR.search(detail):
        # the LAST line of that error is the caret ("(right here) ------^"); say the line that
        # actually names the failure
        why = next((ln for ln in detail.splitlines() if TOOL_ERROR.search(ln)),
                   detail.splitlines()[-1] if detail else "")
        return [Divergence("route_check" + UNCHECKED, "APPL_DB/ASIC_DB", "ROUTE_TABLE",
                           "could not run: " + why.strip()[:300] if why else "route_check.py failed to run")]
    return [Divergence("route_check", "APPL_DB/ASIC_DB", "ROUTE_TABLE", detail[:2000] or "route_check.py failed")]


# Key sets that are non-empty at rest on a healthy box, so a non-zero depth is not a backlog.
# Measured on a lab switch: GEARBOX_TABLE_KEY_SET sits at exactly 97 across repeated samples 5 s apart
# and never drains -- it is persistent gearbox state on a platform with a gbsyncd container, not
# work orchagent is behind on. Flagging it would fire on every run and bury the real signal.
# Re-measure per platform the way the denoise list is measured; a wrong entry here hides a bug.
PERSISTENT_KEY_SETS = frozenset(["GEARBOX_TABLE_KEY_SET"])


@invariant("key_set_backlog", group="signal",
           prefixes={"APPL_DB": ["*_KEY_SET"], "ASIC_DB": ["*_KEY_SET"]})
def key_set_backlog(snap):
    """A ProducerStateTable work queue still non-empty at rest means a daemon is falling behind.

    ``*_KEY_SET`` holds keys a producer has written but the consumer has not drained. Churn there
    is normal (and denoised out of diff); a persistently non-empty set after a settle is the
    earliest signal that orchagent is not keeping up -- it shows before anything times out.

    Caveat worth knowing: a single snapshot cannot tell "backlog" from "persistent state", which
    is why PERSISTENT_KEY_SETS exists and why *growth across a fault window* is the stronger
    signal. Compare two snapshots when you need that.
    """
    out = []
    for db in ("APPL_DB", "ASIC_DB"):
        for key in snap.keys(db):
            if not key.endswith("_KEY_SET") or key in PERSISTENT_KEY_SETS:
                continue
            value = snap.get(db, key, {}) or {}
            pending = value.get("_", value)
            depth = len(pending) if isinstance(pending, (list, tuple, dict)) else 0
            if depth:
                out.append(Divergence("key_set_backlog", db, key, "{} key(s) pending".format(depth)))
    return out


# Registers the invariant library. Deliberately at the bottom: invariants.py imports Divergence
# and invariant from this module, and by here both exist, so the import cycle resolves cleanly.
from . import invariants  # noqa: E402,F401  isort:skip
