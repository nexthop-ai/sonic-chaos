"""Oracle lane -- the invariant library.

An invariant is one thing that must be true. ``oracle.diff`` tells you *what changed*; an
invariant tells you *what is wrong*, by name, with no argument to have about whether a timeout
was too tight. That difference is the whole reason the Oracle lane exists.

Two families here:

**Cross-database** (``lag_member``, ``neighbor``, ``lag``, ``vlan_member``, ``vlan``) compare what APPL_DB
asked for against what ASIC_DB actually holds. They are pure functions of a snapshot, so they
run offline against a saved bundle. ASIC_DB refers to ports, LAGs and RIFs only by OID, so these
depend on the COUNTERS_DB name maps that ``oracle.snapshot`` now carries.

**Health** (``critical_processes``, ``no_cores``, ``bgp_established``) need the DUT, so they
return nothing when handed a snapshot loaded from disk.

Routes are deliberately absent: ``route_check`` in oracle.py wraps the on-box
``/usr/local/bin/route_check.py``, which is maintained upstream, knows the platform's legitimate
exceptions, and already handles in-flight updates. Reimplementing it would be strictly worse.

Shapes verified on a lab switch (202511.2, t2-single-node-min) -- see the module tests in
``selftest.py`` and the live check in ``scripts/check_invariants.py``.
"""
import ipaddress
import json
import logging
import re

from .oracle import UNCHECKED, Divergence, invariant

logger = logging.getLogger(__name__)

ASIC_PREFIX = "ASIC_STATE:SAI_OBJECT_TYPE_"

# COUNTERS_DB name maps, keyed name -> "oid:0x...". oracle.snapshot pulls these so a snapshot is
# self-contained and cross-DB invariants work offline.
PORT_MAP = "COUNTERS_PORT_NAME_MAP"
LAG_MAP = "COUNTERS_LAG_NAME_MAP"
RIF_MAP = "COUNTERS_RIF_NAME_MAP"
VLAN_MAP = "COUNTERS_VLAN_NAME_MAP"


# ----------------------------------------------------------------------------- helpers

def oid_to_name(snap, map_name):
    """Invert a COUNTERS_DB name map into ``{oid: name}``.

    Returns ``None`` when the map is absent from the snapshot -- that is "cannot check", which an
    invariant must report differently from "inconsistent". Guessing here would manufacture
    findings on any platform that simply does not have the map (a lab switch has no VLAN map).

    Filters the empty-key artifact: COUNTERS_LAG_NAME_MAP really does contain ``{"": ""}`` on
    a lab switch, and letting it through would map the empty OID to the empty name.
    """
    raw = snap.get("COUNTERS_DB", map_name)
    if raw is None:
        return None
    return {oid: name for name, oid in raw.items() if name and oid}


def asic_keys(snap, object_type):
    """Every ASIC_DB key of one SAI object type, e.g. ``"LAG_MEMBER"``."""
    return snap.keys("ASIC_DB", ASIC_PREFIX + object_type + ":")


def asic_entry_key(key, object_type):
    """The part of an ASIC_DB key after the object type.

    For OID-keyed objects that is ``"oid:0x..."``; for entry-keyed objects (route, neighbour) it
    is a JSON blob::

        ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{"ip":"10.0.0.1","rif":"oid:0x6...","switch_id":"..."}
    """
    return key[len(ASIC_PREFIX + object_type) + 1:]


def parse_entry_key(key, object_type):
    """Decode the JSON blob in an entry-keyed ASIC_DB key. ``None`` if it is not JSON."""
    blob = asic_entry_key(key, object_type)
    if not blob.startswith("{"):
        return None
    try:
        return json.loads(blob)
    except ValueError:
        return None


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def norm_mac(mac):
    """MACs are lowercase in APPL_DB and uppercase in ASIC_DB. Verified on a lab switch:
    APPL ``22:e7:e9:cc:22:46`` vs ASIC ``22:28:8A:41:64:4B``. Comparing raw would flag every
    neighbour on the box."""
    return (mac or "").strip().lower()


def norm_ip(addr):
    """Normalise an address so two spellings of the same IPv6 do not read as a divergence.

    ``fc00::12`` and ``fc00:0:0:0:0:0:0:12`` are the same address; a string compare says they are
    not. Falls back to the stripped original for anything unparseable rather than dropping it,
    because silently discarding a key would hide a real entry.
    """
    text = (addr or "").strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _cannot_check(name, reason):
    """Report an invariant that could not run. Visible in the report, never fatal."""
    return [Divergence(name + UNCHECKED, "-", "(not checked)", reason)]


# ----------------------------------------------------------------------------- cross-database

@invariant("lag_member", group="parity",
           prefixes={"APPL_DB": ["LAG_MEMBER_TABLE:"], "ASIC_DB": [ASIC_PREFIX + "LAG_MEMBER:"]})
def lag_member(snap):
    """Every APPL_DB LAG member is programmed in ASIC_DB, and vice versa.

        APPL_DB  LAG_MEMBER_TABLE:PortChannel101:Ethernet12          {status: enabled}
        ASIC_DB  ...SAI_OBJECT_TYPE_LAG_MEMBER:oid:0x1b...           {LAG_ID: oid:0x2..., PORT_ID: oid:0x1...}

    An ASIC-side member with no APPL_DB counterpart is the stale-member shape: a stale entry the
    remove silently failed to clear, which re-arms the next orchagent restart into a crash.
    """
    lags = oid_to_name(snap, LAG_MAP)
    ports = oid_to_name(snap, PORT_MAP)
    if lags is None or ports is None:
        return _cannot_check("lag_member", "COUNTERS_DB name maps absent from snapshot")

    appl = {}
    for key in snap.keys("APPL_DB", "LAG_MEMBER_TABLE:"):
        parts = key.split(":", 2)
        if len(parts) == 3:
            appl[(parts[1], parts[2])] = key

    asic, dangling = {}, []
    for key in asic_keys(snap, "LAG_MEMBER"):
        value = snap.get("ASIC_DB", key) or {}
        lag_oid = value.get("SAI_LAG_MEMBER_ATTR_LAG_ID")
        port_oid = value.get("SAI_LAG_MEMBER_ATTR_PORT_ID")
        lag_name, port_name = lags.get(lag_oid), ports.get(port_oid)
        if lag_name is None or port_name is None:
            dangling.append(Divergence(
                "lag_member", "ASIC_DB", key,
                "OID does not resolve via COUNTERS_DB: lag={} port={}".format(lag_oid, port_oid)))
            continue
        asic[(lag_name, port_name)] = key

    out = list(dangling)
    for pair in sorted(set(appl) - set(asic)):
        out.append(Divergence("lag_member", "APPL_DB", appl[pair],
                              "in APPL_DB, not programmed in ASIC_DB"))
    for pair in sorted(set(asic) - set(appl)):
        out.append(Divergence("lag_member", "ASIC_DB", asic[pair],
                              "programmed in ASIC_DB as {}:{}, absent from APPL_DB "
                              "(stale entry -- stale-member shape)".format(*pair)))
    return out


@invariant("lag", group="parity",
           prefixes={"APPL_DB": ["LAG_TABLE:"], "ASIC_DB": [ASIC_PREFIX + "LAG:"]})
def lag(snap):
    """Every APPL_DB LAG_TABLE PortChannel has an ASIC_DB LAG object, and vice versa."""
    lags = oid_to_name(snap, LAG_MAP)
    if lags is None:
        return _cannot_check("lag", "COUNTERS_LAG_NAME_MAP absent from snapshot")

    appl = {key[len("LAG_TABLE:"):]: key for key in snap.keys("APPL_DB", "LAG_TABLE:")}
    asic = {}
    for key in asic_keys(snap, "LAG"):
        oid = asic_entry_key(key, "LAG")
        name = lags.get(oid)
        if name is not None:
            asic[name] = key

    out = []
    for name in sorted(set(appl) - set(asic)):
        out.append(Divergence("lag", "APPL_DB", appl[name], "in APPL_DB, no ASIC_DB LAG object"))
    for name in sorted(set(asic) - set(appl)):
        out.append(Divergence("lag", "ASIC_DB", asic[name],
                              "ASIC_DB LAG {} absent from APPL_DB LAG_TABLE".format(name)))
    return out


@invariant("neighbor", group="parity",
           prefixes={"APPL_DB": ["NEIGH_TABLE:"], "ASIC_DB": [ASIC_PREFIX + "NEIGHBOR_ENTRY:"]})
def neighbor(snap):
    """APPL_DB neighbours match ASIC_DB neighbour entries, including the destination MAC.

        APPL_DB  NEIGH_TABLE:Ethernet132:10.0.0.103   {neigh: 22:e7:e9:cc:22:46, family: IPv4}
        ASIC_DB  ...NEIGHBOR_ENTRY:{"ip":"10.0.0.1","rif":"oid:0x6...",...}  {DST_MAC_ADDRESS: 22:28:...}

    MACs are compared case-insensitively and addresses are normalised, because APPL_DB writes
    lowercase MACs and ASIC_DB uppercase, and IPv6 has more than one spelling per address.
    """
    rifs = oid_to_name(snap, RIF_MAP)
    ports = oid_to_name(snap, PORT_MAP)
    lags = oid_to_name(snap, LAG_MAP)
    if rifs is None or ports is None or lags is None:
        return _cannot_check("neighbor", "COUNTERS_DB name maps absent from snapshot")

    # Only interfaces the ASIC can actually hold a neighbour for. neighsyncd writes every kernel
    # neighbour into APPL_DB, including ones on the management port -- a lab switch carries four
    # NEIGH_TABLE:eth0:* entries that will never be programmed, by design. Skipping them removes
    # exactly that noise (14 APPL - 4 mgmt = 10 = the ASIC count) while still catching a
    # front-panel neighbour that went missing, which is the bug we care about.
    asic_facing = set(ports.values()) | set(lags.values())

    appl, skipped = {}, []
    for key in snap.keys("APPL_DB", "NEIGH_TABLE:"):
        rest = key[len("NEIGH_TABLE:"):]
        ifname, _, addr = rest.partition(":")   # IPv6 contains ':', so split once only
        if not addr:
            continue
        if ifname not in asic_facing:
            skipped.append(ifname)
            continue
        appl[(ifname, norm_ip(addr))] = (key, norm_mac((snap.get("APPL_DB", key) or {}).get("neigh")))
    if skipped:
        logger.debug("[neighbor] skipped %d non-ASIC-facing neighbour(s) on %s",
                     len(skipped), ", ".join(sorted(set(skipped))))

    asic, dangling = {}, []
    for key in asic_keys(snap, "NEIGHBOR_ENTRY"):
        parsed = parse_entry_key(key, "NEIGHBOR_ENTRY")
        if not parsed:
            continue
        rif_name = rifs.get(parsed.get("rif"))
        if rif_name is None:
            dangling.append(Divergence("neighbor", "ASIC_DB", key,
                                       "rif {} does not resolve via COUNTERS_RIF_NAME_MAP"
                                       .format(parsed.get("rif"))))
            continue
        value = snap.get("ASIC_DB", key) or {}
        mac = norm_mac(value.get("SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS"))
        if mac == BROADCAST_MAC:
            # orchagent's directed-broadcast neighbour for an interface subnet (IntfsOrch adds
            # one per VLAN IPv4 subnet, e.g. Vlan1000 192.168.7.255 for 192.168.0.1/21). It is
            # programmed straight into the ASIC and never appears in NEIGH_TABLE, by design.
            continue
        asic[(rif_name, norm_ip(parsed.get("ip")))] = (key, mac)

    out = list(dangling)
    for pair in sorted(set(appl) - set(asic)):
        out.append(Divergence("neighbor", "APPL_DB", appl[pair][0],
                              "in APPL_DB, not programmed in ASIC_DB"))
    for pair in sorted(set(asic) - set(appl)):
        out.append(Divergence("neighbor", "ASIC_DB", asic[pair][0],
                              "programmed in ASIC_DB as {} {}, absent from APPL_DB".format(*pair)))
    for pair in sorted(set(appl) & set(asic)):
        appl_key, appl_mac = appl[pair]
        _, asic_mac = asic[pair]
        if appl_mac and asic_mac and appl_mac != asic_mac:
            out.append(Divergence("neighbor", "APPL_DB/ASIC_DB", appl_key,
                                  "MAC disagrees: APPL_DB {} vs ASIC_DB {}".format(appl_mac, asic_mac)))
    return out


@invariant("vlan_member", group="parity",
           prefixes={"APPL_DB": ["VLAN_MEMBER_TABLE:"],
                     "ASIC_DB": [ASIC_PREFIX + "VLAN_MEMBER:", ASIC_PREFIX + "VLAN:",
                                 ASIC_PREFIX + "BRIDGE_PORT:"]})
def vlan_member(snap):
    """Every APPL_DB VLAN member is programmed in ASIC_DB, and vice versa.

    ASIC_DB names neither end of a member directly: SAI_VLAN_MEMBER_ATTR_VLAN_ID is a VLAN OID and
    SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID a bridge-port OID. Both are resolved the way
    sonic_py_common.port_util does it for fdbshow: the VLAN through its own SAI_VLAN_ATTR_VLAN_ID
    (so no COUNTERS_VLAN_NAME_MAP is needed -- a lab switch has none), the bridge port through
    SAI_BRIDGE_PORT_ATTR_PORT_ID to a port or LAG OID, then the port and LAG name maps. A member
    whose references do not resolve points at an object that is not there, and is reported.
    """
    ports = oid_to_name(snap, PORT_MAP)
    if ports is None:
        return _cannot_check("vlan_member", "COUNTERS_PORT_NAME_MAP absent; ASIC ports cannot be named")
    names = dict(ports)
    names.update(oid_to_name(snap, LAG_MAP) or {})     # a PortChannel can be a VLAN member

    vid_of = {}
    for key in asic_keys(snap, "VLAN"):
        vid = (snap.get("ASIC_DB", key) or {}).get("SAI_VLAN_ATTR_VLAN_ID")
        if vid is not None and str(vid).isdigit():
            vid_of[asic_entry_key(key, "VLAN")] = int(vid)
    port_of_bridge_port = {}
    for key in asic_keys(snap, "BRIDGE_PORT"):
        port_oid = (snap.get("ASIC_DB", key) or {}).get("SAI_BRIDGE_PORT_ATTR_PORT_ID")
        if port_oid:
            port_of_bridge_port[asic_entry_key(key, "BRIDGE_PORT")] = port_oid

    appl = {}
    for key in snap.keys("APPL_DB", "VLAN_MEMBER_TABLE:"):
        parts = key.split(":", 2)
        if len(parts) == 3:
            appl[(parts[1], parts[2])] = key

    asic, dangling = {}, []
    for key in asic_keys(snap, "VLAN_MEMBER"):
        value = snap.get("ASIC_DB", key) or {}
        vlan_oid = value.get("SAI_VLAN_MEMBER_ATTR_VLAN_ID")
        bridge_port_oid = value.get("SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID")
        vid = vid_of.get(vlan_oid)
        port_name = names.get(port_of_bridge_port.get(bridge_port_oid))
        if vid is None or port_name is None:
            dangling.append(Divergence(
                "vlan_member", "ASIC_DB", key,
                "references an object that is not there: vlan={} ({}) bridge_port={} ({})".format(
                    vlan_oid, "vid {}".format(vid) if vid is not None else "no such VLAN",
                    bridge_port_oid, port_name or "no such port")))
            continue
        asic[("Vlan{}".format(vid), port_name)] = key

    out = list(dangling)
    for pair in sorted(set(appl) - set(asic)):
        out.append(Divergence("vlan_member", "APPL_DB", appl[pair],
                              "in APPL_DB, not programmed in ASIC_DB"))
    for pair in sorted(set(asic) - set(appl)):
        out.append(Divergence("vlan_member", "ASIC_DB", asic[pair],
                              "programmed in ASIC_DB, absent from APPL_DB (stale entry)"))
    return out


@invariant("vlan", group="parity",
           prefixes={"APPL_DB": ["VLAN_TABLE:"], "ASIC_DB": [ASIC_PREFIX + "VLAN:"]})
def vlan(snap):
    """Every APPL_DB VLAN is programmed in ASIC_DB, and vice versa.

    The probe-object check behind the SAI hijack demo: ``config vlan add 4001`` under a
    ``vlan:create`` status fault leaves ``VLAN_TABLE:Vlan4001`` in APPL_DB with no ASIC object --
    the swallowed-TABLE_FULL shape, which ``route_check`` cannot see. Keyed on
    ``SAI_VLAN_ATTR_VLAN_ID`` rather than COUNTERS_VLAN_NAME_MAP so it runs on t2 boxes that have
    no VLAN map (a lab switch) instead of reporting "cannot check". VLAN 1 is the ASIC default and is
    never in APPL_DB, so it is skipped rather than reported as stale.
    """
    appl = {}
    for key in snap.keys("APPL_DB", "VLAN_TABLE:"):
        name = key.split(":", 1)[1]
        if name.startswith("Vlan") and name[4:].isdigit():
            appl[int(name[4:])] = key

    asic = {}
    for key in asic_keys(snap, "VLAN"):
        vid = (snap.get("ASIC_DB", key) or {}).get("SAI_VLAN_ATTR_VLAN_ID")
        if vid is not None and str(vid).isdigit():
            asic[int(vid)] = key
    if 1 not in appl:
        asic.pop(1, None)

    out = []
    for vid in sorted(set(appl) - set(asic)):
        out.append(Divergence("vlan", "APPL_DB", appl[vid],
                              "in APPL_DB, not programmed in ASIC_DB"))
    for vid in sorted(set(asic) - set(appl)):
        out.append(Divergence("vlan", "ASIC_DB", asic[vid],
                              "programmed in ASIC_DB, absent from APPL_DB (stale entry)"))
    return out


# ----------------------------------------------------------------------------- health

_SUPERVISOR_ROW = re.compile(r"^(?P<name>\S+)\s+(?P<state>[A-Z]+)")


@invariant("critical_processes", group="health")
def critical_processes(snap):
    """Every process listed in a container's own critical_processes file is RUNNING.

    Read the list from the box rather than hard-coding it: each container ships
    ``/etc/supervisor/critical_processes`` with ``program:orchagent`` lines, and it differs per
    container and per release.

    Checking "everything supervisorctl reports is RUNNING" would be wrong -- a lab switch's swss has
    ``dependent-startup`` and ``enable_counters`` in state EXITED, which is normal for one-shot
    programs. Only the critical list matters.
    """
    if snap.duthost is None:
        return []
    containers = ("swss", "syncd", "bgp", "teamd", "pmon")
    out = []
    for container in containers:
        listing = snap.duthost.shell(
            "docker exec {} cat /etc/supervisor/critical_processes 2>/dev/null".format(container),
            module_ignore_errors=True)
        if listing.get("rc", 1) != 0:
            continue    # container not running on this platform; not our finding to report
        wanted = set()
        for line in (listing.get("stdout") or "").splitlines():
            line = line.strip()
            if line.startswith("program:"):
                wanted.add(line[len("program:"):].strip())
        if not wanted:
            continue

        status = snap.duthost.shell(
            "docker exec {} supervisorctl status 2>/dev/null".format(container),
            module_ignore_errors=True)
        states = {}
        for line in (status.get("stdout") or "").splitlines():
            match = _SUPERVISOR_ROW.match(line.strip())
            if match:
                states[match.group("name")] = match.group("state")

        for name in sorted(wanted):
            state = states.get(name)
            if state is None:
                # Listed critical but absent from supervisord config -- syncd on a lab switch lists
                # program:dsserve and supervisord has no such row. That is a static property of
                # the image, not something a fault caused, and it would fire on every single run.
                # We genuinely cannot verify that process's health, so say so instead.
                out.append(Divergence("critical_processes" + UNCHECKED, container, name,
                                      "listed critical but not known to supervisor -- "
                                      "cannot verify its health"))
            elif state != "RUNNING":
                out.append(Divergence("critical_processes", container, name,
                                      "state is {}, expected RUNNING".format(state)))
    return out


SERVICE_UNITS = ("swss", "syncd", "bgp", "teamd", "lldp", "pmon", "database")


@invariant("no_start_limit", group="health")
def no_start_limit(snap):
    """No SONiC service is stuck in systemd's start limit, or otherwise failed.

    The failure this exists for, seen on a lab switch (202511.2): two swss restarts inside
    systemd's 20-minute window (``StartLimitBurst=3``) left ``swss.service`` in
    ``Result=start-limit-hit ActiveState=failed`` with syncd, bgp and teamd inactive behind it.
    Nothing restarts it; the box sits dead until someone runs ``systemctl reset-failed``. Every
    other health check reads that as "orchagent not running" -- true, and useless. This one names
    the cause, and the fix.
    """
    if snap.duthost is None:
        return []
    probe = "echo \"$u $(systemctl show $u -p ActiveState -p Result 2>/dev/null | tr '\\n' ' ')\""
    cmd = "for u in {}; do {}; done".format(" ".join(SERVICE_UNITS), probe)
    res = snap.duthost.shell(cmd, module_ignore_errors=True)
    out = []
    for line in (res.get("stdout") or "").splitlines():
        parts = line.split()
        if not parts:
            continue
        unit, fields = parts[0], dict(kv.split("=", 1) for kv in parts[1:] if "=" in kv)
        result, active = fields.get("Result", ""), fields.get("ActiveState", "")
        if result == "start-limit-hit":
            out.append(Divergence("no_start_limit", "systemd", unit + ".service",
                                  "start-limit-hit: systemd gave up restarting it; needs "
                                  "`systemctl reset-failed {}` before anything will bring it back".format(unit)))
        elif active == "failed":
            out.append(Divergence("no_start_limit", "systemd", unit + ".service",
                                  "ActiveState=failed (Result={})".format(result or "?")))
    return out


@invariant("no_cores", group="health")
def no_cores(snap):
    """No core files on the box.

    Absolute, not differential: a core predating the run is still worth surfacing, and the
    experiment's steady-state gate is what turns "there were already cores" into an invalid run
    rather than a finding. A lab switch baselines at 0.
    """
    if snap.duthost is None:
        return []
    res = snap.duthost.shell("ls -1 /var/core 2>/dev/null", module_ignore_errors=True)
    cores = [line.strip() for line in (res.get("stdout") or "").splitlines() if line.strip()]
    return [Divergence("no_cores", "system", "/var/core/" + core, "core file present")
            for core in sorted(cores)]


@invariant("bgp_established", group="health")
def bgp_established(snap):
    """Every configured BGP peer is Established -- read through vtysh, never STATE_DB.

    unified-FRR-mode: in unified FRR mode ``bgpmon`` does not run, so STATE_DB's NEIGH_STATE_TABLE is
    empty on our testbeds. An invariant reading it would find nothing and pass, every time.

    On a lab switch right now all five peers sit in ``Active`` with ``connectionsEstablished: 0``, so
    this correctly reports the box as not ready. That is what ``steady_state`` is for: the run is
    invalid, not failed.
    """
    if snap.duthost is None:
        return []
    res = snap.duthost.shell("vtysh -c 'show ip bgp summary json'", module_ignore_errors=True)
    if res.get("rc", 1) != 0:
        return [Divergence("bgp_established", "bgp", "vtysh",
                           "could not read BGP summary: {}".format(
                               (res.get("stderr") or res.get("stdout") or "").strip()[:200]))]
    text = (res.get("stdout") or "").strip()
    start = text.find("{")
    try:
        summary = json.loads(text[start:]) if start >= 0 else {}
    except ValueError:
        return [Divergence("bgp_established", "bgp", "vtysh", "BGP summary was not valid JSON")]

    out = []
    for af_name, af in sorted(summary.items()):
        if not isinstance(af, dict):
            continue
        for peer, info in sorted((af.get("peers") or {}).items()):
            state = info.get("state", info.get("bgpState", "unknown"))
            if state != "Established":
                out.append(Divergence("bgp_established", af_name, peer,
                                      "state is {} (established {} times)".format(
                                          state, info.get("connectionsEstablished", "?"))))
    return out
