"""Kernel/protocol lane -- flood the CPU-bound learning paths from the PTF.

    --chaos storm=arp:rate=5000:seconds=30      ARP storm
    --chaos storm=nd:rate=5000                  IPv6 neighbour discovery
    --chaos storm=mac:rate=20000                MAC-move storm (same MACs, flapping ports)
    --chaos storm=netlink                       LAG flap at high rate -> netlink burst

These are the faults that attack the *path between* the kernel and the daemons, which nothing
else in the catalogue touches. What they expose:

* **CoPP actually working.** Every one of these lands on a CPU queue. If a queue is unpoliced,
  a storm on it starves the control plane -- BGP drops while the box is technically healthy.
* **ENOBUFS in the syncd family.** A netlink burst overruns the socket buffers in fpmsyncd,
  teamsyncd and neighsyncd. netlink-flap-storm is exactly this: a PortChannel flap storm floods netlink,
  fpmsyncd hits ENOBUFS, and neighbours stop resolving. The daemon does not crash; it silently
  misses updates, which is the worst failure mode we have.
* **FDB churn.** A MAC-move storm rewrites the same entries thousands of times per second and
  is the cheapest way to find FDB accounting bugs.

Mechanism: scapy from the PTF container, which already faces every DUT port. ``netlink`` is the
exception -- it is driven on the DUT by flapping a LAG member, no traffic needed.

Assert on ``dmesg``/syslog for ENOBUFS, on CoPP queue counters, and on neighbours still
resolving *after* the storm stops. A storm that passes while it runs but leaves stale neighbours
behind is the finding.
"""
import logging

from ..injector import (
    Injector, ChaosUsageError, register, run, quote, sudo_prefix, deadman_tag,
)

logger = logging.getLogger(__name__)

KINDS = ("arp", "nd", "mac", "netlink")
# arp/nd/mac need scapy on a PTF peer; netlink is driven entirely on the DUT.
DUT_KINDS = ("netlink",)
MARKER = "sonic-chaos-storm"
# netlink mechanisms. The console offered all three while the plugin silently did `lag` for
# every one -- the exact silent-no-op this plugin is meant to have none of.
#   lag    flap a PortChannel member (RTM_NEWLINK storm through teamsyncd; the netlink-flap-storm shape)
#   link   flap a routed front-panel port that is NOT in a LAG (same storm, no teamd in the path)
#   neigh  churn scratch neighbours with `ip neigh replace/del` (RTM_NEWNEIGH/DELNEIGH storm into
#          neighsyncd). Link-local 169.254 addresses on a routed interface: the kernel emits the
#          events, and neighsyncd -- as measured on a lab switch -- ignores off-link entries, so nothing
#          reaches the ASIC. Pure netlink pressure, no dataplane change.
HOWS = ("lag", "link", "neigh")
COUNT_FILE = "/tmp/sonic-chaos-storm-flaps"


@register
class StormInjector(Injector):
    name = "storm"
    lane = "oracle"
    positional = ("kind", "rate")
    defaults = {"rate": "5000", "seconds": "30", "port": "", "count": "1000", "how": "lag"}
    # The console reads this to grey out what will refuse at apply time, with the reason.
    CAPABILITIES = {
        "kind": {"available": ["netlink"],
                 "unavailable": {k: "needs scapy on the PTF peer; ChaosSession now carries a ptfhost "
                                    "but the sender is not written yet" for k in ("arp", "nd", "mac")}},
        "how": {"available": ["lag", "link", "neigh"], "unavailable": {}},
    }

    def validate(self):
        p = self.params
        if "kind" not in p:
            raise ChaosUsageError("storm: needs a kind, one of {}".format("/".join(KINDS)))
        if p["kind"] not in KINDS:
            raise ChaosUsageError("storm: kind must be one of {}, got {!r}".format(
                "/".join(KINDS), p["kind"]))
        if p["kind"] not in DUT_KINDS:
            raise ChaosUsageError(
                "storm: {!r} is not implemented yet -- arp/nd/mac need a scapy sender on the PTF "
                "peer that is not written. Only netlink runs today; use kind=netlink.".format(p["kind"]))
        for key, lo, hi in (("rate", 1, 1000000), ("seconds", 1, 600), ("count", 1, 1000000)):
            try:
                value = int(p[key])
            except ValueError:
                raise ChaosUsageError("storm: {} must be an integer, got {!r}".format(key, p[key]))
            if not lo <= value <= hi:
                raise ChaosUsageError("storm: {} must be {}..{}, got {}".format(key, lo, hi, value))
        if p["how"] not in HOWS:
            raise ChaosUsageError("storm: how must be one of {}, got {!r}".format("/".join(HOWS), p["how"]))

    # -- target ---------------------------------------------------------------------------------

    def lag_member(self, duthost):
        """A LAG member to flap. Prefers a PortChannel with more than one member.

        Flapping the only member of a LAG takes the LAG -- and any BGP session over it -- down for
        the duration, which turns a netlink-pressure test into a link-down test. With a spare
        member the LAG stays up and the fault stays the one we meant to inject.
        """
        if getattr(self, "_member", None):
            return self._member
        rc, out, _ = run(duthost, "{}sonic-db-cli CONFIG_DB KEYS 'PORTCHANNEL_MEMBER|*'".format(
            sudo_prefix(duthost)))
        members = {}
        for key in (out or "").split():
            parts = key.split("|")
            if len(parts) == 3:
                members.setdefault(parts[1], []).append(parts[2])
        if not members:
            raise RuntimeError(
                "storm: no PortChannel members on {} -- how=lag needs a LAG member to flap; "
                "how=link or how=neigh work without one".format(duthost.hostname))
        for pc, ports in sorted(members.items()):
            if len(ports) > 1:
                self._member = (pc, sorted(ports)[-1], True)
                return self._member
        pc, ports = sorted(members.items())[0]
        logger.warning("[storm] %s is the only member of %s: the LAG will go down while this "
                       "runs, so read a finding here knowing that", ports[0], pc)
        self._member = (pc, ports[0], False)
        return self._member

    def routed_port(self, duthost):
        """A front-panel port with an IP that is NOT a LAG member -- for how=link and how=neigh."""
        if getattr(self, "_member", None):
            return self._member
        rc, out, _ = run(duthost, "{}sonic-db-cli CONFIG_DB KEYS 'PORTCHANNEL_MEMBER|*'".format(
            sudo_prefix(duthost)))
        in_lag = {k.split("|")[2] for k in (out or "").split() if k.count("|") == 2}
        rc, out, _ = run(duthost, "{}ip -4 -br addr show".format(sudo_prefix(duthost)))
        for line in (out or "").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("Ethernet") and parts[0] not in in_lag:
                self._member = ("(none)", parts[0], True)
                return self._member
        raise RuntimeError("storm: no routed non-LAG Ethernet port on {} for how={}".format(
            duthost.hostname, self.params["how"]))

    def target(self, duthost):
        return self.lag_member(duthost) if self.params["how"] == "lag" else self.routed_port(duthost)

    @property
    def tag(self):
        return deadman_tag("storm", self.params["kind"])

    def flap_script(self, member):
        """The loop, as one shell line. `rate` is a target: the kernel sets the real ceiling."""
        rate = int(self.params["rate"])
        delay = "" if rate >= 200 else "sleep {:.4f}; ".format(1.0 / rate)
        if self.params["how"] == "neigh":
            # 169.254.200.N cycles through 250 scratch addresses; replace+del is two netlink
            # events per iteration, the same shape a neighbour flap produces.
            body = ("a=169.254.200.$((n%250+1)); ip neigh replace $a lladdr 00:11:22:33:44:55 dev {m} "
                    "nud permanent 2>/dev/null; ip neigh del $a dev {m} 2>/dev/null").format(m=member)
            tail = ("for i in $(seq 1 250); do ip neigh del 169.254.200.$i dev {m} 2>/dev/null; "
                    "done").format(m=member)
        else:
            body = "ip link set dev {m} down; ip link set dev {m} up".format(m=member)
            tail = "ip link set dev {m} up".format(m=member)
        return (
            "n=0; end=$(($(date +%s) + {secs})); "
            "while [ $(date +%s) -lt $end ]; do {body}; n=$((n+1)); {delay}"
            "done; echo $n > {cf}; {tail}"
        ).format(secs=int(self.params["seconds"]), body=body, delay=delay, cf=COUNT_FILE, tail=tail)

    # -- lifecycle ------------------------------------------------------------------------------

    def apply(self, duthost, **params):
        p = self.params
        pc, member, lag_survives = self.target(duthost)
        sudo = sudo_prefix(duthost)
        run(duthost, "{}sh -c {}".format(sudo, quote("rm -f " + COUNT_FILE)))
        # Baselines for the two things this fault is actually about: socket overruns, and whether
        # neighbours still resolve afterwards. Counted before, so the delta is attributable.
        _, enobufs, _ = run(duthost, "{}sh -c {}".format(sudo, quote(
            "dmesg 2>/dev/null | grep -ci enobufs; true")))
        _, neigh, _ = run(duthost, "{}sh -c {}".format(sudo, quote(
            "sonic-db-cli APPL_DB KEYS 'NEIGH_TABLE:*' | wc -l")))
        self._before = {"enobufs": int((enobufs or "0").split()[0] or 0),
                        "neighbours": int((neigh or "0").split()[0] or 0)}

        rc, _, err = run(duthost, "{}sh -c {}".format(sudo, quote(
            "setsid nohup sh -c {} {} >/dev/null 2>&1 &".format(
                quote(self.flap_script(member)), quote(MARKER)))))
        if rc != 0:
            raise RuntimeError("storm: could not start the flap loop on {}: {}".format(
                member, err[:200]))
        how = p["how"]
        if how == "lag":
            what = "flapping {} ({} of {})".format(
                member, "one member" if lag_survives else "the ONLY member", pc)
        elif how == "link":
            what = "flapping routed port {} (not in a LAG)".format(member)
        else:
            what = "churning scratch neighbours on {} (replace+del, off-link: netlink only)".format(member)
        events = ["netlink/{}: {} for {}s at up to {}/s{}".format(
            how, what, p["seconds"], p["rate"], "" if lag_survives else " -- the LAG will go down")]
        logger.info("[storm] %s on %s: %s", self.describe(), duthost.hostname, events[0])
        return self.record(duthost, action="storm", kind=p["kind"], portchannel=pc,
                           member=member, lag_survives=lag_survives,
                           baseline=self._before, events=events)

    def release(self, duthost):
        """Stop the loop, put the member back up, and report what the storm actually did."""
        sudo = sudo_prefix(duthost)
        pattern = "[{}]{}".format(MARKER[0], MARKER[1:])
        run(duthost, "{}pkill -9 -f {} || true".format(sudo, quote(pattern)))
        member = getattr(self, "_member", None)
        if member:
            # Unconditionally: a killed loop may have left the link down mid-cycle, or a scratch
            # neighbour behind.
            if self.params["how"] == "neigh":
                run(duthost, "{}sh -c {}".format(sudo, quote(
                    "for i in $(seq 1 250); do ip neigh del 169.254.200.$i dev {} 2>/dev/null; "
                    "done; true".format(member[1]))))
            else:
                run(duthost, "{}ip link set dev {} up".format(sudo, member[1]))
        rc, out, _ = run(duthost, "{}sh -c {}".format(sudo, quote(
            "cat {} 2>/dev/null || echo 0".format(COUNT_FILE))))
        try:
            self._flaps = int((out or "0").split()[0] or 0)
        except ValueError:
            self._flaps = 0
        run(duthost, "{}rm -f {}".format(sudo, COUNT_FILE))
        logger.info("[storm] released %s on %s after %s flaps",
                    self.describe(), duthost.hostname, self._flaps)

    def status(self, duthost):
        """The finding is never the flapping itself -- it is what did not come back afterwards.

        ENOBUFS in dmesg means a syncd-family socket overran and silently dropped updates
        (netlink-flap-storm). A neighbour count below baseline means they did not re-resolve.
        """
        sudo = sudo_prefix(duthost)
        member = getattr(self, "_member", None)
        rc, out, _ = run(duthost, "{}sh -c {}".format(sudo, quote(
            "echo ENOBUFS=$(dmesg 2>/dev/null | grep -ci enobufs; true); "
            "echo NEIGH=$(sonic-db-cli APPL_DB KEYS 'NEIGH_TABLE:*' | wc -l); "
            "echo RUNNING=$(pgrep -f '[s]onic-chaos-storm' | wc -l)")))
        fields = {}
        for line in (out or "").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                fields[k.strip()] = v.strip().split()[0] if v.strip() else "0"
        before = getattr(self, "_before", {}) or {}
        enobufs = int(fields.get("ENOBUFS", 0) or 0)
        neigh = int(fields.get("NEIGH", 0) or 0)
        return {
            "active": int(fields.get("RUNNING", 0) or 0) > 0,
            "kind": self.params["kind"],
            "member": member[1] if member else None,
            "flaps": getattr(self, "_flaps", None),
            "enobufs_before": before.get("enobufs"),
            "enobufs_now": enobufs,
            "enobufs_new": None if "enobufs" not in before else enobufs - before["enobufs"],
            "neighbours_before": before.get("neighbours"),
            "neighbours_now": neigh,
            # the real finding: neighbours that never came back
            "neighbours_lost": None if "neighbours" not in before else before["neighbours"] - neigh,
        }

    def expected_syslog(self):
        """A flap storm logs link up/down by the hundred. Those are the fault, not the finding."""
        return (r".*Port Ethernet\d+ oper state set from (up|down) to (up|down).*",
                r".*link (up|down).*")
