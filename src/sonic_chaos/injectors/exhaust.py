"""Resource lane -- push a hardware table past its limit and watch the way back.

    --chaos exhaust=route:120000        advertise routes until the FIB is over the CRM threshold
    --chaos exhaust=nhg                 fill nexthop groups
    --chaos exhaust=acl                 fill the ACL table
    --chaos exhaust=mirror              fill mirror sessions
    --chaos exhaust=fdb:200000          fill the MAC table

The interesting half is never the exhaustion, it is the recovery. Going over the limit is
supposed to produce a clean TABLE_FULL and a logged error; what actually happens in the tickets
is leaked objects, wrong CRM accounting, and stale entries that survive scaling back down.
Leaks of the ACL profile pool, the mirror table and ECMP groups are all this
shape: the box never returns to its pre-fault resource count.

So the assertion is a *round trip*: snapshot CRM counters, exceed, scale back, and require the
counters to return to baseline. A permanent delta is the bug, and it is invisible to any test
that only checks the error at the limit.

Scale comes from the PTF peer advertising routes, or from `sonic-db-cli` writes for table types
with no protocol path. Both are slow, so this is the fault to run last in a window.
"""
import logging
import time

from ..injector import Injector, ChaosUsageError, register, run, quote, sudo_prefix

logger = logging.getLogger(__name__)

# CRM resource name per table type -- `crm show resources all` reports used/available for these.
CRM_RESOURCE = {
    "route": "ipv4_route",
    "route6": "ipv6_route",
    "nhg": "nexthop_group",
    "nexthop": "ipv4_nexthop",
    "neighbor": "ipv4_neighbor",
    "acl": "acl_entry",
    "mirror": "mirror_session",
    "fdb": "fdb_entry",
}


# Tables this injector can actually fill from the DUT alone. The rest need a PTF peer or a
# protocol path we do not have here; they raise rather than silently doing nothing, because an
# injector that applies cleanly and injects nothing reports a pass for a fault that never ran.
IMPLEMENTED = ("route", "route6", "neighbor", "nexthop", "nhg", "acl")
# neighbor/nexthop move together: each programmed neighbour creates one of each, measured on
# a lab switch as 5 -> 505 on both counters for 500 neighbours.
NEIGH_TABLES = ("neighbor", "nexthop")
# A /31 point-to-point link has no room for thousands of neighbours, and neighsyncd only programs
# ON-LINK ones -- an off-subnet `ip neigh add` is accepted by the kernel and silently never
# reaches APPL_DB. So a roomy secondary subnet goes on first and comes off in release.
NEIGH_SUBNET = "10.200.0.1/16"
NEIGH_MAX = 60000
# One nexthop GROUP per distinct nexthop SET -- SONiC dedupes, so N routes sharing a set make one
# group, not N. Distinct pairs drawn from K neighbours give K*(K-1)/2 groups, which is why the
# neighbour count below is derived from the group count and not the other way round.
# nexthop_group is the one table here small enough to really exhaust: 1024 on the platform measured,
# against millions for routes and neighbours. The cap allows going past it so `count=0` can
# actually reach TABLE_FULL, which is the case the round trip is most interesting for.
NHG_MAX = 2000
NHG_PREFIX = "100.100"
# acl_entry is NOT in `crm show resources all`'s main list -- it lives in a per-ACL-table section
# keyed by Table ID, so it needs its own parser. Measured on a lab switch: 2048 entries per table.
ACL_TABLES_SECTION = "Table ID"
ACL_MAX = 4000
# Why these four still refuse, specifically -- the generic "needs a PTF peer" was wrong for them:
#   fdb    fdb_entry IS CRM-tracked, but needs a VLAN with members; a routed t2 topology has none
#   mirror mirror_session is not in this platform's CRM list at all, so there is nothing to assert
NOT_TRACKED = {
    "fdb": "fdb_entry is CRM-tracked but needs a VLAN with members to learn MACs into, and a "
           "routed topology has none. Creating one would change the box more than the fault does.",
    "mirror": "mirror_session does not appear in this platform's `crm show resources all` at all, "
              "so the round trip this injector asserts cannot be measured.",
}
# FRR runs in its own container. `vtysh -f /tmp/x.conf` on the host fails with "Can't open
# configuration file" from every daemon, because the daemons live in the container's mount
# namespace and never see a host /tmp. Generate and apply the config INSIDE the container.
FRR_CONTAINER = "bgp"
MAX_PUSH = 200000          # refuse to generate more than this in one go
CHUNK = 5000               # routes per vtysh file, so one failure does not lose the whole batch


@register
class ExhaustInjector(Injector):
    name = "exhaust"
    # What the console reads to grey out options that will refuse at apply time, with the
    # specific reason. `validate()` cannot tell it -- refusal happens in apply(), after the
    # steady-state gate has already been paid for.
    CAPABILITIES = {"table": {"available": list(IMPLEMENTED), "unavailable": dict(NOT_TRACKED)}}
    lane = "oracle"
    positional = ("table", "count")
    defaults = {"count": "0", "over_pct": "110", "settle": "60"}

    def validate(self):
        p = self.params
        if "table" not in p:
            raise ChaosUsageError("exhaust: needs a table, one of {}".format("/".join(sorted(CRM_RESOURCE))))
        if p["table"] not in CRM_RESOURCE:
            raise ChaosUsageError("exhaust: unknown table {!r}; known: {}".format(
                p["table"], ", ".join(sorted(CRM_RESOURCE))))
        for key in ("count", "over_pct", "settle"):
            try:
                int(p[key])
            except ValueError:
                raise ChaosUsageError("exhaust: {} must be an integer, got {!r}".format(key, p[key]))
        if int(p["over_pct"]) < 100:
            raise ChaosUsageError("exhaust: over_pct must be >= 100 (it is a percentage of the "
                                  "limit to reach), got {}".format(p["over_pct"]))

    @property
    def crm_resource(self):
        return CRM_RESOURCE[self.params["table"]]

    # -- CRM accounting ------------------------------------------------------------------------

    def _sh(self, duthost, script):
        return run(duthost, "{}sh -c {}".format(sudo_prefix(duthost), quote(script)))

    def acl_counts(self, duthost):
        """``(used, available)`` for acl_entry, summed across ACL tables.

        The per-table section looks like::

            Table ID         Resource Name    Used Count   Available Count
            0x7000000000a40  acl_entry                 20              2008

        Summed, because rules are added to one table but the baseline may span several, and only
        the delta is meaningful.
        """
        rc, out, _ = run(duthost, "{}crm show resources all".format(sudo_prefix(duthost)))
        used = avail = 0
        seen = False
        for line in (out or "").splitlines():
            parts = line.split()
            if len(parts) == 4 and parts[1] == "acl_entry":
                try:
                    used += int(parts[2])
                    avail += int(parts[3])
                    seen = True
                except ValueError:
                    continue
        if not seen:
            raise RuntimeError(
                "exhaust: no acl_entry rows in `crm show resources all` on {} -- no ACL table is "
                "bound, so there is nothing to fill".format(duthost.hostname))
        return used, avail

    def acl_table(self, duthost):
        """An L3 ingress ACL table to add rules to."""
        if getattr(self, "_acltab", None):
            return self._acltab
        rc, out, _ = run(duthost, "{}sonic-db-cli CONFIG_DB KEYS 'ACL_TABLE|*'".format(
            sudo_prefix(duthost)))
        names = [k.split("|", 1)[1] for k in (out or "").split() if "|" in k]
        for preferred in ("DATAACL", "DATAACL_1"):
            if preferred in names:
                self._acltab = preferred
                return preferred
        if not names:
            raise RuntimeError("exhaust: no ACL_TABLE on {} to add rules to".format(
                duthost.hostname))
        self._acltab = names[0]
        return self._acltab

    def acl_awk(self, table, start, count, delete=False):
        """sonic-db-cli lines for N ACL rules, generated on the DUT.

        The redis key contains a ``|`` so it has to be quoted for the shell, and a literal quote
        inside an awk string inside a shell string inside a Python string is three levels of
        escaping that silently collapsed the first time. ``%c`` with 39 emits the quote with no
        escaping anywhere.
        """
        end_i = start + count
        q = "%c"
        if delete:
            fmt = "sonic-db-cli CONFIG_DB DEL {q}ACL_RULE|{t}|CHAOS_%d{q}".format(q=q, t=table)
            args = "39, i, 39"
        else:
            fmt = ("sonic-db-cli CONFIG_DB HMSET {q}ACL_RULE|{t}|CHAOS_%d{q} PRIORITY %d "
                   "PACKET_ACTION DROP SRC_IP 10.210.%d.%d/32").format(q=q, t=table)
            args = "39, i, 39, 9000-(i%8000), int(i/256)%256, i%256"
        return ('BEGIN{for(i=' + str(start) + ';i<' + str(end_i) + ';i++) printf "'
                + fmt + chr(92) + 'n", ' + args + '}')

    def crm_counts(self, duthost):
        """``(used, available)`` for this table's CRM resource, read off ``crm show resources all``.

        The table is ``Resource Name / Used Count / Available Count``; the row name is matched
        exactly so ``ipv4_route`` does not also pick up ``ipv4_route_...`` variants.
        """
        if self.params["table"] == "acl":
            return self.acl_counts(duthost)
        rc, out, _ = run(duthost, "{}crm show resources all".format(sudo_prefix(duthost)))
        for line in (out or "").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == self.crm_resource:
                try:
                    return int(parts[1]), int(parts[2])
                except ValueError:
                    continue
        raise RuntimeError("exhaust: {} not found in `crm show resources all` on {}".format(
            self.crm_resource, duthost.hostname))

    def l3_interface(self, duthost):
        """A routed interface to hang the neighbours off. Cached; PortChannels preferred."""
        if getattr(self, "_l3if", None):
            return self._l3if
        rc, out, _ = run(duthost, "{}ip -4 -br addr show".format(sudo_prefix(duthost)))
        best = None
        for line in (out or "").splitlines():
            parts = line.split()
            if len(parts) < 3 or parts[0].startswith(("lo", "eth0", "docker", "Loopback")):
                continue
            if parts[0].startswith("PortChannel"):
                best = parts[0]
                break
            best = best or parts[0]
        if not best:
            raise RuntimeError("exhaust: no routed interface found on {} to add neighbours to"
                               .format(duthost.hostname))
        self._l3if = best
        return best

    def neigh_awk(self, iface, start, count, delete=False):
        """awk emitting `ip neigh` lines on the DUT -- same ARG_MAX dodge as the route path.

        Addresses start at .2: .0 is the network address of NEIGH_SUBNET and .1 is the interface's
        own IP, and a neighbour entry for either is nonsense.
        """
        end = start + count
        addr = "int((i+2)/256)%256, (i+2)%256"
        if delete:
            body = ('printf "ip neigh del 10.200.%d.%d dev ' + iface + chr(92) + 'n", ' + addr)
        else:
            body = ('printf "ip neigh replace 10.200.%d.%d lladdr 00:11:22:%02x:%02x:%02x dev '
                    + iface + ' nud permanent' + chr(92) + 'n", ' + addr
                    + ', int((i+2)/65536)%256, int((i+2)/256)%256, (i+2)%256')
        return "BEGIN{for(i=" + str(start) + ";i<" + str(end) + ";i++) " + body + "}"

    def nhg_awk(self, start, count, delete=False):
        """One ECMP route per group, each with a distinct PAIR of nexthops.

        Pair i is enumerated by triangular indexing -- a = floor((sqrt(8i+1)-1)/2)+1, b = i -
        a(a-1)/2 -- which walks every unordered pair exactly once, so every route gets a set no
        other route has and therefore a group of its own.
        """
        end = start + count
        kw = "no ip route" if delete else "ip route"
        pair = 'a=int((sqrt(8*i+1)-1)/2)+1; b=i-a*(a-1)/2; '
        line = ('printf "' + kw + ' ' + NHG_PREFIX + '.%d.%d/32 10.200.0.%d' + chr(92) + 'n", '
                'int(i/256)%256, i%256, ')
        return ("BEGIN{for(i=" + str(start) + ";i<" + str(end) + ";i++){" + pair
                + line + "a+2; " + line + "b+2}}")

    def nhg_neighbours_needed(self, groups):
        """Smallest K whose distinct pairs cover ``groups``: K*(K-1)/2 >= groups."""
        k = 2
        while k * (k - 1) // 2 < groups:
            k += 1
        return k

    def poll_interval(self, duthost):
        """CRM's polling interval in seconds -- how stale a `crm show` reading can be."""
        rc, out, _ = run(duthost, "{}crm show summary".format(sudo_prefix(duthost)))
        for word in (out or "").split():
            if word.isdigit():
                return int(word)
        return 300          # SONiC's default

    def wait_for_crm(self, duthost, differs_from, timeout=None):
        """Read CRM until it stops reporting the pre-push number, or we run out of patience.

        CRM counters are POLLED, not live. Reading immediately after a push reports the old value
        and `peak` silently under-reports -- seen exactly that way: 2000 IPv6 routes pushed, peak
        recorded as unchanged, and the same counter 2000 higher moments later. A fast push beats
        the poll; a slow one does not, which is why the IPv4 run hid this.
        """
        interval = self.poll_interval(duthost)
        deadline = time.time() + (timeout if timeout is not None else interval * 2 + 15)
        used = differs_from
        while time.time() < deadline:
            used, _ = self.crm_counts(duthost)
            if used != differs_from:
                return used
            time.sleep(min(5, max(1, interval // 2)))
        logger.warning("[exhaust] CRM still reads %s after %ss (poll interval %ss); the number "
                       "below may be stale", used, round(time.time() - deadline), interval)
        return used

    def target_count(self, used, available):
        """How many entries to push. ``count=0`` derives it from the limit and ``over_pct``."""
        want = int(self.params["count"])
        if not want:
            limit = used + available
            want = max(0, int(limit * int(self.params["over_pct"]) / 100.0) - used)
        return min(want, MAX_PUSH)

    def prefixes(self, n, start=0):
        """``n`` /32s (or /128s) from a documentation range that cannot collide with real routing."""
        v6 = self.params["table"] == "route6"
        for i in range(start, start + n):
            if v6:
                yield "2001:db8:{:x}:{:x}::1/128".format((i >> 16) & 0xFFFF, i & 0xFFFF)
            else:
                # 100.64.0.0/10 (CGNAT) -- 4M addresses, not routed in these topologies
                yield "100.{}.{}.{}/32".format(64 + ((i >> 16) & 0x3F), (i >> 8) & 0xFF, i & 0xFF)

    def awk_program(self, kw, start, count):
        """awk that emits the same prefixes as ``prefixes()``, but ON the DUT.

        Shipping the config inline died with ``OSError: [Errno 7] Argument list too long`` at 5000
        routes -- 175KB of argv. Generating on the far side keeps the command a few hundred bytes
        no matter how many routes are asked for, and is faster than chunking round trips.
        """
        end = start + count
        if self.params["table"] == "route6":
            expr = ('printf "' + kw + ' 2001:db8:%x:%x::1/128 ' + self.blackhole() + chr(92) + 'n", '
                    'int(i/65536)%65536, i%65536')
        else:
            expr = ('printf "' + kw + ' 100.%d.%d.%d/32 ' + self.blackhole() + chr(92) + 'n", '
                    '64+int(i/65536)%64, int(i/256)%256, i%256')
        return "BEGIN{for(i=" + str(start) + ";i<" + str(end) + ";i++) " + expr + "}"

    def vtysh_cmd(self, duthost, kw, base, n, tag):
        """Generate the config in the FRR container and feed it to vtysh there."""
        path = "/tmp/sonic-chaos-{}-{}.conf".format(tag, base)
        inner = "awk {} > {} && vtysh -f {}".format(
            quote(self.awk_program(kw, base, n)), path, path)
        return "{}docker exec {} sh -c {}".format(
            sudo_prefix(duthost), FRR_CONTAINER, quote(inner))

    def blackhole(self):
        """Static routes to Null0: they consume a FIB entry without needing a reachable next-hop.

        A next-hop that must be resolved would make this a neighbour test as well, and an
        unresolvable one would sit in orchagent's retry loop instead of programming -- which is a
        different fault (orchagent-retry-queue) and would make the CRM round trip meaningless.
        """
        return "Null0"

    # -- lifecycle -----------------------------------------------------------------------------

    def apply(self, duthost, **params):
        p = self.params
        if p["table"] not in IMPLEMENTED:
            why = NOT_TRACKED.get(
                p["table"],
                "it needs a traffic source or a config path this injector does not have")
            raise ChaosUsageError(
                "exhaust: table {!r} is not implemented -- {}. Implemented: {}.".format(
                    p["table"], why, "/".join(IMPLEMENTED)))

        used, available = self.crm_counts(duthost)
        self._baseline = used
        if p["table"] in NEIGH_TABLES:
            return self._apply_neigh(duthost, used, available)
        if p["table"] == "nhg":
            return self._apply_nhg(duthost, used, available)
        if p["table"] == "acl":
            return self._apply_acl(duthost, used, available)
        want = self.target_count(used, available)
        if want <= 0:
            raise RuntimeError(
                "exhaust: nothing to push for {} (used={} available={}, over_pct={}); the table is "
                "already past the requested reach".format(
                    self.crm_resource, used, available, p["over_pct"]))

        kw = "ipv6 route" if p["table"] == "route6" else "ip route"
        # Track progress on self as we go, not at the end: if the push raises half way, release()
        # still has to know how many prefixes are on the box. Setting this only after the loop
        # meant an exception left the routes installed and release() withdrew nothing.
        self._pushed = 0
        for base in range(0, want, CHUNK):
            n = min(CHUNK, want - base)
            rc, _, err = run(duthost, self.vtysh_cmd(duthost, kw, base, n, "exhaust"))
            if rc != 0:
                logger.warning("[exhaust] chunk at %s failed (this may be the limit): %s",
                               base, (err or "")[:200])
                break
            self._pushed += n
        pushed = self._pushed

        peak = self.wait_for_crm(duthost, used) if pushed else used
        self._peak = peak
        events = ["{}: pushed {} of {} requested; CRM {} used {} -> {} (baseline available {})"
                  .format(p["table"], pushed, want, self.crm_resource, used, peak, available)]
        logger.info("[exhaust] %s on %s: %s", self.describe(), duthost.hostname, events[0])
        return self.record(duthost, action="exhaust", table=p["table"],
                           resource=self.crm_resource, baseline=used, pushed=pushed,
                           peak=peak, events=events)

    def _apply_neigh(self, duthost, used, available):
        """Fill the neighbour table: roomy subnet on, then N permanent neighbours in it."""
        p, sudo = self.params, sudo_prefix(duthost)
        iface = self.l3_interface(duthost)
        want = min(self.target_count(used, available), NEIGH_MAX)
        if want <= 0:
            raise RuntimeError("exhaust: nothing to push for {} (used={} available={})".format(
                self.crm_resource, used, available))

        rc, _, err = run(duthost, "{}config interface ip add {} {}".format(
            sudo, iface, NEIGH_SUBNET))
        if rc != 0:
            raise RuntimeError("exhaust: could not add {} to {}: {}".format(
                NEIGH_SUBNET, iface, err[:200]))
        self._secondary = (iface, NEIGH_SUBNET)
        time.sleep(5)

        self._pushed = 0
        rc, _, err = run(duthost, "{}sh -c {}".format(sudo, quote(
            "awk {} > /tmp/sonic-chaos-neigh.sh && sh /tmp/sonic-chaos-neigh.sh".format(
                quote(self.neigh_awk(iface, 0, want))))))
        if rc != 0:
            logger.warning("[exhaust] neighbour push reported: %s", (err or "")[:200])
        self._pushed = want

        peak = self.wait_for_crm(duthost, used)
        self._peak = peak
        events = ["{}: {} neighbours on {} via {}; CRM {} used {} -> {}".format(
            p["table"], want, iface, NEIGH_SUBNET, self.crm_resource, used, peak)]
        logger.info("[exhaust] %s on %s: %s", self.describe(), duthost.hostname, events[0])
        return self.record(duthost, action="exhaust", table=p["table"],
                           resource=self.crm_resource, baseline=used, pushed=want,
                           peak=peak, interface=iface, events=events)

    def _apply_acl(self, duthost, used, available):
        """Fill an ACL table with drop rules, each matching a distinct source address."""
        p, sudo = self.params, sudo_prefix(duthost)
        table = self.acl_table(duthost)
        want = min(self.target_count(used, available), ACL_MAX)
        if want <= 0:
            raise RuntimeError("exhaust: nothing to push for {} (used={} available={})".format(
                self.crm_resource, used, available))
        self._pushed = 0
        rc, _, err = run(duthost, "{}sh -c {}".format(sudo, quote(
            "awk {} > /tmp/sonic-chaos-acl.sh && sh /tmp/sonic-chaos-acl.sh".format(
                quote(self.acl_awk(table, 0, want))))))
        if rc != 0:
            logger.warning("[exhaust] acl push reported: %s", (err or "")[:200])
        self._pushed = want

        peak = self.wait_for_crm(duthost, used)
        self._peak = peak
        events = ["acl: {} drop rules in {}; CRM {} used {} -> {}".format(
            want, table, self.crm_resource, used, peak)]
        logger.info("[exhaust] %s on %s: %s", self.describe(), duthost.hostname, events[0])
        return self.record(duthost, action="exhaust", table=p["table"],
                           resource=self.crm_resource, baseline=used, pushed=want,
                           peak=peak, acl_table=table, events=events)

    def _release_acl(self, duthost):
        sudo = sudo_prefix(duthost)
        pushed = getattr(self, "_pushed", 0)
        if pushed and getattr(self, "_acltab", None):
            run(duthost, "{}sh -c {}".format(sudo, quote(
                "awk {} > /tmp/sonic-chaos-acld.sh && sh /tmp/sonic-chaos-acld.sh".format(
                    quote(self.acl_awk(self._acltab, 0, pushed, delete=True))))))
        run(duthost, "{}rm -f /tmp/sonic-chaos-acl*.sh".format(sudo))

    def _apply_nhg(self, duthost, used, available):
        """Fill the nexthop-group table with ECMP routes over a pool of fake neighbours."""
        p, sudo = self.params, sudo_prefix(duthost)
        iface = self.l3_interface(duthost)
        want = min(self.target_count(used, available), NHG_MAX)
        if want <= 0:
            raise RuntimeError("exhaust: nothing to push for {} (used={} available={})".format(
                self.crm_resource, used, available))
        k = self.nhg_neighbours_needed(want)

        rc, _, err = run(duthost, "{}config interface ip add {} {}".format(
            sudo, iface, NEIGH_SUBNET))
        if rc != 0:
            raise RuntimeError("exhaust: could not add {} to {}: {}".format(
                NEIGH_SUBNET, iface, err[:200]))
        self._secondary = (iface, NEIGH_SUBNET)
        time.sleep(5)
        # the nexthop pool first: routes pointing at unresolved nexthops never program
        run(duthost, "{}sh -c {}".format(sudo, quote(
            "awk {} > /tmp/sonic-chaos-neigh.sh && sh /tmp/sonic-chaos-neigh.sh".format(
                quote(self.neigh_awk(iface, 0, k))))))
        time.sleep(8)

        self._pushed = 0
        rc, _, err = run(duthost, "{}docker exec {} sh -c {}".format(
            sudo, FRR_CONTAINER, quote(
                "awk {} > /tmp/sonic-chaos-nhg.conf && vtysh -f /tmp/sonic-chaos-nhg.conf".format(
                    quote(self.nhg_awk(0, want))))))
        if rc != 0:
            logger.warning("[exhaust] nhg push reported: %s", (err or "")[:200])
        self._pushed = want

        peak = self.wait_for_crm(duthost, used)
        self._peak = peak
        events = ["nhg: {} ECMP routes over {} neighbours on {}; CRM {} used {} -> {}".format(
            want, k, iface, self.crm_resource, used, peak)]
        logger.info("[exhaust] %s on %s: %s", self.describe(), duthost.hostname, events[0])
        return self.record(duthost, action="exhaust", table=p["table"],
                           resource=self.crm_resource, baseline=used, pushed=want,
                           peak=peak, interface=iface, neighbours=k, events=events)

    def _release_nhg(self, duthost):
        sudo = sudo_prefix(duthost)
        pushed = getattr(self, "_pushed", 0)
        if pushed:
            run(duthost, "{}docker exec {} sh -c {}".format(
                sudo, FRR_CONTAINER, quote(
                    "awk {} > /tmp/sonic-chaos-nhgd.conf && vtysh -f /tmp/sonic-chaos-nhgd.conf"
                    .format(quote(self.nhg_awk(0, pushed, delete=True))))))
            run(duthost, "{}docker exec {} rm -f /tmp/sonic-chaos-nhg*.conf".format(
                sudo, FRR_CONTAINER))
        self._release_neigh(duthost)

    def _release_neigh(self, duthost):
        sudo = sudo_prefix(duthost)
        iface = getattr(self, "_l3if", None)
        # nhg creates a small nexthop POOL, not one neighbour per group -- delete what was made.
        made = (self.nhg_neighbours_needed(self._pushed)
                if self.params["table"] == "nhg" and getattr(self, "_pushed", 0)
                else getattr(self, "_pushed", 0))
        if iface and made:
            run(duthost, "{}sh -c {}".format(sudo, quote(
                "awk {} > /tmp/sonic-chaos-neighd.sh && sh /tmp/sonic-chaos-neighd.sh".format(
                    quote(self.neigh_awk(iface, 0, made, delete=True))))))
        sec = getattr(self, "_secondary", None)
        if sec:
            # Always take the secondary subnet back off: leaving it would change the box's
            # addressing for everything that runs after this fault.
            rc, _, err = run(duthost, "{}config interface ip remove {} {}".format(
                sudo, sec[0], sec[1]))
            if rc != 0:
                logger.error("[exhaust] could not remove %s from %s: %s", sec[1], sec[0], err[:150])
            else:
                self._secondary = None
        run(duthost, "{}rm -f /tmp/sonic-chaos-neigh*.sh".format(sudo))

    def release(self, duthost):
        """Withdraw everything, settle, and re-read CRM. A used-count above baseline is the finding."""
        p = self.params
        if p["table"] in NEIGH_TABLES:
            self._release_neigh(duthost)
        elif p["table"] == "nhg":
            self._release_nhg(duthost)
        elif p["table"] == "acl":
            self._release_acl(duthost)
        else:
            self._release_routes(duthost)
        time.sleep(int(p["settle"]))
        after = self.wait_for_crm(duthost, getattr(self, "_peak", None))
        self._after = after
        baseline = getattr(self, "_baseline", None)
        if baseline is not None and after > baseline:
            logger.error("[exhaust] LEAK on %s: %s used %s before, %s after release (+%s) -- the "
                         "box did not return to its pre-fault resource count",
                         duthost.hostname, self.crm_resource, baseline, after, after - baseline)
        else:
            logger.info("[exhaust] released %s on %s: %s back to %s (baseline %s)",
                        self.describe(), duthost.hostname, self.crm_resource, after, baseline)

    def _release_routes(self, duthost):
        p = self.params
        kw = "no ipv6 route" if p["table"] == "route6" else "no ip route"
        pushed = getattr(self, "_pushed", 0)
        for base in range(0, pushed, CHUNK):
            n = min(CHUNK, pushed - base)
            run(duthost, self.vtysh_cmd(duthost, kw, base, n, "unexhaust"))
        run(duthost, "{}docker exec {} sh -c {}".format(
            sudo_prefix(duthost), FRR_CONTAINER,
            quote("rm -f /tmp/sonic-chaos-*exhaust-*.conf")))

    def pressure_evidence(self, duthost):
        """What the box says when a table fills -- which is NOT "TABLE_FULL".

        Driving nexthop_group to its 1024 limit on a lab switch produced zero SAI_STATUS_TABLE_FULL,
        SAI_STATUS_INSUFFICIENT_RESOURCES or NO_MEMORY lines. The only thing that said anything
        was CRM's own threshold monitor:

            checkCrmThresholds: NEXTHOP_GROUP THRESHOLD_EXCEEDED for TH_PERCENTAGE 100%
                                Used count 1024 free count 0

        The 96 groups that did not fit were never logged at all -- they sit in orchagent's
        in-memory retry queue, invisible to redis (the orchagent-retry-queue signature). So grep for both,
        and treat "the table was full and nothing said SAI failed" as the interesting case.
        """
        rc, out, _ = self._sh(duthost, (
            "echo THRESHOLD=$(grep -c THRESHOLD_EXCEEDED /var/log/syslog); "
            "echo SAIFULL=$(grep -cE "
            "'SAI_STATUS_(TABLE_FULL|INSUFFICIENT_RESOURCES|NO_MEMORY)' /var/log/syslog)"))
        got = {}
        for line in (out or "").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                got[k.strip()] = int((v.strip() or "0").split()[0] or 0)
        return got

    def status(self, duthost):
        """``leaked`` is the whole point: a permanent delta after release is the bug.

        It is None until release() has run -- "not measured yet" is not the same as "no leak",
        and reporting 0 before the round trip closed would be a false all-clear.
        """
        baseline, after = getattr(self, "_baseline", None), getattr(self, "_after", None)
        peak = getattr(self, "_peak", None)
        used, available = self.crm_counts(duthost)
        return {
            "active": getattr(self, "_pushed", 0) > 0 and after is None,
            "resource": self.crm_resource,
            "baseline": baseline,
            "pushed": getattr(self, "_pushed", 0),
            "peak": getattr(self, "_peak", None),
            "after_release": after,
            "used_now": used,
            "available_now": available,
            "leaked": None if (baseline is None or after is None) else after - baseline,
            # `pushed` is what we asked for; `peak - baseline` is what the ASIC accepted. A gap
            # means entries were refused, and `sai_errors` says whether anything admitted it.
            "accepted": None if (peak is None or baseline is None) else peak - baseline,
            "refused": None if (peak is None or baseline is None)
            else max(0, getattr(self, "_pushed", 0) - (peak - baseline)),
        }
