"""Run every Oracle invariant against a live DUT. No pytest, no inventory, no container.

    sonic-chaos tool check-invariants --dut ssh://admin@<switch>

Read-only. This is the Oracle lane's acceptance test on hardware: it proves the OID resolution,
the cross-database comparisons and the health checks all work against a real box, and it prints
what each invariant actually examined so a clean result can be trusted rather than assumed.

Exit code is 0 when no invariant is violated. Invariants that could not run are reported
separately and never fail the script -- see oracle.UNCHECKED.
"""
import sys

from .. import invariants, oracle  # noqa: E402
from . import target_dut  # noqa: E402


def main():
    dut = target_dut()
    print("snapshotting {} ...".format(dut.hostname))
    snap = oracle.snapshot(dut)
    print("  {} keys across {}".format(len(snap), ", ".join(sorted(snap.tables))))

    # Prove OID resolution works before trusting any cross-DB result: an invariant that silently
    # resolved nothing would compare two empty sets and report a clean box.
    print("\nOID name maps:")
    for label, name in (("port", invariants.PORT_MAP), ("lag", invariants.LAG_MAP),
                        ("rif", invariants.RIF_MAP), ("vlan", invariants.VLAN_MAP)):
        resolved = invariants.oid_to_name(snap, name)
        print("  {:<5} {:<32} {}".format(
            label, name, "absent" if resolved is None else "{} entries".format(len(resolved))))

    print("\nobject counts:")
    for label, appl, asic_type in (
            ("lag members", "LAG_MEMBER_TABLE:", "LAG_MEMBER"),
            ("lags", "LAG_TABLE:", "LAG"),
            ("neighbors", "NEIGH_TABLE:", "NEIGHBOR_ENTRY"),
            ("vlan members", "VLAN_MEMBER_TABLE:", "VLAN_MEMBER"),
            ("routes", "ROUTE_TABLE:", "ROUTE_ENTRY")):
        print("  {:<13} APPL_DB {:>5}   ASIC_DB {:>5}".format(
            label, len(snap.keys("APPL_DB", appl)), len(invariants.asic_keys(snap, asic_type))))

    violations, notices = [], []
    for group in oracle.GROUPS:
        print("\n{} -- {}".format(group, {
            "parity": "do APPL_DB, ASIC_DB and STATE_DB agree (this is Oracle's job)",
            "health": "is the box up at all",
            "signal": "is something falling behind, before anything has diverged",
        }[group]))
        for name in oracle.group_members(group):
            found = oracle.check(snap, only=[name])
            real, unchecked = oracle.split_unchecked(found)
            violations.extend(real)
            notices.extend(unchecked)
            if real:
                verdict = "\033[31mFAIL ({})\033[0m".format(len(real))
            elif unchecked:
                verdict = "\033[33mnot checked\033[0m"
            else:
                verdict = "\033[32mok\033[0m"
            print("  {:<20} {}".format(name, verdict))
            for d in real[:6]:
                print("      {:<14} {}  {}".format(d.db, d.key[:70], str(d.detail)[:100]))
            if len(real) > 6:
                print("      ... and {} more".format(len(real) - 6))
            for d in unchecked:
                print("      reason: {}".format(d.detail))

    print("\n" + "=" * 78)
    if violations:
        print("{} invariant violation(s) on {}".format(len(violations), dut.hostname))
    else:
        print("no invariant violations on {}".format(dut.hostname))
    if notices:
        print("{} invariant(s) could not run (reported, not fatal)".format(len(notices)))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
