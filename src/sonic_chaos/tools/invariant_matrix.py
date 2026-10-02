"""Prove each cross-DB invariant actually FIRES on hardware, not just that it stays quiet.

    sonic-chaos tool invariant-matrix --dut ssh://admin@<switch>

Verified on a lab switch (202511.2, t2-single-node-min) -- 4/4 fired, box clean after::

    FIRED  lag_member  programmed in ASIC_DB as PortChannel101:Ethernet48, absent from
                       APPL_DB (stale entry -- stale-member shape)
    FIRED  lag         ASIC_DB LAG PortChannel105 absent from APPL_DB LAG_TABLE
    FIRED  neighbor    MAC disagrees: APPL_DB de:ad:be:ef:00:01 vs ASIC_DB 1e:7b:63:a1:2c:47
    FIRED  neighbor    programmed in ASIC_DB as Ethernet52 10.0.0.103, absent from APPL_DB


Passing on a healthy box shows no false positives. This shows detection: for each invariant,
inject a one-sided change, assert the right invariant reports it with the right message, then
restore and assert the box is clean again.

Every case restores in a finally. The run aborts before touching anything if the baseline is
already dirty, since a fault injected into an unknown state proves nothing either way.
"""
import sys
import traceback

from .. import oracle                      # noqa: E402
from ..injector import get                # noqa: E402
from . import target_dut         # noqa: E402


NARROW = dict(
    dbs=("APPL_DB", "ASIC_DB"),
    prefixes={
        "APPL_DB": ["LAG_MEMBER_TABLE:", "LAG_TABLE:", "NEIGH_TABLE:"],
        "ASIC_DB": ["ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:", "ASIC_STATE:SAI_OBJECT_TYPE_LAG:",
                    "ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:"],
    },
)
CHECKS = ["lag_member", "lag", "neighbor"]

# (label, injector spec, invariant expected to fire, substring expected in its detail)
CASES = [
    ("lag_member: APPL entry deleted -> stale ASIC member",
     "APPL_DB:[LAG_MEMBER_TABLE:PortChannel101:Ethernet48]:delete=true",
     "lag_member", "stale-member"),

    ("lag: APPL LAG_TABLE deleted -> orphan ASIC LAG object",
     "APPL_DB:[LAG_TABLE:PortChannel105]:delete=true",
     "lag", "absent from APPL_DB LAG_TABLE"),

    ("neighbor: APPL MAC rewritten -> disagreement with ASIC",
     "APPL_DB:[NEIGH_TABLE:PortChannel101:10.0.0.101]:neigh=[de:ad:be:ef:00:01]",   # [...] so the MAC's colons survive
     "neighbor", "MAC disagrees"),

    ("neighbor: APPL entry deleted -> ASIC neighbour stranded",
     "APPL_DB:[NEIGH_TABLE:Ethernet52:10.0.0.103]:delete=true",
     "neighbor", "absent from APPL_DB"),
]


def findings(dut):
    snap = oracle.snapshot(dut, **NARROW)
    real, _ = oracle.split_unchecked(oracle.check(snap, only=CHECKS))
    return real


def main():
    dut = target_dut()
    print("box: {}\n".format(dut.hostname))

    base = findings(dut)
    if base:
        print("ABORT: baseline is already divergent:")
        for d in base:
            print("   [{}] {} {}".format(d.kind, d.db, d.key[:60]))
        return 2
    print("baseline CLEAN across {}\n".format(", ".join(CHECKS)))

    results = []
    for label, spec, want_kind, want_text in CASES:
        print("=" * 78)
        print(label)
        verdict, note = "FAIL", ""
        injector = None
        try:
            injector = get("corrupt").from_spec(spec)
            injector.apply(dut)
            found = findings(dut)
            hit = [d for d in found if d.kind == want_kind and want_text in str(d.detail)]
            other = [d for d in found if d.kind != want_kind]
            if hit:
                verdict = "FIRED"
                print("  {} fired: {}".format(want_kind, str(hit[0].detail)[:110]))
                print("    on {} {}".format(hit[0].db, hit[0].key[:62]))
                if other:
                    note = "also fired: {}".format(sorted({d.kind for d in other}))
                    print("  note: {}".format(note))
            else:
                note = "expected {!r} containing {!r}; got {}".format(
                    want_kind, want_text, [(d.kind, str(d.detail)[:50]) for d in found] or "nothing")
                print("  MISS: {}".format(note))
        except Exception:                                            # noqa: BLE001
            note = traceback.format_exc().strip().splitlines()[-1]
            print("  ERROR: {}".format(note))
        finally:
            if injector is not None:
                try:
                    injector.release(dut)
                except Exception as err:                             # noqa: BLE001
                    note += " | RELEASE FAILED: {!r}".format(err)
                    print("  !! release raised: {!r}".format(err))
        after = findings(dut)
        if after:
            verdict = "DIRTY"
            note += " | box still divergent after release"
            print("  !! not clean after release: {}".format([d.kind for d in after]))
        else:
            print("  restored, clean")
        results.append((verdict, label, note))

    print("\n" + "=" * 78)
    print("{:<7} {}".format("RESULT", "CASE"))
    for verdict, label, note in results:
        print("{:<7} {}".format(verdict, label))
        if note:
            print("        {}".format(note[:140]))
    bad = [r for r in results if r[0] != "FIRED"]
    print("\n{} / {} invariants proven to fire on hardware".format(
        len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
