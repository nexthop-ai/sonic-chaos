"""Measure a testbed's idle diff noise floor, so oracle's denoise list stays evidence-based.

    sonic-chaos tool noise --dut ssh://admin@<switch>

Takes two back-to-back snapshots of an idle DUT and reports the RAW difference grouped by
table and field. Everything it prints is churn that has nothing to do with a fault: platform
telemetry, timestamps, transient work queues. Anything that survives `denoise=True` at the
bottom is either a real background change or a gap in VOLATILE_TABLES / VOLATILE_FIELDS.

Re-run this when the platform or the branch changes. A wrong entry in the denoise list hides
real bugs, so the list should always be something somebody measured, not something we assumed.

Reference numbers, a lab switch (202511.2, t2-single-node-min, idle):
    5314 keys, 270 raw divergences, all kind="changed", 0 after denoise.
"""
import collections
import sys


from .. import oracle               # noqa: E402
from . import target_dut            # noqa: E402


def main():
    dut = target_dut()
    print("snapshotting {} twice (idle) ...".format(dut.hostname))
    first = oracle.snapshot(dut)
    second = oracle.snapshot(dut)
    print("  {} keys per snapshot\n".format(len(first)))

    raw = oracle.diff(first, second, denoise=False)
    print("RAW divergences: {}".format(len(raw)))

    by_table = collections.Counter()
    by_field = collections.Counter()
    for d in raw:
        by_table[(d.db, oracle.table_of(d.key))] += 1
        if d.kind == "changed" and isinstance(d.detail, dict):
            for field in d.detail:
                by_field[(d.db, oracle.table_of(d.key), field)] += 1

    print("\n{:<9} {:<38} {:>5}".format("DB", "TABLE", "N"))
    for (db, table), count in by_table.most_common(25):
        known = "" if table not in oracle.VOLATILE_TABLES else "  (in VOLATILE_TABLES)"
        print("{:<9} {:<38} {:>5}{}".format(db, table[:38], count, known))

    print("\nvolatile fields (changed in place):")
    for (db, table, field), count in by_field.most_common(15):
        known = "" if field not in oracle.VOLATILE_FIELDS else "  (in VOLATILE_FIELDS)"
        print("  {:<9} {:<32} {:<28} {:>4}{}".format(db, table[:32], field[:28], count, known))

    print("\nby kind: {}".format(dict(collections.Counter(d.kind for d in raw))))

    quiet = oracle.diff(first, second)
    print("\nAFTER denoise: {} divergence(s)".format(len(quiet)))
    for d in quiet[:15]:
        print("  {:<10} {:<9} {}  {}".format(d.kind, d.db, d.key[:60], str(d.detail)[:80]))
    if not quiet:
        print("  clean -- the denoise list covers this platform")
    else:
        print("\n  ^ each of these is either a real background change or a gap in the denoise list.")
    return 0 if not quiet else 1


if __name__ == "__main__":
    sys.exit(main())
