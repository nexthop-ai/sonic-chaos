"""End-to-end proof that an Oracle invariant fires on a real box.

Spine's `corrupt` injector deletes ONE APPL_DB LAG member key; Oracle's `lag_member` invariant
must then report the ASIC-side entry as stale -- the stale-member shape. Then release restores the
key exactly and the invariant must go clean again.

Why delete from APPL_DB rather than `config portchannel member del`: the CLI removes the member
from both databases, which is a correct operation and produces no divergence at all. Only a
one-sided change is a divergence, and that is the thing worth proving we can see.

Dataplane impact: none. orchagent consumes LAG_MEMBER_TABLE through a ConsumerStateTable fed by
the _KEY_SET, so a raw DEL on the hash is invisible to it and the ASIC keeps forwarding. That is
exactly why the divergence persists, and exactly why `corrupt` is gated behind an explicit spec.

    PC=PortChannel101 PORT=Ethernet48 sonic-chaos tool perturbation-check --dut ssh://admin@<switch>

Verified on a lab switch (202511.2, t2-single-node-min)::

    step 1  baseline        APPL_DB members 4   ASIC_DB members 4   CLEAN
    step 2  inject          APPL_DB key now: (gone)
    step 3  under fault     APPL_DB members 3   ASIC_DB members 4   1 violation
        [lag_member] ASIC_DB  ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:oid:0x1b000000000a0e
            programmed in ASIC_DB as PortChannel101:Ethernet48, absent from APPL_DB
            (stale entry -- stale-member shape)
    step 4  release         restored to {'status': 'enabled'}
    step 5  after release   CLEAN

Note what step 3 proves beyond a set comparison: the invariant turned a raw ASIC OID back into
``PortChannel101:Ethernet48``, so the COUNTERS_DB name-map resolution is exercised end to end.
An invariant that silently resolved nothing would compare two empty sets and call the box clean.
"""
import os
import sys

from .. import oracle  # noqa: E402
from ..injector import get, hgetall  # noqa: E402
from . import target_dut  # noqa: E402

PC = os.environ.get("PC", "PortChannel101")
PORT = os.environ.get("PORT", "Ethernet48")
APPL_KEY = "LAG_MEMBER_TABLE:{}:{}".format(PC, PORT)

NARROW = {
    "dbs": ("APPL_DB", "ASIC_DB"),
    "prefixes": {
        "APPL_DB": ["LAG_MEMBER_TABLE:", "LAG_TABLE:"],
        "ASIC_DB": ["ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:", "ASIC_STATE:SAI_OBJECT_TYPE_LAG:"],
    },
}


def lag_findings(dut):
    """Narrow snapshot + just the LAG invariants, so each probe is seconds not minutes."""
    snap = oracle.snapshot(dut, **NARROW)
    real, _ = oracle.split_unchecked(oracle.check(snap, only=["lag_member", "lag"]))
    return snap, real


def show(label, real):
    print("  {:<28} {}".format(label, "CLEAN" if not real else "{} violation(s)".format(len(real))))
    for d in real:
        print("      [{}] {:<9} {}".format(d.kind, d.db, d.key[:64]))
        print("          {}".format(str(d.detail)[:120]))


def main():
    dut = target_dut()
    failures = []

    print("target: {} {}\n".format(dut.hostname, APPL_KEY))

    # -- step 0: prove the plumbing reads correctly BEFORE changing anything ------------------
    print("step 0  plumbing check")
    original = hgetall(dut, "APPL_DB", APPL_KEY)
    if not original:
        print("  ABORT: {} is empty or unreadable -- refusing to perturb a box we cannot read"
              .format(APPL_KEY))
        return 2
    print("  read back {} = {}".format(APPL_KEY, original))

    # -- step 1: baseline must be clean, or the test proves nothing ---------------------------
    print("\nstep 1  baseline")
    snap, real = lag_findings(dut)
    print("  APPL_DB members {}   ASIC_DB members {}".format(
        len(snap.keys("APPL_DB", "LAG_MEMBER_TABLE:")),
        len(snap.keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:"))))
    show("baseline", real)
    if real:
        print("  ABORT: box is already divergent; a fault injected now would prove nothing")
        return 2

    injector = get("corrupt").from_spec("APPL_DB:[{}]:delete=true".format(APPL_KEY))
    print("\n  injector: {}".format(injector.describe()))

    try:
        # -- step 2: inject -------------------------------------------------------------------
        print("\nstep 2  inject (delete the APPL_DB key only)")
        injector.apply(dut)
        after = hgetall(dut, "APPL_DB", APPL_KEY)
        print("  APPL_DB key now: {}".format(after or "(gone)"))
        if after:
            failures.append("the delete did not take effect")

        # -- step 3: the invariant must fire --------------------------------------------------
        print("\nstep 3  oracle under fault")
        snap, real = lag_findings(dut)
        print("  APPL_DB members {}   ASIC_DB members {}".format(
            len(snap.keys("APPL_DB", "LAG_MEMBER_TABLE:")),
            len(snap.keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:"))))
        show("under fault", real)

        stale = [d for d in real if d.kind == "lag_member" and d.db == "ASIC_DB"
                 and PORT in str(d.detail)]
        if not stale:
            failures.append("lag_member did NOT report the stale ASIC entry for {}".format(PORT))
        elif "stale-member" not in stale[0].detail:
            failures.append("fired, but without the stale-member attribution")
        else:
            print("\n  >>> lag_member correctly identified the stale ASIC entry")

    finally:
        # -- step 4: restore, always ----------------------------------------------------------
        print("\nstep 4  release (runs even if the checks above failed)")
        try:
            injector.release(dut)
        except Exception as err:                                    # noqa: BLE001
            failures.append("RELEASE FAILED: {!r} -- box may be left corrupt".format(err))
            print("  !! release raised: {!r}".format(err))
        restored = hgetall(dut, "APPL_DB", APPL_KEY)
        print("  APPL_DB key restored to: {}".format(restored or "(still gone!)"))
        if restored != original:
            failures.append("restore is not exact: {!r} != {!r}".format(restored, original))

    # -- step 5: clean again ------------------------------------------------------------------
    print("\nstep 5  oracle after release")
    _, real = lag_findings(dut)
    show("after release", real)
    if real:
        failures.append("still divergent after release")

    print("\n" + "=" * 74)
    if failures:
        print("PERTURBATION TEST FAILED")
        for f in failures:
            print("  - {}".format(f))
        return 1
    print("PERTURBATION TEST PASSED")
    print("  clean -> inject -> lag_member fires (stale-member shape) -> release -> clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
