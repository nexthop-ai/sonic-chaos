"""Squeeze self-calibration: prove the achieved-share numbers mean something.

    sonic-chaos tool calibrate --dut ssh://admin@<switch>
    sonic-chaos tool calibrate --dut ssh://admin@<switch> --shares 10,30,50,80 --seconds 8 --workers 3

Caps a synthetic spinner at a known share and checks the measured value lands in tolerance.
Run it once per platform before trusting any number this lane reports.

Why it is not optional
----------------------
Every ``achieved`` figure the cpu injector reports comes from the cgroup's own ``cpu.stat``. If
enforcement and accounting ever disagree -- a different kernel, a different cgroup driver, a
platform where the sibling cgroup is not actually where the daemon ends up -- then the lane is
reporting its own arithmetic back to itself, and *every* finding written against a CPU-starved
daemon is unfalsifiable. A spinner is the one workload whose true demand is known: a shell busy
loop wants exactly one core, so if the cap is 30 and the measurement says 30, both halves work.

Exit status is 0 only when every requested share passes, so this belongs in a pre-run check and
not just in someone's terminal history.
"""
import argparse
import sys


from .. import squeeze              # noqa: E402
from . import target_dut            # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shares", default="10,30,50,80", help="comma-separated percentages")
    parser.add_argument("--seconds", type=int, default=6, help="measurement window per share")
    parser.add_argument("--workers", type=int, default=2,
                        help="spinners; must exceed the cap or nothing is throttled")
    args = parser.parse_args(argv)

    dut = target_dut()
    shares = [int(s) for s in args.shares.split(",") if s.strip()]

    print("calibrating cpu budget enforcement on {} ({} spinners, {}s per point)\n".format(
        args.tb, args.workers, args.seconds))
    squeeze.push_agent(dut)

    print("{:>9} {:>10} {:>9} {:>11} {:>11}  {}".format(
        "REQUESTED", "ACHIEVED", "ERROR", "TOLERANCE", "THROTTLED", "VERDICT"))
    failures = []
    for share in shares:
        result = squeeze.agent(dut, "calibrate", *squeeze.flags(
            share=share, seconds=args.seconds, workers=args.workers), ignore_errors=True)
        if result.get("error"):
            print("{:>8}% {:>10} {:>9} {:>11} {:>11}  ERROR {}".format(
                share, "-", "-", "-", "-", result["error"]))
            failures.append(share)
            continue
        ok = result.get("ok")
        print("{:>8}% {:>9}% {:>+9.2f} {:>10.2f}% {:>11}  {}".format(
            share, result["achieved"], result["error_points"], result["tolerance"],
            result.get("nr_throttled"), "pass" if ok else "FAIL"))
        if not ok:
            failures.append(share)

    if failures:
        print("\nFAILED at {}. The cap and the measurement disagree on this platform -- do not\n"
              "trust an achieved-share number here until this passes. Check that\n"
              "/sys/fs/cgroup is cgroup v2 unified and that the root cgroup.subtree_control\n"
              "lists 'cpu'.".format(", ".join("{}%".format(s) for s in failures)))
        return 1
    print("\nall points within tolerance -- achieved-share numbers on {} are trustworthy".format(
        args.tb))
    return 0


if __name__ == "__main__":
    sys.exit(main())
