"""Standalone tools that check the harness itself against a real switch.

Each is a module with a ``main()`` and runs as ``sonic-chaos tool <name> --dut <url>``:

    calibrate            prove the squeeze lane's achieved-share numbers mean something
    live-check           every injector applies, takes effect, and is undone, on a real box
    check-invariants     snapshot the box once and run every invariant
    invariant-matrix     which invariants can run on this box, and which say "cannot check"
    noise                two idle snapshots: what churns on its own, so it is not a finding
    perturbation-check   make one known divergence and prove the oracle sees it
    restart-recovery     a timed restart-and-recover run, written as a repro bundle

The switch comes from ``--dut`` (``SONIC_CHAOS_DUT``); see ``sonic_chaos.transport``.
"""
import os
import sys

from ..transport import open_dut

TOOLS = {
    "calibrate": "calibrate",
    "live-check": "live_check",
    "check-invariants": "check_invariants",
    "invariant-matrix": "invariant_matrix",
    "noise": "noise",
    "perturbation-check": "perturbation_check",
    "restart-recovery": "restart_recovery",
}


def target_dut():
    """The switch a tool runs against, from ``SONIC_CHAOS_DUT``."""
    url = os.environ.get("SONIC_CHAOS_DUT")
    if not url:
        sys.exit("no switch given: pass --dut (or set SONIC_CHAOS_DUT), e.g. --dut ssh://admin@10.0.0.5")
    return open_dut(url)
