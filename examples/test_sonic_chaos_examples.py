"""Worked examples: how an existing sonic-mgmt test runs under an injected fault.

Each test wraps a normal workload in a fault and ends in one oracle assert. Run them like any
sonic-mgmt test; the ``chaos`` fixture is autouse, so nothing here imports the plugin directly.

    pytest test_sonic_chaos_examples.py --testbed <tb> --testbed_file <file>

These are the three verdict states, all reproduced on real hardware (202511.3):
BROKE (the hijack), HELD (recovery), and the guard that refuses to arm a box already
at its swss restart limit. A fault that never engages is INCONCLUSIVE, never a green pass.
"""
import pytest


def test_vlan_survives_table_full(duthosts, rand_one_dut_hostname, chaos):
    """A VLAN create the ASIC rejected must not be reported as programmed.

    We tell orchagent the ASIC returned TABLE_FULL on a switch that is not full. The control
    plane accepts Vlan4001 into APPL_DB; the ASIC never gets it. The `vlan` invariant catches the
    APPL/ASIC disagreement -- the swallowed-TABLE_FULL shape, with no crash to point at.
    """
    dut = duthosts[rand_one_dut_hostname]
    with chaos.sai("vlan:create:status=SAI_STATUS_TABLE_FULL"):
        dut.shell("config vlan add 4001")
        with pytest.raises(AssertionError):
            chaos.assert_consistent()          # APPL has Vlan4001; ASIC does not -> divergence
    dut.shell("config vlan del 4001", module_ignore_errors=True)


def test_appl_asic_agree_after_orchagent_restart(duthosts, rand_one_dut_hostname, chaos):
    """A cold orchagent restart must not leave APPL_DB and ASIC_DB disagreeing (DNX cold-restart shape).

    The fault fires on apply; recovery is the system's job and is the thing under test.
    """
    with chaos.kill("orchagent:how=restart"):
        pass
    chaos.assert_recovers(within=180)


def test_routes_program_under_orchagent_pressure(duthosts, rand_one_dut_hostname, chaos):
    """Pin orchagent's dispatch thread, then confirm the box reconciles once it is freed.

    While pinned, nothing is serviced (the RouteOrch-livelock livelock shape). The assertion is that the
    databases agree again after release, within the recovery budget.
    """
    with chaos.spin("orchagent:100", ttl=120):
        pass
    chaos.assert_recovers(within=90)
