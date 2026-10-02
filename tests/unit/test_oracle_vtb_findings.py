"""Two oracle false positives found on dut120 (t0-small, main.214697), 2026-09-28.

The port-toggle test passed under spin=orchagent:70, yet was graded BROKE on a divergence that was
there before the fault: ASIC_DB NEIGHBOR_ENTRY Vlan1000 192.168.7.255, MAC FF:FF:FF:FF:FF:FF, not in
APPL_DB. That is orchagent's directed-broadcast neighbour for 192.168.0.1/21. The baseline did not
cover it because loading the shim restarted swss and its RIF OID changed (...6a2 -> ...6a7).
"""
from sonic_chaos import oracle
from sonic_chaos.selftest import RIF132_OID, _lab_snapshot, _neigh_key


def neighbour_findings(snap):
    real, _notices = oracle.split_unchecked(oracle.check(snap, only=["neighbor"]))
    return real


def test_a_directed_broadcast_neighbour_is_not_a_finding():
    snap = _lab_snapshot(ASIC_DB={
        _neigh_key("10.0.0.255", RIF132_OID): {"SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "FF:FF:FF:FF:FF:FF"}})
    assert neighbour_findings(snap) == []


def test_a_real_asic_only_neighbour_still_is():
    snap = _lab_snapshot(ASIC_DB={
        _neigh_key("10.0.0.77", RIF132_OID): {"SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS": "22:E7:E9:CC:22:99"}})
    found = neighbour_findings(snap)
    assert len(found) == 1 and "absent from APPL_DB" in found[0].detail


def test_a_baseline_divergence_survives_an_oid_renumbering():
    before = oracle.Divergence("neighbor", "ASIC_DB",
                               'ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{"ip":"192.168.7.255",'
                               '"rif":"oid:0x60000000006a2","switch_id":"oid:0x21000000000000"}', "stale")
    after = oracle.Divergence("neighbor", "ASIC_DB",
                              'ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{"ip":"192.168.7.255",'
                              '"rif":"oid:0x60000000006a7","switch_id":"oid:0x21000000000000"}', "stale")
    other = oracle.Divergence("neighbor", "ASIC_DB",
                              'ASIC_STATE:SAI_OBJECT_TYPE_NEIGHBOR_ENTRY:{"ip":"192.168.7.254",'
                              '"rif":"oid:0x60000000006a7","switch_id":"oid:0x21000000000000"}', "new")
    assert oracle.subtract([after, other], oracle.finding_keys([before])) == [other]
