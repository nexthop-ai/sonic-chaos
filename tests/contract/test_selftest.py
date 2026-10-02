"""The contract self-check, as a pytest suite.

Every test below is one section of ``sonic_chaos/selftest.py``'s ``main()``, moved across verbatim:
same assertions, same order, same comments. The fakes and the larger checks (``_FakeDut``,
``_FakeBox``, ``squeeze_checks`` ...) are imported from ``selftest.py`` rather than copied, so
the script and this suite cannot drift. The script still runs on its own, and
``test_selftest_script_still_passes`` holds it to that.

The only edits: ``plan``, ``duts`` and ``before`` were locals shared across sections and are
rebuilt per test, and the shipped experiment is found through ``_under_test.PKG_DIR``
instead of ``__file__``.
"""
import os  # noqa: F401  used by the shipped-experiment section

import _under_test

from sonic_chaos.selftest import (  # noqa: E402
    Experiment,
    ChaosPlan,
    ChaosSession,
    REGISTRY,
    _FakeDut,
    _check_shim_lane,
    _expect_error,
    _lab_snapshot,
    bundle,
    check_fault_verdict,
    check_oracle_invariants,
    check_vlan_invariant,
    check_vlan_member_invariant,
    deadman_tag,
    get,
    main,
    oracle,
    parse_hgetall,
    parse_supervisor_status,
    poll,
    quote,
    split_spec,
    squeeze_checks,
)


def test_spec_grammar():
    # grammar
    assert split_spec("orchagent:30") == (["orchagent", "30"], {})
    assert split_spec("route_entry:create:delay=2000") == (["route_entry", "create"], {"delay": "2000"})
    assert split_spec("APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=x") == (
        ["APPL_DB", "LAG_MEMBER_TABLE:PortChannel12:Ethernet48"], {"status": "x"})
    _expect_error(split_spec, "a:k=v:b")     # positional after keyword
    _expect_error(split_spec, "a:[b")        # unbalanced bracket


def test_registry_has_every_lane():
    # registry: the lanes' injectors exist and unknown names fail loudly
    assert set(REGISTRY) >= {"cpu", "sai", "kill", "corrupt", "pause", "redis",
                             "mem", "syslog", "exhaust", "storm", "hog"}, sorted(REGISTRY)
    _expect_error(get, "nope")


def test_plan_from_cli_args_and_validators():
    # a full plan from CLI args, and the validators that stop bad specs before a DUT is touched
    plan = ChaosPlan.from_args([
        "cpu=orchagent:30",
        "sai=route_entry:create:delay=2000",
        "kill=orchagent:how=restart",
        "corrupt=APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=garbage",
    ])
    assert [i.name for i in plan.injectors] == ["cpu", "sai", "kill", "corrupt"]
    assert plan.injectors[0].params["container"] == "swss"
    assert plan.injectors[2].command() == "docker exec swss supervisorctl restart orchagent"
    assert plan.injectors[3].fields == {"status": "garbage"}
    _expect_error(ChaosPlan.from_args, ["cpu=redis-server:10"])            # protected target
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:300"])              # share out of range
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:mode=contend"])  # cut from scope
    _expect_error(ChaosPlan.from_args, ["sai=route_entry:create"])         # no effect requested
    _expect_error(ChaosPlan.from_args, ["corrupt=ASIC_DB:[x]:a=b"])        # ASIC_DB refused
    _expect_error(ChaosPlan.from_args, ["kill=nosuchdaemon"])              # not in targets.yml
    _expect_error(ChaosPlan.from_args, ["bogus"])                          # not INJECTOR=SPEC


def test_pause_and_redis_specs():
    # the two injectors lifted from the chaos-monkey fault catalogue
    freeze = ChaosPlan.from_args(["pause=orchagent:10"]).injectors[0]
    assert freeze.freeze_cmd() == "docker exec swss pkill -STOP -x orchagent"
    assert freeze.thaw_cmd() == "docker exec swss pkill -CONT -x orchagent"
    assert ChaosPlan.from_args(["pause=swss:5:how=docker"]).injectors[0].freeze_cmd() == "docker pause swss"
    _expect_error(ChaosPlan.from_args, ["pause=orchagent:9999"])           # freeze is bounded
    assert "DEBUG SLEEP 2.0" in ChaosPlan.from_args(["redis=sleep:2000"]).injectors[0].command()
    _expect_error(ChaosPlan.from_args, ["redis=sleep:60000"])              # supervisor would restart
    _expect_error(ChaosPlan.from_args, ["redis=bogus_action:x"])
    assert ChaosPlan.from_args(["cpu=orchagent:30"]).injectors[0].quota_us() == 30000


def test_hog_bounds_and_spends():
    # hog is not a cap: it bounds the budget AND spends it, so the container really reads X%.
    # cpu.max is cpu% of `cores` cores, and the load is sized to keep that budget saturated --
    # 40% of one core needs two spinners, verified at 39.93% on a lab switch's swss.
    hog = ChaosPlan.from_args(["hog=swss:cpu=40"]).injectors[0]
    assert hog.quota() == "40000 100000" and hog.spinners() == 2
    assert ChaosPlan.from_args(["hog=swss:cpu=40:cores=2"]).injectors[0].quota() == "80000 100000"
    assert ChaosPlan.from_args(["hog=orchagent:cpu=50"]).injectors[0].params["container"] == "swss"
    assert ChaosPlan.from_args(["hog=swss:mem=30"]).injectors[0].spinners() == 0
    _expect_error(ChaosPlan.from_args, ["hog=swss"])            # neither cpu nor mem: no load
    _expect_error(ChaosPlan.from_args, ["hog=swss:cpu=0:mem=0"])  # same, said explicitly
    _expect_error(ChaosPlan.from_args, ["hog=swss:cpu=140"])     # out of range
    _expect_error(ChaosPlan.from_args, ["hog=swss:mem=90"])      # reads as a crash, not pressure
    _expect_error(ChaosPlan.from_args, ["hog=swss:cpu=40:cores=99"])
    _expect_error(ChaosPlan.from_args, ["hog=redis-server:cpu=40"])  # protected target


def test_exhaust_and_storm_refuse_rather_than_fake():
    # exhaust and storm used to apply() silently and inject nothing, so a run using them reported
    # a pass for a fault that never happened. exhaust now fills route/route6 for real and refuses
    # every other table loudly; storm refuses outright until a ptfhost exists.
    ex = ChaosPlan.from_args(["exhaust=route:0:over_pct=110"]).injectors[0]
    assert ex.crm_resource == "ipv4_route"
    assert ex.target_count(100, 900) == 1000            # 110% of the 1000 limit, less 100 used
    assert ex.target_count(0, 10 ** 9) == 200000        # MAX_PUSH cap
    assert list(ex.prefixes(2)) == ["100.64.0.0/32", "100.64.0.1/32"]
    assert list(ChaosPlan.from_args(["exhaust=route6:5"]).injectors[0].prefixes(1)) == \
        ["2001:db8:0:0::1/128"]
    nb = ChaosPlan.from_args(["exhaust=neighbor:500"]).injectors[0]
    assert nb.crm_resource == "ipv4_neighbor"
    assert ChaosPlan.from_args(["exhaust=nexthop:5"]).injectors[0].crm_resource == "ipv4_nexthop"
    # addresses start at .2: .0 is the subnet's network address and .1 the interface's own IP
    assert "10.200.0.%d" in nb.neigh_awk("PortChannel1", 0, 2) or "(i+2)" in nb.neigh_awk("PortChannel1", 0, 2)
    # storm: netlink runs on the DUT (LAG member flap); the packet kinds still need a PTF peer.
    sn = ChaosPlan.from_args(["storm=netlink:rate=1000:seconds=20"]).injectors[0]
    assert "ip link set dev Ethernet9 down" in sn.flap_script("Ethernet9")
    assert "sleep" not in sn.flap_script("Ethernet9")          # rate >= 200 -> tight loop
    assert "sleep 0.1000" in ChaosPlan.from_args(
        ["storm=netlink:rate=10:seconds=5"]).injectors[0].flap_script("Ethernet9")
    # acl is implemented now; fdb and mirror refuse for reasons specific to each, not a generic
    # "needs a PTF peer" -- fdb has no VLAN to learn into, mirror is not in this platform's CRM.
    ac = ChaosPlan.from_args(["exhaust=acl:500"]).injectors[0]
    assert ac.crm_resource == "acl_entry"
    assert "ACL_RULE|DATAACL|CHAOS_%d" in ac.acl_awk("DATAACL", 0, 2)
    for spec in ("exhaust=fdb:1000", "exhaust=mirror"):
        _expect_error(ChaosPlan.from_args([spec]).injectors[0].apply, None)
    # arp/nd/mac have no sender yet: refused at validate, never accepted and then failed at apply
    for spec in ("storm=arp:rate=5000", "storm=nd:rate=5000", "storm=mac:rate=20000"):
        _expect_error(ChaosPlan.from_args, [spec])
    _expect_error(ChaosPlan.from_args, ["exhaust=bogus_table"])
    _expect_error(ChaosPlan.from_args, ["exhaust=route:0:over_pct=50"])   # over_pct < 100


def test_protected_targets_and_settle_below_ttl():
    # protected targets and owner-bypassing DB writes need an explicit force=true
    _expect_error(ChaosPlan.from_args, ["kill=redis-server"])
    _expect_error(ChaosPlan.from_args, ["cpu=database:20"])
    _expect_error(ChaosPlan.from_args, ["corrupt=ASIC_DB:[x]:a=b"])
    # settle is the hold, ttl the dead-man: a settle that outlives the ttl lifts the fault before
    # the check reads it, so cpu/hog/spin refuse it the way sai does.
    for spec in ("cpu=orchagent:30:settle=900:ttl=900", "spin=orchagent:100:settle=400:ttl=300",
                 "hog=swss:cpu=40:settle=900:ttl=900"):
        _expect_error(ChaosPlan.from_args, [spec])
    assert ChaosPlan.from_args(["spin=orchagent:100:settle=60"]).injectors[0].params["settle"] == "60"
    assert ChaosPlan.from_args(["kill=redis-server:force=true"]).injectors[0].params["container"] == "database"
    assert ChaosPlan.from_args(["corrupt=ASIC_DB:[x]:force=true:a=b"]).injectors[0].fields == {"a": "b"}
    assert ChaosPlan.from_args(["corrupt=APPL_DB:[x]:delete=true"]).injectors[0].delete is True


def test_squeeze_tier_follows_the_target():
    # Squeeze: the tier is picked from the target -- a container gets Tier 0 (one docker
    # command), a daemon gets Tier 1 (a sibling cgroup), and `how=` overrides either way.
    assert ChaosPlan.from_args(["cpu=orchagent:30"]).injectors[0].how == "cgroup"
    assert ChaosPlan.from_args(["cpu=swss:50"]).injectors[0].how == "docker"
    assert ChaosPlan.from_args(["cpu=orchagent:30:how=docker"]).injectors[0].how == "docker"
    assert ChaosPlan.from_args(["cpu=orchagent:30"]).injectors[0].cgroup() == \
        "/sys/fs/cgroup/sonic-chaos/orchagent"
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:how=nonsense"])
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:ttl=5"])        # too short to be useful
    _expect_error(ChaosPlan.from_args, ["cpu=orchagent:30:ttl=99999"])    # longer than any run


def test_remaining_fault_specs():
    # the rest of the fault list
    assert ChaosPlan.from_args(["mem=swss:40:ramp=20"]).injectors[0].steps() == [80, 60, 40]
    assert ChaosPlan.from_args(["mem=swss:70"]).injectors[0].steps() == [70]
    assert ChaosPlan.from_args(["mem=swss:40:ramp=20:period=45"]).injectors[0].ramp_seconds() == 90
    # a ramp the dead-man would cut short is a configuration error, not a surprise at runtime
    _expect_error(ChaosPlan.from_args, ["mem=swss:40:ramp=20:period=600:ttl=60"])
    assert ChaosPlan.from_args(["exhaust=route:120000"]).injectors[0].crm_resource == "ipv4_route"
    _expect_error(ChaosPlan.from_args, ["exhaust=nosuchtable"])
    _expect_error(ChaosPlan.from_args, ["storm=nosuchkind"])
    _expect_error(ChaosPlan.from_args, ["syslog=0"])
    assert ChaosPlan.from_args(["storm=netlink:5000"]).injectors[0].params["kind"] == "netlink"
    assert ChaosPlan.from_args(["syslog=1000:seconds=10"]).injectors[0].estimated_bytes() == 2000000


def test_session_dry_run_touches_nothing():
    plan = _plan()
    # session: dry-run never touches a DUT; release is LIFO, idempotent, and runs to completion
    duts = [_FakeDut("dut1"), _FakeDut("dut2")]
    sess = ChaosSession(duts, dry_run=True)
    for inj in plan.injectors:
        sess.apply(inj)
    assert len(sess.status()) == 8
    sess.release_all()
    assert sess.status() == []
    sess.release_all()   # second release: no-op, not an error


def test_session_release_is_lifo_and_completes():
    duts = [_FakeDut("dut1"), _FakeDut("dut2")]
    # release runs to completion even when one injector raises, then re-raises the first error.
    # Both injectors here are fakes on purpose: this asserts ChaosSession's release semantics,
    # and a real injector would have to reach a DUT to do anything at all.
    released = []

    class _Recorder(object):
        name, lane, params = "rec", "test", {}

        def describe(self):
            return "rec"

        def apply(self, duthost, **kw):
            pass

        def release(self, duthost):
            released.append(duthost.hostname)
            if duthost.hostname == "dut1":
                raise RuntimeError("release blew up")

        def status(self, duthost):
            return {}

    class _Quiet(_Recorder):
        def release(self, duthost):
            released.append("quiet:" + duthost.hostname)

    live = ChaosSession(duts)
    live.apply(_Recorder())
    live.apply(_Quiet())
    try:
        live.release_all()
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected the release error to surface")
    # LIFO across the whole stack: the second injector releases before the first, and within
    # each, dut2 before dut1. dut1 raised and dut1's own release still ran.
    assert released == ["quiet:dut2", "quiet:dut1", "dut2", "dut1"], released


def test_oracle_diff():
    # oracle.diff on plain snapshots
    key = "LAG_MEMBER_TABLE:PortChannel12:Ethernet48"
    before = oracle.DbSnapshot({"APPL_DB": {key: {"status": "enabled"}}})
    moved = oracle.DbSnapshot({"APPL_DB": {"LAG_MEMBER_TABLE:PortChannel12:Ethernet52": {"status": "enabled"}}})
    assert sorted(d.kind for d in oracle.diff(before, moved)) == ["extra", "missing"]
    changed = oracle.diff(before, oracle.DbSnapshot({"APPL_DB": {key: {"status": "disabled"}}}))
    assert changed[0].kind == "changed" and changed[0].detail == {"status": ("enabled", "disabled")}


def test_oracle_denoise():
    # denoise: the platform-telemetry churn measured on a lab switch must not reach the diff,
    # and a real change in the same snapshot must still come through.
    noisy_a = oracle.DbSnapshot({"STATE_DB": {
        "TEMPERATURE_INFO|ASIC": {"timestamp": "1", "temperature": "40"},
        "PROCESS_STATS|104557": {"cpu": "1"},
        "LAG_MEMBER_TABLE|PortChannel101|Ethernet12": {"status": "enabled"},
    }, "APPL_DB": {"GEARBOX_TABLE_KEY_SET": {"_": ["a"]}}})
    noisy_b = oracle.DbSnapshot({"STATE_DB": {
        "TEMPERATURE_INFO|ASIC": {"timestamp": "2", "temperature": "41"},
        "LAG_MEMBER_TABLE|PortChannel101|Ethernet12": {"status": "disabled"},
    }, "APPL_DB": {"GEARBOX_TABLE_KEY_SET": {"_": ["a", "b"]}}})
    quiet = oracle.diff(noisy_a, noisy_b)
    assert len(quiet) == 1 and quiet[0].key.startswith("LAG_MEMBER_TABLE"), quiet
    assert len(oracle.diff(noisy_a, noisy_b, denoise=False)) == 4   # raw sees all of it
    assert oracle.table_of("PROCESS_STATS|104557") == "PROCESS_STATS"
    assert oracle.table_of("LLDP_ENTRY_TABLE:Ethernet0") == "LLDP_ENTRY_TABLE"
    assert oracle.is_volatile_key("APPL_DB_GEARBOX_TABLE_KEY_SET")


def test_oracle_narrow_prefixes():
    # narrow snapshots: every parity invariant declares what it reads, and the union is small
    pre = oracle.prefixes_for("parity")
    assert set(pre) == {"APPL_DB", "ASIC_DB"}, pre
    assert "LAG_MEMBER_TABLE:" in pre["APPL_DB"] and "NEIGH_TABLE:" in pre["APPL_DB"]
    assert oracle.prefixes_for("health") == {}                       # health asks the DUT, reads no rows
    assert oracle.prefixes_for("signal") == {"APPL_DB": ["*_KEY_SET"], "ASIC_DB": ["*_KEY_SET"]}
    for name in oracle.group_members("parity"):
        if name != "route_check":
            assert oracle.INVARIANT_PREFIXES[name], "{} declares no prefixes".format(name)


def test_oracle_baseline_subtraction():
    # baseline subtraction: what was already wrong is not a finding
    d1 = oracle.Divergence("lag_member", "ASIC_DB", "k1", "stale")
    d2 = oracle.Divergence("lag_member", "ASIC_DB", "k2", "stale")
    assert oracle.subtract([d1, d2], oracle.finding_keys([d1])) == [d2]
    assert oracle.subtract([d1], None) == [d1]


def test_oracle_wait_consistent():
    # wait_consistent polls until clean, and gives up at the budget -- with a fake clock
    class _Clock(object):
        def __init__(self):
            self.t = 0.0

        def now(self):
            return self.t

        def sleep(self, secs):
            self.t += secs

    calls = {"n": 0}
    fake = _FakeDut("fixture")            # wait_consistent logs duthost.hostname while polling
    healthy = _lab_snapshot()
    broken = _lab_snapshot(APPL_DB={"LAG_MEMBER_TABLE:PortChannel101:Ethernet12": None})
    real_snapshot_for = oracle.snapshot_for
    try:
        def flaky(dut, only):                   # divergent twice, then clean
            calls["n"] += 1
            return broken if calls["n"] <= 2 else healthy
        oracle.snapshot_for = flaky
        clk = _Clock()
        found, _, elapsed, _ = oracle.wait_consistent(fake, "parity", timeout=60, interval=5,
                                                      sleep=clk.sleep, clock=clk.now)
        assert found == [] and calls["n"] == 3 and elapsed == 10.0, (found, calls, elapsed)

        calls["n"] = 0
        oracle.snapshot_for = lambda dut, only: broken   # never recovers
        clk = _Clock()
        found, _, elapsed, _ = oracle.wait_consistent(fake, "parity", timeout=12, interval=5,
                                                      sleep=clk.sleep, clock=clk.now)
        assert len(found) == 1 and found[0].kind == "lag_member" and elapsed >= 12, (found, elapsed)
    finally:
        oracle.snapshot_for = real_snapshot_for


def test_invariants_registered_and_unchecked_without_maps():
    key = "LAG_MEMBER_TABLE:PortChannel12:Ethernet48"
    before = oracle.DbSnapshot({"APPL_DB": {key: {"status": "enabled"}}})
    # invariants are registered, and run harmlessly against a disk-loaded snapshot (no duthost)
    assert {"route_check", "key_set_backlog", "lag_member", "lag", "neighbor", "vlan_member",
            "critical_processes", "no_cores", "bgp_established", "no_start_limit"} <= set(oracle.INVARIANTS), \
        sorted(oracle.INVARIANTS)
    # A bare snapshot carries no COUNTERS_DB name maps and no duthost, so every cross-DB invariant
    # must say "cannot check" -- and none may claim a real violation out of thin air.
    real, notices = oracle.split_unchecked(oracle.check(before))
    assert real == [], real
    assert {n.kind for n in notices} == {
        "lag_member:unchecked", "lag:unchecked", "neighbor:unchecked", "vlan_member:unchecked"}, \
        sorted(n.kind for n in notices)


def test_experiment_files():
    # experiment files: schema validation, and a seed that replays identically
    exp = Experiment.from_dict({
        "experiment": "selftest",
        "seed": 42,
        "duration": "10m",
        "min_gap": "60s",
        "count": 10,           # explicit: this block tests seeded REPETITION; the default is one per fault
        "steady_state": ["route_check"],
        "faults": [
            {"kill": {"process": "orchagent", "how": "restart", "weight": 3, "tag": "unsupported-op"}},
            {"pause": {"process": "orchagent", "seconds": 30, "weight": 1}},
        ],
        "contract": {"recover_within": "180s", "invariants": ["route_check"]},
    })
    assert exp.duration == 600 and exp.min_gap == 60 and exp.recover_within == 180
    assert [f.tag for f in exp.faults] == ["unsupported-op", "unsupported-op"]
    first, second = exp.schedule(), exp.schedule()
    assert len(first) == 10, len(first)                       # 600s / 60s gap
    assert [f.injector.describe() for _, f in first] == [f.injector.describe() for _, f in second], \
        "same seed must replay the same fault order"
    assert [o for o, _ in first] == list(range(0, 600, 60))
    assert first != exp.schedule(seed=999) or len({f.injector.name for _, f in first}) == 1
    # Without `count`, a file schedules each fault ONCE. Filling duration with min_gap slots turned
    # one kill into six on a lab switch and locked the switch at the second; nobody writing one fault
    # means "repeat until the clock runs out".
    once = Experiment.from_dict({"experiment": "once", "seed": 42, "duration": "10m", "min_gap": "90s",
                                 "faults": [{"kill": {"process": "orchagent"}},
                                            {"pause": {"process": "orchagent", "seconds": 10}}],
                                 "contract": {"invariants": ["route_check"]}})
    sched = once.schedule()
    assert len(sched) == 2 and {f.injector.name for _, f in sched} == {"kill", "pause"}, sched
    assert [o for o, _ in sched] == [0, 90]
    assert len(Experiment.from_dict({"experiment": "solo", "faults": [{"kill": {"process": "orchagent"}}],
                                     "contract": {"invariants": ["route_check"]}}).schedule()) == 1
    assert "each once" in once.describe()
    _expect_error(Experiment.from_dict, {"experiment": "x"})                      # no faults
    _expect_error(Experiment.from_dict, {"experiment": "x", "faults": [{"nope": {}}]})
    _expect_error(Experiment.from_dict, {"experiment": "x", "faults": [
        {"kill": {"process": "orchagent", "tag": "maybe"}}]})                     # bad tag
    _expect_error(Experiment.from_dict, {"experiment": "x", "duration": "ages",
                                         "faults": [{"kill": {"process": "orchagent"}}]})
    _expect_error(Experiment.from_dict, {"experiment": "x", "faults": [
        {"kill": {"process": "redis-server"}}]})                                  # force still required


def test_spine_primitives():
    # sonic-db-cli prints a Python dict repr, not JSON. Verified against a live 202511.2 box.
    assert parse_hgetall("{'admin_status': 'up', 'lanes': '25,26', 'description': ''}") == {
        "admin_status": "up", "lanes": "25,26", "description": ""}
    assert parse_hgetall("f1\nv1\nf2\nv2") == {"f1": "v1", "f2": "v2"}   # raw redis-cli shape
    assert parse_hgetall("") == {} and parse_hgetall(None) == {}

    # supervisorctl status, in all three shapes it actually emits
    parsed = parse_supervisor_status(
        "orchagent      RUNNING   pid 55, uptime 0:01:37\n"
        "gearsyncd      EXITED    Sep 11 07:57 AM\n"
        "portsyncd      FATAL     Exited too quickly (process log may have details)")
    assert parsed["orchagent"] == {"state": "RUNNING", "pid": 55, "uptime": "0:01:37",
                                   "raw": "orchagent      RUNNING   pid 55, uptime 0:01:37"}
    assert parsed["gearsyncd"]["state"] == "EXITED" and parsed["gearsyncd"]["pid"] is None
    assert parsed["portsyncd"]["state"] == "FATAL"
    assert parse_supervisor_status("") == {}

    # poll returns as soon as the condition holds, and gives up at the budget
    ticks = []
    assert poll(lambda: len(ticks) >= 3 or ticks.append(1), timeout=30, interval=0,
                sleep=lambda _: None)[0] is True
    assert poll(lambda: False, timeout=0.01, interval=0, sleep=lambda _: None)[0] is False

    # dead-man tags are filename-safe even for keys full of colons and pipes
    assert deadman_tag("pause", "swss", "orchagent") == "pause-swss-orchagent"
    assert "/" not in deadman_tag("corrupt", "APPL_DB:LAG|x/y")
    assert quote("a b") == "'a b'"

    # every Spine injector builds a real command, not a placeholder
    kill_restart = ChaosPlan.from_args(["kill=orchagent:how=restart"]).injectors[0]
    assert kill_restart.command() == "docker exec swss supervisorctl restart orchagent"
    assert ChaosPlan.from_args(["kill=orchagent"]).injectors[0].command() == \
        "docker exec swss pkill -9 -x orchagent"
    assert ChaosPlan.from_args(["kill=swss:how=container"]).injectors[0].command() == "docker restart swss"
    # how=container names a container, not a daemon inside one
    _expect_error(ChaosPlan.from_args, ["kill=container=swss"])            # how=sigkill needs a daemon
    _expect_error(ChaosPlan.from_args, ["pause=seconds=10:container=swss"])   # how=signal needs a daemon

    # expected_syslog is narrow: it covers supervisor's own exit chatter and nothing else
    patterns = kill_restart.expected_syslog()
    assert any("spawned" in p for p in patterns) and any("exited" in p for p in patterns)
    assert all("orchagent" in p for p in patterns), patterns
    # corrupt deliberately hides nothing: a daemon's complaint about a bad value is the finding
    assert ChaosPlan.from_args(["corrupt=APPL_DB:[x]:a=b"]).injectors[0].expected_syslog() == ()


def test_bundles_and_run_ledger():
    assert bundle.sanitize("tests/pc/test_po.py::test_x[run3]") == "tests.pc.test_po.py.test_x.run3"
    assert "/" not in bundle.sanitize("a/b::c") and bundle.sanitize("") == "unnamed"
    cmd = bundle.repro_command(["kill=orchagent"], "tests/pc/test_po.py::test_x[run4]",
                               repeat=20, seed=20260911)
    # the parametrisation is stripped: you reproduce the test, not pytest's label for it
    assert cmd == ("pytest tests/pc/test_po.py::test_x --chaos kill=orchagent "
                   "--chaos-seed 20260911 --chaos-repeat 20"), cmd

    ledger = bundle.RunLedger()
    assert ledger.split("t.py::x[run3]") == ("t.py::x", "run3")
    assert ledger.split("t.py::x") == ("t.py::x", None)
    for i in range(1, 21):
        ledger.record("t.py::x[run{}]".format(i), passed=i not in (4, 11, 17), bundle=None)
    (nodeid, verdict, failed, _), = ledger.lines()
    assert verdict == "20 runs / 3 FAIL", verdict
    assert failed == ["run4", "run11", "run17"], failed
    assert list(ledger.flaky()) == ["t.py::x"]          # some passed, some failed: a real finding
    steady = bundle.RunLedger()
    for i in range(1, 4):
        steady.record("t.py::y[run{}]".format(i), passed=False)
    assert not steady.flaky(), "failing every time is broken, not flaky"
    assert steady.lines()[0][1] == "3 runs / 3 FAIL"


def test_squeeze_agent_against_fake_box():
    # the Squeeze agent, end to end against a fake box
    squeeze_checks()


def test_invariant_groups():
    # groups: an end user picks parity/health/signal/all, never a list of invariant names
    assert set(oracle.GROUPS) == {"parity", "health", "signal"}, oracle.GROUPS
    assert oracle.group_members("parity") == ["lag", "lag_member", "neighbor", "route_check",
                                              "vlan", "vlan_member"], oracle.group_members("parity")
    assert oracle.group_members("health") == ["bgp_established", "critical_processes",
                                              "no_cores", "no_start_limit"], oracle.group_members("health")
    assert oracle.group_members("signal") == ["key_set_backlog"]
    assert set(oracle.resolve("all")) == set(oracle.INVARIANTS)
    assert oracle.resolve(["parity", "no_cores"]) == sorted(
        set(oracle.group_members("parity")) | {"no_cores"})
    # every invariant belongs to exactly one group -- an untagged one would vanish from "parity"
    # and from "all"-by-group, and nobody would notice it had stopped running
    assert set(oracle.INVARIANT_GROUP) == set(oracle.INVARIANTS), "an invariant has no group"


def test_experiment_defaults_to_parity():
    # both default to parity, so a config need not enumerate anything
    defaults = Experiment.from_dict({"experiment": "d", "faults": [{"kill": {"process": "orchagent"}}]})
    assert defaults.steady_state == oracle.group_members("parity"), defaults.steady_state
    assert defaults.invariants == oracle.group_members("parity"), defaults.invariants
    grouped = Experiment.from_dict({"experiment": "g", "faults": [{"kill": {"process": "orchagent"}}],
                                    "steady_state": "all", "contract": {"invariants": "health"}})
    assert grouped.invariants == oracle.group_members("health"), grouped.invariants
    assert len(grouped.steady_state) == len(oracle.INVARIANTS)


def test_experiment_rejects_unknown_invariants():
    # invariant names in steady_state / contract must name something that exists, or the run
    # would report "all invariants passed" having quietly verified less than it claims
    _expect_error(Experiment.from_dict, {
        "experiment": "x", "faults": [{"kill": {"process": "orchagent"}}],
        "steady_state": ["route_check", "totally_made_up"]})
    _expect_error(Experiment.from_dict, {
        "experiment": "x", "faults": [{"kill": {"process": "orchagent"}}],
        "contract": {"invariants": ["crm_baseline"]}})     # offered by the UI, not implemented
    ok = Experiment.from_dict({
        "experiment": "x", "faults": [{"kill": {"process": "orchagent"}}],
        "steady_state": ["route_check", "lag_member"],
        "contract": {"invariants": ["no_cores"]}})
    # resolve() sorts and de-duplicates, so the stored list is canonical rather than as-typed
    assert ok.steady_state == ["lag_member", "route_check"], ok.steady_state
    assert ok.invariants == ["no_cores"], ok.invariants


def test_shipped_experiment_parses_and_schedules():
    # the shipped experiment file parses and schedules
    shipped = os.path.join(_under_test.PKG_DIR, "experiments",
                           "orchagent-restart.yml")
    live = Experiment.from_file(shipped)
    assert live.seed and live.faults and live.steady_state, live.describe()
    assert len(live.schedule()) == len(live.schedule()), "schedule must be deterministic"


def test_shim_lane():
    _check_shim_lane()


def test_oracle_invariants():
    check_oracle_invariants()


def test_vlan_invariant():
    check_vlan_invariant()


def test_vlan_member_invariant():
    check_vlan_member_invariant()


def test_fault_verdict():
    check_fault_verdict()


def _plan():
    return ChaosPlan.from_args([
        "cpu=orchagent:30",
        "sai=route_entry:create:delay=2000",
        "kill=orchagent:how=restart",
        "corrupt=APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=garbage",
    ])


def test_selftest_script_still_passes(capsys):
    """The script prints the contract line people read, and keeps working until P1 retires it."""
    assert main() == 0
    assert "sonic-chaos contract OK:" in capsys.readouterr().out
