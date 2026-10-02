"""The public API: Chaos, @fault, @injector, entry-point plugins, probe(), the experiment schema."""
import os
import types

import pytest

import sonic_chaos
from sonic_chaos import Chaos, ChaosFinding, ChaosPlan, ChaosUsageError, Injector, fault, register_injector
from sonic_chaos import api, oracle, plugins
from sonic_chaos.experiment import Experiment, json_schema
from sonic_chaos.injector import REGISTRY
from sonic_chaos.testing import RecordingDut

PAUSING = [(r"mkdir -p .*cat >", 0, "4242"), (r"ps -o stat=", 0, "Tl orchagent")]


def paused_box():
    return RecordingDut(responses=PAUSING)


def freezes(dut):
    return [c for c in dut.commands if "pkill -STOP" in c]


def thaws(dut):
    return [c for c in dut.commands if "pkill -CONT" in c and "sleep" not in c]


# ------------------------------------------------------------------------------ Chaos

class TestChaos(object):

    def test_a_with_block_applies_then_releases(self):
        dut = paused_box()
        chaos = Chaos(dut, oracle=None)
        with chaos.fault("pause=orchagent:10"):
            assert freezes(dut) and not thaws(dut)
            assert chaos.recipe().startswith("pause(")
        assert thaws(dut) and chaos.recipe() == "none"

    def test_release_runs_even_when_the_block_raises(self):
        dut = paused_box()
        chaos = Chaos(dut, oracle=None)
        with pytest.raises(RuntimeError, match="boom"):
            with chaos.fault("pause", "orchagent:10"):
                raise RuntimeError("boom")
        assert thaws(dut)

    def test_pause_is_a_named_helper_too(self):
        dut = paused_box()
        with Chaos(dut, oracle=None).pause("orchagent:10"):
            assert freezes(dut)
        assert thaws(dut)

    def test_the_named_helpers_are_the_same_faults(self):
        dut = RecordingDut(responses=[(r"docker inspect -f", 0, "true"),
                                      (r"supervisorctl status", 0, "orchagent RUNNING pid 912, uptime 0:00:02")])
        with Chaos(dut, oracle=None).kill("orchagent:how=restart:settle=0"):
            pass
        assert dut.ran_once(r"supervisorctl restart") == "docker exec swss supervisorctl restart orchagent"

    def test_the_baseline_is_taken_once_and_subtracted(self, monkeypatch):
        stale = oracle.Divergence("lag_member", "ASIC_DB", "k1", "stale before we started")
        monkeypatch.setattr(oracle, "gate", lambda dut, only: ([stale], [], None))
        chaos = Chaos(RecordingDut(), oracle="parity")
        assert chaos.baseline == {"dut1": oracle.finding_keys([stale])}
        chaos.assert_consistent()          # the same divergence is not a finding

    def test_a_divergence_that_outlives_the_budget_is_a_finding(self, monkeypatch):
        new = oracle.Divergence("lag_member", "ASIC_DB", "k2", "appeared under fault")
        monkeypatch.setattr(oracle, "wait_consistent",
                            lambda dut, only, timeout, baseline: ([new], [], timeout, None))
        chaos = Chaos(RecordingDut(), oracle=None)
        with pytest.raises(ChaosFinding, match="k2"):
            chaos.assert_recovers(within=5)
        assert issubclass(ChaosFinding, AssertionError), "pytest must report it as a failure"

    def test_dry_run_touches_nothing(self):
        dut = paused_box()
        with Chaos(dut, dry_run=True).fault("pause=orchagent:10"):
            pass
        assert dut.calls == []

    def test_a_bad_spec_is_refused_before_the_switch_is_touched(self):
        dut = RecordingDut()
        with pytest.raises(ChaosUsageError):
            Chaos(dut, oracle=None).inject("cpu=orchagent:300")
        assert dut.calls == []


# ------------------------------------------------------------------------------ @fault

class TestFaultDecorator(object):

    def test_outside_pytest_it_runs_the_whole_lifecycle(self):
        seen = {}

        @fault("pause=orchagent:10", oracle=None)
        def work(dut):
            seen["frozen_during"] = bool(freezes(dut)) and not thaws(dut)
            return "done"

        dut = paused_box()
        assert work(dut) == "done"
        assert seen["frozen_during"] and thaws(dut)

    def test_stacked_faults_are_each_applied_once(self):
        @fault("pause=orchagent:10", oracle=None)
        @fault("pause=bgpd:5:container=bgp", oracle=None)
        def work(dut):
            return len(freezes(dut))

        dut = paused_box()
        assert work(dut) == 2
        assert len(freezes(dut)) == 2, dut.commands

    def test_it_is_also_the_chaos_marker(self):
        @fault("kill", "orchagent")
        def test_x():
            pass
        marks = [m for m in getattr(test_x, "pytestmark", []) if m.name == "chaos"]
        assert [(m.args, m.kwargs) for m in marks] == [(("kill", "orchagent"), {})]

    def test_under_the_plugin_it_only_calls_through(self):
        dut = paused_box()

        @fault("pause=orchagent:10")
        def work(dut):
            return "ran"

        token = api.CURRENT_TEST.set(work)
        try:
            assert work(dut) == "ran"
        finally:
            api.CURRENT_TEST.reset(token)
        assert dut.calls == [], "the plugin applies marker faults; the wrapper must not apply them again"

    def test_a_helper_called_from_inside_a_test_still_applies_its_fault(self):
        """Review #1: the plugin runs for every test, but only the test itself is plugin-owned."""
        dut = paused_box()

        @fault("pause=orchagent:10", oracle=None)
        def helper(dut):
            return bool(freezes(dut))

        def some_test():
            pass

        token = api.CURRENT_TEST.set(some_test)
        try:
            assert helper(dut) is True, "the fault must be applied around the helper"
        finally:
            api.CURRENT_TEST.reset(token)
        assert thaws(dut)

    def test_a_bad_spec_fails_at_decoration_time(self):
        with pytest.raises(ChaosUsageError):
            fault("cpu=orchagent:300")

    def test_it_needs_to_find_the_switch(self):
        @fault("pause=orchagent:10", oracle=None)
        def work(x):
            return x
        with pytest.raises(ChaosUsageError, match="dut="):
            work(42)


# ------------------------------------------------------------------------------ extension points

@pytest.fixture
def clean_registry():
    before = dict(REGISTRY)
    yield
    REGISTRY.clear()
    REGISTRY.update(before)


class TestExtending(object):

    def test_injector_decorator_registers_a_new_fault(self, clean_registry):
        @register_injector("netem", lane="spine", positional=("port", "loss"))
        class Netem(Injector):
            def apply(self, duthost, **_):
                duthost.shell("tc qdisc add dev {} root netem loss {}%".format(
                    self.params["port"], self.params["loss"]))

            def release(self, duthost):
                duthost.shell("tc qdisc del dev {} root".format(self.params["port"]), module_ignore_errors=True)

        plan = ChaosPlan.from_args(["netem=Ethernet0:5"])
        dut = RecordingDut()
        with Chaos(dut, oracle=None).fault("netem=Ethernet0:5"):
            pass
        assert plan.injectors[0].name == "netem"
        assert dut.commands == ["tc qdisc add dev Ethernet0 root netem loss 5%", "tc qdisc del dev Ethernet0 root"]

    def test_entry_point_plugins_load_on_first_unknown_name(self, clean_registry, monkeypatch):
        class Flap(Injector):
            name, lane, positional = "flap", "spine", ("port",)

        loaded = []

        class EP(object):
            name, value = "flap", "fake:Flap"

            def load(self):
                loaded.append(1)
                return Flap

        monkeypatch.setattr(plugins, "_loaded", [False])
        monkeypatch.setattr(plugins.metadata, "entry_points",
                            lambda group: [EP()] if group == "sonic_chaos.injectors" else [])
        assert ChaosPlan.from_args(["flap=Ethernet0"]).injectors[0].name == "flap"
        ChaosPlan.from_args(["flap=Ethernet0"])
        assert loaded == [1], "entry points are loaded once"

    def test_a_broken_plugin_is_skipped_not_fatal(self, clean_registry, monkeypatch):
        class Broken(object):
            name, value = "broken", "nowhere:Nothing"

            def load(self):
                raise ImportError("no such module")

        monkeypatch.setattr(plugins, "_loaded", [False])
        monkeypatch.setattr(plugins.metadata, "entry_points", lambda group: [Broken()])
        assert ChaosPlan.from_args(["kill=orchagent"]).injectors[0].name == "kill"
        with pytest.raises(ChaosUsageError, match="unknown injector 'broken'"):
            ChaosPlan.from_args(["broken=x"])

    def test_probe_says_what_a_fault_will_do_without_doing_it(self):
        dut = RecordingDut()
        for spec in ("kill=orchagent", "exhaust=nhg:0:over_pct=110", "storm=netlink:rate=100:seconds=5"):
            report = ChaosPlan.from_args([spec]).injectors[0].probe(dut)
            assert set(report) >= {"injector", "lane", "describe", "capabilities", "will_restart", "warnings"}
        assert "available" in ChaosPlan.from_args(["exhaust=nhg:0"]).injectors[0].probe(dut)["capabilities"]["table"]


# ------------------------------------------------------------------------------ experiment files

class TestSchema(object):

    def test_every_injector_has_a_variant(self):
        variants = json_schema()["properties"]["faults"]["items"]["oneOf"]
        assert {v["required"][0] for v in variants} == set(REGISTRY)

    def test_shipped_experiments_validate(self):
        jsonschema = pytest.importorskip("jsonschema")
        import yaml
        root = os.path.join(os.path.dirname(sonic_chaos.__file__), "experiments")
        for name in os.listdir(root):
            with open(os.path.join(root, name)) as fh:
                jsonschema.validate(yaml.safe_load(fh), json_schema())

    def test_version_is_accepted_and_checked(self):
        base = {"experiment": "x", "faults": [{"kill": {"process": "orchagent"}}]}
        Experiment.from_dict(dict(base, version=1))
        with pytest.raises(ChaosUsageError, match="version"):
            Experiment.from_dict(dict(base, version=2))

    def test_victim_is_gone(self):
        with pytest.raises(ChaosUsageError, match="victim"):
            Experiment.from_dict({"experiment": "x", "victim": "orchagent",
                                  "faults": [{"kill": {"process": "orchagent"}}]})


def test_import_is_light():
    """``import sonic_chaos`` must not drag in pytest: the DUT-side and library users have none."""
    import subprocess
    import sys
    code = ("import sys, sonic_chaos; sonic_chaos.__version__; "
            "print(int('pytest' in sys.modules), int('sonic_chaos.injectors' in sys.modules))")
    import _under_test
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=_under_test.SRC_DIR))
    assert out.stdout.split() == ["0", "0"], out.stderr


def test_public_names_resolve():
    for name in sonic_chaos.__all__:
        assert getattr(sonic_chaos, name) is not None
    assert isinstance(api, types.ModuleType)
