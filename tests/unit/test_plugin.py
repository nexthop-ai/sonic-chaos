"""Unit tests for the sonic-chaos pytest plugin: lifecycle, repeat, bundles, loganalyzer policy.

These run pytest inside pytest. Each test writes a tiny throwaway suite with a conftest that
stubs the three sonic-mgmt fixtures the plugin leans on (``duthosts``, ``sanity_check``,
``loganalyzer``), then asserts on what the inner run did. That is the only way to check the
things the Spine lane actually promises:

  * the fault goes in **after** pre-test sanity and comes out **before** post-test sanity,
  * it is released on every exit path, including the ones with no finalizer,
  * a run with no ``--chaos`` costs nothing and never touches a DUT,
  * ``--chaos-repeat`` produces the ``20 runs / 3 FAIL`` line, and
  * a failure leaves a repro bundle behind.

Ported from sonic-mgmt ``tests/common/unit_tests/hypersonic/unit_test_plugin.py``
(hypersonic @ b401b85d4). The inner conftest now loads the plugin through
``_under_test.PLUGIN_BOOTSTRAP`` instead of a ``tests/common/plugins`` checkout. Run from the repo root::

    python3 -m pytest tests/unit/test_plugin.py
"""
import os
import re

import pytest

import _under_test

CONFTEST = _under_test.PLUGIN_BOOTSTRAP.replace("{", "{{").replace("}", "}}") + '''

import json, os
import pytest

TRACE = os.path.join({trace_dir!r}, "trace.log")


def note(line):
    # One command per line: arm_deadman sends a multi-line heredoc whose body contains the thaw
    # command, and a raw write would make that *text* look like a command we ran.
    with open(TRACE, "a") as fh:
        fh.write(line.replace("\\n", "\\\\n") + "\\n")


class FakeDut(object):
    hostname = "dut1"
    pid = 55
    log_lines = 100

    def shell(self, cmd, module_ignore_errors=False, **kwargs):
        note("shell: " + cmd)
        if "supervisorctl status" in cmd:
            # A fresh pid each look: a real supervisor respawns the daemon, and a fixed pid
            # would make every test wait out the full settle budget.
            FakeDut.pid += 1
            return {{"rc": 0, "stdout": "orchagent   RUNNING   pid %d, uptime 0:00:02" % FakeDut.pid,
                    "stderr": ""}}
        if "State.Running" in cmd:
            return {{"rc": 0, "stdout": "true", "stderr": ""}}
        if "wc -l" in cmd:
            FakeDut.log_lines += 40         # the box logged something while the test ran
            return {{"rc": 0, "stdout": str(FakeDut.log_lines), "stderr": ""}}
        if cmd.startswith("tail -n"):
            return {{"rc": 0, "stdout": "Sep 11 sonic INFO spawned: 'orchagent' with pid 912",
                    "stderr": ""}}
        return {{"rc": 0, "stdout": "", "stderr": ""}}


class FakeAnalyzer(object):
    def __init__(self):
        self.ignore_regex = []


@pytest.fixture(scope="module")
def duthosts():
    note("duthosts requested")
    return [FakeDut()]


@pytest.fixture(scope="module", autouse=True)
def sanity_check():
    note("sanity: pre-test")
    yield
    note("sanity: post-test")


@pytest.fixture(autouse=True)
def loganalyzer(request):
    analyzers = {{"dut1": FakeAnalyzer()}}
    yield analyzers
    note("loganalyzer ignore count: %d" % len(analyzers["dut1"].ignore_regex))


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    # tests/conftest.py sets rep_call the same way; the plugin reads it to decide on a bundle.
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)
'''


@pytest.fixture
def suite(pytester):
    """Write the stub conftest and return a helper that runs the inner pytest."""
    trace_dir = str(pytester.path)
    pytester.makeconftest(CONFTEST.format(trace_dir=trace_dir))

    def run(test_source, *args):
        pytester.makepyfile(test_chaos_demo=test_source)
        result = pytester.runpytest_subprocess(*args)
        trace_path = os.path.join(trace_dir, "trace.log")
        trace = open(trace_path).read().splitlines() if os.path.exists(trace_path) else []
        return result, trace

    return run


PASSING = """
    def test_one():
        assert True
"""

FAILING = """
    def test_one():
        assert False, "deliberate failure under fault"
"""


class TestIdleRun(object):
    """A plugin registered in every sonic-mgmt run must cost nothing when it is not in use."""

    def test_no_chaos_flag_never_requests_a_dut(self, suite):
        result, trace = suite(PASSING)
        result.assert_outcomes(passed=1)
        assert not [line for line in trace if line.startswith("duthosts requested")], trace
        assert not [line for line in trace if line.startswith("shell:")], trace

    def test_no_chaos_flag_prints_no_summary(self, suite):
        result, _ = suite(PASSING)
        out = result.stdout.str()
        # Our summary section and report-header lines, not pytest's own "plugins: sonic-chaos-x.y"
        # header, which is there whenever the package is installed.
        assert "= sonic-chaos =" not in out and "sonic-chaos:" not in out and "sonic-chaos experiment" not in out


class TestLifecycle(object):

    def test_fault_is_applied_after_pre_sanity_and_released_before_post_sanity(self, suite):
        """The ordering guarantee: neither sanity pass sees a switch we are hurting on purpose."""
        result, trace = suite(PASSING, "--chaos", "kill=orchagent")
        result.assert_outcomes(passed=1)

        order = [line for line in trace if line.startswith("sanity:") or "pkill" in line]
        assert order[0] == "sanity: pre-test", order
        assert "pkill" in order[1], order
        assert order[-1] == "sanity: post-test", order

    def test_dry_run_resolves_the_plan_but_touches_nothing(self, suite):
        result, trace = suite(PASSING, "--chaos", "kill=orchagent", "--chaos-dry-run")
        result.assert_outcomes(passed=1)
        assert not [line for line in trace if line.startswith("shell:")], trace
        assert "dry-run" in result.stdout.str()

    def test_a_bad_spec_fails_before_any_dut_is_touched(self, suite):
        result, trace = suite(PASSING, "--chaos", "kill=nosuchdaemon")
        assert result.ret != 0
        assert "unknown target" in result.stderr.str() + result.stdout.str()
        assert not trace, "a configure-time error must not reach a DUT"

    def test_marker_injects_for_one_test_only(self, suite):
        result, trace = suite("""
            import pytest

            @pytest.mark.chaos("pause", "orchagent:5")
            def test_marked():
                assert True

            def test_unmarked():
                assert True
        """)
        result.assert_outcomes(passed=2)
        freezes = [line for line in trace if line.startswith("shell: ") and "pkill -STOP" in line]
        thaws = [line for line in trace if line.startswith("shell: docker exec swss pkill -CONT")]
        assert len(freezes) == 1, "only the marked test should be frozen"
        assert len(thaws) == 1, "and it must be thawed again"


class TestRepeat(object):

    def test_repeat_parametrizes_every_test(self, suite):
        result, _ = suite(PASSING, "--chaos", "kill=orchagent", "--chaos-repeat", "3", "-v")
        result.assert_outcomes(passed=3)
        assert "test_one[run1]" in result.stdout.str(), result.stdout.str()
        assert "test_one[run3]" in result.stdout.str()

    def test_summary_reports_runs_and_failures(self, suite):
        """The line the plan calls the best part of the pitch."""
        result, _ = suite(FAILING, "--chaos", "kill=orchagent", "--chaos-repeat", "4")
        out = result.stdout.str()
        assert "sonic-chaos" in out
        assert re.search(r"4 runs / 4 FAIL", out), out
        assert "failed on: run1, run2, run3, run4" in out

    def test_an_intermittent_failure_is_called_out(self, suite):
        """Failing 1-in-N under fault is the signal a single red result hides."""
        result, _ = suite("""
            import os
            COUNT = os.path.join(os.path.dirname(__file__), "count")

            def test_flaky():
                n = 0
                if os.path.exists(COUNT):
                    n = int(open(COUNT).read())
                open(COUNT, "w").write(str(n + 1))
                assert n != 1, "fails only on the second run"
        """, "--chaos", "kill=orchagent", "--chaos-repeat", "3")
        out = result.stdout.str()
        assert re.search(r"3 runs / 1 FAIL", out), out
        assert "disagreed with themselves" in out


class TestBundles(object):

    def test_a_failure_under_fault_leaves_a_repro_bundle(self, pytester, suite):
        result, _ = suite(FAILING, "--chaos", "kill=orchagent")
        result.assert_outcomes(failed=1)

        roots = list(pytester.path.glob("out/chaos/*"))
        assert len(roots) == 1, "expected exactly one bundle, got {}".format(roots)
        files = sorted(p.name for p in roots[0].iterdir())
        # The oracle runs by default (parity), so its before/after/diff travel with the bundle.
        assert files == ["fault.json", "oracle_after.json", "oracle_before.json", "oracle_diff.txt",
                         "outcome.txt", "repro.sh", "syslog.txt"], files

        repro = (roots[0] / "repro.sh").read_text()
        assert "--chaos kill=orchagent" in repro
        assert "test_chaos_demo.py::test_one" in repro
        assert "[" not in repro.split("pytest ")[1].split()[0], "the run label must be stripped"

    def test_the_bundle_records_what_was_injected(self, pytester, suite):
        import json
        suite(FAILING, "--chaos", "kill=orchagent")
        fault = json.loads(next(pytester.path.glob("out/chaos/*/fault.json")).read_text())
        assert fault["injectors"][0]["name"] == "kill"
        assert fault["injectors"][0]["params"]["process"] == "orchagent"
        assert fault["events"][0]["action"] == "kill", fault["events"]

    def test_a_passing_test_leaves_no_bundle(self, pytester, suite):
        suite(PASSING, "--chaos", "kill=orchagent")
        assert not list(pytester.path.glob("out/chaos/*"))

    def test_bundle_dir_is_configurable(self, pytester, suite):
        suite(FAILING, "--chaos", "kill=orchagent", "--chaos-bundle-dir", "evidence")
        assert list(pytester.path.glob("evidence/*/repro.sh"))


class TestLoganalyzerPolicy(object):

    def test_injection_noise_is_added_to_the_ignore_list(self, suite):
        """Without this every result under fault is red for our own supervisor chatter."""
        _, trace = suite(PASSING, "--chaos", "kill=orchagent")
        counts = [int(line.split(": ")[1]) for line in trace if line.startswith("loganalyzer ignore count")]
        assert counts and counts[0] > 0, trace

    def test_an_idle_run_adds_nothing(self, suite):
        _, trace = suite(PASSING)
        counts = [int(line.split(": ")[1]) for line in trace if line.startswith("loganalyzer ignore count")]
        assert counts == [0], trace

    def test_a_fault_injected_mid_test_is_ignored_too(self, suite):
        """loganalyzer reads its ignore list at teardown; a fault that came and went inside the
        test body still printed its lines, so its patterns must be there by then."""
        mid_test = (
            "def test_one(chaos):\n"
            "    with chaos.kill('orchagent:how=restart:settle=0'):\n"
            "        pass\n")
        _, trace = suite(mid_test)
        counts = [int(line.split(": ")[1]) for line in trace if line.startswith("loganalyzer ignore count")]
        assert counts and counts[0] > 0, trace

    def test_sai_ignores_only_its_own_status_lines(self):
        from sonic_chaos import ChaosPlan
        import re
        sai = ChaosPlan.from_args(["sai=vlan:create:status=SAI_STATUS_TABLE_FULL"]).injectors[0]
        ours = ["ERR syncd#syncd: :- sendApiResponse: api SAI_COMMON_API_CREATE failed in syncd "
                "mode:SAI_STATUS_TABLE_FULL",
                "ERR swss#orchagent: :- create: create status: SAI_STATUS_TABLE_FULL"]
        not_ours = ["ERR swss#orchagent: :- handleSaiFailure: Encountered failure in create operation, "
                    "SAI API: SAI_API_VLAN, status: SAI_STATUS_TABLE_FULL",          # the reaction: a finding
                    "ERR syncd#syncd: :- sendApiResponse: api SAI_COMMON_API_REMOVE failed in syncd "
                    "mode:SAI_STATUS_TABLE_FULL",                                   # another op
                    "ERR syncd#syncd: :- sendApiResponse: api SAI_COMMON_API_CREATE failed in syncd "
                    "mode:SAI_STATUS_ITEM_NOT_FOUND"]                               # another status
        patterns = sai.expected_syslog()
        for line in ours:
            assert any(re.match(rx, "Sep 28 10:00:01 sonic " + line) for rx in patterns), line
        for line in not_ours:
            assert not any(re.match(rx, "Sep 28 10:00:01 sonic " + line) for rx in patterns), line
        assert ChaosPlan.from_args(["sai=route_entry:create:delay=2000"]).injectors[0].expected_syslog() == ()


class TestReleaseOnEveryExitPath(object):

    def test_a_crashing_test_still_releases(self, suite):
        _, trace = suite("""
            def test_boom():
                raise KeyboardInterrupt("user pressed ctrl-c mid-test")
        """, "--chaos", "pause=orchagent:30")
        # The freeze must be undone even though the test never returned normally.
        assert [line for line in trace if line.startswith("shell: docker exec swss pkill -CONT")], trace

    def test_a_test_that_errors_in_setup_still_releases(self, suite):
        _, trace = suite("""
            import pytest

            @pytest.fixture
            def broken():
                raise RuntimeError("setup exploded")

            def test_needs_it(broken):
                assert True
        """, "--chaos", "pause=orchagent:30")
        assert [line for line in trace if line.startswith("shell: docker exec swss pkill -CONT")], trace
