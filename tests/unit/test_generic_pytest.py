"""The plugin in a suite that is not sonic-mgmt: no duthosts, no sanity_check, no loganalyzer.

The switch comes from ``--chaos-dut``. The inner conftest registers a ``record://`` transport that
answers like a healthy box and writes every command to trace.log, so each test can assert on what
reached the "switch".
"""
import textwrap

import pytest

import _under_test

CONFTEST = _under_test.PLUGIN_BOOTSTRAP + textwrap.dedent('''
    import os
    from sonic_chaos import Injector, register_injector
    from sonic_chaos.testing import RecordingDut
    from sonic_chaos.transport import register_scheme

    TRACE = os.path.join(os.path.dirname(__file__), "trace.log")
    HEALTHY = [(r"mkdir -p .*cat >", 0, "4242"), (r"ps -o stat=", 0, "Tl orchagent")]


    class TracingDut(RecordingDut):
        def shell(self, cmd, module_ignore_errors=False, **kwargs):
            with open(TRACE, "a") as fh:
                fh.write(cmd.replace("\\n", "\\\\n") + "\\n")
            return super().shell(cmd, module_ignore_errors=module_ignore_errors, **kwargs)


    register_scheme("record", lambda parsed, url: TracingDut(hostname=parsed.hostname, responses=HEALTHY))


    @register_injector("dud", lane="test", positional=("target",))
    class Dud(Injector):
        """Arms and never engages, like a CPU cap on an idle daemon."""
        def apply(self, duthost, **_):
            duthost.shell("arm dud")

        def release(self, duthost):
            duthost.shell("disarm dud")

        def status(self, duthost):
            return {"active": True, "achieved": {"injected": 0}}
''')

TESTS = '''
def test_one(chaos_duts):
    assert chaos_duts[0].hostname == "sw1"

def test_two():
    pass

def test_three():
    pass
'''


@pytest.fixture
def suite(pytester):
    pytester.makeconftest(CONFTEST)

    def run(tests, *args):
        pytester.makepyfile(test_generic=tests)
        result = pytester.runpytest_subprocess("-p", "no:cacheprovider", *args)
        trace = pytester.path / "trace.log"
        return result, (trace.read_text().splitlines() if trace.exists() else [])
    return run


def test_a_fault_reaches_the_switch_named_by_chaos_dut(suite):
    result, trace = suite(TESTS, "--chaos-dut", "record://sw1", "--chaos", "pause=orchagent:10",
                          "--chaos-oracle", "none")
    result.assert_outcomes(passed=3)
    assert sum("pkill -STOP -x orchagent" in c for c in trace) == 1, "held for the module, applied once"
    assert trace[-2:][0].endswith("pkill -CONT -x orchagent") or any("pkill -CONT" in c for c in trace[-3:])


def test_a_fault_with_no_switch_is_a_usage_error(suite):
    result, trace = suite(TESTS, "--chaos", "pause=orchagent:10")
    assert "pass --chaos-dut" in result.stdout.str() + result.stderr.str()
    assert trace == []


def test_an_idle_run_needs_no_switch_at_all(suite):
    result, trace = suite("def test_x():\n    pass\n")
    result.assert_outcomes(passed=1)
    assert trace == []


def test_the_experiment_schedule_deals_one_fault_per_test(suite, pytester):
    pytester.makefile(".yml", exp='''
        experiment: two-freezes
        seed: 7
        faults:
          - pause: {process: orchagent, seconds: 10}
          - pause: {process: bgpd, container: bgp, seconds: 5}
        contract: {invariants: none_at_all}
    '''.replace("none_at_all", "no_cores"))
    result, trace = suite(TESTS, "--chaos-dut", "record://sw1", "--chaos-file", "exp.yml")
    result.assert_outcomes(passed=3)
    frozen = [c.split()[-1] for c in trace if "pkill -STOP" in c]
    assert len(frozen) == 3 and set(frozen) == {"orchagent", "bgpd"}, frozen
    assert frozen[0] == frozen[2] != frozen[1], "slots wrap around in the seeded order"
    assert "verdicts: 3 HELD, 0 BROKE, 0 INCONCLUSIVE" in result.stdout.str()


def test_a_fault_that_never_engaged_is_inconclusive(suite):
    result, _ = suite("def test_x():\n    pass\n", "--chaos-dut", "record://sw1", "--chaos", "dud=x",
                      "--chaos-oracle", "none")
    result.assert_outcomes(passed=1)
    out = result.stdout.str()
    assert "verdicts: 0 HELD, 0 BROKE, 1 INCONCLUSIVE" in out


def test_strict_mode_fails_an_inconclusive_test(suite):
    result, _ = suite("def test_x():\n    pass\n", "--chaos-dut", "record://sw1", "--chaos", "dud=x",
                      "--chaos-oracle", "none", "--chaos-strict")
    result.assert_outcomes(passed=1, errors=1)
    assert "INCONCLUSIVE: no fault engaged" in result.stdout.str()


def test_the_fault_decorator_is_applied_once_by_the_plugin(suite):
    tests = '''
from sonic_chaos import fault

@fault("pause=orchagent:10")
def test_x(chaos_duts):
    assert chaos_duts
'''
    result, trace = suite(tests, "--chaos-dut", "record://sw1", "--chaos-oracle", "none")
    result.assert_outcomes(passed=1)
    assert sum("pkill -STOP -x orchagent" in c for c in trace) == 1, trace
    assert any("pkill -CONT -x orchagent" in c for c in trace)


def test_a_per_test_fault_is_still_checked_after_release(suite):
    """Regression: release() used to drop the per-test session before teardown asked whether any
    fault was active, so marker and scheduled faults were never oracle-checked or bundled."""
    tests = '''
import pytest

@pytest.mark.chaos("pause", "orchagent:10")
def test_x():
    assert False, "deliberate"
'''
    result, _ = suite(tests, "--chaos-dut", "record://sw1", "--chaos-oracle", "none")
    result.assert_outcomes(failed=1)
    out = result.stdout.str()
    assert "FAIL test_generic.py::test_x" in out and "repro:" in out, out
