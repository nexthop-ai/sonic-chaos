"""``--chaos-conditions``: a JSON matrix, every test once per condition, module by module.

Runs pytest inside pytest, like test_plugin.py. The inner suite's switch is a RecordingDut that
answers what ``pause`` and ``kill`` ask for, so both injectors go through their real apply,
status and release paths with no switch attached. Run from the repo root::

    python3 -m pytest tests/unit/test_conditions.py
"""
import json
import os
import re

import pytest

import _under_test

CONFTEST = _under_test.PLUGIN_BOOTSTRAP.replace("{", "{{").replace("}", "}}") + '''

import pytest
from sonic_chaos.testing.recording import RecordingDut

TRACE = {trace!r}

RUNNING = "orchagent   RUNNING   pid %d, uptime 0:00:02"
DUT = RecordingDut("dut1",
    responses=[(r"State\\.Running", 0, "true"), (r"docker top", 0, "191"),
               (r"ps -o stat=", 0, "T orchagent")],
    # a restart is judged by a new pid, so the second look must differ from the first
    sequences={{r"supervisorctl status": [RUNNING % 55, RUNNING % 56]}})


def note(line):
    with open(TRACE, "a") as fh:
        fh.write(line + "\\n")


@pytest.fixture(scope="session")
def duthosts():
    return [DUT]


@pytest.fixture(scope="module")
def sanity_check():
    note("sanity")


@pytest.fixture
def loganalyzer():
    return None
'''

SUITE = '''
import json
from conftest import DUT, note


def test_one(request, chaos):
    note("test_one " + json.dumps([request.node.callspec.params["chaos_condition"].name,
                                   [i.name for _, i in chaos.applied]]))


def test_two(request, chaos):
    name = chaos.condition.name
    note("test_two " + json.dumps([name, [i.name for _, i in chaos.applied]]))
    if not chaos.plan.dry_run:            # a dry run records no properties, by design
        assert dict(request.node.user_properties)["chaos_condition"] == name
        assert name in dict(request.node.user_properties)["chaos"]
    if name == "freeze" and not chaos.plan.dry_run:
        # the freeze really went to the switch before this test ran
        assert any("pkill -STOP -x orchagent" in c for c in DUT.commands)
    assert name != "freeze+restart" or [i.name for _, i in chaos.applied] == ["pause", "kill"]
'''

MATRIX = {
    "conditions": [
        {"name": "baseline", "faults": []},
        {"name": "freeze", "faults": ["pause=orchagent:3"], "note": "SIGSTOP orchagent"},
        ["pause=orchagent:3", {"kill": {"process": "orchagent", "how": "restart", "settle": "1"}}],
    ]
}


def _suite(pytester, matrix=MATRIX, extra_test=""):
    trace = os.path.join(str(pytester.path), "trace.log")
    pytester.makeconftest(CONFTEST.format(trace=trace))
    pytester.makepyfile(test_matrix=SUITE + extra_test)
    path = os.path.join(str(pytester.path), "matrix.json")
    with open(path, "w") as fh:
        json.dump(matrix, fh)
    return trace, path


def _trace(trace):
    with open(trace) as fh:
        return [line.rstrip("\n") for line in fh]


def test_every_test_runs_once_per_condition_module_by_module(pytester):
    trace, matrix = _suite(pytester)
    result = pytester.runpytest("-p", "no:cacheprovider", "-v", "--chaos-conditions", matrix, "--chaos-oracle", "none")
    result.assert_outcomes(passed=6)
    lines = [line for line in _trace(trace) if line.startswith("test_")]
    seen = [(line.split(" ", 1)[0], json.loads(line.split(" ", 1)[1])) for line in lines]
    # grouped: both tests under baseline, then both under freeze, then both under the third
    assert [c for _, (c, _) in seen] == ["baseline"] * 2 + ["freeze"] * 2 + ["pause+kill"] * 2, seen
    # what each condition put in force, in apply order
    assert [a for _, (_, a) in seen] == [[], [], ["pause"], ["pause"], ["pause", "kill"], ["pause", "kill"]]
    # the summary counts per test per condition, and names the conditions with their notes
    result.stdout.fnmatch_lines(["*conditions: *matrix.json*",
                                 "*freeze *pause(*   # SIGSTOP orchagent",
                                 "*ok   *test_one?baseline?*1 run / all pass",
                                 "*ok   *test_two?pause+kill?*1 run / all pass"])


def test_condition_is_released_before_the_next_and_lifo(pytester):
    trace, matrix = _suite(pytester)
    result = pytester.runpytest("-p", "no:cacheprovider", "--chaos-conditions", matrix, "--chaos-oracle", "none",
                                "--log-cli-level=INFO", "--log-format=%(message)s")
    result.assert_outcomes(passed=6)
    out = result.stdout.str()
    order = [m.group(0) for m in re.finditer(r"\[chaos\] (?:condition \S+ released|apply \w+|release \w+)", out)]
    assert order == [
        "[chaos] condition baseline released",
        "[chaos] apply pause", "[chaos] release pause", "[chaos] condition freeze released",
        "[chaos] apply pause", "[chaos] apply kill", "[chaos] release kill", "[chaos] release pause",
        "[chaos] condition pause+kill released",
    ], order


def test_repeat_counts_per_condition_and_the_bundle_selects_it(pytester):
    trace, matrix = _suite(pytester, extra_test='''

def test_breaks_when_frozen(chaos):
    assert chaos.condition.name != "freeze"
''')
    result = pytester.runpytest("-p", "no:cacheprovider", "--chaos-conditions", matrix, "--chaos-oracle", "none",
                                "--chaos-repeat", "2")
    result.assert_outcomes(passed=16, failed=2)
    result.stdout.fnmatch_lines(["*FAIL *test_breaks_when_frozen?freeze?*2 runs / 2 FAIL",
                                 "*failed on: run1, run2",
                                 "*ok   *test_breaks_when_frozen?baseline?*2 runs / all pass"])
    bundles = [d for d in os.listdir(os.path.join(str(pytester.path), "out", "chaos")) if "freeze-run1" in d]
    assert bundles, os.listdir(os.path.join(str(pytester.path), "out", "chaos"))
    with open(os.path.join(str(pytester.path), "out", "chaos", bundles[0], "repro.sh")) as fh:
        repro = fh.read()
    assert "--chaos-conditions {} --chaos-condition freeze --chaos-repeat 2".format(matrix) in repro, repro


def test_only_one_condition(pytester):
    _trace_, matrix = _suite(pytester)
    result = pytester.runpytest("-p", "no:cacheprovider", "--chaos-conditions", matrix, "--chaos-condition", "freeze",
                                "--chaos-oracle", "none", "--co", "-q")
    ids = [line for line in result.stdout.lines if "::" in line]
    assert ids and all("[freeze]" in line for line in ids), ids
    assert len(ids) == 2


def test_a_bad_matrix_fails_before_any_test(pytester):
    for matrix, message in (
            ({"conditions": [{"name": "x", "faults": ["kill=orchagnt"]}]}, "*unknown target 'orchagnt'*"),
            ({"conditions": [{"name": "a b", "faults": []}]}, "*name 'a b' may only use*"),
            ({"conditions": [{"name": "x", "faults": []}, {"name": "x", "faults": []}]}, "*'x' is used twice*"),
            ({"conditions": [[{"sai": "vlan"}]]}, "*must map to a dict*")):
        _trace_, path = _suite(pytester, matrix=matrix)
        result = pytester.runpytest("-p", "no:cacheprovider", "--chaos-conditions", path, "--chaos-oracle", "none")
        assert result.ret == pytest.ExitCode.USAGE_ERROR, result.stderr.str()
        result.stderr.fnmatch_lines(["*--chaos-conditions: *" + message])
    _trace_, path = _suite(pytester)
    result = pytester.runpytest("-p", "no:cacheprovider", "--chaos-conditions", path, "--chaos-condition", "nope")
    result.stderr.fnmatch_lines(["*no condition named nope; the file has: baseline, freeze, pause+kill*"])
    result = pytester.runpytest("-p", "no:cacheprovider", "--chaos-condition", "freeze")
    result.stderr.fnmatch_lines(["*--chaos-condition needs --chaos-conditions PATH*"])


def test_dry_run_applies_nothing(pytester):
    trace, matrix = _suite(pytester)
    result = pytester.runpytest("-p", "no:cacheprovider", "--chaos-conditions", matrix, "--chaos-dry-run",
                                "--chaos-oracle", "none")
    result.assert_outcomes(passed=6)
    with open(os.path.join(str(pytester.path), "trace.log")) as fh:
        assert "sanity" in fh.read()
