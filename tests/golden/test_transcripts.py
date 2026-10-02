"""Golden transcripts: the exact commands each injector sends, frozen before anything moves.

Every scenario builds an injector from its spec, drives ``apply``, ``status`` and ``release``
against a ``RecordingDut``, and compares what it sent -- every shell command, every copy, and
what each step returned -- against ``transcripts/<name>.txt``. A refactor that means to change
nothing must leave every file byte-identical. One that means to change something shows up as a
reviewable diff:

    python3 -m pytest tests/golden --update-golden && git diff tests/golden/transcripts

Time is virtual. ``time.time``/``time.sleep`` and the defaults captured by ``poll`` and
``oracle.wait_consistent`` are replaced by one clock that only moves when something sleeps, so
a 300 s recovery budget costs nothing and every timestamp in a transcript is reproducible.
Module-level caches (the per-host sudo probe, the squeeze push set) are cleared first, so a
scenario records the same thing whichever scenarios ran before it.
"""
import json
import os
import shutil
import time

import pytest

import _under_test
from sonic_chaos import injectors  # noqa: F401  registers them
from sonic_chaos import injector as injector_mod
from sonic_chaos import oracle, squeeze
from sonic_chaos.injector import ChaosPlan
from sonic_chaos.testing import RecordingDut

from scenarios import SCENARIOS

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN_DIR = os.path.join(HERE, "transcripts")
EPOCH = 1800000000.0          # 2027-01-15; any fixed value works, it only has to never change
STEPS = ("apply", "status", "release")


class VirtualClock(object):
    def __init__(self, start=EPOCH):
        self.now = start

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(0.0, seconds)


@pytest.fixture
def clock(monkeypatch):
    clk = VirtualClock()
    monkeypatch.setattr(time, "time", clk.time)
    monkeypatch.setattr(time, "monotonic", clk.time)
    monkeypatch.setattr(time, "sleep", clk.sleep)
    monkeypatch.setattr(injector_mod.poll, "__defaults__", (2, clk.sleep))
    defaults = list(oracle.wait_consistent.__defaults__)
    names = oracle.wait_consistent.__code__.co_varnames[:oracle.wait_consistent.__code__.co_argcount]
    first = len(names) - len(defaults)
    for i, name in enumerate(names[first:]):
        if name == "sleep":
            defaults[i] = clk.sleep
        elif name == "clock":
            defaults[i] = clk.time
    monkeypatch.setattr(oracle.wait_consistent, "__defaults__", tuple(defaults))
    injector_mod._sudo_prefix.clear()
    squeeze._pushed.clear()
    yield clk
    injector_mod._sudo_prefix.clear()
    squeeze._pushed.clear()


def _mask(text):
    """Paths into this checkout differ per machine; the package dir is the stable anchor."""
    return text.replace(_under_test.PKG_DIR, "<pkg>")


def _result(value):
    return _mask(json.dumps(value, sort_keys=True, default=repr))


def record(scenario):
    """Run one scenario and return its transcript as text."""
    dut = RecordingDut(responses=scenario.responses,
                       sequences={k: list(v) for k, v in scenario.sequences.items()})
    lines = ["# golden transcript: {}".format(scenario.name),
             "# spec: {}".format(scenario.spec),
             "# box: {}".format(scenario.box)]
    try:
        injector = ChaosPlan.from_args([scenario.spec]).injectors[0]
    except Exception as err:  # a spec refused at validate time is a behaviour worth pinning too
        lines.append("!! validate raised {}: {}".format(type(err).__name__, err))
        return "\n".join(lines) + "\n"
    lines.append("# injector: {}".format(injector.describe()))
    for step in STEPS:
        lines.append("== {}".format(step))
        mark = len(dut.calls)
        try:
            outcome = "-> " + _result(getattr(injector, step)(dut))
        except Exception as err:
            outcome = "!! {} raised {}: {}".format(step, type(err).__name__, err)
        for line in dut.transcript()[mark:]:
            lines.append(_mask(line))
        lines.append(_mask(outcome))
    return "\n".join(lines) + "\n"


def _can_build_shim():
    return bool(shutil.which("make") and (shutil.which("cc") or shutil.which("gcc")))


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_transcript_matches_golden(scenario, clock, request):
    if scenario.needs_shim and not _can_build_shim():
        pytest.skip("needs make and a C compiler to build the interposer")
    got = record(scenario)
    path = os.path.join(GOLDEN_DIR, scenario.name + ".txt")
    if request.config.getoption("--update-golden"):
        os.makedirs(GOLDEN_DIR, exist_ok=True)
        with open(path, "w") as fh:
            fh.write(got)
        return
    if not os.path.isfile(path):
        pytest.fail("no golden transcript for {0}; record it with --update-golden and review "
                    "tests/golden/transcripts/{0}.txt before committing".format(scenario.name))
    with open(path) as fh:
        want = fh.read()
    assert got == want, "transcript for {} changed; if intended, re-record with --update-golden " \
                        "and review the diff".format(scenario.name)


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_transcript_is_deterministic(scenario, clock):
    """Recording twice in one process gives the same text, so the golden files mean something."""
    if scenario.needs_shim and not _can_build_shim():
        pytest.skip("needs make and a C compiler to build the interposer")
    first = record(scenario)
    injector_mod._sudo_prefix.clear()
    squeeze._pushed.clear()
    clock.now = EPOCH
    assert record(scenario) == first


def test_every_injector_has_a_scenario():
    covered = {ChaosPlan.from_args([s.spec]).injectors[0].name for s in SCENARIOS}
    assert covered == set(injector_mod.REGISTRY), sorted(set(injector_mod.REGISTRY) - covered)
