"""Review #4: a release that fails must never end green, and spin must not strand its control file."""
import pytest

from sonic_chaos import ChaosPlan
from sonic_chaos.engine import runner
from sonic_chaos.testing import RecordingDut

CONTROL = "/sonic-chaos/spin_control.json"


def spin():
    return ChaosPlan.from_args(["spin=orchagent:70"]).injectors[0]


def test_spin_release_removes_and_verifies_before_disarming():
    dut = RecordingDut(responses=[(r"\[ -e " + CONTROL, 0, "gone")])
    spin().release(dut)
    rm = next(i for i, c in enumerate(dut.commands) if "rm -f " + CONTROL in c)
    check = next(i for i, c in enumerate(dut.commands) if "[ -e " + CONTROL in c)
    disarm = next(i for i, c in enumerate(dut.commands) if "kill -- -" in c)
    assert rm < check < disarm, dut.commands


@pytest.mark.parametrize("responses", [
    [(r"\[ -e " + CONTROL, 0, "present")],                       # rm "worked" but the file is still there
    [(r"rm -f " + CONTROL, 1, "Error: No such container: swss"),  # swss down at release
     (r"\[ -e ", 1, "Error: No such container: swss")],
])
def test_spin_release_that_cannot_remove_the_file_raises_and_keeps_the_dead_man(responses):
    dut = RecordingDut(responses=responses)
    with pytest.raises(RuntimeError, match="may still be armed"):
        spin().release(dut)
    assert not [c for c in dut.commands if "kill -- -" in c], "the dead-man must stay armed"


class _FailingSession(object):
    def release_all(self):
        raise RuntimeError("could not thaw orchagent")


def test_a_failed_release_outranks_every_verdict(monkeypatch):
    monkeypatch.setattr(runner, "RELEASE_FAILURES", [])
    dut = RecordingDut()
    runner.release_guarded(_FailingSession(), dut, "release pause")
    assert runner.RELEASE_FAILURES and "could not thaw orchagent" in runner.RELEASE_FAILURES[0]
    assert runner.release_failed(dut) == runner.EXIT_RELEASE_FAILED == 6
