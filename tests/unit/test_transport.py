"""sonic_chaos.transport: URL parsing, and a real round trip through a local shell."""
import os

import pytest

from sonic_chaos.transport import CommandDut, LocalDut, SshDut, TransportError, open_dut, register_scheme


def test_ssh_url_builds_a_non_interactive_ssh():
    dut = open_dut("ssh://admin@10.0.0.5:2222")
    assert isinstance(dut, SshDut) and dut.hostname == "10.0.0.5"
    assert dut.argv[0] == "ssh" and "BatchMode=yes" in dut.argv
    assert dut.argv[dut.argv.index("-p") + 1] == "2222" and dut.argv[-1] == "admin@10.0.0.5"


def test_ssh_defaults_to_admin_on_22():
    dut = open_dut("ssh://box1")
    assert dut.argv[-1] == "admin@box1" and dut.argv[dut.argv.index("-p") + 1] == "22"


def test_cmd_takes_any_prefix():
    dut = open_dut("cmd:sshpass -p secret ssh admin@10.0.0.9")
    assert isinstance(dut, CommandDut) and dut.argv[:2] == ["sshpass", "-p"]
    assert dut.hostname == "10.0.0.9"


def test_local_and_unknown_schemes():
    assert isinstance(open_dut("local://"), LocalDut)
    with pytest.raises(ValueError, match="unknown DUT address"):
        open_dut("telnet://box")


def test_a_site_can_register_a_scheme():
    register_scheme("unit-test-lab", lambda parsed, url: CommandDut(parsed.hostname, ["true"]))
    assert open_dut("unit-test-lab://sw9").hostname == "sw9"


def test_shell_returns_the_duthost_shape():
    dut = LocalDut("here", sudo=False)
    res = dut.shell("echo out; echo err >&2")
    assert res == {"rc": 0, "stdout": "out\n", "stderr": "err\n"}


def test_a_failing_command_raises_unless_told_not_to():
    dut = LocalDut("here", sudo=False)
    with pytest.raises(TransportError, match="rc=3"):
        dut.shell("exit 3")
    assert dut.shell("exit 3", module_ignore_errors=True)["rc"] == 3
    assert dut.shell_raw("exit 4")["rc"] == 4


def test_ansible_kwargs_are_accepted_and_ignored():
    assert LocalDut("here", sudo=False).shell("true", chdir="/", executable="/bin/sh")["rc"] == 0


def test_copy_lands_the_exact_bytes(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(os.urandom(70000))
    dest = tmp_path / "out" / "landed.bin"
    LocalDut("here", sudo=False).copy(src=str(src), dest=str(dest), mode="0600")
    assert dest.read_bytes() == src.read_bytes()
    assert oct(dest.stat().st_mode & 0o777) == "0o600"


def test_a_copy_that_lands_short_is_an_error(tmp_path):
    src = tmp_path / "payload.bin"
    src.write_bytes(b"x" * 1000)

    class Truncating(CommandDut):
        def _run(self, cmd, stdin=None, text=True, timeout=None):
            if stdin is not None:
                stdin = stdin[:100]          # a transport that does not forward all of stdin
            return super()._run(cmd, stdin=stdin, text=text, timeout=timeout)

    dut = Truncating("here", ["sh", "-c"], sudo=False)
    with pytest.raises(TransportError, match="landed"):
        dut.copy(src=str(src), dest=str(tmp_path / "short.bin"))


def test_a_missing_client_is_a_clear_error():
    with pytest.raises(TransportError, match="cannot run"):
        CommandDut("x", ["/nonexistent/ssh-client"], sudo=False).shell("true")


def test_a_timeout_is_an_answer_not_an_exception():
    """Review #6: shell(module_ignore_errors=True) and shell_raw are documented never to raise."""
    dut = LocalDut("here", sudo=False, timeout=1)
    res = dut.shell("sleep 5", module_ignore_errors=True)
    assert res["rc"] == 124 and "timed out after 1s" in res["stderr"]
    assert dut.shell_raw("sleep 5")["rc"] == 124
    with pytest.raises(TransportError, match="rc=124"):
        dut.shell("sleep 5")
