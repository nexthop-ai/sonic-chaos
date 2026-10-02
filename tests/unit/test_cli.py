"""The sonic-chaos command, end to end in-process. Nothing here reaches a real switch."""
import json

import pytest

from sonic_chaos import __version__, cli
from sonic_chaos.engine import runner


def test_version(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert capsys.readouterr().out.strip() == "sonic-chaos " + __version__


def test_list_injectors_names_all_twelve(capsys):
    assert cli.main(["list"]) == 0
    names = {line.split()[0] for line in capsys.readouterr().out.splitlines()}
    assert names >= {"kill", "pause", "corrupt", "redis", "syslog", "sai", "spin", "cpu", "mem", "hog",
                     "exhaust", "storm"}


def test_list_experiments_and_transports(capsys):
    assert cli.main(["list", "experiments"]) == 0
    assert "orchagent-restart" in capsys.readouterr().out
    assert cli.main(["list", "transports"]) == 0
    assert "ssh://user@host" in capsys.readouterr().out


def test_validate_accepts_and_refuses(capsys):
    assert cli.main(["validate", "kill=orchagent"]) == 0
    assert "kill(" in capsys.readouterr().out
    assert cli.main(["validate", "cpu=redis-server:10"]) == 2
    assert "protected" in capsys.readouterr().out


def test_schema_is_json(capsys):
    assert cli.main(["schema"]) == 0
    assert json.loads(capsys.readouterr().out)["title"] == "sonic-chaos experiment"


def test_selftest_passes(capsys):
    assert cli.main(["selftest"]) == 0
    assert "sonic-chaos contract OK" in capsys.readouterr().out


def test_run_dry_run_touches_nothing(capsys):
    # cmd:false would fail every command; a dry run must not issue one.
    rc = cli.main(["run", "--dut", "cmd:false", "--chaos", "kill=orchagent", "--chaos-dry-run"])
    assert rc == runner.EXIT_HELD
    assert "dry run complete; nothing applied" in capsys.readouterr().out


def test_run_a_shipped_experiment_by_name_dry(capsys):
    rc = cli.main(["run", "--dut", "cmd:false", "--chaos-file", "orchagent-restart", "--chaos-dry-run"])
    assert rc == runner.EXIT_HELD
    assert "orchagent-restart" in capsys.readouterr().out


def test_run_needs_a_switch(monkeypatch):
    monkeypatch.delenv("SONIC_CHAOS_DUT", raising=False)
    with pytest.raises(SystemExit) as err:
        cli.main(["run", "--chaos", "kill=orchagent"])
    assert err.value.code == 2


def test_run_refuses_a_bad_spec_before_connecting(capsys):
    rc = cli.main(["run", "--dut", "cmd:false", "--chaos", "cpu=orchagent:300"])
    assert rc == runner.EXIT_USAGE


def test_an_unknown_experiment_names_the_shipped_ones(capsys):
    rc = cli.main(["run", "--dut", "cmd:false", "--chaos-file", "no-such-thing"])
    assert rc == runner.EXIT_USAGE
    assert "orchagent-restart" in capsys.readouterr().out


def test_an_unknown_tool(capsys):
    assert cli.main(["tool", "nope"]) == 2
    assert "live-check" in capsys.readouterr().out
