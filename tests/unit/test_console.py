"""The console server: structured runs only, a token when it is reachable, a real dry run end to end."""
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from sonic_chaos.console import server


@pytest.fixture
def console(tmp_path, monkeypatch):
    monkeypatch.setitem(server.CONFIG, "duts", [server.dut_from_arg("cmd:false")])
    monkeypatch.setitem(server.CONFIG, "workdir", str(tmp_path))
    monkeypatch.setitem(server.CONFIG, "token", None)
    monkeypatch.setitem(server.CONFIG, "sonic_mgmt", None)
    monkeypatch.setitem(server.CONFIG, "hosts", {"127.0.0.1", "localhost", "::1"})
    monkeypatch.setattr(server, "site_duts", lambda: [])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:{}".format(srv.server_address[1])
    srv.shutdown()
    server.RUNS.clear()


def call(base, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers=dict(headers or {}, **(
        {"Content-Type": "application/json"} if data else {})))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


# ------------------------------------------------------------------------------ build_argv

def test_a_flags_request_becomes_a_fixed_argv(console):
    argv, cwd, host = server.build_argv({"dut": "false", "specs": ["kill=orchagent"], "seed": 7,
                                         "repeat": 3, "dry_run": True, "invariants": ["parity"]})
    assert argv[1:5] == ["-m", "sonic_chaos", "run", "--dut=cmd:false"]
    assert argv[5:] == ["--chaos=kill=orchagent", "--chaos-seed=7", "--chaos-repeat=3", "--chaos-dry-run",
                        "--invariant=parity"]
    assert host == "false"


def test_baseline_is_passed_to_the_standalone_runner(console):
    argv, _cwd, _host = server.build_argv({"dut": "false", "specs": ["kill=orchagent"], "baseline": True})
    assert argv[-1] == "--baseline"


@pytest.mark.parametrize("body, why", [
    ({"dut": "nosuch", "specs": ["kill=orchagent"]}, "unknown switch"),
    ({"dut": "false", "specs": ["kill=orchagent; rm -rf /"]}, ""),
    ({"dut": "false", "specs": []}, "no fault"),
    ({"dut": "false", "specs": "kill=orchagent"}, "list"),
    ({"dut": "false", "specs": ["kill=orchagent"], "seed": "x"}, "integer"),
    ({"dut": "false", "specs": ["kill=orchagent"], "invariants": ["made_up"]}, "unknown invariant"),
    ({"dut": "false", "mode": "file", "yaml": "experiment: x\n"}, "experiment rejected"),
    ({"dut": "false", "mode": "shell", "specs": ["kill=orchagent"]}, "mode"),
    ({"dut": "false", "specs": ["kill=orchagent"], "runner": "sonic-mgmt", "tests": ["x.py"]}, "--sonic-mgmt"),
])
def test_bad_requests_are_refused(console, body, why):
    with pytest.raises(server.BadRequest, match=why):
        server.build_argv(body)


def test_test_paths_cannot_leave_the_checkout(console, tmp_path, monkeypatch):
    (tmp_path / "tests").mkdir()
    monkeypatch.setitem(server.CONFIG, "sonic_mgmt", str(tmp_path))
    for bad in (["../../etc/passwd"], ["/etc/passwd"], ["x.py; id"], ["-p", "evil"], ["--rootdir=/"],
                ["x.py", "-o", "addopts=-p evil"]):
        with pytest.raises(server.BadRequest, match="tests must be paths"):
            server.build_argv({"dut": "false", "specs": ["kill=orchagent"], "runner": "sonic-mgmt", "tests": bad})
    argv, cwd, _ = server.build_argv({"dut": "false", "specs": ["kill=orchagent"], "runner": "sonic-mgmt",
                                      "tests": ["platform_tests/test_port_toggle.py"]})
    assert argv[1:4] == ["-m", "pytest", "platform_tests/test_port_toggle.py"] and cwd.endswith("/tests")


def test_an_experiment_is_written_where_the_server_chooses(console, tmp_path):
    yaml_text = "experiment: x\nfaults:\n  - kill: {process: orchagent}\n"
    argv, _cwd, _ = server.build_argv({"dut": "false", "mode": "file", "yaml": yaml_text})
    path = next(a for a in argv if a.startswith("--chaos-file=")).split("=", 1)[1]
    assert path.startswith(str(tmp_path)) and open(path).read() == yaml_text


# ------------------------------------------------------------------------------ over HTTP

def test_the_page_and_catalogue_are_served(console):
    assert call(console, "/")[0] == 200
    status, body = call(console, "/api/plugin")
    assert status == 200 and "kill" in json.loads(body)["injectors"]
    status, body = call(console, "/api/duts")
    assert json.loads(body) == [{"host": "false", "hwsku": "", "topo": "cmd:false"}], "URLs stay server-side"


def test_a_raw_command_is_refused(console):
    status, body = call(console, "/api/run", {"cmd": "id > /tmp/pwned", "dut": "false"})
    assert status == 400 and "no fault given" in body


def test_a_dry_run_streams_to_exit_zero(console):
    status, body = call(console, "/api/run", {"dut": "false", "specs": ["kill=orchagent"], "dry_run": True})
    assert status == 200, body
    run_id = json.loads(body)["id"]
    with urllib.request.urlopen(console + "/api/stream?id=" + run_id, timeout=60) as resp:
        stream = resp.read().decode()
    assert "dry run complete; nothing applied" in stream
    assert 'event: exit\ndata: {"code": 0}' in stream


def test_the_token_is_enforced(console, monkeypatch):
    monkeypatch.setitem(server.CONFIG, "token", "s3cret")
    assert call(console, "/api/health")[0] == 401
    assert call(console, "/api/health", headers={"X-Chaos-Token": "wrong"})[0] == 401
    assert call(console, "/api/health", headers={"X-Chaos-Token": "s3cret"})[0] == 200
    assert call(console, "/api/run", {"dut": "false", "specs": ["kill=orchagent"]})[0] == 401
    req = urllib.request.Request(console + "/?token=s3cret")
    with urllib.request.urlopen(req, timeout=10) as resp:
        cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert call(console, "/api/health", headers={"Cookie": cookie.split(";")[0]})[0] == 200


def raw(base, path, data, headers):
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


RUN = json.dumps({"dut": "false", "specs": ["kill=orchagent"], "dry_run": True}).encode()


def test_a_cross_site_text_plain_post_is_refused(console):
    """Review #2: a page elsewhere can POST text/plain with no preflight; the console refuses it."""
    status, body = raw(console, "/api/run", RUN, {"Content-Type": "text/plain"})
    assert status == 415 and "application/json" in body
    assert server.RUNS == {}, "nothing may start"


def test_a_foreign_origin_is_refused(console):
    status, body = raw(console, "/api/run", RUN, {"Content-Type": "application/json",
                                                  "Origin": "https://evil.example"})
    assert status == 403 and "cross-origin" in body and server.RUNS == {}


def test_a_rebinding_host_is_refused_on_loopback(console):
    port = console.rsplit(":", 1)[1]
    status, body = raw(console, "/api/health", None, {"Host": "evil.example:" + port})
    assert status == 403 and "--allow-host" in body


def test_the_same_origin_page_is_allowed(console):
    host = console.split("//", 1)[1]
    status, _ = raw(console, "/api/run", RUN, {"Content-Type": "application/json", "Origin": "http://" + host})
    assert status == 200


def test_a_token_is_generated_unless_turned_off(tmp_path, monkeypatch):
    for key in ("token", "hosts", "duts", "workdir", "sonic_mgmt"):
        monkeypatch.setitem(server.CONFIG, key, server.CONFIG[key])
    monkeypatch.delenv("SONIC_CHAOS_CONSOLE_TOKEN", raising=False)
    server.configure(["--workdir", str(tmp_path)])
    assert server.CONFIG["token"] and len(server.CONFIG["token"]) >= 20
    server.configure(["--workdir", str(tmp_path), "--no-token"])
    assert server.CONFIG["token"] is None
    with pytest.raises(SystemExit):
        server.configure(["--workdir", str(tmp_path), "--no-token", "--host", "0.0.0.0"])
    server.configure(["--workdir", str(tmp_path), "--host", "0.0.0.0"])
    assert server.CONFIG["token"] and server.CONFIG["hosts"] is None, "network binds: the token is the lock"
    assert server._is_loopback("127.0.0.1") and server._is_loopback("::1") and not server._is_loopback("10.1.2.3")
