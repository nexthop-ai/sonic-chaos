"""The sonic-chaos web console: build a fault or an experiment, run it, stream the verdict.

    sonic-chaos console                                    http://127.0.0.1:8811/
    sonic-chaos console --dut ssh://admin@10.0.0.5         offer this switch in the page
    sonic-chaos console --host 0.0.0.0                     reachable from the lab (the token is the lock)

Every console has a token, generated at start unless --token gives one, and prints its link with
it. The page carries it as an HttpOnly, SameSite=Strict cookie. On top of that, a POST must be
application/json (a cross-site form or text/plain POST cannot be, without a CORS preflight the
console never answers), an Origin header must match the Host, and on a loopback bind the Host must
be a name this console answers to, so a page served from elsewhere cannot reach it by DNS rebinding.
--no-token turns the token off, on a loopback bind only.
    sonic-chaos console --sonic-mgmt ~/sonic-mgmt          also offer pytest runs in that checkout

A run is a structured request, never a command line: the server turns it into a fixed argument
list for ``sonic-chaos run`` (or for pytest inside ``--sonic-mgmt``) and runs that with no shell.
Every argument is validated first -- specs by the plugin's own validators, the switch against
the DUTs this console offers -- so the page cannot run anything else on this machine.

Endpoints
    GET  /                 the console page (?token=... sets the session cookie)
    GET  /api/health       {ok, version, runners, active_run}
    GET  /api/duts         the switches this console offers
    GET  /api/plugin       injectors, their parameters and capabilities, targets, invariants
    GET  /api/baseline     read-only box state before a run: image, routes, CRM, cgroup caps
    POST /api/validate     {specs:[...]} -> what the plugin's validators say about each
    POST /api/run          a RunRequest (see ``build_argv``) -> {id, argv}
    GET  /api/stream?id=   server-sent events: ``line`` per output line, ``exit`` with the code
    POST /api/stop         {id}; SIGINT, so the runner releases every applied fault

DUTs come from ``--dut`` and from site packages: an entry point in ``sonic_chaos.console_duts``
returning ``[{host, url, hwsku?, topo?}]``.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import metadata
from urllib.parse import parse_qs, urlparse

from .. import __version__

HERE = os.path.dirname(os.path.abspath(__file__))
# The directory holding the sonic_chaos package this server runs from. Runs are started as
# `python -m sonic_chaos`, and must load this same copy even when it is a checkout, not an install.
PACKAGE_PARENT = os.path.dirname(os.path.dirname(HERE))
RUNS = {}          # id -> Run
RUNS_LOCK = threading.Lock()
CONFIG = {"token": None, "sonic_mgmt": None, "duts": [], "workdir": None,
          "hosts": {"127.0.0.1", "localhost", "::1"}}   # names the Host header may carry
COOKIE = "sonic_chaos_token"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class Run(object):
    def __init__(self, argv, cwd, dut):
        self.id = uuid.uuid4().hex[:8]
        self.argv = argv
        self.cwd = cwd
        self.dut = dut
        self.lines = []            # history for late subscribers
        self.subs = []             # queues
        self.code = None
        self.proc = None
        self.lock = threading.Lock()

    @property
    def cmd(self):
        return " ".join(self.argv)

    def start(self):
        self.proc = subprocess.Popen(
            self.argv, cwd=self.cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True,
            env=dict(os.environ, PYTHONUNBUFFERED="1", TERM="dumb", PYTHONPATH=os.pathsep.join(
                p for p in (PACKAGE_PARENT, os.environ.get("PYTHONPATH", "")) if p)))
        threading.Thread(target=self._pump, daemon=True).start()
        return self

    def _pump(self):
        for line in self.proc.stdout:
            self._emit("line", line.rstrip("\n"))
        self.code = self.proc.wait()
        self._emit("exit", {"code": self.code})

    def _emit(self, event, data):
        with self.lock:
            self.lines.append((event, data))
            for q in list(self.subs):
                q.put((event, data))

    def subscribe(self):
        q = queue.Queue()
        with self.lock:
            for item in self.lines:
                q.put(item)
            self.subs.append(q)
        return q

    def stop(self):
        if self.proc and self.proc.poll() is None:
            # SIGINT the whole group: the runner's finalizers release LIFO.
            os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
            self._emit("line", "[console] SIGINT sent; waiting for the runner to release faults")
            # A release can need a full consistency snapshot round trip (~40 s) before it even
            # starts thawing, so a short window could SIGKILL mid-thaw and leave a container paused.
            threading.Thread(target=self._force_after, args=(240,), daemon=True).start()

    def _force_after(self, seconds):
        time.sleep(seconds)
        if self.proc.poll() is None:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            self._emit("line", "[console] still alive after %ds; SIGKILL. Check the DUT for anything "
                               "left applied." % seconds)


# ------------------------------------------------------------------------------------ the catalogue

_AGENT = {"loaded": False}


def agent():
    """What the installed sonic-chaos accepts, read from the package itself.

    The page checks its own copy against this, so a rename in the package shows up as a warning
    in the browser instead of a spec the runner refuses.
    """
    if _AGENT["loaded"]:
        return _AGENT
    _AGENT["loaded"] = True
    try:
        from .. import injectors  # noqa: F401  registers the built-ins
        from .. import oracle
        from ..injector import REGISTRY, targets
        from ..plugins import load_entry_points
        load_entry_points()
        _AGENT["injectors"] = {
            name: {"lane": getattr(cls, "lane", ""),
                   "positional": list(getattr(cls, "positional", ())),
                   "defaults": dict(getattr(cls, "defaults", {}) or {}),
                   "choices": {k: list(v) for k, v in vars(cls).items()
                               if k.isupper() and isinstance(v, (list, tuple))},
                   # {field: {available: [...], unavailable: {option: reason}}} -- what will
                   # refuse at apply time, which validate() cannot say. The page greys these.
                   "capabilities": dict(getattr(cls, "CAPABILITIES", {}) or {})}
            for name, cls in REGISTRY.items()}
        _AGENT["targets"] = targets()
        _AGENT["invariants"] = sorted(oracle.INVARIANTS)
        _AGENT["groups"] = list(oracle.GROUPS)
        _AGENT["invariant_group"] = dict(oracle.INVARIANT_GROUP)
        _AGENT["ok"] = True
    except Exception as err:
        _AGENT["ok"] = False
        _AGENT["error"] = "{}: {}".format(type(err).__name__, err)
    return _AGENT


# ------------------------------------------------------------------------------------ switches

def site_duts():
    out = []
    for ep in metadata.entry_points(group="sonic_chaos.console_duts"):
        try:
            out.extend(ep.load()() or [])
        except Exception as err:
            print("[console] DUT source {} failed: {!r}".format(ep.name, err))
    return out


def duts():
    """Every switch this console offers: ``--dut`` first, then site sources. Keyed by ``host``."""
    seen, out = set(), []
    for entry in list(CONFIG["duts"]) + site_duts():
        host = entry.get("host")
        if host and host not in seen and NAME_RE.match(host):
            seen.add(host)
            out.append({"host": host, "url": entry["url"], "hwsku": entry.get("hwsku", ""),
                        "topo": entry.get("topo", "")})
    return out


def dut_entry(host):
    return next((d for d in duts() if d["host"] == host), None)


def dut_from_arg(url):
    """``--dut ssh://admin@10.0.0.5`` -> an offered switch named after its host."""
    from ..transport import open_dut
    dut = open_dut(url)
    host = re.sub(r"[^A-Za-z0-9._-]", "-", dut.hostname)[:64]
    return {"host": host, "url": url, "topo": url}


# ------------------------------------------------------------------------------------ baseline

BASELINE_SCRIPT = r"""
S=/sys/fs/cgroup/system.slice/docker-$(docker inspect --format '{{.Id}}' CONTAINER 2>/dev/null).scope
echo IMAGE=$(sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version 2>/dev/null)
echo HWSKU=$(sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku 2>/dev/null)
echo UPTIME=$(cut -d' ' -f1 /proc/uptime)
echo ROUTES=$(sonic-db-cli ASIC_DB KEYS '*ROUTE_ENTRY*' 2>/dev/null | grep -c .)
echo BGP=$(vtysh -c 'show ip bgp summary' 2>/dev/null | grep -c ' 4 ')
echo CPUMAX=$(cat $S/cpu.max 2>/dev/null)
echo MEMMAX=$(cat $S/memory.max 2>/dev/null)
echo MEMCUR=$(cat $S/memory.current 2>/dev/null)
a=$(awk '/^usage_usec/{print $2}' $S/cpu.stat 2>/dev/null); sleep 2
b=$(awk '/^usage_usec/{print $2}' $S/cpu.stat 2>/dev/null)
echo CPUPCT=$(( (${b:-0}-${a:-0}) / 20000 ))
echo CRMPOLL=$(crm show summary 2>/dev/null | grep -oE '[0-9]+' | head -1)
echo CRM_BEGIN
crm show resources all 2>/dev/null
echo CRM_END
"""


def parse_baseline(out):
    fields, crm, in_crm = {}, {"main": {}, "acl_entry": None}, False
    for line in out.splitlines():
        if line.strip() == "CRM_BEGIN":
            in_crm = True
            continue
        if line.strip() == "CRM_END":
            in_crm = False
            continue
        if in_crm:
            parts = line.split()
            if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                crm["main"][parts[0]] = {"used": int(parts[1]), "available": int(parts[2])}
            elif len(parts) == 4 and parts[1] == "acl_entry" and parts[2].isdigit():
                cur = crm["acl_entry"] or {"used": 0, "available": 0}
                crm["acl_entry"] = {"used": cur["used"] + int(parts[2]),
                                    "available": cur["available"] + int(parts[3])}
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            fields[k.strip()] = v.strip()
    mem_cur = int(fields.get("MEMCUR") or 0)
    return {"image": fields.get("IMAGE", ""), "hwsku": fields.get("HWSKU", ""),
            "uptime_s": float(fields.get("UPTIME") or 0),
            "routes": int(fields.get("ROUTES") or 0), "bgp_peers": int(fields.get("BGP") or 0),
            "cpu_max": fields.get("CPUMAX", ""), "cpu_pct": int(fields.get("CPUPCT") or 0),
            "memory_max": fields.get("MEMMAX", ""), "memory_mb": round(mem_cur / 1048576.0, 1),
            "crm_poll_s": int(fields.get("CRMPOLL") or 0), "crm": crm}


def baseline(host, container):
    """Read-only box state before a run, in one session.

    Whether a repro means anything depends on what the box is: 102k routes on one testbed and 790
    on another is the difference between a valid table-pressure attempt and a meaningless one.
    Memory limits are read from the kernel knobs (memory.max), never docker's HostConfig, which
    goes stale after a release.
    """
    entry = dut_entry(host)
    if entry is None:
        return {"ok": False, "error": "unknown switch {!r}".format(host)}
    from ..transport import open_dut
    try:
        res = open_dut(entry["url"]).shell(BASELINE_SCRIPT.replace("CONTAINER", container),
                                           module_ignore_errors=True)
    except Exception as err:
        return {"ok": False, "error": "{}: {}".format(type(err).__name__, err)}
    out = res.get("stdout") or ""
    if res.get("rc") and not out.strip():
        return {"ok": False, "error": (res.get("stderr") or "no answer").strip()[:300]}
    return dict(parse_baseline(out), ok=True, dut=host, container=container, sampled_at=time.time())


# ------------------------------------------------------------------------------------ runs

class BadRequest(ValueError):
    pass


class Refused(Exception):
    def __init__(self, code, message):
        super(Refused, self).__init__(message)
        self.code = code


def runners():
    """Which runners this console can start. ``sonic-mgmt`` needs a checkout and pytest in it."""
    out = {"standalone": True, "sonic-mgmt": False}
    root = CONFIG["sonic_mgmt"]
    if root and os.path.isdir(os.path.join(root, "tests")):
        try:
            rc = subprocess.run([sys.executable, "-m", "pytest", "--version"], cwd=os.path.join(root, "tests"),
                                capture_output=True, timeout=30).returncode
            out["sonic-mgmt"] = rc == 0
        except Exception:
            pass
    return out


def _validate_specs(specs):
    from .. import injectors  # noqa: F401  registers the built-ins
    from ..injector import ChaosPlan, ChaosUsageError
    if not isinstance(specs, list) or not all(isinstance(s, str) for s in specs) or len(specs) > 32:
        raise BadRequest("specs must be a list of at most 32 strings")
    try:
        plan = ChaosPlan.from_args(specs)
        for inj in plan.injectors:
            inj.validate()
    except ChaosUsageError as err:
        raise BadRequest(str(err))
    return specs


def _write_yaml(text):
    from .. import injectors  # noqa: F401  registers the built-ins
    from ..experiment import Experiment
    import yaml
    from ..injector import ChaosUsageError
    if not isinstance(text, str) or len(text) > 256 * 1024:
        raise BadRequest("yaml must be a string under 256 KiB")
    try:
        raw = yaml.safe_load(text)
        if not isinstance(raw, dict):
            raise BadRequest("the experiment must be a mapping")
        Experiment.from_dict(raw)
    except (yaml.YAMLError, ChaosUsageError) as err:
        raise BadRequest("experiment rejected: {}".format(err))
    path = os.path.join(CONFIG["workdir"], "experiments", "ui-{}.yml".format(uuid.uuid4().hex[:8]))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


def _int(body, key, default, lo, hi):
    value = body.get(key, default)
    if value is None or value == "":
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise BadRequest("{} must be an integer".format(key))
    if not lo <= value <= hi:
        raise BadRequest("{} must be between {} and {}".format(key, lo, hi))
    return value


def build_argv(body):
    """A RunRequest -> ``(argv, cwd, host)``. Everything is validated; nothing reaches a shell.

        {"dut": "<host offered by /api/duts>",
         "mode": "flags" | "file",
         "specs": ["kill=orchagent", ...],          # mode=flags
         "yaml": "<experiment YAML>",               # mode=file
         "seed": 20260911, "repeat": 1, "dry_run": false,
         "baseline": false,                         # runner=standalone: ignore pre-existing divergences
         "invariants": ["parity"],                  # mode=flags: groups or names
         "runner": "standalone" | "sonic-mgmt",
         "tests": ["platform_tests/test_port_toggle.py"]}   # runner=sonic-mgmt
    """
    if not isinstance(body, dict):
        raise BadRequest("expected a JSON object")
    host = body.get("dut") or ""
    entry = dut_entry(host)
    if entry is None:
        raise BadRequest("unknown switch {!r}; this console offers: {}".format(
            host, ", ".join(d["host"] for d in duts()) or "none (start it with --dut)"))
    mode = body.get("mode", "flags")
    runner = body.get("runner", "standalone")
    seed = _int(body, "seed", None, 0, 2 ** 63)
    repeat = _int(body, "repeat", 1, 1, 1000)
    dry = bool(body.get("dry_run"))

    chaos = []
    if mode == "flags":
        chaos = ["--chaos=" + s for s in _validate_specs(body.get("specs") or [])]
        if not chaos:
            raise BadRequest("no fault given")
    elif mode == "file":
        chaos = ["--chaos-file=" + _write_yaml(body.get("yaml"))]
    else:
        raise BadRequest("mode must be flags or file")
    if seed is not None:
        chaos.append("--chaos-seed={}".format(seed))
    if repeat and repeat > 1:
        chaos.append("--chaos-repeat={}".format(repeat))
    if dry:
        chaos.append("--chaos-dry-run")

    if runner == "standalone":
        argv = [sys.executable, "-m", "sonic_chaos", "run", "--dut=" + entry["url"]] + chaos
        if body.get("baseline"):
            argv.append("--baseline")
        if mode == "flags":
            from .. import oracle
            for item in body.get("invariants") or []:
                if not isinstance(item, str):
                    raise BadRequest("invariants must be strings")
                try:
                    oracle.resolve(item)
                except ValueError as err:
                    raise BadRequest(str(err))
                argv.append("--invariant=" + item)
        return argv, CONFIG["workdir"], host
    if runner == "sonic-mgmt":
        root = CONFIG["sonic_mgmt"]
        if not root:
            raise BadRequest("this console was started without --sonic-mgmt")
        tests = body.get("tests") or []
        # A leading "-" would reach pytest as an option (-p, --rootdir, ...), not as a test path.
        if not tests or not all(isinstance(t, str) and re.match(r"^[A-Za-z0-9_][A-Za-z0-9_./:\[\]-]{0,199}$", t)
                                and ".." not in t for t in tests):
            raise BadRequest("tests must be paths inside the sonic-mgmt tests directory")
        argv = [sys.executable, "-m", "pytest"] + tests + [
            "--inventory=../ansible/inventory", "--host-pattern=" + host, "--testbed=" + host,
            "--testbed_file=../ansible/testbed.yaml", "--log-cli-level=info"] + chaos
        return argv, os.path.join(root, "tests"), host
    raise BadRequest("runner must be standalone or sonic-mgmt")


def active_runs():
    return [r for r in RUNS.values() if r.code is None]


def health():
    live = active_runs()
    return {"ok": True, "version": __version__, "agent": agent().get("ok", False), "runners": runners(),
            "auth": bool(CONFIG["token"]), "active_run": live[0].id if live else None,
            "active_cmd": live[0].cmd if live else None}


# ------------------------------------------------------------------------------------ http

class Handler(BaseHTTPRequestHandler):
    server_version = "sonic-chaos-console/" + __version__

    def _json(self, code, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise Refused(415, "POST bodies must be application/json")
        n = int(self.headers.get("Content-Length") or 0)
        if n > 512 * 1024:
            raise BadRequest("request too large")
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise BadRequest("body is not JSON")

    def log_message(self, fmt, *args):
        if "/api/stream" in (args[0] if args else ""):
            return
        BaseHTTPRequestHandler.log_message(self, fmt, *args)

    def _presented_token(self, query):
        if self.headers.get("X-Chaos-Token"):
            return self.headers.get("X-Chaos-Token")
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return (query.get("token") or [""])[0]

    def _authorized(self, query):
        want = CONFIG["token"]
        if not want:
            return True
        return hmac.compare_digest(self._presented_token(query) or "", want)

    def _refuse(self):
        self._json(401, {"ok": False, "error": "this console needs its token: open it as /?token=<token>"})

    def _same_site(self):
        """Refuse a request that did not come from this console's own page.

        Host must be a name this console answers to (DNS rebinding points a hostile name at
        127.0.0.1 and would otherwise pass), and a browser's Origin, when sent, must be that Host.
        """
        host = self.headers.get("Host") or ""
        name = urlparse("//" + host).hostname or ""
        if CONFIG["hosts"] is not None and name not in CONFIG["hosts"]:
            return "Host {!r} is not a name this console answers to (add it with --allow-host)".format(host)
        origin = self.headers.get("Origin")
        if origin is not None and urlparse(origin).netloc != host:
            return "cross-origin request from {} refused".format(origin)
        return None

    def _gate(self, query):
        why = self._same_site()
        if why:
            self._json(403, {"ok": False, "error": why})
            return False
        if not self._authorized(query):
            self._refuse()
            return False
        return True

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if not self._gate(query):
            return
        if url.path in ("/", "/index.html"):
            return self._page(query)
        if url.path == "/api/health":
            return self._json(200, health())
        if url.path == "/api/duts":
            return self._json(200, [{k: v for k, v in d.items() if k != "url"} for d in duts()])
        if url.path == "/api/plugin":
            info = dict(agent())
            info.pop("loaded", None)
            return self._json(200, info)
        if url.path == "/api/baseline":
            host = (query.get("dut") or [""])[0].strip()
            if not NAME_RE.match(host):
                return self._json(400, {"ok": False, "error": "dut required"})
            # Never probe a switch a run is working on: a second session mid-apply can disturb it,
            # and a read taken while a fault is landing is not a baseline.
            if any(r.dut == host for r in active_runs()):
                return self._json(409, {"ok": False, "error": "a run is active on {}; the box state would "
                                        "not be a baseline and the probe could disturb the run".format(host)})
            container = (query.get("container") or ["swss"])[0].strip()
            if not re.match(r"^[A-Za-z0-9_-]{1,40}$", container):
                container = "swss"
            return self._json(200, baseline(host, container))
        if url.path == "/api/stream":
            return self._stream((query.get("id") or [""])[0])
        return self._json(404, {"error": "not found"})

    def _page(self, query):
        with open(os.path.join(HERE, "index.html"), "rb") as fh:
            body = fh.read()
        # Revalidate every time; the ETag keeps an unchanged page to a 304.
        etag = '"%s"' % hashlib.sha1(body).hexdigest()[:16]
        cookie = []
        if CONFIG["token"] and (query.get("token") or [""])[0]:
            cookie = [("Set-Cookie", "{}={}; HttpOnly; SameSite=Strict; Path=/".format(COOKIE, CONFIG["token"]))]
        if self.headers.get("If-None-Match") == etag and not cookie:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        self.send_header("ETag", etag)
        for k, v in cookie:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _stream(self, run_id):
        run = RUNS.get(run_id)
        if not run:
            return self._json(404, {"error": "no such run"})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        q = run.subscribe()
        try:
            while True:
                try:
                    event, data = q.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                self.wfile.write(("event: %s\ndata: %s\n\n" % (event, json.dumps(data))).encode())
                self.wfile.flush()
                if event == "exit":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        url = urlparse(self.path)
        if not self._gate(parse_qs(url.query)):
            return
        try:
            body = self._body()
            if url.path == "/api/validate":
                return self._validate(body)
            if url.path == "/api/run":
                return self._run(body)
            if url.path == "/api/stop":
                return self._stop(body)
        except Refused as err:
            return self._json(err.code, {"ok": False, "error": str(err)})
        except BadRequest as err:
            return self._json(400, {"ok": False, "error": str(err)})
        return self._json(404, {"error": "not found"})

    def _validate(self, body):
        specs = (body.get("specs") or [])[:64]
        info = agent()
        if not info.get("ok"):
            return self._json(200, {"ok": False, "error": info.get("error"), "results": []})
        out = []
        for spec in specs:
            try:
                _validate_specs([spec])
                out.append({"spec": spec, "ok": True})
            except BadRequest as err:
                out.append({"spec": spec, "ok": False, "error": str(err)})
            except Exception as err:   # a bad spec must never take the console down
                out.append({"spec": spec, "ok": False, "error": "{}: {}".format(type(err).__name__, err)})
        return self._json(200, {"ok": True, "results": out})

    def _run(self, body):
        argv, cwd, host = build_argv(body)
        with RUNS_LOCK:
            active = active_runs()
            if active:
                return self._json(409, {"ok": False, "error": "run {} is still active ({}); stop it first".format(
                    active[0].id, active[0].cmd[:120])})
            run = Run(argv, cwd, host).start()
            RUNS[run.id] = run
        print("[console] run %s on %s\n          %s" % (run.id, host, run.cmd))
        return self._json(200, {"ok": True, "id": run.id, "argv": argv})

    def _stop(self, body):
        asked = body.get("id", "")
        run = RUNS.get(asked)
        # A stale id must never silently stop nothing: fall back to whatever is live, so a Stop
        # from any page (or a second tab) always reaches the run that holds the faults.
        targets = [run] if run and run.code is None else active_runs()
        if not targets:
            return self._json(200, {"ok": True, "stopped": [], "note": "nothing was running"})
        for r in targets:
            r.stop()
        return self._json(200, {"ok": True, "stopped": [r.id for r in targets],
                                "asked": asked, "fell_back": bool(run is None or run.code is not None)})


def _is_loopback(host):
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def configure(argv=None):
    """Parse the command line into CONFIG. Returns the parsed args."""
    ap = argparse.ArgumentParser(prog="sonic-chaos console", description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8811)
    ap.add_argument("--token", default=os.environ.get("SONIC_CHAOS_CONSOLE_TOKEN"),
                    help="the token every request must carry (default: $SONIC_CHAOS_CONSOLE_TOKEN, "
                         "else a random one, printed in the link)")
    ap.add_argument("--no-token", action="store_true",
                    help="no token at all; only on a loopback bind, and only if you trust every local user")
    ap.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                    help="another name the console may be reached by (Host header); repeatable")
    ap.add_argument("--dut", action="append", default=[], metavar="URL", help="offer this switch; repeatable")
    ap.add_argument("--sonic-mgmt", metavar="DIR", help="a sonic-mgmt checkout: enables pytest runs in it")
    ap.add_argument("--workdir", default=os.path.join("out", "console"),
                    help="where runs start and experiment files and bundles go (default: out/console)")
    args = ap.parse_args(argv)

    if args.no_token:
        if not _is_loopback(args.host):
            ap.error("--no-token is only allowed on a loopback --host; {} is reachable from the network"
                     .format(args.host))
        args.token = None
    elif not args.token or args.token == "generate":
        args.token = secrets.token_urlsafe(18)
    CONFIG["token"] = args.token
    # On loopback the Host allowlist is what stops DNS rebinding. On a network bind the token is
    # mandatory and a rebinding page cannot know it, so any name the lab reaches the box by is fine,
    # unless --allow-host narrows it.
    if _is_loopback(args.host) or args.allow_host:
        CONFIG["hosts"] = {"127.0.0.1", "localhost", "::1"} | set(args.allow_host)
    else:
        CONFIG["hosts"] = None
    CONFIG["sonic_mgmt"] = os.path.abspath(os.path.expanduser(args.sonic_mgmt)) if args.sonic_mgmt else None
    CONFIG["workdir"] = os.path.abspath(args.workdir)
    os.makedirs(CONFIG["workdir"], exist_ok=True)
    try:
        CONFIG["duts"] = [dut_from_arg(url) for url in args.dut]
    except ValueError as err:
        ap.error(str(err))
    return args


def main(argv=None):
    args = configure(argv)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    shown = "localhost" if _is_loopback(args.host) else args.host
    link = "http://{}:{}/".format(shown, args.port) + ("?token=" + args.token if args.token else "")
    print("sonic-chaos console {}  {}\n  switches: {}\n  work dir: {}".format(
        __version__, link, ", ".join(d["host"] for d in duts()) or "none (add --dut <url>)", CONFIG["workdir"]))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        for run in RUNS.values():
            run.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
