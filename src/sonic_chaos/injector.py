"""Injector contract, spec grammar, registry, and the session that guarantees release.

An Injector is one configured fault: a name (``cpu``, ``sai``, ``kill``, ``corrupt``), a target,
and parameters bound from a CLI spec. Lanes implement ``apply`` / ``release`` / ``status``; the
harness owns *when* those run and guarantees release on every exit path.

Rules every injector honours
----------------------------
* **State faults** (cpu, sai, corrupt): ``apply`` is idempotent -- twice is the same as once --
  and ``release`` undoes it. **Event faults** (kill): ``apply`` fires once per call and
  ``release`` is a no-op, because recovery is the system's job and is the thing under test.
* ``release`` is safe to call twice and never raises for an already-released fault.
* Anything left on the box carries a TTL. A dropped SSH session must never strand a throttled switch.
* ``validate`` runs at configure time, so a typo fails before any DUT is touched.
* Nothing in this module imports pytest: the contract is testable without a session (see selftest.py).

Spec grammar
------------
    --chaos INJECTOR=SPEC
    SPEC   := token (':' token)*
    token  := positional | key '=' value
    A token wrapped in [...] is not split on ':' -- for redis keys that contain colons:
    --chaos corrupt=APPL_DB:[LAG_MEMBER_TABLE:PortChannel12:Ethernet48]:status=garbage
"""
import ast
import logging
import os
import re
import shlex
import time

import yaml

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
TARGETS_FILE = os.path.join(_HERE, "profiles", "default.yml")


class ChaosUsageError(ValueError):
    """Bad --chaos spec or target. Raised at configure time."""


# ----------------------------------------------------------------------------- spec grammar

def parse_chaos_arg(arg):
    """``"cpu=orchagent:30"`` -> ``("cpu", "orchagent:30")``."""
    if "=" not in arg:
        raise ChaosUsageError("expected INJECTOR=SPEC, got {!r}".format(arg))
    name, spec = arg.split("=", 1)
    return name.strip(), spec.strip()


def split_spec(spec):
    """``"route_entry:create:delay=2000"`` -> ``(["route_entry", "create"], {"delay": "2000"})``.

    Bare tokens are positional and mean whatever the injector's ``positional`` tuple says.
    ``key=value`` tokens are keyword params. Values stay strings; the injector coerces.
    """
    positional, kwargs = [], {}
    for tok in _tokens(spec):
        if "=" in tok:
            key, value = tok.split("=", 1)
            kwargs[key.strip()] = value.strip()
        elif kwargs:
            # Almost always this is a value containing colons that got split -- a MAC, an IPv6
            # address, a redis key. Say so, because "positional 'ad' after keyword params" is
            # true and useless when what you typed was neigh=de:ad:be:ef:00:01.
            raise ChaosUsageError(
                "positional {0!r} after keyword params in {1!r}. If a value contains ':' "
                "(a MAC, an IPv6 address, a redis key), wrap it in [...] so it is not split: "
                "key=[{0}...]".format(tok, spec))
        else:
            positional.append(tok.strip())
    return positional, kwargs


def _tokens(spec):
    """Split on ':' outside [...] and strip the brackets."""
    out, buf, depth = [], [], 0
    for ch in spec:
        if ch == "[":
            depth += 1
        elif ch == "]":
            if depth == 0:
                raise ChaosUsageError("unbalanced ']' in {!r}".format(spec))
            depth -= 1
        elif ch == ":" and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if depth:
        raise ChaosUsageError("unbalanced '[' in {!r}".format(spec))
    out.append("".join(buf))
    return [t for t in out if t]


# ----------------------------------------------------------------------------- targets

_targets = None
_profile_names = []
PROFILE_ENV = "SONIC_CHAOS_PROFILE"


def set_profiles(names):
    """Overlay these profiles on the default, in order. Each is a YAML path or the name of a
    ``sonic_chaos.profiles`` entry point. ``SONIC_CHAOS_PROFILE`` (comma-separated) adds more."""
    global _targets
    _profile_names[:] = [n for n in names if n]
    _targets = None


def _load_profile(name):
    if os.path.isfile(name):
        with open(name) as fh:
            return yaml.safe_load(fh) or {}
    from importlib import metadata
    for ep in metadata.entry_points(group="sonic_chaos.profiles"):
        if ep.name == name:
            value = ep.load()
            value = value() if callable(value) else value
            if isinstance(value, dict):
                return value
            with open(value) as fh:
                return yaml.safe_load(fh) or {}
    raise ChaosUsageError("unknown profile {!r}: not a file and no installed package provides it".format(name))


def merge_profile(base, overlay):
    """``processes`` merge key by key; ``containers`` and ``protected`` are unions, base order first."""
    out = {"processes": dict(base.get("processes") or {}),
           "containers": list(base.get("containers") or []),
           "protected": list(base.get("protected") or [])}
    out["processes"].update(overlay.get("processes") or {})
    for key in ("containers", "protected"):
        out[key] += [x for x in overlay.get(key) or [] if x not in out[key]]
    return out


def targets():
    """The target profile as a dict: process -> container, whole containers, and the protected list.

    ``profiles/default.yml`` describes a community SONiC image; a platform's own profile is laid
    over it (see ``set_profiles``).
    """
    global _targets
    if _targets is None:
        with open(TARGETS_FILE) as fh:
            data = yaml.safe_load(fh) or {}
        names = list(_profile_names) + [n.strip() for n in os.environ.get(PROFILE_ENV, "").split(",") if n.strip()]
        for name in names:
            data = merge_profile(data, _load_profile(name))
        _targets = data
    return _targets


def resolve_container(process):
    """Process name -> container name. A whole-container name resolves to itself."""
    data = targets()
    if process in data.get("containers", []):
        return process
    try:
        return data["processes"][process]["container"]
    except KeyError:
        raise ChaosUsageError("unknown target {!r}; add it to {}".format(process, TARGETS_FILE))


def is_container(name):
    """Is ``name`` a whole container rather than a daemon inside one?

    The distinction decides what a fault can even mean: you can SIGSTOP a process and you can
    ``docker pause`` a container, and confusing the two produces a silent no-op -- ``pkill -x
    swss`` matches nothing at all, because no process is named after its container.
    """
    return name in targets().get("containers", [])


def is_protected(name):
    """Targets with no clean recovery path. Refused unless the caller passes ``force``."""
    return name in targets().get("protected", [])


def require_target(process, force=False, what="target"):
    """Resolve ``process`` to a container, refusing protected targets unless ``force``.

    ``redis-server`` and the ``database`` container really do cascade: supervisor health checks
    fail, containers restart, and there is no documented way back. That is worth testing on
    purpose and is on the fault list -- but it should never be what a random scheduler picks by
    accident, so it costs one explicit word::

        --chaos kill=redis-server:force=true
        faults: [{kill: {process: redis-server, force: true, tag: unsupported-op}}]

    Returns the container name.
    """
    if is_protected(process) and not force:
        raise ChaosUsageError(
            "{}: {!r} is protected -- it cascades with no clean recovery path. Pass force=true "
            "if you mean it, and tag the fault unsupported-op.".format(what, process))
    return resolve_container(process)


def as_bool(value, field):
    """YAML gives real booleans, the CLI gives strings. Accept both."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off", ""):
        return False
    raise ChaosUsageError("{}: expected a boolean, got {!r}".format(field, value))


def resolve_pid(duthost, process, container=None):
    """Host-side PID of ``process`` inside its container, via ``docker top``.

    Verified column layout on a lab switch (202511.2, Debian 13)::

        UID   PID     PPID    C  STIME  TTY    TIME      CMD
        root  109662  107468  0  06:12  pts/0  00:00:02  /usr/bin/orchagent -d /var/log/swss ...

    PID is field 2 and CMD runs from field 8 to end of line, so match the process name against
    the *command*, not the last field -- orchagent's argv ends in ``tcp://127.0.0.1``, which is
    what a naive ``$NF`` picks up.

    Returns None when the process is not running: callers re-poll rather than fail, because a
    restart mid-run is expected (Spine's kill injector causes exactly that).
    """
    container = container or resolve_container(process)
    cmd = ("docker top {} 2>/dev/null | awk 'NR>1 {{ cmd=\"\"; for (i=8; i<=NF; i++) cmd=cmd $i \" \"; "
           "if (cmd ~ /{}/) {{ print $2; exit }} }}'").format(container, process)
    res = duthost.shell(cmd, module_ignore_errors=True)
    out = (res.get("stdout") or "").strip()
    return int(out) if out.isdigit() else None


# ----------------------------------------------------------------------------- DUT-side helpers

DEADMAN_DIR = "/tmp/sonic-chaos"


def run(duthost, cmd, **kwargs):
    """``duthost.shell`` with errors ignored -> ``(rc, stdout, stderr)``. Never raises for a non-zero rc."""
    kwargs.setdefault("module_ignore_errors", True)
    res = duthost.shell(cmd, **kwargs) or {}
    rc = res.get("rc")
    return (int(rc) if rc is not None else 1), (res.get("stdout") or ""), (res.get("stderr") or "")


def quote(value):
    """Shell-quote one argument for a command that runs through ``/bin/sh -c`` on the DUT."""
    return shlex.quote(str(value))


_sudo_prefix = {}


def sudo_prefix(duthost):
    """``""`` when we already run as root on this DUT, ``"sudo -n "`` otherwise. Cached per host.

    Injecting a fault is root work -- cgroups, ``docker``, ``systemd-run``, ``supervisorctl``.
    Under pytest ``duthost.shell`` is already root and a bare ``sudo`` is merely redundant, but a
    standalone script over ssh lands as ``admin`` (uid 1000), where the same command
    fails with EACCES. Found exactly that way on a lab switch: the Squeeze agent worked in every
    dev-box test because those were run under sudo, and could not create a single cgroup on a
    real testbed.

    Prefer this over hardcoding ``sudo``: it stays correct in both contexts and costs one cached
    ``id -u`` per host.
    """
    host = getattr(duthost, "hostname", str(duthost))
    if host not in _sudo_prefix:
        res = duthost.shell("id -u", module_ignore_errors=True) or {}
        _sudo_prefix[host] = "" if (res.get("stdout") or "").strip() == "0" else "sudo -n "
    return _sudo_prefix[host]


def ensure_shared_dir(duthost):
    """Create ``DEADMAN_DIR`` so every lane can write in it, whatever user it runs as.

    Mode **1777**, like ``/tmp`` itself. Squeeze's agent needs root and creates the directory
    under sudo; Spine's dead-man writes the same directory as whatever user ``duthost.shell``
    happens to be. A root-owned 0755 directory silently breaks the second one with EACCES --
    found on a lab switch, where arming a dead-man failed with "Permission denied" only *after* a
    Squeeze run had been through first. The sticky bit stops one lane deleting another's files.
    """
    run(duthost, "{s}mkdir -p {d} && {s}chmod 1777 {d}".format(
        s=sudo_prefix(duthost), d=DEADMAN_DIR))


def deadman_tag(*parts):
    """A filename-safe tag for the dead-man timer, e.g. ``deadman_tag("pause", "swss", "orchagent")``."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", "-".join(str(p) for p in parts))


def arm_deadman(duthost, tag, seconds, commands):
    """Schedule ``commands`` on the DUT after ``seconds`` -- the last-resort release.

    The timer is a detached ``sh`` (``setsid`` + ``nohup``), so it survives our SSH session,
    the ansible connection, and the harness dying. ``disarm_deadman`` cancels it on the normal
    release path. Whatever the timer runs must be idempotent with the normal release, because
    both may run.

    Files live under ``/tmp/sonic-chaos`` on the DUT: ``<tag>.sh`` (the script), ``<tag>.pid``
    (the timer), ``<tag>.log`` (what the release printed, if it ever fired).
    """
    if isinstance(commands, str):
        commands = [commands]
    # The script cleans up after itself, leaving only its .log behind: a .log with no .pid next
    # to it is the record that the timer actually fired, which is worth finding later.
    body = "\n".join(["sleep {}".format(int(seconds))] + list(commands) +
                     ["rm -f {d}/{t}.pid {d}/{t}.sh".format(d=DEADMAN_DIR, t=tag)])
    ensure_shared_dir(duthost)
    script = ("mkdir -p {d} && cat > {d}/{t}.sh <<'CHAOS_EOF'\n{body}\nCHAOS_EOF\n"
              "nohup setsid sh {d}/{t}.sh >{d}/{t}.log 2>&1 </dev/null &\n"
              "echo $! > {d}/{t}.pid && cat {d}/{t}.pid").format(d=DEADMAN_DIR, t=tag, body=body)
    rc, out, err = run(duthost, script)
    if rc != 0:
        logger.warning("[chaos] could not arm dead-man %s on %s (rc=%s): %s", tag, duthost.hostname, rc,
                       (err or out).strip()[:200])
        return None
    pid = out.strip().splitlines()[-1] if out.strip() else ""
    logger.info("[chaos] dead-man %s armed on %s: fires in %ss (pid %s)", tag, duthost.hostname, seconds, pid)
    return int(pid) if pid.isdigit() else None


def disarm_deadman(duthost, tag):
    """Cancel the timer armed by ``arm_deadman``. Safe when it never existed or already fired.

    The timer is killed by *pid*, never by ``pkill -f <script path>``. ``duthost.shell`` runs the
    whole command through ``sh -c``, so that shell's own command line contains the script path --
    ``pkill -f`` matches the shell that is running the cleanup and kills it mid-command, before
    the ``rm`` ever happens. (Found exactly that way: release "succeeded" and left the armed
    timer on the box.) Killing the process *group* takes the sleep with it, since the timer was
    started under ``setsid``.
    """
    cmd = ("if [ -f {d}/{t}.pid ]; then p=$(cat {d}/{t}.pid); "
           "kill -- -\"$p\" 2>/dev/null; kill \"$p\" 2>/dev/null; fi; "
           "rm -f {d}/{t}.pid {d}/{t}.sh {d}/{t}.log; true").format(d=DEADMAN_DIR, t=tag)
    run(duthost, cmd)


def parse_hgetall(text):
    """``sonic-db-cli <db> HGETALL <key>`` output -> ``{field: value}``. ``{}`` for a missing key.

    ``sonic-db-cli`` prints a *Python dict repr*, not JSON::

        {'admin_status': 'up', 'lanes': '25,26,27,28', 'description': ''}

    so it is read with ``ast.literal_eval``. Raw ``redis-cli`` alternating field/value lines are
    accepted too, which is what you get when someone runs the command inside the database
    container. ``tests/common/helpers/sonic_db.py:redis_hgetall`` is the same parse; it is not
    imported here because this module must stay importable without the sonic-mgmt test runtime
    (see selftest.py).
    """
    out = (text or "").strip()
    if not out:
        return {}
    if out.startswith("{") and out.endswith("}"):
        try:
            parsed = ast.literal_eval(out.replace("\n", "\\n"))
        except (ValueError, SyntaxError):
            parsed = None
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    lines = out.split("\n")
    return {lines[i]: lines[i + 1] for i in range(0, len(lines) - 1, 2)}


def hgetall(duthost, db, key):
    """Read one hash off the DUT. ``{}`` when the key does not exist."""
    rc, out, _ = run(duthost, "sonic-db-cli {} HGETALL {}".format(db, quote(key)))
    return parse_hgetall(out) if rc == 0 else {}


def hset(duthost, db, key, fields):
    """Write ``{field: value}`` into one hash. Returns the command that was run."""
    pairs = " ".join("{} {}".format(quote(f), quote(v)) for f, v in sorted(fields.items()))
    cmd = "sonic-db-cli {} HSET {} {}".format(db, quote(key), pairs)
    run(duthost, cmd)
    return cmd


def hdel(duthost, db, key, fields):
    if not fields:
        return None
    cmd = "sonic-db-cli {} HDEL {} {}".format(db, quote(key), " ".join(quote(f) for f in sorted(fields)))
    run(duthost, cmd)
    return cmd


def delete_key(duthost, db, key):
    cmd = "sonic-db-cli {} DEL {}".format(db, quote(key))
    run(duthost, cmd)
    return cmd


_SUPERVISOR_LINE = re.compile(r"^(?P<name>\S+)\s+(?P<state>[A-Z]+)(?:\s+pid (?P<pid>\d+), uptime (?P<uptime>\S+))?")


def parse_supervisor_status(text):
    """``supervisorctl status`` output -> ``{name: {"state": ..., "pid": int|None, "uptime": str|None}}``.

        orchagent                        RUNNING   pid 46, uptime 0:12:34
        orchagent                        FATAL     Exited too quickly (process log may have details)
        orchagent                        STARTING
    """
    out = {}
    for line in (text or "").splitlines():
        m = _SUPERVISOR_LINE.match(line.strip())
        if not m:
            continue
        pid = m.group("pid")
        out[m.group("name")] = {"state": m.group("state"), "pid": int(pid) if pid else None,
                                "uptime": m.group("uptime"), "raw": line.strip()}
    return out


def supervisor_status(duthost, container, process=None):
    """One ``supervisorctl status`` round trip. ``process`` narrows to one entry (or ``{}`` if unknown)."""
    cmd = "docker exec {} supervisorctl status{}".format(container, " " + quote(process) if process else "")
    rc, out, err = run(duthost, cmd)
    parsed = parse_supervisor_status(out)
    if process:
        return parsed.get(process, {})
    return parsed


def container_running(duthost, container):
    rc, out, err = run(duthost, "docker inspect -f '{{{{.State.Running}}}}' {}".format(container))
    return rc == 0 and out.strip() == "true"


def poll(fn, timeout, interval=2, sleep=time.sleep):
    """Call ``fn()`` until it returns truthy or ``timeout`` seconds pass. Returns ``(result, elapsed)``."""
    start = time.time()
    while True:
        result = fn()
        elapsed = time.time() - start
        if result or elapsed >= timeout:
            return result, round(elapsed, 1)
        sleep(min(interval, max(0.0, timeout - elapsed)))


# ----------------------------------------------------------------------------- registry

REGISTRY = {}


def register(cls):
    """Class decorator. ``@register`` on an Injector subclass makes ``--chaos <cls.name>=...`` work."""
    if not cls.name:
        raise TypeError("{} must set a class attribute 'name'".format(cls.__name__))
    if cls.name in REGISTRY:
        raise TypeError("injector {!r} already registered by {}".format(cls.name, REGISTRY[cls.name].__name__))
    REGISTRY[cls.name] = cls
    return cls


def get(name):
    if name not in REGISTRY:
        from .plugins import load_entry_points
        load_entry_points()
    try:
        return REGISTRY[name]
    except KeyError:
        raise ChaosUsageError("unknown injector {!r}; known: {}".format(name, ", ".join(sorted(REGISTRY))))


# ----------------------------------------------------------------------------- contract

class Injector(object):
    """Base class. Subclass it, set ``name`` / ``positional`` / ``defaults``, implement the three methods."""

    name = None        # registry key; the word before '=' on the CLI
    lane = ""          # owning lane, documentation only
    positional = ()    # names for bare spec tokens, in order -- e.g. ("process", "share")
    defaults = {}      # default params, overridden by the spec

    def __init__(self, **params):
        merged = dict(self.defaults)
        merged.update(params)
        self.params = merged
        self.validate()

    @classmethod
    def from_spec(cls, spec, **extra):
        positional, kwargs = split_spec(spec) if spec else ([], {})
        if len(positional) > len(cls.positional):
            raise ChaosUsageError("{}: too many positional params in {!r}; accepts: {}".format(
                cls.name, spec, ", ".join(cls.positional) or "none"))
        params = {}
        for key, value in zip(cls.positional, positional):
            params[key] = value
        params.update(kwargs)
        params.update({k: str(v) for k, v in extra.items()})
        return cls(**params)

    # -- the three methods lanes implement ------------------------------------------------

    def validate(self):
        """Raise ChaosUsageError on bad params. Runs at configure time, before any DUT is touched."""

    def apply(self, duthost, **params):
        """Apply the fault on ``duthost``. ``params`` override the spec-bound ones for this call."""
        raise NotImplementedError("{}.apply".format(type(self).__name__))

    def release(self, duthost):
        """Undo the fault. Safe to call twice."""
        raise NotImplementedError("{}.release".format(type(self).__name__))

    def status(self, duthost):
        """``{"active": bool, ...}``. Put the measured effect under ``"achieved"`` when there is one."""
        return {"active": False}

    def fired(self, status):
        """Did the fault actually engage this run? ``True``/``False``, or ``None`` when this
        injector cannot tell from its status.

        A fault that arms but never engages -- an idle box, or an object type nothing on the box
        creates -- reports ``injected: 0`` and would otherwise read as a clean pass. That is a
        false negative: the run proved nothing. The verdict layer treats an explicit ``False`` as
        INCONCLUSIVE, never as a pass. Injectors whose engagement shows in an ``achieved`` counter
        get this for free; the rest override, or return ``None`` to opt out of the gate.
        """
        ach = (status or {}).get("achieved") or {}
        for key in ("injected", "spun_ms", "killed", "flaps", "enobufs_new", "delivered", "pushed"):
            if key in ach:
                try:
                    return int(ach[key]) > 0
                except (TypeError, ValueError):
                    pass
        return None

    def will_restart(self, duthost):
        """True if ``apply`` on this DUT will restart the swss/syncd container to load an
        interposer. Lets the scheduler refuse arming a box already near its systemd start-limit
        instead of bricking it. Only the interposer lanes override this.
        """
        return False

    def warnings(self):
        """Advisory strings the driver prints before applying. Non-fatal, unlike ``validate``:
        for a fault that will run but may mislead (e.g. an effect too small to observe)."""
        return []

    CAPABILITIES = {}

    def probe(self, duthost):
        """What this fault will do on this box, before it does anything. Read-only.

        ``capabilities`` is what the injector can and cannot do in general (tables it can fill,
        kinds it refuses); ``will_restart`` says whether arming it restarts swss/syncd;
        ``warnings`` are the advisories ``validate`` does not fail on. Injectors with more to
        say about a specific box override this and extend the dict.
        """
        try:
            restarts = bool(self.will_restart(duthost))
        except Exception as err:
            restarts = "unknown ({})".format(err)
        return {"injector": self.name, "lane": self.lane, "describe": self.describe(),
                "capabilities": dict(getattr(self, "CAPABILITIES", {}) or {}),
                "will_restart": restarts, "warnings": list(self.warnings())}

    def expected_syslog(self):
        """Regexes for syslog lines this fault *causes on purpose*.

        The harness feeds them to loganalyzer's ignore list while the fault is active, so an
        injected crash does not bury the finding under the supervisor noise it necessarily makes.
        Only list what the injection itself must print (exit/spawn chatter), never the daemon's
        own errors -- those are the finding.
        """
        return ()

    def events(self):
        """What ``apply`` did, per host, for the repro bundle. Injectors append dicts to ``self._events``."""
        return list(getattr(self, "_events", []))

    def record(self, duthost, **fields):
        fields.setdefault("host", duthost.hostname)
        fields.setdefault("at", time.time())
        fields.setdefault("injector", self.describe())
        self.__dict__.setdefault("_events", []).append(fields)
        return fields

    # -- helpers ----------------------------------------------------------------------------

    def describe(self):
        return "{}({})".format(self.name, ",".join("{}={}".format(k, v) for k, v in sorted(self.params.items())))

    def __repr__(self):
        return "<Injector {}>".format(self.describe())


class ChaosPlan(object):
    """The parsed --chaos session settings: what to inject, and whether to actually touch anything."""

    def __init__(self, injectors, dry_run=False):
        self.injectors = list(injectors)
        self.dry_run = dry_run

    @classmethod
    def from_args(cls, args, dry_run=False):
        injectors = []
        for arg in args or []:
            name, spec = parse_chaos_arg(arg)
            injectors.append(get(name).from_spec(spec))
        return cls(injectors, dry_run=dry_run)

    def describe(self):
        if not self.injectors:
            return "(no injectors)"
        lines = ["  {:<8} {:<8} {}".format(i.name, i.lane, i.describe()) for i in self.injectors]
        if self.dry_run:
            lines.insert(0, "  [dry-run] nothing will be applied")
        return "\n".join(lines)

    def summary(self):
        """One line, for junit properties and the report header."""
        return " ".join(i.describe() for i in self.injectors) or "none"


class ChaosSession(object):
    """Applies injectors to DUTs and guarantees release.

    Release is LIFO and never stops at the first failure: every (dut, injector) pair gets its
    ``release`` called, then the first error is re-raised. Nothing stays applied because
    something else broke.
    """

    def __init__(self, duthosts, dry_run=False, ptfhost=None):
        self.duthosts = list(duthosts)
        self.dry_run = dry_run
        # The PTF peer, for faults that source traffic (storm arp/nd/mac). None on a testbed
        # whose topology was never deployed; injectors that need one say so at apply time.
        # The console's run_experiment.py already builds one and passes it if this signature
        # takes it, so this is the missing half of that handshake.
        self.ptfhost = ptfhost
        self.applied = []   # [(duthost, injector)] in apply order

    def apply(self, injector, duthosts=None):
        for dut in duthosts or self.duthosts:
            if self.dry_run:
                logger.info("[chaos dry-run] would apply %s on %s", injector.describe(), dut.hostname)
            else:
                logger.info("[chaos] apply %s on %s", injector.describe(), dut.hostname)
                injector.apply(dut, ptfhost=self.ptfhost)
            self.applied.append((dut, injector))

    def release_all(self):
        first_error = None
        while self.applied:
            dut, injector = self.applied.pop()
            try:
                if self.dry_run:
                    logger.info("[chaos dry-run] would release %s on %s", injector.describe(), dut.hostname)
                else:
                    logger.info("[chaos] release %s on %s", injector.describe(), dut.hostname)
                    injector.release(dut)
            except Exception as err:  # keep releasing the rest, then re-raise the first
                logger.error("[chaos] release of %s on %s failed: %r", injector.describe(), dut.hostname, err)
                first_error = first_error or err
        if first_error is not None:
            raise first_error

    def status(self):
        if self.dry_run:
            return [(dut.hostname, inj.describe(), {"dry_run": True}) for dut, inj in self.applied]
        out = []
        for dut, inj in self.applied:
            try:
                out.append((dut.hostname, inj.describe(), inj.status(dut)))
            except Exception as err:  # status is diagnostics; never let it break a release path
                out.append((dut.hostname, inj.describe(), {"active": None, "error": repr(err)}))
        return out

    def expected_syslog(self):
        seen, out = set(), []
        for _, inj in self.applied:
            for rx in inj.expected_syslog():
                if rx not in seen:
                    seen.add(rx)
                    out.append(rx)
        return out

    def events(self):
        out = []
        for _, inj in self.applied:
            out.extend(inj.events())
        return out
