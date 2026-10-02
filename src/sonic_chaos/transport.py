"""How commands reach a switch.

Every injector, invariant and the engine talk to a switch through one duck type, the same surface
a sonic-mgmt ``duthost`` already has, so a real ``duthost`` is a valid ``Dut`` with no wrapper:

    dut.hostname                                       str, keys every log line and bundle
    dut.shell(cmd, module_ignore_errors=False, **kw)   -> {"rc": int, "stdout": str, "stderr": str}
    dut.copy(src=path, dest=path, mode="0644")         stage a local file on the switch

Extra ansible kwargs (``chdir``, ``executable``...) are accepted and ignored, because callers are
written against a real duthost and a stand-in that raised on them would fail far from the line
that matters.

This module provides the stand-ins for running without sonic-mgmt:

    SshDut("10.0.0.5", user="admin")      plain OpenSSH, key-based
    CommandDut("dut1", ["my-ssh", "box"]) any command prefix; the switch command is appended
    LocalDut()                            this machine is the switch
    open_dut("ssh://admin@10.0.0.5")      the same, from a URL -- what --dut and --chaos-dut take

``open_dut`` also resolves schemes a site package registers under the ``sonic_chaos.transports``
entry-point group, which is how a lab's own testbed CLI plugs in without the core knowing it.
"""
import base64
import os
import shlex
import subprocess
from importlib import metadata
from urllib.parse import urlparse

__all__ = ["CommandDut", "SshDut", "LocalDut", "open_dut", "register_scheme", "TransportError"]

DEFAULT_TIMEOUT = 600
TIMEOUT_RC = 124          # what timeout(1) exits with
_SCHEMES = {}


class TransportError(RuntimeError):
    """A command could not be run, or a copy did not land intact."""


class CommandDut(object):
    """Runs each switch command by appending it, as one argument, to ``argv``.

    ``sudo`` is ``"auto"`` (probe ``sudo -n true`` once and wrap in ``sudo -n sh -c`` if it
    works), ``True`` or ``False``. sonic-mgmt's duthost runs as root; an ssh login is usually
    ``admin``, and without the wrap an injector looks fine until one needs root -- the SAI shim
    got as far as installing itself and then died on ``systemctl restart swss: Access denied``.
    A PTF container has no sudo at all, which is why it is probed rather than assumed.
    """

    def __init__(self, hostname, argv, sudo="auto", timeout=DEFAULT_TIMEOUT):
        self.hostname = hostname
        self.argv = list(argv)
        self.sudo = sudo
        self.timeout = timeout
        self._sudo_ok = None if sudo == "auto" else bool(sudo)

    def __repr__(self):
        return "{}({!r})".format(type(self).__name__, self.hostname)

    # -- the duthost surface ---------------------------------------------------------------

    def shell(self, cmd, module_ignore_errors=False, **kwargs):
        proc = self._run(self._wrap(cmd))
        res = {"rc": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
        if proc.returncode and not module_ignore_errors:
            raise TransportError("{} on {} rc={}: {}".format(
                cmd, self.hostname, proc.returncode, (proc.stderr or proc.stdout).strip()[:300]))
        return res

    def shell_raw(self, cmd, module_ignore_errors=True, **kwargs):
        """``shell`` that never raises. Kept for the tools written against the old stand-in."""
        return self.shell(cmd, module_ignore_errors=True, **kwargs)

    def copy(self, src, dest, mode=None, **kwargs):
        """Stage ``src`` at ``dest`` in one round trip over stdin, then verify the size landed.

        A truncated .so is only a loader warning on the box, so a copy that is not checked would
        silently prove nothing. Transports that do not forward stdin fail the size check loudly
        rather than leaving an empty file behind.
        """
        with open(src, "rb") as handle:
            payload = base64.b64encode(handle.read())
        directory = os.path.dirname(dest) or "."
        script = "mkdir -p {d} && base64 -d > {f} && chmod {m} {f}".format(
            d=shlex.quote(directory), f=shlex.quote(dest), m=mode or "0644")
        proc = self._run(self._wrap(script), stdin=payload, text=False)
        if proc.returncode:
            raise TransportError("copy {} -> {}:{} failed: {}".format(
                src, self.hostname, dest, (proc.stderr or b"").decode("utf-8", "replace")[:300]))
        want = os.path.getsize(src)
        got = self.shell("stat -c %s {} 2>/dev/null || echo 0".format(shlex.quote(dest)),
                         module_ignore_errors=True)["stdout"].strip()
        if str(got) != str(want):
            raise TransportError("copy to {}:{} landed {} bytes, expected {}".format(
                self.hostname, dest, got, want))
        return {"rc": 0, "dest": dest, "changed": True}

    # -- internals -------------------------------------------------------------------------

    def _wrap(self, cmd):
        if self._use_sudo():
            return "sudo -n sh -c {}".format(shlex.quote(cmd))
        return cmd

    def _use_sudo(self):
        if self._sudo_ok is None:
            try:
                self._sudo_ok = self._run("sudo -n true", timeout=120).returncode == 0
            except (OSError, subprocess.SubprocessError):
                self._sudo_ok = False
        return self._sudo_ok

    def _run(self, cmd, stdin=None, text=True, timeout=None):
        """Run one command. A timeout is an answer, not an exception: rc 124 with the reason in
        stderr, the way ``timeout(1)`` reports it, so ``shell(..., module_ignore_errors=True)`` and
        ``shell_raw`` keep their promise never to raise. ``shell`` without it still raises."""
        limit = timeout or self.timeout
        try:
            return subprocess.run(self.argv + [cmd], input=stdin, capture_output=True, text=text,
                                  timeout=limit)
        except FileNotFoundError as err:
            raise TransportError("cannot run {!r} to reach {}: {}".format(self.argv[0], self.hostname, err))
        except subprocess.TimeoutExpired as err:
            why = "timed out after {}s reaching {}".format(limit, self.hostname)
            out = err.stdout or ("" if text else b"")
            if not text:
                why = why.encode()
            elif isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            return subprocess.CompletedProcess(err.cmd, TIMEOUT_RC, out, why)


class SshDut(CommandDut):
    """OpenSSH to ``user@host``. Key-based and non-interactive: a password prompt fails fast."""

    def __init__(self, host, user="admin", port=22, identity=None, options=(), hostname=None, **kw):
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-p", str(port)]
        if identity:
            argv += ["-i", identity]
        for opt in options:
            argv += ["-o", opt]
        argv.append("{}@{}".format(user, host) if user else host)
        super(SshDut, self).__init__(hostname or host, argv, **kw)


class LocalDut(CommandDut):
    """This machine is the switch: commands run under ``sh -c``."""

    def __init__(self, hostname=None, **kw):
        import socket
        super(LocalDut, self).__init__(hostname or socket.gethostname(), ["sh", "-c"], **kw)


def register_scheme(scheme, factory):
    """Make ``open_dut("<scheme>://...")`` call ``factory(parsed_url, url)``."""
    _SCHEMES[scheme] = factory


def _ssh(parsed, _url):
    if not parsed.hostname:
        raise ValueError("ssh:// needs a host, e.g. ssh://admin@10.0.0.5")
    return SshDut(parsed.hostname, user=parsed.username or "admin", port=parsed.port or 22)


def _local(parsed, _url):
    return LocalDut(parsed.hostname or None)


def _cmd(_parsed, url):
    """``cmd:ssh -p 2222 admin@box`` -- any command prefix; the switch command is appended."""
    words = shlex.split(url[len("cmd:"):])
    if not words:
        raise ValueError("cmd: needs a command prefix, e.g. 'cmd:ssh admin@10.0.0.5'")
    return CommandDut(words[-1].split("@")[-1], words)


register_scheme("ssh", _ssh)
register_scheme("local", _local)


def _site_schemes():
    for ep in metadata.entry_points(group="sonic_chaos.transports"):
        if ep.name not in _SCHEMES:
            _SCHEMES[ep.name] = ep.load()


def open_dut(url):
    """A ``Dut`` from a URL: ``ssh://user@host[:port]``, ``local://``, ``cmd:<prefix>``, or a
    scheme a site package registers (``sonic_chaos.transports`` entry points)."""
    if url.startswith("cmd:"):
        return _cmd(None, url)
    parsed = urlparse(url)
    if parsed.scheme not in _SCHEMES:
        _site_schemes()
    if parsed.scheme not in _SCHEMES:
        raise ValueError("unknown DUT address {!r}; use ssh://user@host, local://, cmd:<command>, "
                         "or install a site package that provides {!r}".format(url, parsed.scheme))
    return _SCHEMES[parsed.scheme](parsed, url)
