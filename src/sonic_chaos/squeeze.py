"""Squeeze lane -- getting ``chaos_agent.py`` onto a DUT and talking to it.

Shared by the ``cpu`` and ``mem`` injectors. Nothing here imports pytest, so the lane's scripts
(``scripts/calibrate.py``) drive the same code path the plugin does without a pytest session.

The agent is pushed once per host per session and every call returns one JSON object, so the
injectors never parse output -- a failure on the box arrives as a dict with an ``error`` key and
becomes a ``SqueezeError`` with the DUT's own words in it.
"""
import base64
import hashlib
import json
import logging
import os

from .injector import DEADMAN_DIR, ensure_shared_dir, sudo_prefix

logger = logging.getLogger(__name__)

_HERE = os.path.dirname(os.path.abspath(__file__))
AGENT_SRC = os.path.join(_HERE, "agent", "chaos_agent.py")

# Shared with Spine's dead-man scripts on purpose: one directory to look in on a box that is
# behaving oddly, and one directory to clear. chaos_agent.py hardcodes the same path because it
# runs on the DUT with nothing importable.
AGENT_DIR = DEADMAN_DIR
AGENT_DEST = AGENT_DIR + "/chaos_agent.py"

# Each chunk becomes one `printf` argument in its own ssh round trip, and a round trip through
# each ssh round trip costs seconds. At 3000 the ~52 KB of base64 took 18 of them and the push dominated
# every standalone run; 32000 makes it 2, and is still an order of magnitude under ARG_MAX.
_CHUNK = 32000

_pushed = set()      # hostnames this process has already pushed to


class SqueezeError(RuntimeError):
    """The agent refused, or the DUT could not run it. Carries the agent's own message."""


def _local_md5():
    with open(AGENT_SRC, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


def push_agent(duthost, force=False):
    """Copy the agent to the DUT. Idempotent, content-checked, once per host per session.

    Prefers ansible's ``copy``. Falls back to chunked base64 over ``shell`` so the same helper
    works for the standalone scripts, whose DUT stand-in only has ``shell()``.
    """
    host = getattr(duthost, "hostname", str(duthost))
    if host in _pushed and not force:
        return AGENT_DEST

    want = _local_md5()
    sudo = sudo_prefix(duthost)
    ensure_shared_dir(duthost)      # 1777, so Spine's dead-man can still write here afterwards
    res = duthost.shell("md5sum {} 2>/dev/null | cut -d' ' -f1".format(AGENT_DEST),
                        module_ignore_errors=True)
    # Substring, not equality: a DUT stand-in that shells through a testbed CLI prefixes
    # connection chatter, and re-pushing on every call would cost nine ssh round trips a time.
    if want in (res.get("stdout") or "") and not force:
        _pushed.add(host)
        return AGENT_DEST

    if hasattr(duthost, "copy"):
        duthost.copy(src=AGENT_SRC, dest=AGENT_DEST, mode="0755")
    else:
        _push_over_shell(duthost, sudo)
    logger.info("[squeeze] pushed chaos_agent.py to %s:%s (md5 %s)", host, AGENT_DEST, want[:8])
    _pushed.add(host)
    return AGENT_DEST


def _push_over_shell(duthost, sudo=""):
    """Chunked base64 for a DUT stand-in with no ansible ``copy``.

    Staged through ``/tmp`` rather than straight into AGENT_DIR: that directory may already be
    root-owned from an earlier run, and the calling user is ``admin`` on a real testbed.
    """
    with open(AGENT_SRC, "rb") as fh:
        blob = base64.b64encode(fh.read()).decode("ascii")
    stage = "/tmp/.chaos_agent.b64"
    duthost.shell(": > {}".format(stage))
    for start in range(0, len(blob), _CHUNK):
        duthost.shell("printf '%s' '{}' >> {}".format(blob[start:start + _CHUNK], stage))
    duthost.shell("base64 -d {stage} | {sudo}tee {dest} >/dev/null && {sudo}chmod 0755 {dest} && "
                  "rm -f {stage}".format(stage=stage, sudo=sudo, dest=AGENT_DEST))


def agent(duthost, command, *args, **kwargs):
    """Run one agent command and return its JSON.

    ``ignore_errors=True`` returns the payload even when the agent exited non-zero -- which is
    what ``release`` and ``status`` want, since neither may ever fail a test by raising.
    """
    ignore_errors = kwargs.pop("ignore_errors", False)
    push_agent(duthost)
    argv = " ".join([command] + [str(a) for a in args])
    res = duthost.shell("{}python3 {} {}".format(sudo_prefix(duthost), AGENT_DEST, argv),
                        module_ignore_errors=True)
    payload = _parse(res.get("stdout") or "")

    if payload is None:
        message = "[squeeze] agent {} produced no JSON on {}: rc={} stderr={!r}".format(
            command, getattr(duthost, "hostname", "?"), res.get("rc"),
            (res.get("stderr") or "")[:400])
        if ignore_errors:
            logger.error(message)
            return {"error": message, "active": False}
        raise SqueezeError(message)

    if payload.get("error") and not ignore_errors:
        raise SqueezeError("[squeeze] agent {} on {}: {}".format(
            command, getattr(duthost, "hostname", "?"), payload["error"]))
    return payload


def _parse(stdout):
    """The agent prints one JSON object; ssh banners and motd may precede it."""
    start = stdout.find("{")
    if start < 0:
        return None
    try:
        return json.loads(stdout[start:])
    except ValueError:
        return None


def flags(**kwargs):
    """``{"kind": "cpu", "ttl": 900}`` -> ``["--kind", "cpu", "--ttl", "900"]``, dropping Nones."""
    out = []
    for key in sorted(kwargs):
        if kwargs[key] is not None:
            out += ["--" + key.replace("_", "-"), str(kwargs[key])]
    return out
