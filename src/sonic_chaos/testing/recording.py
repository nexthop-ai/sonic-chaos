"""A switch that records what it was asked to do.

``RecordingDut`` stands in for a sonic-mgmt ``duthost`` (and, from P1 on, for any ``Dut``). It
runs nothing. Every ``shell`` and ``copy`` is appended to ``calls``, and each command is answered
from canned responses matched by regex, so an injector can be driven through apply, status and
release with no switch attached.

    dut = RecordingDut(responses=[(r"docker inspect .*State\\.Running", 0, "true")],
                       sequences={r"supervisorctl status": [RUNNING_55, RUNNING_912]})
    build("kill=orchagent").apply(dut)
    assert dut.ran_once(r"pkill") == "docker exec swss pkill -9 -x orchagent"

Matching rules, in order:

* ``sequences`` -- ``pattern -> [out1, out2, ...]``. Each match consumes the next output; the
  last one repeats forever, so a poll that outlives the script keeps getting the final state.
* ``responses`` -- ordered ``(pattern, rc, stdout)``. The first match wins, so a specific rule
  can shadow a general one.
* anything else -- rc 0 and empty output, which is what most DUT commands really return.

An output may be a callable taking the command, for an answer that can only be computed at run
time -- the digest of a binary built on this machine, say.

This is the ``FakeDut`` from the plugin's unit tests, promoted so every suite shares one.
"""
import hashlib
import re

__all__ = ["RecordingDut", "normalize"]


class RecordingDut(object):

    def __init__(self, hostname="dut1", responses=(), sequences=None):
        self.hostname = hostname
        self.responses = list(responses)
        self.sequences = {k: list(v) for k, v in (sequences or {}).items()}
        self.calls = []

    # -- the duthost surface the plugin uses ---------------------------------------------------

    def shell(self, cmd, module_ignore_errors=False, **kwargs):
        self.calls.append(("shell", cmd))
        rc, out = self._answer(cmd)
        return {"rc": rc, "stdout": out, "stderr": "" if rc == 0 else out}

    def copy(self, src=None, dest=None, mode=None, content=None, **kwargs):
        if content is not None:
            what = "content sha256:{}".format(hashlib.sha256(content.encode()).hexdigest()[:12])
        else:
            what = "src {}".format(src)
        self.calls.append(("copy", "{} -> {} mode={}".format(what, dest, mode)))
        return {"rc": 0, "changed": True}

    # -- assertions ----------------------------------------------------------------------------

    @property
    def commands(self):
        """Shell commands only, in order. What the unit tests assert against."""
        return [arg for kind, arg in self.calls if kind == "shell"]

    @commands.setter
    def commands(self, value):
        """``dut.commands = []`` forgets the shell history, so a test can assert on one phase."""
        self.calls = [c for c in self.calls if c[0] != "shell"] + [("shell", cmd) for cmd in value]

    def ran(self, pattern):
        """Every recorded command matching ``pattern``."""
        return [c for c in self.commands if re.search(pattern, c)]

    def ran_once(self, pattern):
        matches = self.ran(pattern)
        assert len(matches) == 1, "expected exactly one {!r}, got {}".format(pattern, matches)
        return matches[0]

    def transcript(self):
        """Every call, one per line, normalised so it is stable across runs and machines."""
        return [normalize("{}: {}".format(kind, arg)) for kind, arg in self.calls]

    # -- internals -----------------------------------------------------------------------------

    def _answer(self, cmd):
        for pattern, outputs in self.sequences.items():
            if re.search(pattern, cmd):
                out = outputs.pop(0) if len(outputs) > 1 else outputs[0]
                return 0, out(cmd) if callable(out) else out
        for pattern, rc, out in self.responses:
            if re.search(pattern, cmd):
                return rc, out(cmd) if callable(out) else out
        return 0, ""


_B64_RUN = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_TMP_PATH = re.compile(r"/tmp/(?:tmp|pytest-of-)[^\s'\"/]*(?:/[^\s'\"]*)?")


def normalize(line):
    """Make one transcript line comparable across runs.

    Inline payloads (base64 staging of the agent or a shim) are replaced by their length and a
    digest, so a transcript stays readable but still changes when the payload does. Host temp
    paths are masked because they differ on every run.
    """
    line = _B64_RUN.sub(lambda m: "<b64 len={} sha256={}>".format(
        len(m.group(0)), hashlib.sha256(m.group(0).encode()).hexdigest()[:12]), line)
    line = _TMP_PATH.sub("<tmp>", line)
    return line.replace("\n", "\\n")
