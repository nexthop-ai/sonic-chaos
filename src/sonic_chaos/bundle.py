"""Repro bundles: everything needed to re-run one failure, written next to the run.

A finding is only worth filing if someone else can reproduce it. A bundle turns "it failed on
the fourth of twenty runs" into a directory containing the exact flag line, what was injected
and when, whether the daemon came back, and the DUT's syslog for precisely that window.

    out/chaos/<test id>/<run>/
        repro.sh        the pytest command that reproduces this, copy-pasteable
        fault.json      injectors, their params, every apply event, and the status afterwards
        syslog.txt      the DUT's log for this test only, not the whole session
        outcome.txt     what pytest saw

Nothing here imports pytest: the caller passes plain values, so a bundle can be written from a
script (Oracle's passive runs do exactly that) and the writer is testable without a session.
Oracle drops its snapshots and diff into the same directory via ``add``.
"""
import errno
import json
import logging
import os
import re
import time

logger = logging.getLogger(__name__)

DEFAULT_ROOT = "out/chaos"


def sanitize(nodeid):
    """``tests/pc/test_po.py::test_x[run3]`` -> ``tests.pc.test_po.test_x.run3`` (a safe dir name)."""
    clean = re.sub(r"[^A-Za-z0-9_.-]+", ".", nodeid.replace("::", "."))
    return re.sub(r"\.+", ".", clean).strip(".")[:180] or "unnamed"


def repro_command(plan_args, nodeid, repeat=None, seed=None, experiment=None, extra=(),
                  conditions=None, condition=None):
    """Rebuild the command line that reproduces one result.

    The point is that it is *copy-pasteable*: a report saying "run it under CPU pressure" is a
    story, and a report carrying the exact flag line is a repro.
    """
    base = nodeid.split("[")[0]          # drop the run1..runN parametrisation
    parts = ["pytest", base]
    for arg in plan_args or []:
        parts += ["--chaos", arg]
    if experiment:
        parts += ["--chaos-file", experiment]
    if seed is not None:
        parts += ["--chaos-seed", str(seed)]
    if conditions:
        parts += ["--chaos-conditions", conditions]
        if condition:
            parts += ["--chaos-condition", condition]
    if repeat and repeat > 1:
        parts += ["--chaos-repeat", str(repeat)]
    parts += list(extra)
    return " ".join(parts)


class SyslogWindow(object):
    """Captures only the DUT log lines produced between ``open()`` and ``read()``.

    Line-offset based rather than timestamp based: the DUT's clock, the harness's clock and the
    log's own format do not have to agree, and there is no parsing to get wrong. If the log
    rotates mid-test the offset would point past the end, so that case is detected and the
    capture falls back to the whole current file with a note saying why.
    """

    LOG = "/var/log/syslog"

    def __init__(self, duthost):
        self.duthost = duthost
        self.hostname = getattr(duthost, "hostname", "?")
        self.start_line = None

    def open(self):
        self.start_line = self._line_count()
        return self

    def read(self, max_lines=4000):
        if self.start_line is None:
            return ""
        now = self._line_count()
        if now is None or self.start_line is None:
            return ""
        if now < self.start_line:
            note = "# log rotated during this test (was at line {}, now {} lines); showing the tail\n".format(
                self.start_line, now)
            return note + self._shell("tail -n {} {}".format(max_lines, self.LOG))
        return self._shell("tail -n +{} {} | head -n {}".format(self.start_line + 1, self.LOG, max_lines))

    def _line_count(self):
        out = self._shell("wc -l < {}".format(self.LOG)).strip()
        return int(out) if out.isdigit() else None

    def _shell(self, cmd):
        try:
            res = self.duthost.shell(cmd, module_ignore_errors=True) or {}
        except Exception as err:          # a DUT that is still down is exactly when we need the rest
            logger.warning("[chaos] syslog capture on %s failed: %r", self.hostname, err)
            return ""
        return res.get("stdout") or ""


class ReproBundle(object):
    """One directory holding the evidence for one test result."""

    def __init__(self, nodeid, root=DEFAULT_ROOT, run=None):
        self.nodeid = nodeid
        self.run = run
        self.dir = os.path.join(root, sanitize(nodeid))
        self.created_at = time.time()
        self._files = []

    def ensure(self):
        try:
            os.makedirs(self.dir)
        except OSError as err:
            if err.errno != errno.EEXIST:
                raise
        return self.dir

    def add(self, name, content):
        """Write one file into the bundle. ``content`` may be text or a JSON-able object.

        Never raises: a bundle documents a verdict that already exists, so a full disk or an
        unwritable path must not turn one failure into two.
        """
        path = os.path.join(self.dir, name)
        try:
            self.ensure()
            with open(path, "w") as handle:
                if isinstance(content, str):
                    handle.write(content)
                else:
                    json.dump(content, handle, indent=2, sort_keys=True, default=str)
        except (OSError, TypeError, ValueError) as err:
            # A bundle is evidence, never a reason to fail a run that already has a verdict.
            logger.warning("[chaos] could not write %s: %r", path, err)
            return None
        self._files.append(name)
        return path

    def write(self, repro, fault, outcome, syslog=None):
        """The standard four files. Returns the bundle directory."""
        self.add("repro.sh", "#!/bin/sh\n# sonic-chaos repro for {}\n{}\n".format(self.nodeid, repro))
        self.add("fault.json", fault)
        self.add("outcome.txt", outcome if isinstance(outcome, str) else str(outcome))
        if syslog:
            self.add("syslog.txt", syslog)
        logger.info("[chaos] repro bundle: %s (%s)", self.dir, ", ".join(self._files))
        return self.dir


class RunLedger(object):
    """Counts pass/fail per test across ``--chaos-repeat`` iterations.

    The output this feeds is the ``20 runs / 3 FAIL`` line, which is the most useful thing the
    plugin prints: a test that fails three times in twenty under fault is a far stronger signal
    than one that failed once, and it is invisible if you only look at the final verdict.
    """

    def __init__(self):
        self.tests = {}     # base nodeid -> {"runs": [...], "failed": [...], "bundles": [...]}

    @staticmethod
    def split(nodeid):
        """``test_x[run3]`` -> ``("test_x", "run3")``; a plain id keeps ``run`` as None.

        A condition id stays in the base, so ``test_x[restart-run3]`` counts under
        ``test_x[restart]``: the summary is per test *per condition*, which is the comparison
        the matrix exists to make.
        """
        match = re.match(r"^(.*?)\[(?:(.+)-)?(run\d+)\]$", nodeid)
        if match:
            base, cond, run = match.groups()
            return ("{}[{}]".format(base, cond) if cond else base), run
        return nodeid, None

    def record(self, nodeid, passed, bundle=None):
        base, run = self.split(nodeid)
        entry = self.tests.setdefault(base, {"runs": [], "failed": [], "bundles": []})
        label = run or "run{}".format(len(entry["runs"]) + 1)
        entry["runs"].append(label)
        if not passed:
            entry["failed"].append(label)
        if bundle:
            entry["bundles"].append(bundle)
        return entry

    def flaky(self):
        """Tests that did not agree with themselves: some runs passed, some failed."""
        return {k: v for k, v in self.tests.items() if v["failed"] and len(v["failed"]) < len(v["runs"])}

    def lines(self):
        """``[(nodeid, "20 runs / 3 FAIL", [failed run labels])]``, worst first."""
        out = []
        for nodeid, entry in self.tests.items():
            total, failed = len(entry["runs"]), len(entry["failed"])
            verdict = "{} run{} / {}".format(total, "s" if total != 1 else "",
                                             "{} FAIL".format(failed) if failed else "all pass")
            out.append((nodeid, verdict, list(entry["failed"]), list(entry["bundles"])))
        out.sort(key=lambda row: (-len(row[2]), row[0]))
        return out
