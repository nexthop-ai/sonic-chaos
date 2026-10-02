"""sonic-chaos pytest plugin. Loaded automatically once sonic-chaos is installed (``pytest11``).

It works in two places. Inside sonic-mgmt it uses the testbed's ``duthosts``, waits for
``sanity_check`` and teaches ``loganalyzer`` which syslog a fault causes on purpose. In any other
pytest suite those fixtures do not exist, and the switch comes from ``--chaos-dut <url>`` instead
(see ``sonic_chaos.transport``); tests take it from the ``chaos_duts`` fixture.

The surfaces:

    injector.Injector       apply / release / status            Spine, Squeeze, Shim
    oracle.assert_consistent(duthost)   parity by default        Oracle
    --chaos / --chaos-repeat / --chaos-dry-run  + @pytest.mark.chaos   Spine

    pytest ... --chaos cpu=orchagent:30                      # orchagent capped at 30% of a core
    pytest ... --chaos sai=route_entry:create:delay=2000     # every route create waits 2 s in SAI
    pytest ... --chaos kill=orchagent --chaos-repeat 20      # kill -9 orchagent, 20 runs per test
    pytest ... --chaos-dry-run --chaos cpu=orchagent:30      # print the plan, touch nothing

See docs/hld.md for the grammar, the lanes, and how to add an injector.

Zero footprint when idle: with no ``--chaos`` and no ``--chaos-file``, the fixtures below take
no DUT, request no other fixture, and run no command. A plugin that is always registered must
cost nothing on the thousands of runs that are not injecting anything.
"""
import logging

import pytest

from . import oracle
from .api import CURRENT_TEST, FaultMethods, split_fault
from .bundle import ReproBundle, RunLedger, SyslogWindow, repro_command
from .conditions import load_conditions
from .experiment import Experiment
from .injector import ChaosPlan, ChaosSession, ChaosUsageError, get as get_injector
from . import injectors as _registered  # noqa: F401  -- importing the package registers the built-in injectors

logger = logging.getLogger(__name__)

# Every ChaosSession that currently holds something on a DUT. The fixture finalizer is the
# normal release path; this list is what the session-finish and Ctrl-C hooks release from, so a
# fault cannot outlive the run that created it. See release_everything().
_LIVE = []


# ----------------------------------------------------------------------------- CLI

def pytest_addoption(parser):
    group = parser.getgroup("sonic-chaos", "sonic-chaos fault injection")
    group.addoption(
        "--chaos", action="append", default=[], metavar="INJECTOR=SPEC",
        help="Apply a fault for the whole run. Repeatable. Examples: --chaos cpu=orchagent:30 "
             "--chaos sai=route_entry:create:delay=2000 --chaos kill=orchagent")
    group.addoption(
        "--chaos-repeat", type=int, default=1, metavar="N",
        help="Run every collected test N times (ids run1..runN). Flaky-under-fault is the signal.")
    group.addoption(
        "--chaos-file", action="store", default=None, metavar="PATH",
        help="Experiment YAML: a seeded, weighted fault schedule with a steady-state gate and a "
             "recovery contract. See experiments/ for examples.")
    group.addoption(
        "--chaos-conditions", action="store", default=None, metavar="PATH",
        help="JSON matrix of conditions, each a named list of faults applied together. Every "
             "collected test runs once per condition, module by module; ids carry the condition "
             "name. See conditions.py and examples/conditions-example.json.")
    group.addoption(
        "--chaos-condition", action="append", default=[], metavar="NAME",
        help="With --chaos-conditions: run only the named condition(s). Repeatable.")
    group.addoption(
        "--chaos-seed", type=int, default=None, metavar="N",
        help="Override the experiment file's seed. Same seed -> same fault order, every time.")
    group.addoption(
        "--chaos-dry-run", action="store_true", default=False,
        help="Resolve targets and log the plan, but never touch a DUT.")
    group.addoption(
        "--chaos-bundle-dir", action="store", default="out/chaos", metavar="DIR",
        help="Where per-failure repro bundles are written (default: out/chaos).")
    group.addoption(
        "--chaos-oracle", action="store", default="parity", metavar="GROUP",
        help="After every test under fault, check the databases still agree: parity (default), "
             "health, signal, all, or none to disable. A divergence that outlives the recovery "
             "budget fails the test. An experiment file's contract overrides this.")
    group.addoption(
        "--chaos-dut", action="append", default=[], metavar="URL",
        help="The switch, for suites outside sonic-mgmt: ssh://user@host, local://, cmd:<prefix>, or "
             "a site scheme. Repeatable. Ignored when the suite provides a duthosts fixture.")
    group.addoption(
        "--chaos-profile", action="append", default=[], metavar="FILE|NAME",
        help="Target profile laid over the default: the platform's containers and daemons. "
             "Repeatable; a YAML path or a profile a site package provides.")
    group.addoption(
        "--chaos-strict", action="store_true", default=False,
        help="Fail a test whose faults never engaged (INCONCLUSIVE) instead of warning. A pass "
             "under a fault that did nothing proves nothing.")
    group.addoption(
        "--chaos-recover", type=int, default=60, metavar="SECONDS",
        help="How long a divergence may persist after release before it counts (default 60). "
             "An experiment file's contract.recover_within overrides this.")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "chaos(injector, spec, **params): apply one extra fault for this test only, e.g. "
        "@pytest.mark.chaos('kill', 'orchagent'). Stacks with the session-wide --chaos.")
    from .injector import set_profiles
    try:
        set_profiles(config.getoption("--chaos-profile"))
    except ChaosUsageError as err:
        raise pytest.UsageError("--chaos-profile: {}".format(err))
    try:
        config.chaos_plan = ChaosPlan.from_args(config.getoption("--chaos"),
                                                dry_run=config.getoption("--chaos-dry-run"))
    except ChaosUsageError as err:
        raise pytest.UsageError("--chaos: {}".format(err))

    config.chaos_conditions = []
    path = config.getoption("--chaos-conditions")
    if path:
        try:
            config.chaos_conditions = load_conditions(
                path, dry_run=config.getoption("--chaos-dry-run"),
                only=config.getoption("--chaos-condition") or None)
        except (ChaosUsageError, OSError) as err:
            raise pytest.UsageError("--chaos-conditions: {}".format(err))
        logger.info("sonic-chaos conditions\n%s", "\n".join(
            "  " + c.describe() for c in config.chaos_conditions))
    elif config.getoption("--chaos-condition"):
        raise pytest.UsageError("--chaos-condition needs --chaos-conditions PATH")

    config.chaos_experiment = None
    path = config.getoption("--chaos-file")
    if path:
        try:
            from .engine.runner import resolve_experiment
            config.chaos_experiment = Experiment.from_file(resolve_experiment(path))
        except (ChaosUsageError, OSError) as err:
            raise pytest.UsageError("--chaos-file: {}".format(err))
        seed = config.getoption("--chaos-seed")
        if seed is not None:
            config.chaos_experiment.seed = seed
        logger.info("sonic-chaos experiment\n%s", config.chaos_experiment.describe())
        # Under pytest the schedule's order and weights apply, its clock does not: each test is
        # one slot, and the slots are dealt to tests in collection order, wrapping around.
        config.chaos_schedule = [fault for _offset, fault in config.chaos_experiment.schedule()]
    else:
        config.chaos_schedule = []
    config.chaos_slot = 0

    # The oracle's contract: which group to check after each test, and how long recovery may
    # take. The experiment file wins when there is one, so the YAML is the single source of truth.
    selector = (config.getoption("--chaos-oracle") or "").strip()
    if config.chaos_experiment is not None:
        config.chaos_oracle = list(config.chaos_experiment.invariants) or None
        config.chaos_recover = config.chaos_experiment.recover_within
    else:
        config.chaos_oracle = None if selector.lower() in ("none", "off", "0", "") else selector
        config.chaos_recover = config.getoption("--chaos-recover")
    if config.chaos_oracle is not None:
        try:
            oracle.resolve(config.chaos_oracle)
        except ValueError as err:
            raise pytest.UsageError("--chaos-oracle: {}".format(err))
    config.chaos_oracle_baseline = {}        # hostname -> {(kind, db, key)} present before any fault
    config.chaos_oracle_baseline_snap = {}   # hostname -> the snapshot that baseline came from

    config.chaos_ledger = RunLedger()
    config.chaos_verdicts = {"HELD": 0, "BROKE": 0, "INCONCLUSIVE": 0}
    if config.chaos_plan.injectors:
        logger.info("sonic-chaos plan\n%s", config.chaos_plan.describe())


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    """Keep each phase's report on the item, so teardown can judge the call.

    sonic-mgmt's conftest sets ``item.rep_call`` the same way; other suites set nothing, so the
    plugin keeps its own copy under a name nobody else writes.
    """
    outcome = yield
    report = outcome.get_result()
    setattr(item, "chaos_rep_" + report.when, report)


def pytest_report_header(config):
    lines = []
    plan = getattr(config, "chaos_plan", None)
    experiment = getattr(config, "chaos_experiment", None)
    suffix = "  [dry-run]" if plan and plan.dry_run else ""
    if plan and plan.injectors:
        lines.append("sonic-chaos: {}{}".format(plan.summary(), suffix))
    if experiment:
        lines.append("sonic-chaos experiment: {}{}".format(experiment.summary(), suffix))
    conditions = getattr(config, "chaos_conditions", None)
    if conditions:
        lines.append("sonic-chaos conditions: {} from {}{}".format(
            ", ".join(c.name for c in conditions), config.getoption("--chaos-conditions"), suffix))
    return lines


def pytest_generate_tests(metafunc):
    """--chaos-conditions: every test once per condition. --chaos-repeat N: run1..runN.

    The condition parameter is module scoped, so pytest orders a module's tests to run to
    completion under one condition before the next one is applied: a condition holding a kill
    fires once per module, not once per test.
    """
    conditions = getattr(metafunc.config, "chaos_conditions", None)
    if conditions:
        metafunc.fixturenames.append("chaos_condition")
        metafunc.parametrize("chaos_condition", conditions, ids=[c.name for c in conditions],
                             indirect=True, scope="module")
    repeat = metafunc.config.getoption("--chaos-repeat")
    if repeat and repeat > 1:
        metafunc.fixturenames.append("chaos_run")
        metafunc.parametrize("chaos_run", range(1, repeat + 1), ids=lambda i: "run{}".format(i))


# ----------------------------------------------------------------------------- release guarantees

def release_everything(reason):
    """Release every fault still applied anywhere. Idempotent, and never raises.

    This is the backstop for the exit paths a fixture finalizer does not cover: Ctrl-C, a
    crashed internal error, ``--exitfirst`` unwinding, a plugin above us raising during
    teardown. It runs after the normal path has usually already emptied the sessions, so on a
    healthy run it does nothing at all.

    The last resort below this is on the DUT itself: every state fault arms a dead-man timer
    that restores the box even if this process dies outright.
    """
    while _LIVE:
        session = _LIVE.pop()
        try:
            if session.applied:
                logger.warning("[chaos] releasing %d fault(s) left applied (%s)",
                               len(session.applied), reason)
            session.release_all()
        except Exception as err:
            logger.error("[chaos] release during %s failed: %r", reason, err)


def _track(session):
    _LIVE.append(session)
    return session


def _untrack(session):
    try:
        _LIVE.remove(session)
    except ValueError:
        pass


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    release_everything("session finish")


def pytest_keyboard_interrupt(excinfo):
    release_everything("KeyboardInterrupt")


def pytest_internalerror(excrepr, excinfo):
    release_everything("internal error")


# ----------------------------------------------------------------------------- fixtures

def _optional_fixture(request, name):
    """A sonic-mgmt fixture if this suite has it, else None. Outside sonic-mgmt none exist."""
    try:
        return request.getfixturevalue(name)
    except pytest.FixtureLookupError:
        return None


def _duthosts(request):
    """sonic-mgmt's ``duthosts`` when the suite has one, else the ``--chaos-dut`` switches."""
    duthosts = _optional_fixture(request, "duthosts")
    if duthosts is not None:
        return duthosts
    return request.getfixturevalue("chaos_duts")


@pytest.fixture(scope="session")
def chaos_duts(request):
    """The switches named by ``--chaos-dut``, for suites that have no sonic-mgmt testbed."""
    from .transport import open_dut
    urls = request.config.getoption("--chaos-dut")
    if not urls:
        raise pytest.UsageError("sonic-chaos needs a switch: this suite has no duthosts fixture, so "
                                "pass --chaos-dut ssh://user@host (or local://, cmd:<prefix>)")
    try:
        return [open_dut(url) for url in urls]
    except ValueError as err:
        raise pytest.UsageError("--chaos-dut: {}".format(err))


@pytest.fixture(scope="module", autouse=True)
def chaos_module(request):
    """Session-wide --chaos faults, held for the whole module.

    Requesting ``sanity_check`` is what orders us: pytest sets this fixture up *after* the
    module's pre-test sanity and tears it down *before* the post-test sanity, so neither sanity
    pass ever sees a switch we are deliberately hurting.

    It is requested lazily rather than declared as a parameter so that a run with no faults
    pulls in no DUT fixtures at all.
    """
    plan = request.config.chaos_plan
    if not plan.injectors:
        yield None
        return

    _optional_fixture(request, "sanity_check")
    duthosts = _duthosts(request)

    if not plan.dry_run:
        _preload_interposers(request.config, duthosts, plan.injectors)
        _oracle_baseline(request.config, duthosts)

    session = _track(ChaosSession(duthosts, dry_run=plan.dry_run))
    try:
        for injector in plan.injectors:
            session.apply(injector)
        yield session
    finally:
        try:
            session.release_all()
        finally:
            _untrack(session)


@pytest.fixture(scope="module")
def chaos_condition(request, chaos_module):
    """One condition from --chaos-conditions, held for the whole module.

    Requesting ``chaos_module`` first means the session-wide faults go on before the condition's
    and come off after them, so release stays LIFO across the two. A control condition (no
    faults) still takes the DUT and the oracle baseline and yields an empty session, so the
    control run is counted and checked exactly like the others, and a box handed over already
    divergent is subtracted rather than blamed on the empty condition.
    """
    condition = request.param
    plan = condition.plan
    _optional_fixture(request, "sanity_check")
    duthosts = _duthosts(request)

    if not plan.dry_run:
        if plan.injectors:
            _preload_interposers(request.config, duthosts, plan.injectors)
        _oracle_baseline(request.config, duthosts)

    session = _track(ChaosSession(duthosts, dry_run=plan.dry_run))
    logger.info("[chaos] condition %s: %s", condition.name, condition.summary())
    try:
        for injector in plan.injectors:
            session.apply(injector)
        yield session
    finally:
        try:
            session.release_all()
        finally:
            _untrack(session)
            logger.info("[chaos] condition %s released", condition.name)


class ChaosHandle(FaultMethods):
    """What a test gets from the ``chaos`` fixture."""

    def __init__(self, request, module_session, condition_session=None, condition=None):
        self.request = request
        self.plan = request.config.chaos_plan
        self._module = module_session
        self._condition = condition_session
        self.condition = condition          # the ChaosCondition in force, or None
        self._duthosts = None
        self._local = None
        # What this test's own session held, kept after release: the oracle, the bundle and the
        # ledger all run after release and must still see which faults were in force.
        self._released = []
        self._syslog = []           # expected_syslog of every fault this test injected, in order

    # duthosts is resolved on first use so an idle run never requests it.
    @property
    def duthosts(self):
        if self._duthosts is None:
            self._duthosts = _duthosts(self.request)
        return self._duthosts

    @property
    def session(self):
        if self._local is None:
            self._local = _track(ChaosSession(self.duthosts, dry_run=self.plan.dry_run))
        return self._local

    def inject(self, name, spec="", duthosts=None, **params):
        """Apply a fault mid-test; it is released when the test ends.

            chaos.inject("kill", "orchagent")
            chaos.inject("cpu", process="orchagent", share=30)
        """
        name, spec = split_fault(name, spec)
        injector = get_injector(name).from_spec(spec, **params)
        self.session.apply(injector, duthosts=duthosts)
        # Kept past release: loganalyzer reads its ignore list at teardown, after a with-block
        # fault is long gone, and the lines this fault printed are still in the log it reads.
        self._syslog.extend(injector.expected_syslog())
        return injector

    def release(self):
        """Release everything this test injected. Session-wide faults stay until module end."""
        if self._local is not None:
            self._released.extend(self._local.applied)
            try:
                self._local.release_all()
            finally:
                _untrack(self._local)
                self._local = None

    def _sources(self):
        return [s for s in (self._module, self._condition, self._local) if s is not None]

    def status(self):
        return [row for source in self._sources() for row in source.status()]

    def statuses(self):
        """``(hostname, describe, status, injector)`` for every fault in force; one status call each."""
        out = []
        for source in self._sources():
            if source is None:
                continue
            for dut, inj in source.applied:
                if source.dry_run:
                    out.append((dut.hostname, inj.describe(), {"dry_run": True}, inj))
                    continue
                try:
                    out.append((dut.hostname, inj.describe(), inj.status(dut), inj))
                except Exception as err:
                    out.append((dut.hostname, inj.describe(), {"active": None, "error": repr(err)}, inj))
        return out

    @property
    def applied(self):
        """Every injector currently in force for this test, session-wide ones included."""
        out = list(self._module.applied) if self._module else []
        out += list(self._condition.applied) if self._condition else []
        return out + list(self._released) + (list(self._local.applied) if self._local else [])

    @property
    def active(self):
        """Under a fault, or under a condition. A control condition counts: its run is judged too."""
        return (bool(self.plan.injectors) or self.condition is not None
                or bool(self._local and self._local.applied) or bool(self._released))

    def recipe(self):
        """One line naming every fault in force, for the junit property and the bundle."""
        parts = [self.plan.summary() if self.plan.injectors else ""]
        if self.condition is not None:
            parts.append("[{}] {}".format(self.condition.name, self.condition.summary()))
        parts.append(" ".join(i.describe() for _, i in self._released + (self._local.applied if self._local else [])))
        return " ".join(x for x in parts if x) or "none"

    def expected_syslog(self):
        """Every pattern a fault of this test caused on purpose: the module's, and each injected
        one's, including faults already released."""
        seen, out = set(), []
        module = self._module.expected_syslog() if self._module else []
        condition = self._condition.expected_syslog() if self._condition else []
        local = self._local.expected_syslog() if self._local else []
        for rx in list(module) + list(condition) + list(self._syslog) + list(local):
            if rx not in seen:
                seen.add(rx)
                out.append(rx)
        return out

    def events(self):
        out = list(self._module.events()) if self._module else []
        out += list(self._condition.events()) if self._condition else []
        for _dut, injector in self._released:
            out.extend(injector.events())
        return out + (list(self._local.events()) if self._local else [])

    def _baseline(self):
        return getattr(self.request.config, "chaos_oracle_baseline", {})


# Fields an injector may report from status(). Any that are present are attached to the result,
# so what a fault actually did travels with the verdict instead of living in a log somebody has
# to go and find.
MEASURED_FIELDS = ("achieved", "peak", "bit", "throttled_pct", "reattached",
                   "cap_pct", "rss_delta_pct", "recovered", "oom_kill")


def record_measurements(node, handle):
    """Attach what each active fault measured to this test's junit properties.

    A pass under ``cpu=orchagent:30`` means nothing without the share orchagent actually got:
    if the cap never bit, the test passed with no effective fault applied, and that has to be
    visible on the result rather than inferred. Never fails a test -- a status call that cannot
    reach the DUT is a worse log line, not a worse verdict.
    """
    fired = []
    try:
        measured = []
        for hostname, describe, status, injector in handle.statuses():
            if not isinstance(status, dict):
                continue
            try:
                fired.append(injector.fired(status))
            except Exception:
                fired.append(None)
            fields = ["{}={}".format(f, status[f]) for f in MEASURED_FIELDS
                      if status.get(f) is not None]
            if fields:
                measured.append("{} {} {}".format(hostname, describe, " ".join(fields)))
        if measured:
            node.user_properties.append(("chaos_measured", " | ".join(measured)))
            logger.info("[chaos] measured: %s", " | ".join(measured))
    except Exception as err:
        logger.warning("[chaos] could not collect fault measurements: %r", err)
    return fired


def _oracle_label(selector):
    return selector if isinstance(selector, str) else ",".join(selector)


def _oracle_baseline(config, duthosts):
    """The steady-state gate: what already disagrees BEFORE any fault, per DUT.

    Taken once and subtracted from every later check. A box handed to us already divergent is
    reported once as INVALID and never blamed on a fault -- which is the difference between a
    finding and an argument.
    """
    selector = getattr(config, "chaos_oracle", None)
    if selector is None:
        return
    for dut in duthosts:
        if dut.hostname in config.chaos_oracle_baseline:
            continue
        try:
            real, notices, snap = oracle.gate(dut, only=selector)
        except Exception as err:
            logger.warning("[oracle] baseline on %s failed: %r -- later checks run without one",
                           dut.hostname, err)
            config.chaos_oracle_baseline[dut.hostname] = set()
            continue
        config.chaos_oracle_baseline[dut.hostname] = oracle.finding_keys(real)
        config.chaos_oracle_baseline_snap[dut.hostname] = snap
        for notice in notices:
            logger.warning("[oracle] %s on %s could not run: %s", notice.kind, dut.hostname, notice.detail)
        if real:
            logger.warning(
                "[oracle] INVALID baseline on %s: %d divergence(s) present before any fault. Recorded "
                "and ignored from here on; a run on an already-broken box proves nothing.\n%s",
                dut.hostname, len(real), oracle.format_divergences(real))
        else:
            logger.info("[oracle] steady state on %s: %s holds", dut.hostname, _oracle_label(selector))


def _preload_interposers(config, duthosts, injectors):
    """Load the plan's interposers before the baseline is taken.

    Loading a shim re-execs swss/syncd once. Done here it happens before the baseline snapshot,
    not after it: taking the baseline first and loading second records the reconvergence as
    pre-existing divergence and subtracts real findings with it. Each shim is loaded then disarmed
    (a disarmed shim is a passthrough), so the module's own apply only writes the control file.
    Mirrors run_experiment.preload_interposers on the standalone driver.
    """
    selector = getattr(config, "chaos_oracle", None)
    settled = set()
    for injector in injectors:
        for dut in duthosts:
            try:
                if not injector.will_restart(dut):
                    continue
            except Exception:
                continue
            logger.info("[chaos] pre-loading %s interposer on %s (once)", injector.name, dut.hostname)
            injector.apply(dut)
            injector.release(dut)
            settled.add(dut)
    # Let the box reconverge from the load restart before the baseline reads it.
    if selector:
        for dut in settled:
            oracle.wait_consistent(dut, only=selector, timeout=180)


def _oracle_after(request, handle):
    """After release: does the switch agree with itself again, within the recovery budget?

    Runs after ``release`` on purpose. A frozen daemon or a still-corrupted key would flag every
    time; the contract is that the databases agree *again* once the fault is lifted, and
    ``wait_consistent`` gives recovery its window instead of sampling once.
    """
    config = request.config
    selector = getattr(config, "chaos_oracle", None)
    handle.oracle_after = None
    handle.oracle_before = None
    if selector is None:
        return []
    findings = []
    for dut in handle.duthosts:
        handle.oracle_before = config.chaos_oracle_baseline_snap.get(dut.hostname)
        baseline = config.chaos_oracle_baseline.get(dut.hostname)
        try:
            real, notices, elapsed, snap = oracle.wait_consistent(
                dut, only=selector, timeout=config.chaos_recover, interval=5, baseline=baseline)
        except Exception as err:
            # A check that cannot run is reported, never mistaken for a clean box.
            logger.warning("[oracle] check on %s failed: %r", dut.hostname, err)
            request.node.user_properties.append(("chaos_oracle", "{}: check failed: {!r}".format(dut.hostname, err)))
            continue
        handle.oracle_after = snap
        for notice in notices:
            logger.warning("[oracle] %s on %s could not run: %s", notice.kind, dut.hostname, notice.detail)
        if real:
            findings.extend(real)
            request.node.user_properties.append(("chaos_oracle", "{}: {} divergence(s) still present {}s "
                                                 "after release".format(dut.hostname, len(real), elapsed)))
            logger.error("[oracle] %s: %d divergence(s) still present %ss after the fault was released:\n%s",
                         dut.hostname, len(real), elapsed, oracle.format_divergences(real))
        else:
            request.node.user_properties.append(("chaos_oracle", "{}: {} consistent after {}s".format(
                dut.hostname, _oracle_label(selector), elapsed)))
    return findings


def _oracle_failure(handle, findings, bundle_dir):
    lines = ["oracle: {} divergence(s) outlived the recovery budget after the fault was released".format(
        len(findings))]
    lines.append(oracle.format_divergences(findings))
    if bundle_dir:
        lines.append("evidence: {}/oracle_findings.txt".format(bundle_dir))
    return "\n".join(lines)


@pytest.fixture(scope="function", autouse=True)
def chaos(request, chaos_module):
    """Per-test handle: applies @pytest.mark.chaos overrides, offers ``inject()``, writes bundles."""
    condition_session = condition = None
    params = getattr(getattr(request.node, "callspec", None), "params", {})
    if "chaos_condition" in params:
        condition_session = request.getfixturevalue("chaos_condition")
        condition = params["chaos_condition"]
    handle = ChaosHandle(request, chaos_module, condition_session, condition)
    handle.oracle_before = handle.oracle_after = None
    marks = list(request.node.iter_markers("chaos"))
    slot = _next_scheduled_fault(request.config)
    if (marks or slot) and chaos_module is None and condition_session is None and not handle.plan.dry_run:
        # No session-wide fault, so nothing took the steady-state baseline yet. Take it now,
        # BEFORE this test's own faults go on.
        _oracle_baseline(request.config, handle.duthosts)
    for mark in marks:
        name, spec = (list(mark.args) + ["", ""])[:2]
        handle.inject(name, spec, **mark.kwargs)
    if slot is not None:
        handle.inject(slot.injector.name, "", **slot.injector.params)

    window = None
    token = CURRENT_TEST.set(getattr(request.node, "function", None))
    if handle.active and not handle.plan.dry_run:
        # Lands in junit <properties> for this testcase: every result carries its fault recipe.
        request.node.user_properties.append(("chaos", handle.recipe()))
        if condition is not None:
            request.node.user_properties.append(("chaos_condition", condition.name))
        window = _open_syslog_window(handle)

    try:
        yield handle
    finally:
        CURRENT_TEST.reset(token)
        # Order matters. Measurements read live fault status, so before release. The oracle
        # asks whether the box agrees with itself AGAIN, so after release. A release failure is
        # kept and re-raised, never allowed to skip the checks or hide behind them.
        release_error = None
        fired = []
        try:
            if handle.active:
                fired = record_measurements(request.node, handle)
        finally:
            try:
                handle.release()
            except Exception as err:
                release_error = err
                logger.error("[chaos] release failed on teardown: %r", err)
        findings, bundle_dir = [], None
        if handle.active and not handle.plan.dry_run:
            findings = _oracle_after(request, handle)
            bundle_dir = _record_outcome(request, handle, window, findings)
        if release_error is not None:
            raise release_error
        if handle.active and not handle.plan.dry_run:
            verdict = grade(findings, fired)
            request.config.chaos_verdicts[verdict] += 1
            request.node.user_properties.append(("chaos_verdict", verdict))
            if verdict == "INCONCLUSIVE":
                message = ("[chaos] INCONCLUSIVE: no fault engaged during {} ({}), so its pass proves "
                           "nothing".format(request.node.nodeid, handle.recipe()))
                if request.config.getoption("--chaos-strict"):
                    pytest.fail(message, pytrace=False)
                logger.warning(message)
        if findings:
            pytest.fail(_oracle_failure(handle, findings, bundle_dir), pytrace=False)


def _next_scheduled_fault(config):
    """The experiment's next slot for this test, or None when there is no --chaos-file."""
    schedule = getattr(config, "chaos_schedule", None)
    if not schedule:
        return None
    fault = schedule[config.chaos_slot % len(schedule)]
    config.chaos_slot += 1
    return fault


def grade(findings, fired):
    """BROKE if the box did not hold; else HELD if a fault engaged; else INCONCLUSIVE.

    ``fired`` holds each injector's ``fired(status)``: True, False, or None (cannot tell). One
    that cannot tell is not held against the run; only an explicit False with no True is.
    """
    if findings:
        return "BROKE"
    if fired and not any(f is True for f in fired) and any(f is False for f in fired):
        return "INCONCLUSIVE"
    return "HELD"


@pytest.fixture(autouse=True)
def chaos_loganalyzer_policy(request, chaos):
    """Teach loganalyzer which syslog a fault is *supposed* to produce.

    Killing orchagent makes supervisor log an unexpected exit -- every time, by construction.
    Left alone, loganalyzer fails the test on our own injection, so every result under fault is
    red for the same uninteresting reason and the real finding is buried.

    Only the injection's own noise is ignored, never the daemon's errors: each injector lists
    its patterns in ``expected_syslog()`` and they are deliberately narrow. A fault that hid the
    evidence it was meant to expose would be worse than no fault at all.
    """
    loganalyzer = _optional_fixture(request, "loganalyzer")
    if not loganalyzer:
        yield
        return
    added = set()

    def extend(when):
        new = [rx for rx in chaos.expected_syslog() if rx not in added]
        if not new:
            return
        added.update(new)
        for _hostname, analyzer in loganalyzer.items():
            analyzer.ignore_regex.extend(new)
        logger.info("[chaos] loganalyzer: ignoring %d injection-caused pattern(s) %s", len(new), when)

    extend("for this test")
    yield
    # loganalyzer applies ignore_regex when it analyses, at its own teardown -- which runs after
    # this one. Faults injected mid-test (chaos.inject, with chaos.fault(...)) only exist now.
    extend("from faults injected during the test")


# ----------------------------------------------------------------------------- evidence

def _open_syslog_window(handle):
    """Start a per-test syslog capture on every DUT under fault. Never fatal."""
    try:
        windows = [SyslogWindow(dut).open() for dut in handle.duthosts]
        return windows
    except Exception as err:
        logger.warning("[chaos] could not open the syslog window: %r", err)
        return None


def _record_outcome(request, handle, windows, oracle_findings=()):
    """Count the run and, if it failed, write the repro bundle. Never fails the test itself.

    An oracle finding is a failure of the run even when the test's own assertions passed: the
    test did its job, and the switch came out of it disagreeing with itself.
    """
    config = request.config
    report = getattr(request.node, "chaos_rep_call", None) or getattr(request.node, "rep_call", None)
    if report is None:
        return None                          # setup failed or was skipped: nothing to judge
    if report.skipped:
        return None

    failed = (not report.passed) or bool(oracle_findings)
    bundle_dir = None
    if failed and not handle.plan.dry_run:
        try:
            bundle_dir = _write_bundle(request, handle, windows, report, oracle_findings)
        except Exception as err:
            logger.warning("[chaos] repro bundle failed: %r", err)
    config.chaos_ledger.record(request.node.nodeid, not failed, bundle_dir)
    return bundle_dir


def _write_bundle(request, handle, windows, report, oracle_findings=()):
    config = request.config
    nodeid = request.node.nodeid
    experiment = getattr(config, "chaos_experiment", None)
    bundle = ReproBundle(nodeid, root=config.getoption("--chaos-bundle-dir"))

    repro = repro_command(
        config.getoption("--chaos"), nodeid,
        repeat=config.getoption("--chaos-repeat"),
        seed=experiment.seed if experiment else None,
        experiment=experiment.path if experiment else None,
        conditions=config.getoption("--chaos-conditions"),
        condition=handle.condition.name if handle.condition else None)

    fault = {
        "nodeid": nodeid,
        "recipe": handle.recipe(),
        "injectors": [{"name": i.name, "lane": i.lane, "params": i.params}
                      for _, i in handle.applied],
        "events": handle.events(),
        "status": [{"host": host, "injector": desc, "status": state}
                   for host, desc, state in _safe_status(handle)],
    }
    syslog = ""
    for window in windows or []:
        text = window.read()
        if text:
            syslog += "===== {} =====\n{}\n".format(window.hostname, text)

    outcome = "{}\n\n{}".format(report.outcome, report.longreprtext)
    if oracle_findings:
        outcome = "ORACLE: {} divergence(s) after release\n\n{}".format(len(oracle_findings), outcome)
    path = bundle.write(repro=repro, fault=fault, syslog=syslog, outcome=outcome)

    # The oracle's evidence rides in the same bundle: what the box looked like before any fault,
    # what it looked like after, what changed, and what the invariants concluded.
    before = getattr(handle, "oracle_before", None)
    after = getattr(handle, "oracle_after", None)
    if oracle_findings:
        bundle.add("oracle_findings.txt", oracle.format_divergences(
            oracle_findings, header="{} divergence(s) outlived the recovery budget".format(len(oracle_findings))))
    for name, snap in (("oracle_before.json", before), ("oracle_after.json", after)):
        if snap is not None:
            bundle.add(name, {"hostname": snap.hostname, "taken_at": snap.taken_at, "tables": snap.tables})
    if before is not None and after is not None:
        bundle.add("oracle_diff.txt", oracle.format_divergences(
            oracle.diff(before, after), header="what changed between baseline and after-release"))
    return path


def _safe_status(handle):
    try:
        return handle.status()
    except Exception as err:
        return [("?", "status failed", {"error": repr(err)})]


# ----------------------------------------------------------------------------- the 20 runs / 3 FAIL line

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """The repeat summary. Per the plan, this output is the best part of the pitch.

    A single red result says a test failed under fault. ``20 runs / 3 FAIL`` says how *often*,
    which is the difference between a race that reproduces one time in seven and a deterministic
    break -- and it names the runs, so the bundle for a failing iteration is one line away.
    """
    ledger = getattr(config, "chaos_ledger", None)
    plan = getattr(config, "chaos_plan", None)
    experiment = getattr(config, "chaos_experiment", None)
    if not ledger or not ledger.tests or not plan:
        return                               # nothing ran under a fault

    repeat = config.getoption("--chaos-repeat")
    terminalreporter.write_sep("=", "sonic-chaos")
    if plan.injectors:
        terminalreporter.write_line("fault: {}{}".format(
            plan.summary(), "   [dry-run]" if plan.dry_run else ""))
    conditions = getattr(config, "chaos_conditions", None) or []
    if conditions:
        terminalreporter.write_line("conditions: {}{}".format(
            config.getoption("--chaos-conditions"), "   [dry-run]" if plan.dry_run else ""))
        for c in conditions:
            terminalreporter.write_line("  " + c.describe())
    verdicts = getattr(config, "chaos_verdicts", {})
    if any(verdicts.values()):
        terminalreporter.write_line("verdicts: {} HELD, {} BROKE, {} INCONCLUSIVE".format(
            verdicts.get("HELD", 0), verdicts.get("BROKE", 0), verdicts.get("INCONCLUSIVE", 0)))
    if experiment:
        terminalreporter.write_line("experiment: {}  (replay with --chaos-seed {})".format(
            experiment.summary(), experiment.seed))
    selector = getattr(config, "chaos_oracle", None)
    if selector is not None:
        terminalreporter.write_line("oracle: {} checked after every test, {}s to recover".format(
            _oracle_label(selector), getattr(config, "chaos_recover", "?")))
    else:
        terminalreporter.write_line("oracle: disabled -- nothing checked that the databases agree")

    for nodeid, verdict, failed, bundles in ledger.lines():
        marker = "FAIL" if failed else "ok"
        terminalreporter.write_line("  {:<4} {:<62} {}".format(marker, nodeid[-62:], verdict))
        if failed:
            terminalreporter.write_line("       failed on: {}".format(", ".join(failed)))
        for path in bundles:
            terminalreporter.write_line("       repro: {}/repro.sh".format(path))

    flaky = ledger.flaky()
    if flaky:
        terminalreporter.write_line("")
        terminalreporter.write_line(
            "{} test(s) disagreed with themselves across {} runs -- an intermittent failure under "
            "fault is a finding, not noise.".format(len(flaky), repeat))
