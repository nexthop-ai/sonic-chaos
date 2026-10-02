"""The Python API: faults as with-blocks and decorators, outside pytest or inside it.

    from sonic_chaos import Chaos, SshDut

    chaos = Chaos(SshDut("10.0.0.5"))              # takes the steady-state baseline
    with chaos.spin("orchagent:70", ttl=600):      # released on exit, even on ^C
        push_my_config()
    chaos.assert_recovers(within=90)

    @fault("kill=orchagent")                       # under pytest: the chaos marker
    def check_orchagent_restart(dut): ...          # outside pytest: gate, apply, call, release, check

    @register_injector("netem", lane="spine", positional=("port", "loss"))
    class Netem(Injector): ...                     # --chaos netem=Ethernet0:5 works everywhere

The pytest ``chaos`` fixture has the same methods; both come from ``FaultMethods`` below.
"""
import contextlib
import contextvars
import functools
import logging

from . import oracle
from .injector import ChaosSession, ChaosUsageError, get as get_injector, register

logger = logging.getLogger(__name__)

# The test function pytest is running right now, set by the plugin. @fault passes a call through
# only when the function it wraps IS that test: the plugin has already applied its marker faults.
# A @fault helper called from inside some other test is not the test, so it runs its own lifecycle.
CURRENT_TEST = contextvars.ContextVar("sonic_chaos_current_test", default=None)


class ChaosFinding(AssertionError):
    """The switch did not agree with itself after a fault, within the recovery budget."""


def split_fault(name, spec=""):
    """``("kill=orchagent")`` or ``("kill", "orchagent")`` -> ``("kill", "orchagent")``."""
    if not spec and "=" in name and not name.startswith("="):
        name, spec = name.split("=", 1)
    return name, spec


class FaultMethods(object):
    """Shared by ``Chaos`` and the pytest handle. The class it is mixed into provides the five
    members below."""

    duthosts = ()

    def inject(self, name, spec="", **params):
        raise NotImplementedError

    def release(self):
        raise NotImplementedError

    def recipe(self):
        raise NotImplementedError

    def _baseline(self):
        """``{hostname: {finding keys}}`` present before any fault."""
        raise NotImplementedError

    @contextlib.contextmanager
    def fault(self, name, spec="", **params):
        """Hold a fault for a with-block, released on exit.

            with chaos.fault("sai", "vlan:create:status=SAI_STATUS_TABLE_FULL"):
                duthost.shell("config vlan add 4001")
                chaos.assert_consistent()
        """
        name, spec = split_fault(name, spec)
        self.inject(name, spec, **params)
        try:
            yield self
        finally:
            self.release()

    def sai(self, spec="", **kw):
        return self.fault("sai", spec, **kw)

    def pause(self, spec="", **kw):
        return self.fault("pause", spec, **kw)

    def spin(self, spec="", **kw):
        return self.fault("spin", spec, **kw)

    def kill(self, spec="", **kw):
        return self.fault("kill", spec, **kw)

    def assert_consistent(self, within=0, only="parity"):
        """Fail unless every DUT's databases agree, minus the pre-fault baseline. ``within`` > 0
        gives recovery a polling window instead of one sample."""
        baseline = self._baseline()
        for dut in self.duthosts:
            base = baseline.get(dut.hostname) or set()
            if within:
                real, _n, _e, _s = oracle.wait_consistent(dut, only=only, timeout=within, baseline=base)
            else:
                real, _n, _s = oracle.gate(dut, only=only)
                real = oracle.subtract(real, base)
            if real:
                raise ChaosFinding("chaos: {} diverged under {}:\n{}".format(
                    dut.hostname, self.recipe(), oracle.format_divergences(real)))

    def assert_recovers(self, within=90, only="parity"):
        """After a fault is lifted, the databases must agree again within ``within`` seconds."""
        self.assert_consistent(within=within, only=only)


class Chaos(FaultMethods):
    """Faults against one or more switches, from plain Python.

    ``oracle`` is the invariant group whose steady state is recorded on construction, so what
    was already wrong is never reported as a finding; ``None`` skips it. ``dry_run`` logs every
    fault and touches nothing.
    """

    def __init__(self, duts, oracle="parity", dry_run=False, ptf=None):
        if hasattr(duts, "shell"):
            duts = [duts]
        self.duthosts = list(duts)
        self.dry_run = dry_run
        self.selector = oracle
        self.session = ChaosSession(self.duthosts, dry_run=dry_run, ptfhost=ptf)
        self.baseline = {}
        if oracle and not dry_run:
            self.take_baseline()

    def take_baseline(self):
        for dut in self.duthosts:
            real, _notices, _snap = oracle_module().gate(dut, only=self.selector)
            self.baseline[dut.hostname] = oracle_module().finding_keys(real)
            if real:
                logger.warning("[chaos] %s: %d divergence(s) before any fault; they are the baseline, "
                               "not findings", dut.hostname, len(real))
        return self.baseline

    def _baseline(self):
        return self.baseline

    def inject(self, name, spec="", **params):
        """Apply a fault now; it stays until ``release()`` (or the with-block ends)."""
        name, spec = split_fault(name, spec)
        injector = get_injector(name).from_spec(spec, **params)
        self.session.apply(injector)
        return injector

    def release(self):
        self.session.release_all()

    def status(self):
        return self.session.status()

    def recipe(self):
        return " ".join(inj.describe() for _dut, inj in self.session.applied) or "none"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()
        return False


def oracle_module():
    return oracle


def _find_dut(fn, args, kwargs):
    for key in ("dut", "duthost", "switch"):
        if hasattr(kwargs.get(key), "shell"):
            return kwargs[key]
    if hasattr(kwargs.get("duthosts"), "__iter__"):
        return list(kwargs["duthosts"])
    for value in args:
        if hasattr(value, "shell") and hasattr(value, "hostname"):
            return value
    raise ChaosUsageError("@fault on {}: pass the switch as `dut=` (or as the first argument that has "
                          ".shell and .hostname)".format(getattr(fn, "__name__", fn)))


def fault(name, spec="", recover_within=60, oracle="parity", **params):
    """Decorate a test or a plain function with one fault. Stacks; the innermost applies first.

    Under pytest it is exactly ``@pytest.mark.chaos(name, spec, **params)``: the plugin applies,
    measures, releases and grades, and the function runs untouched (its fixtures still resolve).
    Called outside pytest, the wrapper does the same itself: baseline, apply, call, release, then
    the ``oracle`` group must hold again within ``recover_within`` seconds or ``ChaosFinding``
    is raised.
    """
    name, spec = split_fault(name, spec)
    get_injector(name).from_spec(spec, **params)        # refuse a bad spec at decoration time

    def decorate(fn):
        try:
            import pytest
            fn = pytest.mark.chaos(name, spec, **params)(fn)
        except ImportError:
            pass
        # Stacked @fault: every layer calls the original function and applies the whole list
        # itself, so the inner layers' faults are never applied twice.
        target = getattr(fn, "__sonic_chaos_target__", fn)
        faults = list(getattr(fn, "__sonic_chaos_faults__", [])) + [(name, spec, params)]

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if CURRENT_TEST.get() is wrapper:
                return target(*args, **kwargs)
            chaos = Chaos(_find_dut(target, args, kwargs), oracle=oracle)
            try:
                for n, s, p in faults:
                    chaos.inject(n, s, **p)
                result = target(*args, **kwargs)
            finally:
                chaos.release()
            if oracle:
                chaos.assert_recovers(within=recover_within, only=oracle)
            return result

        wrapper.__wrapped__ = target          # pytest reads the fixture signature through this
        wrapper.__sonic_chaos_target__ = target
        wrapper.__sonic_chaos_faults__ = faults
        return wrapper
    return decorate


def register_injector(name, lane="custom", positional=(), defaults=None):
    """Register an Injector subclass under ``name``: ``--chaos <name>=...`` then works everywhere."""
    def decorate(cls):
        cls.name = name
        cls.lane = lane
        cls.positional = tuple(positional)
        if defaults is not None:
            cls.defaults = dict(defaults)
        return register(cls)
    return decorate


invariant = oracle.invariant
