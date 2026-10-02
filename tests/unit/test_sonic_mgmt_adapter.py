"""The sonic-mgmt adapter (integration/sonic-mgmt/tests/common/plugins/sonic_chaos) in both states.

Installed, it loads the real plugin. Not installed, it must leave every ordinary sonic-mgmt run
alone -- the adapter is listed in pytest_plugins for everyone -- and fail only a run that asks
for a fault.
"""
import os
import textwrap

import _under_test

INTEGRATION = os.path.join(_under_test.LIB_DIR, "integration", "sonic-mgmt")

FIXTURES = textwrap.dedent('''
    import pytest

    class FakeDut(object):
        hostname = "dut1"
        def shell(self, cmd, module_ignore_errors=False, **kwargs):
            return {"rc": 0, "stdout": "", "stderr": ""}

    @pytest.fixture(scope="module")
    def duthosts():
        return [FakeDut()]
''')


# "Not installed", even in an environment where it is: sonic_chaos cannot be imported, and the
# inner run is started with plugin autoload off so the package's pytest11 entry point cannot load it.
BLOCK = textwrap.dedent('''
    class _NotInstalled(object):
        def find_spec(self, name, path=None, target=None):
            if name == "sonic_chaos" or name.startswith("sonic_chaos."):
                raise ImportError("sonic_chaos is not installed (simulated by the test)")
    sys.meta_path.insert(0, _NotInstalled())
''')


def conftest(with_package):
    paths = [INTEGRATION] + ([_under_test.SRC_DIR] if with_package else [])
    return ("import sys\n" + ("" if with_package else BLOCK)
            + "".join("sys.path.insert(0, {!r})\n".format(p) for p in paths)
            + "pytest_plugins = ('tests.common.plugins.sonic_chaos',)\n" + FIXTURES)


TESTS = '''
import pytest

def test_plain():
    pass

@pytest.mark.chaos("kill", "orchagent")
def test_marked():
    pass
'''


def run(pytester, with_package, *args):
    pytester.makeconftest(conftest(with_package))
    pytester.makepyfile(test_suite=TESTS)
    # A clean interpreter path: the outer suite put src on sys.path, the inner one must not inherit it.
    env_path = os.environ.pop("PYTHONPATH", None)
    autoload = os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD")
    if not with_package:
        os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    try:
        return pytester.runpytest_subprocess("-p", "no:cacheprovider", *args)
    finally:
        if env_path is not None:
            os.environ["PYTHONPATH"] = env_path
        if autoload is None:
            os.environ.pop("PYTEST_DISABLE_PLUGIN_AUTOLOAD", None)
        else:
            os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = autoload


def test_installed_it_loads_the_real_plugin(pytester):
    result = run(pytester, True, "--chaos", "kill=orchagent", "--chaos-dry-run")
    result.assert_outcomes(passed=2)
    assert "sonic-chaos: kill" in result.stdout.str()


def test_missing_it_leaves_ordinary_runs_alone(pytester):
    result = run(pytester, False)
    result.assert_outcomes(passed=1, skipped=1)


def test_missing_it_refuses_a_fault_with_the_install_hint(pytester):
    result = run(pytester, False, "--chaos", "kill=orchagent")
    assert result.ret != 0
    assert "pip install sonic-chaos" in result.stderr.str() + result.stdout.str()


def test_missing_a_bare_flag_still_gets_the_install_hint(pytester):
    """--chaos-strict and --chaos-dry-run take no value; the stub must not turn them into a usage error."""
    for flag in ("--chaos-strict", "--chaos-dry-run"):
        result = run(pytester, False, flag)
        assert result.ret != 0
        assert "pip install sonic-chaos" in result.stderr.str() + result.stdout.str(), flag
