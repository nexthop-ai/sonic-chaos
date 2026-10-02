"""sonic-chaos in sonic-mgmt: fault injection under the existing test suite.

Listed in ``tests/conftest.py``'s ``pytest_plugins``. The plugin itself lives in the ``sonic-chaos``
package (pip-installed into docker-sonic-mgmt, like ptf); this module only loads it, so the
sonic-mgmt tree carries no copy that could drift from the package.

With sonic-chaos installed, the plugin uses the testbed's ``duthosts``, waits for
``sanity_check`` before touching a switch, and adds each fault's expected syslog to
``loganalyzer``'s ignore list. With no ``--chaos*`` option and no ``chaos`` marker it requests no
fixture and runs no command, so registering it changes nothing for ordinary runs.

Without sonic-chaos installed, ordinary runs are unaffected too: the options still parse, and
only a run that asks for a fault stops, with the install hint.

    ./run_tests.sh -n vms-t1 -c platform_tests/test_port_toggle.py -e "--chaos kill=orchagent"
    @pytest.mark.chaos("kill", "orchagent:how=restart")
"""
import pytest

try:
    import sonic_chaos.pytest_plugin  # noqa: F401
except ImportError:
    _MISSING = True
    pytest_plugins = ()
else:
    _MISSING = False
    # The package registers the same module through its pytest11 entry point under this exact
    # name, so listing it here never loads it twice.
    pytest_plugins = ("sonic_chaos.pytest_plugin",)


if _MISSING:
    _FLAGS = ("--chaos-dry-run", "--chaos-strict")        # take no value
    _VALUED = ("--chaos", "--chaos-file", "--chaos-repeat", "--chaos-seed", "--chaos-oracle",
               "--chaos-recover", "--chaos-bundle-dir", "--chaos-profile", "--chaos-dut")
    _OPTIONS = _FLAGS + _VALUED

    def pytest_addoption(parser):
        group = parser.getgroup("sonic-chaos", "sonic-chaos fault injection (not installed)")
        for name in _FLAGS:
            group.addoption(name, action="store_true", default=False, help="needs: pip install sonic-chaos")
        for name in _VALUED:
            group.addoption(name, action="append", default=None, help="needs: pip install sonic-chaos")

    def pytest_configure(config):
        config.addinivalue_line("markers", "chaos(injector, spec, **params): needs sonic-chaos installed")
        used = [name for name in _OPTIONS if config.getoption(name)]
        if used:
            raise pytest.UsageError("{} given, but sonic-chaos is not installed in this environment: "
                                    "pip install sonic-chaos".format(", ".join(used)))

    def pytest_collection_modifyitems(config, items):
        for item in items:
            if item.get_closest_marker("chaos"):
                item.add_marker(pytest.mark.skip(reason="needs sonic-chaos installed (pip install sonic-chaos)"))
