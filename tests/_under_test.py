"""Which code the suite tests: the sonic_chaos package in ``src``.

The source tree is put first on ``sys.path``, so the suite tests the checkout it lives in whether
or not the package is also installed (CI runs it both ways). Installed, the package's ``pytest11``
entry point also loads the plugin into this outer session; the suite is written to hold either way,
and tests that need "not installed" simulate it rather than assume it.

``PLUGIN_BOOTSTRAP`` is the conftest a pytester subprocess uses to load the real pytest plugin.
It registers ``sonic_chaos.pytest_plugin`` explicitly, so it works whether or not the package's
``pytest11`` entry point is installed.
"""
import os
import sys

LIB_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_DIR = os.path.dirname(LIB_DIR)
SRC_DIR = os.path.join(LIB_DIR, "src")
PKG_DIR = os.path.join(SRC_DIR, "sonic_chaos")


def bind():
    """Put ``src`` first on ``sys.path`` and import the package from it. Idempotent."""
    if SRC_DIR not in sys.path:
        sys.path.insert(0, SRC_DIR)
    import sonic_chaos
    loaded = os.path.dirname(os.path.abspath(sonic_chaos.__file__))
    if loaded != PKG_DIR:
        raise RuntimeError("sonic_chaos imported from {}, expected {}".format(loaded, PKG_DIR))
    return sonic_chaos


PLUGIN_BOOTSTRAP = '''
import sys
sys.path.insert(0, {src!r})
pytest_plugins = ("sonic_chaos.pytest_plugin",)
'''.format(src=SRC_DIR)
