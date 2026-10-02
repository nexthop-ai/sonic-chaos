import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _under_test  # noqa: E402

_under_test.bind()

pytest_plugins = ("pytester",)


def pytest_addoption(parser):
    parser.addoption("--update-golden", action="store_true", default=False,
                     help="rewrite tests/golden/transcripts/*.txt from the current code instead of comparing")
