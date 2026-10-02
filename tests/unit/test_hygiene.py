"""The package ships no lab: no testbed names, ticket numbers, lab CLIs or private paths.

Measurements in comments keep their explanation and lose the lab-specific name ("measured on a
lab switch"); lab specifics live in a site package.
"""
import os
import re

import _under_test

PRIVATE = re.compile(r"BUG-\d|TASK-\d|\blabcli(-go)? tb\b|hypersonic-ui|HWSKU-[AB]\b|"
                     r"/home/\w+")
SHIPPED = (".py", ".c", ".h", ".sh", ".yml", ".html", ".md", "Makefile")


def test_the_package_names_no_lab():
    hits = []
    for root, dirs, files in os.walk(_under_test.PKG_DIR):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "build")]
        for name in files:
            if not name.endswith(SHIPPED):
                continue
            path = os.path.join(root, name)
            with open(path, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    if PRIVATE.search(line):
                        where = os.path.relpath(path, _under_test.PKG_DIR)
                        hits.append("{}:{}: {}".format(where, n, line.strip()[:100]))
    assert not hits, "lab-specific names in the package:\n" + "\n".join(hits)
