# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Pytest bootstrap for the unit suites.

Makes the ``mojobpf`` package in ``src/`` importable so the suites run
from a plain checkout as ``python3 -m pytest tests/unit``. Each suite
file also carries a ``__main__`` runner shim for dependency-free
smoke runs (``python3 tests/unit/test_<name>.py``), but the shim
passes no arguments: tests needing pytest fixtures or
parametrization report as failures there, so a full run of every
suite requires pytest and the ``test_lanes`` runner stays the
supported entry point.

Test-invocation pin: pytest==9.0.2. The pin lives here as a comment
until packaging owns dependency pins; the suites themselves need only
the standard library plus pytest's plain function collection.
"""

import os
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)
