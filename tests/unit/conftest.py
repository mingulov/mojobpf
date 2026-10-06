# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Pytest bootstrap for the unit suites.

Makes the ``mojobpf`` package in ``src/`` importable so the suites run
from a plain checkout as ``python3 -m pytest tests/unit``. Each suite is
also directly runnable as ``python3 tests/unit/test_<name>.py`` without
pytest (see the runner shim at the foot of each suite file).

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
