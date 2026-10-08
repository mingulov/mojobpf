# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the versioned Mojo SDK surface.

Pins the ``mojobpf`` Mojo package export list (modules, names,
signatures, versions) against the packaged tree, checks the static
import checker against the frontend-verified truth table, proves
every in-tree Mojo source stays within the pinned surface, and ties
the SDK document's test citations to live definitions. Any surface
drift fails here until the export list, the version, and the
document are reviewed together.

Deterministic on any host: only the standard library plus pytest's
plain function collection. The genuine-frontend import negatives
live in the packaging compatibility suite, which owns a compiler.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_sdk_surface.py``).
"""

import os
import re
import sys
import tomllib

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

import mojobpf  # noqa: E402
from mojobpf import sdk as sdk_module  # noqa: E402

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SDK_ROOT = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)
SDK_DOC = os.path.join(REPO_ROOT, "docs", "sdk.md")

# Checker truth table: (source, expected violation count).
# Seven rows are re-verified against the genuine Mojo 1.1.0
# frontend on every run of the packaging compatibility suite
# (``mojo build --emit llvm -I <sdk>``): the plain accept, the
# parenthesized-list accept, the ``as``-alias accept, the
# unknown name, the unknown module, the wrong-module name, and
# the deeper path
# (``tests/packaging/test_sdk_compat.py::test_frontend_import_negatives``).
# The remaining fourteen rows (module-only imports, ``std.*``
# ignores, the empty import, the alternate unknown-module
# spellings, and the core-module accept/reject rows) rest on
# one-time manual observation against the same frontend. Accept
# rows exit 0; reject rows exit 1 with a source-layer diagnostic.
CHECKER_CASES = (
    ("from mojobpf.packet import XDP_PASS\n", 0),
    ("from mojobpf.core import core_read_task_pid\n", 0),
    ("from mojobpf.core import core_exists_task_scx as ex\n", 0),
    ("from mojobpf.core import _nope\n", 1),
    ("from mojobpf.core import BPF_ANY\n", 1),
    ("from mojobpf.packet import (\n XDP_PASS,\n load_u8,\n)\n", 0),
    ("from mojobpf.packet import load_u8 as lu8\n", 0),
    ("from mojobpf import packet\n", 0),
    ("import mojobpf\n", 0),
    ("import mojobpf.packet\n", 0),
    ("import mojobpf.packet as pkt\n", 0),
    ("from std.sys import inlined_assembly\n", 0),
    ("import std.random\n", 0),
    ("from mojobpf.packet import _nope\n", 1),
    ("from mojobpf._impl import x\n", 1),
    ("from mojobpf import _impl\n", 1),
    ("import mojobpf._impl\n", 1),
    ("from mojobpf.packet import BPF_ANY\n", 1),
    ("from mojobpf.packet.sub import x\n", 1),
    ("import mojobpf.packet.sub\n", 1),
    ("from mojobpf.packet import\n", 1),
    # Parens inside string literals never join logical lines: a
    # forbidden import after such a line is still reported.
    ('x = f("a(b")\nfrom mojobpf import _impl\n', 1),
    ('x = f("a)b")\nfrom mojobpf import _impl\n', 1),
    ('print("unbalanced (")\nfrom mojobpf import _impl\n', 1),
    ("from mojobpf import packet  # (note)\n", 0),
)


def test_sdk_version_pinned():
    assert sdk_module.SDK_SCHEMA_VERSION == 1
    assert sdk_module.SDK_SURFACE_MINOR == 5
    assert sdk_module.SDK_VERSION == "1.5"
    assert sdk_module.SDK_VERSION == "%d.%d" % (
        sdk_module.SDK_SCHEMA_VERSION,
        sdk_module.SDK_SURFACE_MINOR,
    )
    assert re.match(r"^[0-9]+\.[0-9]+$", sdk_module.SDK_VERSION)


def test_tool_version_matches_packaging():
    assert mojobpf.__version__ == "0.2.0"
    with open(
        os.path.join(REPO_ROOT, "pyproject.toml"), "rb"
    ) as handle:
        project = tomllib.load(handle)["project"]
    assert project["name"] == "mojobpf"
    assert project["version"] == mojobpf.__version__


def test_export_list_matches_tree():
    parsed = sdk_module.parse_sdk_surface(SDK_ROOT)
    assert tuple(sorted(parsed)) == sdk_module.SDK_MODULES
    assert tuple(sorted(sdk_module.SDK_EXPORTS)) == (
        sdk_module.SDK_MODULES
    )
    assert tuple(sorted(sdk_module.SDK_SIGNATURES)) == (
        sdk_module.SDK_MODULES
    )
    for module in sdk_module.SDK_MODULES:
        assert parsed[module].names == (
            sdk_module.SDK_EXPORTS[module]
        ), module
        assert parsed[module].signatures == (
            sdk_module.SDK_SIGNATURES[module]
        ), module


def test_export_list_internally_consistent():
    for module in sdk_module.SDK_MODULES:
        names = sdk_module.SDK_EXPORTS[module]
        assert isinstance(names, tuple), module
        assert tuple(sorted(names)) == names, module
        assert len(set(names)) == len(names), module
        signatures = sdk_module.SDK_SIGNATURES[module]
        for name in names:
            assert name in signatures, (module, name)
        for key in signatures:
            top = key.split(".")[0]
            assert top in names, (module, key)


def test_no_underscore_names_exported():
    for module in sdk_module.SDK_MODULES:
        assert not module.startswith("_"), module
        for name in sdk_module.SDK_EXPORTS[module]:
            assert not name.startswith("_"), (module, name)
        for key in sdk_module.SDK_SIGNATURES[module]:
            assert not key.split(".")[-1].startswith("_"), (
                module, key,
            )
    package = os.path.join(SDK_ROOT, "mojobpf")
    for entry in sorted(os.listdir(package)):
        assert not entry.startswith("_"), entry
        assert entry.endswith(".mojo"), entry


def test_import_checker_truth_table():
    for text, expected in CHECKER_CASES:
        violations = sdk_module.check_mojo_imports(text)
        assert len(violations) == expected, (text, violations)
        for violation in violations:
            assert violation.line >= 1
            assert violation.statement
            assert violation.explanation


def test_import_checker_reports_lines_in_order():
    text = (
        "from mojobpf.packet import XDP_PASS\n"
        "from mojobpf.packet import _nope\n"
        "from mojobpf import _impl\n"
    )
    violations = sdk_module.check_mojo_imports(text)
    assert [item.line for item in violations] == [2, 3]


def _all_mojo_sources():
    found = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs.sort()
        if ".pixi" in dirs:
            dirs.remove(".pixi")
        for name in sorted(files):
            if name.endswith(".mojo"):
                found.append(os.path.join(root, name))
    return found


def test_in_tree_sources_within_surface():
    sources = _all_mojo_sources()
    assert len(sources) >= 70, len(sources)
    failures = []
    for path in sources:
        violations = sdk_module.check_mojo_file(path)
        if violations:
            failures.append(
                (os.path.relpath(path, REPO_ROOT), violations)
            )
    assert failures == []


def test_sdk_doc_citations_resolve():
    with open(SDK_DOC, encoding="utf-8") as handle:
        text = handle.read()
    tokens = sorted(
        set(re.findall(r"`(tests/\S+?\.py::\S+?)`", text))
    )
    assert tokens, "docs/sdk.md must cite runnable tests"
    for token in tokens:
        path, _, name = token.partition("::")
        full = os.path.join(REPO_ROOT, path)
        assert os.path.isfile(full), token
        with open(full, encoding="utf-8") as handle:
            body = handle.read()
        assert re.search(
            r"^def %s\(" % re.escape(name), body, re.M
        ), token


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )
    for name in names:
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
