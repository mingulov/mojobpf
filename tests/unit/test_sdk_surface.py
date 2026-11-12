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
# Twenty-three rows are re-verified against the genuine Mojo 1.1.0
# frontend on every run of the packaging compatibility suite
# (``mojo build --emit llvm -I <sdk>``): the plain accept, the
# parenthesized-list accept, the ``load_u8 as lu8`` alias
# accept, the ``packet/_nope`` unknown name, the
# ``mojobpf._impl`` unknown module, the ``packet/BPF_ANY``
# wrong-module name, the ``packet.sub`` deeper path, the five
# multi-module plain-import rows, the four multi-module
# spaced-dots rows (one accept, three evil), the import-form
# semicolon accept/evil pair, the backslash accept, the
# from-form spaced-dots accept, the two single alias evils
# (from-form and import-form), and the string-hide accept
# (``tests/packaging/test_sdk_compat.py::test_frontend_import_negatives``;
# membership pinned by
# ``test_frontend_probes_cover_checker_rows_exactly``).
# The other thirty-five rows rest on one-time manual
# observation against the same frontend: the core accept,
# the core alias accept, the top-level ``_impl`` reject, the
# alternate unknown-module spellings (``core/_nope``,
# ``core/BPF_ANY``, import-form ``_impl`` and deeper path),
# module-only imports, ``std.*`` ignores, the empty import,
# the string-paren line-join rows, the static semicolon rows
# (from-form accept, string/triple-quote/paren cases), the
# static spaced-dots rows (import-form accept, evil), the
# semicolon+backslash row, the comment backslash row, and
# the non-joining invalid-word rows -- except the seven
# quote/comment masking rows, which pin static masking
# behavior only (no compiler on the audit host), where the
# single-quote rows use invalid-Mojo spellings (Mojo has
# no single-quote strings) that hostile input could carry.
# Accept rows exit 0; reject rows exit 1 with a source-layer
# diagnostic. Row counts are pinned by
# test_checker_case_count_matches_header: update this comment
# when adding rows.
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
    ("import mojobpf.packet, mojobpf.core\n", 0),
    ("import mojobpf.packet, mojobpf._impl\n", 1),
    ("import mojobpf._impl, mojobpf.packet\n", 1),
    ("import mojobpf.packet as pkt, mojobpf._impl as e\n", 1),
    ("from mojobpf._impl import x as y\n", 1),
    ("import mojobpf._impl as e\n", 1),
    ("import mojobpf.packet, std.random\n", 0),
    # Single-quote spans mask parens too, so a hostile line
    # cannot join away a forbidden import below it.
    ("x = '('\nfrom mojobpf import _impl\n", 1),
    ("x = '(')\nfrom mojobpf import _impl\n", 1),
    # Triple-quoted spans mask across lines; an import spelled
    # inside one is string content, never a statement.
    ('x = """("""\nfrom mojobpf import _impl\n', 1),
    ('x = """(\n"""\nfrom mojobpf import _impl\n', 1),
    ('x = """\nfrom mojobpf import _impl\n"""\n', 0),
    # '#' inside a string never starts a comment, and a quote
    # inside a comment never starts a string.
    ('x = "a#b"\nfrom mojobpf import _impl\n', 1),
    ("# don't\nfrom mojobpf import _impl\n", 1),
    # Semicolons separate statements (Mojo 1.1.0 accepts them):
    # every segment judges independently, so a forbidden import
    # after a ';' is still reported.
    ("import mojobpf.packet; import mojobpf.core\n", 0),
    ("import mojobpf.packet; from mojobpf._impl import x\n", 1),
    ("from mojobpf.packet import XDP_PASS;\n", 0),
    ('x = """a"""; from mojobpf import _impl\n', 1),
    ('x = "a;b"\nfrom mojobpf import _impl\n', 1),
    (
        "from mojobpf.packet import (\n XDP_PASS,\n load_u8,\n); "
        "from mojobpf import _impl\n",
        1,
    ),
    # A backslash continues the logical line, and dots may be
    # surrounded by whitespace: both are valid Mojo the checker
    # must accept, while still judging the joined statement.
    ("from mojobpf.packet import \\\n XDP_PASS\n", 0),
    ("from mojobpf . packet import XDP_PASS\n", 0),
    ("import mojobpf . packet\n", 0),
    ("from mojobpf . _impl import x\n", 1),
    ("import mojobpf.packet; \\\nfrom mojobpf import _impl\n", 1),
    # Spaced dots in 2nd+ comma-separated modules: the frontend
    # resolves them (rejecting evil), so the checker must too.
    ("import mojobpf.packet, mojobpf . _impl\n", 1),
    ("import mojobpf.packet, mojobpf . packet . sub\n", 1),
    ("import mojobpf.packet, mojobpf . _impl as e\n", 1),
    ("import mojobpf.packet, mojobpf . core\n", 0),
    # A backslash-newline inside a double-quoted string is string
    # content (the frontend compiles it): an import spelled there
    # is never a statement.
    (
        "def entry() -> Int32:\n"
        '    var x = "a\\\n'
        "from mojobpf import _impl\\\n"
        'b"\n'
        "    return Int32(0)\n",
        0,
    ),
    # A backslash does not continue a comment: the import below
    # is code and still reported.
    (
        "# trailing comment \\\nfrom mojobpf import _impl\n",
        1,
    ),
    # Words that are not dot-separated are invalid Mojo (the
    # frontend rejects them); they must never join into an
    # exported name by accident.
    ("from mojobpf import pack et\n", 1),
    ("from mojobpf.packet import XDP_PASS EXTRA\n", 1),
)


def test_sdk_version_pinned():
    assert sdk_module.SDK_SCHEMA_VERSION == 1
    assert sdk_module.SDK_SURFACE_MINOR == 8
    assert sdk_module.SDK_VERSION == "1.8"
    assert sdk_module.SDK_VERSION == "%d.%d" % (
        sdk_module.SDK_SCHEMA_VERSION,
        sdk_module.SDK_SURFACE_MINOR,
    )
    assert re.match(r"^[0-9]+\.[0-9]+$", sdk_module.SDK_VERSION)


def test_skb_helpers_exported():
    names = sdk_module.SDK_EXPORTS["helpers"]
    for name in (
        "BPF_FUNC_skb_load_bytes",
        "BPF_FUNC_skb_store_bytes",
        "bpf_skb_load_bytes",
        "bpf_skb_store_bytes",
    ):
        assert name in names, name
    signatures = sdk_module.SDK_SIGNATURES["helpers"]
    assert signatures["BPF_FUNC_skb_load_bytes"] == (
        "BPF_FUNC_skb_load_bytes = 26"
    )
    assert signatures["BPF_FUNC_skb_store_bytes"] == (
        "BPF_FUNC_skb_store_bytes = 9"
    )
    assert signatures["bpf_skb_load_bytes"] == (
        "@inline(.always) "
        "def bpf_skb_load_bytes( "
        "ctx: MutPointer[UInt8, MutAnyOrigin], "
        "offset: Int32, "
        "to: MutPointer[UInt32, MutAnyOrigin], "
        "length: Int32, ) -> Int64:"
    )
    assert signatures["bpf_skb_store_bytes"] == (
        "@inline(.always) "
        "def bpf_skb_store_bytes( "
        "ctx: MutPointer[UInt8, MutAnyOrigin], "
        "offset: Int32, "
        "src: MutPointer[UInt32, MutAnyOrigin], "
        "length: Int32, "
        "flags: Int64, ) -> Int64:"
    )


def test_tool_version_matches_packaging():
    assert mojobpf.__version__ == "1.0.0"
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


def test_checker_case_count_matches_header():
    # The header above documents the row budget by category;
    # update both together when adding rows.
    assert len(CHECKER_CASES) == 58, len(CHECKER_CASES)


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
