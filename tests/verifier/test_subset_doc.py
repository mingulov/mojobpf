# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Subset document linkage: the doc table matches the tests exactly.

``docs/supported-subset.md`` carries a generated case table. This
suite is the mechanical tie in both directions:

* every row names live tests: each ``file::test`` entry must exist
  as a ``def`` in its file, and every ``test_*`` token mentioned
  anywhere in the document must be defined in one of the linked
  test files;
* every test change invalidates the doc: each row pins the short
  ``sha256`` of its fixture and of its test files, so editing a
  fixture or a test without refreshing the doc fails here;
* every fixture is listed: the ``# case:`` ids across
  ``tests/compile/subset/*.mojo`` must equal the table's case ids,
  so adding or renaming a fixture without refreshing the doc fails
  here.

The check is structural: it ties names and bytes, it does not run
the named tests (the suites run separately). A new test function
with no fixture and no doc mention is outside this check by
design; name it in the document to bring it inside.

Refresh the table after any intentional change with ``python3
tests/verifier/test_subset_doc.py --refresh`` and commit the doc
together with the change. Runnable directly or under any
``test_``-style runner. Standard library only.
"""

import hashlib
import os
import re
import sys

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
DOC_PATH = os.path.join(REPO_ROOT, "docs", "supported-subset.md")
SUBSET_DIR = os.path.join(REPO_ROOT, "tests", "compile", "subset")

BEGIN_MARKER = "<!-- SUBSET-TABLE-BEGIN -->"
END_MARKER = "<!-- SUBSET-TABLE-END -->"

AUDIT_TEST = "tests/compile/subset/test_subset_audit.py"
KERNEL_TEST = "tests/verifier/test_subset_kernel.py"
OPT_TEST = "tests/ir/test_optimization_invariants.py"

# Rows without their own fixture: the fixture cell is fixed prose.
# (The reused file's bytes stay pinned by its owning row.)
DERIVED_SOURCE = {
    "unoptimized-stack": (
        "(subset_stack_array.mojo compiled with -O0; bytes pinned "
        "by the stack-array row)"
    ),
}

# Canonical rows: (case id, result, layer, evidence,
# fixture stem or None for inline/derived source,
# ((file, test), ...)).
CANON = (
    (
        "loop-sum", "accept", "kernel",
        "test-run actions match the oracle on all frames",
        "subset_loop_sum",
        (
            (AUDIT_TEST, "test_positive_programs_validate"),
            (KERNEL_TEST, "test_loop_sum"),
        ),
    ),
    (
        "call-inline", "accept", "kernel",
        "plain helper inlined; test-run actions match",
        "subset_call_inline",
        (
            (AUDIT_TEST, "test_positive_shapes"),
            (KERNEL_TEST, "test_call_inline"),
        ),
    ),
    (
        "stack-array", "accept", "kernel",
        "initialized array promotes (no alloca); actions match",
        "subset_stack_array",
        (
            (AUDIT_TEST, "test_positive_shapes"),
            (KERNEL_TEST, "test_stack_array"),
        ),
    ),
    (
        "casts", "accept", "kernel",
        "narrow/widen round trip; test-run actions match",
        "subset_casts",
        (
            (AUDIT_TEST, "test_positive_programs_validate"),
            (KERNEL_TEST, "test_casts"),
        ),
    ),
    (
        "checked-arith", "accept", "kernel",
        "wrap and headroom checks; test-run actions match",
        "subset_checked_arith",
        (
            (AUDIT_TEST, "test_positive_programs_validate"),
            (KERNEL_TEST, "test_checked_arith"),
        ),
    ),
    (
        "loop-pressure", "accept", "kernel",
        "frame spills within the 512-byte budget; total exact",
        "subset_loop_pressure",
        (
            (AUDIT_TEST, "test_loop_pressure_frame_within_budget"),
            (KERNEL_TEST, "test_loop_pressure"),
        ),
    ),
    (
        "deep-stack", "reject", "backend",
        "llc exits 1: BPF stack limit is exceeded, no object",
        "subset_deep_stack",
        (
            (AUDIT_TEST, "test_deep_stack_refused_by_backend"),
            (OPT_TEST, "test_backend_failure_surfaced_explicitly"),
        ),
    ),
    (
        "dynamic-stack", "reject", "source",
        "frontend: cannot use a dynamic value in a parameter list",
        None,
        ((AUDIT_TEST, "test_dynamic_stack_rejected_at_source"),),
    ),
    (
        "unoptimized-stack", "reject", "preflight",
        "MBPF310: unoptimized IR keeps stack allocations",
        None,
        ((OPT_TEST, "test_no_optimization_rejected_explicitly"),),
    ),
    (
        "escape-value", "reject", "preflight",
        "MBPF314: value must come from the prepared value slot",
        "subset_escape_value",
        ((AUDIT_TEST, "test_preflight_negatives_rejected"),),
    ),
    (
        "bad-helper", "reject", "preflight",
        "MBPF306: helper calls never use inline assembly",
        "subset_bad_helper",
        ((AUDIT_TEST, "test_preflight_negatives_rejected"),),
    ),
    (
        "ptr-erase", "reject", "source",
        "frontend: rebind input type does not match result type",
        None,
        ((AUDIT_TEST, "test_ptr_erase_rejected_at_source"),),
    ),
    (
        "oob-store", "reject", "kernel",
        "verifier: invalid access to map value off=8 size=8",
        "subset_oob_store",
        ((KERNEL_TEST, "test_oob_store_rejected_by_verifier"),),
    ),
)

CASE_HEADER_RE = re.compile(r"^# case: (\S+)\s*$")
DEF_RE_TEMPLATE = r"^def %s\("
TEST_TOKEN_RE = re.compile(r"\btest_[a-z0-9_]+\b")


def sha8_of_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()[:8]


def repo_path(relpath):
    return os.path.join(REPO_ROOT, relpath)


def render_table():
    """Render the canonical markdown table block (markers included)."""
    lines = [BEGIN_MARKER]
    lines.append(
        "| case | result | layer | evidence | fixture | tests |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for case, result, layer, evidence, stem, tests in CANON:
        if case in DERIVED_SOURCE:
            fixture_cell = DERIVED_SOURCE[case]
        elif stem is None:
            fixture_cell = "(inline source in test)"
        else:
            fixture_cell = "%s.mojo (%s)" % (
                stem, sha8_of_file(repo_path(
                    "tests/compile/subset/%s.mojo" % stem
                )),
            )
        test_cells = []
        for relpath, func in tests:
            test_cells.append(
                "%s::%s (%s)"
                % (relpath, func, sha8_of_file(repo_path(relpath)))
            )
        lines.append(
            "| %s | %s | %s | %s | %s | %s |"
            % (case, result, layer, evidence, fixture_cell,
               "<br>".join(test_cells))
        )
    lines.append(END_MARKER)
    return "\n".join(lines) + "\n"


def read_doc():
    if not os.path.isfile(DOC_PATH):
        raise AssertionError("missing subset document: %s" % DOC_PATH)
    with open(DOC_PATH, "r", encoding="utf-8") as handle:
        return handle.read()


def extract_block(text):
    begin = text.find(BEGIN_MARKER)
    end = text.find(END_MARKER)
    assert begin != -1 and end != -1 and begin < end, (
        "document must contain the generated table markers"
    )
    return text[begin : end + len(END_MARKER)] + "\n"


def fixture_case_ids():
    """Map fixture stem -> case id from every # case: header."""
    found = {}
    names = sorted(
        name for name in os.listdir(SUBSET_DIR) if name.endswith(".mojo")
    )
    assert names, "no subset fixtures found"
    for name in names:
        with open(os.path.join(SUBSET_DIR, name), "r",
                  encoding="utf-8") as handle:
            ids = [
                match.group(1)
                for line in handle
                for match in (CASE_HEADER_RE.match(line.rstrip("\n")),)
                if match
            ]
        assert len(ids) == 1, (
            "%s must carry exactly one # case: header, found %r"
            % (name, ids)
        )
        stem = name[: -len(".mojo")]
        assert stem not in found or found[stem] == ids[0]
        found[stem] = ids[0]
    return found


def check_links():
    """Assert every table row names live files, tests and hashes."""
    text = read_doc()
    assert extract_block(text) == render_table(), (
        "subset table is stale: run python3 "
        "tests/verifier/test_subset_doc.py --refresh"
    )
    by_stem = fixture_case_ids()
    table_ids = set(row[0] for row in CANON)
    assert set(by_stem.values()) == (
        table_ids - {"dynamic-stack", "ptr-erase"} - set(DERIVED_SOURCE)
    ), (
        "fixture case ids %r must equal the table ids %r"
        % (sorted(by_stem.values()), sorted(table_ids))
    )
    for case, _result, _layer, _evidence, stem, tests in CANON:
        if stem is not None:
            assert by_stem.get(stem) == case, (
                "%s.mojo header names %r, table says %r"
                % (stem, by_stem.get(stem), case)
            )
        for relpath, func in tests:
            path = repo_path(relpath)
            assert os.path.isfile(path), "missing test file: %s" % relpath
            with open(path, "r", encoding="utf-8") as handle:
                body = handle.read()
            assert re.search(DEF_RE_TEMPLATE % re.escape(func), body,
                             re.MULTILINE), (
                "%s must define %s" % (relpath, func)
            )
    linked = set()
    for _c, _r, _l, _e, _s, tests in CANON:
        for relpath, _func in tests:
            with open(repo_path(relpath), "r",
                      encoding="utf-8") as handle:
                linked.update(
                    match.group(1)
                    for match in re.finditer(r"^def (test_[a-z0-9_]+)\(",
                                             handle.read(), re.MULTILINE)
                )
    stems = {os.path.basename(__file__)[: -len(".py")]}
    for _c, _r, _l, _e, _s, tests in CANON:
        for relpath, _func in tests:
            stems.add(os.path.basename(relpath)[: -len(".py")])
    for token in sorted(set(TEST_TOKEN_RE.findall(text))):
        if token in stems:
            continue
        assert token in linked, (
            "document cites %s, which no linked test file defines"
            % token
        )


def test_subset_doc_current():
    check_links()
    print(
        "PASS subset doc table matches %d rows + %d fixtures"
        % (len(CANON), len(fixture_case_ids()))
    )


def refresh():
    text = read_doc()
    block = extract_block(text)
    rendered = render_table()
    if block == rendered:
        print("subset doc table already current (%d rows)" % len(CANON))
        return False
    updated = text.replace(block, rendered)
    with open(DOC_PATH, "w", encoding="utf-8") as handle:
        handle.write(updated)
    print("refreshed subset doc table (%d rows)" % len(CANON))
    return True


def main(argv):
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    if len(argv) == 2 and argv[1] == "--refresh":
        refresh()
        return 0
    if len(argv) != 1:
        print("usage: test_subset_doc.py [--refresh]")
        return 2
    try:
        test_subset_doc_current()
    except AssertionError as exc:
        print("FAIL test_subset_doc_current: %s" % exc)
        return 1
    print("PASS test_subset_doc_current")
    print("subset doc: names and bytes match the linked tests")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
