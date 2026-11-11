# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Target-proof table validation (T4a-0).

Each migrated shape lands one approved row: shape, lowering
commit, equivalence report digest, approver, date. Rows without
an approver or evidence, unknown shapes, and duplicate shapes
are rejected; the table grows monotonically.

Runnable directly or under pytest. Standard library only.
"""

import importlib.util
import json
import os
import shutil

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
AUDIT = os.path.join(REPO_ROOT, "compiler", "audit.py")
TABLE = os.path.join(REPO_ROOT, "compiler", "target_proof_table.json")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def good_row(**overrides):
    row = {
        "shape": "classifier",
        "lowering_commit": "0" * 40,
        "equivalence_report_sha256": "1" * 64,
        "approver": "owner",
        "date": "2026-11-05",
    }
    row.update(overrides)
    return row


def test_empty_table_validates():
    audit = load_module("audit_table_empty", AUDIT)
    assert audit.validate_target_proof_table(
        json.dumps({"schema_version": 1, "rows": []})
    ) == []


def test_valid_row_accepted():
    audit = load_module("audit_table_good", AUDIT)
    assert audit.validate_target_proof_table(
        json.dumps(
            {"schema_version": 1, "rows": [good_row()]}
        )
    ) == ["classifier"]


def test_row_without_approver_rejected():
    audit = load_module("audit_table_noapprover", AUDIT)
    try:
        audit.validate_target_proof_table(
            json.dumps(
                {"schema_version": 1,
                 "rows": [good_row(approver="")]}
            )
        )
    except audit.TableError:
        pass
    else:
        raise AssertionError("row without approver must refuse")


def test_unknown_shape_rejected():
    audit = load_module("audit_table_unknown", AUDIT)
    try:
        audit.validate_target_proof_table(
            json.dumps(
                {"schema_version": 1,
                 "rows": [good_row(shape="nope")]}
            )
        )
    except audit.TableError:
        pass
    else:
        raise AssertionError("unknown shape must refuse")


def test_duplicate_shape_rejected():
    audit = load_module("audit_table_dupe", AUDIT)
    try:
        audit.validate_target_proof_table(
            json.dumps(
                {"schema_version": 1,
                 "rows": [good_row(), good_row()]}
            )
        )
    except audit.TableError:
        pass
    else:
        raise AssertionError("duplicate shape must refuse")


def _write_table(tmp, rows):
    path = os.path.join(tmp, "target_proof_table.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "rows": rows}, handle)
    return path


def test_qualified_needs_frozenset_and_row():
    # parsed_qualified is the conjunction: a mode flips only
    # when the frozenset names it AND the table approves it.
    # A frozenset entry without a row stays lane-a.
    import tempfile
    audit = load_module("audit_table_gate", AUDIT)
    tmp = tempfile.mkdtemp(prefix="proof-table-")
    try:
        table = _write_table(tmp, [good_row(shape="map")])
        assert audit.parsed_qualified(
            "map", table_path=table
        ) is True
        assert audit.parsed_qualified(
            "classifier", table_path=table
        ) is False
        assert audit.parsed_qualified(
            "classifier-loop", table_path=table
        ) is False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_qualified_malformed_table_raises():
    # A corrupt table fails loudly (no silent lane-a
    # downgrade, no silent parsed admission).
    import tempfile
    audit = load_module("audit_table_gatemalformed", AUDIT)
    tmp = tempfile.mkdtemp(prefix="proof-table-")
    try:
        table = os.path.join(tmp, "target_proof_table.json")
        with open(table, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        try:
            audit.parsed_qualified("map", table_path=table)
        except audit.TableError:
            pass
        else:
            raise AssertionError("malformed table must raise")
        try:
            audit.parsed_qualified(
                "map",
                table_path=os.path.join(tmp, "absent.json"),
            )
        except audit.TableError:
            pass
        else:
            raise AssertionError("absent table must raise")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_committed_rows_cover_qualified_modes():
    # The committed table approves exactly the frozenset: no
    # silent flip (frozenset without row) and no orphan row.
    audit = load_module("audit_table_cover", AUDIT)
    with open(TABLE, encoding="utf-8") as handle:
        approved = audit.validate_target_proof_table(handle.read())
    assert sorted(approved) == sorted(
        audit.PARSED_QUALIFIED_MODES
    ), approved
    for mode in audit.PARSED_QUALIFIED_MODES:
        assert audit.parsed_qualified(mode) is True, mode


def test_committed_row_evidence_is_verifiable():
    # Every row's digest is the release evidence record's
    # bytes (docs/evidence-1.0.0.md, frozen at the v1.0.0 tag
    # commit the rows name): anyone recomputes it without git.
    import hashlib
    audit = load_module("audit_table_evidence", AUDIT)
    with open(TABLE, encoding="utf-8") as handle:
        table = json.load(handle)
    evidence = os.path.join(
        REPO_ROOT, "docs", "evidence-1.0.0.md"
    )
    with open(evidence, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assert table["rows"], "no approved rows"
    for row in table["rows"]:
        assert row["equivalence_report_sha256"] == digest, row
        assert row["lowering_commit"] == (
            "cdc96199cdf20ccc1d7ca3f113c2428361b21c67"
        ), row
