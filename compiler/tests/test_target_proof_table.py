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
    with open(TABLE, encoding="utf-8") as handle:
        table = handle.read()
    assert audit.validate_target_proof_table(table) == []


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
