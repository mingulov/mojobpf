# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Capability coverage ledger materializer tests.

Every test here runs the materializer against synthetic inline
inputs, except the drift test, which checks the committed ledger
against the in-repo registry and matrix only. The live API input
lives in the sibling libbpf-mojo repository, which this suite
must not depend on; full byte-regeneration is an executor
receipt step. Negative tests pin each fail-closed rule with a
minimal violating input.
"""

import hashlib
import importlib.util
import json
import os

import pytest

from jsonschema import Draft202012Validator

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
TOOL_PATH = os.path.join(
    ROOT, "tools", "validation", "materialize_coverage.py"
)
EXTRACTOR_PATH = os.path.join(
    ROOT, "tools", "validation", "extract_api_rows.py"
)
SCHEMA_PATH = os.path.join(
    ROOT, "schemas", "coverage-ledger.schema.json"
)
REGISTRY_PATH = os.path.join(ROOT, "capabilities", "registry.json")
MATRIX_PATH = os.path.join(ROOT, "capabilities", "target-matrix.json")
LEDGER_PATH = os.path.join(ROOT, "capabilities", "coverage-ledger.json")
EXTRACT_PATH = os.path.join(ROOT, "capabilities", "api-rows.json")

PROVENANCE = {
    "repo": "https://github.com/mingulov/libbpf-mojo",
    "rev": "ab" * 20,
    "path": "docs/api-coverage.json",
}

LAYERS = (
    "source",
    "native_host",
    "mojo_host",
    "installed_host",
    "target_runtime",
    "binary_abi",
)


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "materialize_coverage", TOOL_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_TOOL = _load_tool()
LEDGER_FORMAT_VERSION = _TOOL.LEDGER_FORMAT_VERSION
CoverageError = _TOOL.CoverageError
materialize_coverage = _TOOL.materialize_coverage


def _load_extractor():
    spec = importlib.util.spec_from_file_location(
        "extract_api_rows", EXTRACTOR_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_EXTRACTOR = _load_extractor()


def _record(**over):
    base = {
        "id": "helper:bpf_test",
        "family": "helpers",
        "owner_task": "X-HELPERS",
        "implementation_state": "PLANNED",
        "evidence_level": "none",
        "evidence_refs": [],
        "scope_required": True,
        "targets_required": ["linux-x86-64"],
        "userspace_api_surface": "not-applicable",
        "applicability_predicate": "test predicate",
        "upstream_source_refs": ["test:ref"],
        "blocker": None,
        "positive_tests": ["T-01"],
        "negative_tests": ["N-01"],
        "interaction_tests": [],
        "cost_cases": [],
        "program_types": ["xdp"],
        "attach_types": [],
        "link_types": [],
        "map_types": [],
        "helpers_or_kfuncs": [
            {"name": "bpf_test", "kind": "helper", "callable": True}
        ],
        "callable_context_predicates": ["ctx-ok"],
    }
    base.update(over)
    return base


def _row(symbol, **over):
    base = {
        "id": f"function:{symbol}",
        "workflow": "objects",
        "applicability": "required",
        "blocker": {
            "reason": "not implemented",
            "next_action": "implement it",
        },
        "raw_declaration": {"status": "ABSENT", "refs": []},
        "forwarding_adapter": {"status": "ABSENT", "refs": []},
        "typed_workflow": {"status": "ABSENT", "refs": []},
        "tests": {
            "positive_refs": [],
            "negative_refs": [],
            "interaction_refs": [],
        },
        "evidence_cells": [
            {
                "id": layer,
                "layer": layer,
                "outcome": "NOT_RUN",
                "target_profile": "test-profile",
                "evidence_refs": [],
            }
            for layer in LAYERS
        ],
    }
    base.update(over)
    return base


def _pass_row(symbol):
    return _row(
        symbol,
        blocker=None,
        raw_declaration={"status": "SOURCE_PRESENT", "refs": []},
        forwarding_adapter={
            "status": "SOURCE_PRESENT_COMPLETE",
            "refs": [],
        },
        typed_workflow={"status": "SOURCE_PRESENT_COMPLETE", "refs": []},
        evidence_cells=[
            {
                "id": layer,
                "layer": layer,
                "outcome": "PASS",
                "target_profile": (
                    "test-runtime-profile"
                    if layer == "target_runtime"
                    else "test-profile"
                ),
                "evidence_refs": [],
            }
            for layer in LAYERS
        ],
    )


def _inputs(records, matrix=None, api_rows=None, packages=None):
    registry = {
        "records": records,
        "packages": (
            packages
            if packages is not None
            else [
                {
                    "id": "X-HELPERS",
                    "title": "Complete typed helper coverage",
                },
                {
                    "id": "U-OBJECT",
                    "title": "Object, program, BTF and owned-resource API",
                },
            ]
        ),
        "blockers": [],
    }
    if matrix is None:
        matrix = {
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {"linux-x86-64": ["test-profile"]},
            "runtime_profiles": {"linux-x86-64": ["test-runtime-profile"]},
        }
    api = {
        "schema_version": 1,
        "api_provenance": dict(
            PROVENANCE, artifact_sha256="c" * 64
        ),
    }
    api.update(api_rows or {})
    return registry, matrix, api


def _materialize(registry, matrix, api_rows):
    return materialize_coverage(registry, matrix, api_rows)


def _schema():
    return _TOOL._load_json_strict(SCHEMA_PATH)


def test_minimal_registry_yields_expected_cells():
    registry, matrix, api = _inputs(
        [
            _record(id="helper:a", owner_task="X-HELPERS"),
            _record(
                id="api:sym_b",
                family="userspace-object",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            ),
        ],
        api_rows={"rows": [_pass_row("sym_b")]},
    )
    ledger = _materialize(registry, matrix, api)
    assert ledger["ledger_version"] == LEDGER_FORMAT_VERSION
    assert ledger["inputs"]["record_count"] == 2
    assert ledger["inputs"]["api_provenance"] == PROVENANCE
    assert ledger["inputs"]["api_artifact_sha256"] == "c" * 64
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert set(by_id) == {
        "helper:a@linux-x86-64#producer",
        "api:sym_b@linux-x86-64#producer",
        "api:sym_b@linux-x86-64#consumer",
    }
    assert by_id["helper:a@linux-x86-64#producer"]["status"] == "OPEN"
    producer = by_id["api:sym_b@linux-x86-64#producer"]
    assert producer["status"] == "QUALIFIED"
    assert producer["implementation"]["package_title"] == (
        "Object, program, BTF and owned-resource API"
    )
    assert producer["qualification"]["positive_tests"] == ["T-01"]
    assert producer["obligations"]["lifecycle"] == []
    assert producer["legal_context"]["program_types"] == ["xdp"]
    assert producer["legal_context"]["helpers_or_kfuncs"] == [
        {"name": "bpf_test", "kind": "helper", "callable": True}
    ]
    assert producer["applicability"]["predicate"] == "test predicate"
    consumer = by_id["api:sym_b@linux-x86-64#consumer"]
    assert consumer["status"] == "QUALIFIED"
    assert consumer["consumer"]["api_row"] == "function:sym_b"
    assert consumer["consumer"]["verdict"]["raw_status"] == (
        "SOURCE_PRESENT"
    )
    assert all(
        entry["outcome"] == "PASS"
        for entry in consumer["consumer"]["verdict"]["layers"]
    )


def test_input_hashes_match_bytes():
    registry, matrix, api = _inputs([_record()])
    ledger = _materialize(registry, matrix, api)
    assert ledger["inputs"]["registry_sha256"] == hashlib.sha256(
        json.dumps(registry, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert ledger["inputs"]["matrix_sha256"] == hashlib.sha256(
        json.dumps(matrix, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert ledger["inputs"]["api_coverage_sha256"] == hashlib.sha256(
        json.dumps(api, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_matrix_blocked_target_yields_open_with_rationale():
    registry, matrix, api = _inputs(
        [_record(id="helper:a", targets_required=["linux-x86-64"])],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "BLOCKED_HARDWARE",
                    "detail": "no ARM guest",
                    "next_action": "provision guest",
                    "source_refs": ["ci:test"],
                }
            ],
        },
    )
    registry["records"][0]["targets_required"] = [
        "linux-x86-64",
        "linux-aarch64-physical",
    ]
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    cell = by_id["helper:a@linux-aarch64-physical#producer"]
    assert cell["status"] == "OPEN"
    assert cell["rationale"]["status"] == "BLOCKED_HARDWARE"
    assert cell["rationale"]["next_action"] == "provision guest"


def test_matrix_excluded_target_yields_not_applicable():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "reserved combination",
                    "source_refs": ["upstream:doc"],
                }
            ],
        },
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    cell = by_id["helper:a@linux-aarch64-physical#producer"]
    assert cell["status"] == "NOT_APPLICABLE"
    assert "reserved combination" in cell["rationale"]["detail"]


def test_unjustified_exclusion_fails():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "excluded but uncited",
                    "source_refs": [],
                }
            ],
        },
    )
    with pytest.raises(CoverageError, match="unjustified"):
        _materialize(registry, matrix, api)


def test_record_blocker_does_not_excuse_absent_target():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
                blocker={
                    "status": "PLANNED",
                    "detail": "record excuse",
                    "next_action": "fix record",
                },
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {"linux-x86-64": ["test-profile"]},
            "runtime_profiles": {"linux-x86-64": ["test-runtime-profile"]},
        },
    )
    with pytest.raises(CoverageError, match="linux-aarch64-physical"):
        _materialize(registry, matrix, api)


def test_contradictory_matrix_fails():
    registry, matrix, api = _inputs(
        [_record(id="helper:a")],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-x86-64",
                    "status": "BLOCKED_HARDWARE",
                    "detail": "contradiction",
                }
            ],
        },
    )
    with pytest.raises(CoverageError, match="both provisioned and absent"):
        _materialize(registry, matrix, api)


def test_absent_target_without_excuse_fails():
    registry, matrix, api = _inputs(
        [_record(targets_required=["linux-x86-64", "linux-nope"])]
    )
    with pytest.raises(CoverageError, match="linux-nope"):
        _materialize(registry, matrix, api)


def test_unowned_record_fails():
    registry, matrix, api = _inputs([_record(owner_task="")])
    with pytest.raises(CoverageError, match="unowned"):
        _materialize(registry, matrix, api)


def test_unknown_owner_fails():
    registry, matrix, api = _inputs([_record(owner_task="ZZ-UNKNOWN")])
    with pytest.raises(CoverageError, match="unknown owner"):
        _materialize(registry, matrix, api)


def test_unknown_surface_fails():
    registry, matrix, api = _inputs(
        [_record(userspace_api_surface="mystery-surface")]
    )
    with pytest.raises(CoverageError, match="unknown userspace surface"):
        _materialize(registry, matrix, api)


def test_duplicate_record_ids_fail():
    registry, matrix, api = _inputs(
        [_record(id="helper:dup"), _record(id="helper:dup")]
    )
    with pytest.raises(CoverageError, match="duplicate record"):
        _materialize(registry, matrix, api)


def test_duplicate_targets_fail():
    registry, matrix, api = _inputs(
        [_record(targets_required=["linux-x86-64", "linux-x86-64"])]
    )
    with pytest.raises(CoverageError, match="duplicate target"):
        _materialize(registry, matrix, api)


def test_duplicate_api_row_ids_fail():
    registry, matrix, api = _inputs(
        [_record()],
        api_rows={"rows": [_row("x"), _row("x")]},
    )
    with pytest.raises(CoverageError, match="duplicate API row"):
        _materialize(registry, matrix, api)


def test_misshapen_record_fields_fail():
    registry, matrix, api = _inputs(
        [_record(targets_required={"linux-x86-64": False})]
    )
    with pytest.raises(CoverageError, match="targets_required"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [_record(positive_tests="T-01")]
    )
    with pytest.raises(CoverageError, match="positive_tests"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [_record(program_types="xdp")]
    )
    with pytest.raises(CoverageError, match="program_types"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [_record(helpers_or_kfuncs=[{"name": "bpf_test"}])]
    )
    with pytest.raises(CoverageError, match="helpers_or_kfuncs"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [
            _record(
                helpers_or_kfuncs=[
                    {"name": "x", "kind": "spell", "callable": True}
                ]
            )
        ]
    )
    with pytest.raises(CoverageError, match="helpers_or_kfuncs"):
        _materialize(registry, matrix, api)


def test_misshapen_registry_containers_fail():
    for registry in (
        {"records": {}, "packages": [], "blockers": []},
        {"records": [], "packages": {}, "blockers": []},
        {"records": [], "packages": [], "blockers": {}},
        {"records": [], "packages": ["X-HELPERS"], "blockers": []},
    ):
        _, matrix, api = _inputs([_record()])
        with pytest.raises(CoverageError, match="records|package|blockers"):
            _materialize(registry, matrix, api)


def test_misshapen_identities_fail():
    for field, bad in (
        ("id", ["helper:a"]),
        ("owner_task", ["X-HELPERS"]),
        ("family", ["helpers"]),
        ("userspace_api_surface", ["library-symbol"]),
        ("implementation_state", ["PLANNED"]),
        ("evidence_level", ["none"]),
    ):
        registry, matrix, api = _inputs([_record(**{field: bad})])
        with pytest.raises(CoverageError):
            _materialize(registry, matrix, api)


def test_record_without_cells_fails_as_lost():
    registry, matrix, api = _inputs([_record(targets_required=[])])
    with pytest.raises(CoverageError, match="no cells"):
        _materialize(registry, matrix, api)


def test_non_api_library_symbol_fails():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:sneaky",
                userspace_api_surface="library-symbol",
            )
        ],
        api_rows={"rows": [_pass_row("sneaky")]},
    )
    with pytest.raises(CoverageError, match="must use an api: record"):
        _materialize(registry, matrix, api)


def test_missing_consumer_row_fails():
    registry, matrix, api = _inputs(
        [
            _record(
                id="api:lonely",
                userspace_api_surface="library-symbol",
            )
        ]
    )
    with pytest.raises(CoverageError, match="lonely"):
        _materialize(registry, matrix, api)


def test_dangling_consumer_row_fails():
    registry, matrix, api = _inputs(
        [_record()], api_rows={"rows": [_row("ghost")]}
    )
    with pytest.raises(CoverageError, match="ghost"):
        _materialize(registry, matrix, api)


def test_malformed_cost_cases_fail():
    for bad in ([""], ["   "], [42], ["ok", ""], ["lowercase"]):
        registry, matrix, api = _inputs([_record(cost_cases=bad)])
        with pytest.raises(CoverageError, match="cost"):
            _materialize(registry, matrix, api)


def test_valid_cost_cases_survive_on_cells():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                cost_cases=["COST-01"],
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "BLOCKED_HARDWARE",
                    "detail": "no ARM guest",
                }
            ],
        },
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["helper:a@linux-x86-64#producer"]["obligations"][
        "cost_cases"
    ] == ["COST-01"]
    assert by_id["helper:a@linux-aarch64-physical#producer"][
        "obligations"
    ]["cost_cases"] == ["COST-01"]


def test_producer_without_evidence_refs_stays_open():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=[],
            )
        ]
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["helper:a@linux-x86-64#producer"]["status"] == "OPEN"


def test_blocked_producer_stays_open_with_rationale():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
                blocker={
                    "status": "BLOCKED_UPSTREAM",
                    "detail": "upstream gap",
                    "next_action": "wait",
                },
            )
        ]
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    cell = by_id["helper:a@linux-x86-64#producer"]
    assert cell["status"] == "OPEN"
    assert cell["rationale"]["status"] == "BLOCKED_UPSTREAM"


def test_family_blocker_blocks_qualification():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                family="net-afxdp",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            )
        ]
    )
    registry["blockers"] = [
        {
            "id": "net-afxdp-userspace",
            "family": "net-afxdp",
            "status": "BLOCKED_UPSTREAM",
            "detail": "userspace outside libbpf",
            "next_action": "bind companion",
            "source_refs": ["libbpf:libbpf.map@1.7.0"],
        }
    ]
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    cell = by_id["helper:a@linux-x86-64#producer"]
    assert cell["status"] == "OPEN"
    assert cell["rationale"]["status"] == "BLOCKED_UPSTREAM"
    assert ledger["blockers"] == [
        {
            "id": "net-afxdp-userspace",
            "family": "net-afxdp",
            "status": "BLOCKED_UPSTREAM",
            "matched_cells": 1,
        }
    ]


def test_unmatched_family_blocker_stays_visible():
    registry, matrix, api = _inputs([_record(id="helper:a")])
    registry["blockers"] = [
        {
            "id": "net-afxdp-userspace",
            "family": "net-afxdp",
            "status": "BLOCKED_UPSTREAM",
            "detail": "userspace outside libbpf",
            "next_action": "bind companion",
            "source_refs": ["libbpf:libbpf.map@1.7.0"],
        }
    ]
    ledger = _materialize(registry, matrix, api)
    assert ledger["blockers"] == [
        {
            "id": "net-afxdp-userspace",
            "family": "net-afxdp",
            "status": "BLOCKED_UPSTREAM",
            "matched_cells": 0,
        }
    ]


def test_consumer_needs_library_verdict():
    registry, matrix, api = _inputs(
        [
            _record(
                id="api:sym_b",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            )
        ],
        api_rows={"rows": [_row("sym_b")]},
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#producer"]["status"] == (
        "QUALIFIED"
    )
    consumer = by_id["api:sym_b@linux-x86-64#consumer"]
    assert consumer["status"] == "OPEN"
    assert consumer["consumer"]["verdict"]["blocker"]["reason"] == (
        "not implemented"
    )


def test_consumer_absent_layer_stays_open():
    row = _pass_row("sym_b")
    row["typed_workflow"] = {"status": "ABSENT", "refs": []}
    registry, matrix, api = _inputs(
        [
            _record(
                id="api:sym_b",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            )
        ],
        api_rows={"rows": [row]},
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"


def test_consumer_failed_layer_stays_open():
    row = _pass_row("sym_b")
    row["evidence_cells"][0] = dict(
        row["evidence_cells"][0], outcome="FAIL"
    )
    registry, matrix, api = _inputs(
        [
            _record(
                id="api:sym_b",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            )
        ],
        api_rows={"rows": [row]},
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"


def test_native_host_gap_leaves_consumer_open():
    row = _pass_row("sym_b")
    for entry in row["evidence_cells"]:
        if entry["layer"] == "mojo_host":
            entry["outcome"] = "NOT_RUN"
    registry, matrix, api = _inputs(
        [
            _record(
                id="api:sym_b",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            )
        ],
        api_rows={"rows": [row]},
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#producer"]["status"] == (
        "QUALIFIED"
    )
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"


def test_excluded_row_fails_join():
    # Admitted rows cannot be excluded under the pinned API
    # contract (the upstream validator rejects reclassification
    # without source-policy review), so any excluded joined row
    # fails closed instead of hiding coverage.
    for blocker, pattern in (
        ({"reason": "test pending", "next_action": "run it"}, "excluded"),
        ({"reason": "   ", "next_action": "act"}, "blocker"),
        (None, "excluded"),
    ):
        row = _pass_row("sym_b")
        row["applicability"] = "excluded"
        row["blocker"] = blocker
        registry, matrix, api = _inputs(
            [_libsym_record("sym_b")], api_rows={"rows": [row]}
        )
        with pytest.raises(CoverageError, match=pattern):
            _materialize(registry, matrix, api)


def test_consumer_cells_cover_absent_targets():
    registry, matrix, api = _inputs(
        [
            _record(
                id="api:sym_b",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "BLOCKED_HARDWARE",
                    "detail": "no ARM guest",
                }
            ],
        },
        api_rows={"rows": [_row("sym_b")]},
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    cell = by_id["api:sym_b@linux-aarch64-physical#consumer"]
    assert cell["status"] == "OPEN"
    assert cell["rationale"]["status"] == "BLOCKED_HARDWARE"
    assert cell["consumer"]["api_row"] == "function:sym_b"


def test_output_is_deterministic_ordered_and_schema_valid():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:b",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            ),
            _record(id="helper:a", targets_required=["linux-x86-64"]),
            _record(id="helper:pre", targets_required=["linux-x86-64"]),
            _record(id="helper:pre2", targets_required=["linux-x86-64"]),
            _record(
                id="api:ord",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                targets_required=["linux-x86-64"],
            ),
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "BLOCKED_HARDWARE",
                    "detail": "no ARM guest",
                }
            ],
        },
        api_rows={"rows": [_row("ord")]},
    )
    first = _materialize(registry, matrix, api)
    second = _materialize(registry, matrix, api)
    assert json.dumps(first, sort_keys=True) == json.dumps(
        second, sort_keys=True
    )
    assert [cell["id"] for cell in first["cells"]] == sorted(
        cell["id"] for cell in first["cells"]
    )
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(first)


def test_schema_rejects_contradictory_cells():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [_record(id="helper:a", targets_required=["linux-x86-64"])]
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    base = good["cells"][0]

    def _check(mutator):
        bad = json.loads(json.dumps(good))
        mutator(bad["cells"][0])
        assert not Draft202012Validator(schema).is_valid(bad), mutator

    def _qualified_planned(cell):
        cell["status"] = "QUALIFIED"

    def _consumer_without_row(cell):
        cell["path"] = "consumer"
        cell["id"] = "helper:a@linux-x86-64#consumer"

    def _applicable_without_rationale(cell):
        cell["status"] = "NOT_APPLICABLE"

    for mutator in (
        _qualified_planned,
        _consumer_without_row,
        _applicable_without_rationale,
    ):
        _check(mutator)
    doubled = json.loads(json.dumps(good))
    doubled["cells"].append(json.loads(json.dumps(good["cells"][0])))
    assert not Draft202012Validator(schema).is_valid(doubled)


def test_full_pipeline_on_live_shaped_inputs():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:live",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            ),
            _record(
                id="api:live_sym",
                family="userspace-object",
                owner_task="U-OBJECT",
                userspace_api_surface="library-symbol",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            ),
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "BLOCKED_HARDWARE",
                    "detail": "no ARM guest",
                }
            ],
        },
        api_rows={"rows": [_pass_row("live_sym")]},
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["helper:live@linux-x86-64#producer"]["status"] == (
        "QUALIFIED"
    )
    assert by_id["helper:live@linux-aarch64-physical#producer"][
        "status"
    ] == "OPEN"
    assert by_id["api:live_sym@linux-x86-64#consumer"]["status"] == (
        "QUALIFIED"
    )
    assert ledger["inputs"]["record_count"] == 2
    assert ledger["inputs"]["cell_count"] == 4
    Draft202012Validator(_schema()).validate(ledger)


def test_committed_ledger_matches_inputs():
    with open(REGISTRY_PATH, encoding="utf-8") as handle:
        registry = json.load(handle)
    with open(MATRIX_PATH, encoding="utf-8") as handle:
        matrix = json.load(handle)
    with open(LEDGER_PATH, encoding="utf-8") as handle:
        ledger = json.load(handle)
    with open(EXTRACT_PATH, encoding="utf-8") as handle:
        api_rows = json.load(handle)
    _assert_ledger_consistent(ledger, registry, matrix, api_rows)
    assert len({cell["id"] for cell in ledger["cells"]}) == len(
        ledger["cells"]
    )
    assert [cell["id"] for cell in ledger["cells"]] == sorted(
        cell["id"] for cell in ledger["cells"]
    )


def _libsym_record(symbol):
    return _record(
        id=f"api:{symbol}",
        owner_task="U-OBJECT",
        userspace_api_surface="library-symbol",
        implementation_state="IMPLEMENTED",
        evidence_level="tested",
        evidence_refs=["host:test"],
    )


def test_api_version_mismatch_fails():
    registry, matrix, api = _inputs(
        [_record()], api_rows={"rows": [], "schema_version": 2}
    )
    with pytest.raises(CoverageError, match="schema_version"):
        _materialize(registry, matrix, api)


def test_consumer_needs_all_six_layers():
    row = _pass_row("sym_b")
    row["evidence_cells"] = [
        entry
        for entry in row["evidence_cells"]
        if entry["layer"] != "mojo_host"
    ]
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"


def test_single_pass_layer_stays_open():
    row = _pass_row("sym_b")
    row["evidence_cells"] = [row["evidence_cells"][0]]
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"


def test_row_contract_violations_fail():
    rows = []
    row = _pass_row("sym_b")
    del row["blocker"]
    rows.append(row)
    row = _pass_row("sym_b")
    del row["tests"]
    rows.append(row)
    row = _pass_row("sym_b")
    del row["evidence_cells"][0]["evidence_refs"]
    rows.append(row)
    row = _pass_row("sym_b")
    row["evidence_cells"].append(dict(row["evidence_cells"][0]))
    rows.append(row)
    row = _pass_row("sym_b")
    row["evidence_cells"][0] = dict(
        row["evidence_cells"][0], id="mismatch"
    )
    rows.append(row)
    for row in rows:
        registry, matrix, api = _inputs(
            [_libsym_record("sym_b")], api_rows={"rows": [row]}
        )
        with pytest.raises(CoverageError, match="row|layer|cell"):
            _materialize(registry, matrix, api)


def test_api_version_true_is_not_one():
    registry, matrix, api = _inputs(
        [_record()], api_rows={"rows": [], "schema_version": True}
    )
    with pytest.raises(CoverageError, match="schema_version"):
        _materialize(registry, matrix, api)


def test_scalar_source_refs_fail():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "reserved combination",
                    "source_refs": "upstream:doc",
                }
            ],
        },
    )
    with pytest.raises(CoverageError, match="source_refs"):
        _materialize(registry, matrix, api)


def test_blank_upstream_ref_rejected():
    registry, matrix, api = _inputs(
        [_record(id="helper:a", upstream_source_refs=[""])]
    )
    with pytest.raises(CoverageError, match="upstream"):
        _materialize(registry, matrix, api)


def test_family_blocker_fields_checked():
    registry, matrix, api = _inputs([_record(id="helper:a")])
    registry["blockers"] = [
        {"id": "x", "status": "BLOCKED_UPSTREAM"}
    ]
    with pytest.raises(CoverageError, match="blocker"):
        _materialize(registry, matrix, api)


def test_null_family_blocker_stays_visible():
    registry, matrix, api = _inputs([_record(id="helper:a")])
    registry["blockers"] = [
        {
            "id": "future-scope",
            "family": None,
            "status": "PLANNED",
            "detail": "not yet scoped to a family",
            "source_refs": ["plan:doc"],
            "next_action": "scope it",
        }
    ]
    ledger = _materialize(registry, matrix, api)
    assert ledger["blockers"] == [
        {
            "id": "future-scope",
            "family": None,
            "status": "PLANNED",
            "matched_cells": 0,
        }
    ]


def test_misshapen_row_fields_fail():
    good = _pass_row("sym_b")

    def _case(mutator):
        row = json.loads(json.dumps(good))
        mutator(row)
        registry, matrix, api = _inputs(
            [_libsym_record("sym_b")], api_rows={"rows": [row]}
        )
        with pytest.raises(CoverageError, match="row|layer|cell|blocker"):
            _materialize(registry, matrix, api)

    _case(lambda row: row.update(raw_declaration="ABSENT"))
    _case(lambda row: row.update(applicability=["required"]))
    _case(lambda row: row.update(evidence_cells={}))
    _case(lambda row: row["evidence_cells"].__setitem__(0, "source"))
    _case(lambda row: row.update(blocker=42))
    _case(
        lambda row: row.update(
            blocker={"reason": "", "next_action": "act"}
        )
    )
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": ["nope"]}
    )
    with pytest.raises(CoverageError, match="row"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": {"x": 1}}
    )
    with pytest.raises(CoverageError, match="rows"):
        _materialize(registry, matrix, api)


def test_unknown_row_values_fail():
    cases = []
    row = _pass_row("sym_b")
    row["evidence_cells"][0] = dict(
        row["evidence_cells"][0], outcome="MAYBE"
    )
    cases.append(row)
    row = _pass_row("sym_b")
    row["evidence_cells"][0] = dict(row["evidence_cells"][0], layer="q")
    cases.append(row)
    row = _pass_row("sym_b")
    row["raw_declaration"] = {"status": "COMPLETE", "refs": []}
    cases.append(row)
    row = _pass_row("sym_b")
    row["forwarding_adapter"] = {"status": "SOURCE_PRESENT", "refs": []}
    cases.append(row)
    row = _pass_row("sym_b")
    row["applicability"] = "maybe"
    cases.append(row)
    for row in cases:
        registry, matrix, api = _inputs(
            [_libsym_record("sym_b")], api_rows={"rows": [row]}
        )
        with pytest.raises(CoverageError, match="row|status|layer"):
            _materialize(registry, matrix, api)


def test_blank_evidence_ref_rejected():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=[""],
            )
        ]
    )
    with pytest.raises(CoverageError, match="evidence_refs"):
        _materialize(registry, matrix, api)


def test_empty_blocker_rejected():
    for blocker in ({}, {"status": "PLANNED"}):
        registry, matrix, api = _inputs(
            [_record(id="helper:a", blocker=blocker)]
        )
        with pytest.raises(CoverageError, match="blocker"):
            _materialize(registry, matrix, api)


def test_unknown_blocker_status_rejected():
    for bad_status in ("QUALIFIED", [], {}):
        bad = {"status": bad_status, "detail": "done", "next_action": "x"}
        registry, matrix, api = _inputs([_record(blocker=bad)])
        with pytest.raises(CoverageError, match="status|blocker"):
            _materialize(registry, matrix, api)
    for bad_status in ("QUALIFIED", []):
        registry, matrix, api = _inputs([_record(id="helper:a")])
        registry["blockers"] = [
            {
                "id": "odd-status",
                "family": None,
                "status": bad_status,
                "detail": "done",
                "source_refs": ["plan:doc"],
                "next_action": "x",
            }
        ]
        with pytest.raises(CoverageError, match="status"):
            _materialize(registry, matrix, api)
    for bad_status in ("QUALIFIED", []):
        registry, matrix, api = _inputs(
            [
                _record(
                    id="helper:a",
                    targets_required=[
                        "linux-x86-64",
                        "linux-aarch64-physical",
                    ],
                )
            ],
            matrix={
                "profiles": ["linux-x86-64"],
                "evidence_profiles": {"linux-x86-64": []},
                "runtime_profiles": {"linux-x86-64": []},
                "absent": [
                    {
                        "target": "linux-aarch64-physical",
                        "status": bad_status,
                        "detail": "done",
                    }
                ],
            },
        )
        with pytest.raises(CoverageError, match="status"):
            _materialize(registry, matrix, api)


def test_unknown_state_or_evidence_fails():
    registry, matrix, api = _inputs(
        [_record(id="helper:a", implementation_state="IMPLEMENTD")]
    )
    with pytest.raises(CoverageError, match="implementation state"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [_record(id="helper:a", evidence_level="maybe")]
    )
    with pytest.raises(CoverageError, match="evidence level"):
        _materialize(registry, matrix, api)


def test_vocabularies_match_registry_schema():
    with open(
        os.path.join(ROOT, "schemas", "capability.schema.json"),
        encoding="utf-8",
    ) as handle:
        schema = json.load(handle)
    record = schema["properties"]["records"]["items"]
    props = record["properties"]
    assert _TOOL.KNOWN_SURFACES == set(
        props["userspace_api_surface"]["enum"]
    )
    assert _TOOL.KNOWN_STATES == set(
        props["implementation_state"]["enum"]
    )
    assert _TOOL.KNOWN_EVIDENCE_LEVELS == set(
        props["evidence_level"]["enum"]
    )
    assert _TOOL.RECORD_BLOCKER_STATUSES == set(
        props["blocker"]["properties"]["status"]["enum"]
    )
    assert _TOOL.RECORD_BLOCKER_STATUSES == set(
        schema["properties"]["blockers"]["items"]["properties"][
            "status"
        ]["enum"]
    )


def test_whitespace_excuse_rejected():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "   ",
                    "source_refs": ["upstream:doc"],
                }
            ],
        },
    )
    with pytest.raises(CoverageError, match="detail"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "excluded",
                    "source_refs": [""],
                }
            ],
        },
    )
    with pytest.raises(CoverageError, match="malformed source_refs"):
        _materialize(registry, matrix, api)


def test_exclusion_carries_source_refs():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {
                "linux-x86-64": ["test-profile"]
            },
            "runtime_profiles": {
                "linux-x86-64": ["test-runtime-profile"]
            },
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "reserved combination",
                    "source_refs": ["upstream:doc"],
                }
            ],
        },
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["helper:a@linux-aarch64-physical#producer"][
        "rationale"
    ]["source_refs"] == ["upstream:doc"]


def test_duplicate_package_ids_or_titles_fail():
    registry, matrix, api = _inputs(
        [_record()],
        packages=[
            {"id": "X-HELPERS", "title": "one"},
            {"id": "X-HELPERS", "title": "two"},
        ],
    )
    with pytest.raises(CoverageError, match="package"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs(
        [_record()],
        packages=[
            {"id": "X-HELPERS", "title": "same"},
            {"id": "U-OBJECT", "title": "same"},
        ],
    )
    with pytest.raises(CoverageError, match="title"):
        _materialize(registry, matrix, api)


def test_cost_trailing_newline_rejected():
    registry, matrix, api = _inputs([_record(cost_cases=["COST-01\n"])])
    with pytest.raises(CoverageError, match="cost"):
        _materialize(registry, matrix, api)


def test_schema_rejects_unearned_consumer_qualification():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [_pass_row("sym_b")]}
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    consumer = next(
        cell for cell in good["cells"] if cell["path"] == "consumer"
    )
    assert consumer["status"] == "QUALIFIED"

    def _check(mutator):
        bad = json.loads(json.dumps(good))
        target = next(
            cell for cell in bad["cells"] if cell["path"] == "consumer"
        )
        mutator(target)
        assert not Draft202012Validator(schema).is_valid(bad), mutator

    def _fail_layer(cell):
        cell["consumer"]["verdict"]["layers"][0]["outcome"] = "FAIL"

    def _absent_raw(cell):
        cell["consumer"]["verdict"]["raw_status"] = "ABSENT"

    def _row_blocker(cell):
        cell["consumer"]["verdict"]["blocker"] = {
            "reason": "blocked",
            "next_action": "wait",
        }

    for mutator in (_fail_layer, _absent_raw, _row_blocker):
        _check(mutator)


def test_schema_rejects_incomplete_qualified_verdicts():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [
            _libsym_record("sym_b"),
            _record(
                id="helper:a",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            ),
        ],
        api_rows={"rows": [_pass_row("sym_b")]},
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)

    def _check(predicate, mutator):
        bad = json.loads(json.dumps(good))
        target = next(
            cell for cell in bad["cells"] if predicate(cell)
        )
        assert target["status"] == "QUALIFIED"
        mutator(target)
        assert not Draft202012Validator(schema).is_valid(bad), mutator

    def _is_consumer(cell):
        return cell["path"] == "consumer"

    def _is_qualified_producer(cell):
        return (
            cell["path"] == "producer"
            and cell["status"] == "QUALIFIED"
        )

    def _drop_layers(cell):
        cell["consumer"]["verdict"]["layers"] = [
            cell["consumer"]["verdict"]["layers"][0]
        ]

    def _empty_refs(cell):
        cell["applicability"]["evidence_refs"] = []

    def _blank_ref(cell):
        cell["applicability"]["evidence_refs"] = [""]

    _check(_is_consumer, _drop_layers)
    _check(_is_qualified_producer, _empty_refs)
    _check(_is_qualified_producer, _blank_ref)


def _canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _diff_report(expected, actual):
    expected_cells = {
        cell["id"]: cell for cell in expected.get("cells", [])
    }
    actual_cells = {
        cell["id"]: cell for cell in actual.get("cells", [])
    }
    missing = sorted(set(expected_cells) - set(actual_cells))
    extra = sorted(set(actual_cells) - set(expected_cells))
    lines = [
        "ledger differs from regeneration: %d expected cells, %d actual"
        % (len(expected_cells), len(actual_cells))
    ]
    if missing:
        lines.append("missing: %s" % ", ".join(missing[:5]))
    if extra:
        lines.append("extra: %s" % ", ".join(extra[:5]))
    shown = 0
    for ident in sorted(set(expected_cells) & set(actual_cells)):
        if expected_cells[ident] != actual_cells[ident] and shown < 3:
            lines.append("divergent: %s" % ident)
            shown += 1
    if expected.get("inputs") != actual.get("inputs"):
        lines.append("inputs differ")
    if expected.get("blockers") != actual.get("blockers"):
        lines.append("blockers differ")
    return "\n".join(lines)


def _assert_ledger_consistent(
    ledger, registry, matrix, api_rows, ledger_text=None, api_text=None
):
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    assert ledger["inputs"]["registry_sha256"] == hashlib.sha256(
        _canonical(registry).encode()
    ).hexdigest()
    assert ledger["inputs"]["matrix_sha256"] == hashlib.sha256(
        _canonical(matrix).encode()
    ).hexdigest()
    assert ledger["inputs"]["api_coverage_sha256"] == hashlib.sha256(
        _canonical(api_rows).encode()
    ).hexdigest()
    assert ledger["inputs"]["record_count"] == len(registry["records"])
    assert ledger["inputs"]["cell_count"] == len(ledger["cells"])
    fresh = materialize_coverage(registry, matrix, api_rows)
    # Compare digests, not the multi-megabyte blobs: pytest would
    # otherwise spend eternity difflib-ing the two strings while
    # rendering the failure. The diff report names the cells.
    assert hashlib.sha256(_canonical(fresh).encode()).hexdigest() == (
        hashlib.sha256(_canonical(ledger).encode()).hexdigest()
    ), _diff_report(fresh, ledger)
    if ledger_text is not None:
        expected_text = _TOOL.dump_ledger(fresh)
        assert hashlib.sha256(expected_text.encode()).hexdigest() == (
            hashlib.sha256(ledger_text.encode()).hexdigest()
        ), "ledger bytes differ from regeneration"
    if api_text is not None:
        expected_extract = _EXTRACTOR.dump_extract(api_rows)
        assert hashlib.sha256(expected_extract.encode()).hexdigest() == (
            hashlib.sha256(api_text.encode()).hexdigest()
        ), "extract bytes differ from canonical form"
    Draft202012Validator(schema).validate(ledger)


def test_drift_catches_removed_consumer_cells():
    ledger, registry, matrix, api_rows = _mutated_committed_ledger()
    keep = [
        cell for cell in ledger["cells"] if cell["path"] != "consumer"
    ]
    assert len(keep) < len(ledger["cells"])
    mutated = dict(ledger)
    mutated["cells"] = keep
    mutated["inputs"] = dict(ledger["inputs"], cell_count=len(keep))
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api_rows)


def test_source_profile_cannot_satisfy_runtime():
    row = _pass_row("sym_b")
    for entry in row["evidence_cells"]:
        if entry["layer"] == "target_runtime":
            entry["target_profile"] = "test-profile"
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    matrix["runtime_profiles"] = {"linux-x86-64": []}
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"


def test_admitted_runtime_profile_qualifies():
    row = _pass_row("sym_b")
    for entry in row["evidence_cells"]:
        if entry["layer"] == "target_runtime":
            entry["target_profile"] = "runtime-x86"
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    matrix["runtime_profiles"] = {"linux-x86-64": ["runtime-x86"]}
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == (
        "QUALIFIED"
    )


def test_anchor_extra_keys_or_reversed_range_fail():
    anchor = _valid_anchor()
    anchor["extra"] = 1
    row = _pass_row("sym_b")
    row["evidence_cells"][0] = dict(
        row["evidence_cells"][0], evidence_refs=[anchor]
    )
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    with pytest.raises(CoverageError, match="anchor"):
        _materialize(registry, matrix, api)
    anchor = _valid_anchor()
    anchor["start_line"] = 30
    anchor["end_line"] = 20
    row = _pass_row("sym_b")
    row["evidence_cells"][0] = dict(
        row["evidence_cells"][0], evidence_refs=[anchor]
    )
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    with pytest.raises(CoverageError, match="anchor|line"):
        _materialize(registry, matrix, api)


def test_extractor_main_refuses_ambiguous_bytes(tmp_path):
    dup = tmp_path / "dup.json"
    dup.write_text(
        '{"schema_version": 2, "schema_version": 1, "rows": []}',
        encoding="utf-8",
    )
    out = tmp_path / "out.json"
    assert _EXTRACTOR.main(
        [
            "--artifact",
            str(dup),
            "--repo",
            "r",
            "--rev",
            "ab" * 20,
            "--path",
            "p",
            "--output",
            str(out),
        ]
    ) == 1
    nan = tmp_path / "nan.json"
    nan.write_text(
        '{"schema_version": 1, "rows": [], "x": Infinity}',
        encoding="utf-8",
    )
    assert _EXTRACTOR.main(
        [
            "--artifact",
            str(nan),
            "--repo",
            "r",
            "--rev",
            "ab" * 20,
            "--path",
            "p",
            "--output",
            str(out),
        ]
    ) == 1
    nested = tmp_path / "nested.json"
    nested.write_text(
        '{"schema_version": 1, "rows": [{"id": "function:x",'
        ' "evidence_cells": [{"outcome": "FAIL", "outcome": "PASS"}]}]}',
        encoding="utf-8",
    )
    assert _EXTRACTOR.main(
        [
            "--artifact",
            str(nested),
            "--repo",
            "r",
            "--rev",
            "ab" * 20,
            "--path",
            "p",
            "--output",
            str(out),
        ]
    ) == 1
    overflow = tmp_path / "overflow.json"
    overflow.write_text(
        '{"schema_version": 1, "rows": [], "x": 1e400}',
        encoding="utf-8",
    )
    assert _EXTRACTOR.main(
        [
            "--artifact",
            str(overflow),
            "--repo",
            "r",
            "--rev",
            "ab" * 20,
            "--path",
            "p",
            "--output",
            str(out),
        ]
    ) == 1


def test_failed_run_preserves_existing_output(tmp_path):
    out = tmp_path / "out.json"
    out.write_text("sentinel", encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema_version": 2, "rows": []}', encoding="utf-8")
    assert _EXTRACTOR.main(
        [
            "--artifact",
            str(bad),
            "--repo",
            "r",
            "--rev",
            "ab" * 20,
            "--path",
            "p",
            "--output",
            str(out),
        ]
    ) == 1
    assert out.read_text(encoding="utf-8") == "sentinel"


def test_extractor_reads_artifact_once(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact.json"
    artifact.write_text(
        '{"schema_version": 1, "rows": []}', encoding="utf-8"
    )
    out = tmp_path / "out.json"
    real_open = open
    reads = []

    def _counting_open(path, *args, **kwargs):
        if str(path) == str(artifact):
            reads.append(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _counting_open)
    assert _EXTRACTOR.main(
        [
            "--artifact",
            str(artifact),
            "--repo",
            "r",
            "--rev",
            "ab" * 20,
            "--path",
            "p",
            "--output",
            str(out),
        ]
    ) == 0
    assert len(reads) == 1


def _cli_args(reg_path, matrix_path, api_path, out_path):
    return [
        "--registry",
        str(reg_path),
        "--matrix",
        str(matrix_path),
        "--api-coverage",
        str(api_path),
        "--schema",
        SCHEMA_PATH,
        "--output",
        str(out_path),
    ]


def test_capability_schema_pin_matches_tree():
    with open(
        os.path.join(ROOT, "schemas", "capability.schema.json"), "rb"
    ) as handle:
        assert (
            hashlib.sha256(handle.read()).hexdigest()
            == _TOOL.CAPABILITY_SCHEMA_SHA256
        )


def test_cli_regenerates_committed_ledger(tmp_path):
    out_path = tmp_path / "out.json"
    assert _TOOL.main(
        _cli_args(REGISTRY_PATH, MATRIX_PATH, EXTRACT_PATH, out_path)
    ) == 0
    with open(LEDGER_PATH, "rb") as handle:
        committed = handle.read()
    assert out_path.read_bytes() == committed


def test_cli_without_capability_sibling_fails_cleanly(tmp_path):
    lonely = tmp_path / "schemas"
    lonely.mkdir()
    schema_copy = lonely / "coverage-ledger.schema.json"
    with open(SCHEMA_PATH, "rb") as handle:
        schema_copy.write_bytes(handle.read())
    out_path = tmp_path / "out.json"
    assert _TOOL.main(
        [
            "--registry",
            REGISTRY_PATH,
            "--matrix",
            MATRIX_PATH,
            "--api-coverage",
            EXTRACT_PATH,
            "--schema",
            str(schema_copy),
            "--output",
            str(out_path),
        ]
    ) == 1
    assert not out_path.exists()


def _sibling_run(tmp_path, sibling_text):
    lonely = tmp_path / "schemas"
    lonely.mkdir(exist_ok=True)
    schema_copy = lonely / "coverage-ledger.schema.json"
    with open(SCHEMA_PATH, "rb") as handle:
        schema_copy.write_bytes(handle.read())
    sibling = lonely / "capability.schema.json"
    sibling.write_text(sibling_text, encoding="utf-8")
    out_path = tmp_path / "out.json"
    code = _TOOL.main(
        [
            "--registry",
            REGISTRY_PATH,
            "--matrix",
            MATRIX_PATH,
            "--api-coverage",
            EXTRACT_PATH,
            "--schema",
            str(schema_copy),
            "--output",
            str(out_path),
        ]
    )
    return code, out_path.exists()


def test_cli_rejects_broken_capability_sibling(tmp_path):
    for broken in ("[]", "{}", '{"properties": []}'):
        code, produced = _sibling_run(tmp_path, broken)
        assert code == 1
        assert not produced


def test_cli_rejects_permissive_capability_sibling(tmp_path):
    for sibling in (
        '{"required": ["records"]}',
        '{"required": ["packages"]}',
    ):
        code, produced = _sibling_run(tmp_path, sibling)
        assert code == 1
        assert not produced


def test_cli_rejects_unresolvable_capability_sibling(tmp_path):
    code, produced = _sibling_run(
        tmp_path, '{"$ref": "#/$defs/missing"}'
    )
    assert code == 1
    assert not produced


def test_cli_refuses_schema_invalid_registry(tmp_path):
    registry = _TOOL._load_json_strict(REGISTRY_PATH)
    registry["records"][0] = dict(
        registry["records"][0], zzz_bogus=True
    )
    reg_path = tmp_path / "registry.json"
    reg_path.write_text(
        json.dumps(registry, sort_keys=True), encoding="utf-8"
    )
    out_path = tmp_path / "out.json"
    assert _TOOL.main(
        _cli_args(reg_path, MATRIX_PATH, EXTRACT_PATH, out_path)
    ) == 1
    assert not out_path.exists()


def test_extractor_filters_stamps_and_sorts():
    first = _pass_row("bbb")
    second = _pass_row("aaa")
    artifact = {
        "schema_version": 1,
        "rows": [
            second,
            {"id": "member:zzz"},
            first,
            {"id": "enumerator:yyy"},
        ],
    }
    extract = _EXTRACTOR.extract_api_rows(
        artifact,
        repo="https://github.com/mingulov/libbpf-mojo",
        rev="ab" * 20,
        path="docs/api-coverage.json",
        artifact_sha256="d" * 64,
    )
    assert extract["schema_version"] == 1
    assert extract["license"] == "Apache-2.0 WITH LLVM-exception"
    assert extract["api_provenance"] == {
        "repo": "https://github.com/mingulov/libbpf-mojo",
        "rev": "ab" * 20,
        "path": "docs/api-coverage.json",
        "artifact_sha256": "d" * 64,
    }
    assert [row["id"] for row in extract["rows"]] == [
        "function:aaa",
        "function:bbb",
    ]
    again = _EXTRACTOR.extract_api_rows(
        artifact,
        repo="https://github.com/mingulov/libbpf-mojo",
        rev="ab" * 20,
        path="docs/api-coverage.json",
        artifact_sha256="d" * 64,
    )
    assert json.dumps(extract, sort_keys=True) == json.dumps(
        again, sort_keys=True
    )


def test_extractor_rejects_bad_version_or_provenance():
    for bad_version in (2, True, 1.0):
        with pytest.raises(ValueError, match="schema_version"):
            _EXTRACTOR.extract_api_rows(
                {"schema_version": bad_version, "rows": []},
                repo="r",
                rev="ab" * 20,
                path="p",
                artifact_sha256="d" * 64,
            )
    for bad_rev in ("", "HEAD", "abc123", "z" * 40, "v" * 40):
        with pytest.raises(ValueError, match="provenance|revision"):
            _EXTRACTOR.extract_api_rows(
                {"schema_version": 1, "rows": []},
                repo="r",
                rev=bad_rev,
                path="p",
                artifact_sha256="d" * 64,
            )


def test_extractor_rejects_misshapen_rows():
    for rows in (
        {"function:x": {}},
        ["function:x"],
        [{"id": 42}],
    ):
        with pytest.raises(ValueError, match="rows|row"):
            _EXTRACTOR.extract_api_rows(
                {"schema_version": 1, "rows": rows},
                repo="r",
                rev="ab" * 20,
                path="p",
                artifact_sha256="d" * 64,
            )


def test_extract_feeds_materializer():
    artifact = {
        "schema_version": 1,
        "rows": [_pass_row("sym_b"), {"id": "member:zzz"}],
    }
    extract = _EXTRACTOR.extract_api_rows(
        artifact,
        repo="https://github.com/mingulov/libbpf-mojo",
        rev="ab" * 20,
        path="docs/api-coverage.json",
        artifact_sha256="d" * 64,
    )
    registry, matrix, _ = _inputs([_libsym_record("sym_b")])
    ledger = materialize_coverage(registry, matrix, extract)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == (
        "QUALIFIED"
    )
    assert ledger["inputs"]["api_artifact_sha256"] == "d" * 64


def test_misshapen_matrix_containers_fail():
    registry, matrix, api = _inputs([_record()])
    matrix["profiles"] = {"linux-x86-64": False}
    with pytest.raises(CoverageError, match="profiles"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record()])
    matrix["absent"] = {"linux-nope": {}}
    with pytest.raises(CoverageError, match="absent"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record()])
    matrix["absent"] = ["linux-nope"]
    with pytest.raises(CoverageError, match="absent"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record()])
    matrix["profiles"] = ["linux-x86-64", None]
    matrix["evidence_profiles"][None] = []
    matrix["runtime_profiles"][None] = []
    with pytest.raises(CoverageError, match="target"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record()])
    matrix["profiles"] = ["linux-x86-64", {}]
    with pytest.raises(CoverageError, match="target"):
        _materialize(registry, matrix, api)


def test_non_boolean_scope_rejected():
    for bad in (0.5, 1, "yes"):
        registry, matrix, api = _inputs(
            [_record(id="helper:a", scope_required=bad)]
        )
        with pytest.raises(CoverageError, match="scope_required"):
            _materialize(registry, matrix, api)


def test_opener_failure_leaves_no_trace(tmp_path):
    def _failing_opener(path, *args, **kwargs):
        raise OSError("cannot wrap")

    out = tmp_path / "out.json"
    out.write_text("sentinel", encoding="utf-8")
    for writer in (_TOOL._atomic_write_text, _EXTRACTOR._atomic_write_text):
        with pytest.raises(OSError, match="cannot wrap"):
            writer(str(out), "new bytes", _opener=_failing_opener)
        assert out.read_text(encoding="utf-8") == "sentinel"
        assert list(tmp_path.iterdir()) == [out]


def test_name_collision_preserves_existing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        _TOOL.secrets, "token_hex", lambda n: "00" * 8
    )
    out = tmp_path / "out.json"
    squatter = tmp_path / (".out.json." + "00" * 8 + ".tmp")
    squatter.write_text("mine", encoding="utf-8")
    for writer in (_TOOL._atomic_write_text, _EXTRACTOR._atomic_write_text):
        with pytest.raises(FileExistsError):
            writer(str(out), "new bytes")
        assert squatter.read_text(encoding="utf-8") == "mine"
        assert not out.exists()


def test_replace_failure_preserves_everything(tmp_path):
    parent = tmp_path / "sub"
    parent.mkdir()
    victim = parent / "victim"
    victim.mkdir()
    (victim / "keep").write_text("x", encoding="utf-8")
    for writer in (_TOOL._atomic_write_text, _EXTRACTOR._atomic_write_text):
        with pytest.raises(OSError):
            writer(str(victim), "new bytes")
        assert (victim / "keep").read_text(encoding="utf-8") == "x"
        assert sorted(path.name for path in parent.iterdir()) == [
            "victim"
        ]


def test_failed_write_preserves_existing_output(tmp_path):
    class _FailingWriter:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def write(self, text):
            raise OSError("disk full")

    def _failing_open(path, *args, **kwargs):
        return _FailingWriter()

    out = tmp_path / "out.json"
    out.write_text("sentinel", encoding="utf-8")
    for writer in (_TOOL._atomic_write_text, _EXTRACTOR._atomic_write_text):
        with pytest.raises(OSError, match="disk full"):
            writer(str(out), "new bytes", _opener=_failing_open)
        assert out.read_text(encoding="utf-8") == "sentinel"
        assert list(tmp_path.iterdir()) == [out]


def test_roots_and_provenance_must_be_objects():
    registry, matrix, api = _inputs([_record()])
    with pytest.raises(CoverageError, match="object"):
        _materialize([], matrix, api)
    with pytest.raises(CoverageError, match="object"):
        _materialize(registry, [], api)
    with pytest.raises(CoverageError, match="object"):
        _materialize(registry, matrix, [])
    api["api_provenance"] = []
    with pytest.raises(CoverageError, match="object"):
        _materialize(registry, matrix, api)
    with pytest.raises(ValueError, match="object"):
        _EXTRACTOR.extract_api_rows(
            [],
            repo="r",
            rev="ab" * 20,
            path="p",
            artifact_sha256="d" * 64,
        )


def test_unclean_matrix_targets_fail():
    registry, matrix, api = _inputs([_record()])
    matrix["profiles"] = ["linux-x86-64", "bad\rtarget"]
    matrix["evidence_profiles"]["bad\rtarget"] = []
    matrix["runtime_profiles"]["bad\rtarget"] = []
    with pytest.raises(CoverageError, match="target"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record()])
    matrix["profiles"] = [""]
    matrix["evidence_profiles"] = {"": []}
    matrix["runtime_profiles"] = {"": []}
    with pytest.raises(CoverageError, match="target"):
        _materialize(registry, matrix, api)


def test_cross_target_profile_reuse_fails():
    registry, matrix, api = _inputs([_record()])
    matrix["profiles"] = ["linux-x86-64", "linux-aarch64-physical"]
    matrix["evidence_profiles"] = {
        "linux-x86-64": ["shared-profile"],
        "linux-aarch64-physical": [],
    }
    matrix["runtime_profiles"] = {
        "linux-x86-64": [],
        "linux-aarch64-physical": ["shared-profile"],
    }
    with pytest.raises(CoverageError, match="one meaning"):
        _materialize(registry, matrix, api)


def test_mutable_revision_rejected():
    registry, matrix, api = _inputs([_record()])
    api["api_provenance"]["rev"] = "HEAD"
    with pytest.raises(CoverageError, match="revision"):
        _materialize(registry, matrix, api)


def test_duplicate_keys_rejected(tmp_path):
    blob = tmp_path / "dup.json"
    blob.write_text('{"a": 1, "a": 2}', encoding="utf-8")
    with pytest.raises(CoverageError, match="duplicate"):
        _TOOL._load_json_strict(str(blob))
    clean = tmp_path / "clean.json"
    clean.write_text('{"a": 1}', encoding="utf-8")
    assert _TOOL._load_json_strict(str(clean)) == {"a": 1}


def test_nonstandard_constants_rejected(tmp_path):
    blob = tmp_path / "nan.json"
    blob.write_text('{"a": NaN}', encoding="utf-8")
    with pytest.raises(CoverageError, match="constant"):
        _TOOL._load_json_strict(str(blob))
    overflow = tmp_path / "overflow.json"
    overflow.write_text('{"a": 1e400}', encoding="utf-8")
    with pytest.raises(CoverageError, match="finite"):
        _TOOL._load_json_strict(str(overflow))


def test_overlapping_or_unqualified_profiles_fail():
    registry, matrix, api = _inputs([_record()])
    matrix["runtime_profiles"] = {"linux-x86-64": ["test-profile"]}
    with pytest.raises(CoverageError, match="overlap"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record()])
    matrix["runtime_profiles"] = {
        "linux-x86-64": ["runtime-target-unqualified"]
    }
    with pytest.raises(CoverageError, match="[Uu]nqualified"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record()])
    matrix["evidence_profiles"] = {
        "linux-x86-64": ["contract-Unqualified-draft"]
    }
    with pytest.raises(CoverageError, match="[Uu]nqualified"):
        _materialize(registry, matrix, api)


def _mutated_committed_ledger():
    registry = _TOOL._load_json_strict(REGISTRY_PATH)
    matrix = _TOOL._load_json_strict(MATRIX_PATH)
    ledger = _TOOL._load_json_strict(LEDGER_PATH)
    api_rows = _TOOL._load_json_strict(EXTRACT_PATH)
    return json.loads(json.dumps(ledger)), registry, matrix, api_rows


def test_committed_bytes_match_regeneration():
    with open(LEDGER_PATH, "rb") as handle:
        ledger_text = handle.read().decode("utf-8")
    with open(EXTRACT_PATH, "rb") as handle:
        api_text = handle.read().decode("utf-8")
    ledger = json.loads(ledger_text)
    registry = _TOOL._load_json_strict(REGISTRY_PATH)
    matrix = _TOOL._load_json_strict(MATRIX_PATH)
    api_rows = _TOOL._load_json_strict(EXTRACT_PATH)
    _assert_ledger_consistent(
        ledger, registry, matrix, api_rows, ledger_text, api_text
    )
    reformatted = json.dumps(ledger, indent=4, sort_keys=True) + "\n"
    with pytest.raises(AssertionError, match="bytes differ"):
        _assert_ledger_consistent(
            ledger, registry, matrix, api_rows, reformatted, api_text
        )
    reformatted_extract = json.dumps(api_rows, indent=4) + "\n"
    with pytest.raises(AssertionError, match="bytes differ"):
        _assert_ledger_consistent(
            ledger, registry, matrix, api_rows, ledger_text,
            reformatted_extract,
        )


def test_drift_catches_retargeted_cells():
    mutated, registry, matrix, api_rows = _mutated_committed_ledger()
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["path"] == "consumer"
    )
    victim["target"] = "linux-x86-64-OTHER"
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api_rows)


def test_drift_catches_remapped_api_rows():
    mutated, registry, matrix, api_rows = _mutated_committed_ledger()
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["path"] == "consumer"
    )
    victim["consumer"]["api_row"] = "function:other"
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api_rows)


def test_drift_catches_hidden_blocked_cells():
    mutated, registry, matrix, api_rows = _mutated_committed_ledger()
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["target"] == "linux-aarch64-physical"
        and cell["status"] == "OPEN"
    )
    victim["status"] = "NOT_APPLICABLE"
    victim["rationale"]["status"] = "NOT_APPLICABLE"
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api_rows)


def test_drift_catches_promoted_blocked_cells():
    mutated, registry, matrix, api_rows = _mutated_committed_ledger()
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["target"] == "linux-aarch64-physical"
        and cell["status"] == "OPEN"
        and cell["path"] == "producer"
    )
    victim["status"] = "QUALIFIED"
    victim["implementation"]["state"] = "IMPLEMENTED"
    victim["implementation"]["evidence_level"] = "tested"
    victim["applicability"]["evidence_refs"] = ["host:forged"]
    del victim["rationale"]
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api_rows)


def test_drift_catches_unearned_consumer_status():
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [_pass_row("sym_b")]}
    )
    matrix["runtime_profiles"] = {"linux-x86-64": []}
    ledger = _materialize(registry, matrix, api)
    _assert_ledger_consistent(ledger, registry, matrix, api)
    mutated = json.loads(json.dumps(ledger))
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["path"] == "consumer"
    )
    assert victim["status"] == "OPEN"
    victim["status"] = "QUALIFIED"
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api)


def test_drift_catches_rationale_on_qualified():
    mutated, registry, matrix, api_rows = _mutated_committed_ledger()
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["status"] == "QUALIFIED"
    )
    victim["rationale"] = {
        "status": "BLOCKED_UPSTREAM",
        "detail": "forged",
    }
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api_rows)


def test_drift_catches_stripped_blocked_rationale():
    mutated, registry, matrix, api_rows = _mutated_committed_ledger()
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["target"] == "linux-aarch64-physical"
    )
    assert victim.get("rationale")
    del victim["rationale"]
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api_rows)


def test_schema_rejects_rationale_on_qualified():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            )
        ]
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    bad = json.loads(json.dumps(good))
    target = next(
        cell
        for cell in bad["cells"]
        if cell["status"] == "QUALIFIED"
    )
    target["rationale"] = {"status": "BLOCKED_UPSTREAM", "detail": "x"}
    assert not Draft202012Validator(schema).is_valid(bad)


def test_schema_rejects_citationless_exclusion():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {"linux-x86-64": []},
            "runtime_profiles": {"linux-x86-64": []},
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "reserved combination",
                    "source_refs": ["upstream:doc"],
                }
            ],
        },
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    bad = json.loads(json.dumps(good))
    target = next(
        cell
        for cell in bad["cells"]
        if cell["status"] == "NOT_APPLICABLE"
    )
    del target["rationale"]["source_refs"]
    assert not Draft202012Validator(schema).is_valid(bad)


def test_schema_rejects_trailing_newline_hashes():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs([_record()])
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    bad = json.loads(json.dumps(good))
    bad["inputs"]["api_provenance"]["rev"] += "\n"
    assert not Draft202012Validator(schema).is_valid(bad)
    bad = json.loads(json.dumps(good))
    bad["inputs"]["api_artifact_sha256"] += "\n"
    assert not Draft202012Validator(schema).is_valid(bad)
    bad = json.loads(json.dumps(good))
    bad["cells"][0]["id"] += "\n"
    assert not Draft202012Validator(schema).is_valid(bad)
    for break_char in ("\r", "\u0085", "\u2028", "\u2029"):
        bad = json.loads(json.dumps(good))
        bad["cells"][0]["id"] += break_char
        assert not Draft202012Validator(schema).is_valid(bad), repr(
            break_char
        )
        bad = json.loads(json.dumps(good))
        stem, sep, rest = bad["cells"][0]["id"].partition("@")
        bad["cells"][0]["id"] = stem + break_char + sep + rest
        assert not Draft202012Validator(schema).is_valid(bad), repr(
            break_char
        )


def test_schema_rejects_optional_scope():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                implementation_state="IMPLEMENTED",
                evidence_level="tested",
                evidence_refs=["host:test"],
            )
        ]
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    bad = json.loads(json.dumps(good))
    bad["cells"][0]["producer"]["scope_required"] = False
    assert not Draft202012Validator(schema).is_valid(bad)


def test_schema_rejects_mismatched_exclusion_rationale():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                targets_required=[
                    "linux-x86-64",
                    "linux-aarch64-physical",
                ],
            )
        ],
        matrix={
            "profiles": ["linux-x86-64"],
            "evidence_profiles": {"linux-x86-64": []},
            "runtime_profiles": {"linux-x86-64": []},
            "absent": [
                {
                    "target": "linux-aarch64-physical",
                    "status": "NOT_APPLICABLE",
                    "detail": "reserved combination",
                    "source_refs": ["upstream:doc"],
                }
            ],
        },
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    bad = json.loads(json.dumps(good))
    target = next(
        cell
        for cell in bad["cells"]
        if cell["status"] == "NOT_APPLICABLE"
    )
    target["rationale"]["status"] = "BLOCKED_HARDWARE"
    assert not Draft202012Validator(schema).is_valid(bad)


def test_drift_catches_orphaned_consumer_qualification():
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [_pass_row("sym_b")]}
    )
    ledger = _materialize(registry, matrix, api)
    _assert_ledger_consistent(ledger, registry, matrix, api)
    mutated = json.loads(json.dumps(ledger))
    victim = next(
        cell
        for cell in mutated["cells"]
        if cell["path"] == "producer"
    )
    assert victim["status"] == "QUALIFIED"
    victim["status"] = "OPEN"
    with pytest.raises(AssertionError):
        _assert_ledger_consistent(mutated, registry, matrix, api)


def _valid_anchor():
    return {
        "path": "src/object.c",
        "sha256": "a" * 64,
        "symbol": "bpf_object__open",
        "start_line": 10,
        "end_line": 20,
        "span_sha256": "b" * 64,
    }


def test_malformed_evidence_anchors_fail():
    for refs in ([None], [{"path": "src/object.c"}], ["plain-string"]):
        row = _pass_row("sym_b")
        row["evidence_cells"][0] = dict(
            row["evidence_cells"][0], evidence_refs=refs
        )
        registry, matrix, api = _inputs(
            [_libsym_record("sym_b")], api_rows={"rows": [row]}
        )
        with pytest.raises(CoverageError, match="anchor|evidence_refs"):
            _materialize(registry, matrix, api)


def test_valid_anchors_qualify():
    row = _pass_row("sym_b")
    row["evidence_cells"][0] = dict(
        row["evidence_cells"][0], evidence_refs=[_valid_anchor()]
    )
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == (
        "QUALIFIED"
    )


def test_empty_evidence_cells_stay_open_and_validate():
    row = _pass_row("sym_b")
    row["evidence_cells"] = []
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"
    Draft202012Validator(_schema()).validate(ledger)


def test_consumer_needs_matching_evidence_profile():
    row = _pass_row("sym_b")
    for entry in row["evidence_cells"]:
        entry["target_profile"] = "other-profile"
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [row]}
    )
    ledger = _materialize(registry, matrix, api)
    by_id = {cell["id"]: cell for cell in ledger["cells"]}
    assert by_id["api:sym_b@linux-x86-64#consumer"]["status"] == "OPEN"


def test_missing_evidence_profiles_key_fails():
    registry, matrix, api = _inputs([_record()])
    del matrix["evidence_profiles"]
    with pytest.raises(CoverageError, match="evidence_profiles"):
        _materialize(registry, matrix, api)


def test_schema_rejects_extra_qualified_layers():
    schema = _schema()
    Draft202012Validator.check_schema(schema)
    registry, matrix, api = _inputs(
        [_libsym_record("sym_b")], api_rows={"rows": [_pass_row("sym_b")]}
    )
    good = _materialize(registry, matrix, api)
    Draft202012Validator(schema).validate(good)
    bad = json.loads(json.dumps(good))
    target = next(
        cell for cell in bad["cells"] if cell["path"] == "consumer"
    )
    assert target["status"] == "QUALIFIED"
    target["consumer"]["verdict"]["layers"].append(
        {
            "layer": "extra_layer",
            "outcome": "PASS",
            "target_profile": "test-profile",
        }
    )
    assert not Draft202012Validator(schema).is_valid(bad)


def test_non_string_next_action_rejected():
    registry, matrix, api = _inputs(
        [
            _record(
                id="helper:a",
                blocker={
                    "status": "PLANNED",
                    "detail": "waiting",
                    "next_action": 17,
                },
            )
        ]
    )
    with pytest.raises(CoverageError, match="blocker"):
        _materialize(registry, matrix, api)
    registry, matrix, api = _inputs([_record(id="helper:a")])
    registry["blockers"] = [
        {
            "id": "odd-action",
            "family": None,
            "status": "PLANNED",
            "detail": "waiting",
            "source_refs": ["plan:doc"],
            "next_action": 17,
        }
    ]
    with pytest.raises(CoverageError, match="blocker"):
        _materialize(registry, matrix, api)


def test_mixed_source_refs_rejected():
    registry, matrix, api = _inputs([_record(id="helper:a")])
    registry["blockers"] = [
        {
            "id": "mixed-refs",
            "family": None,
            "status": "PLANNED",
            "detail": "waiting",
            "source_refs": ["plan:doc", None],
            "next_action": "scope it",
        }
    ]
    with pytest.raises(CoverageError, match="source_refs"):
        _materialize(registry, matrix, api)
