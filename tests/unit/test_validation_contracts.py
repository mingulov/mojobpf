# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the frozen validation contracts and aggregation.

Covers test-contracts-v1/suite-result-v1: exact enums, target/fixture
parsing, plan sealing, result parsing, every aggregation negative from
the F02 contract, and the digest-pinned schema bundle. Every negative
asserts a non-PASS gate with every attempt preserved. Standard library
only.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_<name>.py``).
"""

import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf.validation import (  # noqa: E402
    AVAILABILITY,
    EXECUTION_OUTCOMES,
    FAILURE_STAGES,
    SUITE_RESULT_VERSION,
    TEST_CONTRACTS_VERSION,
    CaseResult,
    ContractError,
    CostRecord,
    Fixture,
    RunPlan,
    SuiteResult,
    TargetManifest,
    aggregate,
    export_schema_bundle,
    load_schema,
    plan,
    schema_digest,
    verify_schema_bundle,
)
from mojobpf.validation.aggregate import verify_suite_result  # noqa: E402
from mojobpf.validation.models import (  # noqa: E402
    IMPLEMENTATION_STATES,
    SCHEMA_FILES,
)

COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40


def _sha(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _assert_contract_error(code, func, *args, **kwargs):
    try:
        func(*args, **kwargs)
    except ContractError as exc:
        assert exc.code == code, "want %s, got %s (%s)" % (
            code,
            exc.code,
            exc,
        )
        return exc
    raise AssertionError("expected ContractError %s" % code)


def make_target(**overrides):
    body = {
        "schema_version": 1,
        "kernel": {
            "source_commit": COMMIT,
            "release": "6.12.0-test",
            "build_id": "build-1",
            "config_sha256": _sha("config"),
        },
        "btf": {
            "vmlinux_sha256": _sha("vmlinux-btf"),
            "modules": [{"name": "bpf_testmod", "sha256": _sha("mod")}],
        },
        "image": {
            "digest": "sha256:" + _sha("rootfs"),
            "packages": {
                "libc": "2.39",
                "libbpf": "1.7.0",
                "bpftool": "7.5.0",
            },
        },
        "cpu": {
            "architecture": "x86-64",
            "model": "qemu64",
            "features": ["x2apic"],
            "page_size": 4096,
            "cpus": 4,
        },
        "execution_mode": "tcg",
        "byte_order": "le",
        "instruction_profile": "v3",
        "jit": {"state": "enabled", "hardening": ["spectre"]},
        "boot": {
            "parameters": ["quiet"],
            "lsms": ["capability"],
            "lockdown": "none",
        },
        "privileges": {
            "capabilities": ["CAP_BPF", "CAP_SYS_ADMIN"],
            "token": "none",
            "delegation": "exclusive-lease",
            "rlimits": {"memlock": "unlimited"},
        },
        "mounts": {
            "tracefs": "/sys/kernel/tracing",
            "bpffs": "/run/mojobpf-1/bpffs",
            "cgroup": "/sys/fs/cgroup/mojobpf-1",
            "namespaces": ["net:mojobpf-1"],
        },
        "build_host": {
            "identity": "mojo-1.1.0/x86-64",
            "flags": ["-O2"],
        },
    }
    body.update(overrides)
    body["fingerprint"] = TargetManifest.fingerprint_of(body)
    return body


def make_case(case_id, target_fp, **overrides):
    case = {
        "case_id": case_id,
        "fixture_id": "fx-%s" % case_id.lower().replace("_", "-"),
        "targets": [target_fp],
        "expectation": "positive",
        "required": True,
        "consumers": [{"name": "stock-libbpf", "version": "1.7.0"}],
        "source_sha256": _sha("source:%s" % case_id),
        "object_sha256": _sha("object:%s" % case_id),
        "expected_attempts": 1,
        "expected": {"outcome": "PASS", "failure_stage": None},
    }
    case.update(overrides)
    return case


REVISIONS = {
    "repository_commit": COMMIT,
    "package": "mojobpf-0.2.0",
    "tool": "run-vm-tests-0.2.0",
}


def make_plan(cases, targets, plan_id="plan-1", revisions=None):
    return plan(cases, targets, revisions or dict(REVISIONS), plan_id)


def basic_plan():
    target = make_target()
    case = make_case("NET-XDP-01", target["fingerprint"])
    return make_plan([case], [target]), target, case


def guarded_plan():
    target = make_target()
    fp = target["fingerprint"]
    positive = make_case("NET-XDP-01", fp)
    denial = make_case(
        "NET-XDP-01-DENY",
        fp,
        expectation="denial",
        denies="NET-XDP-01",
    )
    return make_plan([positive, denial], [target]), target


def make_result(
    run_plan,
    case_id,
    target_fp,
    attempt=1,
    outcome="PASS",
    applicability="APPLICABLE",
    failure_stage=None,
    run_id="run-1",
    **overrides,
):
    case = next(
        item for item in run_plan.cases if item.case_id == case_id
    )
    if outcome == "PASS":
        observed = {"outcome": "PASS", "failure_stage": None}
        evidence = [
            {
                "path": "evidence/%s.log" % case_id,
                "sha256": _sha("log:%s" % case_id),
                "bytes": 10,
            }
        ]
        cleanup = {"status": "CLEAN", "residue": []}
    else:
        observed = {
            "outcome": outcome,
            "failure_stage": failure_stage or "INFRA",
        }
        evidence = []
        cleanup = {"status": "NOT_CHECKED", "residue": []}
    result = {
        "schema_version": 1,
        "run_id": run_id,
        "case_id": case_id,
        "target_fingerprint": target_fp,
        "attempt": attempt,
        "plan_hash": run_plan.plan_hash,
        "identities": {
            "repository_commit": run_plan.revisions["repository_commit"],
            "package": run_plan.revisions["package"],
            "tool": run_plan.revisions["tool"],
            "consumer": {"name": "stock-libbpf", "version": "1.7.0"},
            "object_sha256": case.object_sha256,
            "source_sha256": case.source_sha256,
            "workload": {
                "fixture_id": case.fixture_id,
                "corpus_sha256": _sha("corpus:%s" % case_id),
            },
        },
        "applicability": applicability,
        "required": case.required,
        "expected": {"outcome": "PASS", "failure_stage": None},
        "observed": observed,
        "outcome": outcome,
        "failure_stage": observed["failure_stage"],
        "evidence": evidence,
        "cleanup": cleanup,
        "costs": [],
    }
    result.update(overrides)
    return result


# Exact enums from validation spec section 3.3.


def test_enums_match_spec():
    assert TEST_CONTRACTS_VERSION == "test-contracts-v1"
    assert SUITE_RESULT_VERSION == "suite-result-v1"
    assert EXECUTION_OUTCOMES == {
        "PASS",
        "FAIL",
        "INFRA_ERROR",
        "NOT_RUN",
    }
    assert AVAILABILITY == {
        "APPLICABLE",
        "KERNEL_FEATURE_ABSENT",
        "CONFIG_DISABLED",
        "POLICY_DENIED",
        "TARGET_RESOURCE_ABSENT",
        "HARDWARE_MISSING",
        "TOOLCHAIN_UNAVAILABLE",
        "UPSTREAM_BLOCKED",
        "NOT_APPLICABLE",
        "UNKNOWN",
    }
    assert IMPLEMENTATION_STATES == {
        "REPORTED",
        "AUDITED",
        "IN_PROGRESS",
        "IMPLEMENTED",
        "QUALIFIED",
    }
    assert FAILURE_STAGES == {
        "BUILD",
        "ARTIFACT_INSPECTION",
        "LOAD",
        "ATTACH",
        "TEST_RUN",
        "RUNTIME",
        "VERIFY",
        "CLEANUP",
        "COST",
        "INFRA",
    }


def test_schemas_present_and_versioned():
    assert SCHEMA_FILES == (
        "target.schema.json",
        "fixture.schema.json",
        "run-plan.schema.json",
        "result.schema.json",
        "cost.schema.json",
    )
    for name in ("target", "fixture", "run-plan", "result", "cost"):
        schema = load_schema(name)
        assert schema["$schema"].endswith("/draft/2020-12/schema")
        assert "Apache-2.0 WITH LLVM-exception" in schema["$comment"]
        digest = schema_digest(name)
        assert len(digest) == 64
        assert digest == schema_digest(name)


def test_schema_documents_pin_version_1():
    for name in ("target", "fixture", "run-plan", "result", "cost"):
        schema = load_schema(name)
        if name == "result":
            props = schema["$defs"]["case_result"]["properties"]
        else:
            props = schema["properties"]
        assert props["schema_version"] == {"description": props[
            "schema_version"
        ]["description"], "const": 1}


def test_load_schema_rejects_unknown():
    _assert_contract_error("MBPF307", load_schema, "nope")


# Target manifests.


def test_target_round_trip():
    raw = make_target()
    manifest = TargetManifest.from_dict(raw)
    assert manifest.fingerprint == raw["fingerprint"]
    assert manifest.to_dict() == raw
    assert TargetManifest.fingerprint_of(raw) == raw["fingerprint"]


def test_target_fingerprint_tamper_rejected():
    raw = make_target()
    raw["kernel"]["release"] = "6.6.0-evil"
    _assert_contract_error("MBPF306", TargetManifest.from_dict, raw)


def test_target_rejects_bare_release():
    raw = make_target()
    del raw["kernel"]
    _assert_contract_error("MBPF303", TargetManifest.from_dict, raw)
    raw = make_target()
    raw["uname"] = "6.12.0"
    raw["fingerprint"] = TargetManifest.fingerprint_of(raw)
    _assert_contract_error("MBPF302", TargetManifest.from_dict, raw)


def test_target_rejects_bad_mode_and_version():
    raw = make_target(execution_mode="container")
    raw["fingerprint"] = TargetManifest.fingerprint_of(raw)
    _assert_contract_error("MBPF305", TargetManifest.from_dict, raw)
    raw = make_target()
    raw["schema_version"] = 2
    raw["fingerprint"] = TargetManifest.fingerprint_of(raw)
    _assert_contract_error("MBPF304", TargetManifest.from_dict, raw)


# Fixture ABI.


def make_fixture(**overrides):
    fixture = {
        "schema_version": 1,
        "fixture_id": "fx-net-xdp-01",
        "object": {
            "path": "objects/xdp_counter.bpf.o",
            "sha256": _sha("object"),
            "bytes": 4096,
        },
        "entries": [
            {
                "symbol": "xdp_counter",
                "program_type": "xdp",
                "section": "xdp",
            }
        ],
        "maps": [
            {
                "name": "counts",
                "map_type": "PERCPU_ARRAY",
                "key": {"type": "u32", "bytes": 4},
                "value": {"type": "u64", "bytes": 8},
                "max_entries": 4,
            }
        ],
        "event_abi": None,
        "corpus": {
            "corpus_id": "packets-33",
            "sha256": _sha("corpus"),
            "record_count": 33,
        },
        "oracle": {"name": "packet-oracle", "version": "1.3.0"},
        "barriers": ["ready", "start", "stop", "drained"],
    }
    fixture.update(overrides)
    return fixture


def test_fixture_round_trip():
    raw = make_fixture()
    fixture = Fixture.from_dict(raw)
    assert fixture.fixture_id == "fx-net-xdp-01"
    assert fixture.to_dict() == raw


def test_fixture_freezes_abi():
    raw = make_fixture()
    del raw["object"]["sha256"]
    _assert_contract_error("MBPF303", Fixture.from_dict, raw)
    raw = make_fixture()
    raw["maps"] = []
    raw["event_abi"] = {"version": 1, "record_bytes": 32}
    assert Fixture.from_dict(raw).to_dict() == raw
    raw = make_fixture(barriers=["ready", "ready"])
    _assert_contract_error("MBPF305", Fixture.from_dict, raw)
    raw = make_fixture(barriers=["launch"])
    _assert_contract_error("MBPF305", Fixture.from_dict, raw)
    raw = make_fixture()
    raw["maps"].append(dict(raw["maps"][0]))
    _assert_contract_error("MBPF305", Fixture.from_dict, raw)
    raw = make_fixture(extra="nope")
    _assert_contract_error("MBPF302", Fixture.from_dict, raw)


# Run plans.


def test_plan_happy_path_and_stable_hash():
    run_plan, target, case = basic_plan()
    assert run_plan.plan_id == "plan-1"
    assert run_plan.cells() == [("NET-XDP-01", target["fingerprint"])]
    clone = make_plan([case], [target])
    assert clone.plan_hash == run_plan.plan_hash
    assert RunPlan.from_dict(run_plan.to_dict()) == run_plan


def test_plan_accepts_mapping_targets():
    run_plan, _, _ = basic_plan()
    again = RunPlan.from_dict(json.loads(json.dumps(run_plan.to_dict())))
    assert again.plan_hash == run_plan.plan_hash


def test_plan_hash_tamper_rejected():
    run_plan, _, _ = basic_plan()
    raw = run_plan.to_dict()
    raw["plan_hash"] = "0" * 64
    _assert_contract_error("MBPF306", RunPlan.from_dict, raw)


def test_plan_rejects_bad_cross_references():
    target = make_target()
    fp = target["fingerprint"]
    other = make_target(execution_mode="physical")["fingerprint"]
    assert other != fp
    bad_target = make_case("NET-XDP-01", other)
    _assert_contract_error(
        "MBPF305", make_plan, [bad_target], [target]
    )
    dup = [make_case("NET-XDP-01", fp), make_case("NET-XDP-01", fp)]
    _assert_contract_error("MBPF305", make_plan, dup, [target])
    lonely_deny = make_case(
        "DENY-1", fp, expectation="denial", denies="MISSING"
    )
    _assert_contract_error(
        "MBPF305", make_plan, [lonely_deny], [target]
    )
    positive = make_case("NET-XDP-01", fp)
    deny_of_deny = make_case(
        "DENY-2", fp, expectation="denial", denies="DENY-1"
    )
    first_deny = make_case(
        "DENY-1", fp, expectation="denial", denies="NET-XDP-01"
    )
    _assert_contract_error(
        "MBPF305", make_plan, [positive, first_deny, deny_of_deny],
        [target],
    )
    sneaky = make_case("NET-XDP-01", fp, denies="NET-XDP-01")
    _assert_contract_error("MBPF305", make_plan, [sneaky], [target])


def test_plan_rejects_bad_revisions():
    target = make_target()
    case = make_case("NET-XDP-01", target["fingerprint"])
    bad = dict(REVISIONS)
    bad["repository_commit"] = "xyz"
    _assert_contract_error("MBPF305", make_plan, [case], [target],
                           "plan-1", bad)


# Case results and cost records.


def test_result_pass_round_trip_and_digest():
    run_plan, target, _ = basic_plan()
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    result = CaseResult.from_dict(raw)
    assert result.to_dict() == raw
    assert result.digest() == CaseResult.from_dict(raw).digest()
    assert len(result.digest()) == 64


def test_result_rejects_forged_pass():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(run_plan, "NET-XDP-01", fp, evidence=[])
    _assert_contract_error("MBPF305", CaseResult.from_dict, raw)
    raw = make_result(
        run_plan,
        "NET-XDP-01",
        fp,
        observed={"outcome": "FAIL", "failure_stage": "RUNTIME"},
        outcome="PASS",
        failure_stage=None,
    )
    _assert_contract_error("MBPF305", CaseResult.from_dict, raw)
    raw = make_result(
        run_plan,
        "NET-XDP-01",
        fp,
        cleanup={"status": "NOT_CHECKED", "residue": []},
    )
    _assert_contract_error("MBPF305", CaseResult.from_dict, raw)


def test_result_rejects_truncated_and_unknown():
    run_plan, target, _ = basic_plan()
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    del raw["identities"]["workload"]
    _assert_contract_error("MBPF303", CaseResult.from_dict, raw)
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    del raw["outcome"]
    _assert_contract_error("MBPF303", CaseResult.from_dict, raw)
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    raw["success_text"] = "PASS (trust me)"
    _assert_contract_error("MBPF302", CaseResult.from_dict, raw)
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    raw["schema_version"] = 99
    _assert_contract_error("MBPF304", CaseResult.from_dict, raw)


def test_result_fail_requires_stage_and_matches_observed():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(
        run_plan, "NET-XDP-01", fp, outcome="FAIL",
        failure_stage="RUNTIME",
    )
    raw["cleanup"] = {"status": "CLEAN", "residue": []}
    assert CaseResult.from_dict(raw).outcome == "FAIL"
    raw = make_result(
        run_plan, "NET-XDP-01", fp, outcome="FAIL",
        failure_stage=None,
        observed={"outcome": "FAIL", "failure_stage": None},
    )
    _assert_contract_error("MBPF305", CaseResult.from_dict, raw)
    raw = make_result(
        run_plan, "NET-XDP-01", fp, outcome="FAIL",
        failure_stage="LOAD",
        observed={"outcome": "FAIL", "failure_stage": "RUNTIME"},
    )
    _assert_contract_error("MBPF305", CaseResult.from_dict, raw)


def test_cost_record_values():
    good = {
        "schema_version": 1,
        "case_id": "NET-XDP-01",
        "target_fingerprint": _sha("t"),
        "metric": "reachable_slots",
        "unit": "slots",
        "value": 128,
        "basis": {
            "object_sha256": _sha("o"),
            "profile": "linux-bpfel-v3",
            "flags": ["-O2"],
        },
    }
    assert CostRecord.from_dict(good).to_dict() == good
    unavailable = dict(good)
    unavailable["value"] = None
    unavailable["unavailable_reason"] = "verifier metrics not exposed"
    assert CostRecord.from_dict(unavailable).to_dict() == unavailable
    missing_reason = dict(good)
    missing_reason["value"] = None
    _assert_contract_error("MBPF305", CostRecord.from_dict, missing_reason)
    both = dict(unavailable)
    both["value"] = 0
    _assert_contract_error("MBPF305", CostRecord.from_dict, both)


# Aggregation: happy paths, retries and denial scoping.


def test_aggregate_pass():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(run_plan, "NET-XDP-01", fp)
    decision = aggregate(run_plan, [raw])
    assert decision.verdict == "PASS"
    assert decision.ledger["passed"] == {
        "count": 1,
        "cells": ["NET-XDP-01@%s" % fp],
    }
    assert decision.ledger["required"]["count"] == 1
    assert decision.rejected == ()
    suite = decision.to_suite_dict()
    assert suite["suite_result_version"] == "suite-result-v1"
    assert suite["plan_hash"] == run_plan.plan_hash
    assert suite["result_digests"] == [CaseResult.from_dict(raw).digest()]
    assert suite["attempts_preserved"] == 1
    assert suite["decision"]["verdict"] == "PASS"


def test_aggregate_retry_preserves_every_attempt():
    target = make_target()
    fp = target["fingerprint"]
    case = make_case("NET-XDP-01", fp, expected_attempts=2)
    run_plan = make_plan([case], [target])
    first = make_result(
        run_plan, "NET-XDP-01", fp, attempt=1, outcome="INFRA_ERROR",
        failure_stage="INFRA",
    )
    second = make_result(run_plan, "NET-XDP-01", fp, attempt=2)
    decision = aggregate(run_plan, [first, second])
    assert decision.verdict == "PASS"
    assert len(decision.accepted) == 2
    assert decision.suite.attempts_preserved == 2
    assert len(decision.suite.result_digests) == 2


def test_aggregate_denial_passes_only_its_case():
    run_plan, target = guarded_plan()
    fp = target["fingerprint"]
    denial_pass = make_result(run_plan, "NET-XDP-01-DENY", fp)
    decision = aggregate(run_plan, [denial_pass])
    assert decision.verdict == "INCOMPLETE"
    assert decision.ledger["passed"]["cells"] == [
        "NET-XDP-01-DENY@%s" % fp
    ]
    assert decision.ledger["not_run"]["cells"] == ["NET-XDP-01@%s" % fp]
    assert any("missing cell" in reason for reason in decision.reasons)


def test_aggregate_guarded_full_pass():
    run_plan, target = guarded_plan()
    fp = target["fingerprint"]
    decision = aggregate(
        run_plan,
        [
            make_result(run_plan, "NET-XDP-01", fp),
            make_result(run_plan, "NET-XDP-01-DENY", fp),
        ],
    )
    assert decision.verdict == "PASS"
    assert decision.ledger["passed"]["count"] == 2


# Aggregation negatives: every one forces a non-PASS gate and preserves
# every submitted attempt.


def test_aggregate_missing_case_is_incomplete():
    run_plan, _, _ = basic_plan()
    decision = aggregate(run_plan, [])
    assert decision.verdict == "INCOMPLETE"
    assert decision.ledger["not_run"]["count"] == 1
    assert decision.suite is None


def test_aggregate_duplicate_is_rejected():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(run_plan, "NET-XDP-01", fp)
    decision = aggregate(run_plan, [raw, dict(raw)])
    assert decision.verdict == "FAIL"
    assert len(decision.rejected) == 1
    assert decision.rejected[0]["code"] == "MBPF312"
    assert decision.rejected[0]["raw_digest"] == CaseResult.from_dict(
        raw
    ).digest()
    assert decision.suite.attempts_preserved == 2


def test_aggregate_unplanned_case_and_unknown_target():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    planned = make_result(run_plan, "NET-XDP-01", fp)
    stray = make_result(run_plan, "NET-XDP-01", fp)
    stray["case_id"] = "HARNESS-01"
    wrong_target = make_result(run_plan, "NET-XDP-01", fp)
    wrong_target["target_fingerprint"] = _sha("elsewhere")
    decision = aggregate(run_plan, [planned, stray, wrong_target])
    assert decision.verdict == "FAIL"
    codes = [entry["code"] for entry in decision.rejected]
    assert codes == ["MBPF310", "MBPF310"]
    assert decision.suite.attempts_preserved == 3


def _mutated_identity_result(run_plan, target, mutate):
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    mutate(raw)
    return raw


def _drift_expected(raw):
    # A FAIL whose expectation disagrees with the plan parses cleanly
    # (only PASS must observe its expectation) and fails at aggregation.
    raw.update(
        {
            "expected": {"outcome": "FAIL", "failure_stage": "LOAD"},
            "observed": {"outcome": "FAIL", "failure_stage": "RUNTIME"},
            "outcome": "FAIL",
            "failure_stage": "RUNTIME",
            "cleanup": {"status": "CLEAN", "residue": []},
        }
    )


def test_aggregate_wrong_hashes_rejected():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    good = make_result(run_plan, "NET-XDP-01", fp)
    mutations = [
        lambda raw: raw.update({"plan_hash": "1" * 64}),
        lambda raw: raw["identities"].update(
            {"repository_commit": OTHER_COMMIT}
        ),
        lambda raw: raw["identities"].update({"package": "mojobpf-9.9.9"}),
        lambda raw: raw["identities"].update({"tool": "other-1.0"}),
        lambda raw: raw["identities"].update(
            {"source_sha256": _sha("wrong-source")}
        ),
        lambda raw: raw["identities"].update(
            {"object_sha256": _sha("wrong-object")}
        ),
        lambda raw: raw["identities"].update(
            {"consumer": {"name": "stock-libbpf", "version": "9.9.9"}}
        ),
        lambda raw: raw["identities"]["workload"].update(
            {"fixture_id": "fx-other"}
        ),
        lambda raw: raw.update({"required": False}),
        _drift_expected,
    ]
    for mutate in mutations:
        bad = _mutated_identity_result(run_plan, target, mutate)
        decision = aggregate(run_plan, [bad])
        assert decision.verdict == "FAIL"
        assert len(decision.rejected) == 1
        assert decision.rejected[0]["code"] == "MBPF311", mutate
        assert decision.rejected[0]["raw_digest"] is not None
    assert aggregate(run_plan, [good]).verdict == "PASS"


def test_aggregate_truncated_record_preserved():
    run_plan, target, _ = basic_plan()
    good = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    truncated = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    del truncated["observed"]
    del truncated["identities"]["workload"]
    decision = aggregate(run_plan, [good, truncated, "not-a-record"])
    assert decision.verdict == "FAIL"
    assert [entry["code"] for entry in decision.rejected] == [
        "MBPF303",
        "MBPF301",
    ]
    assert decision.suite.attempts_preserved == 3


def test_aggregate_dropped_shard_and_attempt():
    first_target = make_target()
    second_target = make_target(execution_mode="physical")
    fp1 = first_target["fingerprint"]
    fp2 = second_target["fingerprint"]
    case = make_case("NET-XDP-01", fp1, targets=[fp1, fp2])
    run_plan = make_plan([case], [first_target, second_target])
    only_first = make_result(run_plan, "NET-XDP-01", fp1)
    decision = aggregate(run_plan, [only_first])
    assert decision.verdict == "INCOMPLETE"
    assert decision.ledger["not_run"]["cells"] == ["NET-XDP-01@%s" % fp2]

    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    two_attempt_case = make_case("NET-XDP-01", fp, expected_attempts=2)
    run_plan = make_plan([two_attempt_case], [target])
    one_of_two = make_result(run_plan, "NET-XDP-01", fp, attempt=1)
    decision = aggregate(run_plan, [one_of_two])
    assert decision.verdict == "INCOMPLETE"
    assert any("dropped attempt" in reason for reason in decision.reasons)


def test_aggregate_forged_success_cannot_pass():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    no_evidence = make_result(run_plan, "NET-XDP-01", fp, evidence=[])
    decision = aggregate(run_plan, [no_evidence])
    assert decision.verdict == "FAIL"
    assert decision.rejected[0]["code"] == "MBPF305"
    assert decision.ledger["passed"]["count"] == 0


def test_aggregate_missing_workload_rejected():
    run_plan, target, _ = basic_plan()
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    del raw["identities"]["workload"]
    decision = aggregate(run_plan, [raw])
    assert decision.verdict == "FAIL"
    assert decision.rejected[0]["code"] == "MBPF303"


def test_aggregate_retry_replacement_rejected():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    orphan_second = make_result(run_plan, "NET-XDP-01", fp, attempt=2)
    decision = aggregate(run_plan, [orphan_second])
    assert decision.verdict == "FAIL"
    assert decision.rejected[0]["code"] == "MBPF313"
    assert decision.suite.attempts_preserved == 1


def test_aggregate_cleanup_residue_fails():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    dirty = make_result(
        run_plan,
        "NET-XDP-01",
        fp,
        outcome="FAIL",
        failure_stage="CLEANUP",
        cleanup={"status": "RESIDUE", "residue": ["/run/mojobpf-1/bpffs/x"]},
    )
    decision = aggregate(run_plan, [dirty])
    assert decision.verdict == "FAIL"
    assert decision.ledger["failed"]["count"] == 1


def test_aggregate_cleanup_not_checked_is_incomplete():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    unchecked = make_result(
        run_plan,
        "NET-XDP-01",
        fp,
        outcome="INFRA_ERROR",
        failure_stage="INFRA",
    )
    decision = aggregate(run_plan, [unchecked])
    assert decision.verdict == "INCOMPLETE"
    assert decision.ledger["blocked"]["count"] == 1


def test_aggregate_blocked_cells_never_pass():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    for availability in (
        "HARDWARE_MISSING",
        "KERNEL_FEATURE_ABSENT",
        "CONFIG_DISABLED",
        "TOOLCHAIN_UNAVAILABLE",
        "UNKNOWN",
        "UPSTREAM_BLOCKED",
        "POLICY_DENIED",
        "TARGET_RESOURCE_ABSENT",
    ):
        raw = make_result(
            run_plan,
            "NET-XDP-01",
            fp,
            outcome="NOT_RUN",
            applicability=availability,
            failure_stage="INFRA",
        )
        decision = aggregate(run_plan, [raw])
        assert decision.verdict == "INCOMPLETE", availability
        assert decision.ledger["passed"]["count"] == 0, availability
        assert decision.ledger["blocked"]["count"] == 1, availability


def test_aggregate_pass_on_unavailable_cell_rejected():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    lying = make_result(
        run_plan, "NET-XDP-01", fp, applicability="HARDWARE_MISSING"
    )
    decision = aggregate(run_plan, [lying])
    assert decision.verdict == "FAIL"
    assert decision.rejected[0]["code"] == "MBPF314"
    assert decision.ledger["passed"]["count"] == 0


def test_aggregate_not_applicable_excluded():
    first_target = make_target()
    second_target = make_target(byte_order="be")
    fp1 = first_target["fingerprint"]
    fp2 = second_target["fingerprint"]
    assert fp1 != fp2
    case = make_case("NET-XDP-01", fp1, targets=[fp1, fp2])
    run_plan = make_plan([case], [first_target, second_target])
    decision = aggregate(
        run_plan,
        [
            make_result(run_plan, "NET-XDP-01", fp1),
            make_result(
                run_plan,
                "NET-XDP-01",
                fp2,
                outcome="NOT_RUN",
                applicability="NOT_APPLICABLE",
                failure_stage="INFRA",
            ),
        ],
    )
    assert decision.verdict == "PASS"
    assert decision.ledger["passed"]["count"] == 1
    assert any("excluded" in reason for reason in decision.reasons)


def test_aggregate_optional_failure_stays_visible():
    target = make_target()
    fp = target["fingerprint"]
    required_case = make_case("NET-XDP-01", fp)
    optional_case = make_case("COST-01", fp, required=False)
    run_plan = make_plan([required_case, optional_case], [target])
    failed_optional = make_result(
        run_plan,
        "COST-01",
        fp,
        outcome="FAIL",
        failure_stage="COST",
        cleanup={"status": "CLEAN", "residue": []},
    )
    decision = aggregate(
        run_plan,
        [
            make_result(run_plan, "NET-XDP-01", fp),
            failed_optional,
        ],
    )
    assert decision.verdict == "PASS"
    assert decision.ledger["failed"]["cells"] == ["COST-01@%s" % fp]


def test_aggregate_same_cell_rerun_id_change_is_duplicate():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    decision = aggregate(
        run_plan,
        [
            make_result(run_plan, "NET-XDP-01", fp, run_id="run-1"),
            make_result(run_plan, "NET-XDP-01", fp, run_id="run-2"),
        ],
    )
    # Both rows share one (case, target, attempt) key, so the second is a
    # duplicate even though its run_id differs.
    assert decision.verdict == "FAIL"
    assert decision.rejected[0]["code"] == "MBPF312"


def test_aggregate_mixed_run_id_two_cells():
    target = make_target()
    fp = target["fingerprint"]
    run_plan = make_plan(
        [make_case("NET-XDP-01", fp), make_case("MAP-01", fp)], [target]
    )
    decision = aggregate(
        run_plan,
        [
            make_result(run_plan, "NET-XDP-01", fp, run_id="run-1"),
            make_result(run_plan, "MAP-01", fp, run_id="run-2"),
        ],
    )
    assert decision.verdict == "FAIL"
    assert any(
        entry["code"] == "MBPF311" for entry in decision.rejected
    )


def test_aggregate_malformed_plan_raises():
    _assert_contract_error("MBPF303", aggregate, {"nope": True}, [])


def test_aggregate_accepts_model_objects():
    run_plan, target, _ = basic_plan()
    raw = make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    decision = aggregate(run_plan, [CaseResult.from_dict(raw)])
    assert decision.verdict == "PASS"


# Suite binding and the digest-pinned schema bundle.


def test_verify_suite_result_round_trip():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raws = [make_result(run_plan, "NET-XDP-01", fp)]
    decision = aggregate(run_plan, raws)
    checked = verify_suite_result(decision.to_suite_dict(), run_plan, raws)
    assert checked.decision["verdict"] == "PASS"


def test_verify_suite_result_rejects_tampering():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raws = [make_result(run_plan, "NET-XDP-01", fp)]
    suite = aggregate(run_plan, raws).to_suite_dict()
    forged = json.loads(json.dumps(suite))
    forged["result_digests"] = ["0" * 64]
    _assert_contract_error(
        "MBPF314", verify_suite_result, forged, run_plan, raws
    )
    forged = json.loads(json.dumps(suite))
    forged["decision"]["verdict"] = "FAIL"
    _assert_contract_error(
        "MBPF314", verify_suite_result, forged, run_plan, raws
    )
    forged = json.loads(json.dumps(suite))
    forged["attempts_preserved"] = 99
    _assert_contract_error(
        "MBPF314", verify_suite_result, forged, run_plan, raws
    )


def test_suite_result_rejects_bad_ledger_counts():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    suite = aggregate(
        run_plan, [make_result(run_plan, "NET-XDP-01", fp)]
    ).to_suite_dict()
    suite["ledger"]["passed"]["count"] = 99
    _assert_contract_error("MBPF305", SuiteResult.from_dict, suite)


def test_schema_bundle_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "bundle")
        manifest = export_schema_bundle(dest)
        assert manifest["bundle"] == "mojobpf-test-contracts"
        assert manifest["version"] == 1
        assert manifest["contracts"] == [
            "test-contracts-v1",
            "suite-result-v1",
        ]
        assert sorted(manifest["schemas"]) == sorted(SCHEMA_FILES)
        assert os.path.isfile(os.path.join(dest, "README.txt"))
        checked = verify_schema_bundle(dest)
        assert checked == manifest


def test_schema_bundle_rejects_tampering_and_loss():
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "bundle")
        export_schema_bundle(dest)
        with open(
            os.path.join(dest, "result.schema.json"), "a", encoding="utf-8"
        ) as handle:
            handle.write(" ")
        _assert_contract_error("MBPF307", verify_schema_bundle, dest)
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "bundle")
        export_schema_bundle(dest)
        os.unlink(os.path.join(dest, "cost.schema.json"))
        _assert_contract_error("MBPF307", verify_schema_bundle, dest)
    with tempfile.TemporaryDirectory() as tmp:
        manifest = export_schema_bundle(tmp)
        manifest["contracts"] = ["test-contracts-v1"]
        with open(
            os.path.join(tmp, "bundle.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(manifest, handle)
        _assert_contract_error("MBPF307", verify_schema_bundle, tmp)


def test_schema_bundle_matches_live_schemas():
    with tempfile.TemporaryDirectory() as tmp:
        manifest = export_schema_bundle(tmp)
        for name in ("target", "fixture", "run-plan", "result", "cost"):
            filename = "%s.schema.json" % name
            assert manifest["schemas"][filename]["sha256"] == schema_digest(
                name
            )


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
