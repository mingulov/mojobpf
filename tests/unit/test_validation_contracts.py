# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the frozen validation contracts and aggregation.

Covers test-contracts-v1/suite-result-v1: exact enums, target/fixture
parsing, plan sealing, result parsing, every aggregation negative from
the frozen contract, and the digest-pinned schema bundle. Every
negative asserts a non-PASS gate with every attempt preserved.
Standard library only.

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
    digest_of,
)

COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40


def _sha(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _sha_raw(raw):
    return hashlib.sha256(raw).hexdigest()


CONSUMER = {
    "name": "stock-libbpf",
    "version": "1.7.0",
    "artifact_sha256": _sha("consumer:stock-libbpf:1.7.0"),
}


def _evidence(case_id):
    return [
        {
            "path": "evidence/%s.log" % case_id,
            "sha256": _sha("log:%s" % case_id),
            "bytes": 10,
        }
    ]


def _schema_path(name):
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "schemas",
        "%s.schema.json" % name,
    )


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
        "consumers": [dict(CONSUMER)],
        "source_sha256": _sha("source:%s" % case_id),
        "object_sha256": _sha("object:%s" % case_id),
        "corpus_sha256": _sha("corpus:%s" % case_id),
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


def make_plan(cases, targets, revisions=None):
    return plan(cases, targets, revisions or dict(REVISIONS))


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
        expected={"outcome": "FAIL", "failure_stage": "ATTACH"},
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
            "consumer": dict(CONSUMER),
            "object_sha256": case.object_sha256,
            "source_sha256": case.source_sha256,
            "workload": {
                "fixture_id": case.fixture_id,
                "corpus_sha256": case.corpus_sha256,
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


def make_denial_result(run_plan, case_id, target_fp, **overrides):
    """Build a denial record observing the plan's expected failure."""
    case = next(
        item for item in run_plan.cases if item.case_id == case_id
    )
    assert case.expectation == "denial"
    params = {
        "outcome": "FAIL",
        "failure_stage": case.expected["failure_stage"],
        "expected": dict(case.expected),
        "cleanup": {"status": "CLEAN", "residue": []},
        "evidence": _evidence(case_id),
    }
    params.update(overrides)
    return make_result(run_plan, case_id, target_fp, **params)


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
        with open(_schema_path(name), "rb") as handle:
            expected = hashlib.sha256(handle.read()).hexdigest()
        assert schema_digest(name) == expected
        assert len(expected) == 64


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


def _strip_descriptions(value):
    if isinstance(value, dict):
        return {
            key: _strip_descriptions(item)
            for key, item in value.items()
            if key != "description"
        }
    if isinstance(value, list):
        return [_strip_descriptions(item) for item in value]
    return value


def test_embedded_target_schema_matches_standalone():
    run_plan_schema = load_schema("run-plan")
    embedded = run_plan_schema["properties"]["targets"]["items"]
    assert "kernel" in embedded["properties"]
    standalone = load_schema("target")
    for key in ("$schema", "$comment", "license", "title"):
        standalone.pop(key, None)
    assert _strip_descriptions(embedded) == _strip_descriptions(
        standalone
    )


def test_embedded_cost_schema_matches_standalone():
    result_schema = load_schema("result")
    embedded = result_schema["$defs"]["case_result"]["properties"][
        "costs"
    ]["items"]
    assert embedded["required"]
    standalone = load_schema("cost")
    for key in ("$schema", "$comment", "license", "title"):
        standalone.pop(key, None)
    assert _strip_descriptions(embedded) == _strip_descriptions(
        standalone
    )


def test_result_schema_enforces_cross_field_rules():
    schema = load_schema("result")
    behavior = schema["$defs"]["behavior"]
    assert behavior["then"]["properties"]["failure_stage"] == {
        "const": None
    }
    assert behavior["else"]["properties"]["failure_stage"] == {
        "$ref": "#/$defs/failure_stage"
    }
    rules = schema["$defs"]["case_result"]["allOf"]
    by_desc = {
        entry.get("description"): entry
        for entry in rules
        if "description" in entry
    }
    pass_rule = by_desc[
        "A PASS carries evidence, clean cleanup, a null stage and a "
        "PASS observation."
    ]
    then_props = pass_rule["then"]["properties"]
    assert then_props["evidence"] == {"minItems": 1}
    assert then_props["cleanup"]["properties"]["status"] == {
        "const": "CLEAN"
    }
    na_rule = by_desc["Exclusion from the gate denominator needs proof."]
    assert na_rule["then"]["properties"]["evidence"] == {"minItems": 1}
    stage_rules = [
        entry
        for entry in rules
        if set(entry.get("if", {}).get("properties", {}))
        == {"failure_stage"}
    ]
    pinned = {
        entry["if"]["properties"]["failure_stage"].get("const")
        for entry in stage_rules
    }
    pinned.discard(None)
    assert pinned == set(FAILURE_STAGES)
    consumer = schema["$defs"]["case_result"]["properties"][
        "identities"
    ]["properties"]["consumer"]
    assert consumer["required"] == ["name", "version", "artifact_sha256"]
    suite_required = schema["$defs"]["suite_result"]["required"]
    assert "rejected_digests" in suite_required


def test_run_plan_schema_pins_new_fields():
    schema = load_schema("run-plan")
    case = schema["properties"]["cases"]["items"]
    assert "corpus_sha256" in case["required"]
    assert (
        case["properties"]["consumers"]["items"]["required"]
        == ["name", "version", "artifact_sha256"]
    )
    assert "kernel" in schema["properties"]["targets"]["items"][
        "properties"
    ]


def test_fixture_schema_accepts_zero_map_sizes():
    schema = load_schema("fixture")
    layouts = schema["properties"]["maps"]["items"]["properties"]
    assert layouts["key"]["properties"]["bytes"]["minimum"] == 0
    assert layouts["value"]["properties"]["bytes"]["minimum"] == 0


def test_cost_schema_enforces_value_reason_exclusivity():
    schema = load_schema("cost")
    rule = schema["allOf"][0]
    assert rule["then"]["required"] == ["unavailable_reason"]


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


def test_target_rejects_hostile_shapes():
    raw = make_target()
    raw["cpu"]["features"] = 5
    _assert_contract_error("MBPF305", TargetManifest.from_dict, raw)
    raw = make_target()
    raw["jit"]["hardening"] = {"spectre": True}
    _assert_contract_error("MBPF305", TargetManifest.from_dict, raw)
    raw = make_target()
    raw["btf"]["modules"] = "bpf_testmod"
    _assert_contract_error("MBPF305", TargetManifest.from_dict, raw)
    raw = make_target()
    raw["execution_mode"] = ["tcg"]
    _assert_contract_error("MBPF305", TargetManifest.from_dict, raw)


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


def test_fixture_accepts_ringbuf_zero_sizes():
    raw = make_fixture()
    raw["maps"] = [
        {
            "name": "events",
            "map_type": "RINGBUF",
            "key": {"type": "void", "bytes": 0},
            "value": {"type": "void", "bytes": 0},
            "max_entries": 4096,
        }
    ]
    assert Fixture.from_dict(raw).to_dict() == raw


def test_fixture_rejects_hostile_shapes():
    _assert_contract_error(
        "MBPF305", Fixture.from_dict, make_fixture(barriers=[[]])
    )
    _assert_contract_error(
        "MBPF305", Fixture.from_dict, make_fixture(barriers="ready")
    )
    _assert_contract_error(
        "MBPF305", Fixture.from_dict, make_fixture(maps={})
    )


# Run plans.


def test_plan_happy_path_and_stable_hash():
    run_plan, target, case = basic_plan()
    assert run_plan.plan_id.startswith("plan-")
    assert len(run_plan.plan_id) == len("plan-") + 16
    assert run_plan.cells() == [("NET-XDP-01", target["fingerprint"])]
    clone = make_plan([case], [target])
    assert clone.plan_id == run_plan.plan_id
    assert clone.plan_hash == run_plan.plan_hash
    assert RunPlan.from_dict(run_plan.to_dict()) == run_plan


def test_plan_takes_exactly_three_arguments():
    target = make_target()
    case = make_case("NET-XDP-01", target["fingerprint"])
    run_plan = plan([case], [target], dict(REVISIONS))
    assert run_plan.cells() == [("NET-XDP-01", target["fingerprint"])]
    try:
        plan([case], [target], dict(REVISIONS), "plan-1")
    except TypeError:
        pass
    else:
        raise AssertionError("plan() must not accept a plan_id argument")


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
    deny_expected = {"outcome": "FAIL", "failure_stage": "ATTACH"}
    lonely_deny = make_case(
        "DENY-1",
        fp,
        expectation="denial",
        denies="MISSING",
        expected=dict(deny_expected),
    )
    _assert_contract_error(
        "MBPF305", make_plan, [lonely_deny], [target]
    )
    positive = make_case("NET-XDP-01", fp)
    deny_of_deny = make_case(
        "DENY-2",
        fp,
        expectation="denial",
        denies="DENY-1",
        expected=dict(deny_expected),
    )
    first_deny = make_case(
        "DENY-1",
        fp,
        expectation="denial",
        denies="NET-XDP-01",
        expected=dict(deny_expected),
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
    _assert_contract_error(
        "MBPF305", make_plan, [case], [target], bad
    )


def test_plan_rejects_denial_expecting_pass():
    target = make_target()
    fp = target["fingerprint"]
    positive = make_case("NET-XDP-01", fp)
    bad = make_case(
        "DENY-1", fp, expectation="denial", denies="NET-XDP-01"
    )
    _assert_contract_error(
        "MBPF305", make_plan, [positive, bad], [target]
    )


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


def test_result_rejects_bare_not_applicable():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(
        run_plan, "NET-XDP-01", fp, outcome="NOT_RUN",
        applicability="NOT_APPLICABLE", failure_stage="INFRA",
    )
    _assert_contract_error("MBPF305", CaseResult.from_dict, raw)
    raw = make_result(
        run_plan, "NET-XDP-01", fp, outcome="NOT_RUN",
        applicability="NOT_APPLICABLE", failure_stage="INFRA",
        evidence=_evidence("NET-XDP-01"),
    )
    assert CaseResult.from_dict(raw).applicability == "NOT_APPLICABLE"


def test_result_rejects_hostile_shapes_without_abort():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    hostile = [
        lambda raw: raw.update({"outcome": []}),
        lambda raw: raw.update({"outcome": {"nested": True}}),
        lambda raw: raw.update({"failure_stage": ["INFRA"]}),
        lambda raw: raw.update({"applicability": {}}),
        lambda raw: raw.update({"required": "yes"}),
        lambda raw: raw.update({"attempt": "1"}),
        lambda raw: raw.update({"attempt": True}),
        lambda raw: raw.update({"costs": 5}),
        lambda raw: raw.update(
            {"costs": {"metric": "reachable_slots"}}
        ),
        lambda raw: raw.update({"evidence": {}}),
        lambda raw: raw.update(
            {"expected": {"outcome": "PASS", "failure_stage": []}}
        ),
        lambda raw: raw.update(
            {"observed": {"outcome": "FAIL", "failure_stage": []}}
        ),
        lambda raw: raw.update(
            {"cleanup": {"status": [], "residue": []}}
        ),
    ]
    for index, mutate in enumerate(hostile):
        raw = make_result(run_plan, "NET-XDP-01", fp)
        mutate(raw)
        decision = aggregate(run_plan, [raw])
        assert decision.verdict == "FAIL", index
        assert len(decision.rejected) == 1, index
        assert decision.rejected[0]["code"] == "MBPF305", index


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
    assert suite["rejected_digests"] == []
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
    denial_pass = make_denial_result(run_plan, "NET-XDP-01-DENY", fp)
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
            make_denial_result(run_plan, "NET-XDP-01-DENY", fp),
        ],
    )
    assert decision.verdict == "PASS"
    assert decision.ledger["passed"]["count"] == 2


def test_aggregate_denial_wrong_stage_fails():
    run_plan, target = guarded_plan()
    fp = target["fingerprint"]
    rec = make_denial_result(
        run_plan,
        "NET-XDP-01-DENY",
        fp,
        observed={"outcome": "FAIL", "failure_stage": "RUNTIME"},
        outcome="FAIL",
        failure_stage="RUNTIME",
    )
    decision = aggregate(
        run_plan,
        [make_result(run_plan, "NET-XDP-01", fp), rec],
    )
    assert decision.verdict == "FAIL"
    assert decision.ledger["failed"]["cells"] == [
        "NET-XDP-01-DENY@%s" % fp
    ]
    assert decision.ledger["passed"]["count"] == 1


def test_aggregate_denial_without_proof_fails():
    run_plan, target = guarded_plan()
    fp = target["fingerprint"]
    bare = make_denial_result(
        run_plan, "NET-XDP-01-DENY", fp, evidence=[]
    )
    decision = aggregate(
        run_plan, [make_result(run_plan, "NET-XDP-01", fp), bare]
    )
    assert decision.verdict == "FAIL"
    assert any("unproven" in reason for reason in decision.reasons)
    dirty = make_denial_result(
        run_plan,
        "NET-XDP-01-DENY",
        fp,
        cleanup={"status": "RESIDUE", "residue": ["bpffs-stale"]},
    )
    decision = aggregate(
        run_plan, [make_result(run_plan, "NET-XDP-01", fp), dirty]
    )
    assert decision.verdict == "FAIL"
    assert decision.ledger["failed"]["cells"] == [
        "NET-XDP-01-DENY@%s" % fp
    ]


def test_aggregate_denial_ordinary_pass_rejected():
    run_plan, target = guarded_plan()
    fp = target["fingerprint"]
    rec = make_result(run_plan, "NET-XDP-01-DENY", fp)
    decision = aggregate(
        run_plan, [make_result(run_plan, "NET-XDP-01", fp), rec]
    )
    assert decision.verdict == "FAIL"
    assert decision.rejected[0]["code"] == "MBPF311"
    assert decision.ledger["passed"]["count"] == 1


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
            {
                "consumer": dict(
                    CONSUMER, version="9.9.9"
                )
            }
        ),
        lambda raw: raw["identities"].update(
            {
                "consumer": dict(
                    CONSUMER, artifact_sha256=_sha("wrong-consumer")
                )
            }
        ),
        lambda raw: raw["identities"]["workload"].update(
            {"fixture_id": "fx-other"}
        ),
        lambda raw: raw["identities"]["workload"].update(
            {"corpus_sha256": _sha("wrong-corpus")}
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
    target = make_target()
    fp = target["fingerprint"]
    case = make_case("NET-XDP-01", fp, expected_attempts=2)
    run_plan = make_plan([case], [target])
    orphan_second = make_result(run_plan, "NET-XDP-01", fp, attempt=2)
    decision = aggregate(run_plan, [orphan_second])
    assert decision.verdict == "FAIL"
    assert decision.rejected[0]["code"] == "MBPF313"
    assert decision.suite.attempts_preserved == 1


def test_aggregate_extra_attempt_rejected():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    first = make_result(run_plan, "NET-XDP-01", fp, attempt=1)
    extra = make_result(run_plan, "NET-XDP-01", fp, attempt=2)
    decision = aggregate(run_plan, [first, extra])
    assert decision.verdict == "FAIL"
    assert len(decision.rejected) == 1
    assert decision.rejected[0]["code"] == "MBPF310"
    assert decision.suite.attempts_preserved == 2
    assert len(decision.suite.rejected_digests) == 1


def test_aggregate_residue_before_retry_fails():
    target = make_target()
    fp = target["fingerprint"]
    case = make_case("NET-XDP-01", fp, expected_attempts=2)
    run_plan = make_plan([case], [target])
    first = make_result(
        run_plan,
        "NET-XDP-01",
        fp,
        attempt=1,
        outcome="FAIL",
        failure_stage="CLEANUP",
        cleanup={"status": "RESIDUE", "residue": ["/run/mojobpf-1/x"]},
    )
    second = make_result(run_plan, "NET-XDP-01", fp, attempt=2)
    decision = aggregate(run_plan, [first, second])
    assert decision.verdict == "FAIL"
    assert decision.ledger["failed"]["count"] == 1
    assert decision.ledger["passed"]["count"] == 0
    assert decision.suite.attempts_preserved == 2
    assert any("residue" in reason for reason in decision.reasons)


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
        assert decision.ledger["not_run"]["count"] == 1, availability


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


def test_aggregate_required_not_applicable_is_incomplete():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(
        run_plan,
        "NET-XDP-01",
        fp,
        outcome="NOT_RUN",
        applicability="NOT_APPLICABLE",
        failure_stage="INFRA",
        evidence=_evidence("NET-XDP-01"),
    )
    decision = aggregate(run_plan, [raw])
    assert decision.verdict == "INCOMPLETE"
    assert decision.ledger["passed"]["count"] == 0
    assert decision.ledger["blocked"]["count"] == 1
    assert not any("excluded" in reason for reason in decision.reasons)


def test_aggregate_optional_not_applicable_excluded():
    target = make_target()
    fp = target["fingerprint"]
    required_case = make_case("NET-XDP-01", fp)
    optional_case = make_case("BE-ONLY-01", fp, required=False)
    run_plan = make_plan([required_case, optional_case], [target])
    decision = aggregate(
        run_plan,
        [
            make_result(run_plan, "NET-XDP-01", fp),
            make_result(
                run_plan,
                "BE-ONLY-01",
                fp,
                outcome="NOT_RUN",
                applicability="NOT_APPLICABLE",
                failure_stage="INFRA",
                evidence=_evidence("BE-ONLY-01"),
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


def test_aggregate_revalidates_model_instances():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(run_plan, "NET-XDP-01", fp)
    good = CaseResult.from_dict(raw)
    evil = CaseResult(
        run_id=good.run_id,
        case_id=good.case_id,
        target_fingerprint=good.target_fingerprint,
        attempt=good.attempt,
        plan_hash=good.plan_hash,
        identities=good.identities,
        applicability=good.applicability,
        required=good.required,
        expected=good.expected,
        observed=good.observed,
        outcome="PASS",
        failure_stage=None,
        evidence=(),
        cleanup=good.cleanup,
        costs=good.costs,
    )
    decision = aggregate(run_plan, [evil])
    assert decision.verdict == "FAIL"
    assert len(decision.rejected) == 1
    assert decision.rejected[0]["code"] == "MBPF305"
    assert decision.ledger["passed"]["count"] == 0


def test_aggregate_revalidates_plan_instance():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    raw = make_result(run_plan, "NET-XDP-01", fp)
    run_plan.revisions["package"] = "mutated-9.9.9"
    _assert_contract_error("MBPF306", aggregate, run_plan, [raw])


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
    forged = json.loads(json.dumps(suite))
    forged["rejected_digests"] = ["0" * 64]
    _assert_contract_error(
        "MBPF314", verify_suite_result, forged, run_plan, raws
    )


def test_verify_suite_result_binds_rejected_attempts():
    run_plan, target, _ = basic_plan()
    fp = target["fingerprint"]
    good = make_result(run_plan, "NET-XDP-01", fp)
    bad = make_result(run_plan, "NET-XDP-01", fp, attempt=9)
    bad["identities"]["object_sha256"] = "1" * 64
    suite = aggregate(run_plan, [good, bad]).to_suite_dict()
    assert len(suite["rejected_digests"]) == 1
    assert suite["attempts_preserved"] == 2
    swapped = json.loads(json.dumps(bad))
    swapped["identities"]["object_sha256"] = "2" * 64
    _assert_contract_error(
        "MBPF314", verify_suite_result, suite, run_plan,
        [good, swapped],
    )
    dropped = json.loads(json.dumps(suite))
    dropped["rejected_digests"] = []
    _assert_contract_error(
        "MBPF314", verify_suite_result, dropped, run_plan,
        [good, bad],
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


def test_schema_bundle_manifest_pin():
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "bundle")
        manifest = export_schema_bundle(dest)
        pin = digest_of(manifest)
        assert len(pin) == 64
        assert verify_schema_bundle(dest, pin) == manifest
        _assert_contract_error(
            "MBPF307", verify_schema_bundle, dest, "0" * 64
        )


def test_schema_bundle_pin_rejects_resigned_tampering():
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "bundle")
        manifest = export_schema_bundle(dest)
        pin = digest_of(manifest)
        schema_path = os.path.join(dest, "result.schema.json")
        with open(schema_path, encoding="utf-8") as handle:
            doc = json.load(handle)
        doc["$defs"]["execution_outcome"]["enum"].append("FAKE_PASS")
        raw = json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")
        with open(schema_path, "wb") as handle:
            handle.write(raw)
        manifest["schemas"]["result.schema.json"]["sha256"] = _sha_raw(
            raw
        )
        with open(
            os.path.join(dest, "bundle.json"), "w", encoding="utf-8"
        ) as handle:
            json.dump(manifest, handle)
        # Self-consistent, so an unpinned check still passes; the
        # pinned check rejects the resigned bundle.
        assert verify_schema_bundle(dest)["version"] == 1
        _assert_contract_error(
            "MBPF307", verify_schema_bundle, dest, pin
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
