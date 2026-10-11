# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Offline bootstrap evidence tests; fixtures do not qualify a real target."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ci" / "targets" / "bootstrap.py"


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def bootstrap():
    assert SCRIPT.is_file(), "the offline bootstrap assessor is not implemented"
    spec = importlib.util.spec_from_file_location("target_bootstrap", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_record(root, attempt, name, record):
    raw = (json.dumps(record, indent=2) + "\n").encode()
    path = root / (name + ".json")
    path.write_bytes(raw)
    attempt["evidence"][name] = {
        "path": path.name, "sha256": hashlib.sha256(raw).hexdigest()
    }


@pytest.fixture
def evidence(tmp_path):
    expected = {
        "kernel_release": "6.12.0-control", "kernel_source_commit": None,
        "kernel_build_id": "control-build", "kernel_config_sha256": "b" * 64,
        "vmlinux_btf_sha256": "e" * 64,
        "kernel_image_sha256": "c" * 64, "kernel_packages_sha256": "d" * 64,
        "rootfs_sha256": "e" * 64, "payload_sha256": "f" * 64,
        "runner_admission_sha256": "1" * 64,
        "launcher_admission_sha256": "2" * 64, "qemu_admission_sha256": "3" * 64,
        "observer_sha256": "4" * 64, "compiler_sha256": "5" * 64,
        "control_source_sha256": "6" * 64, "control_object_sha256": "7" * 64,
        "packet_sha256": "8" * 64, "bpftool_sha256": "9" * 64,
        "python_sha256": "a" * 64, "libbpf_sha256": "b" * 64,
        "recovery_plan_sha256": "c" * 64,
        "bpftool_version": "bpftool v7.7.0", "execution_mode": "tcg",
        "architecture": "x86_64", "byte_order": "le", "instruction_profile": "v3",
    }
    proposal = {
        "schema_version": 1, "run_id": "control-run", "lane_id": "control-tcg",
        "lease": {"id": "control-lease", "owner": "target-worker", "exclusive": True,
                  "record_sha256": "d" * 64, "rootfs_read_only": True,
                  "guest_pin_root": "/sys/fs/bpf/mojobpf/control-run",
                  "host_write_paths": [str(tmp_path / "output")]},
        "expected": expected,
    }
    target = {
        "schema_version": 1,
        "kernel": {"release": expected["kernel_release"],
                   "source_commit": None,
                   "build_id": expected["kernel_build_id"],
                   "config_sha256": expected["kernel_config_sha256"]},
        "btf": {"vmlinux_sha256": "e" * 64, "modules": []},
        "image": {"digest": expected["rootfs_sha256"],
                  "packages": {"bpftool": "7.7.0", "libbpf": "1.7"}},
        "cpu": {"architecture": "x86_64", "model": "QEMU", "features": [],
                "page_size": 4096, "cpus": 1},
        "execution_mode": "tcg", "byte_order": "le", "instruction_profile": "v3",
        "jit": {"state": "enabled", "hardening": []},
        "boot": {"parameters": ["console=ttyS0"], "lsms": [], "lockdown": "none"},
        "privileges": {"capabilities": ["CAP_BPF"], "token": "none",
                       "delegation": "none", "rlimits": {"memlock": "unlimited"}},
        "mounts": {"tracefs": "guest-private", "bpffs": proposal["lease"]["guest_pin_root"],
                   "cgroup": "guest-private", "namespaces": ["disposable-guest"]},
        "build_host": {"identity": expected["compiler_sha256"],
                       "flags": ["--target=bpfel", "-O2", "-g"]},
    }
    target["fingerprint"] = digest(target)
    attempt = {"schema_version": 1, "run_id": proposal["run_id"],
               "lane_id": proposal["lane_id"], "lease_id": proposal["lease"]["id"],
               "provisional_sha256": digest(proposal), "evidence": {}}
    execution = {"run_id": proposal["run_id"], "terminal": True, "exit_code": 0,
                 "outcome": "PASS", "inputs": copy.deepcopy(expected),
                 "host_write_paths": proposal["lease"]["host_write_paths"]}
    positive = {
        "tool": "bpf_test_run", "contract_version": 2, "status": "pass",
        "stage": "run", "classification": None, "expected_action": 2,
        "actual_action": 2, "repeat": 1, "cleanup_ok": True,
        "object": {"path": "control.bpf.o", "sha256": expected["control_object_sha256"]},
        "data_in": {"path": "packet.bin", "sha256": expected["packet_sha256"], "size": 60},
        "bpftool": {"path": "/usr/sbin/bpftool", "version": expected["bpftool_version"],
                    "entry_sha256": expected["bpftool_sha256"], "exec_path": None,
                    "exec_sha256": None},
        "runtime": {"uid": 0, "kernel_release": expected["kernel_release"]},
        "pin_path": proposal["lease"]["guest_pin_root"] + "/positive",
        "admission": {"bpftool_admitted": True, "owned_root": "/sys/fs/bpf/mojobpf",
                      "ownership_token": proposal["run_id"]},
        "commands": [
            {"argv": ["/usr/sbin/bpftool", "version"], "exit_code": 0, "timeout": False,
             "stdout": "bpftool v7.7.0\n", "stderr": ""},
            {"argv": ["/usr/sbin/bpftool", "prog", "load", "control.bpf.o",
                      proposal["lease"]["guest_pin_root"] + "/positive"],
             "exit_code": 0, "timeout": False, "stdout": "", "stderr": ""},
            {"argv": ["/usr/sbin/bpftool", "prog", "run", "pinned",
                      proposal["lease"]["guest_pin_root"] + "/positive",
                      "data_in", "packet.bin", "repeat", "1"],
             "exit_code": 0, "timeout": False, "stdout": "Return value: 2\n", "stderr": ""},
            {"argv": ["rm", "-f", proposal["lease"]["guest_pin_root"] + "/positive"],
             "exit_code": 0, "timeout": False, "stdout": "", "stderr": ""},
        ], "note": None,
    }
    negative = copy.deepcopy(positive)
    negative.update(status="fail", stage="load", classification="environment",
                    actual_action=None, cleanup_ok=None)
    negative["runtime"]["uid"] = 1001
    negative["pin_path"] = proposal["lease"]["guest_pin_root"] + "/negative"
    negative["commands"] = negative["commands"][:2]
    negative["commands"][1].update(exit_code=255, stderr="libbpf: Operation not permitted")
    negative["commands"][1]["argv"][-1] = negative["pin_path"]
    cleanup = {"status": "CLEAN", "owned_processes": [], "owned_mounts": [], "owned_pins": []}
    interrupted = {"run_id": "control-run-interrupted", "terminal": True,
                   "outcome": "INFRA_ERROR", "exit_code": -15,
                   "cleanup": copy.deepcopy(cleanup)}
    fresh = {"run_id": "control-run-recovered", "exit_code": 0,
             "result": copy.deepcopy(positive)}
    recovery = {"outcome": "PASS", "terminal": True, "plan_sha256": expected["recovery_plan_sha256"],
                "cleanup": copy.deepcopy(cleanup)}
    for name, record in (("interrupted_attempt", interrupted), ("fresh_control", fresh)):
        raw = (json.dumps(record) + "\n").encode()
        (tmp_path / (name + ".json")).write_bytes(raw)
        recovery[name] = {"path": name + ".json", "sha256": hashlib.sha256(raw).hexdigest()}
    records = {"target": target, "execution": execution,
               "positive": {"exit_code": 0, "result": positive},
               "permission_negative": {"exit_code": 3, "result": negative},
               "cleanup": cleanup, "recovery": recovery}
    for name, record in records.items():
        write_record(tmp_path, attempt, name, record)
    return tmp_path, proposal, attempt, records


def assess(evidence):
    root, proposal, attempt, _ = evidence
    return bootstrap().assess_bootstrap(proposal, attempt, digest(proposal), root)


def test_complete_offline_evidence_seals_only_the_target_boundary(evidence):
    report = assess(evidence)
    assert report["status"] == "READY"
    assert report["outcome"] == "PASS"
    assert report["target"]["kernel"]["release"] == "6.12.0-control"
    assert report["fingerprint"] == digest({k: v for k, v in report.items() if k != "fingerprint"})


@pytest.mark.parametrize("ready", [True, False])
def test_ready_contract_accepts_reports_and_refuses_incomplete_success(evidence, ready):
    # The assessor has no external runtime dependencies. The optional validator
    # independently checks the standalone schema when available to developers.
    jsonschema = pytest.importorskip("jsonschema")

    schema_path = ROOT / "ci" / "targets" / "target-ready.schema.json"
    assert schema_path.is_file(), "the standalone readiness contract is not implemented"
    schema = json.loads(schema_path.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    report = assess(evidence) if ready else bootstrap().assess_bootstrap(None, None, None, evidence[0])
    validator = jsonschema.Draft202012Validator(schema)
    assert not list(validator.iter_errors(report))
    report.update(status="READY", outcome="PASS", fingerprint="a" * 64, failure=None, target=None)
    assert list(validator.iter_errors(report)), "an absent target cannot satisfy a READY contract"


@pytest.mark.parametrize("field", ["kernel_image_sha256", "rootfs_sha256",
                                    "payload_sha256", "observer_sha256", "bpftool_sha256"])
def test_unknown_provisional_identity_is_unready(evidence, field):
    root, proposal, attempt, records = evidence
    proposal["expected"][field] = None
    attempt["provisional_sha256"] = digest(proposal)
    report = assess(evidence)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == "IDENTITY_UNKNOWN"
    assert report["target"] is None


def test_independent_provisional_pin_is_required(evidence):
    root, proposal, attempt, _ = evidence
    report = bootstrap().assess_bootstrap(proposal, attempt, "0" * 64, root)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == "ADMISSION_REFUSED"


def test_unknown_optional_source_provenance_does_not_block_runtime_identity(evidence):
    report = assess(evidence)
    assert report["status"] == "READY"
    assert report["target"]["kernel"]["source_commit"] is None


def test_admitted_source_provenance_cannot_be_substituted(evidence):
    root, proposal, attempt, records = evidence
    proposal["expected"]["kernel_source_commit"] = "a" * 40
    attempt["provisional_sha256"] = digest(proposal)
    records["execution"]["inputs"] = copy.deepcopy(proposal["expected"])
    records["target"]["kernel"]["source_commit"] = "b" * 40
    records["target"]["fingerprint"] = digest({k: v for k, v in records["target"].items() if k != "fingerprint"})
    for name in ("execution", "target"):
        write_record(root, attempt, name, records[name])
    assert assess(evidence)["failure"]["code"] == "IDENTITY_MISMATCH"


def test_guest_btf_must_match_the_admitted_kernel_image(evidence):
    root, _, attempt, records = evidence
    records["target"]["btf"]["vmlinux_sha256"] = "9" * 64
    records["target"]["fingerprint"] = digest({k: v for k, v in records["target"].items() if k != "fingerprint"})
    write_record(root, attempt, "target", records["target"])
    assert assess(evidence)["failure"]["code"] == "IDENTITY_MISMATCH"


def test_sealed_report_owns_its_input_records(evidence):
    _, proposal, attempt, _ = evidence
    report = assess(evidence)
    proposal["lease"]["owner"] = "different-owner"
    proposal["expected"]["kernel_release"] = "different-kernel"
    attempt["evidence"]["positive"]["sha256"] = "9" * 64
    assert report["lease"]["owner"] == "target-worker"
    assert report["inputs"]["kernel_release"] == "6.12.0-control"
    assert report["evidence"]["positive"]["sha256"] != "9" * 64


def test_recovery_requires_consumed_interruption_and_fresh_control_records(evidence):
    root, _, _, _ = evidence
    (root / "fresh_control.json").unlink()
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


def test_recovery_refuses_unclean_interrupted_attempt(evidence):
    root, _, attempt, records = evidence
    interrupted = json.loads((root / "interrupted_attempt.json").read_text())
    interrupted["cleanup"]["owned_processes"] = [123]
    raw = json.dumps(interrupted).encode()
    (root / "interrupted_attempt.json").write_bytes(raw)
    records["recovery"]["interrupted_attempt"]["sha256"] = hashlib.sha256(raw).hexdigest()
    write_record(root, attempt, "recovery", records["recovery"])
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


@pytest.mark.parametrize("change", ["missing", "nonexclusive", "writable-root", "wrong-attempt"])
def test_unleased_attempt_cannot_publish_readiness(evidence, change):
    _, proposal, attempt, _ = evidence
    if change == "missing":
        proposal["lease"] = None
    elif change == "nonexclusive":
        proposal["lease"]["exclusive"] = False
    elif change == "writable-root":
        proposal["lease"]["rootfs_read_only"] = False
    else:
        attempt["lease_id"] = "other-lease"
    attempt["provisional_sha256"] = digest(proposal)
    report = assess(evidence)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == "LEASE_REQUIRED"


@pytest.mark.parametrize("name,field,value,code", [
    ("execution", "terminal", False, "RUN_NONTERMINAL"),
    ("execution", "exit_code", -15, "RUN_FAILED"),
    ("execution", "outcome", "NOT_RUN", "RUN_NONTERMINAL"),
    ("execution", "host_write_paths", ["/tmp/foreign"], "LEASE_REQUIRED"),
    ("positive", "exit_code", 3, "CONTROL_FAILED"),
    ("permission_negative", "exit_code", 0, "NEGATIVE_FAILED"),
    ("cleanup", "owned_processes", [123], "CLEANUP_INCOMPLETE"),
    ("cleanup", "owned_mounts", ["foreign"], "CLEANUP_INCOMPLETE"),
    ("cleanup", "status", "NOT_CHECKED", "CLEANUP_INCOMPLETE"),
    ("recovery", "outcome", "NOT_RUN", "RECOVERY_FAILED"),
    ("recovery", "terminal", False, "RECOVERY_FAILED"),
    ("recovery", "plan_sha256", "a" * 64, "RECOVERY_FAILED"),
])
def test_non_successful_required_proof_is_unready(evidence, name, field, value, code):
    root, _, attempt, records = evidence
    records[name][field] = value
    write_record(root, attempt, name, records[name])
    report = assess(evidence)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == code


@pytest.mark.parametrize("path,value,code", [
    (("kernel", "release"), "6.12.0-wrong", "IDENTITY_MISMATCH"),
    (("kernel", "config_sha256"), "9" * 64, "IDENTITY_MISMATCH"),
    (("image", "digest"), "9" * 64, "IDENTITY_MISMATCH"),
    (("cpu", "architecture"), "aarch64", "IDENTITY_MISMATCH"),
    (("btf", "vmlinux_sha256"), None, "BTF_UNAVAILABLE"),
])
def test_wrong_or_absent_target_identity_is_unready(evidence, path, value, code):
    root, _, attempt, records = evidence
    records["target"][path[0]][path[1]] = value
    records["target"]["fingerprint"] = digest({k: v for k, v in records["target"].items() if k != "fingerprint"})
    write_record(root, attempt, "target", records["target"])
    report = assess(evidence)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == code


@pytest.mark.parametrize("field,value", [("status", "skipped"), ("actual_action", 1),
                                         ("repeat", True), ("cleanup_ok", False)])
def test_positive_control_requires_observed_single_repeat_pass(evidence, field, value):
    root, _, attempt, records = evidence
    records["positive"]["result"][field] = value
    write_record(root, attempt, "positive", records["positive"])
    assert assess(evidence)["failure"]["code"] == "CONTROL_FAILED"


def test_forged_control_summary_cannot_replace_command_observation(evidence):
    root, _, attempt, records = evidence
    records["positive"]["result"]["commands"][2]["stdout"] = "Return value: 1\n"
    write_record(root, attempt, "positive", records["positive"])
    assert assess(evidence)["failure"]["code"] == "CONTROL_FAILED"


@pytest.mark.parametrize("field,value", [("classification", "verifier"), ("stage", "setup")])
def test_permission_negative_must_reject_at_the_permission_layer(evidence, field, value):
    root, _, attempt, records = evidence
    records["permission_negative"]["result"][field] = value
    write_record(root, attempt, "permission_negative", records["permission_negative"])
    assert assess(evidence)["failure"]["code"] == "NEGATIVE_FAILED"


def test_changed_consumed_evidence_bytes_are_refused(evidence):
    root, _, _, _ = evidence
    (root / "positive.json").write_text('{}\n')
    assert assess(evidence)["failure"]["code"] == "EVIDENCE_INVALID"


def test_evidence_cannot_escape_the_owned_bundle(evidence):
    _, _, attempt, _ = evidence
    attempt["evidence"]["positive"]["path"] = "../positive.json"
    assert assess(evidence)["failure"]["code"] == "EVIDENCE_INVALID"


def test_missing_or_truncated_record_is_typed_unready(evidence):
    root, _, attempt, _ = evidence
    raw = b'{"terminal":'
    (root / "execution.json").write_bytes(raw)
    attempt["evidence"]["execution"]["sha256"] = hashlib.sha256(raw).hexdigest()
    assert assess(evidence)["failure"]["code"] == "EVIDENCE_INVALID"


def test_cli_emits_unready_json_for_unreadable_inputs(tmp_path):
    assert SCRIPT.is_file(), "the offline bootstrap assessor is not implemented"
    output = tmp_path / "report.json"
    proc = subprocess.run([sys.executable, str(SCRIPT), "--provisional", str(tmp_path / "missing"),
                           "--provisional-sha256", "a" * 64,
                           "--attempt", str(tmp_path / "missing-attempt"),
                           "--evidence-root", str(tmp_path), "--output", str(output)],
                          capture_output=True, text=True, timeout=10)
    assert proc.returncode == 3
    assert json.loads(output.read_text())["status"] == "UNREADY"
