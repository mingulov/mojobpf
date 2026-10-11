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
        "kernel_release": "6.12.0-control", "kernel_source_commit": "a" * 40,
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
                   "source_commit": expected["kernel_source_commit"],
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
    def capture(phase, first_pid, boot_id):
        attempt_id = "control-run." + phase
        binding = {"attempt_id": attempt_id, "guest_id": attempt_id, "boot_id": boot_id}
        guest = {"id": binding["guest_id"], "boot_id": boot_id, "session_id": first_pid,
                 "processes": [{"pid": first_pid, "start_ticks": first_pid * 100, "role": "runner"},
                               {"pid": first_pid + 1, "start_ticks": first_pid * 100 + 1, "role": "qemu"}]}
        observed_target = copy.deepcopy(target)
        observed_target["boot"]["parameters"].append("virtme_hostname=" + guest["id"])
        observed_target["fingerprint"] = digest({k: v for k, v in observed_target.items() if k != "fingerprint"})
        execution = {"run_id": proposal["run_id"], "attempt_id": attempt_id,
                     "lane_id": proposal["lane_id"], "lease_id": proposal["lease"]["id"],
                     "provisional_sha256": digest(proposal), "phase": phase,
                     "terminal": True, "exit_code": -9 if phase == "interrupted" else 0,
                     "outcome": "INFRA_ERROR" if phase == "interrupted" else "PASS",
                     "inputs": copy.deepcopy(expected), "host_write_paths": proposal["lease"]["host_write_paths"],
                     "guest": guest, "target_fingerprint": observed_target["fingerprint"]}
        pin_base = proposal["lease"]["guest_pin_root"] + "/" + attempt_id
        result = {"tool": "bpf_test_run", "contract_version": 2, "status": "pass",
                  "stage": "run", "classification": None, "expected_action": 2,
                  "actual_action": 2, "repeat": 1, "cleanup_ok": True,
                  "object": {"path": "control.bpf.o", "sha256": expected["control_object_sha256"]},
                  "data_in": {"path": "packet.bin", "sha256": expected["packet_sha256"], "size": 60},
                  "bpftool": {"path": "/usr/sbin/bpftool", "version": expected["bpftool_version"],
                              "entry_sha256": expected["bpftool_sha256"], "exec_path": None, "exec_sha256": None},
                  "runtime": {"uid": 0, "kernel_release": expected["kernel_release"]},
                  "pin_path": pin_base + "/positive",
                  "admission": {"bpftool_admitted": True, "owned_root": "/sys/fs/bpf/mojobpf",
                                "ownership_token": proposal["run_id"]},
                  "commands": [
                      {"argv": ["/usr/sbin/bpftool", "version"], "exit_code": 0, "timeout": False,
                       "stdout": "bpftool v7.7.0\n", "stderr": ""},
                      {"argv": ["/usr/sbin/bpftool", "prog", "load", "control.bpf.o", pin_base + "/positive"],
                       "exit_code": 0, "timeout": False, "stdout": "", "stderr": ""},
                      {"argv": ["/usr/sbin/bpftool", "prog", "run", "pinned", pin_base + "/positive",
                                "data_in", "packet.bin", "repeat", "1"],
                       "exit_code": 0, "timeout": False, "stdout": "Return value: 2\n", "stderr": ""},
                      {"argv": ["rm", "-f", pin_base + "/positive"], "exit_code": 0, "timeout": False,
                       "stdout": "", "stderr": ""}], "note": None}
        positive = {**binding, "exit_code": 0, "result": result, "process": None, "context_sha256": None}
        negative_result = copy.deepcopy(result)
        negative_result.update(status="fail", stage="load", classification="environment", actual_action=None, cleanup_ok=None)
        negative_result["runtime"]["uid"] = 1001
        negative_result["pin_path"] = pin_base + "/permission-negative"
        negative_result["commands"] = negative_result["commands"][:2]
        negative_result["commands"][1].update(exit_code=255, stderr="libbpf: Operation not permitted")
        negative_result["commands"][1]["argv"][-1] = negative_result["pin_path"]
        process = {"pid": 17, "start_ticks": 50}
        proc_status = ("Pid:\t17\nUid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n"
                       "Groups:\t\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n"
                       "CapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n"
                       "CapBnd:\t0000000000000000\nNoNewPrivs:\t1\n")
        permission_context = {**binding, "process": process, "uid": 1001, "gid": 1001, "groups": [],
                              "no_new_privs": 1, "capabilities": {name: "0000000000000000" for name in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")},
                              "proc_status": proc_status, "proc_stat": "17 (python3) R " + " ".join(["0"] * 18 + ["50"]), "pin_parent": pin_base, "pin_parent_writable": True, "object_readable": True}
        context_ref = reference(phase + "_permission_context", permission_context)
        negative = {**binding, "exit_code": 3, "result": negative_result, "process": process, "context_sha256": context_ref["sha256"]}
        raw_mounts = "1 0 0:1 / / rw - tmpfs rootfs rw\n"
        cleanup = {**binding, "status": "CLEAN", "owned_processes": [], "owned_mounts": [], "owned_pins": [],
                   "process_observations": [{"pid": proc["pid"], "start_ticks": proc["start_ticks"], "alive": False} for proc in guest["processes"]],
                   "mount_observations": {"before": raw_mounts, "after": raw_mounts},
                   "guest_unmount": None if phase=="interrupted" else {"argv":["/usr/bin/umount","/sys/fs/bpf"],"exit_code":0,"timeout":False,"stdout":"","stderr":""},
                   "pin_observation": {"root": proposal["lease"]["guest_pin_root"], "root_exists": False,
                                       "entries": [], "basis": "guest-destroyed" if phase == "interrupted" else "guest-unmounted"}}
        absence = {**binding, "pin_root": proposal["lease"]["guest_pin_root"], "exists": False, "entries": []}
        return {"target": observed_target, "execution": execution, "positive": positive,
                "permission_negative": negative, "permission_context": permission_context,
                "cleanup": cleanup, "pin_root_absence": absence}

    def reference(name, record):
        raw = (json.dumps(record, indent=2) + "\n").encode()
        (tmp_path / (name + ".json")).write_bytes(raw)
        return {"path": name + ".json", "sha256": hashlib.sha256(raw).hexdigest()}

    records = capture("main", 100, "11111111-1111-4111-8111-111111111111")
    interrupted = capture("interrupted", 200, "22222222-2222-4222-8222-222222222222")
    binding = {key: interrupted["positive"][key] for key in ("attempt_id", "guest_id", "boot_id")}
    held_pin = proposal["lease"]["guest_pin_root"] + "/control-run.interrupted/recovery-held"
    interrupted["trigger"] = {**binding, "marker": "INTERRUPT_OWNED_GUEST", "held_pin": held_pin,
                              "held_pin_exists": True, "positive_sha256": digest(interrupted["positive"]),
                              "load_command": {"argv": ["/usr/sbin/bpftool", "prog", "load", "control.bpf.o", held_pin],
                                               "exit_code": 0, "timeout": False, "stdout": "", "stderr": ""}}
    fresh = capture("fresh", 300, "33333333-3333-4333-8333-333333333333")
    containers = {}
    for phase, data in (("interrupted", interrupted), ("fresh", fresh)):
        names = ("execution", "target", "positive", "trigger", "cleanup", "pin_root_absence") if phase == "interrupted" else tuple(data)
        containers[phase] = {key: reference(phase + "_" + key, data[key]) for key in names}
    records["recovery"] = {"outcome": "PASS", "terminal": True, "plan_sha256": expected["recovery_plan_sha256"],
                           "interrupted_attempt": reference("interrupted_attempt", containers["interrupted"]),
                           "fresh_attempt": reference("fresh_attempt", containers["fresh"])}
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


def test_unknown_source_provenance_cannot_publish_a_frozen_ready_target(evidence):
    root, proposal, attempt, records = evidence
    proposal["expected"]["kernel_source_commit"] = None
    attempt["provisional_sha256"] = digest(proposal)
    records["execution"]["inputs"] = copy.deepcopy(proposal["expected"])
    records["target"]["kernel"]["source_commit"] = None
    records["target"]["fingerprint"] = digest({k: v for k, v in records["target"].items() if k != "fingerprint"})
    for name in ("execution", "target"):
        write_record(root, attempt, name, records[name])
    report = assess(evidence)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == "IDENTITY_UNKNOWN"


def test_ready_target_is_consumable_by_the_frozen_model_and_schema(evidence):
    from mojobpf.validation.models import TargetManifest

    target = assess(evidence)["target"]
    assert TargetManifest.from_dict(target).fingerprint == target["fingerprint"]
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((ROOT / "schemas/target.schema.json").read_text())
    assert not list(jsonschema.Draft202012Validator(schema).iter_errors(target))


def test_permission_errno_does_not_override_raw_verifier_rejection(evidence):
    root, _, attempt, records = evidence
    records["permission_negative"]["result"]["commands"][1]["stderr"] = (
        "libbpf: prog load log: invalid mem access 'scalar'\n"
        "libbpf: failed to load program: Operation not permitted\n"
    )
    write_record(root, attempt, "permission_negative", records["permission_negative"])
    report = assess(evidence)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == "NEGATIVE_FAILED"


@pytest.mark.parametrize("name, code", [("positive", "CONTROL_FAILED"),
                                        ("permission_negative", "NEGATIVE_FAILED"),
                                        ("fresh_positive", "RECOVERY_FAILED"),
                                        ("interrupted_positive", "RECOVERY_FAILED"),
                                        ("fresh_permission_negative", "RECOVERY_FAILED")])
def test_raw_tool_version_must_agree_with_the_admitted_summary(evidence, name, code):
    root, _, attempt, records = evidence
    def change(record):
        record["result"]["commands"][0]["stdout"] = "bpftool v0.0.1\n"
    if name.startswith(("fresh_", "interrupted_")):
        phase, key = name.split("_", 1)
        mutate_recovery(evidence, phase, key, change)
    else:
        change(records[name])
        write_record(root, attempt, name, records[name])
    report = assess(evidence)
    assert report["status"] == "UNREADY"
    assert report["failure"]["code"] == code


def mutate_recovery(evidence, phase, name, change):
    """Edit captured bytes and reseal only their reference chain."""
    root, _, attempt, records = evidence
    ref = records["recovery"][phase + "_attempt"]
    container = json.loads((root / ref["path"]).read_text())
    if name is None:
        change(container)
    else:
        child = container[name]
        record = json.loads((root / child["path"]).read_text())
        change(record)
        raw = (json.dumps(record, indent=2) + "\n").encode()
        (root / child["path"]).write_bytes(raw)
        child["sha256"] = hashlib.sha256(raw).hexdigest()
    raw = (json.dumps(container) + "\n").encode()
    (root / ref["path"]).write_bytes(raw)
    ref["sha256"] = hashlib.sha256(raw).hexdigest()
    write_record(root, attempt, "recovery", records["recovery"])


@pytest.mark.parametrize("phase,name", [
    ("interrupted", name) for name in ("execution", "target", "positive", "trigger", "cleanup", "pin_root_absence")
] + [("fresh", name) for name in ("execution", "target", "positive", "permission_negative", "permission_context", "cleanup", "pin_root_absence")])
def test_every_recovery_observation_is_required(evidence, phase, name):
    mutate_recovery(evidence, phase, None, lambda container: container.pop(name))
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


@pytest.mark.parametrize("phase,name", [("interrupted", "positive"), ("fresh", "positive"),
                                       ("fresh", "permission_negative"), ("fresh", "cleanup"),
                                       ("fresh", "pin_root_absence")])
def test_main_evidence_cannot_be_reused_as_recovery(evidence, phase, name):
    replacement = copy.deepcopy(evidence[3][name])
    mutate_recovery(evidence, phase, name, lambda record: (record.clear(), record.update(replacement)))
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


@pytest.mark.parametrize("phase,field,value", [
    (phase, field, value) for phase in ("interrupted", "fresh") for field, value in (
        ("lane_id", "foreign"), ("lease_id", "foreign"), ("provisional_sha256", "9" * 64),
        ("inputs", {}), ("host_write_paths", ["/tmp/foreign"]), ("terminal", False),
        ("target_fingerprint", "9" * 64), ("attempt_id", "foreign"))])
def test_recovery_execution_must_match_the_admitted_attempt(evidence, phase, field, value):
    mutate_recovery(evidence, phase, "execution", lambda record: record.__setitem__(field, value))
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


@pytest.mark.parametrize("field", ["id", "boot_id", "session_id", "processes"])
def test_fresh_guest_and_host_process_identity_cannot_reuse_main(evidence, field):
    main = evidence[3]["execution"]["guest"][field]
    mutate_recovery(evidence, "fresh", "execution", lambda record: record["guest"].__setitem__(field, main))
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


@pytest.mark.parametrize("name,field,value", [
    ("trigger", "held_pin_exists", False), ("trigger", "marker", "OTHER"),
    ("trigger", "held_pin", "/sys/fs/bpf/foreign"), ("trigger", "positive_sha256", "9" * 64),
    ("trigger", "load_command", {"exit_code": 0}),
    ("pin_root_absence", "exists", True), ("pin_root_absence", "boot_id", "foreign"),
    ("cleanup", "status", "FAILED"), ("cleanup", "owned_processes", [200]),
    ("cleanup", "process_observations", []), ("cleanup", "mount_observations", {"before": "a", "after": "b"})])
def test_interrupted_attempt_requires_trigger_and_observed_cleanup(evidence, name, field, value):
    mutate_recovery(evidence, "interrupted", name, lambda record: record.__setitem__(field, value))
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


@pytest.mark.parametrize("name,field,value", [
    ("execution", "exit_code", -9), ("execution", "outcome", "NOT_RUN"),
    ("permission_negative", "exit_code", 0), ("cleanup", "status", "FAILED"),
    ("pin_root_absence", "entries", ["old-positive"]),
    ("pin_root_absence", "pin_root", "/sys/fs/bpf/foreign")])
def test_fresh_attempt_is_a_complete_new_control_run(evidence, name, field, value):
    mutate_recovery(evidence, "fresh", name, lambda record: record.__setitem__(field, value))
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


@pytest.mark.parametrize("field,value", [
    ("uid", 0), ("gid", 0), ("groups", [0]), ("no_new_privs", 0),
    ("capabilities", {"CapEff": "0000000000000001"}),
    ("proc_status", "Pid: 17\nUid: 0 0 0 0\n"), ("proc_stat", "17 (python3) R 0"),
    ("pin_parent_writable", False), ("object_readable", False),
    ("pin_parent", "/sys/fs/bpf/foreign"), ("boot_id", "foreign")])
def test_negative_requires_measured_unprivileged_writable_context(evidence, field, value):
    root, _, attempt, records = evidence
    records["permission_context"][field] = value
    write_record(root, attempt, "permission_context", records["permission_context"])
    # Keep the negative's digest consistent so this exercises the measured
    # context rather than the reference digest check.
    records["permission_negative"]["context_sha256"] = attempt["evidence"]["permission_context"]["sha256"]
    write_record(root, attempt, "permission_negative", records["permission_negative"])
    assert assess(evidence)["failure"]["code"] == "NEGATIVE_FAILED"


@pytest.mark.parametrize("field,value", [("context_sha256", "9" * 64), ("process", {"pid": 18, "start_ticks": 50})])
def test_negative_context_must_belong_to_the_control_process(evidence, field, value):
    root, _, attempt, records = evidence
    records["permission_negative"][field] = value
    write_record(root, attempt, "permission_negative", records["permission_negative"])
    assert assess(evidence)["failure"]["code"] == "NEGATIVE_FAILED"


@pytest.mark.parametrize("field,value", [("process_observations", []),
                                        ("mount_observations", {"before": "same", "after": "changed"}),
                                        ("pin_observation", {"root_exists": True})])
def test_cleanup_summary_cannot_replace_owned_resource_observations(evidence, field, value):
    root, _, attempt, records = evidence
    records["cleanup"][field] = value
    write_record(root, attempt, "cleanup", records["cleanup"])
    assert assess(evidence)["failure"]["code"] == "CLEANUP_INCOMPLETE"


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
    (root / "fresh_positive.json").unlink()
    assert assess(evidence)["failure"]["code"] == "RECOVERY_FAILED"


def test_recovery_refuses_unclean_interrupted_attempt(evidence):
    mutate_recovery(evidence, "interrupted", "cleanup", lambda record: record.__setitem__("owned_processes", [200]))
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


def test_cleanup_retains_every_captured_descendant_identity(evidence):
    root, _, attempt, records = evidence
    records['execution']['guest']['processes'].append({'pid':102,'start_ticks':10002,'role':'descendant'})
    write_record(root,attempt,'execution',records['execution'])
    # A clean runner/QEMU pair does not prove the retained descendant is gone.
    assert assess(evidence)['failure']['code']=='CLEANUP_INCOMPLETE'
    records['cleanup']['process_observations'].append({'pid':102,'start_ticks':10002,'alive':False})
    write_record(root,attempt,'cleanup',records['cleanup'])
    assert assess(evidence)['status']=='READY'


def test_relabelled_main_control_is_still_not_a_fresh_test_run(evidence):
    main=copy.deepcopy(evidence[3]['positive']['result'])
    mutate_recovery(evidence,'fresh','positive',lambda record:record.__setitem__('result',main))
    report=assess(evidence)
    assert report['failure']['code']=='RECOVERY_FAILED'
    assert 'control pin belongs to another attempt' in report['failure']['detail']


@pytest.mark.parametrize('field,value', [('CapEff','0000000000000001'),('NoNewPrivs','0')])
def test_zero_capability_summary_cannot_override_raw_process_status(evidence,field,value):
    root,_,attempt,records=evidence
    context=records['permission_context']
    old='0000000000000000' if field=='CapEff' else '1'
    context['proc_status']=context['proc_status'].replace(field+':\t'+old,field+':\t'+value)
    write_record(root,attempt,'permission_context',context)
    records['permission_negative']['context_sha256']=attempt['evidence']['permission_context']['sha256']
    write_record(root,attempt,'permission_negative',records['permission_negative'])
    assert assess(evidence)['failure']['code']=='NEGATIVE_FAILED'


def test_fresh_capture_cannot_relabel_a_reused_boot_identity(evidence):
    root,_,_,records=evidence
    boot=records['execution']['guest']['boot_id']
    mutate_recovery(evidence,'fresh','execution',lambda record:record['guest'].__setitem__('boot_id',boot))
    for name in ('positive','permission_negative','permission_context','cleanup','pin_root_absence'):
        mutate_recovery(evidence,'fresh',name,lambda record:record.__setitem__('boot_id',boot))
    container=json.loads((root/'fresh_attempt.json').read_text())
    context_sha=container['permission_context']['sha256']
    mutate_recovery(evidence,'fresh','permission_negative',lambda record:record.__setitem__('context_sha256',context_sha))
    report=assess(evidence)
    assert report['failure']['code']=='RECOVERY_FAILED'
    assert 'reused a guest, boot, session or process identity' in report['failure']['detail']


def test_fresh_capture_cannot_relabel_reused_host_processes(evidence):
    main=evidence[3]['execution']['guest']
    def change(record):
        record['guest']['session_id']=main['session_id']
        record['guest']['processes']=copy.deepcopy(main['processes'])
    mutate_recovery(evidence,'fresh','execution',change)
    observations=copy.deepcopy(evidence[3]['cleanup']['process_observations'])
    mutate_recovery(evidence,'fresh','cleanup',lambda record:record.__setitem__('process_observations',observations))
    report=assess(evidence)
    assert report['failure']['code']=='RECOVERY_FAILED'
    assert 'reused a guest, boot, session or process identity' in report['failure']['detail']


@pytest.mark.parametrize('value',[None,{'argv':['/usr/bin/umount','/sys/fs/bpf'],'exit_code':1,'timeout':False,'stdout':'','stderr':'busy'},
                                   {'argv':['other'],'exit_code':0,'timeout':False,'stdout':'','stderr':''}])
def test_cleanup_requires_the_observed_guest_unmount(evidence,value):
    root,_,attempt,records=evidence
    records['cleanup']['guest_unmount']=value
    write_record(root,attempt,'cleanup',records['cleanup'])
    assert assess(evidence)['failure']['code']=='CLEANUP_INCOMPLETE'


def test_fresh_cleanup_cannot_substitute_a_failed_guest_unmount(evidence):
    def change(record):record['guest_unmount']['exit_code']=1
    mutate_recovery(evidence,'fresh','cleanup',change)
    assert assess(evidence)['failure']['code']=='RECOVERY_FAILED'
