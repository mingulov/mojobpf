# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Read-only controller admission contracts; never start a runner."""

import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess

import pytest
from jsonschema import Draft202012Validator

from mojobpf import execution
from mojobpf.validation import digest_of


BOOT = "12345678-1234-4567-9234-123456789abc"
HASH = "a" * 64


@pytest.fixture
def controller():
    try:
        return importlib.import_module("mojobpf.target_controller")
    except ModuleNotFoundError as exc:
        if exc.name != "mojobpf.target_controller":
            raise
        pytest.fail("controller approval and lease enforcement is absent", pytrace=False)


@pytest.fixture(autouse=True)
def no_spawn(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("input validation executed or signaled a process")
    for name in ("Popen", "run", "call", "check_output", "check_call"):
        monkeypatch.setattr(subprocess, name, forbidden)
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden)
    monkeypatch.setattr(execution, "admit_execution", forbidden)
    monkeypatch.setattr(execution, "run_admitted", forbidden)


def chain_fixture(tmp_path):
    image = tmp_path / "runner.bin"
    image.write_bytes(b"\x7fELF historical admission fixture\n")
    image.chmod(0o755)
    identity = execution.identify_file(str(image))
    # This historical record is assembled without admission or a version probe.
    summary = {
        "contract": "execution-contract-v1", "name": "runner", "form": "binary",
        "trust_root": "fixture-external-approval", "entry": vars(identity),
        "hops": [], "image": vars(identity), "interpreter": None, "modules": [],
        "version": "historical observation 7.4", "argv_prefix": [str(image)],
        "env_unset": list(execution.SPAWN_ENV_UNSET),
        "env_set": [list(pair) for pair in execution.PYTHON_ENV_SET],
    }
    summary["digest"] = digest_of(summary)
    return summary


def write_document(path, data):
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return {"path": str(path), "file_sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_sha256": digest_of(data)}


def launch_fixture(tmp_path, controller, monkeypatch):
    monkeypatch.setattr(controller, "_host_boot_id", lambda: BOOT)
    monkeypatch.setattr(controller, "_wall_time", lambda: 1893456000.0)  # 2030-01-01
    summary = chain_fixture(tmp_path)
    paths = {name: str(tmp_path / name) for name in ("output_root", "tmp_root", "farm")}
    for path in paths.values():
        Path(path).mkdir()
    paths.update(controller_output=str(Path(paths["output_root"]) / "controller"),
                 lease_journal=str(Path(paths["output_root"]) / "controller" / "lease.json"),
                 controller_pycache=str(Path(paths["tmp_root"]) / "controller-cache"),
                 final_path=paths["farm"] + ":/usr/bin:/usr/sbin:/bin:/sbin")
    limits = {"vcpus": 1, "ram_mib": 768, "nice_increment": 10, "attempt_seconds": 900,
              "startup_seconds": 300, "marker_seconds": 300,
              "guardian": {"cleanup_seconds": 30.0, "poll_seconds": 0.05,
                           "max_live_processes": 128, "max_retained_processes": 4096,
                           "max_tasks_per_process": 128, "max_proc_reads_per_tick": 4096}}
    inputs = {}
    records = {
        "parent_proposal": {"contract": "provisional-disposable-launch-v1", "revision": 2,
                            "status": "NON_ADMISSIBLE_CONTROLLER_IDENTITY_SAFE_IMPLEMENTATION_OPEN"},
        "admission": {"contract": "controller-execution-input-v1", "runner": summary,
                      "launcher": summary, "qemu": summary},
        "capture_contract": {"contract": "captured-bootstrap-attempts-v2"},
        "recovery_plan": {"contract": "owned-disposable-recovery-v2"},
        "controller_distribution": {"contract": "controller-distribution-v1", "files": []},
        "original_closure": {"contract": "runtime-closure-v1", "files": []},
        "supplemental_closure": {"contract": "runtime-closure-v1", "files": []},
        "rootfs_manifest": {"contract": "rootfs-manifest-v1", "files": []},
        "rootfs_provenance": {"contract": "rootfs-provenance-v1"},
        "payload": {"contract": "owned-bootstrap-payload-v1", "files": []},
        "kernel_packages": {"contract": "kernel-packages-v1", "files": []},
        "assessor": {"contract": "assessor-input-v1"},
        "assessor_schema": {"type": "object"},
        "input_sidecar": {"contract": "lane-input-v1", "lane_id": "local-tcg"},
    }
    for name, record in records.items():
        inputs[name] = write_document(tmp_path / (name + ".json"), record)
    invocations = []
    for phase in ("main", "interrupted", "fresh"):
        attempt_id = "fixture-run." + phase
        temporary = str(Path(paths["tmp_root"]) / attempt_id)
        invocations.append({"phase": phase, "attempt_id": attempt_id,
                            "argv": [summary["argv_prefix"][0], "--phase", phase],
                            "cwd": str(tmp_path), "env_overrides": {
                                "PATH": paths["final_path"], "TMPDIR": temporary,
                                "PYTHONPYCACHEPREFIX": temporary + "/pycache"},
                            "start_new_session": True, "timeout_seconds": 900,
                            "output_path": str(Path(paths["output_root"]) / attempt_id)})
    expected = {"kernel_release": "fixture-6.12", "kernel_source_commit": "b" * 40,
                "kernel_build_id": "fixture-build", "bpftool_version": "historical-bpftool",
                "execution_mode": "tcg", "architecture": "x86_64", "byte_order": "little",
                "instruction_profile": "v3"}
    for key in ("kernel_config_sha256", "kernel_image_sha256", "vmlinux_btf_sha256",
                "kernel_packages_sha256", "rootfs_sha256", "payload_sha256", "observer_sha256",
                "compiler_sha256", "control_source_sha256", "control_object_sha256", "packet_sha256",
                "bpftool_sha256", "python_sha256", "libbpf_sha256"):
        expected[key] = HASH
    for role in ("runner", "launcher", "qemu"):
        expected[role + "_admission_sha256"] = summary["digest"]
    expected["recovery_plan_sha256"] = inputs["recovery_plan"]["canonical_sha256"]
    proposal = {"schema_version": 1, "contract": "controller-launch-v1",
                "controller_contract": "controller-result-v1", "owner": "fixture-owner",
                "host_boot_id": BOOT, "execution_mode": "tcg", "vm_concurrency": 1,
                "limits": limits, "paths": paths, "inputs": inputs,
                "lanes": {"local-tcg": {"run_id": "fixture-run", "expected": expected,
                                        "invocations": invocations}},
                "nice_policy": "controller-once-inherited",
                "hard_death_policy": "quarantine", "acceptance_rule": "controller-result-plus-v1"}
    proposal_ref = write_document(tmp_path / "proposal.json", proposal)
    approval = {"schema_version": 1, "contract": "controller-approval-v1", "status": "APPROVED",
                "owner": "fixture-owner", "host_boot_id": BOOT, "proposal": proposal_ref,
                "inputs": inputs, "approved_at": "2029-12-31T23:00:00Z",
                "expires_at": "2030-01-01T02:00:00Z", "trusted_writers": "exclusive-nonconcurrent"}
    approval_ref = write_document(tmp_path / "approval.json", approval)
    lock = tmp_path / "lane.lock"
    lock.touch(mode=0o600)
    st = lock.stat()
    lease = {"schema_version": 1, "contract": "controller-lease-v1", "state": "PROVISIONAL",
             "owner": "fixture-owner", "lease_id": "fixture-lease", "host_boot_id": BOOT,
             "run_id": "fixture-run", "lane_id": "local-tcg", "vm_concurrency": 1,
             "approval_sha256": approval_ref["file_sha256"],
             "proposal_sha256": proposal_ref["file_sha256"],
             "controller_distribution_sha256": inputs["controller_distribution"]["file_sha256"],
             "paths": paths, "limits": limits,
             "lock": {"path": str(lock), "dev": st.st_dev, "ino": st.st_ino,
                      "owner_uid": st.st_uid, "mode": 0o600},
             "issued_at": "2029-12-31T23:00:00Z", "expires_at": "2030-01-01T01:00:00Z",
             "state_policy": "quarantine-unresolved"}
    lease_ref = write_document(tmp_path / "lease.json", lease)
    return proposal, approval, lease, proposal_ref, approval_ref, lease_ref


def pinned(controller, reference):
    return controller.read_approved_document(Path(reference["path"]), reference["file_sha256"])


def validate_fixture(controller, fixture):
    return controller.validate_launch(*(pinned(controller, ref) for ref in fixture[3:]), lane_id="local-tcg")


def test_approval_pin_is_external(tmp_path, controller):
    ref = write_document(tmp_path / "approval.json", {"sha256": HASH, "status": "APPROVED"})
    with pytest.raises(controller.ControllerError) as error:
        controller.read_approved_document(Path(ref["path"]), HASH)
    assert error.value.code == "ADMISSION_REFUSED"


def test_summary_roundtrip_and_spawn_reverification(tmp_path, controller):
    summary = chain_fixture(tmp_path)
    admitted = controller.load_approved_chain(summary)
    assert isinstance(admitted, execution.AdmittedExecution)
    assert execution.summarize(admitted) == summary
    Path(summary["entry"]["path"]).write_bytes(b"replacement")
    with pytest.raises(controller.ControllerError) as error:
        controller.load_approved_chain(summary)
    assert error.value.code == "ADMISSION_REFUSED"


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(unapproved=True), lambda d: d["entry"].update(unknown=1),
    lambda d: d["entry"].update(size=True), lambda d: d.update(digest="b" * 64),
    lambda d: d["modules"].append({"name": "module", "file": {}}),
    lambda d: d["env_set"].append(d["env_set"][0]),
    lambda d: d.update(argv_prefix=[]), lambda d: d.update(contract="future-contract"),
])
def test_summary_rejects_structural_or_digest_drift(tmp_path, controller, mutate):
    summary = chain_fixture(tmp_path)
    mutate(summary)
    with pytest.raises(controller.ControllerError) as error:
        controller.load_approved_chain(summary)
    assert error.value.code == "ADMISSION_REFUSED"


@pytest.mark.parametrize("raw", [b'{"status":1,"status":2}', b'{"nested":{"x":1,"x":2}}',
                                 b'{"value":NaN}', b'{"value":Infinity}', b'[]'])
def test_unknown_fields_and_duplicate_json_keys_refused(tmp_path, controller, raw):
    path = tmp_path / "record.json"
    path.write_bytes(raw)
    with pytest.raises(controller.ControllerError) as error:
        controller.read_approved_document(path, hashlib.sha256(raw).hexdigest())
    assert error.value.code == "ADMISSION_REFUSED"


def test_no_self_pinning_or_probe(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    with pytest.raises(controller.ControllerError):
        controller.validate_launch(*fixture[:3], lane_id="local-tcg")
    validated = validate_fixture(controller, fixture)
    assert validated is not None, "pinned independent approval and lease were not reconstructed"
    assert validated.run_id == "fixture-run"
    assert validated.runner.version == "historical observation 7.4"
    assert validated.proposal_sha256 == fixture[3]["file_sha256"]
    with pytest.raises(AttributeError):
        validated.run_id = "replacement"


def test_lease_has_no_ready_dependency(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    assert validate_fixture(controller, fixture).lease_id == "fixture-lease"
    fixture[2]["ready_sha256"] = HASH
    fixture = (*fixture[:5], write_document(Path(fixture[5]["path"]), fixture[2]))
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "LEASE_REQUIRED"


@pytest.mark.parametrize("field,value", [("proposal_sha256", "b" * 64), ("lane_id", "foreign"),
                                         ("vm_concurrency", 2), ("state", "READY"),
                                         ("expires_at", "2030-01-01T00:30:00Z")])
def test_lease_binding_and_whole_lane_budget(tmp_path, controller, monkeypatch, field, value):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    fixture[2][field] = value
    fixture = (*fixture[:5], write_document(Path(fixture[5]["path"]), fixture[2]))
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "LEASE_REQUIRED"


def test_unknown_proposal_field_is_refused(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    fixture[0]["backend"] = "ambient-program"
    fixture[1]["proposal"] = write_document(Path(fixture[3]["path"]), fixture[0])
    fixture[2]["proposal_sha256"] = fixture[1]["proposal"]["file_sha256"]
    fixture[4].update(write_document(Path(fixture[4]["path"]), fixture[1]))
    fixture[2]["approval_sha256"] = fixture[4]["file_sha256"]
    fixture[5].update(write_document(Path(fixture[5]["path"]), fixture[2]))
    fixture[3].update(fixture[1]["proposal"])
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "ADMISSION_REFUSED"


def test_input_bytes_are_independently_pinned(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    Path(fixture[0]["inputs"]["admission"]["path"]).write_text('{"digest":"self-pinned"}')
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "ADMISSION_REFUSED"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "ancestor-symlink", "oversize"])
def test_pinned_read_refuses_unsafe_file(tmp_path, controller, kind):
    source = tmp_path / "source.json"
    source.write_bytes(b"{}")
    target = tmp_path / "target.json"
    if kind == "symlink":
        target.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, target)
    elif kind == "ancestor-symlink":
        (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
        target = tmp_path / "link" / source.name
    else:
        source.write_bytes(b" " * (4 * 1024 * 1024 + 1))
        target = source
    with pytest.raises(controller.ControllerError):
        controller.read_approved_document(target, hashlib.sha256(source.read_bytes()).hexdigest())


def test_validate_only_has_no_output_lock_or_spawn(tmp_path, controller, monkeypatch, capsys):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = controller.main(["--proposal", fixture[3]["path"], "--approval", fixture[4]["path"],
                              "--approval-sha256", fixture[4]["file_sha256"],
                              "--lease", fixture[5]["path"], "--lease-sha256", fixture[5]["file_sha256"],
                              "--lane", "local-tcg", "--validate-only"])
    assert result == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "NOT_RUN"
    assert before == {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert not Path(fixture[0]["paths"]["controller_output"]).exists()


def sidecar_fixture():
    return {"schema_version": 1, "contract": "controller-result-v1", "run_id": None, "lane_id": None,
            "bindings": {name: None for name in ("proposal", "approval", "lease", "capture_contract",
                                                 "recovery_plan", "controller_distribution", "original_closure",
                                                 "supplemental_closure")},
            "terminal": True, "outcome": "INFRA_ERROR", "failure": {
                "code": "ADMISSION_REFUSED", "detail": "external pin mismatch", "errno": None,
                "predecessor": None}, "attempts": [], "lease_disposition": "QUARANTINED",
            "projection": None, "journal": None, "artifacts": []}


def schema_validator():
    path = Path(__file__).resolve().parents[2] / "ci" / "targets" / "controller-result.schema.json"
    assert path.is_file(), "strict incomplete-result contract is absent"
    schema = json.loads(path.read_bytes())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_result_schema_accepts_failure_without_invented_guest():
    schema_validator().validate(sidecar_fixture())


@pytest.mark.parametrize("mutate", [lambda d: d.update(outcome="READY"),
                                      lambda d: d.update(success=True),
                                      lambda d: d["failure"].update(hidden=True),
                                      lambda d: d.update(projection={"path": "../foreign", "sha256": HASH}),
                                      lambda d: d.update(lease_disposition="RELEASABLE")])
def test_result_schema_rejects_forged_success_or_reference(mutate):
    sidecar = sidecar_fixture()
    mutate(sidecar)
    assert list(schema_validator().iter_errors(sidecar))


@pytest.mark.parametrize("field,value", [("form", []), ("form", {}), ("env_set", [["LD_PRELOAD", "/foreign.so"]])])
def test_malformed_chain_fields_remain_typed(tmp_path, controller, field, value):
    summary = chain_fixture(tmp_path)
    summary[field] = value
    summary["digest"] = digest_of({key: val for key, val in summary.items() if key != "digest"})
    with pytest.raises(controller.ControllerError):
        controller.load_approved_chain(summary)


def test_summary_cannot_execute_an_unidentified_argv_prefix(tmp_path, controller):
    summary = chain_fixture(tmp_path)
    summary["argv_prefix"] = [str(tmp_path / "unidentified")]
    summary["digest"] = digest_of({key: value for key, value in summary.items() if key != "digest"})
    with pytest.raises(controller.ControllerError):
        controller.load_approved_chain(summary)


def test_summary_cannot_reintroduce_loader_injection(tmp_path, controller):
    summary = chain_fixture(tmp_path)
    summary["env_set"].append(["LD_PRELOAD", "/foreign.so"])
    summary["digest"] = digest_of({key: value for key, value in summary.items() if key != "digest"})
    with pytest.raises(controller.ControllerError):
        controller.load_approved_chain(summary)


def repin_proposal(fixture):
    p, a, l, pr, ar, lr = fixture
    pr.update(write_document(Path(pr["path"]), p))
    a["proposal"] = dict(pr)
    ar.update(write_document(Path(ar["path"]), a))
    l["proposal_sha256"], l["approval_sha256"] = pr["file_sha256"], ar["file_sha256"]
    lr.update(write_document(Path(lr["path"]), l))
    return fixture


def test_malformed_nested_reference_is_typed_refusal(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    fixture[0]["inputs"]["controller_distribution"] = []
    repin_proposal(fixture)
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "ADMISSION_REFUSED"


def test_recovery_expected_identity_matches_consumed_canonical_input(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    fixture[0]["lanes"]["local-tcg"]["expected"]["recovery_plan_sha256"] = "b" * 64
    repin_proposal(fixture)
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "ADMISSION_REFUSED"


def test_attempt_output_roots_cannot_contain_another_attempt(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    invocations = fixture[0]["lanes"]["local-tcg"]["invocations"]
    invocations[1]["output_path"] = invocations[0]["output_path"] + "/interrupted"
    repin_proposal(fixture)
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "ADMISSION_REFUSED"


@pytest.mark.parametrize("name", ["original_closure", "supplemental_closure", "recovery_plan"])
def test_frozen_input_canonical_identity_remains_distinct_from_file_pin(tmp_path, controller, monkeypatch, name):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    if name == "recovery_plan":
        record = {"contract": "owned-disposable-recovery-v2", "status": "DESIGN_ONLY"}
        expected_digest = digest_of(record)
    else:
        record = {"status": "OBSERVED_PENDING_CONTROLLER_ADMISSION", "files": []}
        expected_digest = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    record["sha256"] = expected_digest
    reference = fixture[0]["inputs"][name]
    reference.update(write_document(Path(reference["path"]), record))
    reference["canonical_sha256"] = expected_digest
    if name == "recovery_plan":
        fixture[0]["lanes"]["local-tcg"]["expected"]["recovery_plan_sha256"] = expected_digest
    repin_proposal(fixture)
    validated = validate_fixture(controller, fixture)
    _, consumed, canonical = next(item for item in validated.inputs if item[0] == name)
    assert canonical == expected_digest
    assert consumed.file_sha256 == reference["file_sha256"] != expected_digest


def unstarted_attempt(phase="fresh"):
    return {"phase": phase, "attempt_id": "fixture-run." + phase, "started": False, "terminal": True,
            "invocation": None, "timings": {"wall_start": None, "wall_end": None,
                                            "monotonic_start": None, "monotonic_end": None},
            "runner_exit": None, "reason": "predecessor failed", "outcome": "NOT_RUN", "failure": {
                "code": "CLEANUP_INCOMPLETE", "detail": "predecessor did not drain", "errno": None,
                "predecessor": "fixture-run.interrupted"}, "guest": None, "target_fingerprint": None,
            "processes": [], "cleanup": None, "streams": {"stdout": None, "stderr": None,
                                                           "limit_bytes": 67108864, "overflow": False},
            "guest_files": [], "projection": None}


@pytest.mark.parametrize("field,value", [("failure", None), ("outcome", "INFRA_ERROR"),
                                         ("started", True)])
def test_not_run_retains_predecessor_and_never_claims_started(field, value):
    attempt = unstarted_attempt()
    attempt[field] = value
    validator = schema_validator()
    nested = {"$schema": validator.schema["$schema"], "$defs": validator.schema["$defs"],
              "$ref": "#/$defs/attempt"}
    assert list(Draft202012Validator(nested).iter_errors(attempt))


def test_result_schema_records_a_causally_unstarted_phase():
    validator = schema_validator()
    nested = {"$schema": validator.schema["$schema"], "$defs": validator.schema["$defs"],
              "$ref": "#/$defs/attempt"}
    Draft202012Validator(nested).validate(unstarted_attempt())
