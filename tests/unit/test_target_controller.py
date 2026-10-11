# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Read-only controller admission contracts; never start a runner."""

import copy
from dataclasses import replace
import errno
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import zipfile

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


def started_attempt(phase, *, observed=False, outcome="INFRA_ERROR"):
    reference = {"path": "raw.json", "sha256": HASH}
    attempt = unstarted_attempt(phase)
    attempt.update(started=True, outcome=outcome, runner_exit=0 if outcome == "PASS" else 1,
                   reason="controlled fixture terminal outcome", failure=None if outcome == "PASS" else {
                       "code": "STARTUP_TIMEOUT", "detail": "guest did not boot", "errno": None,
                       "predecessor": None},
                   invocation={"argv": ["/runner"], "cwd": "/tmp",
                               "environment_policy": "admitted-sanitized-with-approved-overrides",
                               "environment": {}, "environment_sha256": HASH},
                   timings={"wall_start": 1, "wall_end": 2, "monotonic_start": 1, "monotonic_end": 2},
                   cleanup={"status": "CLEAN", "subreaper_readback": True, "scans": 1, "adoptions": 0,
                            "final_echild": True, "unresolved_live": 0, "all_pidfds_exited": True,
                            "mountinfo_before": reference, "mountinfo_after": reference})
    if observed:
        process = {"sequence": 1, "time": 1,
                   "identity": {"pid": 101, "start_ticks": 1001, "host_boot_id": BOOT},
                   "role": "runner", "ownership_basis": "spawn-child", "parent": None,
                   "raw_stat": [reference], "raw_fdinfo": [reference], "signals": [],
                   "pidfd_exited": True, "wait_status": 0, "pidfd_diagnostic": None}
        attempt.update(guest={"attempt_id": attempt["attempt_id"], "guest_id": "fixture-guest",
                              "boot_id": BOOT, "session_id": 101}, target_fingerprint=HASH,
                       processes=[process, dict(process, sequence=2, role="qemu")], projection=reference)
    return attempt


def completed_sidecar(*, successful=False):
    sidecar = sidecar_fixture()
    sidecar.update(run_id="fixture-run", lane_id="local-tcg", journal={"path": "journal.json", "sha256": HASH},
                   bindings={name: {"path": name + ".json", "file_sha256": HASH, "canonical_sha256": None}
                             for name in sidecar["bindings"]}, lease_disposition="RELEASABLE")
    if successful:
        interrupted = started_attempt("interrupted", observed=True)
        interrupted.update(runner_exit=-9, failure={"code": "CANCELLED", "detail": "intentional interruption",
                                                  "errno": None, "predecessor": None})
        sidecar.update(outcome="PASS", failure=None, projection={"path": "projected.json", "sha256": HASH},
                       attempts=[started_attempt("main", observed=True, outcome="PASS"), interrupted,
                                 started_attempt("fresh", observed=True, outcome="PASS")])
    else:
        main = started_attempt("main")
        interrupted, fresh = unstarted_attempt("interrupted"), unstarted_attempt("fresh")
        for attempt, predecessor in ((interrupted, main), (fresh, interrupted)):
            attempt["failure"] = dict(main["failure"], predecessor=predecessor["attempt_id"])
        sidecar.update(failure=main["failure"], attempts=[main, interrupted, fresh])
    return sidecar


def test_pass_sidecar_rejects_unobserved_interrupted_attempt():
    sidecar = completed_sidecar(successful=True)
    sidecar["attempts"][1].update(guest=None, target_fingerprint=None, processes=[], projection=None)
    assert list(schema_validator().iter_errors(sidecar))


@pytest.mark.parametrize("field,value", [("guest", None), ("target_fingerprint", None),
                                         ("processes", []), ("projection", None), ("overflow", True)])
def test_pass_sidecar_requires_each_interrupted_evidence_field(field, value):
    sidecar = completed_sidecar(successful=True)
    interrupted = sidecar["attempts"][1]
    if field == "overflow":
        interrupted["streams"][field] = value
    else:
        interrupted[field] = value
    assert list(schema_validator().iter_errors(sidecar))


def test_observed_intentional_interruption_can_complete_lane():
    schema_validator().validate(completed_sidecar(successful=True))


def test_ordinary_preboot_interrupted_failure_retains_nullable_evidence():
    sidecar = completed_sidecar(successful=True)
    failed = started_attempt("interrupted")
    fresh = unstarted_attempt("fresh")
    fresh["failure"] = dict(failed["failure"], predecessor=failed["attempt_id"])
    sidecar.update(outcome="INFRA_ERROR", failure=failed["failure"], projection=None,
                   lease_disposition="QUARANTINED", attempts=[sidecar["attempts"][0], failed, fresh])
    schema_validator().validate(sidecar)


def test_pinned_deep_json_is_a_typed_refusal(tmp_path, controller):
    raw = b'{"x":' * 600 + b"0" + b"}" * 600
    assert isinstance(json.loads(raw), dict)
    path = tmp_path / "nested.json"
    path.write_bytes(raw)
    with pytest.raises(controller.ControllerError) as error:
        controller.read_approved_document(path, hashlib.sha256(raw).hexdigest())
    assert error.value.code == "ADMISSION_REFUSED"


@pytest.mark.parametrize("operation", ["freeze", "thaw"])
def test_deep_frozen_conversion_is_a_typed_refusal(controller, operation):
    value = 0
    for _ in range(600):
        value = {"x": value} if operation == "freeze" else controller._FrozenObject((("x", value),))
    with pytest.raises(controller.ControllerError) as error:
        getattr(controller, "_" + operation)(value)
    assert error.value.code == "ADMISSION_REFUSED"


def test_bounded_json_roundtrip_preserves_nested_values(tmp_path, controller):
    value = 0
    for level in range(64):
        value = {"x": value} if level % 2 else [value]
    reference = write_document(tmp_path / "nested.json", {"nested": value})
    assert controller._document(pinned(controller, reference)) == {"nested": value}


@pytest.mark.parametrize("field", ["poll_seconds", "cleanup_seconds"])
def test_pinned_large_integer_time_bound_is_a_typed_refusal(tmp_path, controller, monkeypatch, field):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    fixture[0]["limits"]["guardian"][field] = 10 ** 400
    repin_proposal(fixture)
    with pytest.raises(controller.ControllerError) as error:
        validate_fixture(controller, fixture)
    assert error.value.code == "ADMISSION_REFUSED"


@pytest.mark.parametrize("outcome,code", [("INFRA_ERROR", "STARTUP_TIMEOUT"), ("FAIL", "EVIDENCE_INVALID"),
                                         ("INFRA_ERROR", "MARKER_TIMEOUT"), ("INFRA_ERROR", "ATTEMPT_TIMEOUT"),
                                         ("INFRA_ERROR", "CANCELLED")])
def test_clean_failed_lane_can_release_with_causal_not_run_phases(outcome, code):
    sidecar = completed_sidecar()
    sidecar["outcome"] = sidecar["attempts"][0]["outcome"] = outcome
    sidecar["failure"]["code"] = code
    for attempt in sidecar["attempts"]:
        attempt["failure"]["code"] = code
    schema_validator().validate(sidecar)
    assert all(attempt["cleanup"] is None for attempt in sidecar["attempts"][1:])
    assert all(attempt["outcome"] == "NOT_RUN" for attempt in sidecar["attempts"][1:])


@pytest.mark.parametrize("code", ["ADMISSION_REFUSED", "LEASE_REQUIRED", "OWNERSHIP_UNKNOWN",
                                 "IO_FAILED", "CLEANUP_INCOMPLETE"])
def test_release_refuses_uncertain_or_unadmitted_failure_despite_clean_claim(code):
    sidecar = completed_sidecar()
    sidecar["attempts"] = sidecar["attempts"][:1]
    sidecar["failure"]["code"] = code
    assert list(schema_validator().iter_errors(sidecar))


def test_not_run_result_cannot_release_from_a_claimed_started_epoch():
    sidecar = completed_sidecar()
    sidecar.update(outcome="NOT_RUN", attempts=sidecar["attempts"][:1])
    assert list(schema_validator().iter_errors(sidecar))


def test_release_refuses_uncertainty_in_a_later_causal_failure():
    sidecar = completed_sidecar()
    sidecar["attempts"][1]["failure"]["code"] = "OWNERSHIP_UNKNOWN"
    assert list(schema_validator().iter_errors(sidecar))


@pytest.mark.parametrize("defect", ["no-started-epoch", "nonterminal", "missing-cleanup", "unresolved"])
def test_release_requires_actual_terminal_clean_started_epoch(defect):
    sidecar = completed_sidecar()
    main = sidecar["attempts"][0]
    if defect == "no-started-epoch":
        sidecar["attempts"][0] = unstarted_attempt("main")
    elif defect == "nonterminal":
        main["terminal"] = False
    elif defect == "missing-cleanup":
        main["cleanup"] = None
    else:
        main["cleanup"].update(status="INCOMPLETE", final_echild=False, unresolved_live=1, all_pidfds_exited=False)
    assert list(schema_validator().iter_errors(sidecar))


def test_quarantined_ownership_failure_preserves_unstarted_phases():
    sidecar = completed_sidecar()
    sidecar["lease_disposition"] = "QUARANTINED"
    for failure in [sidecar["failure"], *(attempt["failure"] for attempt in sidecar["attempts"])]:
        failure["code"] = "OWNERSHIP_UNKNOWN"
    schema_validator().validate(sidecar)


def launch_v2_fixture(tmp_path, controller, monkeypatch):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    fixture[0].update(schema_version=2, contract="controller-launch-v2",
                      controller_contract="controller-result-v2", acceptance_rule="controller-result-v2-plus-v1")
    fixture[0]["lanes"]["local-tcg"]["expected"]["byte_order"] = "le"
    payload = {"contract": "owned-bootstrap-payload-v1", "files": [], "sha256": digest_of([])}
    reference = fixture[0]["inputs"]["payload"]
    reference.update(write_document(Path(reference["path"]), payload))
    reference["canonical_sha256"] = payload["sha256"]
    fixture[1]["inputs"] = copy.deepcopy(fixture[0]["inputs"])
    return repin_proposal(fixture)


def test_launch_v2_accepts_exact_versioned_authority(tmp_path, controller, monkeypatch):
    fixture = launch_v2_fixture(tmp_path, controller, monkeypatch)
    validated = validate_fixture(controller, fixture)
    assert validated.schema_version == 2
    assert dict(validated.expected)["byte_order"] == "le"
    assert validated.proposal_sha256 == fixture[3]["file_sha256"]


@pytest.mark.parametrize("field,value", [("schema_version", 1), ("schema_version", True),
                                         ("contract", "controller-launch-v1"),
                                         ("controller_contract", "controller-result-v1"),
                                         ("acceptance_rule", "controller-result-plus-v1"),
                                         ("byte_order", "little")])
def test_launch_v2_refuses_mixed_versions_without_rewriting(tmp_path, controller, monkeypatch, field, value):
    fixture = launch_v2_fixture(tmp_path, controller, monkeypatch)
    if field == "byte_order":
        fixture[0]["lanes"]["local-tcg"]["expected"][field] = value
    else:
        fixture[0][field] = value
    repin_proposal(fixture)
    with pytest.raises(controller.ControllerError):
        validate_fixture(controller, fixture)


@pytest.mark.parametrize("version", [1, 2])
def test_versioned_validate_only_does_not_lock_write_or_spawn(tmp_path, controller, monkeypatch, capsys, version):
    fixture = (launch_fixture if version == 1 else launch_v2_fixture)(tmp_path, controller, monkeypatch)
    before = {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    code = controller.main(["--proposal", fixture[3]["path"], "--approval", fixture[4]["path"],
                            "--approval-sha256", fixture[4]["file_sha256"], "--lease", fixture[5]["path"],
                            "--lease-sha256", fixture[5]["file_sha256"], "--lane", "local-tcg", "--validate-only"])
    assert code == 0, capsys.readouterr().err
    assert json.loads(capsys.readouterr().out)["outcome"] == "NOT_RUN"
    assert before == {str(p.relative_to(tmp_path)): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


@pytest.mark.parametrize("defect", ["old-approval", "old-lease"])
def test_old_pins_do_not_authorize_new_launch(tmp_path, controller, monkeypatch, defect):
    fixture = launch_fixture(tmp_path, controller, monkeypatch)
    old_proposal = pinned(controller, fixture[3])
    old_approval, old_lease = pinned(controller, fixture[4]), pinned(controller, fixture[5])
    fixture[0].update(schema_version=2, contract="controller-launch-v2",
                      controller_contract="controller-result-v2", acceptance_rule="controller-result-v2-plus-v1")
    fixture[0]["lanes"]["local-tcg"]["expected"]["byte_order"] = "le"
    repin_proposal(fixture)
    documents = (pinned(controller, fixture[3]), old_approval, old_lease) if defect == "old-approval" else (
                 pinned(controller, fixture[3]), pinned(controller, fixture[4]), old_lease)
    with pytest.raises(controller.ControllerError):
        controller.validate_launch(*documents, lane_id="local-tcg")
    assert old_proposal.consumed.raw != documents[0].consumed.raw


def v2_schema_validator():
    path = Path(__file__).resolve().parents[2] / "ci/targets/controller-result-v2.schema.json"
    assert path.is_file(), "versioned durable completion result schema is absent"
    schema = json.loads(path.read_bytes())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def v2_sidecar_fixture():
    record = sidecar_fixture()
    record.update(schema_version=2, contract="controller-result-v2")
    return record


def result_check(controller, record):
    check = getattr(controller, "validate_result", None)
    assert callable(check), "standalone strict versioned result validation is absent"
    return check(record)


def test_versioned_result_checker_accepts_truthful_refusal(controller):
    result_check(controller, sidecar_fixture())
    result_check(controller, v2_sidecar_fixture())
    v2_schema_validator().validate(v2_sidecar_fixture())


@pytest.mark.parametrize("field,value", [("schema_version", 1), ("schema_version", True),
                                         ("contract", "controller-result-v1"), ("unknown", True)])
def test_result_v2_refuses_mixed_or_unknown_fields(controller, field, value):
    record = v2_sidecar_fixture()
    record[field] = value
    with pytest.raises(controller.ControllerError):
        result_check(controller, record)
    assert list(v2_schema_validator().iter_errors(record))


@pytest.mark.parametrize("defect", ["journal-null", "receipt-null", "journal-missing", "receipt-missing", "extra"])
def test_clean_v2_requires_both_completion_refs(controller, defect):
    record = completed_sidecar()
    record.update(schema_version=2, contract="controller-result-v2")
    cleanup = record["attempts"][0]["cleanup"]
    cleanup.update(completion_journal={"path": "controller/main/prefix.jsonl", "sha256": HASH},
                   completion_receipt={"path": "controller/main/receipt.json", "sha256": HASH})
    key = "completion_journal" if defect.startswith("journal") else "completion_receipt"
    if defect.endswith("null"):
        cleanup[key] = None
    elif defect.endswith("missing"):
        del cleanup[key]
    else:
        cleanup["trusted"] = True
    with pytest.raises(controller.ControllerError):
        result_check(controller, record)
    assert list(v2_schema_validator().iter_errors(record))


def test_v1_completion_additions_are_refused_without_silent_upgrade(controller):
    record = completed_sidecar()
    record["attempts"][0]["cleanup"].update(completion_journal=None, completion_receipt=None)
    with pytest.raises(controller.ControllerError):
        result_check(controller, record)
    assert list(schema_validator().iter_errors(record))


def test_original_result_schema_remains_byte_identical():
    path = Path(__file__).resolve().parents[2] / "ci/targets/controller-result.schema.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "eab30832e3484fd48593b7a88238bf61298b80ecd460a1afdfdd349129340552"


def guardian_kernel_fixture():
    """Reuse the frozen public unit-test kernel model, without real processes."""
    path = Path(__file__).with_name("test_process_guardian.py")
    spec = importlib.util.spec_from_file_location("controller_guardian_model", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.LifecycleKernel()


def persistence_fixture(tmp_path, controller, monkeypatch, *, fault=None, late=None, short_write=False):
    fixture = launch_v2_fixture(tmp_path, controller, monkeypatch)
    validated = validate_fixture(controller, fixture)
    kernel = guardian_kernel_fixture()
    backend_class = getattr(controller, "_PersistenceBackend", None)
    assert callable(backend_class), "durable owned-file operations are absent"
    class IO(backend_class):
        def __init__(self):
            self.calls, self.fd_operations = [], []
            self.failed = False
            self.unknown_fd = None
            self.armed = False
        def monotonic(self): return kernel.clock
        def wall_time(self): return 1893456000.0 + kernel.clock
        def checkpoint(self, operation, path):
            self.calls.append((operation, path))
            if late == (operation, path): kernel.clock = 30.0
            if self.armed and fault == (operation, path) and not self.failed:
                self.failed = True
                raise OSError(errno.EIO, "injected persistence acknowledgement failure")
        def write(self, fd, raw):
            self.fd_operations.append(("write", fd))
            if short_write: raw = raw[:7]
            return super().write(fd, raw)
        def fsync(self, fd):
            self.fd_operations.append(("fsync", fd))
            return super().fsync(fd)
        def close(self, fd):
            self.fd_operations.append(("close", fd))
            return super().close(fd)
    backend = IO()
    store_class, barrier_class = getattr(controller, "_OwnedStore", None), getattr(controller, "_CompletionBarrier", None)
    assert callable(store_class) and callable(barrier_class), "caller completion barrier is absent"
    budget = controller._Budget(validated, backend)
    store = store_class(validated.paths.controller_output, output_root=validated.paths.output_root,
                        budget=budget, _backend=backend)
    barrier = barrier_class(validated, store, budget=budget,
                            controller_identity={"pid": 100, "start_ticks": 99, "host_boot_id": BOOT})
    guardian_module = importlib.import_module("mojobpf.process_guardian")
    guardian = guardian_module.ProcessGuardian(limits=validated.limits.guardian, journal=barrier.guardian_record,
                                              _backend=kernel)
    return fixture, validated, kernel, backend, store, barrier, guardian


def finish_barrier_epoch(validated, kernel, barrier, guardian, phase="main", *, pid=101, interrupt=False):
    from types import SimpleNamespace
    invocation = next(item for item in validated.invocations if item.phase == phase)
    barrier.open_attempt(invocation)
    guardian.prepare()
    kernel.add(pid=pid, ticks=pid * 10, session=pid)
    guardian.retain_runner(SimpleNamespace(pid=pid, returncode=None))
    if not interrupt: kernel.exit(kernel.current[pid])
    barrier._store._io.armed = True
    return guardian.finish(reason="intentional-interruption" if interrupt else "normal", interrupt=interrupt)


def test_durable_completion_requires_pair_and_bound_controller_commit(tmp_path, controller, monkeypatch):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch)
    proof = finish_barrier_epoch(validated, kernel, barrier, guardian)
    try:
        accepted = barrier.commit(proof)
        assert accepted["cleanup"]["status"] == "CLEAN"
        assert accepted["runner_exit"] == 0
        for name in ("completion_journal", "completion_receipt"):
            reference = accepted["cleanup"][name]
            path = Path(validated.paths.output_root) / reference["path"]
            assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == reference["sha256"]
        assert barrier.may_prepare is True
        transitions = list(map(json.loads, (Path(validated.paths.controller_output) / "transitions.active.jsonl").read_bytes().splitlines()))
        assert [item["event"] for item in transitions] == ["attempt-open", "completion-committed"]
        assert transitions[-1]["data"]["epoch_last_sequence"] == proof["completion_receipt"]["epoch_last_sequence"]
        assert all(item["proposal_sha256"] == validated.proposal_sha256 for item in transitions)
    finally: store.close()


def test_three_epochs_preserve_global_fixed_byte_prefixes(tmp_path, controller, monkeypatch):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch)
    prefixes = []
    try:
        for index, phase in enumerate(("main", "interrupted", "fresh")):
            proof = finish_barrier_epoch(validated, kernel, barrier, guardian, phase, pid=101+index, interrupt=phase=="interrupted")
            accepted = barrier.commit(proof)
            prefix = (Path(validated.paths.output_root) / accepted["cleanup"]["completion_journal"]["path"]).read_bytes()
            assert prefix.startswith(prefixes[-1] if prefixes else b"")
            records = list(map(json.loads, prefix.splitlines()))
            assert records[0]["sequence"] == 1
            assert records[-1]["sequence"] == proof["completion_receipt"]["epoch_last_sequence"]
            assert sum(r["event"] == "prepared" for r in records) == index+1
            prefixes.append(prefix)
        assert barrier.verify_committed() is None
    finally: store.close()


@pytest.mark.parametrize("operation,path", [
    ("after-write", "guardian.active.jsonl"), ("after-fsync", "guardian.active.jsonl"),
    ("after-write", "attempts/fixture-run.main/guardian-prefix.jsonl"),
    ("after-fsync", "attempts/fixture-run.main/guardian-prefix.jsonl"),
    ("after-close", "attempts/fixture-run.main/guardian-prefix.jsonl"),
    ("after-directory-fsync", "attempts/fixture-run.main/guardian-prefix.jsonl"),
    ("after-readback", "attempts/fixture-run.main/guardian-prefix.jsonl"),
    ("after-write", "attempts/fixture-run.main/guardian-receipt.json"),
    ("after-fsync", "attempts/fixture-run.main/guardian-receipt.json"),
    ("after-close", "attempts/fixture-run.main/guardian-receipt.json"),
    ("after-directory-fsync", "attempts/fixture-run.main/guardian-receipt.json"),
    ("after-readback", "attempts/fixture-run.main/guardian-receipt.json"),
])
def test_persistence_failure_never_enables_next_prepare(tmp_path, controller, monkeypatch, operation, path):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch,
                                                                          fault=(operation,path))
    try:
        proof = finish_barrier_epoch(validated, kernel, barrier, guardian)
        with pytest.raises(controller.ControllerError): barrier.commit(proof)
        assert barrier.may_prepare is False
        with pytest.raises(controller.ControllerError): barrier.open_attempt(validated.invocations[1])
        assert (Path(validated.paths.controller_output) / "guardian.active.jsonl").exists()
        assert len([item for item in barrier.guardian_records if item["event"] == "prepared"]) <= 1
    finally: store.close()


@pytest.mark.parametrize("operation,path", [
    ("after-fsync", "attempts/fixture-run.main/guardian-prefix.jsonl"),
    ("after-close", "attempts/fixture-run.main/guardian-receipt.json"),
    ("after-readback", "attempts/fixture-run.main/guardian-receipt.json"),
])
def test_persistence_deadline_equality_is_late(tmp_path, controller, monkeypatch, operation, path):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch,
                                                                          late=(operation,path))
    try:
        proof = finish_barrier_epoch(validated, kernel, barrier, guardian)
        assert proof["completion_receipt"]["deadline"] == 30.0
        with pytest.raises(controller.ControllerError): barrier.commit(proof)
        assert barrier.may_prepare is False
    finally: store.close()


def test_successful_short_writes_are_written_all(tmp_path, controller, monkeypatch):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch, short_write=True)
    try:
        proof = finish_barrier_epoch(validated, kernel, barrier, guardian)
        assert barrier.commit(proof)["cleanup"]["status"] == "CLEAN"
        assert barrier.verify_committed() is None
    finally: store.close()


def test_mutable_finish_value_cannot_fabricate_physical_cleanup(tmp_path, controller, monkeypatch):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch)
    try:
        proof = finish_barrier_epoch(validated, kernel, barrier, guardian)
        proof["processes"][0]["identity"]["pid"] = 999
        with pytest.raises(controller.ControllerError): barrier.commit(proof)
        assert barrier.may_prepare is False
    finally: store.close()


def test_mutable_accepted_copy_does_not_change_internal_seal(tmp_path, controller, monkeypatch):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch)
    try:
        accepted = barrier.commit(finish_barrier_epoch(validated, kernel, barrier, guardian))
        accepted["cleanup"]["completion_journal"]["sha256"] = "b"*64
        accepted["processes"].clear()
        assert barrier.verify_committed() is None and barrier.may_prepare
        assert barrier.accepted[0]["processes"]
        assert barrier.accepted[0]["cleanup"]["completion_journal"]["sha256"] != "b"*64
    finally: store.close()


@pytest.mark.parametrize("defect", ["whitespace-rewrite", "hardlink", "symlink", "inode-replacement"])
def test_previous_committed_artifact_drift_refuses_later_epoch(tmp_path, controller, monkeypatch, defect):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch)
    try:
        accepted = barrier.commit(finish_barrier_epoch(validated, kernel, barrier, guardian))
        path = Path(validated.paths.output_root) / accepted["cleanup"]["completion_receipt"]["path"]
        raw = path.read_bytes()
        if defect == "whitespace-rewrite": path.write_bytes(raw+b" ")
        elif defect == "hardlink": os.link(path,path.with_name("alias.json"))
        else:
            path.unlink()
            if defect == "symlink":
                replacement=path.with_name("replacement.json");replacement.write_bytes(raw);path.symlink_to(replacement.name)
            else:path.write_bytes(raw)
        with pytest.raises(controller.ControllerError): barrier.open_attempt(validated.invocations[1])
        assert not barrier.may_prepare
    finally: store.close()


def test_zero_runner_epoch_has_real_durable_cleanup(tmp_path, controller, monkeypatch):
    _, validated, _, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch)
    try:
        barrier.open_attempt(validated.invocations[0]);guardian.prepare()
        accepted = barrier.commit(guardian.finish(reason="spawn-failed",interrupt=True))
        assert accepted["cleanup"]["status"] == "CLEAN" and accepted["processes"] == []
        assert accepted["runner_exit"] is None
    finally: store.close()


@pytest.mark.parametrize("defect", ["receipt-absent", "receipt-range", "controller-identity", "suffix", "newline"])
def test_bound_pair_refuses_unsealed_foreign_or_discarded_tail(tmp_path, controller, monkeypatch, defect):
    _, validated, kernel, _, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch)
    try:
        proof = finish_barrier_epoch(validated, kernel, barrier, guardian)
        if defect=="receipt-absent":proof["completion_receipt"]=None
        elif defect=="receipt-range":proof["completion_receipt"]["epoch_first_sequence"]+=1
        elif defect=="controller-identity":barrier._controller_identity=controller._freeze({"pid":999,"start_ticks":99,"host_boot_id":BOOT})
        elif defect=="suffix":barrier.guardian_record(dict(barrier.guardian_records[-1],sequence=proof["completion_receipt"]["epoch_last_sequence"]+1,event="failure",code="IO_FAILED"))
        else:barrier._guardian_bytes=barrier._guardian_bytes[:-1]
        with pytest.raises(controller.ControllerError):barrier.commit(proof)
        assert not barrier.may_prepare
    finally:store.close()


@pytest.mark.parametrize("operation", ["after-write", "after-fsync", "after-readback"])
def test_controller_commit_acknowledgement_failure_refuses_next_epoch(tmp_path, controller, monkeypatch, operation):
    _, validated, kernel, backend, store, barrier, guardian = persistence_fixture(tmp_path, controller, monkeypatch,
                                                    fault=(operation,"transitions.active.jsonl"))
    try:
        proof=finish_barrier_epoch(validated,kernel,barrier,guardian)
        if operation=="after-readback":
            checkpoint=backend.checkpoint
            def committed_only(stage,path):
                if stage==operation and path=="transitions.active.jsonl" and b'"event":"completion-committed"' not in (Path(validated.paths.controller_output)/path).read_bytes():return
                return checkpoint(stage,path)
            backend.checkpoint=committed_only
        with pytest.raises(controller.ControllerError):barrier.commit(proof)
        assert not barrier.may_prepare and barrier.accepted==[]
        with pytest.raises(controller.ControllerError):barrier.open_attempt(validated.invocations[1])
        assert (Path(validated.paths.controller_output)/"attempts/fixture-run.main/guardian-receipt.json").is_file()
    finally:store.close()


def test_consumed_then_error_close_never_touches_reused_descriptor(tmp_path,controller,monkeypatch):
    _,validated,kernel,backend,store,barrier,guardian=persistence_fixture(tmp_path,controller,monkeypatch)
    replacement=[]
    normal_close=backend.close
    def uncertain(fd):
        path=store._fds.get(fd)
        # The release action removes fd authority before entering this backend.
        if not replacement and fd not in store._fds:
            normal_close(fd)
            new_fd=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC)
            if new_fd!=fd:os.dup2(new_fd,fd);os.close(new_fd)
            replacement.append(fd)
            raise OSError(errno.EIO,"consumed owned fd, reused number, then reported failure")
        return normal_close(fd)
    try:
        proof=finish_barrier_epoch(validated,kernel,barrier,guardian)
        backend.close=uncertain
        with pytest.raises(controller.ControllerError):barrier.commit(proof)
        assert not barrier.may_prepare and replacement
        backend.close=normal_close
        store.close()
        os.fstat(replacement[0])  # Independent retained descriptor is still open.
    finally:
        backend.close=normal_close
        store.close()
        for fd in replacement:os.close(fd)


def test_failed_open_acknowledgement_retains_handle_for_safe_cleanup(tmp_path,controller,monkeypatch):
    _,_,_,backend,store,_,_=persistence_fixture(tmp_path,controller,monkeypatch)
    observed=[]
    actual_open=os.open
    def track(path,flags,*args,**kwargs):
        fd=actual_open(path,flags,*args,**kwargs)
        if path=="candidate.json":observed.append(fd)
        return fd
    monkeypatch.setattr(os,"open",track)
    def fail(operation,path):
        if operation=="after-create" and path=="candidate.json":raise OSError(errno.EIO,"created fd but acknowledgement failed")
    backend.checkpoint=fail
    try:
        with pytest.raises(controller.ControllerError):store.persist("candidate.json",b"{}\n",maximum=controller.JSON_LIMIT)
        store.close()
        assert observed
        with pytest.raises(OSError) as error:os.fstat(observed[0])
        assert error.value.errno==errno.EBADF
    finally:
        # This independent cleanup closes only the exact test-observed fd.
        for fd in observed:
            try:os.close(fd)
            except OSError as error:assert error.errno==errno.EBADF


@pytest.mark.parametrize("defect",["premature-eof","replaced-root","lease-expiry","backwards-clock","huge-clock"])
def test_readback_and_clock_faults_refuse_caller_seal(tmp_path,controller,monkeypatch,defect):
    _,validated,kernel,backend,store,barrier,guardian=persistence_fixture(tmp_path,controller,monkeypatch)
    try:
        proof=finish_barrier_epoch(validated,kernel,barrier,guardian)
        if defect=="premature-eof":backend.read=lambda fd,maximum:b""
        elif defect=="replaced-root":
            root=Path(validated.paths.controller_output);root.rename(root.with_name("retained-controller"));root.mkdir()
        elif defect=="lease-expiry":backend.wall_time=lambda:validated.expires_at
        elif defect=="backwards-clock":kernel.clock=-1
        else:kernel.clock=10**400
        with pytest.raises(controller.ControllerError):barrier.commit(proof)
        assert not barrier.may_prepare
    finally:store.close()


@pytest.mark.parametrize("bound",["record","count","prefix"])
def test_guardian_callback_enforces_cumulative_lane_bounds(tmp_path,controller,monkeypatch,bound):
    _,validated,kernel,_,store,barrier,guardian=persistence_fixture(tmp_path,controller,monkeypatch)
    try:
        barrier.open_attempt(validated.invocations[0]);guardian.prepare()
        before=bytes(barrier._guardian_bytes)
        if bound=="record":monkeypatch.setattr(controller,"_GUARDIAN_RECORD_LIMIT",1)
        elif bound=="count":monkeypatch.setattr(controller,"_GUARDIAN_RECORD_COUNT",barrier._guardian_count)
        else:monkeypatch.setattr(controller,"_GUARDIAN_PREFIX_LIMIT",len(before))
        with pytest.raises(controller.ControllerError):barrier.guardian_record({"sequence":barrier._guardian_count+1,"event":"echild","time":0.0})
        assert not barrier.may_prepare and bytes(barrier._guardian_bytes)==before
    finally:
        guardian.finish(reason="test-bound-refusal",interrupt=True)
        store.close()


def test_callback_capture_is_independent_of_later_argument_mutation(tmp_path,controller,monkeypatch):
    _,validated,kernel,_,store,barrier,guardian=persistence_fixture(tmp_path,controller,monkeypatch)
    try:
        barrier.open_attempt(validated.invocations[0]);guardian.prepare()
        retained=barrier.guardian_records[0]
        retained["controller_identity"]["pid"]=999
        accepted=barrier.commit(guardian.finish(reason="empty",interrupt=False))
        assert accepted["cleanup"]["status"]=="CLEAN"
        assert barrier.guardian_records[0]["controller_identity"]["pid"]==100
    finally:store.close()


def closure_fixture(tmp_path,controller,monkeypatch):
    """An externally pinned, tiny actual filesystem; no executable is run."""
    fixture=launch_v2_fixture(tmp_path,controller,monkeypatch)
    p,a,l,_,_,_=fixture
    def put(path,raw=b"fixture\n",mode=0o644):
        path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode);return str(path)
    install=tmp_path/"install";purelib=install/"lib/python3.14/site-packages";producer_root=tmp_path/"producer"
    ctrl=tmp_path/"controller-python";runner=tmp_path/"runner-python";tool=tmp_path/"tool"
    ctrl_image=put(ctrl/"bin/python3.14",b"controller image\n",0o755)
    runner_image=put(runner/"bin/python3.13",b"runner image\n",0o755)
    tool_interpreter=tool/"bin/python";tool_interpreter.parent.mkdir(parents=True);tool_interpreter.symlink_to(runner_image)
    entry=put(tool/"bin/vng",b"#!"+str(tool_interpreter).encode()+b"\n",0o755)
    put(ctrl/"lib/python3.14/os.py",b"# stdlib\n");put(runner/"lib/python3.13/os.py",b"# stdlib\n")
    module=put(tool/"lib/python3.13/site-packages/virtme_ng/__init__.py",b"# module\n")
    summary=chain_fixture(tmp_path)
    summary.update(form="console-script",entry=vars(execution.identify_file(entry)),image=vars(execution.identify_file(entry)),
                   interpreter=vars(execution.identify_file(str(tool_interpreter))),modules=[{"name":"virtme_ng","file":vars(execution.identify_file(module))}],argv_prefix=[entry])
    summary["digest"]=digest_of({k:v for k,v in summary.items() if k!="digest"})
    admission={"contract":"controller-execution-input-v1","runner":summary,"launcher":summary,"qemu":chain_fixture(tmp_path)}
    for invocation in p["lanes"]["local-tcg"]["invocations"]:invocation["argv"][0]=entry
    expected=p["lanes"]["local-tcg"]["expected"]
    for role in ["runner","launcher","qemu"]:expected[role+"_admission_sha256"]=admission[role]["digest"]
    qemu_modules=tmp_path/"qemu-modules";qemu_data=tmp_path/"qemu-data"
    monkeypatch.setattr(controller,"_QEMU_MODULE_ROOT",str(qemu_modules),raising=False)
    monkeypatch.setattr(controller,"_QEMU_DATA_ROOT",str(qemu_data),raising=False)
    native=put(qemu_modules/"block-fixture.so",b"separately admitted native runtime\n")
    put(qemu_data/"fixture.rom",b"data\n")
    rootfs=tmp_path/"rootfs";rootfs.mkdir();(rootfs/"empty").mkdir();guestbin=put(rootfs/"usr/bin/sh",b"guest shell\n",0o755)
    (rootfs/"bin").symlink_to("usr/bin")
    entries=[]
    for path in sorted(rootfs.rglob("*")):
        info=path.lstat();row={"path":str(path.relative_to(rootfs)),"mode":stat.S_IMODE(info.st_mode)}
        if path.is_symlink():row.update(kind="symlink",target=os.readlink(path))
        elif path.is_dir():row.update(kind="directory")
        else:row.update(kind="file",size=info.st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        entries.append(row)
    root_doc={"contract":"owned-rootfs-v1","root":str(rootfs),"sha256":digest_of(entries),"entry_encoding":"canonical JSON(entries), sort_keys, compact separators, ASCII","entries":entries}
    payload=tmp_path/"payload";payload_rows=[]
    for name in ["bpf_test_run.py","control.bpf.c","control.bpf.o","guest-observer.py","negative-control.py","packet.bin","v6.12-kernel.config","v6.6-kernel.config"]:
        path=put(payload/name,name.encode());payload_rows.append({"path":name,"sha256":hashlib.sha256(Path(path).read_bytes()).hexdigest(),"bytes":Path(path).stat().st_size})
    payload_doc={"contract":"owned-bootstrap-payload-v1","root":str(payload),"files":payload_rows,"sha256":digest_of(payload_rows),"exclusion":"Only two lane-input sidecars are excluded."}
    packages=[]
    for name in ["image.deb","modules.deb"]:
        path=put(tmp_path/"kernel"/name,name.encode());packages.append({"path":path,"sha256":hashlib.sha256(Path(path).read_bytes()).hexdigest(),"metadata":"Package: fixture\nArchitecture: amd64\n","exit":0})
    boot=put(tmp_path/"kernel/vmlinuz",b"kernel\n")
    expected.update(kernel_release="6.12.0-fixture",rootfs_sha256=root_doc["sha256"],payload_sha256=payload_doc["sha256"],kernel_packages_sha256=digest_of(packages),kernel_image_sha256=hashlib.sha256(Path(boot).read_bytes()).hexdigest(),kernel_config_sha256=next(r["sha256"] for r in payload_rows if r["path"]=="v6.12-kernel.config"))
    sidecar=put(payload/"v6.12-inputs.json",json.dumps({"inputs":expected,"packages":{},"build_flags":[]}).encode())
    other=put(payload/"v6.6-inputs.json",b'{"inputs":{}}\n')
    parent={"contract":"provisional-disposable-launch-v1","revision":2,"payload":payload_doc,"rootfs":{"path":str(rootfs),"sha256":root_doc["sha256"]},"lanes":{"local-tcg":{"packages":packages,"boot_image":boot,"input_sidecar":{"path":sidecar,"sha256":hashlib.sha256(Path(sidecar).read_bytes()).hexdigest()},"expected":expected},"v6.6-tcg":{"packages":packages,"boot_image":boot,"input_sidecar":{"path":other,"sha256":hashlib.sha256(Path(other).read_bytes()).hexdigest()},"expected":dict(expected,kernel_config_sha256=next(r["sha256"] for r in payload_rows if r["path"]=="v6.6-kernel.config"))}}}
    # The admitted profile associates local-tcg's kernel release with v6.12.
    parent["lanes"]["v6.6-tcg"]["expected"]["kernel_release"]="6.6.0-fixture"
    original_rows=[{"path":entry,"realpath":str(Path(entry).resolve()),"sha256":hashlib.sha256(Path(entry).read_bytes()).hexdigest(),"bytes":Path(entry).stat().st_size}]
    supplement_rows=[{"path":native,"realpath":native,"sha256":hashlib.sha256(Path(native).read_bytes()).hexdigest(),"bytes":Path(native).stat().st_size}]
    original={"status":"PASS","files":original_rows,"sha256":digest_of(original_rows)}
    supplement={"status":"PASS","files":supplement_rows,"sha256":digest_of(supplement_rows),"modules":1}
    wheel_files={"mojobpf/__init__.py":b"# fixture\n","mojobpf/target_controller.py":b"# fixture controller\n","mojobpf/cli.py":b"def main(): return 0\n","mojobpf/resources/adapter/admission.json":b"{}\n","mojobpf-0.2.0.dist-info/licenses/LICENSE":b"fixture license\n","mojobpf-0.2.0.dist-info/METADATA":b"Metadata-Version: 2.4\nName: mojobpf\nVersion: 0.2.0\n","mojobpf-0.2.0.dist-info/WHEEL":b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n","mojobpf-0.2.0.dist-info/entry_points.txt":b"[console_scripts]\nmojobpf = mojobpf.cli:main\n","mojobpf-0.2.0.dist-info/top_level.txt":b"mojobpf\n","mojobpf-0.2.0.dist-info/RECORD":b"mojobpf-0.2.0.dist-info/RECORD,,\n"}
    for name in ["cost","fixture","result","run-plan","target"]:wheel_files["mojobpf-0.2.0.data/data/share/mojobpf/schemas/"+name+".schema.json"]=b'{"type":"object"}\n'
    wheel_raw=io.BytesIO()
    with zipfile.ZipFile(wheel_raw,"w",compression=zipfile.ZIP_DEFLATED) as archive:
        for name,raw in sorted(wheel_files.items()):archive.writestr(name,raw)
    wheel=put(producer_root/"mojobpf-0.2.0-py3-none-any.whl",wheel_raw.getvalue())
    sources,members=[],[]
    for name,raw in sorted(wheel_files.items()):
        source=None;destination=str(purelib/name)
        if ".data/data/" in name:destination=str(install/name.split(".data/data/",1)[1]);source="schemas/"+Path(name).name
        elif "/licenses/" in name:source=Path(name).name
        elif ".dist-info/" not in name:source="src/"+name
        elif name.endswith("/RECORD"):destination=None
        if source:sources.append({"path":source,"sha256":hashlib.sha256(raw).hexdigest()})
        if destination:put(destination,raw)
        members.append({"member":name,"sha256":hashlib.sha256(raw).hexdigest(),"size":len(raw),"source_path":source,"installed_path":destination})
    generated=[]
    for name,kind,raw in [("RECORD","record",b"installed rewritten\n"),("INSTALLER","installer",b"pip\n"),("REQUESTED","requested",b"")]:
        path=put(purelib/("mojobpf-0.2.0.dist-info/"+name),raw);generated.append({"path":path,"kind":kind})
    script=put(install/"bin/mojobpf",b"#!"+ctrl_image.encode()+b"\n",0o755);generated.append({"path":script,"kind":"entrypoint"})
    farm=Path(p["paths"]["farm"]);(farm/"vng").symlink_to(entry)
    runtime_roots=[{"path":str(ctrl/"lib/python3.14"),"purpose":"python-stdlib"},{"path":str(runner/"lib/python3.13"),"purpose":"python-stdlib"},{"path":str(tool/"lib/python3.13/site-packages"),"purpose":"python-site-packages"},{"path":str(qemu_modules),"purpose":"qemu-modules"},{"path":str(qemu_data),"purpose":"qemu-data"}]
    complete=[producer_root,install,farm,rootfs,payload]+[Path(r["path"]) for r in runtime_roots]
    files={}
    def add(path):
        path=Path(path)
        if str(path) in files or str(path)=="/":return
        info=path.lstat();kind="symlink" if path.is_symlink() else "directory" if path.is_dir() else "regular"
        files[str(path)]={"path":str(path),"realpath":str(path.resolve()),"kind":kind,"mode":stat.S_IMODE(info.st_mode),"dev":info.st_dev,"ino":info.st_ino,"uid":info.st_uid,"gid":info.st_gid,"nlink":info.st_nlink,"size":info.st_size,"mtime_ns":info.st_mtime_ns,"ctime_ns":info.st_ctime_ns,"sha256":hashlib.sha256(path.read_bytes()).hexdigest() if kind=="regular" else None,"link_target":os.readlink(path) if kind=="symlink" else None}
        add(path.parent)
        if kind=="symlink":add(path.resolve())
    inventories=[]
    for root in complete:
        for directory,dirs,names in os.walk(root,followlinks=False):
            add(directory);inventories.append({"path":directory,"entries":sorted(dirs+names)})
            for name in dirs+names:add(Path(directory)/name)
    for path in [ctrl_image,runner_image,str(tool_interpreter),entry,module,boot,*[r["path"] for r in packages],admission["qemu"]["entry"]["path"]]:add(path)
    roles={k:[] for k in ["controller","runtime","original_closure","supplemental_closure","rootfs","payload","input_sidecars","kernel_packages","kernel_images","farm"]}
    roles.update(controller=[path for path,row in files.items() if row["kind"]!="directory" and (path==wheel or Path(path).is_relative_to(install))],original_closure=[entry],supplemental_closure=[native],rootfs=[str(rootfs/e["path"]) for e in entries],payload=[str(payload/e["path"]) for e in payload_rows],input_sidecars=[sidecar,other],kernel_packages=[r["path"] for r in packages],kernel_images=[boot,str(payload/"v6.12-kernel.config"),str(payload/"v6.6-kernel.config")],farm=[str(farm/"vng")])
    assigned=set().union(*map(set,roles.values()));roles["runtime"]=[path for path,row in files.items() if row["kind"]!="directory" and path not in assigned]
    distribution={"schema_version":2,"contract":"controller-distribution-v2","producer":{"wheel_path":wheel,"sources":sorted(sources,key=lambda r:r["path"]),"wheel_members":members,"installed_generated":sorted(generated,key=lambda r:r["path"]),"install_scheme":{"purelib":str(purelib),"data":str(install),"scripts":str(install/"bin")},"runtime_layout":{"controller_interpreter":ctrl_image,"controller_stdlib":str(ctrl/"lib/python3.14"),"runner_stdlib":str(runner/"lib/python3.13"),"runner_site_packages":str(tool/"lib/python3.13/site-packages"),"qemu_module_root":str(qemu_modules),"qemu_data_root":str(qemu_data)}},"coverage":{"producer_root":str(producer_root),"install_root":str(install),"runtime_roots":sorted(runtime_roots,key=lambda r:r["path"]),"farm_root":str(farm),"rootfs_root":str(rootfs),"payload_root":str(payload),"shared_files":sorted(path for path,row in files.items() if row["kind"]!="directory" and not any(Path(path).is_relative_to(root) for root in complete))},"files":[files[p] for p in sorted(files)],"roles":{k:sorted(v) for k,v in roles.items()},"inventories":sorted(inventories,key=lambda r:r["path"])}
    records={"admission":admission,"parent_proposal":parent,"kernel_packages":parent,"payload":payload_doc,"rootfs_manifest":root_doc,"original_closure":original,"supplemental_closure":supplement,"controller_distribution":distribution,"input_sidecar":json.loads(Path(sidecar).read_bytes())}
    for name,record in records.items():
        ref=p["inputs"][name]
        if name=="input_sidecar":ref.update(path=sidecar,file_sha256=hashlib.sha256(Path(sidecar).read_bytes()).hexdigest(),canonical_sha256=digest_of(record))
        else:ref.update(write_document(Path(ref["path"]),record))
        if name in ["original_closure","supplemental_closure","payload","rootfs_manifest"]:ref["canonical_sha256"]=record["sha256"]
    # The kernel input consumes exactly the same immutable parent bytes/path.
    p["inputs"]["kernel_packages"]=dict(p["inputs"]["parent_proposal"])
    a["inputs"]=copy.deepcopy(p["inputs"]);l["controller_distribution_sha256"]=p["inputs"]["controller_distribution"]["file_sha256"]
    repin_proposal(fixture)
    observation={"interpreter":ctrl_image,"base_prefix":str(ctrl),"version":[3,14],"sys_path":[str(ctrl/"lib/python3.14"),str(purelib)],"module_path":str(purelib/"mojobpf/target_controller.py"),"distribution_path":str(purelib/"mojobpf-0.2.0.dist-info"),"mapped_files":[]}
    return fixture,distribution,records,observation


def verify_closure(controller,fixture,observation):
    validated=validate_fixture(controller,fixture)
    verify=getattr(controller,"_ClosureVerifier",None)
    assert callable(verify),"complete role-bound closure and producer verification is absent"
    backend=controller._ClosureBackend()
    backend.runtime_observation=lambda:copy.deepcopy(observation)
    backend.monotonic=lambda:0.0
    backend.wall_time=lambda:1893456000.0
    checker=verify(validated,budget=controller._Budget(validated,backend),_backend=backend)
    return checker.verify()


def test_complete_real_shaped_closure_and_wheel_mapping(tmp_path,controller,monkeypatch):
    fixture,distribution,_,observation=closure_fixture(tmp_path,controller,monkeypatch)
    proof=verify_closure(controller,fixture,observation)
    assert proof["files"]==len(distribution["files"])
    assert proof["wheel_members"]==len(distribution["producer"]["wheel_members"])
    assert proof["inventories"]==len(distribution["inventories"])


@pytest.mark.parametrize("defect",["file-bytes","mode","empty-dir-inventory","farm-root","runtime-root","schema-mapping","metadata-source","record-mapping","generated-entrypoint","rootfs-role","excluded-sidecar","module-role","duplicate-member","missing-member","extra-sibling","ancestor-link"])
def test_closure_drift_refuses_before_spawn(tmp_path,controller,monkeypatch,defect):
    fixture,d,_,obs=closure_fixture(tmp_path,controller,monkeypatch)
    if defect=="file-bytes":Path(d["roles"]["payload"][0]).write_bytes(b"different bytes")
    elif defect=="mode":Path(d["roles"]["original_closure"][0]).chmod(0o644)
    elif defect=="empty-dir-inventory":d["inventories"]=[r for r in d["inventories"] if not r["path"].endswith("/empty")]
    elif defect=="farm-root":d["files"]=[r for r in d["files"] if r["path"]!=d["coverage"]["farm_root"]];d["inventories"]=[r for r in d["inventories"] if r["path"]!=d["coverage"]["farm_root"]]
    elif defect=="runtime-root":d["coverage"]["runtime_roots"].pop()
    elif defect=="schema-mapping":next(r for r in d["producer"]["wheel_members"] if ".data/" in r["member"])["installed_path"]=d["producer"]["install_scheme"]["purelib"]+"/bad.json"
    elif defect=="metadata-source":next(r for r in d["producer"]["wheel_members"] if r["member"]=="mojobpf/target_controller.py")["source_path"]=None
    elif defect=="record-mapping":next(r for r in d["producer"]["wheel_members"] if r["member"].endswith("/RECORD"))["installed_path"]=d["producer"]["installed_generated"][0]["path"]
    elif defect=="generated-entrypoint":d["producer"]["installed_generated"]=[r for r in d["producer"]["installed_generated"] if r["kind"]!="entrypoint"]
    elif defect=="rootfs-role":d["roles"]["rootfs"].clear()
    elif defect=="excluded-sidecar":d["roles"]["payload"].append(d["roles"]["input_sidecars"][0])
    elif defect=="module-role":d["roles"]["supplemental_closure"].clear()
    elif defect=="duplicate-member":d["producer"]["wheel_members"].append(copy.deepcopy(d["producer"]["wheel_members"][0]))
    elif defect=="missing-member":d["producer"]["wheel_members"].pop()
    elif defect=="extra-sibling":(Path(d["coverage"]["payload_root"])/"extra").write_bytes(b"extra")
    else:
        link_path=next(Path(r["path"]) for r in d["files"] if r["kind"]=="symlink" and r["path"].endswith("/bin"));link_path.unlink();link_path.symlink_to("/usr/bin")
    reference=fixture[0]["inputs"]["controller_distribution"];reference.update(write_document(Path(reference["path"]),d))
    fixture[1]["inputs"]=copy.deepcopy(fixture[0]["inputs"]);fixture[2]["controller_distribution_sha256"]=reference["file_sha256"];repin_proposal(fixture)
    with pytest.raises(controller.ControllerError):verify_closure(controller,fixture,obs)


@pytest.mark.parametrize("name,allowed",[("controller_distribution",True),("rootfs_provenance",True),("capture_contract",False)])
def test_large_reader_is_selected_by_externally_bound_role(tmp_path,controller,monkeypatch,name,allowed):
    fixture=launch_v2_fixture(tmp_path,controller,monkeypatch)
    ref=fixture[0]["inputs"][name];ref.update(write_document(Path(ref["path"]),{"contract":"claims-large-role","padding":"x"*controller.JSON_LIMIT}))
    fixture[1]["inputs"]=copy.deepcopy(fixture[0]["inputs"])
    if name=="controller_distribution":fixture[2]["controller_distribution_sha256"]=ref["file_sha256"]
    repin_proposal(fixture)
    if allowed:assert validate_fixture(controller,fixture).schema_version==2
    else:
        with pytest.raises(controller.ControllerError):validate_fixture(controller,fixture)


def repin_closure(fixture, descriptor):
    reference = fixture[0]["inputs"]["controller_distribution"]
    reference.update(write_document(Path(reference["path"]), descriptor))
    fixture[1]["inputs"] = copy.deepcopy(fixture[0]["inputs"])
    fixture[2]["controller_distribution_sha256"] = reference["file_sha256"]
    return repin_proposal(fixture)


def closure_checker(controller, fixture, observation):
    validated = validate_fixture(controller, fixture)
    backend = controller._ClosureBackend()
    backend.runtime_observation = lambda: copy.deepcopy(observation)
    backend.monotonic = lambda: 0.0
    backend.wall_time = lambda: 1893456000.0
    checker = controller._ClosureVerifier(validated, budget=controller._Budget(validated, backend), _backend=backend)
    return checker, backend


def test_closure_refresh_allows_owned_output_creation_after_admission(tmp_path, controller, monkeypatch):
    fixture, descriptor, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    checker, _ = closure_checker(controller, fixture, observed)
    Path(fixture[0]["paths"]["controller_output"]).mkdir(mode=0o700)
    (tmp_path / "new-owned-directory").mkdir(mode=0o700)
    assert checker.verify()["files"] == len(descriptor["files"])


@pytest.mark.parametrize("defect", ["ancestor-mode", "ancestor-owner", "ancestor-group", "complete-time", "complete-mode", "complete-empty-extra"])
def test_closure_directory_exception_is_limited_to_ancestor_mutable_observations(tmp_path, controller, monkeypatch, defect):
    fixture, descriptor, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    root = Path(descriptor["coverage"]["rootfs_root"])
    if defect.startswith("ancestor"):
        row = next(row for row in descriptor["files"] if row["path"] == str(tmp_path))
        field = {"ancestor-mode": "mode", "ancestor-owner": "uid", "ancestor-group": "gid"}[defect]
        row[field] = row[field] ^ 1
        repin_closure(fixture, descriptor)
    elif defect == "complete-time": os.utime(root, ns=(1, 1))
    elif defect == "complete-mode": root.chmod(0o700)
    else: (root / "empty" / "extra").write_bytes(b"unauthorized")
    with pytest.raises(controller.ControllerError): verify_closure(controller, fixture, observed)


@pytest.mark.parametrize("name", ["files", "inventories", "edges", "roles", "runtime_roots", "sources", "wheel_members", "installed_generated"])
def test_each_closure_count_is_intrinsically_bounded(tmp_path, controller, monkeypatch, name):
    fixture, _, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    monkeypatch.setitem(controller._CLOSURE_COUNTS, name, 1)
    with pytest.raises(controller.ControllerError): verify_closure(controller, fixture, observed)


@pytest.mark.parametrize("name", ["_WHEEL_BYTES", "_WHEEL_EXPANDED", "_WHEEL_MEMBER_BYTES", "_RUNTIME_FILE_BYTES", "_RUNTIME_TOTAL_BYTES", "_LARGE_NODE_LIMIT"])
def test_closure_byte_and_structural_limits_refuse_without_truncation(tmp_path, controller, monkeypatch, name):
    fixture, _, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    monkeypatch.setattr(controller, name, 1)
    with pytest.raises(controller.ControllerError): verify_closure(controller, fixture, observed)


@pytest.mark.parametrize("field", ["interpreter", "module_path", "distribution_path", "base_prefix", "sys_path", "mapped_files"])
def test_actual_controller_runtime_is_required_not_just_a_descriptor_claim(tmp_path, controller, monkeypatch, field):
    fixture, _, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    observed[field] = ["/unapproved"] if field in {"sys_path", "mapped_files"} else "/unapproved"
    with pytest.raises(controller.ControllerError): verify_closure(controller, fixture, observed)


@pytest.mark.parametrize("defect", ["missing-canonical", "unknown-top", "unknown-row", "unknown-layout", "boolean-stat", "huge-stat", "relative-path", "unclassified"])
def test_closed_distribution_fields_and_external_canonical_pin(tmp_path, controller, monkeypatch, defect):
    fixture, descriptor, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    if defect == "unknown-top": descriptor["extra"] = True
    elif defect == "unknown-row": descriptor["files"][0]["extra"] = True
    elif defect == "unknown-layout": descriptor["producer"]["runtime_layout"]["extra"] = True
    elif defect == "boolean-stat": descriptor["files"][0]["ino"] = True
    elif defect == "huge-stat": descriptor["files"][0]["ino"] = 2**63
    elif defect == "relative-path": descriptor["files"][0]["path"] = "../escape"
    elif defect == "unclassified":
        path = descriptor["roles"]["runtime"][0]
        for values in descriptor["roles"].values():
            if path in values: values.remove(path)
    repin_closure(fixture, descriptor)
    if defect == "missing-canonical":
        fixture[0]["inputs"]["controller_distribution"]["canonical_sha256"] = None
        fixture[1]["inputs"] = copy.deepcopy(fixture[0]["inputs"])
        repin_proposal(fixture)
    with pytest.raises(controller.ControllerError): verify_closure(controller, fixture, observed)


def test_deadline_failure_still_physically_closes_unreleased_closure_handles(tmp_path, controller, monkeypatch):
    fixture, _, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    checker, backend = closure_checker(controller, fixture, observed)
    now, opened = [0.0], []
    backend.monotonic = lambda: now[0]
    def expire(operation, path):
        if operation == "after-directory-open":
            opened.extend(checker.directories.values())
            now[0] = 4000.0
    backend.checkpoint = expire
    try:
        with pytest.raises(controller.ControllerError): checker.verify()
        assert opened
        for fd in opened:
            with pytest.raises(OSError): os.fstat(fd)
    finally:
        for fd in opened:
            try: os.close(fd)
            except OSError: pass


def test_closure_short_reads_are_fully_hashed(tmp_path, controller, monkeypatch):
    fixture, descriptor, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    checker, backend = closure_checker(controller, fixture, observed)
    backend.read = lambda fd, maximum: os.read(fd, min(3, maximum))
    assert checker.verify()["files"] == len(descriptor["files"])


def test_late_overwrite_of_an_already_hashed_file_refuses_the_whole_pass(tmp_path, controller, monkeypatch):
    fixture, descriptor, _, observed = closure_fixture(tmp_path, controller, monkeypatch)
    checker, backend = closure_checker(controller, fixture, observed)
    earlier = descriptor["roles"]["payload"][0]
    last = max(row["path"] for row in descriptor["files"] if row["kind"] == "regular")
    changed = [False]
    def mutate(operation, path):
        if operation == "after-content-read" and path == last and not changed[0]:
            changed[0] = True
            Path(earlier).write_bytes(b"late overwrite\n")
    backend.checkpoint = mutate
    with pytest.raises(controller.ControllerError): checker.verify()
    assert changed[0]


@pytest.mark.parametrize("kind", ["dictionary", "copy", "legacy"])
def test_execution_authority_cannot_be_made_from_caller_values(tmp_path, controller, monkeypatch, kind):
    fixture = launch_fixture(tmp_path, controller, monkeypatch) if kind == "legacy" else launch_v2_fixture(tmp_path, controller, monkeypatch)
    validated = validate_fixture(controller, fixture)
    if kind == "dictionary": validated = vars(validated)
    if kind == "copy":
        from dataclasses import replace
        validated = replace(validated)
    with pytest.raises(controller.ControllerError): controller._execution_authority(validated)


def lease_fixture(tmp_path, controller, monkeypatch):
    fixture = launch_v2_fixture(tmp_path, controller, monkeypatch)
    validated = validate_fixture(controller, fixture)
    backend = controller._PersistenceBackend()
    backend.monotonic = lambda: 0.0
    backend.wall_time = lambda: 1893456000.0
    return fixture, validated, controller._Budget(validated, backend), backend


def test_second_lease_holder_refused_before_spawn(tmp_path, controller, monkeypatch):
    _, validated, budget, backend = lease_fixture(tmp_path, controller, monkeypatch)
    lease_class = getattr(controller, "_LaneLease", None)
    assert callable(lease_class), "exclusive retained lease locking is absent"
    first = lease_class(validated, budget=budget, _backend=backend)
    try:
        with pytest.raises(controller.ControllerError) as error: lease_class(validated, budget=budget, _backend=backend)
        assert error.value.code == "LEASE_REQUIRED"
        first.verify()
    finally: first.close()


@pytest.mark.parametrize("state", ["ACTIVE", "QUARANTINED", "RELEASABLE"])
def test_stale_lease_history_never_resumes_under_a_new_lock(tmp_path, controller, monkeypatch, state):
    _, validated, budget, backend = lease_fixture(tmp_path, controller, monkeypatch)
    root = Path(validated.paths.controller_output); root.mkdir(mode=0o700)
    Path(validated.paths.lease_journal).write_text(json.dumps({"state": state}))
    lease_class = getattr(controller, "_LaneLease", None)
    assert callable(lease_class), "stale lease history refusal is absent"
    with pytest.raises(controller.ControllerError): lease_class(validated, budget=budget, _backend=backend)
    assert json.loads(Path(validated.paths.lease_journal).read_bytes())["state"] == state


def test_lock_path_replacement_is_refused_while_original_lock_is_held(tmp_path, controller, monkeypatch):
    _, validated, budget, backend = lease_fixture(tmp_path, controller, monkeypatch)
    lease_class = getattr(controller, "_LaneLease", None)
    assert callable(lease_class), "retained lock identity revalidation is absent"
    lease = lease_class(validated, budget=budget, _backend=backend)
    try:
        lock = Path(validated.lock.path); lock.rename(lock.with_name("old.lock")); lock.touch(mode=0o600)
        with pytest.raises(controller.ControllerError): lease.verify()
    finally: lease.close()


def test_guest_export_reader_preserves_partial_bytes_and_seals_exact_capture(tmp_path, controller, monkeypatch):
    _, validated, budget, backend = lease_fixture(tmp_path, controller, monkeypatch)
    reader_class = getattr(controller, "_GuestExport", None)
    assert callable(reader_class), "bounded retained guest-export capture is absent"
    path = Path(validated.invocations[0].output_path); path.mkdir(mode=0o700); path.chmod(0o700)
    reader = reader_class(str(path), budget=budget, _backend=backend)
    try:
        (path / "marker.json").write_bytes(b'{"partial":')
        assert reader.capture("marker.json", partial=True) is None
        assert reader.partial_bytes == [("marker.json", b'{"partial":')]
        (path / "marker.json").write_bytes(b'{"actual":42}\n')
        captured = reader.capture("marker.json")
        assert captured.raw == b'{"actual":42}\n' and captured.value == {"actual": 42}
        (path / "marker.json").write_bytes(b'{"actual":43}\n')
        assert captured.raw == b'{"actual":42}\n'
        with pytest.raises(controller.ControllerError): reader.revalidate(captured)
    finally: reader.close()


@pytest.mark.parametrize("defect", ["symlink", "hard-link", "traversal", "duplicate", "nonfinite", "oversize", "foreign-root"])
def test_guest_cannot_substitute_controller_evidence_or_unbounded_json(tmp_path, controller, monkeypatch, defect):
    _, validated, budget, backend = lease_fixture(tmp_path, controller, monkeypatch)
    reader_class = getattr(controller, "_GuestExport", None)
    assert callable(reader_class), "guest no-follow capture boundary is absent"
    path = Path(validated.invocations[0].output_path); path.mkdir(mode=0o700); path.chmod(0o700)
    reader = reader_class(str(path), budget=budget, _backend=backend)
    name = "marker.json"
    try:
        if defect == "symlink": (path / name).symlink_to(validated.lock.path)
        elif defect == "hard-link": os.link(validated.lock.path, path / name)
        elif defect == "traversal": name = "../lane.lock"
        elif defect == "duplicate": (path / name).write_bytes(b'{"key":1,"key":2}')
        elif defect == "nonfinite": (path / name).write_bytes(b'{"key":NaN}')
        elif defect == "oversize": (path / name).write_bytes(b"x" * (controller.JSON_LIMIT + 1))
        else:
            path.rename(path.with_name("old-export")); path.mkdir(mode=0o700)
        with pytest.raises(controller.ControllerError): reader.capture(name)
    finally: reader.close()


def controller_engine_fixture(tmp_path, controller, monkeypatch, *, defect=None):
    fixture, _, _, observation = closure_fixture(tmp_path, controller, monkeypatch)
    validated = validate_fixture(controller, fixture)
    engine_class = getattr(controller, "_LaneController", None)
    backend_class = getattr(controller, "_ControllerBackend", None)
    assert callable(engine_class) and callable(backend_class), "lease-bound three-phase evidence engine is absent"
    # Independent guest observations originate in the frozen assessor's public
    # controls. They are inert fixture data, never real kernel qualification.
    template_root = tmp_path / "guest-observation-templates"; template_root.mkdir()
    path = Path(__file__).with_name("test_target_bootstrap.py")
    spec = importlib.util.spec_from_file_location("controller_bootstrap_controls", path)
    controls = importlib.util.module_from_spec(spec); spec.loader.exec_module(controls)
    _, old_provisional, old_attempt, _ = controls.evidence.__wrapped__(template_root)
    templates = {}
    for phase in ("main", "interrupted", "fresh"):
        if phase == "main": refs = {k:v for k,v in old_attempt["evidence"].items() if k != "recovery"}
        else: refs = json.loads((template_root / (phase + "_attempt.json")).read_bytes())
        templates[phase] = {name:json.loads((template_root / ref["path"]).read_bytes()) for name,ref in refs.items()}
    kernel = guardian_kernel_fixture()
    kernel.read_mountinfo = lambda: "1 0 0:1 / / rw - tmpfs rootfs rw\n"
    class Backend(backend_class):
        def __init__(self): self.spawns, self.nice_calls, self.pending, self.calls = [], [], None, []
        def monotonic(self): return kernel.clock
        def wall_time(self): return 1893456000.0 + kernel.clock
        def runtime_observation(self): return copy.deepcopy(observation)
        def controller_identity(self): return {"pid":100,"start_ticks":99,"host_boot_id":BOOT}
        def controller_launch_observation(self): return {"isolated":True,"dont_write_bytecode":True,"pycache_prefix":validated.paths.controller_pycache}
        def change_nice(self, increment): self.nice_calls.append(increment); return {"before":0,"after":increment}
        def guardian(self, *, limits, journal): return controller.ProcessGuardian(limits=limits,journal=journal,_backend=kernel)
        def owned_image(self, identity):
            return validated.qemu.image if defect != "wrong-qemu" else validated.runner.interpreter
        def checkpoint(self, operation, path):
            self.calls.append((operation,path))
            if defect == "terminal-write" and operation == "before-create" and path == "controller-result.json": raise OSError(errno.EIO,"terminal write fault")
            if defect == "late-commit" and operation == "after-readback" and path.endswith("guardian-receipt.json"): kernel.clock += 30
        def pause(self, seconds):
            held_marker = defect in {"marker-timeout","late-marker"} and self.spawns[-1] == "interrupted"
            kernel.clock += 100 if defect == "startup-timeout" or held_marker else seconds
            if defect == "late-marker" and held_marker and kernel.clock >= 300:
                write_document(*self.late_marker)
            if self.pending and defect != "startup-timeout" and not held_marker:
                runner, qemu = self.pending; kernel.exit(qemu); kernel.exit(runner, 1 if defect == "ordinary-failure" else 0); self.pending=None
        def spawn(self, admitted, invocation, stdout, stderr):
            phase = invocation.phase; self.spawns.append(phase)
            assert admitted is validated.runner
            index = ("main","interrupted","fresh").index(phase)
            first = 1000 + index * 10
            runner = kernel.add(pid=first,ticks=first*100,session=first)
            qemu = kernel.add(pid=first+1,ticks=first*100+1,ppid=first,session=first)
            data = copy.deepcopy(templates[phase]); expected = dict(validated.expected)
            binding = {"attempt_id":invocation.attempt_id,"guest_id":invocation.attempt_id,
                       "boot_id":str(index+1)*8+"-"+str(index+1)*4+"-4"+str(index+1)*3+"-8"+str(index+1)*3+"-"+str(index+1)*12}
            target = data["target"]
            target["kernel"].update(source_commit=expected["kernel_source_commit"],release=expected["kernel_release"],build_id=expected["kernel_build_id"],config_sha256=expected["kernel_config_sha256"])
            target["btf"]["vmlinux_sha256"]=expected["vmlinux_btf_sha256"]; target["image"]["digest"]=expected["rootfs_sha256"]
            target["build_host"]["identity"]=expected["compiler_sha256"]; target["mounts"]["bpffs"]="/sys/fs/bpf/mojobpf/"+validated.run_id
            target["boot"]["parameters"]=["console=ttyS0","virtme_hostname="+invocation.attempt_id]
            if defect == "wrong-kernel": target["kernel"]["release"]="foreign"
            target["fingerprint"]=digest_of({k:v for k,v in target.items() if k!="fingerprint"})
            for record in data.values():
                if "attempt_id" in record: record.update(binding)
            pinbase=target["mounts"]["bpffs"]+"/"+invocation.attempt_id
            context=data.get("permission_context")
            if context:
                context["pin_parent"]=pinbase
                context["proc_stat"]="17 (python3) R 1 17 17 " + "0 "*15 + "50\n"
            for name in ["positive","permission_negative"]:
                if name not in data: continue
                result=data[name]["result"]; result["runtime"]["kernel_release"]=expected["kernel_release"]
                result["object"]["sha256"]=expected["control_object_sha256"]; result["data_in"]["sha256"]=expected["packet_sha256"]
                result["bpftool"].update(entry_sha256=expected["bpftool_sha256"],version=expected["bpftool_version"])
                result["commands"][0]["stdout"]=expected["bpftool_version"]+"\n"
                result["admission"]["ownership_token"]=validated.run_id
                oldpin=result["pin_path"]; result["pin_path"]=pinbase+("/positive" if name=="positive" else "/permission-negative")
                for command in result["commands"]:
                    command["argv"]=[result["pin_path"] if arg==oldpin else arg for arg in command["argv"]]
            data["pin_root_absence"]["pin_root"]=target["mounts"]["bpffs"]
            cleanup=data["cleanup"]
            cleanup={**binding,**{k:cleanup[k] for k in ["status","owned_processes","owned_mounts","owned_pins","guest_unmount","pin_observation"]},"created_pin_root":True,"created_attempt_root":True}
            cleanup["pin_observation"]["root"]=target["mounts"]["bpffs"]
            data["guest-cleanup"] = cleanup
            data["guest-identity"]={**binding,"boot_parameters":target["boot"]["parameters"]}
            if phase == "interrupted":
                trigger=data["trigger"]; trigger["held_pin"]=pinbase+"/recovery-held"; trigger["load_command"]["argv"][-1]=trigger["held_pin"]
                trigger["positive_sha256"]=digest_of(data["positive"]); data["ready-to-interrupt"]=trigger
            if defect == "foreign-marker" and phase == "interrupted": data["ready-to-interrupt"]["guest_id"]="foreign"
            if defect == "marker-digest" and phase == "interrupted": data["ready-to-interrupt"]["positive_sha256"]=HASH
            export=Path(invocation.output_path)
            if defect == "late-marker" and phase == "interrupted": self.late_marker=(export/"ready-to-interrupt.json",data["ready-to-interrupt"])
            for name, record in data.items():
                if name in {"cleanup","execution","trigger"}: continue
                if defect in {"startup-timeout","exit-without-evidence"}: continue
                if defect == "missing-negative-context" and name=="permission_context": continue
                if defect in {"marker-timeout","late-marker"} and name=="ready-to-interrupt": continue
                write_document(export/(name+".json"),record)
            if context and defect != "missing-negative-context":
                data["permission_negative"]["context_sha256"]=hashlib.sha256((export/"permission_context.json").read_bytes()).hexdigest()
                write_document(export/"permission_negative.json",data["permission_negative"])
            os.write(stdout,b"controlled stdout\n"); os.write(stderr,b"controlled stderr\n")
            if phase != "interrupted" or defect == "ordinary-failure": self.pending=(runner,qemu)
            if defect == "cancel-after-spawn": kernel.cancel_handler(2,None)
            if defect == "mount-drift": kernel.read_mountinfo=lambda:"2 0 0:1 / / rw - tmpfs rootfs rw\n"
            from types import SimpleNamespace
            return SimpleNamespace(pid=first,returncode=None)
    backend = Backend()
    return fixture, validated, backend, kernel, engine_class(validated, _backend=backend), controls


def test_three_phases_use_real_assembly_and_the_frozen_assessor(tmp_path, controller, monkeypatch):
    _, validated, backend, _, engine, controls = controller_engine_fixture(tmp_path,controller,monkeypatch)
    result=engine.run()
    assert result["outcome"]=="PASS" and result["lease_disposition"]=="RELEASABLE"
    assert backend.spawns==["main","interrupted","fresh"] and backend.nice_calls==[10]
    assert [a["runner_exit"] for a in result["attempts"]]==[0,-9,0]
    result_check(controller,result);v2_schema_validator().validate(result)
    root=Path(validated.paths.output_root)
    wrapper=json.loads((root/result["projection"]["path"]).read_bytes())
    report=controls.bootstrap().assess_bootstrap(engine.provisional,wrapper,digest_of(engine.provisional),root)
    assert report["status"]=="READY",report


@pytest.mark.parametrize("defect", ["exit-without-evidence","startup-timeout","wrong-kernel","wrong-qemu","missing-negative-context","ordinary-failure","cancel-after-spawn","mount-drift","terminal-write","late-commit"])
def test_phase_failures_never_launch_a_successor_or_fabricate_guest_facts(tmp_path,controller,monkeypatch,defect):
    _,_,backend,kernel,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch,defect=defect)
    try: result=engine.run()
    except controller.ControllerError:
        assert defect in {"terminal-write","late-commit"}
    else:
        assert result["outcome"]!="PASS" and result["projection"] is None
        assert all(not a["started"] and a["cleanup"] is None for a in result["attempts"][1:])
        if defect in {"exit-without-evidence","startup-timeout"}: assert result["attempts"][0]["guest"] is None
        if defect=="ordinary-failure": assert result["lease_disposition"]=="RELEASABLE"
        if defect=="mount-drift": assert result["lease_disposition"]=="QUARANTINED"
    assert backend.spawns==(["main","interrupted","fresh"] if defect=="terminal-write" else ["main"])
    assert not any(not process.exited for process in kernel.current.values())


@pytest.mark.parametrize("defect",["foreign-marker","marker-digest","marker-timeout","late-marker"])
def test_interruption_requires_a_valid_timely_owned_guest_marker(tmp_path,controller,monkeypatch,defect):
    _,_,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch,defect=defect)
    result=engine.run()
    assert result["outcome"]!="PASS" and result["attempts"][2]["outcome"]=="NOT_RUN"
    assert backend.spawns==["main","interrupted"]


def test_current_qemu_must_still_be_owned_and_live_when_marker_is_consumed(tmp_path,controller,monkeypatch):
    _,_,backend,kernel,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    checkpoint=backend.checkpoint; killed=[False]
    def exit_qemu(operation,path):
        checkpoint(operation,path)
        if operation=="after-guest-read" and path=="ready-to-interrupt.json" and not killed[0]:
            killed[0]=True; kernel.exit(kernel.current[1011])
    backend.checkpoint=exit_qemu
    result=engine.run()
    assert killed[0] and backend.spawns==["main","interrupted"]
    assert result["outcome"]!="PASS" and result["attempts"][2]["outcome"]=="NOT_RUN"


def test_owned_adoption_continues_after_qemu_role_has_been_observed(tmp_path,controller,monkeypatch):
    _,validated,backend,kernel,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    spawn,pause=backend.spawn,backend.pause
    marker, ticks, observed_before_marker=[None],[0],[False]
    def hold(admitted,invocation,stdout,stderr):
        process=spawn(admitted,invocation,stdout,stderr)
        if invocation.phase=="interrupted":
            path=Path(invocation.output_path)/"ready-to-interrupt.json"
            marker[0]=(path,path.read_bytes());path.unlink()
        return process
    def tick(seconds):
        pause(seconds)
        if backend.spawns[-1]=="interrupted":
            ticks[0]+=1
            if ticks[0]==1:kernel.add(pid=1030,ticks=103000,ppid=1011,session=1010)
            if ticks[0]==2:
                observed_before_marker[0]=any(item.pid==1030 for item in kernel.handles.values())
                marker[0][0].write_bytes(marker[0][1])
    backend.spawn,backend.pause=hold,tick
    backend.owned_image=lambda identity:validated.runner.interpreter if identity["pid"]==1030 else validated.qemu.image
    result=engine.run()
    assert result["outcome"]=="PASS"
    assert observed_before_marker[0],"controller stopped owned discovery once QEMU was known"
    assert any(p["identity"]["pid"]==1030 for p in result["attempts"][1]["processes"])


def test_failure_during_cache_setup_closes_each_earlier_owned_directory(tmp_path,controller,monkeypatch):
    _,validated,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    instances=[]; original_dir=controller._OwnedDirectory; original_export=controller._GuestExport
    class Directory(original_dir):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs);instances.append(self)
    class Export(original_export):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs);instances.append(self)
    monkeypatch.setattr(controller,"_OwnedDirectory",Directory);monkeypatch.setattr(controller,"_GuestExport",Export)
    fsync=backend.fsync; created=[False]
    attempt_cache=Path(dict(validated.invocations[0].env_overrides)["PYTHONPYCACHEPREFIX"])
    def inject(fd):
        if attempt_cache.parent.exists() and not created[0]:
            created[0]=True;attempt_cache.mkdir(mode=0o700)
        return fsync(fd)
    backend.fsync=inject
    try:
        result=engine.run()
        assert result["outcome"]!="PASS" and not backend.spawns
        assert result["attempts"][0]["cleanup"] is None
        assert all(instance.fd is None for instance in instances),"a setup predecessor directory handle leaked"
    finally:
        for instance in instances:instance.close()


def test_owned_store_constructor_failure_closes_its_retained_root(tmp_path,controller,monkeypatch):
    _,validated,budget,backend=lease_fixture(tmp_path,controller,monkeypatch)
    instances=[]; original=controller._OwnedStore
    class Store(original):
        def __new__(cls,*args,**kwargs):
            instance=super().__new__(cls);instances.append(instance);return instance
    def fault(operation,path):
        if operation=="after-directory-fsync" and path==".":raise OSError(errno.EIO,"constructor acknowledgement failed")
    backend.checkpoint=fault
    try:
        with pytest.raises(controller.ControllerError):Store(validated.paths.controller_output,output_root=validated.paths.output_root,budget=budget,_backend=backend)
        assert not instances[0]._fds,"constructor lost a live directory handle"
    finally:
        for instance in instances:instance.close()


def test_private_clock_refusal_is_typed_even_during_budget_construction(tmp_path,controller,monkeypatch):
    fixture=launch_v2_fixture(tmp_path,controller,monkeypatch);validated=validate_fixture(controller,fixture)
    backend=controller._PersistenceBackend();backend.monotonic=lambda:10**1000
    with pytest.raises(controller.ControllerError):controller._Budget(validated,backend)


def test_marker_changed_while_written_is_preserved_and_never_accepted_early(tmp_path,controller,monkeypatch):
    _,validated,budget,backend=lease_fixture(tmp_path,controller,monkeypatch)
    path=Path(validated.invocations[0].output_path);path.mkdir(mode=0o700);path.chmod(0o700)
    reader=controller._GuestExport(str(path),budget=budget,_backend=backend)
    (path/"marker.json").write_bytes(b'{"key":')
    changed=[False]
    def complete(operation,name):
        if operation=="after-guest-read" and not changed[0]:
            changed[0]=True
            with (path/name).open("ab") as stream:stream.write(b"42}")
    backend.checkpoint=complete
    try:
        assert reader.capture("marker.json",partial=True) is None
        assert reader.partial_bytes
        assert reader.capture("marker.json",partial=True).value=={"key":42}
    finally:reader.close()


def test_stream_overflow_keeps_the_full_original_bytes_and_stops_the_lane(tmp_path,controller,monkeypatch):
    _,validated,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    spawn=backend.spawn
    def overflow(admitted,invocation,stdout,stderr):
        process=spawn(admitted,invocation,stdout,stderr);os.ftruncate(stdout,67108865);return process
    backend.spawn=overflow
    result=engine.run()
    assert result["outcome"]!="PASS" and backend.spawns==["main"]
    assert result["attempts"][0]["streams"]["overflow"] is True
    assert (Path(validated.paths.controller_output)/"attempts/fixture-run.main/stdout.log").stat().st_size==67108865


@pytest.mark.parametrize("defect",["existing-output","output-link","existing-controller-cache"])
def test_owned_roots_and_stale_bytecode_refuse_before_spawn(tmp_path,controller,monkeypatch,defect):
    _,validated,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    if defect=="existing-controller-cache":
        path=Path(validated.paths.controller_pycache);path.mkdir(mode=0o700);path.chmod(0o700);(path/"stale.pyc").write_bytes(b"stale")
    elif defect=="existing-output":Path(validated.invocations[0].output_path).mkdir()
    else:Path(validated.invocations[0].output_path).symlink_to(validated.paths.farm)
    try:result=engine.run()
    except controller.ControllerError:
        assert defect=="existing-controller-cache"
    else:assert result["lease_disposition"]=="QUARANTINED" and result["attempts"][0]["cleanup"] is None
    assert not backend.spawns


def completed_bundle_fixture(tmp_path, controller, monkeypatch, *, defect=None):
    _, validated, backend, _, engine, _ = controller_engine_fixture(tmp_path, controller, monkeypatch, defect=defect)
    result = engine.run()
    consumed = controller.read_approved_document(Path(validated.paths.output_root)/engine.result_artifact.relative,
                                                 result_hash := engine.result_artifact.reference["sha256"])
    return validated, backend, engine, result, consumed, result_hash


def completed_observation(controller, validated, engine, result, result_hash):
    observation_type = getattr(controller, "DispatcherCompletionObservation", None)
    pin_type = getattr(controller, "BytePin", None)
    assert observation_type is not None and pin_type is not None, "completed execution provenance boundary is absent"
    from mojobpf.process_guardian import ProcessIdentity
    root = Path(validated.paths.output_root)
    return observation_type(run_id=validated.run_id, lane_id=validated.lane_id, lease_id=validated.lease_id,
        proposal_sha256=validated.proposal_sha256, approval_sha256=validated.approval_sha256,
        lease_sha256=validated.lease_sha256,
        controller_distribution_sha256=dict((n,b.file_sha256) for n,b,_ in validated.inputs)["controller_distribution"],
        controller_identity=ProcessIdentity(100,99,BOOT), normal_exit=True,
        exit_code=0 if result["outcome"]=="PASS" else 3, final_readback_acknowledged=True,
        result=pin_type(str(root/engine.result_artifact.relative), result_hash),
        journal=pin_type(str(root/result["journal"]["path"]), result["journal"]["sha256"]))


def bundle_api(controller, name):
    function = getattr(controller, name, None)
    assert callable(function), "fixed-byte controller bundle acceptance is absent"
    return function


def test_completed_bundle_integrity_does_not_grant_release(tmp_path, controller, monkeypatch):
    validated, _, engine, result, consumed, sha = completed_bundle_fixture(tmp_path,controller,monkeypatch)
    inspected = bundle_api(controller,"inspect_result_bundle")(validated,consumed)
    assert inspected["integrity"]=="VALID" and inspected["release_authority"] is False
    with pytest.raises(controller.ControllerError): bundle_api(controller,"validate_result_bundle")(validated,consumed)
    observed = completed_observation(controller,validated,engine,result,sha)
    accepted = bundle_api(controller,"validate_result_bundle")(validated,consumed,completed_controller=observed)
    assert accepted["release_eligible"] is True and accepted["assessment"]=="NOT_RUN"
    assert accepted["result"]==result


@pytest.mark.parametrize("field,value", [("normal_exit",False),("normal_exit",1),("exit_code",True),("exit_code",-9),
    ("exit_code",3),("final_readback_acknowledged",False),("final_readback_acknowledged",1),
    ("run_id","other"),("lane_id","other"),("lease_id","other"),("proposal_sha256",HASH),
    ("approval_sha256",HASH),("lease_sha256",HASH),("controller_distribution_sha256",HASH)])
def test_completed_observation_must_match_trusted_termination(tmp_path,controller,monkeypatch,field,value):
    validated,_,engine,result,consumed,sha=completed_bundle_fixture(tmp_path,controller,monkeypatch)
    observed=completed_observation(controller,validated,engine,result,sha)
    with pytest.raises(controller.ControllerError):
        bundle_api(controller,"validate_result_bundle")(validated,consumed,completed_controller=replace(observed,**{field:value}))


@pytest.mark.parametrize("defect", ["result-pin","journal-pin","controller-pid","controller-ticks","controller-boot","raw-observation"])
def test_completed_observation_requires_independent_byte_pins_and_identity(tmp_path,controller,monkeypatch,defect):
    validated,_,engine,result,consumed,sha=completed_bundle_fixture(tmp_path,controller,monkeypatch)
    observed=completed_observation(controller,validated,engine,result,sha)
    from mojobpf.process_guardian import ProcessIdentity
    if defect=="result-pin": observed=replace(observed,result=replace(observed.result,sha256=HASH))
    elif defect=="journal-pin": observed=replace(observed,journal=replace(observed.journal,sha256=HASH))
    elif defect=="controller-pid": observed=replace(observed,controller_identity=ProcessIdentity(101,99,BOOT))
    elif defect=="controller-ticks": observed=replace(observed,controller_identity=ProcessIdentity(100,100,BOOT))
    elif defect=="controller-boot": observed=replace(observed,controller_identity=ProcessIdentity(100,99,"abcdefab-1234-4567-9234-123456789abc"))
    else: observed=vars(observed)
    with pytest.raises(controller.ControllerError): bundle_api(controller,"validate_result_bundle")(validated,consumed,completed_controller=observed)


def test_clean_failed_lane_is_releasable_with_normal_exit_three(tmp_path,controller,monkeypatch):
    validated,_,engine,result,consumed,sha=completed_bundle_fixture(tmp_path,controller,monkeypatch,defect="ordinary-failure")
    observed=completed_observation(controller,validated,engine,result,sha)
    accepted=bundle_api(controller,"validate_result_bundle")(validated,consumed,completed_controller=observed)
    assert accepted["release_eligible"] is True and accepted["result"]["outcome"]=="INFRA_ERROR"
    assert accepted["result"]["projection"] is None
    with pytest.raises(controller.ControllerError):
        bundle_api(controller,"validate_result_bundle")(validated,consumed,completed_controller=replace(observed,exit_code=0))


@pytest.mark.parametrize("defect", ["raw-stat","raw-fdinfo","raw-mount","signed-wait","parent","retained-time",
    "qemu-role","cleanup-scans","attempt-id","invocation","binding","journal-context","journal-boolean-sequence",
    "commit-range","commit-reference","missing-terminal","terminal-attempts","prefix-suffix","prior-prefix-rewrite","receipt-swap"])
def test_fixed_byte_bundle_rejects_counterfeit_sidecar_or_binding(tmp_path,controller,monkeypatch,defect):
    validated,_,engine,result,_,_=completed_bundle_fixture(tmp_path,controller,monkeypatch)
    result=copy.deepcopy(result); root=Path(validated.paths.output_root); first=result["attempts"][0]
    # Re-pin all changed bytes deliberately: pins prove integrity, never semantic truth.
    def rewrite(reference, raw):
        path=root/reference["path"];path.write_bytes(raw);new=hashlib.sha256(raw).hexdigest()
        old=copy.deepcopy(reference)
        def replace_refs(value):
            if isinstance(value,dict):
                if value==old: value["sha256"]=new
                else:
                    for item in value.values():replace_refs(item)
            elif isinstance(value,list):
                for item in value:replace_refs(item)
        replace_refs(result)
    if defect in {"raw-stat","raw-fdinfo"}:rewrite(first["processes"][0]["raw_stat" if defect=="raw-stat" else "raw_fdinfo"][0],b"forged\n")
    elif defect=="raw-mount":rewrite(first["cleanup"]["mountinfo_after"],b"2 0 0:1 / / rw - tmpfs rootfs rw\n")
    elif defect=="signed-wait":first["processes"][0]["wait_status"]=-9
    elif defect=="parent":first["processes"][1]["parent"]=None
    elif defect=="retained-time":first["processes"][0]["time"]+=1
    elif defect=="qemu-role":first["processes"][1]["role"]="descendant"
    elif defect=="cleanup-scans":first["cleanup"]["scans"]+=1
    elif defect=="attempt-id":first["attempt_id"]="foreign"
    elif defect=="invocation":first["invocation"]["argv"][0]="/foreign"
    elif defect=="binding":result["bindings"]["approval"]["canonical_sha256"]=HASH
    elif defect=="prefix-suffix":rewrite(first["cleanup"]["completion_journal"],(root/first["cleanup"]["completion_journal"]["path"]).read_bytes()+b'{}\n')
    elif defect=="prior-prefix-rewrite":
        ref=result["attempts"][1]["cleanup"]["completion_journal"];raw=(root/ref["path"]).read_bytes()
        rewrite(ref,b" "+raw)
    elif defect=="receipt-swap":first["cleanup"]["completion_receipt"]=copy.deepcopy(result["attempts"][1]["cleanup"]["completion_receipt"])
    else:
        ref=result["journal"];events=[json.loads(line) for line in (root/ref["path"]).read_bytes().splitlines()]
        if defect=="journal-context":events[0]["lease_sha256"]=HASH
        elif defect=="journal-boolean-sequence":events[0]["sequence"]=True
        elif defect=="commit-range":next(e for e in events if e["event"]=="completion-committed")["data"]["epoch_first_sequence"]+=1
        elif defect=="commit-reference":next(e for e in events if e["event"]=="completion-committed")["data"]["completion_receipt"]=copy.deepcopy(result["attempts"][1]["cleanup"]["completion_receipt"])
        elif defect=="missing-terminal":events.pop()
        elif defect=="terminal-attempts":events[-1]["data"]["attempts"][0]["runner_exit"]=-9
        rewrite(ref,b"".join(json.dumps(e,sort_keys=True,separators=(",",":")).encode()+b"\n" for e in events))
    if defect in {"raw-stat","raw-fdinfo","raw-mount","signed-wait","parent","retained-time","qemu-role",
                  "cleanup-scans","attempt-id","invocation","binding","prefix-suffix","prior-prefix-rewrite","receipt-swap"}:
        ref=result["journal"];events=[json.loads(line) for line in (root/ref["path"]).read_bytes().splitlines()]
        # A counterfeit writer also updates its generated context commitments.
        # External authority and guardian physical records remain the oracle.
        for event in events:
            if event["event"]=="completion-committed":
                attempt=next(a for a in result["attempts"] if a["phase"]==event["phase"])
                for key in ("completion_journal","completion_receipt"):event["data"][key]=copy.deepcopy(attempt["cleanup"][key])
        events[-1]["data"]={key:copy.deepcopy(result[key]) for key in ("outcome","lease_disposition","attempts","projection")}
        events[-1]["data"]["artifacts"]=[copy.deepcopy(a) for a in result["artifacts"] if a!=ref]
        rewrite(ref,b"".join(json.dumps(e,sort_keys=True,separators=(",",":")).encode()+b"\n" for e in events))
    ref=write_document(root/engine.result_artifact.relative,result)
    consumed=controller.read_approved_document(Path(ref["path"]),ref["file_sha256"])
    with pytest.raises(controller.ControllerError):bundle_api(controller,"inspect_result_bundle")(validated,consumed)


def test_controller_owned_store_clears_inherited_directory_mode_bits(tmp_path,controller,monkeypatch):
    _,validated,budget,backend=lease_fixture(tmp_path,controller,monkeypatch)
    Path(validated.paths.output_root).chmod(0o2770)
    store=controller._OwnedStore(validated.paths.controller_output,output_root=validated.paths.output_root,budget=budget,_backend=backend)
    try:assert stat.S_IMODE(Path(validated.paths.controller_output).stat().st_mode)==0o700
    finally:store.close()


def test_all_frozen_guest_diagnostics_preserve_original_bytes(tmp_path,controller,monkeypatch):
    _,validated,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    spawn=backend.spawn;diagnostics={"guest-commands.json":b'[ {"argv":["observed"],"exit_code":0} ]\n',
        "observations.json":b'{ "observation": "original byte layout" }\n',
        "positive-harness.json":b'{"raw":"positive"}\n',"permission-negative-harness.json":b'{"raw":"negative"}\n'}
    def with_diagnostics(admitted,invocation,stdout,stderr):
        process=spawn(admitted,invocation,stdout,stderr)
        for name,raw in diagnostics.items():(Path(invocation.output_path)/name).write_bytes(raw)
        return process
    backend.spawn=with_diagnostics
    result=engine.run();root=Path(validated.paths.output_root)
    for attempt in result["attempts"]:
        rows={row["name"]:row["reference"] for row in attempt["guest_files"]}
        for name,raw in diagnostics.items():assert name in rows and (root/rows[name]["path"]).read_bytes()==raw
    consumed=controller.read_approved_document(root/engine.result_artifact.relative,engine.result_artifact.reference["sha256"])
    assert controller.inspect_result_bundle(validated,consumed)["integrity"]=="VALID"


@pytest.mark.parametrize("window",["before-spawn","after-retain","marker-read"])
def test_cancellation_at_each_attempt_boundary_stops_progress(tmp_path,controller,monkeypatch,window):
    _,_,backend,kernel,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    checkpoint=backend.checkpoint;fired=[False]
    def cancel(operation,path):
        checkpoint(operation,path)
        last=None
        if engine.barrier is not None and engine.barrier._transitions:
            last=json.loads(bytes(engine.barrier._transitions).splitlines()[-1])["event"]
        match=(window=="before-spawn" and operation=="after-readback" and path=="transitions.active.jsonl"
               and last=="spawn-intent")
        match=match or (window=="after-retain" and operation=="after-readback" and path=="transitions.active.jsonl"
                        and last=="runner-retained")
        match=match or (window=="marker-read" and operation=="after-guest-read" and path=="ready-to-interrupt.json")
        if match and not fired[0]:fired[0]=True;kernel.cancel_handler(2,None)
    backend.checkpoint=cancel
    result=engine.run()
    assert fired[0] and result["outcome"]!="PASS"
    assert backend.spawns==(["main","interrupted"] if window=="marker-read" else ["main"] if window=="after-retain" else [])
    assert result["attempts"][-1]["outcome"]=="NOT_RUN"
    assert not any(not p.exited for p in kernel.current.values())


def test_public_projection_is_integrity_only(tmp_path,controller,monkeypatch):
    validated,_,_,result,consumed,_=completed_bundle_fixture(tmp_path,controller,monkeypatch)
    reference=bundle_api(controller,"project_attempt")(validated,consumed,phase="fresh")
    assert reference==result["attempts"][2]["projection"]
    reference["sha256"]=HASH
    assert result["attempts"][2]["projection"]["sha256"]!=HASH


@pytest.mark.parametrize("version,outcome,exit_code",[(2,"PASS",0),(2,"INFRA_ERROR",3),(1,"PASS",3)])
def test_cli_executes_only_issued_v2_and_emits_ack_after_run(tmp_path,controller,monkeypatch,capsys,version,outcome,exit_code):
    fixture=(launch_fixture if version==1 else launch_v2_fixture)(tmp_path,controller,monkeypatch)
    calls=[];record=v2_sidecar_fixture();record["outcome"]=outcome
    def execute(validated,*,cancel_fd=None):
        assert validated.schema_version==2;calls.append(validated.run_id)
        return record
    monkeypatch.setattr(controller,"run_lane",execute)
    result=controller.main(["--proposal",fixture[3]["path"],"--approval",fixture[4]["path"],
        "--approval-sha256",fixture[4]["file_sha256"],"--lease",fixture[5]["path"],"--lease-sha256",fixture[5]["file_sha256"],"--lane","local-tcg"])
    captured=capsys.readouterr()
    assert result==exit_code
    if version==2:assert calls==["fixture-run"] and json.loads(captured.out)==record
    else:assert not calls and not captured.out and json.loads(captured.err)["code"]=="ADMISSION_REFUSED"


def test_failed_final_handle_release_never_returns_completed_ack(tmp_path,controller,monkeypatch):
    validated=None
    _,validated,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    close=backend.close; failed=[False];lease_fd=[None];checkpoint=backend.checkpoint
    def pin_release(operation,path):
        checkpoint(operation,path)
        if operation=="before-create" and path=="controller-result.json":lease_fd[0]=engine.lease.fd
    backend.checkpoint=pin_release
    def consumed_then_failure(fd):
        close(fd)
        if engine.result_artifact is not None and fd==lease_fd[0] and not failed[0]:
            failed[0]=True;raise OSError(errno.EIO,"last release acknowledgement failed")
    backend.close=consumed_then_failure
    with pytest.raises(controller.ControllerError):engine.run()
    assert failed[0] and engine.result_artifact is not None
    raw=engine.result_artifact.raw;result=json.loads(raw)
    assert result["lease_disposition"]=="RELEASABLE"
    consumed=controller.read_approved_document(Path(validated.paths.output_root)/engine.result_artifact.relative,engine.result_artifact.reference["sha256"])
    assert controller.inspect_result_bundle(validated,consumed)["integrity"]=="VALID"
    with pytest.raises(controller.ControllerError):controller.validate_result_bundle(validated,consumed)


def test_terminal_ack_returns_immutable_fixed_byte_readback(tmp_path,controller,monkeypatch):
    _,_,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    checkpoint=backend.checkpoint;changed=[False]
    def mutate(operation,path):
        checkpoint(operation,path)
        if operation=="before-create" and path=="controller-result.json":
            changed[0]=True;engine.attempts[0]["cleanup"]["scans"]+=100
    backend.checkpoint=mutate
    result=engine.run()
    assert changed[0] and result==json.loads(engine.result_artifact.raw)


def test_owned_cache_inventory_is_bounded(tmp_path,controller,monkeypatch):
    _,validated,budget,backend=lease_fixture(tmp_path,controller,monkeypatch)
    path=Path(validated.paths.controller_pycache);path.mkdir(mode=0o700);path.chmod(0o700)
    for name in ("one","two"):(path/name).touch()
    monkeypatch.setitem(controller._CLOSURE_COUNTS,"edges",1)
    directory=controller._OwnedDirectory(str(path),budget=budget,_backend=backend)
    try:
        with pytest.raises(controller.ControllerError):directory.empty_observation()
    finally:directory.close()


def test_uncertain_epoch_preserves_known_retained_process_observations(tmp_path,controller,monkeypatch):
    _,validated,backend,kernel,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    tasks=kernel.tasks;failed=[False]
    def refused(pid,maximum):
        if pid==1000 and not failed[0]:failed[0]=True;raise OSError(errno.EACCES,"owned task census unavailable")
        return tasks(pid,maximum)
    kernel.tasks=refused
    result=engine.run();attempt=result["attempts"][0]
    assert failed[0] and result["lease_disposition"]=="QUARANTINED" and backend.spawns==["main"]
    assert attempt["cleanup"]["status"]=="INCOMPLETE" and attempt["projection"] is None
    assert {p["identity"]["pid"] for p in attempt["processes"]}=={1000,1001}
    root=Path(validated.paths.output_root)
    for p in attempt["processes"]:
        for field in ("raw_stat","raw_fdinfo"):
            assert len(p[field])==2 and all((root/ref["path"]).is_file() for ref in p[field])


def test_final_fixed_byte_verification_precedes_terminal_sidecar(tmp_path,controller,monkeypatch):
    _,_,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    checkpoint=backend.checkpoint;changed=[False]
    def mutate(operation,path):
        checkpoint(operation,path)
        if operation=="after-readback" and path=="controller-journal.jsonl" and not changed[0]:
            changed[0]=True;engine.attempts[0]["cleanup"]["scans"]+=100
    backend.checkpoint=mutate
    with pytest.raises(controller.ControllerError):engine.run()
    assert changed[0] and engine.result_artifact is None
    assert not (Path(engine.v.paths.controller_output)/"controller-result.json").exists()


def test_pid_reuse_keeps_both_retained_identities_and_refuses_projection(tmp_path,controller,monkeypatch):
    _,validated,backend,kernel,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    changed=[False]
    def replace_descendant(seconds):
        kernel.clock+=seconds
        if not changed[0]:
            old=kernel.current[1001];kernel.exit(old);kernel.current.pop(1001)
            kernel.add(pid=1001,ticks=100199,ppid=1000,session=1000);changed[0]=True
    backend.pause=replace_descendant
    result=engine.run();attempt=result["attempts"][0]
    assert result["outcome"]!="PASS" and backend.spawns==["main"] and attempt["projection"] is None
    reused=[p for p in attempt["processes"] if p["identity"]["pid"]==1001]
    assert len(reused)==2 and {p["identity"]["start_ticks"] for p in reused}=={100001,100199}
    assert reused[0]["wait_status"] is None and attempt["cleanup"]["status"]=="CLEAN"
    root=Path(validated.paths.output_root)
    consumed=controller.read_approved_document(root/engine.result_artifact.relative,engine.result_artifact.reference["sha256"])
    assert controller.inspect_result_bundle(validated,consumed)["integrity"]=="VALID"


@pytest.mark.parametrize("field",["boot_id","session_id"])
def test_recovery_projection_refuses_reused_observed_guest_identity(tmp_path,controller,monkeypatch,field):
    _,_,_,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    engine.run();engine.attempts[2]["guest"][field]=engine.attempts[0]["guest"][field]
    with pytest.raises(controller.ControllerError) as error:engine._final_projection()
    assert error.value.code=="EVIDENCE_INVALID"


def test_wrong_guest_boot_identity_stops_before_recovery(tmp_path,controller,monkeypatch):
    _,_,backend,_,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    spawn=backend.spawn
    def foreign(admitted,invocation,stdout,stderr):
        process=spawn(admitted,invocation,stdout,stderr)
        path=Path(invocation.output_path)/"guest-identity.json"
        value=json.loads(path.read_bytes());value["boot_id"]="00000000-0000-0000-0000-000000000000";write_document(path,value)
        return process
    backend.spawn=foreign
    result=engine.run()
    assert result["outcome"]!="PASS" and backend.spawns==["main"]
    assert result["attempts"][0]["guest"] is None and all(not a["started"] for a in result["attempts"][1:])


@pytest.mark.parametrize("root",["output_root","tmp_root"])
def test_raw_mount_comparison_decodes_owned_path_escapes(tmp_path,controller,monkeypatch,root):
    _,validated,backend,kernel,engine,_=controller_engine_fixture(tmp_path,controller,monkeypatch)
    owned=getattr(validated.paths,root)+"/owned path"
    text="1 0 0:1 / "+owned.replace(" ","\\040")+" rw - tmpfs owned rw\n"
    kernel.read_mountinfo=lambda:text
    result=engine.run()
    assert result["outcome"]!="PASS" and result["lease_disposition"]=="QUARANTINED" and backend.spawns==["main"]


@pytest.mark.parametrize("defect",["late-terminal","missing-spawn-intent","missing-runner-retained","cache-replaced"])
def test_controller_completion_requires_full_causal_chronology(tmp_path,controller,monkeypatch,defect):
    validated,_,engine,result,_,_=completed_bundle_fixture(tmp_path,controller,monkeypatch)
    root=Path(validated.paths.output_root);ref=result["journal"]
    events=[json.loads(line) for line in (root/ref["path"]).read_bytes().splitlines()]
    if defect=="late-terminal":
        receipt=json.loads((root/result["attempts"][2]["cleanup"]["completion_receipt"]["path"]).read_bytes())
        events[-1]["time"]=receipt["deadline"]
    elif defect in {"missing-spawn-intent","missing-runner-retained"}:
        name="spawn-intent" if defect=="missing-spawn-intent" else "runner-retained"
        events.remove(next(e for e in events if e["event"]==name))
        for index,event in enumerate(events,1):event["sequence"]=index
    else:next(e for e in events if e["event"]=="cache-after")["data"]["ino"]+=1
    raw=b"".join(json.dumps(e,sort_keys=True,separators=(",",":")).encode()+b"\n" for e in events)
    (root/ref["path"]).write_bytes(raw);old=copy.deepcopy(ref);ref["sha256"]=hashlib.sha256(raw).hexdigest()
    next(a for a in result["artifacts"] if a==old)["sha256"]=ref["sha256"]
    record=write_document(root/engine.result_artifact.relative,result)
    consumed=controller.read_approved_document(Path(record["path"]),record["file_sha256"])
    with pytest.raises(controller.ControllerError):controller.inspect_result_bundle(validated,consumed)


@pytest.mark.parametrize("boundary,observed,want", [
    ("startup-read", 299.999, "PASS"),
    ("startup-read", 300.0, "STARTUP_TIMEOUT"),
    ("startup-read", 300.001, "STARTUP_TIMEOUT"),
    ("terminal-owned", 899.999, "PASS"),
    ("terminal-owned", 900.0, "ATTEMPT_TIMEOUT"),
    ("terminal-owned", 900.001, "ATTEMPT_TIMEOUT"),
    ("terminal-wait", 899.999, "PASS"),
    ("terminal-wait", 900.0, "ATTEMPT_TIMEOUT"),
    ("terminal-wait", 900.001, "ATTEMPT_TIMEOUT"),
])
def test_fallible_observation_keeps_original_phase_deadline(tmp_path, controller, monkeypatch, boundary, observed, want):
    _, validated, backend, kernel, engine, _ = controller_engine_fixture(tmp_path, controller, monkeypatch)
    fired = []
    if boundary == "startup-read":
        checkpoint = backend.checkpoint
        def delayed_target(operation, path):
            checkpoint(operation, path)
            if not fired and backend.spawns == ["main"] and operation == "after-guest-read" and path == "target.json":
                fired.append(kernel.clock)
                kernel.clock = observed
        backend.checkpoint = delayed_target
    elif boundary == "terminal-owned":
        pause, read_children = backend.pause, kernel.read_children
        def near_terminal(seconds):
            pause(seconds)
            if backend.spawns == ["main"]: kernel.clock = 899.0
        def delayed_owned(pid, tid):
            if not fired and backend.spawns == ["main"] and kernel.clock == 899.0:
                fired.append(kernel.clock)
                kernel.clock = observed
            return read_children(pid, tid)
        backend.pause, kernel.read_children = near_terminal, delayed_owned
    else:
        guardian = backend.guardian
        def delayed_guardian(*, limits, journal):
            guard = guardian(limits=limits, journal=journal)
            runner_exit = guard.runner_exit
            def delayed_wait():
                signed = runner_exit()
                if not fired and backend.spawns == ["main"] and signed is not None:
                    fired.append(kernel.clock)
                    kernel.clock = observed
                return signed
            guard.runner_exit = delayed_wait
            return guard
        backend.guardian = delayed_guardian
    result = engine.run()
    (tmp_path / "boundary-observation.json").write_text(json.dumps({"boundary": boundary, "observed": observed,
        "want": want, "result": result, "spawns": backend.spawns}, indent=2) + "\n")
    assert fired
    main = result["attempts"][0]
    assert main["cleanup"]["status"] == "CLEAN"
    root = Path(validated.paths.output_root)
    prefix = (root / main["cleanup"]["completion_journal"]["path"]).read_bytes()
    receipt = json.loads((root / main["cleanup"]["completion_receipt"]["path"]).read_bytes())
    entered = next(json.loads(line) for line in prefix.splitlines() if json.loads(line)["event"] == "cleanup-entered")
    assert entered["deadline"] == entered["time"] + 30.0 == receipt["deadline"]
    assert receipt["acknowledged_at"] < receipt["deadline"]
    if want == "PASS":
        assert result["outcome"] == "PASS" and main["failure"] is None
        assert backend.spawns == ["main", "interrupted", "fresh"]
    else:
        assert result["outcome"] == "INFRA_ERROR" and result["failure"]["code"] == want
        assert main["failure"]["code"] == want and main["projection"] is None
        assert backend.spawns == ["main"] and [a["outcome"] for a in result["attempts"][1:]] == ["NOT_RUN", "NOT_RUN"]
        assert result["projection"] is None and result["lease_disposition"] == "RELEASABLE"
    assert not any(not process.exited for process in kernel.current.values())


def terminal_cancellation_fixture(tmp_path, controller, monkeypatch, window, *, phase="fresh"):
    _, validated, backend, kernel, engine, _ = controller_engine_fixture(tmp_path, controller, monkeypatch)
    read_fd, write_fd = os.pipe()
    engine.cancel_fd = read_fd
    phases = ["main", "interrupted", "fresh"][:("main", "interrupted", "fresh").index(phase) + 1]
    fired = []
    def cancel():
        fired.append(kernel.clock)
        if window in {"terminal-owned", "cleanup-provisional"}: kernel.cancel_handler(2, None)
        else: os.write(write_fd, b"c")
    if window == "terminal-owned":
        read_children = kernel.read_children
        def cancelled_observation(pid, tid):
            if not fired and backend.spawns == phases and backend.pending is None: cancel()
            return read_children(pid, tid)
        kernel.read_children = cancelled_observation
    elif window == "cleanup-provisional":
        guardian = backend.guardian
        def cancelling_guardian(*, limits, journal):
            def recorded(value):
                journal(value)
                if not fired and backend.spawns == phases and value["event"] == "cleanup-provisional": cancel()
            return guardian(limits=limits, journal=recorded)
        backend.guardian = cancelling_guardian
    elif window == "final-close":
        close = backend.close
        def cancelled_close(fd):
            close(fd)
            if not fired and backend.spawns == phases and engine.result_artifact is not None: cancel()
        backend.close = cancelled_close
    else:
        checkpoint = backend.checkpoint
        def cancelled_readback(operation, path):
            checkpoint(operation, path)
            if fired or backend.spawns != phases or operation != "after-readback": return
            last = json.loads(bytes(engine.barrier._transitions).splitlines()[-1])
            match = window == "receipt-readback" and path.endswith("guardian-receipt.json")
            match = match or (window in {"cache-after", "attempt-terminal", "lane-terminal"}
                             and path == "transitions.active.jsonl" and last["event"] == window)
            match = match or (window == "recovery-readback" and path == "recovery.json")
            match = match or (window == "result-readback" and path == "controller-result.json")
            if match: cancel()
        backend.checkpoint = cancelled_readback
    return validated, backend, kernel, engine, fired, (read_fd, write_fd)


@pytest.mark.parametrize("window", ["terminal-owned", "cleanup-provisional", "receipt-readback", "cache-after"])
def test_fresh_terminal_cancellation_is_clean_non_success(tmp_path, controller, monkeypatch, window):
    validated, backend, kernel, engine, fired, descriptors = terminal_cancellation_fixture(tmp_path, controller, monkeypatch, window)
    try: result = engine.run()
    finally:
        for fd in descriptors: os.close(fd)
    (tmp_path / "cancellation-observation.json").write_text(json.dumps({"window": window, "fired": fired, "result": result}, indent=2) + "\n")
    assert fired and backend.spawns == ["main", "interrupted", "fresh"]
    fresh = result["attempts"][2]
    assert result["outcome"] == "INFRA_ERROR" and result["failure"]["code"] == "CANCELLED"
    assert fresh["failure"]["code"] == "CANCELLED" and fresh["cleanup"]["status"] == "CLEAN"
    assert fresh["projection"] is None and result["projection"] is None
    assert result["lease_disposition"] == "RELEASABLE"
    assert not any(not process.exited for process in kernel.current.values())
    root = Path(validated.paths.output_root)
    sha = engine.result_artifact.reference["sha256"]
    pinned = controller.read_approved_document(root / engine.result_artifact.relative, sha)
    assert controller.inspect_result_bundle(validated, pinned)["release_authority"] is False
    observed = completed_observation(controller, validated, engine, result, sha)
    assert observed.exit_code == 3
    accepted = controller.validate_result_bundle(validated, pinned, completed_controller=observed)
    assert accepted["release_eligible"] is True and accepted["assessment"] == "NOT_RUN"
    with pytest.raises(controller.ControllerError):
        controller.validate_result_bundle(validated, pinned, completed_controller=replace(observed, exit_code=0))
    with pytest.raises(controller.ControllerError): controller.project_attempt(validated, pinned, phase="fresh")


def test_external_cancel_during_interrupted_cleanup_stops_recovery(tmp_path, controller, monkeypatch):
    _, backend, kernel, engine, fired, descriptors = terminal_cancellation_fixture(tmp_path, controller, monkeypatch, "cleanup-provisional", phase="interrupted")
    try: result = engine.run()
    finally:
        for fd in descriptors: os.close(fd)
    assert fired and result["outcome"] == "INFRA_ERROR" and result["failure"]["code"] == "CANCELLED"
    assert backend.spawns == ["main", "interrupted"]
    assert result["attempts"][1]["cleanup"]["status"] == "CLEAN" and result["attempts"][1]["projection"] is None
    assert result["attempts"][2]["outcome"] == "NOT_RUN"
    assert not any(not process.exited for process in kernel.current.values())


@pytest.mark.parametrize("window", ["attempt-terminal", "recovery-readback", "lane-terminal", "result-readback", "final-close"])
def test_cancellation_after_semantic_seal_refuses_completion_ack(tmp_path, controller, monkeypatch, window):
    validated, backend, kernel, engine, fired, descriptors = terminal_cancellation_fixture(tmp_path, controller, monkeypatch, window)
    try:
        with pytest.raises(controller.ControllerError) as failure: engine.run()
        assert failure.value.code == "CANCELLED"
    finally:
        for fd in descriptors: os.close(fd)
    assert fired and backend.spawns == ["main", "interrupted", "fresh"]
    assert not any(not process.exited for process in kernel.current.values())
    # A later cancellation cannot rewrite previously sealed immutable bytes.
    # Even a visible candidate sidecar has no completed-dispatcher acknowledgement.
    if engine.result_artifact is not None:
        root = Path(validated.paths.output_root)
        sha = engine.result_artifact.reference["sha256"]
        pinned = controller.read_approved_document(root / engine.result_artifact.relative, sha)
        visible = json.loads(pinned.consumed.raw)
        observation = completed_observation(controller, validated, engine, visible, sha)
        with pytest.raises(controller.ControllerError):
            controller.validate_result_bundle(validated, pinned, completed_controller=replace(
                observation, exit_code=3, final_readback_acknowledged=False))


def test_fixed_byte_inspector_refuses_retained_cancelled_pass(tmp_path, controller, monkeypatch):
    validated, _, _, engine, fired, descriptors = terminal_cancellation_fixture(tmp_path, controller, monkeypatch, "terminal-owned")
    inspect_record = controller._inspect_result_record
    captured = []
    def retain_candidate(v, result, **options):
        captured.append(copy.deepcopy(result))
        return inspect_record(v, result, **options)
    # Withhold the producer's cancellation observation to exercise a dishonest
    # PASS claim independently of its normal outcome guard. The real guardian
    # still receives cancellation and writes its immutable observed prefix.
    monkeypatch.setattr(engine, "_cancelled", lambda: False)
    monkeypatch.setattr(controller, "_inspect_result_record", retain_candidate)
    try:
        try: engine.run()
        except controller.ControllerError as failure: assert failure.code == "EVIDENCE_INVALID"
    finally:
        for fd in descriptors: os.close(fd)
    monkeypatch.setattr(controller, "_inspect_result_record", inspect_record)
    assert fired and captured
    candidate = captured[-1]
    assert candidate["outcome"] == "PASS" and candidate["attempts"][2]["projection"] is not None
    root = Path(validated.paths.output_root)
    fresh = candidate["attempts"][2]
    records = [json.loads(line) for line in (root / fresh["cleanup"]["completion_journal"]["path"]).read_bytes().splitlines()]
    entered = [record for record in records if record["event"] == "cleanup-entered"][-1]
    assert entered["cancelled"] is True and entered["cancellation_signal"] == 2
    destination = Path(validated.paths.controller_output) / "controller-result.json"
    reference = write_document(destination, candidate); destination.chmod(0o600)
    pinned = controller.read_approved_document(destination, reference["file_sha256"])
    with pytest.raises(controller.ControllerError) as failure: controller.inspect_result_bundle(validated, pinned)
    assert failure.value.code == "EVIDENCE_INVALID"


def test_expected_interruption_is_not_retained_external_cancellation(tmp_path, controller, monkeypatch):
    validated, _, _, result, pinned, _ = completed_bundle_fixture(tmp_path, controller, monkeypatch)
    root = Path(validated.paths.output_root)
    interrupted = result["attempts"][1]
    records = [json.loads(line) for line in (root / interrupted["cleanup"]["completion_journal"]["path"]).read_bytes().splitlines()]
    entered = [record for record in records if record["event"] == "cleanup-entered"][-1]
    assert entered["interrupt"] is True and entered["cancelled"] is False and entered["cancellation_signal"] is None
    assert interrupted["runner_exit"] == -9 and interrupted["failure"]["code"] == "CANCELLED"
    assert controller.inspect_result_bundle(validated, pinned)["result"]["outcome"] == "PASS"
