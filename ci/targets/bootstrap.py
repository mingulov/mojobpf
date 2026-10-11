# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Assess captured disposable-target bootstrap evidence without running a VM.

The controller independently pins the provisional manifest and grants its
exclusive lease before execution. This assessor consumes one terminal attempt,
the stock-C test-run records and cleanup/recovery records from an owned bundle.
It never provisions a target, executes commands or grants a lease. A READY
record establishes the captured environment/control boundary; subsequent
product qualification uses its own contracts. A READY target must be consumable
by the frozen target-manifest API, including known kernel source provenance.

Usage: python3 ci/targets/bootstrap.py --provisional provisional.json
    --provisional-sha256 CONTROLLER_PIN --attempt attempt.json
    --evidence-root BUNDLE --output target-ready.json

Evidence record digests bind the bytes consumed, including interrupted and
recovered attempts. Authentic recording and lease authority remain the caller's
responsibility; hashes and internal consistency do not authenticate a VM.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from mojobpf.validation.models import ContractError, TargetManifest, digest_of, json_equal  # noqa: E402

_control_spec = importlib.util.spec_from_file_location("bootstrap_control_contract", ROOT / "tests/harness/bpf_test_run.py")
control_contract = importlib.util.module_from_spec(_control_spec)
_control_spec.loader.exec_module(control_contract)

HASH = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
TEXT_INPUTS = {
    "kernel_release", "kernel_build_id", "bpftool_version", "execution_mode",
    "architecture", "byte_order", "instruction_profile",
}
HASH_INPUTS = {
    "kernel_config_sha256", "kernel_image_sha256", "kernel_packages_sha256",
    "vmlinux_btf_sha256",
    "rootfs_sha256", "payload_sha256", "observer_sha256", "compiler_sha256",
    "runner_admission_sha256", "launcher_admission_sha256", "qemu_admission_sha256",
    "control_source_sha256", "control_object_sha256", "packet_sha256",
    "bpftool_sha256", "python_sha256", "libbpf_sha256", "recovery_plan_sha256",
}
BINDING_KEYS = {"attempt_id", "guest_id", "boot_id"}
ATTEMPT_NAMES = {"target", "execution", "positive", "permission_negative",
                 "permission_context", "pin_root_absence", "cleanup"}
EVIDENCE_NAMES = ATTEMPT_NAMES | {"recovery"}
CAPABILITIES = {"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"}


class Unready(Exception):
    def __init__(self, code, detail, stage="INFRA", outcome="INFRA_ERROR"):
        super().__init__(detail)
        self.code, self.detail, self.stage, self.outcome = code, detail, stage, outcome


def require(condition, code, detail, stage="INFRA", outcome="INFRA_ERROR"):
    if not condition:
        raise Unready(code, detail, stage, outcome)


def mapping(value, keys, code="EVIDENCE_INVALID"):
    require(type(value) is dict and set(value) == set(keys), code,
            "record has missing or unknown fields")
    return value


def valid_hash(value):
    return type(value) is str and HASH.fullmatch(value) is not None and value != "0" * 64


def text(value):
    return type(value) is str and bool(value.strip()) and value.lower() not in {"unknown", "missing"}


def integer(value):
    return type(value) is int


def source_commit(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) and value != "0" * 40


def load_json(raw):
    def invalid_constant(value):
        raise ValueError("non-JSON constant " + value)
    return json.loads(raw, parse_constant=invalid_constant)


def read_evidence(root, reference):
    """Hash and parse the same captured bytes; references stay inside the bundle."""
    mapping(reference, {"path", "sha256"})
    name = reference["path"]
    require(type(name) is str and name and not Path(name).is_absolute()
            and ".." not in Path(name).parts and valid_hash(reference["sha256"]),
            "EVIDENCE_INVALID", "invalid evidence reference")
    base = Path(root).resolve(strict=True)
    path = base / name
    require(not path.is_symlink() and path.resolve(strict=True).is_relative_to(base),
            "EVIDENCE_INVALID", "evidence escapes the owned bundle")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == reference["sha256"],
            "EVIDENCE_INVALID", "consumed evidence digest differs")
    record = load_json(raw)
    require(type(record) is dict, "EVIDENCE_INVALID", "evidence must be a JSON object")
    return record


def check_binding(record, binding, code):
    require(all(json_equal(record.get(key), binding[key]) for key in BINDING_KEYS),
            code, "observation belongs to another guest attempt")


def check_process(record, code):
    mapping(record, {"pid", "start_ticks"}, code)
    require(all(integer(record[key]) and record[key] > 0 for key in record),
            code, "invalid captured process identity")
    return record["pid"], record["start_ticks"]


def check_execution(record, provisional, expected, lease, phase, target):
    mapping(record, {"run_id", "attempt_id", "lane_id", "lease_id", "provisional_sha256",
                     "phase", "terminal", "exit_code", "outcome", "inputs",
                     "host_write_paths", "guest", "target_fingerprint"})
    require(record["terminal"] is True and record["outcome"] != "NOT_RUN",
            "RUN_NONTERMINAL", "required bootstrap run is incomplete", outcome="NOT_RUN")
    wanted_exit = integer(record["exit_code"]) and (record["exit_code"] < 0 if phase == "interrupted" else record["exit_code"] == 0)
    require(record["outcome"] == ("INFRA_ERROR" if phase == "interrupted" else "PASS")
            and wanted_exit, "RUN_FAILED", "bootstrap command failed or was not interrupted")
    attempt_id = provisional["run_id"] + "." + phase
    require(record["run_id"] == provisional["run_id"] and record["attempt_id"] == attempt_id
            and record["lane_id"] == provisional["lane_id"] and record["lease_id"] == lease["id"]
            and record["provisional_sha256"] == digest_of(provisional) and record["phase"] == phase
            and json_equal(record["inputs"], expected)
            and record["target_fingerprint"] == target["fingerprint"],
            "IDENTITY_MISMATCH", "consumed execution/target identity differs")
    require(json_equal(record["host_write_paths"], lease["host_write_paths"]),
            "LEASE_REQUIRED", "attempt write scope differs from the lease")
    guest = mapping(record["guest"], {"id", "boot_id", "session_id", "processes"})
    require(guest["id"] == attempt_id and type(guest["boot_id"]) is str
            and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", guest["boot_id"])
            and guest["boot_id"] != "00000000-0000-0000-0000-000000000000"
            and integer(guest["session_id"]) and guest["session_id"] > 0
            and "virtme_hostname=" + guest["id"] in target["boot"]["parameters"],
            "IDENTITY_MISMATCH", "guest boot/session identity is absent or foreign")
    require(type(guest["processes"]) is list and len(guest["processes"]) >= 2,
            "IDENTITY_MISMATCH", "runner and QEMU process identities are required")
    identities, roles = set(), set()
    for process in guest["processes"]:
        mapping(process, {"pid", "start_ticks", "role"})
        identity = check_process({key: process[key] for key in ("pid", "start_ticks")}, "IDENTITY_MISMATCH")
        require(identity not in identities and process["role"] in {"runner", "qemu", "descendant"}
                and (process["role"] == "descendant" or process["role"] not in roles)
                and (process["role"] != "runner" or process["pid"] == guest["session_id"]),
                "IDENTITY_MISMATCH", "captured processes are reused or not in the owned session")
        identities.add(identity)
        roles.add(process["role"])
    require({"runner", "qemu"}.issubset(roles)
            and len({p["pid"] for p in guest["processes"]}) == len(guest["processes"]),
            "IDENTITY_MISMATCH", "captured runner, QEMU and descendants must be distinct processes")
    return {"attempt_id": attempt_id, "guest_id": guest["id"], "boot_id": guest["boot_id"]}


def check_permission(record, binding, lease):
    code = "NEGATIVE_FAILED"
    mapping(record, BINDING_KEYS | {"process", "uid", "gid", "groups", "no_new_privs", "capabilities",
                                  "proc_status", "proc_stat", "pin_parent", "pin_parent_writable", "object_readable"}, code)
    check_binding(record, binding, code)
    pid, ticks = check_process(record["process"], code)
    require(integer(record["uid"]) and record["uid"] == 1001
            and integer(record["gid"]) and record["gid"] == 1001
            and type(record["groups"]) is list and record["groups"] == []
            and integer(record["no_new_privs"]) and record["no_new_privs"] == 1
            and record["capabilities"] == {name: "0000000000000000" for name in CAPABILITIES}
            and record["pin_parent"] == lease["guest_pin_root"] + "/" + binding["attempt_id"]
            and record["pin_parent_writable"] is True and record["object_readable"] is True,
            code, "negative context retains privilege or cannot access the owned control path", "LOAD", "FAIL")
    require(type(record["proc_status"]) is str and type(record["proc_stat"]) is str,
            code, "raw negative process observations are absent", "LOAD", "FAIL")
    fields = {}
    for line in record["proc_status"].splitlines():
        key, separator, value = line.partition(":")
        if key in CAPABILITIES | {"Pid", "Uid", "Gid", "Groups", "NoNewPrivs"}:
            require(separator and key not in fields, code, "ambiguous raw process status", "LOAD", "FAIL")
            fields[key] = value.split()
    wanted = {"Pid": [str(pid)], "Uid": ["1001"] * 4, "Gid": ["1001"] * 4,
              "Groups": [], "NoNewPrivs": ["1"], **{name: ["0000000000000000"] for name in CAPABILITIES}}
    require(fields == wanted, code, "raw privilege status contradicts the negative context", "LOAD", "FAIL")
    stat = record["proc_stat"]
    tail = stat.rsplit(")", 1)[-1].split()
    require(stat.split(" ", 1)[0] == str(pid) and len(tail) >= 20 and tail[19] == str(ticks),
            code, "raw start time contradicts the control process", "LOAD", "FAIL")


def check_absence(record, binding, lease):
    mapping(record, BINDING_KEYS | {"pin_root", "exists", "entries"}, "CLEANUP_INCOMPLETE")
    check_binding(record, binding, "CLEANUP_INCOMPLETE")
    require(record["pin_root"] == lease["guest_pin_root"] and record["exists"] is False
            and type(record["entries"]) is list and not record["entries"],
            "CLEANUP_INCOMPLETE", "fresh guest did not observe an absent pin root", "CLEANUP")


def check_cleanup(record, binding, lease, execution, phase):
    code = "CLEANUP_INCOMPLETE"
    mapping(record, BINDING_KEYS | {"status", "owned_processes", "owned_mounts", "owned_pins",
                                  "process_observations", "mount_observations", "pin_observation", "guest_unmount"}, code)
    check_binding(record, binding, code)
    require(record["status"] == "CLEAN" and all(type(record[name]) is list and not record[name]
            for name in ("owned_processes", "owned_mounts", "owned_pins")),
            code, "owned resources remain or were not checked", "CLEANUP")
    observations = record["process_observations"]
    require(type(observations) is list and len(observations) == len(execution["guest"]["processes"]),
            code, "cleanup lacks each captured host process observation", "CLEANUP")
    actual = set()
    for observation in observations:
        mapping(observation, {"pid", "start_ticks", "alive"}, code)
        identity = check_process({key: observation[key] for key in ("pid", "start_ticks")}, code)
        require(observation["alive"] is False and identity not in actual,
                code, "owned process remains or its observation is reused", "CLEANUP")
        actual.add(identity)
    require(actual == {(p["pid"], p["start_ticks"]) for p in execution["guest"]["processes"]},
            code, "cleanup observed another process", "CLEANUP")
    mounts = mapping(record["mount_observations"], {"before", "after"}, code)
    require(text(mounts["before"]) and mounts["before"] == mounts["after"]
            and not any(path in mounts["after"] for path in lease["host_write_paths"]),
            code, "host mount observations are absent or differ after cleanup", "CLEANUP")
    if phase == "interrupted":
        require(record["guest_unmount"] is None, code, "interrupted kernel cleanup cannot claim a guest unmount", "CLEANUP")
    else:
        unmount = mapping(record["guest_unmount"], {"argv", "exit_code", "timeout", "stdout", "stderr"}, code)
        require(unmount["argv"] == ["/usr/bin/umount", "/sys/fs/bpf"]
                and integer(unmount["exit_code"]) and unmount["exit_code"] == 0
                and unmount["timeout"] is False and type(unmount["stdout"]) is str and type(unmount["stderr"]) is str,
                code, "guest unmount did not complete successfully", "CLEANUP")
    pins = mapping(record["pin_observation"], {"root", "root_exists", "entries", "basis"}, code)
    require(pins["root"] == lease["guest_pin_root"] and pins["root_exists"] is False
            and type(pins["entries"]) is list and not pins["entries"]
            and pins["basis"] == ("guest-destroyed" if phase == "interrupted" else "guest-unmounted"),
            code, "owned guest pins were not observed removed", "CLEANUP")


def check_target(target, expected, lease):
    require(type(target) is dict and type(target.get("btf")) is dict
            and valid_hash(target["btf"].get("vmlinux_sha256")),
            "BTF_UNAVAILABLE", "guest vmlinux BTF identity is absent")
    mapping(target, {"schema_version", "fingerprint", "kernel", "btf", "image", "cpu",
                     "execution_mode", "byte_order", "instruction_profile", "jit", "boot",
                     "privileges", "mounts", "build_host"})
    require(type(target["schema_version"]) is int and target["schema_version"] == 1
            and valid_hash(target["fingerprint"])
            and target["fingerprint"] == digest_of({k: v for k, v in target.items() if k != "fingerprint"}),
            "EVIDENCE_INVALID", "target fingerprint/version differs")
    mapping(target["kernel"], {"source_commit", "release", "build_id", "config_sha256"})
    source = target["kernel"]["source_commit"]
    require(source_commit(source), "EVIDENCE_INVALID", "invalid source provenance")
    comparisons = (
        (source, expected["kernel_source_commit"]),
        (target["kernel"]["release"], expected["kernel_release"]),
        (target["kernel"]["build_id"], expected["kernel_build_id"]),
        (target["kernel"]["config_sha256"], expected["kernel_config_sha256"]),
        (target["btf"]["vmlinux_sha256"], expected["vmlinux_btf_sha256"]),
        (target["image"].get("digest"), expected["rootfs_sha256"]),
        (target["cpu"].get("architecture"), expected["architecture"]),
        (target["execution_mode"], expected["execution_mode"]),
        (target["byte_order"], expected["byte_order"]),
        (target["instruction_profile"], expected["instruction_profile"]),
        (target["mounts"].get("bpffs"), lease["guest_pin_root"]),
        (target["build_host"].get("identity"), expected["compiler_sha256"]),
    )
    require(all(json_equal(actual, wanted) for actual, wanted in comparisons),
            "IDENTITY_MISMATCH", "expected and observed target identities differ")
    mapping(target["image"], {"digest", "packages"})
    require(type(target["image"]["packages"]) is dict and target["image"]["packages"]
            and all(text(k) and text(v) for k, v in target["image"]["packages"].items()),
            "IDENTITY_UNKNOWN", "guest package identities are incomplete")
    mapping(target["cpu"], {"architecture", "model", "features", "page_size", "cpus"})
    require(text(target["cpu"]["model"]) and type(target["cpu"]["features"]) is list
            and all(text(f) for f in target["cpu"]["features"])
            and all(integer(target["cpu"][k]) and target["cpu"][k] > 0 for k in ("page_size", "cpus")),
            "IDENTITY_UNKNOWN", "guest CPU identity is incomplete")
    mapping(target["jit"], {"state", "hardening"})
    require(target["jit"]["state"] in {"enabled", "disabled"}
            and type(target["jit"]["hardening"]) is list
            and all(text(v) for v in target["jit"]["hardening"]),
            "IDENTITY_UNKNOWN", "effective JIT state is unknown")
    for name, keys, lists, objects in (
        ("boot", {"parameters", "lsms", "lockdown"}, {"parameters", "lsms"}, set()),
        ("privileges", {"capabilities", "token", "delegation", "rlimits"}, {"capabilities"}, {"rlimits"}),
        ("mounts", {"tracefs", "bpffs", "cgroup", "namespaces"}, {"namespaces"}, set()),
        ("build_host", {"identity", "flags"}, {"flags"}, set()),
    ):
        mapping(target[name], keys)
        for key in keys:
            value = target[name][key]
            if key in lists:
                valid = type(value) is list and all(text(v) for v in value)
            elif key in objects:
                valid = type(value) is dict and all(text(k) and text(v) for k, v in value.items())
            else:
                valid = text(value)
            require(valid, "IDENTITY_UNKNOWN", "target field %s.%s is unknown" % (name, key))
    mapping(target["btf"], {"vmlinux_sha256", "modules"})
    require(type(target["btf"]["modules"]) is list and all(
        type(m) is dict and set(m) == {"name", "sha256"} and text(m["name"]) and valid_hash(m["sha256"])
        for m in target["btf"]["modules"]), "EVIDENCE_INVALID", "invalid module BTF identity")
    try:
        TargetManifest.from_dict(target)
    except ContractError as exc:
        raise Unready("EVIDENCE_INVALID", "frozen target contract refused: %s" % exc) from exc


def check_control(record, expected, lease, binding, negative=False, context=None, context_sha256=None):
    code = "NEGATIVE_FAILED" if negative else "CONTROL_FAILED"
    stage = "LOAD" if negative else "TEST_RUN"
    mapping(record, BINDING_KEYS | {"exit_code", "result", "process", "context_sha256"}, code)
    check_binding(record, binding, code)
    if negative:
        require(json_equal(record["process"], context["process"]) and record["context_sha256"] == context_sha256,
                code, "permission context is not from the captured control process", stage, "FAIL")
    else:
        require(record["process"] is None and record["context_sha256"] is None,
                code, "positive carries an unexpected negative context", stage, "FAIL")
    result = record["result"]
    require(type(result) is dict and integer(record["exit_code"])
            and record["exit_code"] == (3 if negative else 0), code,
            "required stock-C command did not reach its expected exit", stage, "FAIL")
    require(result.get("tool") == "bpf_test_run" and type(result.get("contract_version")) is int
            and result["contract_version"] == 2 and type(result.get("repeat")) is int
            and result["repeat"] == 1 and type(result.get("expected_action")) is int
            and result["expected_action"] == 2, code, "wrong stock-C control contract", stage, "FAIL")
    if negative:
        wanted = {"status": "fail", "stage": "load", "classification": "environment",
                  "actual_action": None, "cleanup_ok": None}
    else:
        wanted = {"status": "pass", "stage": "run", "classification": None,
                  "actual_action": 2, "cleanup_ok": True}
    require(all(json_equal(result.get(k), v) for k, v in wanted.items()),
            code, "stock-C result differs from the independent oracle", stage, "FAIL")
    runtime = result.get("runtime", {})
    require(type(runtime) is dict and integer(runtime.get("uid"))
            and (runtime["uid"] == context["uid"] if negative else runtime["uid"] == 0)
            and runtime.get("kernel_release") == expected["kernel_release"],
            code, "wrong control guest identity", stage, "FAIL")
    obj, packet, tool = result.get("object", {}), result.get("data_in", {}), result.get("bpftool", {})
    require(all(type(v) is dict for v in (obj, packet, tool))
            and obj.get("sha256") == expected["control_object_sha256"]
            and packet.get("sha256") == expected["packet_sha256"]
            and integer(packet.get("size")) and packet["size"] == 60
            and tool.get("entry_sha256") == expected["bpftool_sha256"]
            and tool.get("version") == expected["bpftool_version"]
            and tool.get("exec_path") is None and tool.get("exec_sha256") is None,
            code, "wrong consumed control/object/tool bytes", stage, "FAIL")
    pin = result.get("pin_path")
    root = PurePosixPath(lease["guest_pin_root"])
    require(pin == str(root / binding["attempt_id"] / ("permission-negative" if negative else "positive")),
            code, "control pin belongs to another attempt", stage, "FAIL")
    admission = result.get("admission", {})
    require(type(admission) is dict and admission.get("bpftool_admitted") is True
            and root == PurePosixPath(str(admission.get("owned_root"))) / str(admission.get("ownership_token")),
            code, "control ownership/admission differs", stage, "FAIL")
    commands = result.get("commands")
    require(type(commands) is list and len(commands) == (2 if negative else 4),
            code, "missing stock-C command observation", stage, "FAIL")
    argv = [[tool.get("path"), "version"],
            [tool.get("path"), "prog", "load", obj.get("path"), pin]]
    if not negative:
        argv.extend([[tool.get("path"), "prog", "run", "pinned", pin, "data_in", packet.get("path"), "repeat", "1"],
                     ["rm", "-f", pin]])
    for index, command in enumerate(commands):
        require(type(command) is dict and command.get("argv") == argv[index]
                and command.get("timeout") is False and integer(command.get("exit_code"))
                and type(command.get("stdout")) is str and type(command.get("stderr")) is str,
                code, "invalid stock-C command record", stage, "FAIL")
        if negative and index == 1:
            error = (command["stdout"] + command["stderr"]).lower()
            require(command["exit_code"] != 0
                    and control_contract.classify_load_failure(command) == "environment"
                    and any(p in error for p in (
                "operation not permitted", "permission denied", "eperm")),
                code, "negative did not observe permission denial", stage, "FAIL")
        else:
            require(command["exit_code"] == 0, code, "stock-C command failed", stage, "FAIL")
    observed_version = commands[0]["stdout"].splitlines()
    require(observed_version and observed_version[0] == expected["bpftool_version"],
            code, "raw tool version contradicts its admitted summary", stage, "FAIL")
    if not negative:
        actions = re.findall(r"return value:\s*(\d+)", commands[2]["stdout"] + commands[2]["stderr"], re.I)
        require(actions == ["2"], code, "test-run did not independently observe action 2", stage, "FAIL")


def assess_bootstrap(provisional, attempt, provisional_sha256, evidence_root):
    """Return READY or typed UNREADY; never change a lease or run a command."""
    report = {"schema_version": 1, "contract": "target-ready-v1", "status": "UNREADY",
              "outcome": "INFRA_ERROR", "run_id": None, "lane_id": None,
              "provisional_sha256": provisional_sha256 if valid_hash(provisional_sha256) else None,
              "attempt_sha256": None, "fingerprint": None, "lease": None,
              "inputs": None, "evidence": None, "target": None, "failure": None}
    try:
        mapping(provisional, {"schema_version", "run_id", "lane_id", "lease", "expected"}, "ADMISSION_REFUSED")
        require(valid_hash(provisional_sha256) and digest_of(provisional) == provisional_sha256,
                "ADMISSION_REFUSED", "provisional manifest lacks its independent admission pin")
        require(type(provisional["schema_version"]) is int and provisional["schema_version"] == 1
                and all(type(provisional[k]) is str and IDENTIFIER.fullmatch(provisional[k])
                        for k in ("run_id", "lane_id")), "ADMISSION_REFUSED", "invalid provisional identity")
        report.update(run_id=provisional["run_id"], lane_id=provisional["lane_id"])
        lease = mapping(provisional["lease"], {"id", "owner", "exclusive", "record_sha256",
                        "rootfs_read_only", "guest_pin_root", "host_write_paths"}, "LEASE_REQUIRED")
        require(all(text(lease[k]) for k in ("id", "owner", "guest_pin_root"))
                and lease["exclusive"] is True and lease["rootfs_read_only"] is True
                and valid_hash(lease["record_sha256"]) and type(lease["host_write_paths"]) is list
                and lease["host_write_paths"] and all(type(p) is str and Path(p).is_absolute()
                                                    for p in lease["host_write_paths"]),
                "LEASE_REQUIRED", "approved exclusive disposable-target lease is missing")
        expected = mapping(provisional["expected"], HASH_INPUTS | TEXT_INPUTS | {"kernel_source_commit"}, "IDENTITY_UNKNOWN")
        require(all(valid_hash(expected[k]) for k in HASH_INPUTS)
                and all(text(expected[k]) for k in TEXT_INPUTS)
                and expected["execution_mode"] in {"tcg", "hardware-vm", "physical"}
                and expected["byte_order"] in {"le", "be"}
                and source_commit(expected["kernel_source_commit"]),
                "IDENTITY_UNKNOWN", "required provisional runtime identity is unknown")
        mapping(attempt, {"schema_version", "run_id", "lane_id", "lease_id", "provisional_sha256", "evidence"})
        require(type(attempt["schema_version"]) is int and attempt["schema_version"] == 1
                and all(attempt[k] == provisional[k] for k in ("run_id", "lane_id"))
                and attempt["provisional_sha256"] == provisional_sha256,
                "IDENTITY_MISMATCH", "attempt is not bound to the admitted provisional identity")
        require(attempt["lease_id"] == lease["id"], "LEASE_REQUIRED", "attempt used another lease")
        mapping(attempt["evidence"], EVIDENCE_NAMES)
        records = {name: read_evidence(evidence_root, attempt["evidence"][name]) for name in sorted(EVIDENCE_NAMES)}
        check_target(records["target"], expected, lease)
        binding = check_execution(records["execution"], provisional, expected, lease, "main", records["target"])
        check_absence(records["pin_root_absence"], binding, lease)
        check_control(records["positive"], expected, lease, binding)
        check_permission(records["permission_context"], binding, lease)
        check_control(records["permission_negative"], expected, lease, binding, negative=True,
                      context=records["permission_context"], context_sha256=attempt["evidence"]["permission_context"]["sha256"])
        check_cleanup(records["cleanup"], binding, lease, records["execution"], "main")
        recovery = mapping(records["recovery"], {"outcome", "terminal", "plan_sha256",
                           "interrupted_attempt", "fresh_attempt"}, "RECOVERY_FAILED")
        require(recovery["outcome"] == "PASS" and recovery["terminal"] is True
                and recovery["plan_sha256"] == expected["recovery_plan_sha256"],
                "RECOVERY_FAILED", "interruption/recovery proof is incomplete", "CLEANUP")
        try:
            captured = {"main": records}
            for phase in ("interrupted", "fresh"):
                references = read_evidence(evidence_root, recovery[phase + "_attempt"])
                names = (ATTEMPT_NAMES - {"permission_negative", "permission_context"}) | {"trigger"} if phase == "interrupted" else ATTEMPT_NAMES
                mapping(references, names, "RECOVERY_FAILED")
                data = {name: read_evidence(evidence_root, references[name]) for name in sorted(names)}
                captured[phase] = data
                check_target(data["target"], expected, lease)
                phase_binding = check_execution(data["execution"], provisional, expected, lease, phase, data["target"])
                check_absence(data["pin_root_absence"], phase_binding, lease)
                check_control(data["positive"], expected, lease, phase_binding)
                if phase == "fresh":
                    check_permission(data["permission_context"], phase_binding, lease)
                    check_control(data["permission_negative"], expected, lease, phase_binding, negative=True,
                                  context=data["permission_context"], context_sha256=references["permission_context"]["sha256"])
                else:
                    trigger = mapping(data["trigger"], BINDING_KEYS | {"marker", "held_pin", "held_pin_exists",
                                     "positive_sha256", "load_command"}, "RECOVERY_FAILED")
                    check_binding(trigger, phase_binding, "RECOVERY_FAILED")
                    held = lease["guest_pin_root"] + "/" + phase_binding["attempt_id"] + "/recovery-held"
                    command = mapping(trigger["load_command"], {"argv", "exit_code", "timeout", "stdout", "stderr"}, "RECOVERY_FAILED")
                    positive = data["positive"]["result"]
                    require(trigger["marker"] == "INTERRUPT_OWNED_GUEST" and trigger["held_pin"] == held
                            and trigger["held_pin_exists"] is True and trigger["positive_sha256"] == digest_of(data["positive"])
                            and command["argv"] == [positive["bpftool"]["path"], "prog", "load", positive["object"]["path"], held]
                            and integer(command["exit_code"]) and command["exit_code"] == 0 and command["timeout"] is False
                            and type(command["stdout"]) is str and type(command["stderr"]) is str,
                            "RECOVERY_FAILED", "owned held-pin interruption trigger is absent or foreign", "CLEANUP")
                check_cleanup(data["cleanup"], phase_binding, lease, data["execution"], phase)
            guests = [data["execution"]["guest"] for data in captured.values()]
            require(all(len({guest[key] for guest in guests}) == 3 for key in ("id", "boot_id", "session_id"))
                    and len({(p["pid"], p["start_ticks"]) for guest in guests for p in guest["processes"]}) == sum(len(guest["processes"]) for guest in guests),
                    "RECOVERY_FAILED", "recovery reused a guest, boot, session or process identity", "CLEANUP")
        except (Unready, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise Unready("RECOVERY_FAILED", "recovery evidence refused: %s" % exc, "CLEANUP") from exc
        report.update(status="READY", outcome="PASS", lease=copy.deepcopy(lease), inputs=copy.deepcopy(expected),
                      evidence=copy.deepcopy(attempt["evidence"]), target=records["target"],
                      attempt_sha256=digest_of(attempt))
        report["fingerprint"] = digest_of({k: v for k, v in report.items() if k != "fingerprint"})
    except Unready as exc:
        report.update(outcome=exc.outcome, failure={"code": exc.code, "stage": exc.stage, "detail": exc.detail})
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        report["failure"] = {"code": "EVIDENCE_INVALID", "stage": "INFRA", "detail": str(exc)}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("provisional", "provisional-sha256", "attempt", "evidence-root", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        provisional = load_json(Path(args.provisional).read_bytes())
        attempt = load_json(Path(args.attempt).read_bytes())
    except (OSError, ValueError, UnicodeError) as exc:
        report = assess_bootstrap(None, None, args.provisional_sha256, args.evidence_root)
        report["failure"] = {"code": "EVIDENCE_INVALID", "stage": "INFRA", "detail": str(exc)}
    else:
        report = assess_bootstrap(provisional, attempt, args.provisional_sha256, args.evidence_root)
    try:
        Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        sys.stderr.write("cannot write bootstrap report: %s\n" % exc)
        return 3
    return 0 if report["status"] == "READY" else 3


if __name__ == "__main__":
    sys.exit(main())
