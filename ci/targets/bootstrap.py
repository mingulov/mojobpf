# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Assess captured disposable-target bootstrap evidence without running a VM.

The controller independently pins the provisional manifest and grants its
exclusive lease before execution. This assessor consumes one terminal attempt,
the stock-C test-run records and cleanup/recovery records from an owned bundle.
It never provisions a target, executes commands or grants a lease. A READY
record establishes the captured environment/control boundary; subsequent
product qualification uses its own contracts. Unknown kernel source provenance
is retained as null, separate from the required runtime identities.

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
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from mojobpf.validation.models import digest_of, json_equal  # noqa: E402

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
EVIDENCE_NAMES = {"target", "execution", "positive", "permission_negative", "cleanup", "recovery"}


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
    return value is None or (type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value)
                             and value != "0" * 40)


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


def clean(record):
    return (type(record) is dict and set(record) == {
        "status", "owned_processes", "owned_mounts", "owned_pins"
    } and record["status"] == "CLEAN" and all(
        type(record[name]) is list and not record[name]
        for name in ("owned_processes", "owned_mounts", "owned_pins")))


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


def check_control(record, expected, lease, negative=False):
    code = "NEGATIVE_FAILED" if negative else "CONTROL_FAILED"
    stage = "LOAD" if negative else "TEST_RUN"
    mapping(record, {"exit_code", "result"}, code)
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
            and (runtime["uid"] > 0 if negative else runtime["uid"] == 0)
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
    require(text(pin) and PurePosixPath(pin).is_relative_to(root) and PurePosixPath(pin) != root
            and ".." not in PurePosixPath(pin).parts, code, "control pin escapes its lease", stage, "FAIL")
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
            require(command["exit_code"] != 0 and any(p in error for p in (
                "operation not permitted", "permission denied", "eperm")),
                code, "negative did not observe permission denial", stage, "FAIL")
        else:
            require(command["exit_code"] == 0, code, "stock-C command failed", stage, "FAIL")
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
        execution = mapping(records["execution"], {"run_id", "terminal", "exit_code", "outcome", "inputs", "host_write_paths"})
        require(execution["terminal"] is True and execution["outcome"] != "NOT_RUN",
                "RUN_NONTERMINAL", "required bootstrap run is incomplete", outcome="NOT_RUN")
        require(execution["outcome"] == "PASS" and integer(execution["exit_code"])
                and execution["exit_code"] == 0, "RUN_FAILED", "bootstrap command failed")
        require(execution["run_id"] == provisional["run_id"]
                and json_equal(execution["inputs"], expected), "IDENTITY_MISMATCH", "consumed inputs differ")
        require(json_equal(execution["host_write_paths"], lease["host_write_paths"]),
                "LEASE_REQUIRED", "attempt write scope differs from the lease")
        check_target(records["target"], expected, lease)
        check_control(records["positive"], expected, lease)
        check_control(records["permission_negative"], expected, lease, negative=True)
        require(clean(records["cleanup"]), "CLEANUP_INCOMPLETE", "owned resources remain or were not checked", "CLEANUP")
        recovery = mapping(records["recovery"], {"outcome", "terminal", "plan_sha256", "cleanup",
                           "interrupted_attempt", "fresh_control"}, "RECOVERY_FAILED")
        require(recovery["outcome"] == "PASS" and recovery["terminal"] is True
                and recovery["plan_sha256"] == expected["recovery_plan_sha256"] and clean(recovery["cleanup"]),
                "RECOVERY_FAILED", "interruption/recovery proof is incomplete", "CLEANUP")
        try:
            interrupted = read_evidence(evidence_root, recovery["interrupted_attempt"])
            fresh = read_evidence(evidence_root, recovery["fresh_control"])
            mapping(interrupted, {"run_id", "terminal", "outcome", "exit_code", "cleanup"}, "RECOVERY_FAILED")
            mapping(fresh, {"run_id", "exit_code", "result"}, "RECOVERY_FAILED")
            require(text(interrupted["run_id"]) and text(fresh["run_id"])
                    and len({provisional["run_id"], interrupted["run_id"], fresh["run_id"]}) == 3
                    and interrupted["terminal"] is True and interrupted["outcome"] == "INFRA_ERROR"
                    and integer(interrupted["exit_code"]) and interrupted["exit_code"] < 0
                    and clean(interrupted["cleanup"]), "RECOVERY_FAILED", "interrupted attempt was not recovered", "CLEANUP")
            check_control({"exit_code": fresh["exit_code"], "result": fresh["result"]}, expected, lease)
        except (Unready, OSError, ValueError, TypeError) as exc:
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
