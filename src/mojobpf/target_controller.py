# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Read-only approval and lease boundary for a disposable target controller.

The versioned controller-launch-v1 amendment retains its immutable parent
proposal as an independently pinned input. Approval binds the complete new
proposal and every input; a separately pinned provisional lease binds that
approval, proposal, installed controller distribution and one host/lane/run.
No document binds a future result or requires its future READY assessment.

Only --validate-only is operational. Successful validation records NOT_RUN:
full closure inventories, active locking, empty caches, subreaper lifecycle,
phase execution and measured evidence assembly still require implementation
and independent qualification. This module never grants a lease or admission.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from uuid import UUID

from mojobpf import execution
from mojobpf.process_guardian import GuardLimits, GuardianError
from mojobpf.validation import digest_of
from mojobpf.validation.models import json_equal


CONTROLLER_CONTRACT = "controller-result-v1"
JSON_LIMIT = 4 * 1024 * 1024
JSON_DEPTH_LIMIT = 128  # Maximum number of nested object/array containers.
FAILURE_CODES = frozenset({"ADMISSION_REFUSED", "LEASE_REQUIRED", "OWNERSHIP_UNKNOWN", "STARTUP_TIMEOUT",
                           "MARKER_TIMEOUT", "ATTEMPT_TIMEOUT", "CANCELLED", "EVIDENCE_INVALID",
                           "IO_FAILED", "CLEANUP_INCOMPLETE"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_DOCUMENT_SEAL = object()
_INPUT_NAMES = frozenset({"parent_proposal", "admission", "capture_contract", "recovery_plan",
                         "controller_distribution", "original_closure", "supplemental_closure",
                         "rootfs_manifest", "rootfs_provenance", "payload", "kernel_packages",
                         "assessor", "assessor_schema", "input_sidecar"})
_HASH_INPUTS = frozenset({"kernel_config_sha256", "kernel_image_sha256", "vmlinux_btf_sha256",
                        "kernel_packages_sha256", "rootfs_sha256", "payload_sha256", "observer_sha256",
                        "compiler_sha256", "runner_admission_sha256", "launcher_admission_sha256",
                        "qemu_admission_sha256", "control_source_sha256", "control_object_sha256",
                        "packet_sha256", "bpftool_sha256", "python_sha256", "libbpf_sha256",
                        "recovery_plan_sha256"})
_TEXT_INPUTS = frozenset({"kernel_release", "kernel_build_id", "bpftool_version", "execution_mode",
                        "architecture", "byte_order", "instruction_profile"})


class ControllerError(Exception):
    """A typed non-success; errno preserves an underlying file/API failure."""

    def __init__(self, code: str, detail: str = "", *, errno: int | None = None):
        if code not in FAILURE_CODES:
            raise ValueError("unknown controller failure code")
        super().__init__(detail)
        self.code, self.detail, self.errno = code, detail, errno


def _require(condition, detail, code="ADMISSION_REFUSED"):
    if not condition:
        raise ControllerError(code, detail)


def _mapping(value, names, code="ADMISSION_REFUSED"):
    _require(type(value) is dict and set(value) == set(names), "missing or unknown record fields", code)
    return value


def _text(value, *, identifier=False, code="ADMISSION_REFUSED"):
    _require(type(value) is str and bool(value.strip()) and "\x00" not in value,
             "invalid text field", code)
    if identifier:
        _require(_IDENTIFIER.fullmatch(value) is not None, "invalid record identifier", code)
    return value


def _hash(value, code="ADMISSION_REFUSED"):
    _require(type(value) is str and _HASH.fullmatch(value) is not None and value != "0" * 64,
             "invalid SHA-256 pin", code)
    return value


def _integer(value, minimum=0, code="ADMISSION_REFUSED"):
    _require(type(value) is int and value >= minimum, "invalid integer field", code)
    return value


def _absolute_path(value, code="ADMISSION_REFUSED"):
    _text(value, code=code)
    _require(value.startswith("/") and value != "/" and os.path.normpath(value) == value
             and not value.startswith("//"), "path must be absolute and normalized", code)
    return value


def _boot(value, code="ADMISSION_REFUSED"):
    try:
        _require(type(value) is str and str(UUID(value)) == value, "invalid host boot identity", code)
    except (ValueError, AttributeError) as exc:
        raise ControllerError(code, "invalid host boot identity") from exc
    return value


def _host_boot_id():
    try:
        return _boot(Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    except OSError as exc:
        raise ControllerError("ADMISSION_REFUSED", "host boot identity unavailable", errno=exc.errno) from exc


def _wall_time():
    return time.time()


def _stamp(value, code):
    _text(value, code=code)
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        _require(result.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "noncanonical UTC timestamp", code)
        return result.timestamp()
    except (ValueError, OverflowError) as exc:
        raise ControllerError(code, "invalid UTC timestamp") from exc


def _strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("non-JSON constant")

    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite JSON number")
        return result

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=reject_constant, parse_float=number)
        _require(type(result) is dict, "document must be a JSON object")
        pending = [(result, 0)]
        while pending:
            value, depth = pending.pop()
            if type(value) in (dict, list):
                _require(depth < JSON_DEPTH_LIMIT, "JSON container depth exceeds the bound")
                children = value.values() if type(value) is dict else value
                pending.extend((item, depth + 1) for item in children)
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ControllerError("ADMISSION_REFUSED", "invalid or ambiguous JSON document") from exc


@dataclass(frozen=True)
class _FrozenObject:
    items: tuple


def _freeze(value, *, _depth=0):
    try:
        if type(value) in (dict, list):
            _require(_depth < JSON_DEPTH_LIMIT, "JSON container depth exceeds the bound")
            if type(value) is dict:
                return _FrozenObject(tuple((key, _freeze(item, _depth=_depth + 1)) for key, item in value.items()))
            return tuple(_freeze(item, _depth=_depth + 1) for item in value)
        return value
    except RecursionError as exc:
        raise ControllerError("ADMISSION_REFUSED", "JSON freezing exceeded the recursion budget") from exc


def _thaw(value, *, _depth=0):
    try:
        if isinstance(value, _FrozenObject) or type(value) is tuple:
            _require(_depth < JSON_DEPTH_LIMIT, "JSON container depth exceeds the bound")
            if isinstance(value, _FrozenObject):
                return {key: _thaw(item, _depth=_depth + 1) for key, item in value.items}
            return [_thaw(item, _depth=_depth + 1) for item in value]
        return value
    except RecursionError as exc:
        raise ControllerError("ADMISSION_REFUSED", "JSON thawing exceeded the recursion budget") from exc


@dataclass(frozen=True)
class _PinnedBytes:
    path: str
    file_sha256: str
    raw: bytes
    stat_identity: tuple[int, ...]


@dataclass(frozen=True)
class _PinnedDocument:
    consumed: _PinnedBytes
    value: _FrozenObject
    _seal: object


def _stat_identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _open_parent(path):
    """Open every existing directory component with O_NOFOLLOW."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(path).parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_pinned_bytes(path, expected_sha256) -> _PinnedBytes:
    path = _absolute_path(str(path))
    _hash(expected_sha256)
    directory_fd, file_fd = None, None
    try:
        directory_fd = _open_parent(path)
        file_fd = os.open(Path(path).name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
                          dir_fd=directory_fd)
        before = os.fstat(file_fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                 "pinned input must be a single-link regular file")
        _require(before.st_size <= JSON_LIMIT, "pinned input exceeds the byte bound")
        chunks, size = [], 0
        while True:
            chunk = os.read(file_fd, min(65536, JSON_LIMIT + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            _require(size <= JSON_LIMIT, "pinned input exceeded the byte bound while reading")
        after = os.fstat(file_fd)
        at_path = os.stat(Path(path).name, dir_fd=directory_fd, follow_symlinks=False)
        _require(_stat_identity(before) == _stat_identity(after) == _stat_identity(at_path)
                 and size == before.st_size, "pinned file changed during capture")
        raw = b"".join(chunks)
        observed = hashlib.sha256(raw).hexdigest()
        _require(hmac.compare_digest(observed, expected_sha256), "whole input file pin differs")
        return _PinnedBytes(path, observed, raw, _stat_identity(after))
    except OSError as exc:
        raise ControllerError("ADMISSION_REFUSED", "pinned input cannot be consumed safely", errno=exc.errno) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def read_approved_document(path: Path, expected_sha256: str) -> _PinnedDocument:
    """Consume a document once using a pin supplied by an external authority.

    No digest from inside this document can replace expected_sha256. Frozen
    parsed values prevent caller mutation from changing the consumed record.
    """
    consumed = _read_pinned_bytes(path, expected_sha256)
    return _PinnedDocument(consumed, _freeze(_strict_json(consumed.raw)), _DOCUMENT_SEAL)


def _document(value, code="ADMISSION_REFUSED"):
    _require(type(value) is _PinnedDocument and value._seal is _DOCUMENT_SEAL,
             "independently byte-pinned document required", code)
    return _thaw(value.value)


def _reference(value, code="ADMISSION_REFUSED"):
    _mapping(value, {"path", "file_sha256", "canonical_sha256"}, code)
    _absolute_path(value["path"], code)
    _hash(value["file_sha256"], code)
    if value["canonical_sha256"] is not None:
        _hash(value["canonical_sha256"], code)
    return value


def _canonical_input_digest(name, record):
    # Retain the frozen producers' canonical recipes, not a new hash of
    # their pretty-printed documents or a hash that includes its own field.
    if name in {"original_closure", "supplemental_closure"} and "sha256" in record:
        _require(type(record.get("files")) is list, "invalid closure file inventory")
        observed = digest_of(record["files"])
        _require(record["sha256"] == observed, "frozen closure canonical digest differs")
        return observed
    if name == "recovery_plan" and record.get("contract") == "owned-disposable-recovery-v2" and "sha256" in record:
        observed = digest_of({key: value for key, value in record.items() if key != "sha256"})
        _require(record["sha256"] == observed, "frozen recovery canonical digest differs")
        return observed
    return digest_of(record)


def _check_reference(value, consumed, record=None, *, name=None):
    _reference(value)
    _require(value["path"] == consumed.path and value["file_sha256"] == consumed.file_sha256,
             "consumed bytes differ from approved reference")
    if value["canonical_sha256"] is not None:
        if record is None:
            record = _strict_json(consumed.raw)
        _require(value["canonical_sha256"] == _canonical_input_digest(name, record), "canonical input digest differs")


def _file_identity(value):
    names = {field.name for field in fields(execution.FileIdentity)}
    _mapping(value, names)
    _absolute_path(value["path"])
    _absolute_path(value["realpath"])
    _hash(value["sha256"])
    for name in ("size", "dev", "ino", "mtime_ns"):
        _integer(value[name])
    for name in ("link_dev", "link_ino"):
        _integer(value[name], -1)
    _require((value["link_dev"] == -1) == (value["link_ino"] == -1), "partial symlink identity")
    return execution.FileIdentity(**value)


def _strings(value, *, nonempty=False):
    _require(type(value) is list and (not nonempty or bool(value)), "invalid string sequence")
    for item in value:
        _text(item)
    return tuple(value)


def load_approved_chain(summary: dict) -> execution.AdmittedExecution:
    """Reconstruct a previously externally approved summarize() record.

    Call only after the containing file's independent byte pin matched.
    This loader checks record integrity and verify_spawn; its embedded digest
    is not admission authority and its version remains historical evidence.
    """
    names = {field.name for field in fields(execution.AdmittedExecution)}
    _mapping(summary, names)
    _require(summary["contract"] == execution.EXECUTION_CONTRACT_VERSION,
             "unsupported execution summary contract")
    _text(summary["name"])
    _text(summary["trust_root"])
    _require(type(summary["form"]) is str and
             summary["form"] in set(execution.DEFAULT_FORMS) | {execution.FORM_SCRIPT_DATA},
             "unsupported execution form")
    _require(type(summary["hops"]) is list and type(summary["modules"]) is list,
             "invalid chain identity sequence")
    modules, module_names = [], set()
    for item in summary["modules"]:
        _mapping(item, {"name", "file"})
        _require(type(item["name"]) is str and re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", item["name"])
                 and item["name"] not in module_names, "ambiguous module identity")
        module_names.add(item["name"])
        modules.append(execution.ModuleIdentity(item["name"], _file_identity(item["file"])))
    prefix = _strings(summary["argv_prefix"], nonempty=True)
    _absolute_path(prefix[0])
    unset = _strings(summary["env_unset"])
    _require(len(set(unset)) == len(unset) and set(execution.SPAWN_ENV_UNSET) <= set(unset),
             "incomplete or ambiguous stripped environment")
    _require(type(summary["env_set"]) is list, "invalid environment overlay")
    overlay, keys = [], set()
    for pair in summary["env_set"]:
        _require(type(pair) is list and len(pair) == 2, "invalid environment pair")
        key, value = pair
        _text(key)
        _require(type(value) is str and "\x00" not in value and key not in keys,
                 "ambiguous environment overlay")
        keys.add(key)
        overlay.append((key, value))
    _require(all(dict(overlay).get(key) == value for key, value in execution.PYTHON_ENV_SET),
             "missing admitted Python hardening")
    _require(keys <= {key for key, _ in execution.PYTHON_ENV_SET} | {"PYTHONPATH"},
             "summary introduces an unadmitted environment overlay")
    if "PYTHONPATH" in keys:
        for root in dict(overlay)["PYTHONPATH"].split(os.pathsep):
            _absolute_path(root)
    if summary["version"] is not None:
        _text(summary["version"])
    _hash(summary["digest"])
    _require(digest_of({key: value for key, value in summary.items() if key != "digest"}) == summary["digest"],
             "execution summary digest differs")
    admitted = execution.AdmittedExecution(
        contract=summary["contract"], name=summary["name"], form=summary["form"], trust_root=summary["trust_root"],
        entry=_file_identity(summary["entry"]), hops=tuple(_file_identity(item) for item in summary["hops"]),
        image=_file_identity(summary["image"]), interpreter=(None if summary["interpreter"] is None
                                                            else _file_identity(summary["interpreter"])),
        modules=tuple(modules), version=summary["version"], argv_prefix=prefix,
        env_unset=unset, env_set=tuple(overlay), digest=summary["digest"])
    if admitted.form == execution.FORM_SCRIPT_DATA:
        _require(admitted.interpreter is not None and
                 admitted.argv_prefix == (admitted.interpreter.path, admitted.entry.path),
                 "script-data argv does not identify its interpreter and data")
    else:
        _require(admitted.argv_prefix == (admitted.entry.path,), "argv prefix is not the identified entry")
    if admitted.form == execution.FORM_EXEC_LAUNCHER:
        _require(bool(admitted.hops) and admitted.hops[0] == admitted.entry and admitted.hops[-1] == admitted.image,
                 "launcher endpoints differ from its hop identities")
    else:
        _require(not admitted.hops and admitted.image == admitted.entry, "direct chain has inconsistent image identities")
    _require((admitted.interpreter is None) == (admitted.form == execution.FORM_BINARY),
             "execution form has an inconsistent interpreter identity")
    _require(json_equal(execution.summarize(admitted), summary), "execution summary does not roundtrip exactly")
    try:
        execution.verify_spawn(admitted)
    except execution.AdmissionError as exc:
        raise ControllerError("ADMISSION_REFUSED", "approved execution identity drifted: " + exc.reason) from exc
    return admitted


@dataclass(frozen=True)
class _Invocation:
    phase: str
    attempt_id: str
    argv: tuple[str, ...]
    cwd: str
    env_overrides: tuple[tuple[str, str], ...]
    output_path: str
    timeout_seconds: int


@dataclass(frozen=True)
class _LaunchLimits:
    vcpus: int
    ram_mib: int
    nice_increment: int
    attempt_seconds: int
    startup_seconds: int
    marker_seconds: int
    guardian: GuardLimits


@dataclass(frozen=True)
class _OwnedPaths:
    output_root: str
    tmp_root: str
    controller_output: str
    lease_journal: str
    controller_pycache: str
    farm: str
    final_path: str


@dataclass(frozen=True)
class _LockIdentity:
    path: str
    dev: int
    ino: int
    owner_uid: int
    mode: int


@dataclass(frozen=True)
class _ValidatedLaunch:
    """Frozen read-only input check; not permission or qualification to spawn."""
    proposal_sha256: str
    approval_sha256: str
    lease_sha256: str
    run_id: str
    lane_id: str
    lease_id: str
    owner: str
    host_boot_id: str
    expires_at: float
    runner: execution.AdmittedExecution
    launcher: execution.AdmittedExecution
    qemu: execution.AdmittedExecution
    invocations: tuple[_Invocation, ...]
    expected: tuple[tuple[str, str], ...]
    paths: _OwnedPaths
    limits: _LaunchLimits
    lock: _LockIdentity
    inputs: tuple[tuple[str, _PinnedBytes, str | None], ...]


def _limits(value):
    _mapping(value, {field.name for field in fields(_LaunchLimits)})
    exact = {"vcpus": 1, "ram_mib": 768, "nice_increment": 10, "attempt_seconds": 900,
             "startup_seconds": 300, "marker_seconds": 300}
    _require(all(type(value[key]) is int and value[key] == expected for key, expected in exact.items()),
             "unapproved resource/deadline bounds")
    _mapping(value["guardian"], {field.name for field in fields(GuardLimits)})
    try:
        guardian = GuardLimits(**value["guardian"])
    except GuardianError as exc:
        raise ControllerError("ADMISSION_REFUSED", exc.detail) from exc
    _require(guardian.cleanup_seconds == 30.0 and guardian.poll_seconds <= 0.05 and
             guardian.max_live_processes <= 128 and guardian.max_retained_processes <= 4096 and
             guardian.max_tasks_per_process <= 128 and guardian.max_proc_reads_per_tick <= 4096,
             "guardian bounds exceed approved controller policy")
    return _LaunchLimits(**exact, guardian=guardian)


def _path_ancestry(path):
    """Read-only refusal of symlinks in existing path components."""
    current = Path("/")
    for component in Path(path).parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ControllerError("ADMISSION_REFUSED", "path ancestry unavailable", errno=exc.errno) from exc
        _require(not stat.S_ISLNK(info.st_mode), "owned path contains a symlink")
        if current != Path(path):
            _require(stat.S_ISDIR(info.st_mode), "owned ancestor is not a directory")


def _inside(path, root):
    return path != root and Path(path).is_relative_to(root)


def _paths(value):
    _mapping(value, {field.name for field in fields(_OwnedPaths)})
    for key in value:
        if key != "final_path":
            _absolute_path(value[key])
            _path_ancestry(value[key])
    _require(not Path(value["tmp_root"]).is_relative_to(value["output_root"])
             and not Path(value["output_root"]).is_relative_to(value["tmp_root"]), "write roots overlap")
    _require(_inside(value["controller_output"], value["output_root"])
             and _inside(value["lease_journal"], value["controller_output"])
             and _inside(value["controller_pycache"], value["tmp_root"]), "controller paths escape owned roots")
    _require(value["final_path"] == value["farm"] + ":/usr/bin:/usr/sbin:/bin:/sbin",
             "farm-first approved PATH differs")
    return _OwnedPaths(**value)


def _load_chains(record):
    if record.get("contract") == "controller-execution-input-v1":
        _mapping(record, {"contract", "runner", "launcher", "qemu"})
        return tuple(load_approved_chain(record[role]) for role in ("runner", "launcher", "qemu"))
    # Historical host admission is kept byte-for-byte; no new admission or
    # version observation substitutes for any of these summarize records.
    _mapping(record, {"operation", "lock_sha256", "status", "runner"})
    _require(record["status"] == "admitted", "historical runner admission is not admitted")
    _hash(record["lock_sha256"])
    runner = record["runner"]
    _mapping(runner, {"path", "realpath", "version", "sha256", "exec_path", "exec_sha256", "qemu_binary",
                      "qemu_path", "qemu_version", "qemu_sha256", "virtme_run_path", "virtme_run_version",
                      "virtme_run_sha256", "farm", "digest", "admission", "virtme_run_admission", "qemu_admission"})
    result = tuple(load_approved_chain(runner[key]) for key in ("admission", "virtme_run_admission", "qemu_admission"))
    _require(runner["digest"] == result[0].digest, "historical admission digest differs")
    return result


def validate_launch(proposal, approval, lease, *, lane_id: str) -> _ValidatedLaunch:
    """Validate pinned records without locking, writing, probing or spawning.

    Closure file-byte correspondence is checked here. Inventory contents,
    kernel admission, empty caches and active ownership are separate checks;
    this immutable result cannot yet be passed to a phase execution API.
    """
    p, a, l = _document(proposal), _document(approval), _document(lease, "LEASE_REQUIRED")
    _mapping(a, {"schema_version", "contract", "status", "owner", "host_boot_id", "proposal", "inputs",
                 "approved_at", "expires_at", "trusted_writers"})
    _require(type(a["schema_version"]) is int and a["schema_version"] == 1
             and a["contract"] == "controller-approval-v1" and a["status"] == "APPROVED"
             and a["trusted_writers"] == "exclusive-nonconcurrent", "unsupported external approval")
    _check_reference(a["proposal"], proposal.consumed, p)
    _mapping(p, {"schema_version", "contract", "controller_contract", "owner", "host_boot_id", "execution_mode",
                 "vm_concurrency", "limits", "paths", "inputs", "lanes", "nice_policy", "hard_death_policy",
                 "acceptance_rule"})
    _require(type(p["schema_version"]) is int and p["schema_version"] == 1
             and p["contract"] == "controller-launch-v1" and p["controller_contract"] == CONTROLLER_CONTRACT
             and p["execution_mode"] == "tcg" and type(p["vm_concurrency"]) is int and p["vm_concurrency"] == 1
             and p["nice_policy"] == "controller-once-inherited" and p["hard_death_policy"] == "quarantine"
             and p["acceptance_rule"] == "controller-result-plus-v1", "proposal lacks the controller amendment")
    _text(p["owner"], identifier=True)
    _boot(p["host_boot_id"])
    _require(p["owner"] == a["owner"] and p["host_boot_id"] == a["host_boot_id"] == _host_boot_id(),
             "approval belongs to another owner or host boot")
    now = _wall_time()
    approval_expiry = _stamp(a["expires_at"], "ADMISSION_REFUSED")
    _require(_stamp(a["approved_at"], "ADMISSION_REFUSED") <= now < approval_expiry,
             "approval is not currently valid")
    _mapping(p["inputs"], _INPUT_NAMES)
    for reference in p["inputs"].values():
        _reference(reference)
    _require(json_equal(p["inputs"], a["inputs"]), "approval does not bind every proposal input")
    limits, paths = _limits(p["limits"]), _paths(p["paths"])
    _text(lane_id, identifier=True)
    _require(type(p["lanes"]) is dict and lane_id in p["lanes"], "lane is not approved")
    for name, lane in p["lanes"].items():
        _text(name, identifier=True)
        _mapping(lane, {"run_id", "expected", "invocations"})
    lane = p["lanes"][lane_id]
    _text(lane["run_id"], identifier=True)
    _mapping(lane["expected"], _HASH_INPUTS | _TEXT_INPUTS | {"kernel_source_commit"})
    for key in _HASH_INPUTS:
        _hash(lane["expected"][key])
    for key in _TEXT_INPUTS:
        _text(lane["expected"][key])
    _require(type(lane["expected"]["kernel_source_commit"]) is str and
             re.fullmatch(r"[0-9a-f]{40}", lane["expected"]["kernel_source_commit"]) and
             lane["expected"]["kernel_source_commit"] != "0" * 40, "kernel source identity is unknown")
    _require(lane["expected"]["execution_mode"] == "tcg" and lane["expected"]["architecture"] == "x86_64"
             and lane["expected"]["byte_order"] == "little", "unsupported controller target")
    _mapping(l, {"schema_version", "contract", "state", "owner", "lease_id", "host_boot_id", "run_id", "lane_id",
                 "vm_concurrency", "approval_sha256", "proposal_sha256", "controller_distribution_sha256",
                 "paths", "limits", "lock", "issued_at", "expires_at", "state_policy"}, "LEASE_REQUIRED")
    _require(type(l["schema_version"]) is int and l["schema_version"] == 1 and l["contract"] == "controller-lease-v1"
             and l["state"] == "PROVISIONAL" and l["state_policy"] == "quarantine-unresolved"
             and type(l["vm_concurrency"]) is int and l["vm_concurrency"] == 1, "unsupported provisional lease", "LEASE_REQUIRED")
    _text(l["lease_id"], identifier=True, code="LEASE_REQUIRED")
    _require(l["owner"] == p["owner"] and l["host_boot_id"] == p["host_boot_id"]
             and l["lane_id"] == lane_id and l["run_id"] == lane["run_id"]
             and l["approval_sha256"] == approval.consumed.file_sha256
             and l["proposal_sha256"] == proposal.consumed.file_sha256
             and l["controller_distribution_sha256"] == p["inputs"]["controller_distribution"]["file_sha256"]
             and json_equal(l["paths"], p["paths"]) and json_equal(l["limits"], p["limits"]),
             "lease scope or independent bindings differ", "LEASE_REQUIRED")
    expiry = _stamp(l["expires_at"], "LEASE_REQUIRED")
    budget = 3 * (limits.attempt_seconds + limits.guardian.cleanup_seconds)
    _require(_stamp(l["issued_at"], "LEASE_REQUIRED") <= now and now + budget <= expiry <= approval_expiry,
             "lease expires before the complete lane and cleanup budget", "LEASE_REQUIRED")
    _mapping(l["lock"], {field.name for field in fields(_LockIdentity)}, "LEASE_REQUIRED")
    _absolute_path(l["lock"]["path"], "LEASE_REQUIRED")
    for key in ("dev", "ino", "owner_uid", "mode"):
        _integer(l["lock"][key], code="LEASE_REQUIRED")
    try:
        fd = _open_parent(l["lock"]["path"])
        try:
            st = os.stat(Path(l["lock"]["path"]).name, dir_fd=fd, follow_symlinks=False)
        finally:
            os.close(fd)
    except OSError as exc:
        raise ControllerError("LEASE_REQUIRED", "precreated lock identity is unavailable", errno=exc.errno) from exc
    _require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid()
             and (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode)) ==
             tuple(l["lock"][key] for key in ("dev", "ino", "owner_uid", "mode"))
             and stat.S_IMODE(st.st_mode) == 0o600, "precreated exclusive lock identity differs", "LEASE_REQUIRED")
    consumed_inputs, records = [], {}
    for name, reference in p["inputs"].items():
        _reference(reference)
        consumed = _read_pinned_bytes(reference["path"], reference["file_sha256"])
        record = _strict_json(consumed.raw) if name in {"admission", "parent_proposal"} or reference["canonical_sha256"] else None
        _check_reference(reference, consumed, record, name=name)
        consumed_inputs.append((name, consumed, reference["canonical_sha256"]))
        if record is not None:
            records[name] = record
    _require(records["parent_proposal"].get("contract") == "provisional-disposable-launch-v1",
             "controller amendment does not retain its immutable parent proposal")
    _require(p["inputs"]["recovery_plan"]["canonical_sha256"] == lane["expected"]["recovery_plan_sha256"],
             "expected recovery identity differs from the consumed canonical input")
    runner, launcher, qemu = _load_chains(records["admission"])
    for role, chain in (("runner", runner), ("launcher", launcher), ("qemu", qemu)):
        _require(lane["expected"][role + "_admission_sha256"] == chain.digest,
                 "expected execution identity differs from historical approved chain")
    invocations = []
    _require(type(lane["invocations"]) is list and len(lane["invocations"]) == 3, "exact three-phase invocation required")
    for phase, record in zip(("main", "interrupted", "fresh"), lane["invocations"]):
        _mapping(record, {"phase", "attempt_id", "argv", "cwd", "env_overrides", "start_new_session", "timeout_seconds", "output_path"})
        argv = _strings(record["argv"], nonempty=True)
        _require(record["phase"] == phase and record["attempt_id"] == lane["run_id"] + "." + phase
                 and record["start_new_session"] is True and type(record["timeout_seconds"]) is int
                 and record["timeout_seconds"] == limits.attempt_seconds
                 and argv[:len(runner.argv_prefix)] == runner.argv_prefix, "approved invocation differs from its runner or phase")
        _absolute_path(record["cwd"])
        _path_ancestry(record["cwd"])
        _absolute_path(record["output_path"])
        _path_ancestry(record["output_path"])
        _require(_inside(record["output_path"], paths.output_root)
                 and not Path(record["output_path"]).is_relative_to(paths.controller_output)
                 and not Path(paths.controller_output).is_relative_to(record["output_path"]), "guest export overlaps controller records")
        env = _mapping(record["env_overrides"], {"PATH", "TMPDIR", "PYTHONPYCACHEPREFIX"})
        _require(env["PATH"] == paths.final_path and env["TMPDIR"] == paths.tmp_root + "/" + record["attempt_id"]
                 and env["PYTHONPYCACHEPREFIX"] == env["TMPDIR"] + "/pycache"
                 and not Path(paths.controller_pycache).is_relative_to(env["TMPDIR"]), "per-attempt environment or cache roots differ")
        _path_ancestry(env["TMPDIR"])
        _path_ancestry(env["PYTHONPYCACHEPREFIX"])
        invocations.append(_Invocation(phase, record["attempt_id"], argv, record["cwd"], tuple(env.items()),
                                       record["output_path"], record["timeout_seconds"]))
    _require(all(not Path(item.output_path).is_relative_to(other.output_path)
                 for index, item in enumerate(invocations)
                 for other_index, other in enumerate(invocations) if index != other_index),
             "attempt output roots overlap")
    return _ValidatedLaunch(proposal.consumed.file_sha256, approval.consumed.file_sha256, lease.consumed.file_sha256,
                            lane["run_id"], lane_id, l["lease_id"], p["owner"], p["host_boot_id"], expiry,
                            runner, launcher, qemu, tuple(invocations), tuple(lane["expected"].items()), paths,
                            limits, _LockIdentity(**l["lock"]), tuple(consumed_inputs))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate externally pinned disposable-controller inputs")
    for name in ("proposal", "approval", "approval-sha256", "lease", "lease-sha256", "lane"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--cancel-fd", type=int)
    arguments = parser.parse_args(argv)
    try:
        approval = read_approved_document(Path(arguments.approval), arguments.approval_sha256)
        approved = _document(approval)
        proposal_ref = _reference(approved.get("proposal"))
        _require(str(Path(arguments.proposal)) == proposal_ref["path"], "CLI proposal path differs from external approval")
        lease = read_approved_document(Path(arguments.lease), arguments.lease_sha256)
        proposal = read_approved_document(Path(arguments.proposal), proposal_ref["file_sha256"])
        validated = validate_launch(proposal, approval, lease, lane_id=arguments.lane)
        _require(arguments.validate_only, "controller lifecycle is not implemented; only read-only validation is available")
        print(json.dumps({"contract": "controller-validation-v1", "outcome": "NOT_RUN", "run_id": validated.run_id,
                          "lane_id": validated.lane_id, "proposal_sha256": validated.proposal_sha256}, sort_keys=True))
        return 0
    except ControllerError as exc:
        print(json.dumps({"code": exc.code, "detail": exc.detail, "errno": exc.errno}, sort_keys=True), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
