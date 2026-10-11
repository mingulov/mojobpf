# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Externally admitted disposable target controller and fixed-byte evidence.

The versioned controller-launch-v1 amendment retains its immutable parent
proposal as an independently pinned input. Approval binds the complete new
proposal and every input; a separately pinned provisional lease binds that
approval, proposal, installed controller distribution and one host/lane/run.
No document binds a future result or requires its future READY assessment.

Legacy launches remain validate-only. Version 2 runs require a dedicated Linux
controller, prior external approval, a separately pinned lease and complete
installed/runtime closure. Integrity inspection grants neither release nor
READY. This module never grants a lease or admission.
"""

from __future__ import annotations

import argparse
import configparser
import fcntl
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import hmac
import io
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import select
import stat
import sys
import subprocess
import time
import weakref
from uuid import UUID
import zipfile

from mojobpf import execution
from mojobpf.process_guardian import GuardLimits, GuardianError, ProcessGuardian, ProcessIdentity, parse_process_stat, replay_completion
from mojobpf.validation import ContractError, TargetManifest, digest_of
from mojobpf.validation.models import json_equal


CONTROLLER_CONTRACT = "controller-result-v1"
CONTROLLER_CONTRACT_V2 = "controller-result-v2"
JSON_LIMIT = 4 * 1024 * 1024
JSON_DEPTH_LIMIT = 128  # Maximum number of nested object/array containers.
FAILURE_CODES = frozenset({"ADMISSION_REFUSED", "LEASE_REQUIRED", "OWNERSHIP_UNKNOWN", "STARTUP_TIMEOUT",
                           "MARKER_TIMEOUT", "ATTEMPT_TIMEOUT", "CANCELLED", "EVIDENCE_INVALID",
                           "IO_FAILED", "CLEANUP_INCOMPLETE"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_DOCUMENT_SEAL = object()
_VALIDATED_LAUNCHES = {}
_INPUT_BYTE_LIMITS = {"controller_distribution": 32 * 1024 * 1024, "rootfs_provenance": 16 * 1024 * 1024}
_LARGE_NODE_LIMIT = 2_000_000
_QEMU_MODULE_ROOT = "/usr/lib/x86_64-linux-gnu/qemu"
_QEMU_DATA_ROOT = "/usr/share/qemu"
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


def _strict_json(raw, *, depth_limit=JSON_DEPTH_LIMIT, node_limit=None):
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
        pending, nodes = [(result, 0)], 0
        while pending:
            value, depth = pending.pop()
            nodes += 1
            if type(value) in (dict, list):
                _require(depth < depth_limit, "JSON container depth exceeds the bound")
                if type(value) is dict: nodes += len(value)
                children = value.values() if type(value) is dict else value
                pending.extend((item, depth + 1) for item in children)
            if node_limit is not None:
                _require(nodes + len(pending) <= node_limit, "JSON value/key node bound exceeded")
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


def _read_pinned_bytes(path, expected_sha256, *, _limit=JSON_LIMIT, _check=None) -> _PinnedBytes:
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
        _require(before.st_size <= _limit, "pinned input exceeds the byte bound")
        chunks, size = [], 0
        while True:
            if _check is not None: _check()
            chunk = os.read(file_fd, min(65536, _limit + 1 - size))
            if _check is not None: _check()
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            _require(size <= _limit, "pinned input exceeded the byte bound while reading")
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


def _canonical_input_digest(name, record, *, version=1):
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
    if version == 2 and ((name == "rootfs_manifest" and record.get("contract") == "owned-rootfs-v1")
                         or (name == "payload" and record.get("contract") == "owned-bootstrap-payload-v1")):
        field = "entries" if name == "rootfs_manifest" else "files"
        _require(type(record.get(field)) is list, "invalid frozen producer entries")
        observed = digest_of(record[field])
        _require(record.get("sha256") == observed, "frozen producer canonical digest differs")
        return observed
    return digest_of(record)


def _check_reference(value, consumed, record=None, *, name=None, version=1):
    _reference(value)
    _require(value["path"] == consumed.path and value["file_sha256"] == consumed.file_sha256,
             "consumed bytes differ from approved reference")
    if value["canonical_sha256"] is not None:
        if record is None:
            record = _strict_json(consumed.raw)
        _require(value["canonical_sha256"] == _canonical_input_digest(name, record, version=version), "canonical input digest differs")


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
    schema_version: int


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
    versions = {1: ("controller-launch-v1", CONTROLLER_CONTRACT, "controller-result-plus-v1"),
                2: ("controller-launch-v2", CONTROLLER_CONTRACT_V2, "controller-result-v2-plus-v1")}
    _require(type(p["schema_version"]) is int and p["schema_version"] in versions,
             "unsupported launch version")
    version = p["schema_version"]
    _require((p["contract"], p["controller_contract"], p["acceptance_rule"]) == versions[version]
             and p["execution_mode"] == "tcg" and type(p["vm_concurrency"]) is int and p["vm_concurrency"] == 1
             and p["nice_policy"] == "controller-once-inherited" and p["hard_death_policy"] == "quarantine",
             "proposal lacks the versioned controller amendment")
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
             and lane["expected"]["byte_order"] == ("little" if version == 1 else "le"),
             "unsupported controller target or byte-order contract")
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
        large_role = version == 2 and name in _INPUT_BYTE_LIMITS
        consumed = _read_pinned_bytes(reference["path"], reference["file_sha256"],
                                      _limit=_INPUT_BYTE_LIMITS[name] if large_role else JSON_LIMIT)
        record = (_strict_json(consumed.raw, depth_limit=32 if large_role else JSON_DEPTH_LIMIT,
                               node_limit=_LARGE_NODE_LIMIT if large_role else None)
                  if large_role or name in {"admission", "parent_proposal"} or reference["canonical_sha256"] else None)
        _check_reference(reference, consumed, record, name=name, version=version)
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
    validated = _ValidatedLaunch(proposal.consumed.file_sha256, approval.consumed.file_sha256, lease.consumed.file_sha256,
                            lane["run_id"], lane_id, l["lease_id"], p["owner"], p["host_boot_id"], expiry,
                            runner, launcher, qemu, tuple(invocations), tuple(lane["expected"].items()), paths,
                            limits, _LockIdentity(**l["lock"]), tuple(consumed_inputs), version)
    key = id(validated)
    _VALIDATED_LAUNCHES[key] = (weakref.ref(validated, lambda reference: _VALIDATED_LAUNCHES.pop(key, None)),
                              (proposal, approval, lease))
    return validated


def _execution_authority(validated):
    issued = _VALIDATED_LAUNCHES.get(id(validated))
    _require(type(validated) is _ValidatedLaunch and issued is not None and issued[0]() is validated
             and validated.schema_version == 2, "execution requires the issued launch-v2 validation object")
    return issued[1]



# Embedded contracts keep installed validation independent of checkout schemas.
_GUARDIAN_PREFIX_LIMIT = 64 * 1024 * 1024
_GUARDIAN_RECORD_LIMIT = 16 * 1024 * 1024
_GUARDIAN_RECORD_COUNT = 65536


def _json_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ControllerError("EVIDENCE_INVALID", "value is not bounded JSON") from exc


class _PersistenceBackend:
    """Private synchronous syscall seam; production never selects it from inputs."""
    def monotonic(self): return time.monotonic()
    def wall_time(self): return _wall_time()
    def write(self, fd, raw): return os.write(fd, raw)
    def fsync(self, fd): return os.fsync(fd)
    def close(self, fd): return os.close(fd)
    def read(self, fd, maximum): return os.read(fd, maximum)
    def checkpoint(self, operation, path): pass


class _Budget:
    def __init__(self, validated, backend):
        self._io = backend
        try:
            self._last = self._start = backend.monotonic()
            self._wall_start = backend.wall_time()
            valid = (type(self._start) in (int, float) and type(self._wall_start) in (int, float)
                     and math.isfinite(self._start) and math.isfinite(self._wall_start))
        except (ValueError, TypeError, OverflowError) as exc:
            raise ControllerError("IO_FAILED", "initial clock observation cannot be represented") from exc
        _require(valid, "initial clock observation is invalid", "IO_FAILED")
        self._expiry = validated.expires_at
        self._lease_deadline = self._start + self._expiry - self._wall_start
        self._lane_deadline = self._start + 3 * (validated.limits.attempt_seconds + validated.limits.guardian.cleanup_seconds)
        self.cleanup_deadline = None
        self.check()

    def check(self):
        try:
            now, wall = self._io.monotonic(), self._io.wall_time()
            valid = (type(now) in (int, float) and type(wall) in (int, float)
                     and math.isfinite(now) and math.isfinite(wall) and now >= self._last)
        except (ValueError, TypeError, OverflowError) as exc:
            raise ControllerError("IO_FAILED", "clock observation cannot be represented") from exc
        _require(valid,
                 "clock observation is invalid or moved backwards", "IO_FAILED")
        self._last = now
        _require(now < self._lease_deadline and wall < self._expiry,
                 "lease expired during the lane", "LEASE_REQUIRED")
        _require(now < self._lane_deadline, "lane budget expired", "ATTEMPT_TIMEOUT")
        if self.cleanup_deadline is not None:
            _require(now < self.cleanup_deadline, "original cleanup deadline expired", "CLEANUP_INCOMPLETE")
        return now


_CLOSURE_COUNTS = {"files": 65536, "inventories": 16384, "edges": 65536,
                   "roles": 131072, "runtime_roots": 256, "sources": 8192,
                   "wheel_members": 8192, "installed_generated": 256}
_WHEEL_BYTES = 64 * 1024 * 1024
_WHEEL_EXPANDED = 256 * 1024 * 1024
_WHEEL_MEMBER_BYTES = 32 * 1024 * 1024
_RUNTIME_FILE_BYTES = 4 * 1024**3
_RUNTIME_TOTAL_BYTES = 16 * 1024**3
_CLOSURE_ROLES = {"controller", "runtime", "original_closure", "supplemental_closure",
                  "rootfs", "payload", "input_sidecars", "kernel_packages", "kernel_images", "farm"}
_FILE_FIELDS = {"path", "realpath", "kind", "mode", "dev", "ino", "uid", "gid", "nlink",
                "size", "mtime_ns", "ctime_ns", "sha256", "link_target"}


def _bounded_path(value, *, relative=False):
    _text(value)
    _require(len(value.encode("utf-8")) <= 4096 and "\\" not in value, "path exceeds the closed path policy")
    if relative:
        _require(not value.startswith("/") and all(p not in ("", ".", "..") for p in value.split("/")),
                 "relative path escapes its root")
    else:
        _absolute_path(value)
    return value


def _sorted_rows(value, key, limit):
    _require(type(value) is list and len(value) <= limit, "closure sequence exceeds its bound")
    keys = []
    for row in value:
        _require(type(row) is dict and key in row, "invalid closure sequence row")
        keys.append(_text(row[key]))
    _require(keys == sorted(set(keys)), "closure rows are not unique and sorted")
    return value


def _sorted_paths(value, limit):
    _require(type(value) is list and len(value) <= limit, "closure path count exceeds its bound")
    for path in value: _bounded_path(path)
    _require(value == sorted(set(value)), "closure paths are not unique and sorted")
    return set(value)


class _ClosureBackend(_PersistenceBackend):
    """In-process runtime observations; inputs cannot select a different observer."""
    def runtime_observation(self):
        try:
            distribution = importlib.metadata.distribution("mojobpf")
            mapped = set()
            with open("/proc/self/maps", encoding="utf-8") as stream:
                for line in stream:
                    columns = line.rstrip("\n").split(None, 5)
                    if len(columns) == 6 and columns[5].startswith("/"):
                        path = columns[5]
                        _require(not path.endswith(" (deleted)"), "mapped runtime file was deleted")
                        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), path)
                        mapped.add(path)
            return {"interpreter": os.path.realpath(sys.executable), "base_prefix": sys.base_prefix,
                    "version": list(sys.version_info[:2]), "sys_path": list(sys.path),
                    "module_path": os.path.abspath(__file__), "distribution_path": str(distribution._path),
                    "mapped_files": sorted(mapped)}
        except (OSError, importlib.metadata.PackageNotFoundError) as exc:
            raise ControllerError("ADMISSION_REFUSED", "installed runtime observation unavailable",
                                  errno=getattr(exc, "errno", None)) from exc


class _ClosureVerifier:
    """Refresh an externally approved complete closure without executing probes.

    Every pass retains directory handles, observes metadata around inventories
    and reads, and hashes each regular inode once. Old producer digest recipes
    remain separate from the distribution supplement's full-object digest.
    """
    def __init__(self, validated, *, budget, _backend=None):
        self.validated, self.budget = validated, budget
        self.backend = _backend or _ClosureBackend()
        self.authority = _execution_authority(validated)
        self.inputs = {name: (consumed, canonical) for name, consumed, canonical in validated.inputs}
        self.documents = {}
        self.rows, self.roles, self.directories, self.inventories = {}, {}, {}, {}
        self.complete, self.hashed, self.total = set(), {}, 0

    def _step(self, operation, path, action):
        self.budget.check()
        try:
            self.backend.checkpoint(operation, path)
            result = action()
            self.backend.checkpoint("after-" + operation, path)
        except OSError as exc:
            raise ControllerError("ADMISSION_REFUSED", "closure " + operation + " failed", errno=exc.errno) from exc
        self.budget.check()
        return result

    def _refresh_inputs(self):
        for document in self.authority:
            consumed = document.consumed
            again = _read_pinned_bytes(consumed.path, consumed.file_sha256, _check=self.budget.check)
            _require(again.raw == consumed.raw and again.stat_identity == consumed.stat_identity,
                     "external authority changed after validation")
        for name, (consumed, canonical) in self.inputs.items():
            large = name in _INPUT_BYTE_LIMITS
            again = _read_pinned_bytes(consumed.path, consumed.file_sha256,
                                      _limit=_INPUT_BYTE_LIMITS[name] if large else JSON_LIMIT,
                                      _check=self.budget.check)
            _require(again.raw == consumed.raw and again.stat_identity == consumed.stat_identity,
                     "approved input identity changed after validation")
            if canonical is not None or large or name in {"admission", "parent_proposal"}:
                record = _strict_json(again.raw, depth_limit=32 if large else JSON_DEPTH_LIMIT,
                                      node_limit=_LARGE_NODE_LIMIT if large else None)
                if canonical is not None:
                    _require(_canonical_input_digest(name, record, version=2) == canonical,
                             "approved canonical input changed")
                self.documents[name] = record
        for chain in (self.validated.runner, self.validated.launcher, self.validated.qemu):
            try: execution.verify_spawn(chain)
            except execution.AdmissionError as exc:
                raise ControllerError("ADMISSION_REFUSED", "approved spawn identity changed: " + exc.reason) from exc
            self.budget.check()

    def _covered(self, path):
        return any(path == root or _inside(path, root) for root in self.complete)

    def _shape(self):
        d = self.documents["controller_distribution"]
        _require(self.inputs["controller_distribution"][1] == digest_of(d),
                 "complete distribution requires its independently approved full-object canonical pin")
        _mapping(d, {"schema_version", "contract", "producer", "coverage", "files", "roles", "inventories"})
        _require(type(d["schema_version"]) is int and d["schema_version"] == 2
                 and d["contract"] == "controller-distribution-v2", "unsupported complete distribution")
        _mapping(d["producer"], {"wheel_path", "sources", "wheel_members", "installed_generated", "install_scheme", "runtime_layout"})
        c = d["coverage"]
        _mapping(c, {"producer_root", "install_root", "runtime_roots", "farm_root", "rootfs_root", "payload_root", "shared_files"})
        for field in c.keys() - {"runtime_roots", "shared_files"}:
            self.complete.add(_bounded_path(c[field]))
        roots = _sorted_rows(c["runtime_roots"], "path", _CLOSURE_COUNTS["runtime_roots"])
        for row in roots:
            _mapping(row, {"path", "purpose"})
            _bounded_path(row["path"])
            _require(row["purpose"] in {"python-stdlib", "python-site-packages", "qemu-modules", "qemu-data"},
                     "unknown runtime root purpose")
            self.complete.add(row["path"])
        self.shared = _sorted_paths(c["shared_files"], _CLOSURE_COUNTS["files"])
        _require(not any(self._covered(path) for path in self.shared), "shared file hides complete-root content")
        for row in _sorted_rows(d["files"], "path", _CLOSURE_COUNTS["files"]):
            _mapping(row, _FILE_FIELDS)
            _bounded_path(row["path"]); _bounded_path(row["realpath"])
            _require(row["kind"] in {"regular", "directory", "symlink"}, "unknown closure file kind")
            for name in {"dev", "ino", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns", "mode"}:
                _integer(row[name], 1 if name in {"ino", "nlink"} else 0)
                _require(row[name] <= (4095 if name == "mode" else 2**63 - 1), "closure integer exceeds its bound")
            if row["kind"] == "regular":
                _hash(row["sha256"])
                _require(row["link_target"] is None and row["size"] <= _RUNTIME_FILE_BYTES,
                         "regular closure content exceeds policy")
            elif row["kind"] == "symlink":
                _text(row["link_target"])
                _require(len(row["link_target"].encode("utf-8")) <= 4096 and row["sha256"] is None
                         and row["size"] == len(row["link_target"].encode("utf-8")), "invalid component link")
            else:
                _require(row["sha256"] is None and row["link_target"] is None, "directory has content claim")
            self.rows[row["path"]] = row
        _require(sum(r["kind"] == "directory" for r in self.rows.values()) <= _CLOSURE_COUNTS["inventories"],
                 "directory count exceeds its bound")
        _mapping(d["roles"], _CLOSURE_ROLES)
        count, assigned = 0, set()
        for name, paths in d["roles"].items():
            self.roles[name] = _sorted_paths(paths, _CLOSURE_COUNTS["roles"])
            count += len(paths); assigned.update(paths)
        _require(count <= _CLOSURE_COUNTS["roles"] and assigned <= self.rows.keys(), "invalid role references")
        nondirs = {path for path, row in self.rows.items() if row["kind"] != "directory"}
        _require(nondirs <= assigned and self.shared == {path for path in nondirs if not self._covered(path)},
                 "unclassified or missing shared content")
        edges = 0
        for row in _sorted_rows(d["inventories"], "path", _CLOSURE_COUNTS["inventories"]):
            _mapping(row, {"path", "entries"}); _bounded_path(row["path"])
            _require(type(row["entries"]) is list, "invalid directory inventory")
            for name in row["entries"]:
                _text(name)
                _require(name not in {".", ".."} and "/" not in name and "\\" not in name
                         and len(name.encode("utf-8")) <= 255, "invalid directory entry")
            _require(row["entries"] == sorted(set(row["entries"])), "ambiguous directory entries")
            edges += len(row["entries"])
            _require(edges <= _CLOSURE_COUNTS["edges"], "inventory edge count exceeds its bound")
            self.inventories[row["path"]] = row["entries"]
        expected = {path for path, row in self.rows.items() if row["kind"] == "directory" and self._covered(path)}
        _require(set(self.inventories) == expected and self.complete <= expected,
                 "complete directory coverage is missing")
        for directory, names in self.inventories.items():
            _require(all(directory + "/" + name in self.rows for name in names), "inventory child has no identity")

    def _matches(self, path, observed):
        row = self.rows[path]
        kind = "regular" if stat.S_ISREG(observed.st_mode) else "directory" if stat.S_ISDIR(observed.st_mode) else "symlink" if stat.S_ISLNK(observed.st_mode) else None
        _require(kind == row["kind"], "closure file kind drifted")
        actual = {"dev": observed.st_dev, "ino": observed.st_ino, "uid": observed.st_uid, "gid": observed.st_gid,
                  "nlink": observed.st_nlink, "size": observed.st_size, "mtime_ns": observed.st_mtime_ns,
                  "ctime_ns": observed.st_ctime_ns, "mode": stat.S_IMODE(observed.st_mode)}
        # Owned directory creation changes shared ancestor times/link counts.
        # Complete roots and all regular/link rows retain the full observations.
        checked = {"dev", "ino", "uid", "gid", "mode"} if kind == "directory" and not self._covered(path) else actual.keys()
        _require(all(actual[key] == row[key] for key in checked), "closure stat or mode drifted: " + path)
        return _stat_identity(observed)

    def _resolve(self, path):
        remaining, current, hops = list(Path(path).parts[1:]), "/", 0
        while remaining:
            component = remaining.pop(0)
            current = os.path.join(current, component)
            _require(current in self.rows, "path component lacks a declared identity: " + current)
            row = self.rows[current]
            if row["kind"] == "symlink":
                hops += 1
                _require(hops <= 40, "component link cycle or depth exceeds its bound")
                self._matches(current, self._step("lstat", current, lambda: os.lstat(current)))
                target = self._step("readlink", current, lambda: os.readlink(current))
                _require(target == row["link_target"], "component link text changed")
                target = os.path.normpath(target if target.startswith("/") else os.path.join(os.path.dirname(current), target))
                remaining = list(Path(target).parts[1:]) + remaining
                current = "/"
            elif remaining:
                _require(row["kind"] == "directory", "nondirectory path component")
        return current

    def _retain_directories(self):
        for path, row in self.rows.items():
            self._matches(path, self._step("lstat", path, lambda p=path: os.lstat(p)))
            resolved = self._resolve(path)
            _require(resolved == row["realpath"] and resolved in self.rows, "undeclared or different final path")
        for path, row in self.rows.items():
            if row["kind"] != "directory": continue
            fd = None
            try:
                # Register the handle before any fallible post-open observation.
                def opened():
                    nonlocal fd
                    fd = os.open(row["realpath"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    self.directories[path] = fd
                    return fd
                self._step("directory-open", path, opened)
                self._matches(path, self._step("fstat", path, lambda: os.fstat(fd)))
            except Exception:
                raise

    def _check_directories(self):
        for path, fd in self.directories.items():
            self._matches(path, self._step("directory-fstat", path, lambda f=fd: os.fstat(f)))
            self._matches(path, self._step("directory-lstat", path, lambda p=path: os.lstat(p)))

    def _inventory(self):
        for path, expected in self.inventories.items():
            fd = self.directories[path]
            before = self._step("inventory-stat", path, lambda: os.fstat(fd))
            self._matches(path, before)
            def names():
                result = []
                with os.scandir(fd) as entries:
                    for item in entries:
                        self.budget.check()
                        _require(len(result) < _CLOSURE_COUNTS["edges"], "actual inventory exceeds bound")
                        result.append(item.name)
                return sorted(result)
            actual = self._step("inventory", path, names)
            _require(actual == expected, "complete inventory drifted: " + path)
            after = self._step("inventory-stat", path, lambda: os.fstat(fd))
            _require(_stat_identity(before) == _stat_identity(after), "directory changed during inventory")
            self._matches(path, after)

    def _content(self, path, *, maximum=_RUNTIME_FILE_BYTES, capture=False):
        row = self.rows[path]
        _require(row["kind"] == "regular" and row["size"] <= maximum, "required content is not bounded regular data")
        key = (row["dev"], row["ino"])
        admitted = (row["size"], row["sha256"], row["mode"], row["uid"], row["gid"], row["nlink"], row["mtime_ns"], row["ctime_ns"])
        if key in self.hashed:
            _require(self.hashed[key] == admitted, "overlapping inode observations disagree")
            if not capture: return None
        else:
            _require(self.total + row["size"] <= _RUNTIME_TOTAL_BYTES, "aggregate content exceeds bound")
        realpath = self._resolve(path)
        parent = os.path.dirname(realpath)
        _require(parent in self.directories, "regular target lacks a retained parent")
        fd, data, size, hashed = None, bytearray(), 0, hashlib.sha256()
        try:
            def opened():
                nonlocal fd
                fd = os.open(os.path.basename(realpath), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=self.directories[parent])
                return fd
            self._step("file-open", path, opened)
            before = self._step("file-stat", path, lambda: os.fstat(fd))
            self._matches(path, before)
            while True:
                chunk = self._step("content-read", path, lambda: self.backend.read(fd, min(1024 * 1024, maximum - size + 1)))
                _require(type(chunk) is bytes, "content reader returned nonbytes")
                if not chunk: break
                size += len(chunk)
                _require(size <= maximum and size <= row["size"], "streamed content exceeds admission")
                hashed.update(chunk)
                if capture: data.extend(chunk)
            after = self._step("file-stat", path, lambda: os.fstat(fd))
            self._matches(path, after)
            self._matches(path, self._step("file-lstat", path, lambda: os.lstat(path)))
            _require(_stat_identity(before) == _stat_identity(after) and size == row["size"]
                     and hashed.hexdigest() == row["sha256"], "runtime bytes changed")
            if key not in self.hashed:
                self.total += size; self.hashed[key] = admitted
            return bytes(data) if capture else None
        finally:
            if fd is not None:
                released, fd = fd, None
                self._release_handle("file-close", path, released)

    def _release_handle(self, operation, path, fd):
        # Release our known descriptor even when the admission deadline failed.
        # Keep the failure; late physical release never becomes acceptance.
        error = None
        for action in (self.budget.check, lambda: self.backend.checkpoint(operation, path),
                       lambda: self.backend.close(fd),
                       lambda: self.backend.checkpoint("after-" + operation, path), self.budget.check):
            try: action()
            except OSError as exc:
                if error is None: error = ControllerError("ADMISSION_REFUSED", "closure release failed", errno=exc.errno)
            except ControllerError as exc:
                if error is None: error = exc
        if error is not None: raise error

    def _regular(self, path, digest=None, size=None):
        _require(path in self.rows, "required path missing from complete supplement")
        resolved = self._resolve(path)
        row = self.rows[resolved]
        _require(row["kind"] == "regular" and (digest is None or row["sha256"] == digest)
                 and (size is None or row["size"] == size), "producer content correspondence differs")
        return row

    def _exact_role(self, name, paths):
        _require(self.roles[name] == set(paths), "historical role coverage differs: " + name)

    def _legacy_roles(self):
        for name in ("original_closure", "supplemental_closure"):
            record = self.documents[name]
            _require(type(record.get("files")) is list and len(record["files"]) <= _CLOSURE_COUNTS["files"],
                     "invalid historical runtime files")
            _require(digest_of(record["files"]) == record.get("sha256") == self.inputs[name][1],
                     "historical file-array digest differs")
            raw_paths, paths, normalized = set(), set(), {}
            for row in record["files"]:
                _mapping(row, {"path", "realpath", "sha256", "bytes"})
                _text(row["path"]); _require(row["path"].startswith("/") and row["path"] not in raw_paths,
                                           "duplicate historical path")
                raw_paths.add(row["path"])
                path = _bounded_path(os.path.normpath(row["path"])); _bounded_path(row["realpath"])
                _hash(row["sha256"]); _integer(row["bytes"])
                facts = (row["realpath"], row["sha256"], row["bytes"])
                _require(path not in normalized or normalized[path] == facts, "historical normalized alias conflicts")
                normalized[path] = facts; paths.add(path)
                _require(self._resolve(path) == row["realpath"], "historical final image differs")
                self._regular(path, row["sha256"], row["bytes"])
            self._exact_role(name, paths)
        supplemental = self.documents["supplemental_closure"]
        _integer(supplemental.get("modules"))
        _require(supplemental["modules"] == sum(_inside(path, _QEMU_MODULE_ROOT) for path in self.roles["supplemental_closure"]),
                 "supplemental module count differs from fixed runtime layout")
        root = self.documents["rootfs_manifest"]
        _mapping(root, {"contract", "root", "sha256", "entry_encoding", "entries"})
        _require(root["contract"] == "owned-rootfs-v1" and type(root["entries"]) is list,
                 "unsupported rootfs producer")
        _text(root["entry_encoding"])
        _require(digest_of(root["entries"]) == root["sha256"] == self.inputs["rootfs_manifest"][1]
                 == dict(self.validated.expected)["rootfs_sha256"], "rootfs entries digest differs")
        root_paths = set()
        for entry in root["entries"]:
            _require(type(entry) is dict and entry.get("kind") in {"file", "directory", "symlink"}, "invalid rootfs entry")
            kind = entry["kind"]
            _mapping(entry, {"path", "kind", "mode"} | ({"sha256", "size"} if kind == "file" else {"target"} if kind == "symlink" else set()))
            relative = _bounded_path(entry["path"], relative=True); _integer(entry["mode"])
            path = root["root"] + "/" + relative
            _require(path not in root_paths and path in self.rows, "duplicate or missing rootfs path")
            root_paths.add(path); row = self.rows[path]
            _require(row["kind"] == ("regular" if kind == "file" else kind) and row["mode"] == entry["mode"],
                     "rootfs kind or mode correspondence differs")
            if kind == "file": self._regular(path, _hash(entry["sha256"]), _integer(entry["size"]))
            elif kind == "symlink": _require(row["link_target"] == entry["target"], "rootfs link text differs")
        self._exact_role("rootfs", root_paths)
        parent, payload = self.documents["parent_proposal"], self.documents["payload"]
        _mapping(payload, {"contract", "root", "files", "sha256", "exclusion"})
        _require(parent.get("revision") == 2 and json_equal(payload, parent.get("payload"))
                 and payload["contract"] == "owned-bootstrap-payload-v1" and type(payload["files"]) is list
                 and len(payload["files"]) == 8, "payload is not the frozen eight-member parent payload")
        _text(payload["exclusion"])
        expected = dict(self.validated.expected)
        _require(digest_of(payload["files"]) == payload["sha256"] == self.inputs["payload"][1]
                 == expected["payload_sha256"], "payload files digest differs")
        payload_paths, names = set(), set()
        for row in payload["files"]:
            _mapping(row, {"path", "sha256", "bytes"})
            name = _bounded_path(row["path"], relative=True); _require(name not in names, "duplicate payload member")
            names.add(name); path = payload["root"] + "/" + name; payload_paths.add(path)
            self._regular(path, _hash(row["sha256"]), _integer(row["bytes"]))
        _require(names == {"bpf_test_run.py", "control.bpf.c", "control.bpf.o", "guest-observer.py", "negative-control.py",
                           "packet.bin", "v6.12-kernel.config", "v6.6-kernel.config"}, "unexpected payload members")
        self._exact_role("payload", payload_paths)
        kernel, _ = self.inputs["kernel_packages"]
        original, _ = self.inputs["parent_proposal"]
        _require(kernel.raw == original.raw and kernel.file_sha256 == original.file_sha256
                 and self.inputs["kernel_packages"][1] == digest_of(parent), "kernel packages do not consume the complete parent")
        _require(type(parent.get("lanes")) is dict and self.validated.lane_id in parent["lanes"], "selected parent lane missing")
        sidecars, packages, images, package_pins = set(), set(), set(), {}
        for name, lane in parent["lanes"].items():
            _require(type(lane) is dict and type(lane.get("expected")) is dict and type(lane.get("packages")) is list,
                     "invalid frozen parent lane")
            lane_expected = lane["expected"]
            _require(digest_of(lane["packages"]) == lane_expected.get("kernel_packages_sha256"), "ordered package digest differs")
            for row in lane["packages"]:
                _mapping(row, {"path", "sha256", "metadata", "exit"})
                path, digest = _bounded_path(row["path"]), _hash(row["sha256"])
                _text(row["metadata"]); _require(type(row["exit"]) is int and row["exit"] == 0, "package metadata observation failed")
                _require(path not in package_pins or package_pins[path] == digest, "parent package pins conflict")
                package_pins[path] = digest; packages.add(path); self._regular(path, digest)
            boot = _bounded_path(lane.get("boot_image")); images.add(boot)
            self._regular(boot, _hash(lane_expected.get("kernel_image_sha256")))
            match = re.match(r"^(\d+\.\d+)(?:\D|$)", _text(lane_expected.get("kernel_release")))
            _require(match is not None, "kernel release has no unambiguous config version")
            config = payload["root"] + "/v" + match[1] + "-kernel.config"
            _require(config in payload_paths, "kernel config is outside frozen payload")
            images.add(config); self._regular(config, _hash(lane_expected.get("kernel_config_sha256")))
            sidecar = lane.get("input_sidecar"); _mapping(sidecar, {"path", "sha256"})
            path = _bounded_path(sidecar["path"]); _require(path not in sidecars, "duplicate lane sidecar")
            sidecars.add(path); self._regular(path, _hash(sidecar["sha256"]))
            if name == self.validated.lane_id:
                consumed = self.inputs["input_sidecar"][0]
                _require(consumed.path == path and consumed.file_sha256 == sidecar["sha256"], "selected sidecar pin differs")
                for key, value in lane_expected.items():
                    if key in expected and key != "recovery_plan_sha256":
                        _require(json_equal(value, expected[key]), "selected immutable parent identity differs: " + key)
        _require(len(sidecars) == 2 and set(self.inventories[payload["root"]]) == names | {Path(p).name for p in sidecars},
                 "payload inventory does not contain exactly eight members and two sidecars")
        self._exact_role("input_sidecars", sidecars); self._exact_role("kernel_packages", packages); self._exact_role("kernel_images", images)
        coverage = self.documents["controller_distribution"]["coverage"]
        _require(coverage["rootfs_root"] == root["root"] == parent.get("rootfs", {}).get("path")
                 and coverage["payload_root"] == payload["root"] and coverage["farm_root"] == self.validated.paths.farm,
                 "mandatory old producer or farm root differs")
        farm_paths = {path for path, row in self.rows.items() if _inside(path, coverage["farm_root"]) and row["kind"] != "directory"}
        self._exact_role("farm", farm_paths)
        admitted_targets = set(self.roles["original_closure"] | self.roles["supplemental_closure"])
        for chain in (self.validated.runner, self.validated.launcher, self.validated.qemu):
            for image in (chain.entry, chain.image, chain.interpreter):
                if image: admitted_targets.add(image.realpath)
        _require(all(self._resolve(path) in {self._resolve(p) for p in admitted_targets} for path in farm_paths),
                 "farm contains an unapproved executable or link")

    def _runtime(self):
        d = self.documents["controller_distribution"]; producer = d["producer"]
        layout = producer["runtime_layout"]
        _mapping(layout, {"controller_interpreter", "controller_stdlib", "runner_stdlib", "runner_site_packages", "qemu_module_root", "qemu_data_root"})
        for path in layout.values(): _bounded_path(path)
        observed = self._step("runtime-observation", "self", self.backend.runtime_observation)
        _mapping(observed, {"interpreter", "base_prefix", "version", "sys_path", "module_path", "distribution_path", "mapped_files"})
        version = observed["version"]
        _require(type(version) is list and len(version) == 2 and all(type(n) is int and n >= 0 for n in version)
                 and version[0] == 3 and version[1] >= 11, "unsupported observed controller interpreter")
        stdlib = _bounded_path(observed["base_prefix"]) + "/lib/python" + ".".join(map(str, version))
        _require(layout["controller_interpreter"] == observed["interpreter"] and layout["controller_stdlib"] == stdlib,
                 "actual interpreter layout differs")
        self._regular(layout["controller_interpreter"])
        runner_layouts = set()
        for chain in (self.validated.runner, self.validated.launcher):
            _require(chain.interpreter is not None, "runner interpreter layout is not supplied")
            match = re.fullmatch(r"(.+)/bin/python(3\.\d+)", chain.interpreter.realpath)
            _require(match is not None and "/bin/" in chain.interpreter.path, "ambiguous admitted interpreter version layout")
            environment = chain.interpreter.path.rsplit("/bin/", 1)[0]
            pair = (match[1] + "/lib/python" + match[2], environment + "/lib/python" + match[2] + "/site-packages")
            runner_layouts.add(pair)
            for module in chain.modules:
                _require(any(module.identity.realpath == root or _inside(module.identity.realpath, root) for root in pair),
                         "admitted module resolves outside required Python roots")
                self._regular(module.identity.path, module.identity.sha256, module.identity.size)
        _require(len(runner_layouts) == 1 and next(iter(runner_layouts)) == (layout["runner_stdlib"], layout["runner_site_packages"]),
                 "runner/launcher layouts differ")
        _require((layout["qemu_module_root"], layout["qemu_data_root"]) == (_QEMU_MODULE_ROOT, _QEMU_DATA_ROOT),
                 "QEMU layout is outside the admitted profile")
        derived = {(stdlib, "python-stdlib"), (layout["runner_stdlib"], "python-stdlib"),
                   (layout["runner_site_packages"], "python-site-packages"), (_QEMU_MODULE_ROOT, "qemu-modules"), (_QEMU_DATA_ROOT, "qemu-data")}
        _require({(r["path"], r["purpose"]) for r in d["coverage"]["runtime_roots"]} == derived,
                 "mandatory runtime root omitted or substituted")
        _require(len({path for path, _ in derived}) == len(derived)
                 and not any(_inside(a, b) for a, _ in derived for b, _ in derived if a != b), "overlapping runtime roots")
        purelib = producer["install_scheme"]["purelib"]
        allowed = {stdlib, stdlib + "/lib-dynload", purelib}
        zip_candidate = observed["base_prefix"] + "/lib/python" + "".join(map(str, version)) + ".zip"
        _require(type(observed["sys_path"]) is list and all(path in allowed or path == zip_candidate and not os.path.lexists(path)
                                                          for path in observed["sys_path"]), "actual import path escapes admitted roots")
        _require(observed["module_path"] == purelib + "/mojobpf/target_controller.py", "controller was imported from a source fallback")
        _require(type(observed["mapped_files"]) is list, "mapped runtime identity is unavailable")
        for path in observed["mapped_files"]:
            self._regular(_bounded_path(path))
        return observed

    def _wheel(self, observation):
        d = self.documents["controller_distribution"]; p = d["producer"]; c = d["coverage"]
        _mapping(p["install_scheme"], {"purelib", "data", "scripts"})
        scheme = p["install_scheme"]
        for value in scheme.values(): _bounded_path(value)
        install = c["install_root"]
        _require(scheme["data"] == install and scheme["scripts"] == install + "/bin"
                 and re.fullmatch(re.escape(install) + r"/lib/python3\.\d+/site-packages", scheme["purelib"]), "installed scheme differs")
        wheel = _bounded_path(p["wheel_path"])
        _require(str(Path(wheel).parent) == c["producer_root"] and wheel in self.roles["controller"], "producer root is not the wheel parent")
        sources = {}
        for row in _sorted_rows(p["sources"], "path", _CLOSURE_COUNTS["sources"]):
            _mapping(row, {"path", "sha256"}); _bounded_path(row["path"], relative=True)
            sources[row["path"]] = _hash(row["sha256"])
        members = {}
        for row in _sorted_rows(p["wheel_members"], "member", _CLOSURE_COUNTS["wheel_members"]):
            _mapping(row, {"member", "sha256", "size", "source_path", "installed_path"})
            _bounded_path(row["member"], relative=True); _hash(row["sha256"]); _integer(row["size"])
            _require(row["size"] <= _WHEEL_MEMBER_BYTES, "wheel member exceeds bound")
            if row["source_path"] is not None:
                _bounded_path(row["source_path"], relative=True)
                _require(sources.get(row["source_path"]) == row["sha256"], "wheel/source byte correspondence differs")
            if row["installed_path"] is not None: _bounded_path(row["installed_path"])
            members[row["member"]] = row
        raw = self._content(wheel, maximum=_WHEEL_BYTES, capture=True)
        try:
            archive = zipfile.ZipFile(io.BytesIO(raw))
            with archive:
                infos = archive.infolist()
                _require(len(infos) <= _CLOSURE_COUNTS["wheel_members"] and len(infos) == len({i.filename for i in infos})
                         and set(members) == {i.filename for i in infos}, "archive member inventory differs")
                _require(sum(i.file_size for i in infos) <= _WHEEL_EXPANDED, "declared wheel expansion exceeds bound")
                total, metadata = 0, {}
                for info in infos:
                    name = _bounded_path(info.filename, relative=True)
                    mode = info.external_attr >> 16
                    _require(not info.is_dir() and not info.flag_bits & 1 and (stat.S_IFMT(mode) in (0, stat.S_IFREG))
                             and info.file_size <= _WHEEL_MEMBER_BYTES and not name.lower().endswith((".so", ".pyd", ".dll", ".dylib")),
                             "wheel has a native, encrypted or nonregular member")
                    hashed, size, header, content = hashlib.sha256(), 0, bytearray(), bytearray()
                    with archive.open(info) as stream:
                        while True:
                            chunk = self._step("wheel-member-read", name, lambda: stream.read(1024 * 1024))
                            if not chunk: break
                            size += len(chunk); total += len(chunk)
                            _require(size <= _WHEEL_MEMBER_BYTES and total <= _WHEEL_EXPANDED, "streamed wheel expansion exceeds bound")
                            hashed.update(chunk)
                            if len(header) < 4: header.extend(chunk[:4-len(header)])
                            if ".dist-info/" in name: content.extend(chunk)
                    _require(bytes(header) not in {b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}
                             and not bytes(header).startswith(b"MZ"), "wheel contains native executable content")
                    row = members[name]
                    _require(size == row["size"] == info.file_size and hashed.hexdigest() == row["sha256"], "actual wheel member bytes differ")
                    if ".dist-info/" in name: metadata[name] = bytes(content)
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, EOFError) as exc:
            raise ControllerError("ADMISSION_REFUSED", "wheel is not a bounded valid archive") from exc
        distinfos = {name.split("/", 1)[0] for name in members if ".dist-info/" in name}
        _require(len(distinfos) == 1, "wheel has no unique distribution metadata")
        distinfo = next(iter(distinfos)); _require(distinfo.startswith("mojobpf-") and distinfo.endswith(".dist-info"), "wheel distribution identity differs")
        required_metadata = {distinfo + "/" + name for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")}
        _require(required_metadata <= members.keys() and observation["distribution_path"] == scheme["purelib"] + "/" + distinfo,
                 "installed distribution location differs")
        try:
            from email.parser import BytesParser
            meta = BytesParser().parsebytes(metadata[distinfo + "/METADATA"])
            wh = BytesParser().parsebytes(metadata[distinfo + "/WHEEL"])
            _require(meta.get_all("Name") == ["mojobpf"] and meta.get_all("Version") == [distinfo[len("mojobpf-"):-len(".dist-info")]]
                     and wh.get_all("Root-Is-Purelib") == ["true"] and wh.get_all("Wheel-Version") == ["1.0"]
                     and wh.get_all("Tag") == ["py3-none-any"], "wheel metadata does not name the pure Python distribution")
            parser = configparser.ConfigParser(interpolation=None, strict=True); parser.optionxform = str
            parser.read_string(metadata[distinfo + "/entry_points.txt"].decode("utf-8"))
            scripts = set(parser["console_scripts"]) if parser.has_section("console_scripts") else set()
            _require(all(_IDENTIFIER.fullmatch(name) for name in scripts), "invalid generated script name")
        except (ValueError, UnicodeError, configparser.Error) as exc:
            raise ControllerError("ADMISSION_REFUSED", "invalid wheel metadata") from exc
        destinations = set(); schema_members = set()
        for name, row in members.items():
            if row["source_path"] is None:
                _require(name in required_metadata, "metadata source exception used for runtime content")
            if name == distinfo + "/RECORD":
                _require(row["installed_path"] is None, "archive RECORD is not installed RECORD authority")
                continue
            if ".data/" in name:
                prefix, separator, suffix = name.partition(".data/data/")
                _require(separator and prefix == distinfo[:-len(".dist-info")] and suffix,
                         "unapproved wheel installation scheme")
                destination = scheme["data"] + "/" + suffix
                schema_members.add(suffix)
            else: destination = scheme["purelib"] + "/" + name
            _require(row["installed_path"] == destination and destination not in destinations and _inside(destination, install)
                     and destination in self.roles["controller"], "installed member mapping differs")
            destinations.add(destination); self._regular(destination, row["sha256"], row["size"])
        _require(schema_members == {"share/mojobpf/schemas/" + name + ".schema.json" for name in ("cost", "fixture", "result", "run-plan", "target")},
                 "five shipped schemas are not mapped exactly")
        generated, kinds = set(), {}
        allowed_generated = {scheme["purelib"] + "/" + distinfo + "/" + basename: kind for basename, kind in
                             (("RECORD", "record"), ("INSTALLER", "installer"), ("REQUESTED", "requested"), ("direct_url.json", "direct_url"))}
        allowed_generated.update({scheme["scripts"] + "/" + name: "entrypoint" for name in scripts})
        for row in _sorted_rows(p["installed_generated"], "path", _CLOSURE_COUNTS["installed_generated"]):
            _mapping(row, {"path", "kind"}); path = _bounded_path(row["path"])
            _require(allowed_generated.get(path) == row["kind"] and path not in destinations and path in self.roles["controller"],
                     "unapproved or overlapping generated install file")
            generated.add(path); kinds[path] = row["kind"]; self._regular(path)
        required_generated = {path for path, kind in allowed_generated.items() if kind in {"record", "installer", "entrypoint"}}
        _require(required_generated <= generated, "required generated install file missing")
        installed = {path for path, row in self.rows.items() if _inside(path, install) and row["kind"] != "directory"}
        for path in self.rows:
            if path == install or _inside(path, install):
                _require(not path.endswith(".pyc") and "__pycache__" not in Path(path).parts, "installed controller has stale bytecode")
        support = installed - destinations - generated
        allowed_support = re.compile(re.escape(install) + r"/(?:pyvenv\.cfg|bin/(?:python(?:3(?:\.\d+)?)?|activate(?:\.csh|\.fish)?|Activate\.ps1))\Z")
        _require(all(path in self.roles["runtime"] and allowed_support.fullmatch(path) for path in support),
                 "install tree contains an unexplained runtime member")
        self.wheel_count = len(members)

    def verify(self):
        first_error, result = None, None
        try:
            self._refresh_inputs(); self._shape(); self._retain_directories(); self._inventory()
            self._legacy_roles(); observed = self._runtime(); self._wheel(observed)
            for path, row in self.rows.items():
                if row["kind"] == "regular": self._content(path)
            self._inventory(); self._check_directories(); self._refresh_inputs()
            for path, row in self.rows.items():
                self._matches(path, self._step("final-lstat", path, lambda p=path: os.lstat(p)))
                _require(self._resolve(path) == row["realpath"], "component resolution changed during closure pass")
            _require(json_equal(observed, self._step("runtime-observation", "self", self.backend.runtime_observation)),
                     "in-process runtime layout changed during refresh")
            result = {"files": len(self.rows), "inventories": len(self.inventories),
                      "wheel_members": self.wheel_count, "unique_bytes": self.total}
        except Exception as exc:
            first_error = exc
        finally:
            for path, fd in list(self.directories.items()):
                del self.directories[path]  # A consumed-then-error close never reuses the numeric handle.
                try: self._release_handle("directory-close", path, fd)
                except Exception as exc:
                    if first_error is None: first_error = exc
        if first_error is not None: raise first_error
        self.budget.check()
        return result


def _release_known_fd(backend, budget, fd):
    """One release attempt, with late/error outcomes retained by the caller."""
    errors = []
    for action in (budget.check, lambda: backend.close(fd), budget.check):
        try: action()
        except OSError as exc: errors.append(ControllerError("IO_FAILED", "owned handle close failed", errno=exc.errno))
        except ControllerError as exc: errors.append(exc)
    return tuple(errors)


class _LaneLease:
    def __init__(self, validated, *, budget, _backend=None):
        _execution_authority(validated)
        self.validated, self.budget, self.backend = validated, budget, _backend or _PersistenceBackend()
        self.fd, self.identity = None, None
        _require(not os.path.lexists(validated.paths.lease_journal) and not os.path.lexists(validated.paths.controller_output),
                 "prior controller history requires separate recovery authority", "LEASE_REQUIRED")
        parent = None
        try:
            budget.check()
            parent = _open_parent(validated.lock.path)
            self.fd = os.open(Path(validated.lock.path).name, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            info = os.fstat(self.fd)
            wanted = validated.lock
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                     and (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) ==
                     (wanted.dev, wanted.ino, wanted.owner_uid, wanted.mode), "precreated lock identity changed", "LEASE_REQUIRED")
            self.identity = _stat_identity(info) + (info.st_uid, info.st_gid)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.verify()
        except OSError as exc:
            self.close()
            raise ControllerError("LEASE_REQUIRED", "exclusive lease lock is unavailable", errno=exc.errno) from exc
        except BaseException:
            self.close()
            raise
        finally:
            if parent is not None: os.close(parent)

    def verify(self):
        _require(self.fd is not None, "lease handle is no longer usable", "LEASE_REQUIRED")
        self.budget.check()
        parent = None
        try:
            parent = _open_parent(self.validated.lock.path)
            named = os.stat(Path(self.validated.lock.path).name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(self.fd)
            _require(_stat_identity(named) + (named.st_uid, named.st_gid) == self.identity ==
                     _stat_identity(held) + (held.st_uid, held.st_gid), "retained lock or pathname was replaced", "LEASE_REQUIRED")
        except OSError as exc:
            raise ControllerError("LEASE_REQUIRED", "lease identity cannot be refreshed", errno=exc.errno) from exc
        finally:
            if parent is not None: os.close(parent)
        self.budget.check()

    def close(self):
        if self.fd is None: return ()
        fd, self.fd = self.fd, None
        # Closing the retained file description releases flock. No numeric fd retry.
        return _release_known_fd(self.backend, self.budget, fd)


class _OwnedDirectory:
    def __init__(self, path, *, budget, _backend=None, create=False):
        self.path, self.budget = _absolute_path(path), budget
        self.backend, self.fd, self.identity = _backend or _PersistenceBackend(), None, None
        parent = None
        try:
            self.budget.check()
            parent = _open_parent(path)
            if create: os.mkdir(Path(path).name, 0o700, dir_fd=parent)
            self.fd = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            if create: os.fchmod(self.fd, 0o700)
            info = os.fstat(self.fd)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                     "owned directory requires the controller owner and mode 0700", "IO_FAILED")
            self.identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            if create:
                self.backend.fsync(parent)
                self.backend.fsync(self.fd)
            self.verify()
        except OSError as exc:
            self.close()
            raise ControllerError("IO_FAILED", "owned directory cannot be opened exclusively", errno=exc.errno) from exc
        except BaseException:
            self.close()
            raise
        finally:
            if parent is not None: os.close(parent)

    def verify(self):
        _require(self.fd is not None, "owned directory handle is unavailable", "IO_FAILED")
        self.budget.check()
        parent = None
        try:
            parent = _open_parent(self.path)
            named = os.stat(Path(self.path).name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(self.fd)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            _require(stat.S_ISDIR(named.st_mode) and stat.S_ISDIR(held.st_mode)
                     and identity(named) == identity(held) == self.identity, "owned directory was replaced or changed", "IO_FAILED")
        except OSError as exc:
            raise ControllerError("IO_FAILED", "owned directory cannot be revalidated", errno=exc.errno) from exc
        finally:
            if parent is not None: os.close(parent)
        self.budget.check()

    def empty_observation(self):
        self.verify()
        before = os.fstat(self.fd)
        entries = []
        with os.scandir(self.fd) as observed:
            for item in observed:
                self.budget.check()
                _require(len(entries)<_CLOSURE_COUNTS["edges"], "cache inventory exceeds its bound", "IO_FAILED")
                entries.append(item.name)
        entries.sort()
        after = os.fstat(self.fd)
        _require(_stat_identity(before) == _stat_identity(after), "cache changed during its inventory", "IO_FAILED")
        self.verify()
        return {"path": self.path, "dev": after.st_dev, "ino": after.st_ino, "entries": entries, "empty": not entries}

    def close(self):
        if self.fd is None: return ()
        fd, self.fd = self.fd, None
        return _release_known_fd(self.backend, self.budget, fd)


@dataclass(frozen=True)
class _GuestCapture:
    name: str
    raw: bytes
    identity: tuple
    parsed: _FrozenObject | None

    @property
    def value(self): return _thaw(self.parsed)


class _GuestExport(_OwnedDirectory):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.partial_bytes = []

    def _preserve_partial(self, name, content):
        pair = (name, content)
        if pair not in self.partial_bytes:
            _require(len(self.partial_bytes) < 256
                     and sum(len(raw) for _, raw in self.partial_bytes) + len(content) <= JSON_LIMIT,
                     "partial guest captures exceed bound", "EVIDENCE_INVALID")
            self.partial_bytes.append(pair)

    def capture(self, name, *, partial=False, optional=False, structured=True):
        _bounded_path(name, relative=True)
        _require("/" not in name, "guest capture requires a direct basename", "EVIDENCE_INVALID")
        self.verify()
        fd = None
        try:
            try:
                fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            except FileNotFoundError:
                if optional or partial: return None
                raise
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
                     and before.st_size <= JSON_LIMIT, "guest file is not bounded owned regular data", "EVIDENCE_INVALID")
            chunks, size = [], 0
            while True:
                self.budget.check()
                self.backend.checkpoint("guest-read", name)
                raw = self.backend.read(fd, min(65536, JSON_LIMIT - size + 1))
                self.backend.checkpoint("after-guest-read", name)
                self.budget.check()
                _require(type(raw) is bytes, "guest reader returned nonbytes", "IO_FAILED")
                if not raw: break
                size += len(raw); _require(size <= JSON_LIMIT, "guest stream exceeds JSON bound", "EVIDENCE_INVALID")
                chunks.append(raw)
            after = os.fstat(fd); named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            content = b"".join(chunks)
            stable = _stat_identity(before) == _stat_identity(after) == _stat_identity(named) and size == before.st_size
            if partial and not stable:
                identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink)
                _require(stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                         and identity(before) == identity(after) == identity(named)
                         and after.st_size <= JSON_LIMIT and named.st_size <= JSON_LIMIT,
                         "guest file identity changed while being written", "EVIDENCE_INVALID")
                self._preserve_partial(name, content)
                self.verify()
                return None
            _require(stable,
                     "guest file changed during capture", "EVIDENCE_INVALID")
            if not structured:
                self.verify()
                return _GuestCapture(name, content, _stat_identity(after), None)
            try: value = _strict_json(content)
            except ControllerError as exc:
                cause = exc.__cause__
                incomplete = (type(cause) is json.JSONDecodeError and
                              (cause.pos >= len(cause.doc.rstrip()) - 1 or cause.msg.startswith("Unterminated string")))
                if partial and incomplete:
                    self._preserve_partial(name, content)
                    return None
                raise ControllerError("EVIDENCE_INVALID", "guest JSON is invalid or ambiguous") from exc
            self.verify()
            return _GuestCapture(name, content, _stat_identity(after), _freeze(value))
        except OSError as exc:
            raise ControllerError("IO_FAILED", "guest file cannot be captured safely", errno=exc.errno) from exc
        finally:
            if fd is not None:
                errors = _release_known_fd(self.backend, self.budget, fd)
                if errors: raise errors[0]

    def revalidate(self, captured):
        current = self.capture(captured.name,structured=captured.parsed is not None)
        _require(current.raw == captured.raw and current.identity == captured.identity,
                 "guest marker or observation changed after consumption", "EVIDENCE_INVALID")


@dataclass(frozen=True)
class _Artifact:
    relative: str
    raw: bytes
    identity: tuple[int, ...]

    @property
    def reference(self):
        return {"path": self.relative, "sha256": hashlib.sha256(self.raw).hexdigest()}


@dataclass
class _AppendFile:
    path: str
    fd: int
    identity: tuple[int, int]
    size: int = 0


class _OwnedStore:
    """Exclusive owned artifacts and retained no-follow directory identities.

    A failed close consumes the handle from the usable set before the call.
    No later operation retries that numeric descriptor. Partial names remain.
    """
    def __init__(self, root, *, output_root, budget, _backend=None):
        self.root, self.output_root, self._budget = _absolute_path(root), _absolute_path(output_root), budget
        _require(_inside(self.root, self.output_root), "artifact root escapes output", "ADMISSION_REFUSED")
        self._io = _backend or _PersistenceBackend()
        self._directories, self._fds, self._appenders = {}, {}, {}
        self._poisoned, self._closed = False, False
        parent = _open_parent(self.root)
        try:
            self._budget.check()
            os.mkdir(Path(self.root).name, 0o700, dir_fd=parent)
            fd = os.open(Path(self.root).name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            self._fds[fd] = "."
            os.fchmod(fd, 0o700)
            self._directories[""] = (fd, self._directory_identity(os.fstat(fd)))
            self._call("directory-fsync", ".", lambda: self._io.fsync(parent))
        except OSError as exc:
            self._poisoned = True
            self.close()
            raise ControllerError("IO_FAILED", "exclusive controller directory unavailable", errno=exc.errno) from exc
        except BaseException:
            self._poisoned = True
            self.close()
            raise
        finally:
            os.close(parent)

    @staticmethod
    def _directory_identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))

    def _relative(self, path):
        _require(type(path) is str and path and not path.startswith("/") and "\\" not in path
                 and "\x00" not in path and all(part not in ("", ".", "..") for part in path.split("/")),
                 "artifact path must be a normalized relative path", "EVIDENCE_INVALID")
        return path

    def _usable(self):
        _require(not self._closed and not self._poisoned, "owned persistence is permanently refused", "IO_FAILED")

    def _check_directories(self):
        for path, (fd, identity) in self._directories.items():
            observed = os.fstat(fd)
            _require(stat.S_ISDIR(observed.st_mode) and self._directory_identity(observed) == identity,
                     "retained directory identity changed", "IO_FAILED")
            if path:
                parent, name = path.rsplit("/", 1) if "/" in path else ("", path)
                named = os.stat(name, dir_fd=self._directories[parent][0], follow_symlinks=False)
            else:
                parent_fd = _open_parent(self.root)
                try: named = os.stat(Path(self.root).name, dir_fd=parent_fd, follow_symlinks=False)
                finally: os.close(parent_fd)
            _require(stat.S_ISDIR(named.st_mode) and self._directory_identity(named) == identity,
                     "owned directory was replaced or aliased", "IO_FAILED")

    def _call(self, operation, path, action):
        self._usable()
        try:
            self._budget.check()
            self._check_directories()
            self._io.checkpoint("before-" + operation, path)
            self._budget.check()
            result = action()
            self._io.checkpoint("after-" + operation, path)
            self._budget.check()
            self._check_directories()
            return result
        except (ControllerError, OSError) as exc:
            self._poisoned = True
            if isinstance(exc, ControllerError): raise
            raise ControllerError("IO_FAILED", "owned " + operation + " failed: " + path, errno=exc.errno) from exc

    def _release_fd(self, fd, path):
        # Remove authority immediately before close; an unattempted handle remains.
        _require(fd in self._fds, "descriptor is already released or uncertain", "IO_FAILED")
        first_error = None
        try: self._budget.check()
        except ControllerError as exc: first_error = exc
        try:
            self._io.checkpoint("before-close", path)
            self._fds.pop(fd)
            self._io.close(fd)
            self._io.checkpoint("after-close", path)
            self._budget.check()
        except (ControllerError, OSError) as exc:
            if first_error is None:
                first_error = exc if isinstance(exc, ControllerError) else ControllerError("IO_FAILED", "owned close uncertain: " + path, errno=exc.errno)
        if first_error is not None:
            self._poisoned = True
            raise first_error

    def _open_fd(self, path, name, flags, parent, mode=0o600):
        # Retain before any fallible post-open acknowledgement/time check.
        fd = os.open(name, flags, mode, dir_fd=parent)
        self._fds[fd] = path
        return fd

    def mkdir(self, path):
        path = self._relative(path)
        for index in range(1, len(path.split("/")) + 1):
            current = "/".join(path.split("/")[:index])
            if current in self._directories: continue
            parent, name = current.rsplit("/", 1) if "/" in current else ("", current)
            parent_fd = self._directories[parent][0]
            self._call("mkdir", current, lambda: os.mkdir(name, 0o700, dir_fd=parent_fd))
            fd = self._call("open-directory", current, lambda: self._open_fd(current, name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, parent_fd))
            self._directories[current] = (fd, self._directory_identity(os.fstat(fd)))
            self._call("directory-fsync", current, lambda: self._io.fsync(parent_fd))

    def _parent(self, path):
        path = self._relative(path)
        parent, name = path.rsplit("/", 1) if "/" in path else ("", path)
        _require(parent in self._directories, "artifact parent was not exclusively created", "IO_FAILED")
        return self._directories[parent][0], name

    def open_append(self, path):
        parent, name = self._parent(path)
        fd = self._call("create", path, lambda: self._open_fd(path, name, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, parent))
        info = os.fstat(fd)
        writer = _AppendFile(path, fd, (info.st_dev, info.st_ino))
        self._appenders[path] = writer
        self._call("directory-fsync", path, lambda: self._io.fsync(parent))
        return writer

    def append(self, writer, raw):
        _require(type(raw) is bytes and writer.fd in self._fds and self._appenders.get(writer.path) is writer,
                 "append writer is not retained", "IO_FAILED")
        parent, name = self._parent(writer.path)
        def check():
            observed, named = os.fstat(writer.fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
            _require(stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1 and observed.st_uid == os.geteuid()
                     and (observed.st_dev, observed.st_ino) == writer.identity
                     and _stat_identity(observed) == _stat_identity(named) and observed.st_size == writer.size,
                     "append artifact changed or aliased", "IO_FAILED")
        self._call("append-identity", writer.path, check)
        self._write_all(writer.fd, writer.path, raw)
        writer.size += len(raw)
        self._call("fsync", writer.path, lambda: self._io.fsync(writer.fd))
        self._call("append-identity", writer.path, check)

    def _write_all(self, fd, path, raw):
        offset = 0
        while offset < len(raw):
            amount = self._call("write", path, lambda: self._io.write(fd, memoryview(raw)[offset:]))
            _require(type(amount) is int and 0 < amount <= len(raw) - offset, "invalid or stalled write", "IO_FAILED")
            offset += amount

    def readback(self, path, expected, *, maximum, identity=None):
        _require(type(expected) is bytes and len(expected) <= maximum, "readback byte bound exceeded", "EVIDENCE_INVALID")
        parent, name = self._parent(path)
        fd = self._call("open-readback", path, lambda: self._open_fd(path, name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, parent))
        result = None
        try:
            before = self._call("readback-stat", path, lambda: os.fstat(fd))
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
                     and before.st_size == len(expected) <= maximum
                     and (identity is None or _stat_identity(before) == identity),
                     "readback is not the committed single-link identity/size", "IO_FAILED")
            chunks, size = [], 0
            while True:
                raw = self._call("read", path, lambda: self._io.read(fd, min(65536, maximum + 1 - size)))
                if not raw: break
                size += len(raw)
                _require(size <= maximum, "readback exceeded byte bound", "IO_FAILED")
                chunks.append(raw)
            after = self._call("readback-stat", path, lambda: os.fstat(fd))
            named = self._call("readback-path", path, lambda: os.stat(name, dir_fd=parent, follow_symlinks=False))
            raw = b"".join(chunks)
            _require(_stat_identity(before) == _stat_identity(after) == _stat_identity(named)
                     and size == before.st_size and raw == expected,
                     "readback bytes or identity changed", "IO_FAILED")
            relative = str(Path(self.root).relative_to(self.output_root) / path)
            result = _Artifact(relative, raw, _stat_identity(after))
            self._call("readback", path, lambda: None)
        finally:
            self._release_fd(fd, path)
        return result

    def persist(self, path, raw, *, maximum):
        _require(type(raw) is bytes and len(raw) <= maximum, "artifact byte bound exceeded", "EVIDENCE_INVALID")
        parent, name = self._parent(path)
        fd = self._call("create", path, lambda: self._open_fd(path, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, parent))
        try:
            self._write_all(fd, path, raw)
            self._call("fsync", path, lambda: self._io.fsync(fd))
        finally:
            self._release_fd(fd, path)
        self._call("directory-fsync", path, lambda: self._io.fsync(parent))
        return self.readback(path, raw, maximum=maximum)

    def revalidate(self, artifact, *, maximum):
        relative = str(Path(artifact.relative).relative_to(Path(self.root).relative_to(self.output_root)))
        return self.readback(relative, artifact.raw, maximum=maximum, identity=artifact.identity)

    def close(self):
        """Release known handles once; failures cannot authorize completion."""
        failures = []
        for fd, path in reversed(tuple(self._fds.items())):
            try: self._release_fd(fd, path)
            except ControllerError as exc: failures.append(exc)
        self._closed = True
        return tuple(failures)


@dataclass(frozen=True)
class _CommittedCompletion:
    invocation: _Invocation
    prefix: _Artifact
    receipt: _Artifact
    result: _FrozenObject
    first: int
    last: int


class _CompletionBarrier:
    """Caller authority after fixed-byte replay and a durable context commit."""
    def __init__(self, validated, store, *, budget, controller_identity):
        self._validated, self._store, self._budget = validated, store, budget
        self._controller_identity = _freeze(controller_identity)
        self._guardian_bytes = bytearray()
        self._guardian_count, self._transitions = 0, bytearray()
        self._committed, self._active, self._failed = [], None, False
        self._expected_sequence, self._prepared = None, False
        self._guardian_writer = store.open_append("guardian.active.jsonl")
        self._transition_writer = store.open_append("transitions.active.jsonl")

    @property
    def guardian_records(self):
        return [_strict_json(raw) for raw in bytes(self._guardian_bytes).splitlines()]

    @property
    def accepted(self): return [_thaw(item.result) for item in self._committed]

    @property
    def may_prepare(self): return not self._failed and not self._store._poisoned and self._active is None

    def _refuse(self, exc):
        self._failed = True
        if isinstance(exc, ControllerError): return exc
        return ControllerError("IO_FAILED", "completion persistence failed", errno=getattr(exc, "errno", None))

    def transition(self, event, *, invocation=None, data=None):
        v = self._validated
        record = {"schema_version": 2, "contract": "controller-transition-v2", "sequence": self._transitions.count(b"\n") + 1,
                  "time": self._budget.check(), "run_id": v.run_id, "lane_id": v.lane_id,
                  "lease_sha256": v.lease_sha256, "proposal_sha256": v.proposal_sha256,
                  "controller_distribution_sha256": dict((n, b.file_sha256) for n, b, _ in v.inputs)["controller_distribution"],
                  "event": event, "phase": None if invocation is None else invocation.phase,
                  "attempt_id": None if invocation is None else invocation.attempt_id, "data": data or {}}
        raw = _json_bytes(record) + b"\n"
        _require(len(self._transitions) + len(raw) <= JSON_LIMIT, "controller journal byte bound exceeded", "IO_FAILED")
        self._store.append(self._transition_writer, raw)
        self._transitions.extend(raw)
        self._store.readback("transitions.active.jsonl", bytes(self._transitions), maximum=JSON_LIMIT)
        return _freeze(record)

    def open_attempt(self, invocation):
        try:
            _require(self.may_prepare and len(self._committed) < 3
                     and invocation is self._validated.invocations[len(self._committed)],
                     "next epoch lacks immutable caller completion authority", "EVIDENCE_INVALID")
            self.verify_committed()
            self._budget.cleanup_deadline = None
            self._active, self._prepared = invocation, False
            self._expected_sequence = self._guardian_count + 1
            self._store.mkdir("attempts/" + invocation.attempt_id)
            self.transition("attempt-open", invocation=invocation,
                            data={"expected_guardian_sequence": self._expected_sequence})
        except (ControllerError, OSError) as exc: raise self._refuse(exc)

    def guardian_record(self, record):
        try:
            _require(not self._failed and self._active is not None, "guardian event has no active caller epoch", "IO_FAILED")
            raw = _json_bytes(record)
            _require(len(raw) <= _GUARDIAN_RECORD_LIMIT and self._guardian_count < _GUARDIAN_RECORD_COUNT
                     and len(self._guardian_bytes) + len(raw) + 1 <= _GUARDIAN_PREFIX_LIMIT,
                     "whole lane guardian byte/record bound exceeded", "IO_FAILED")
            captured = _strict_json(raw)
            _require(type(captured.get("sequence")) is int and captured["sequence"] == self._guardian_count + 1,
                     "guardian global sequence is not contiguous from one", "EVIDENCE_INVALID")
            if not self._prepared:
                _require(captured.get("event") == "prepared" and captured["sequence"] == self._expected_sequence
                         and json_equal(captured.get("controller_identity"), _thaw(self._controller_identity)),
                         "prepared event does not bind active attempt/controller", "EVIDENCE_INVALID")
                self._prepared = True
            else:
                _require(captured.get("event") != "prepared", "duplicate prepared event within active attempt", "EVIDENCE_INVALID")
            if captured.get("event") == "cleanup-entered":
                _require(self._budget.cleanup_deadline is None and type(captured.get("deadline")) in (int, float)
                         and math.isfinite(captured["deadline"]), "cleanup deadline is missing or repeated", "EVIDENCE_INVALID")
                self._budget.cleanup_deadline = captured["deadline"]
            self._store.append(self._guardian_writer, raw + b"\n")
            self._guardian_bytes.extend(raw + b"\n")
            self._guardian_count += 1
        except (ControllerError, OSError) as exc: raise self._refuse(exc)

    @staticmethod
    def _replay(prefix, receipt):
        result = replay_completion(prefix, receipt)
        _require(result["status"] == "CLEAN", "fixed completion replay refused: " + str(result["failures"]), "EVIDENCE_INVALID")
        return result

    def verify_committed(self):
        try:
            _require(not self._failed, "failed caller barrier cannot be resumed", "IO_FAILED")
            for item in self._committed:
                self._store.revalidate(item.prefix, maximum=_GUARDIAN_PREFIX_LIMIT)
                self._store.revalidate(item.receipt, maximum=4096)
                self._replay(item.prefix.raw, item.receipt.raw)
            self._store.readback("transitions.active.jsonl", bytes(self._transitions), maximum=JSON_LIMIT)
        except (ControllerError, OSError) as exc: raise self._refuse(exc)

    def commit(self, returned):
        try:
            _require(not self._failed and self._active is not None and self._prepared,
                     "no acknowledged active epoch", "IO_FAILED")
            frozen_return = _freeze(_strict_json(_json_bytes(returned)))
            observed = _thaw(frozen_return)
            receipt_value = observed.get("completion_receipt")
            _require(observed.get("status") == "CLEAN" and type(receipt_value) is dict,
                     "guardian finalization lacks clean synchronous receipt", "CLEANUP_INCOMPLETE")
            receipt_bytes = _json_bytes(receipt_value) + b"\n"
            prefix_bytes = bytes(self._guardian_bytes)
            _require(len(receipt_bytes) <= 4096 and prefix_bytes.endswith(b"\n"),
                     "completion byte bound or newline is invalid", "EVIDENCE_INVALID")
            records = self.guardian_records
            first, last = receipt_value.get("epoch_first_sequence"), receipt_value.get("epoch_last_sequence")
            _require(type(first) is int and type(last) is int and first == self._expected_sequence
                     and last == records[-1]["sequence"] and records[0]["sequence"] == 1
                     and receipt_value.get("deadline") == self._budget.cleanup_deadline,
                     "receipt range/end/deadline does not bind caller attempt", "EVIDENCE_INVALID")
            previous = self._committed[-1] if self._committed else None
            _require(previous is None or prefix_bytes.startswith(previous.prefix.raw)
                     and first == previous.last + 1, "earlier fixed-byte prefix was omitted or rewritten", "EVIDENCE_INVALID")
            _require(sum(r["event"] == "prepared" for r in records) == len(self._committed) + 1,
                     "prefix does not contain exactly one new epoch", "EVIDENCE_INVALID")
            replay = self._replay(prefix_bytes, receipt_bytes)
            physical = replay["physical_drain"]
            _require(all(json_equal(observed.get(field), physical[field]) for field in
                         ("subreaper_readback", "scans", "adoptions", "final_echild", "unresolved_live", "all_pidfds_exited",
                          "mountinfo_before", "mountinfo_after", "failures", "processes", "runner_exit"))
                     and all(json_equal(observed.get(field), replay["release"][field]) for field in replay["release"]),
                     "mutable finish values disagree with fixed physical/release facts", "EVIDENCE_INVALID")
            _require(json_equal(records[first - 1]["controller_identity"], _thaw(self._controller_identity)),
                     "completion belongs to a foreign controller", "EVIDENCE_INVALID")
            self.verify_committed()
            for item in self._committed: self._replay(prefix_bytes, item.receipt.raw)
            base = "attempts/" + self._active.attempt_id + "/"
            prefix = self._store.persist(base + "guardian-prefix.jsonl", prefix_bytes, maximum=_GUARDIAN_PREFIX_LIMIT)
            receipt = self._store.persist(base + "guardian-receipt.json", receipt_bytes, maximum=4096)
            self._replay(prefix.raw, receipt.raw)
            self.transition("completion-committed", invocation=self._active,
                            data={"epoch_first_sequence": first, "epoch_last_sequence": last,
                                  "completion_journal": prefix.reference, "completion_receipt": receipt.reference})
            self._budget.check()
            cleanup = {key: physical[key] for key in ("subreaper_readback", "scans", "adoptions", "final_echild",
                       "unresolved_live", "all_pidfds_exited", "mountinfo_before", "mountinfo_after")}
            cleanup.update(status="CLEAN", completion_journal=prefix.reference, completion_receipt=receipt.reference)
            accepted = _freeze({"cleanup": cleanup, "processes": physical["processes"], "runner_exit": physical["runner_exit"]})
            self._committed.append(_CommittedCompletion(self._active, prefix, receipt, accepted, first, last))
            self._active = None
            self._budget.cleanup_deadline = None
            return _thaw(accepted)
        except (ControllerError, OSError, KeyError, IndexError) as exc: raise self._refuse(exc)


_STREAM_LIMIT = 64 * 1024 * 1024
_QUARANTINE_CODES = {"ADMISSION_REFUSED", "LEASE_REQUIRED", "OWNERSHIP_UNKNOWN", "IO_FAILED", "CLEANUP_INCOMPLETE"}
_BINDING_KEYS = {"attempt_id", "guest_id", "boot_id"}


class _ControllerBackend(_ClosureBackend):
    def controller_identity(self):
        observed = parse_process_stat(Path("/proc/self/stat").read_text())
        return {"pid": observed.pid, "start_ticks": observed.start_ticks, "host_boot_id": _host_boot_id()}
    def controller_launch_observation(self):
        return {"isolated": bool(sys.flags.isolated), "dont_write_bytecode": bool(sys.dont_write_bytecode),
                "pycache_prefix": sys.pycache_prefix}
    def change_nice(self, increment):
        before = os.getpriority(os.PRIO_PROCESS, 0)
        after = os.nice(increment)
        _require(after == before + increment == os.getpriority(os.PRIO_PROCESS, 0),
                 "controller nice increment/readback differs", "ADMISSION_REFUSED")
        return {"before": before, "after": after}
    def guardian(self, *, limits, journal): return ProcessGuardian(limits=limits, journal=journal)
    def owned_image(self, identity): return execution.identify_file("/proc/" + str(identity["pid"]) + "/exe")
    def pause(self, seconds): time.sleep(seconds)
    def spawn(self, admitted, invocation, stdout, stderr):
        suffix = invocation.argv[len(admitted.argv_prefix):]
        _require(admitted.argv_prefix + suffix == invocation.argv, "exact argv reconstruction failed")
        return execution.popen_admitted(admitted, suffix, cwd=invocation.cwd,
                    env_extra=dict(invocation.env_overrides), start_new_session=True,
                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True)


def _failure_value(error, *, predecessor=None):
    return {"code": error.code, "detail": error.detail or error.code, "errno": error.errno, "predecessor": predecessor}


def _not_run(invocation, error, *, predecessor=None):
    return {"phase": invocation.phase, "attempt_id": invocation.attempt_id, "started": False, "terminal": True,
            "invocation": None, "timings": {key: None for key in ("wall_start", "wall_end", "monotonic_start", "monotonic_end")},
            "runner_exit": None, "reason": error.detail or error.code, "outcome": "NOT_RUN", "failure": _failure_value(error, predecessor=predecessor),
            "guest": None, "target_fingerprint": None, "processes": [], "cleanup": None,
            "streams": {"stdout": None, "stderr": None, "limit_bytes": _STREAM_LIMIT, "overflow": False},
            "guest_files": [], "projection": None}


def _check_binding(record, binding):
    _require(type(record) is dict and all(json_equal(record.get(key), value) for key, value in binding.items()),
             "guest observation belongs to a foreign attempt", "EVIDENCE_INVALID")


def _guest_identity(records, provisional, phase):
    identity, target = records["guest-identity"], records["target"]
    _mapping(identity, _BINDING_KEYS | {"boot_parameters"}, "EVIDENCE_INVALID")
    attempt_id = provisional["run_id"] + "." + phase
    _require(identity["attempt_id"] == identity["guest_id"] == attempt_id, "foreign guest identity", "EVIDENCE_INVALID")
    _boot(identity["boot_id"], "EVIDENCE_INVALID")
    _require(identity["boot_id"] != "00000000-0000-0000-0000-000000000000", "zero guest boot identity", "EVIDENCE_INVALID")
    binding = {key: identity[key] for key in _BINDING_KEYS}
    try: TargetManifest.from_dict(target)
    except (ContractError, ValueError, TypeError, KeyError) as exc:
        raise ControllerError("EVIDENCE_INVALID", "observed target is not the public target contract") from exc
    expected, lease = provisional["expected"], provisional["lease"]
    comparisons = [(target["kernel"]["source_commit"], expected["kernel_source_commit"]),
                   (target["kernel"]["release"], expected["kernel_release"]), (target["kernel"]["build_id"], expected["kernel_build_id"]),
                   (target["kernel"]["config_sha256"], expected["kernel_config_sha256"]),
                   (target["btf"]["vmlinux_sha256"], expected["vmlinux_btf_sha256"]),
                   (target["image"]["digest"], expected["rootfs_sha256"]), (target["cpu"]["architecture"], expected["architecture"]),
                   (target["execution_mode"], expected["execution_mode"]), (target["byte_order"], expected["byte_order"]),
                   (target["instruction_profile"], expected["instruction_profile"]), (target["build_host"]["identity"], expected["compiler_sha256"]),
                   (target["mounts"]["bpffs"], lease["guest_pin_root"])]
    _require(all(json_equal(a, b) for a, b in comparisons)
             and identity["boot_parameters"] == target["boot"]["parameters"]
             and "virtme_hostname=" + attempt_id in identity["boot_parameters"], "observed boot/target does not match admitted inputs", "EVIDENCE_INVALID")
    return binding


def _check_control(record, binding, provisional, *, negative=False, context=None, context_sha256=None):
    _mapping(record, _BINDING_KEYS | {"exit_code", "result", "process", "context_sha256"}, "EVIDENCE_INVALID")
    _check_binding(record, binding)
    expected, lease = provisional["expected"], provisional["lease"]
    result = record["result"]
    _require(type(result) is dict and type(record["exit_code"]) is int and record["exit_code"] == (3 if negative else 0),
             "control wrapper failed", "EVIDENCE_INVALID")
    wanted = {"tool": "bpf_test_run", "contract_version": 2, "repeat": 1, "expected_action": 2,
              "status": "fail" if negative else "pass", "stage": "load" if negative else "run",
              "classification": "environment" if negative else None, "actual_action": None if negative else 2,
              "cleanup_ok": None if negative else True}
    _require(all(json_equal(result.get(k), v) for k, v in wanted.items()), "control oracle failed", "EVIDENCE_INVALID")
    if negative:
        _require(json_equal(record["process"], context["process"]) and record["context_sha256"] == context_sha256,
                 "negative context byte/process binding differs", "EVIDENCE_INVALID")
    else:
        _require(record["process"] is None and record["context_sha256"] is None, "positive carries a foreign context", "EVIDENCE_INVALID")
    runtime, obj, packet, tool = (result.get(name) for name in ("runtime", "object", "data_in", "bpftool"))
    _require(all(type(item) is dict for item in (runtime, obj, packet, tool)), "control input identities missing", "EVIDENCE_INVALID")
    _require(type(runtime.get("uid")) is int and runtime["uid"] == (1001 if negative else 0)
             and runtime.get("kernel_release") == expected["kernel_release"]
             and obj.get("sha256") == expected["control_object_sha256"] and packet.get("sha256") == expected["packet_sha256"]
             and type(packet.get("size")) is int and packet["size"] == 60 and tool.get("entry_sha256") == expected["bpftool_sha256"]
             and tool.get("version") == expected["bpftool_version"] and tool.get("exec_path") is None and tool.get("exec_sha256") is None,
             "control consumed a foreign tool/object/packet", "EVIDENCE_INVALID")
    pin = lease["guest_pin_root"] + "/" + binding["attempt_id"] + ("/permission-negative" if negative else "/positive")
    admission = result.get("admission")
    _require(result.get("pin_path") == pin and type(admission) is dict and admission.get("bpftool_admitted") is True
             and str(admission.get("owned_root")) + "/" + str(admission.get("ownership_token")) == lease["guest_pin_root"],
             "control pin ownership differs", "EVIDENCE_INVALID")
    argv = [[tool.get("path"), "version"], [tool.get("path"), "prog", "load", obj.get("path"), pin]]
    if not negative:
        argv += [[tool.get("path"), "prog", "run", "pinned", pin, "data_in", packet.get("path"), "repeat", "1"], ["rm", "-f", pin]]
    commands = result.get("commands")
    _require(type(commands) is list and len(commands) == len(argv), "actual control command observations missing", "EVIDENCE_INVALID")
    for index, command in enumerate(commands):
        _require(type(command) is dict and command.get("argv") == argv[index] and command.get("timeout") is False
                 and type(command.get("exit_code")) is int and type(command.get("stdout")) is str and type(command.get("stderr")) is str,
                 "actual control command is malformed", "EVIDENCE_INVALID")
        if negative and index == 1:
            text = (command["stdout"] + command["stderr"]).lower()
            _require(command["exit_code"] != 0 and any(word in text for word in ("operation not permitted", "permission denied", "eperm")),
                     "negative did not observe a permission denial", "EVIDENCE_INVALID")
        else: _require(command["exit_code"] == 0, "control command failed", "EVIDENCE_INVALID")
    _require(commands[0]["stdout"].splitlines() and commands[0]["stdout"].splitlines()[0] == expected["bpftool_version"],
             "observed tool version contradicts admitted summary", "EVIDENCE_INVALID")
    if not negative:
        _require(re.findall(r"return value:\s*(\d+)", commands[2]["stdout"] + commands[2]["stderr"], re.I) == ["2"],
                 "test-run output did not observe action 2", "EVIDENCE_INVALID")


def _check_permission(context, binding, provisional):
    capabilities = {"CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"}
    _mapping(context, _BINDING_KEYS | {"process", "uid", "gid", "groups", "no_new_privs", "capabilities", "proc_status", "proc_stat", "pin_parent", "pin_parent_writable", "object_readable"}, "EVIDENCE_INVALID")
    _check_binding(context, binding)
    _mapping(context["process"], {"pid", "start_ticks"}, "EVIDENCE_INVALID")
    for value in context["process"].values(): _integer(value, 1, "EVIDENCE_INVALID")
    _require(type(context["uid"]) is int and context["uid"] == 1001 and type(context["gid"]) is int and context["gid"] == 1001
             and context["groups"] == [] and type(context["no_new_privs"]) is int and context["no_new_privs"] == 1
             and context["capabilities"] == {name: "0000000000000000" for name in capabilities}
             and context["pin_parent"] == provisional["lease"]["guest_pin_root"] + "/" + binding["attempt_id"]
             and context["pin_parent_writable"] is True and context["object_readable"] is True,
             "negative process retains privilege or inaccessible inputs", "EVIDENCE_INVALID")
    fields = {}
    _require(type(context["proc_status"]) is str and type(context["proc_stat"]) is str, "raw permission context missing", "EVIDENCE_INVALID")
    for line in context["proc_status"].splitlines():
        key, separator, value = line.partition(":")
        if key in capabilities | {"Pid", "Uid", "Gid", "Groups", "NoNewPrivs"}:
            _require(separator and key not in fields, "ambiguous permission status", "EVIDENCE_INVALID")
            fields[key] = value.split()
    wanted = {"Pid": [str(context["process"]["pid"])], "Uid": ["1001"] * 4, "Gid": ["1001"] * 4,
              "Groups": [], "NoNewPrivs": ["1"], **{name: ["0000000000000000"] for name in capabilities}}
    try: observed = parse_process_stat(context["proc_stat"])
    except GuardianError as exc:
        raise ControllerError("EVIDENCE_INVALID", "raw guest process identity is malformed") from exc
    _require(fields == wanted and observed.pid == context["process"]["pid"] and observed.start_ticks == context["process"]["start_ticks"],
             "raw privilege/process observations contradict context", "EVIDENCE_INVALID")


def _check_trigger(trigger, binding, positive, provisional):
    _mapping(trigger, _BINDING_KEYS | {"marker", "held_pin", "held_pin_exists", "positive_sha256", "load_command"}, "EVIDENCE_INVALID")
    _check_binding(trigger, binding)
    held = provisional["lease"]["guest_pin_root"] + "/" + binding["attempt_id"] + "/recovery-held"
    command = trigger["load_command"]
    _mapping(command, {"argv", "exit_code", "timeout", "stdout", "stderr"}, "EVIDENCE_INVALID")
    _require(trigger["marker"] == "INTERRUPT_OWNED_GUEST" and trigger["held_pin"] == held and trigger["held_pin_exists"] is True
             and trigger["positive_sha256"] == digest_of(positive)
             and command["argv"] == [positive["result"]["bpftool"]["path"], "prog", "load", positive["result"]["object"]["path"], held]
             and type(command["exit_code"]) is int and command["exit_code"] == 0 and command["timeout"] is False
             and type(command["stdout"]) is str and type(command["stderr"]) is str, "invalid owned interruption marker", "EVIDENCE_INVALID")


def _check_mounts(before, after, write_paths):
    _require(type(before) is str and before and before == after, "raw host mount observations changed or are absent", "CLEANUP_INCOMPLETE")
    for line in after.splitlines():
        columns = line.split()
        _require(len(columns) >= 10 and "-" in columns[6:], "host mountinfo cannot be parsed", "CLEANUP_INCOMPLETE")
        path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), columns[4])
        _require(not any(path == root or _inside(path, root) for root in write_paths), "owned path remains mounted", "CLEANUP_INCOMPLETE")


def _projection_records(validated, provisional, invocation, attempt, records, accepted):
    _require(attempt["cleanup"] is not None and attempt["cleanup"]["status"] == "CLEAN" and not attempt["streams"]["overflow"],
             "projection lacks caller-accepted clean facts", "EVIDENCE_INVALID")
    binding = _guest_identity(records, provisional, invocation.phase)
    processes = attempt["processes"]
    _require(len({p["identity"]["pid"] for p in processes}) == len(processes), "v1 cannot represent reused numeric PIDs", "EVIDENCE_INVALID")
    runners = [p for p in processes if p["role"] == "runner"]; qemus = [p for p in processes if p["role"] == "qemu"]
    _require(len(runners) == len(qemus) == 1, "observed runner and QEMU roles required", "EVIDENCE_INVALID")
    runner = next(p for p in accepted["processes"] if p["role"] == "runner")
    _require(runner["session_id"] == runner["identity"]["pid"], "runner did not establish its own session", "EVIDENCE_INVALID")
    _check_control(records["positive"], binding, provisional)
    absence = records["pin_root_absence"]
    _mapping(absence, _BINDING_KEYS | {"pin_root", "exists", "entries"}, "EVIDENCE_INVALID"); _check_binding(absence, binding)
    _require(absence["pin_root"] == provisional["lease"]["guest_pin_root"] and absence["exists"] is False and absence["entries"] == [],
             "fresh guest did not observe absent pin root", "EVIDENCE_INVALID")
    if invocation.phase == "interrupted":
        _require(attempt["runner_exit"] == -9, "intentional interruption did not preserve signed SIGKILL exit", "EVIDENCE_INVALID")
        _check_trigger(records["ready-to-interrupt"], binding, records["positive"], provisional)
        guest_unmount = None
        pins = {"root": absence["pin_root"], "root_exists": False, "entries": [], "basis": "guest-destroyed"}
    else:
        _require(attempt["runner_exit"] == 0, "ordinary runner failed", "EVIDENCE_INVALID")
        _check_permission(records["permission_context"], binding, provisional)
        context_ref = next(row["reference"] for row in attempt["guest_files"] if row["name"] == "permission_context.json")
        _check_control(records["permission_negative"], binding, provisional, negative=True,
                       context=records["permission_context"], context_sha256=context_ref["sha256"])
        guest_cleanup = records["guest-cleanup"]
        _mapping(guest_cleanup, _BINDING_KEYS | {"status", "created_pin_root", "created_attempt_root", "owned_processes", "owned_mounts", "owned_pins", "guest_unmount", "pin_observation"}, "EVIDENCE_INVALID")
        _check_binding(guest_cleanup, binding)
        _require(guest_cleanup["status"] == "CLEAN" and guest_cleanup["created_pin_root"] is True and guest_cleanup["created_attempt_root"] is True
                 and all(guest_cleanup[key] == [] for key in ("owned_processes", "owned_mounts", "owned_pins")), "guest cleanup failed", "EVIDENCE_INVALID")
        guest_unmount, pins = guest_cleanup["guest_unmount"], guest_cleanup["pin_observation"]
        _mapping(guest_unmount, {"argv", "exit_code", "timeout", "stdout", "stderr"}, "EVIDENCE_INVALID")
        _require(guest_unmount["argv"] == ["/usr/bin/umount", "/sys/fs/bpf"] and type(guest_unmount["exit_code"]) is int
                 and guest_unmount["exit_code"] == 0 and guest_unmount["timeout"] is False
                 and type(guest_unmount["stdout"]) is str and type(guest_unmount["stderr"]) is str, "guest unmount failed", "EVIDENCE_INVALID")
        _mapping(pins, {"root", "root_exists", "entries", "basis"}, "EVIDENCE_INVALID")
        _require(pins == {"root": absence["pin_root"], "root_exists": False, "entries": [], "basis": "guest-unmounted"}, "guest pins remain", "EVIDENCE_INVALID")
    mounts = accepted["cleanup"]
    _check_mounts(mounts["mountinfo_before"], mounts["mountinfo_after"], provisional["lease"]["host_write_paths"])
    guest = {"id": binding["guest_id"], "boot_id": binding["boot_id"], "session_id": runner["session_id"],
             "processes": [{"pid": p["identity"]["pid"], "start_ticks": p["identity"]["start_ticks"], "role": p["role"]} for p in processes]}
    guest_record = {**binding, "session_id": runner["session_id"]}
    execution_record = {"run_id": validated.run_id, "attempt_id": invocation.attempt_id, "lane_id": validated.lane_id,
                        "lease_id": validated.lease_id, "provisional_sha256": digest_of(provisional), "phase": invocation.phase,
                        "terminal": True, "exit_code": attempt["runner_exit"], "outcome": "INFRA_ERROR" if invocation.phase == "interrupted" else "PASS",
                        "inputs": dict(validated.expected), "host_write_paths": provisional["lease"]["host_write_paths"],
                        "guest": guest, "target_fingerprint": records["target"]["fingerprint"]}
    cleanup_record = {**binding, "status": "CLEAN", "owned_processes": [], "owned_mounts": [], "owned_pins": [],
                      "process_observations": [{"pid": p["pid"], "start_ticks": p["start_ticks"], "alive": False} for p in guest["processes"]],
                      "mount_observations": {"before": mounts["mountinfo_before"], "after": mounts["mountinfo_after"]},
                      "guest_unmount": guest_unmount, "pin_observation": pins}
    return execution_record, cleanup_record, guest_record, records["target"]["fingerprint"]


class _LaneController:
    def __init__(self, validated, *, cancel_fd=None, _backend=None):
        self.authority = _execution_authority(validated)
        self.v, self.backend, self.cancel_fd = validated, _backend or _ControllerBackend(), cancel_fd
        self.budget = _Budget(validated, self.backend)
        self.store = self.lease = self.guardian = self.barrier = None
        self.artifacts, self.attempts, self.maps, self.directories = [], [], [], []
        self.result_artifact, self._ran, self._cancel_requested = None, False, False
        self._provisional = _freeze({"schema_version": 1, "run_id": validated.run_id, "lane_id": validated.lane_id,
                    "lease": {"id": validated.lease_id, "owner": validated.owner, "exclusive": True,
                              "record_sha256": validated.lease_sha256, "rootfs_read_only": True,
                              "guest_pin_root": "/sys/fs/bpf/mojobpf/" + validated.run_id,
                              "host_write_paths": [validated.paths.output_root, validated.paths.tmp_root]}, "expected": dict(validated.expected)})

    @property
    def provisional(self): return _thaw(self._provisional)

    def _persist(self, path, raw, *, maximum=JSON_LIMIT):
        artifact = self.store.persist(path, raw, maximum=maximum)
        self.artifacts.append(artifact)
        return artifact.reference

    def _record(self, path, value): return self._persist(path, _json_bytes(value) + b"\n")

    def _cancelled(self):
        if self.guardian is not None and self.guardian.cancelled: self._cancel_requested = True
        if self._cancel_requested: return True
        if self.cancel_fd is None: return False
        self.budget.check()
        try:
            ready, _, _ = select.select([self.cancel_fd], [], [], 0)
            if ready:
                os.read(self.cancel_fd, 1)  # A byte or EOF is cancellation; never inherited by the runner.
                self._cancel_requested = True
                return True
        except OSError as exc:
            raise ControllerError("IO_FAILED", "cancellation descriptor failed", errno=exc.errno) from exc
        return False

    def _phase_time(self, origin, *, ready, phase):
        # Observation work consumes the original spawn-based phase budgets.
        # Cleanup retains its independent deadline after execution stops.
        now = self.budget.check()
        _require(now < origin + self.v.limits.attempt_seconds, "attempt deadline expired", "ATTEMPT_TIMEOUT")
        if not ready:
            _require(now < origin + self.v.limits.startup_seconds, "startup deadline expired", "STARTUP_TIMEOUT")
        if phase == "interrupted":
            _require(now < origin + self.v.limits.marker_seconds, "interruption marker deadline expired", "MARKER_TIMEOUT")

    def _final_cancellation(self, error, intentional, attempt):
        cancelled = self._cancelled()
        if cancelled:
            if error is None or (error.code == "CANCELLED" and error.detail == "intentional interruption"):
                error = ControllerError("CANCELLED", "controller cancellation requested during finalization")
            intentional = False
            attempt["projection"] = None
        return error, intentional, cancelled

    def _qemu(self):
        before = self.guardian.observe(); candidates = []
        for process in before:
            if process["role"] == "runner" or process["exited"]: continue
            try: image = self.backend.owned_image(process["identity"])
            except (OSError, execution.AdmissionError):
                after = self.guardian.observe()
                if any(p["sequence"] == process["sequence"] and p["exited"] for p in after): continue
                raise ControllerError("OWNERSHIP_UNKNOWN", "retained process executable identity is unreadable")
            approved = self.v.qemu.image
            matches = image is not None and all(getattr(image, key) == getattr(approved, key) for key in ("realpath", "sha256", "dev", "ino", "size", "mtime_ns"))
            after = self.guardian.observe()
            stable = any(p["sequence"] == process["sequence"] and json_equal(p["identity"], process["identity"]) and not p["exited"] for p in after)
            if matches and stable: candidates.append((process, image))
        _require(len(candidates) <= 1, "multiple live processes match the QEMU role", "EVIDENCE_INVALID")
        return candidates[0] if candidates else None

    def _streams(self, writers, attempt, *, seal=False):
        for name, writer in writers.items():
            info = os.fstat(writer.fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                     and (info.st_dev, info.st_ino) == writer.identity, "owned stream identity changed", "IO_FAILED")
            if info.st_size > _STREAM_LIMIT:
                attempt["streams"]["overflow"] = True
                if not seal: raise ControllerError("EVIDENCE_INVALID", "owned stream exceeded 64 MiB")
                continue  # Preserve the complete original file; never hash a truncation as the file.
            if seal:
                os.lseek(writer.fd, 0, os.SEEK_SET); chunks, size = [], 0
                while True:
                    self.budget.check(); raw = self.backend.read(writer.fd, min(65536, _STREAM_LIMIT-size+1)); self.budget.check()
                    if not raw: break
                    size += len(raw); _require(size <= _STREAM_LIMIT, "stream overflow during sealing", "EVIDENCE_INVALID"); chunks.append(raw)
                artifact = self.store.readback(writer.path, b"".join(chunks), maximum=_STREAM_LIMIT)
                self.artifacts.append(artifact); attempt["streams"][name] = artifact.reference

    def _capture_guest(self, reader, captured, name, *, partial=False):
        if name in captured: return captured[name]
        value = reader.capture(name + ".json", partial=partial, optional=partial)
        if value is not None: captured[name] = value
        return value

    def _externalize(self, invocation, accepted, qemu_sequence, attempt, *, first=None, last=None):
        base = "attempts/" + invocation.attempt_id + "/"
        cleanup = accepted["cleanup"]
        for key in ("mountinfo_before", "mountinfo_after"):
            if type(cleanup[key]) is str:cleanup[key] = self._persist(base + key + ".txt", cleanup[key].encode())
        attempt["cleanup"] = cleanup
        raw_processes = accepted["processes"]; by_sequence = {p["sequence"]: p for p in raw_processes}
        # Entry sequences reset per epoch. Select only the current fixed range.
        if first is None:
            epoch = self.barrier._committed[-1];first,last=epoch.first,epoch.last
        events = self.barrier.guardian_records[first-1:last]
        retained = {r["entry_sequence"]: r for r in events if r["event"] == "retained"}
        for process in raw_processes:
            sequence = process["sequence"]
            raw = {}
            for key in ("raw_stat", "raw_fdinfo"):
                raw[key] = [self._persist(base + "process-" + str(sequence) + "-" + key + "-" + str(i) + ".txt", value.encode())
                            for i, value in enumerate(process[key])]
            parent = by_sequence.get(process["parent_sequence"])
            signals = [{"time": r["time"], "signal": r["signal"], "errno": r["errno"], "sent": r["sent"]}
                       for r in events if r["event"] == "signal" and r["entry_sequence"] == sequence]
            wait = process["wait_status"]
            attempt["processes"].append({"sequence": sequence, "time": retained[sequence]["time"], "identity": process["identity"],
                "role": "qemu" if sequence == qemu_sequence else process["role"], "ownership_basis": process["ownership_basis"],
                "parent": None if parent is None else parent["identity"], **raw, "signals": signals,
                "pidfd_exited": process["exited"], "wait_status": None if wait is None else wait["exit_code"], "pidfd_diagnostic": None})

    def _projection(self, invocation, attempt, captured, accepted):
        execution_record, cleanup_record, guest, fingerprint = _projection_records(
            self.v, self.provisional, invocation, attempt, {n:c.value for n,c in captured.items()}, accepted)
        attempt["guest"], attempt["target_fingerprint"] = guest, fingerprint
        base = "attempts/" + invocation.attempt_id + "/"
        references = {"execution": self._record(base + "execution.json", execution_record), "cleanup": self._record(base + "cleanup.json", cleanup_record)}
        names = {"target", "positive", "pin_root_absence"} | ({"ready-to-interrupt"} if invocation.phase == "interrupted" else {"permission_negative", "permission_context"})
        for name in names:
            references["trigger" if name == "ready-to-interrupt" else name] = next(row["reference"] for row in attempt["guest_files"] if row["name"] == name + ".json")
        attempt["projection"] = self._record(base + "projection-map.json", references)
        self.maps.append(_freeze(references))

    def _attempt(self, invocation):
        self.lease.verify()
        self.budget.cleanup_deadline = None
        proof = _ClosureVerifier(self.v, budget=self.budget, _backend=self.backend).verify()
        self.barrier.transition("closure-refreshed", invocation=invocation, data=proof)
        self.barrier.open_attempt(invocation)
        attempt = _not_run(invocation, ControllerError("EVIDENCE_INVALID", "attempt incomplete"))
        attempt.update(started=True, outcome="INFRA_ERROR", invocation={"argv": list(invocation.argv), "cwd": invocation.cwd,
                       "environment_policy": "admitted-sanitized-with-approved-overrides", "environment": dict(invocation.env_overrides),
                       "environment_sha256": digest_of(dict(invocation.env_overrides))})
        attempt["timings"].update(wall_start=self.backend.wall_time(), monotonic_start=self.budget.check())
        self.attempts.append(attempt)
        reader = temp = cache = None
        captured, writers, qemu_sequence, error, intentional, returned = {}, {}, None, None, False, None
        prepare_entered = False
        try:
            env = dict(invocation.env_overrides)
            reader = _GuestExport(invocation.output_path, budget=self.budget, _backend=self.backend, create=True)
            temp = _OwnedDirectory(env["TMPDIR"], budget=self.budget, _backend=self.backend, create=True)
            cache = _OwnedDirectory(env["PYTHONPYCACHEPREFIX"], budget=self.budget, _backend=self.backend, create=True)
            self.directories.extend([reader, temp, cache])
            before_cache = cache.empty_observation(); _require(before_cache["empty"], "attempt pycache is not initially empty")
            self.barrier.transition("cache-before", invocation=invocation, data=before_cache)
            base = "attempts/" + invocation.attempt_id + "/"
            writers = {name: self.store.open_append(base + name + ".log") for name in ("stdout", "stderr")}
            prepare_entered = True; self.guardian.prepare()
            if self._cancelled(): raise ControllerError("CANCELLED", "cancelled before spawn")
            self.lease.verify()
            # The final content pass brackets the exact spawn, after setup writes.
            _ClosureVerifier(self.v, budget=self.budget, _backend=self.backend).verify()
            self.barrier.transition("spawn-intent", invocation=invocation, data={"argv": list(invocation.argv)})
            if self._cancelled(): raise ControllerError("CANCELLED", "cancelled at spawn boundary")
            origin = self.budget.check()
            process = self.backend.spawn(self.v.runner, invocation, writers["stdout"].fd, writers["stderr"].fd)
            self.guardian.retain_runner(process)
            self.barrier.transition("runner-retained", invocation=invocation)
            ready = False
            while True:
                self.lease.verify()
                if self._cancelled(): raise ControllerError("CANCELLED", "controller cancellation requested")
                self._streams(writers, attempt)
                self._phase_time(origin, ready=ready, phase=invocation.phase)
                observed_qemu = self._qemu()
                if observed_qemu is not None:
                    if qemu_sequence is None:
                        qemu, image = observed_qemu; qemu_sequence = qemu["sequence"]
                        self.barrier.transition("qemu-observed", invocation=invocation, data={"sequence":qemu_sequence,"identity":qemu["identity"],"image":vars(image)})
                    else:
                        _require(observed_qemu[0]["sequence"] == qemu_sequence,
                                 "QEMU role changed after observation", "EVIDENCE_INVALID")
                for name in ("guest-identity", "target"):
                    self._capture_guest(reader, captured, name, partial=True)
                if all(name in captured for name in ("guest-identity", "target")) and qemu_sequence is not None:
                    _guest_identity({name:value.value for name,value in captured.items()}, self.provisional, invocation.phase)
                    if self._cancelled(): raise ControllerError("CANCELLED", "cancelled during startup observation")
                    self._phase_time(origin, ready=ready, phase=invocation.phase)
                    ready = True
                if invocation.phase == "interrupted" and ready:
                    for name in ("positive", "pin_root_absence", "ready-to-interrupt"):
                        self._capture_guest(reader, captured, name, partial=True)
                    if all(name in captured for name in ("positive", "pin_root_absence", "ready-to-interrupt")):
                        records = {name:value.value for name,value in captured.items()}
                        binding = _guest_identity(records, self.provisional, invocation.phase)
                        _check_control(records["positive"], binding, self.provisional)
                        _check_trigger(records["ready-to-interrupt"], binding, records["positive"], self.provisional)
                        for name in ("guest-identity", "target", "positive", "ready-to-interrupt"): reader.revalidate(captured[name])
                        live_qemu = self._qemu()
                        _require(live_qemu is not None and live_qemu[0]["sequence"] == qemu_sequence,
                                 "interruption marker has no current retained live QEMU", "EVIDENCE_INVALID")
                        if self._cancelled(): raise ControllerError("CANCELLED", "cancelled during marker consumption")
                        self._phase_time(origin, ready=ready, phase=invocation.phase)
                        intentional = True; break
                signed = self.guardian.runner_exit()
                if self._cancelled(): raise ControllerError("CANCELLED", "cancelled during terminal observation")
                self._phase_time(origin, ready=ready, phase=invocation.phase)
                if signed is not None:
                    if signed != 0: raise ControllerError("EVIDENCE_INVALID", "ordinary runner failed with signed exit " + str(signed))
                    _require(ready, "runner exited without required startup evidence", "EVIDENCE_INVALID")
                    break
                self.backend.pause(self.v.limits.guardian.poll_seconds)
        except (ControllerError, GuardianError, OSError, execution.AdmissionError) as exc:
            error = exc if isinstance(exc, ControllerError) else ControllerError(
                exc.code if isinstance(exc, GuardianError) and exc.code in FAILURE_CODES else "IO_FAILED", str(exc), errno=getattr(exc,"errno",None))
        finally:
            if prepare_entered:
                try: returned = self.guardian.finish(reason="intentional interruption" if intentional else "completed" if error is None else error.detail,
                                                    interrupt=intentional or error is not None)
                except GuardianError as exc:
                    error = ControllerError(exc.code if exc.code in FAILURE_CODES else "OWNERSHIP_UNKNOWN", exc.detail, errno=exc.errno)
            # Finalization can observe cancellation after the ordinary exit.
            # This check follows the guardian drain so it cannot skip cleanup.
            error, intentional, _ = self._final_cancellation(error, intentional, attempt)
            if returned is not None and returned.get("status") == "CLEAN":
                # Failure here permanently poisons the barrier, even after drain.
                accepted = self.barrier.commit(returned)
                self.budget.cleanup_deadline = returned["completion_receipt"]["deadline"]
                committed = self.barrier._committed[-1]; self.artifacts.extend([committed.prefix, committed.receipt])
                attempt["runner_exit"] = accepted["runner_exit"]
                physical = _thaw(committed.result)  # Raw mounts stay immutable for projection.
                self._externalize(invocation, accepted, qemu_sequence, attempt)
                try: _check_mounts(physical["cleanup"]["mountinfo_before"], physical["cleanup"]["mountinfo_after"], self.provisional["lease"]["host_write_paths"])
                except ControllerError as exc: error = exc
                self._streams(writers, attempt, seal=True)
                if reader is not None:
                    required = {"guest-identity", "target", "positive", "pin_root_absence"} | ({"ready-to-interrupt"} if invocation.phase=="interrupted" else {"permission_negative", "permission_context", "guest-cleanup"})
                    try:
                        for name in required:
                            if name not in captured: self._capture_guest(reader, captured, name)
                        for value in captured.values(): reader.revalidate(value)
                    except ControllerError as exc:
                        if error is None: error = exc
                    for name in ("guest-commands.json","observations.json","guest-infra.json","positive-harness.json","permission-negative-harness.json"):
                        diagnostic=reader.capture(name,optional=True,structured=False)
                        if diagnostic is not None:captured[name]=diagnostic
                    if captured: self.store.mkdir("attempts/" + invocation.attempt_id + "/guest")
                    for name, value in sorted(captured.items()):
                        reference = self._persist("attempts/" + invocation.attempt_id + "/guest/" + value.name, value.raw)
                        attempt["guest_files"].append({"name":value.name,"reference":reference})
                    for index, (name, raw) in enumerate(reader.partial_bytes):
                        self._persist("attempts/" + invocation.attempt_id + "/partial-" + str(index) + "-" + name, raw)
                error, intentional, _ = self._final_cancellation(error, intentional, attempt)
                if error is None:
                    try: self._projection(invocation, attempt, captured, physical)
                    except (ControllerError, KeyError) as exc:
                        error = exc if isinstance(exc, ControllerError) else ControllerError("EVIDENCE_INVALID", "required guest evidence missing")
                if intentional and error is None:
                    error = ControllerError("CANCELLED", "intentional interruption")
                attempt["outcome"] = "INFRA_ERROR" if error else "PASS"
                attempt["failure"] = None if error is None else _failure_value(error)
                attempt["reason"] = "completed" if error is None else error.detail
            elif returned is not None:
                if error is None:error = ControllerError("CLEANUP_INCOMPLETE", "guardian finalization did not seal cleanly")
                attempt["runner_exit"] = returned.get("runner_exit")
                attempt["cleanup"] = {key:returned.get(key) for key in ("subreaper_readback", "scans", "adoptions", "final_echild", "unresolved_live", "all_pidfds_exited")}
                attempt["cleanup"].update(status="INCOMPLETE",mountinfo_before=returned.get("mountinfo_before"),
                                         mountinfo_after=returned.get("mountinfo_after"),completion_journal=None,completion_receipt=None)
                self._externalize(invocation,{"cleanup":attempt["cleanup"],"processes":returned["processes"]},qemu_sequence,attempt,
                                  first=self.barrier._expected_sequence,last=self.barrier._guardian_count)
            for directory in (cache, temp, reader):
                if directory is not None:
                    if directory is cache:
                        self.barrier.transition("cache-after", invocation=invocation, data=cache.empty_observation())
                    errors = directory.close()
                    if errors: raise errors[0]
            attempt["timings"].update(wall_end=self.backend.wall_time(),monotonic_end=self.budget.check())
            error, intentional, cancellation_known = self._final_cancellation(error, intentional, attempt)
            if error is not None:
                attempt.update(reason=error.detail,outcome="INFRA_ERROR",failure=_failure_value(error))
            self.barrier.transition("attempt-terminal", invocation=invocation, data={"outcome":attempt["outcome"],"failure":attempt["failure"],"projection":attempt["projection"]})
            if not cancellation_known:
                _require(not self._cancelled(), "cancelled after attempt semantic seal", "CANCELLED")
        return error, intentional and error is not None and error.code == "CANCELLED" and attempt["projection"] is not None

    def _final_projection(self):
        guests = [attempt["guest"] for attempt in self.attempts]
        _require(all(len({guest[key] for guest in guests}) == 3 for key in ("guest_id", "boot_id", "session_id")),
                 "recovery reused a guest/boot/session", "EVIDENCE_INVALID")
        identities = [(p["identity"]["pid"],p["identity"]["start_ticks"]) for attempt in self.attempts for p in attempt["processes"]]
        _require(len(set(identities)) == len(identities), "recovery reused a process identity", "EVIDENCE_INVALID")
        maps = [_thaw(record) for record in self.maps]
        interrupted = self._record("interrupted-map.json",maps[1]); fresh = self._record("fresh-map.json",maps[2])
        recovery = self._record("recovery.json", {"outcome":"PASS","terminal":True,"plan_sha256":dict(self.v.expected)["recovery_plan_sha256"],
                                                "interrupted_attempt":interrupted,"fresh_attempt":fresh})
        wrapper = {"schema_version":1,"run_id":self.v.run_id,"lane_id":self.v.lane_id,"lease_id":self.v.lease_id,
                   "provisional_sha256":digest_of(self.provisional),"evidence":dict(maps[0],recovery=recovery)}
        self._record("provisional.json",self.provisional)
        return self._record("projected-attempt.json",wrapper)

    def run(self):
        _require(not self._ran, "controller invocations cannot resume", "LEASE_REQUIRED"); self._ran = True
        terminal_error, projection, lease_writer, own_cache = None, None, None, None
        try:
            self.lease = _LaneLease(self.v,budget=self.budget,_backend=self.backend)
            _ClosureVerifier(self.v,budget=self.budget,_backend=self.backend).verify()
            launch = self.backend.controller_launch_observation()
            _require(launch == {"isolated":True,"dont_write_bytecode":True,"pycache_prefix":self.v.paths.controller_pycache},
                     "controller requires isolated Python, disabled bytecode writes and the approved private prefix")
            own_cache = _OwnedDirectory(self.v.paths.controller_pycache,budget=self.budget,_backend=self.backend,
                                        create=not os.path.lexists(self.v.paths.controller_pycache))
            self.directories.append(own_cache)
            _require(own_cache.empty_observation()["empty"], "controller private cache is not initially empty")
            if self.cancel_fd is not None:
                _integer(self.cancel_fd)
                fcntl.fcntl(self.cancel_fd,fcntl.F_SETFD,fcntl.fcntl(self.cancel_fd,fcntl.F_GETFD)|fcntl.FD_CLOEXEC)
            identity = self.backend.controller_identity()
            _mapping(identity,{"pid","start_ticks","host_boot_id"}); _integer(identity["pid"],1);_integer(identity["start_ticks"],1)
            _require(identity["host_boot_id"] == self.v.host_boot_id,"controller host boot identity differs")
            self.store = _OwnedStore(self.v.paths.controller_output,output_root=self.v.paths.output_root,budget=self.budget,_backend=self.backend)
            self.barrier = _CompletionBarrier(self.v,self.store,budget=self.budget,controller_identity=identity)
            self.guardian = self.backend.guardian(limits=self.v.limits.guardian,journal=self.barrier.guardian_record)
            lease_name = str(Path(self.v.paths.lease_journal).relative_to(self.v.paths.controller_output))
            lease_writer = self.store.open_append(lease_name)
            active = {"state":"ACTIVE","run_id":self.v.run_id,"lane_id":self.v.lane_id,"lease_sha256":self.v.lease_sha256,"controller_identity":identity}
            self.store.append(lease_writer,_json_bytes(active)+b"\n")
            self.store.readback(lease_name,_json_bytes(active)+b"\n",maximum=JSON_LIMIT)
            self.barrier.transition("lease-active",data=active)
            self.barrier.transition("controller-cache-before",data=own_cache.empty_observation())
            self.store.mkdir("inputs")
            bindings = {}
            for name, document in zip(("proposal","approval","lease"), self.authority):
                reference = self._persist("inputs/" + name + ".json", document.consumed.raw)
                bindings[name] = {"path":reference["path"],"file_sha256":reference["sha256"],"canonical_sha256":digest_of(_document(document))}
            for name, consumed, canonical in self.v.inputs:
                if name in {"capture_contract","recovery_plan","controller_distribution","original_closure","supplemental_closure"}:
                    reference = self._persist("inputs/" + name + ".json",consumed.raw,maximum=_INPUT_BYTE_LIMITS.get(name,JSON_LIMIT))
                    bindings[name] = {"path":reference["path"],"file_sha256":reference["sha256"],"canonical_sha256":canonical}
            nice = self.backend.change_nice(self.v.limits.nice_increment)
            _require(type(nice) is dict and set(nice)=={"before","after"} and all(type(n) is int for n in nice.values())
                     and nice["after"]==nice["before"]+10,"nice inheritance readback failed")
            self.barrier.transition("nice-inherited",data=nice)
            for invocation in self.v.invocations:
                _require(not self._cancelled(), "cancelled before phase advancement", "CANCELLED")
                error, intentional = self._attempt(invocation)
                if error is not None and not intentional:
                    terminal_error = error; break
            if terminal_error is not None:
                predecessor = self.attempts[-1]["attempt_id"] if self.attempts else None
                for invocation in self.v.invocations[len(self.attempts):]:
                    attempt = _not_run(invocation,terminal_error,predecessor=predecessor)
                    self.attempts.append(attempt); predecessor = attempt["attempt_id"]
            else:
                try: projection = self._final_projection()
                except ControllerError as exc: terminal_error = exc
            if terminal_error is None:
                _require(not self._cancelled(), "cancelled after lane semantic seal", "CANCELLED")
            disposition = "RELEASABLE" if terminal_error is None or terminal_error.code not in _QUARANTINE_CODES else "QUARANTINED"
            if any(a["started"] and (a["cleanup"] is None or a["cleanup"]["status"]!="CLEAN") for a in self.attempts): disposition="QUARANTINED"
            self.barrier.verify_committed();self.lease.verify()
            for artifact in self.artifacts: self.store.revalidate(artifact,maximum=_GUARDIAN_PREFIX_LIMIT if artifact.relative.endswith(".jsonl") else _STREAM_LIMIT)
            self.barrier.transition("controller-cache-after",data=own_cache.empty_observation())
            self.barrier.transition("lane-terminal",data={"outcome":"PASS" if terminal_error is None else "INFRA_ERROR","lease_disposition":disposition,
                                                        "attempts":self.attempts,"projection":projection,"artifacts":[a.reference for a in self.artifacts]})
            journal = self._persist("controller-journal.jsonl",bytes(self.barrier._transitions))
            result = {"schema_version":2,"contract":CONTROLLER_CONTRACT_V2,"run_id":self.v.run_id,"lane_id":self.v.lane_id,"bindings":bindings,
                      "terminal":True,"outcome":"PASS" if terminal_error is None else "INFRA_ERROR","failure":None if terminal_error is None else _failure_value(terminal_error),
                      "attempts":self.attempts,"lease_disposition":disposition,"projection":projection,"journal":journal,
                      "artifacts":[artifact.reference for artifact in self.artifacts]}
            result=validate_result(result)  # Detach callback-visible mutable observations.
            _inspect_result_record(self.v,result,_budget=self.budget)
            self.result_artifact = self.store.persist("controller-result.json",_json_bytes(result)+b"\n",maximum=JSON_LIMIT)
            self.barrier.verify_committed(); self.store.revalidate(self.result_artifact,maximum=JSON_LIMIT)
            hint = {"state":disposition,"run_id":self.v.run_id,"lane_id":self.v.lane_id,"result":self.result_artifact.reference,"journal":journal}
            lease_bytes = _json_bytes(active)+b"\n"+_json_bytes(hint)+b"\n"
            self.store.append(lease_writer,_json_bytes(hint)+b"\n"); self.store.readback(lease_name,lease_bytes,maximum=JSON_LIMIT)
            errors = own_cache.close(); own_cache = None
            if errors: raise errors[0]
            errors = self.store.close()
            if errors: raise errors[0]
            errors = self.lease.close()
            if errors: raise errors[0]
            self.budget.check()
            if terminal_error is None:
                _require(not self._cancelled(), "cancelled before final completion acknowledgement", "CANCELLED")
            return _thaw(_freeze(result))
        except OSError as exc:
            raise ControllerError("IO_FAILED","controller operation failed",errno=exc.errno) from exc
        finally:
            # Known owned handles are closed once even after deadline/I/O failure.
            for directory in self.directories: directory.close()
            if self.store is not None: self.store.close()
            if self.lease is not None: self.lease.close()


def run_lane(validated, *, cancel_fd=None):
    """Execute one already externally admitted v2 lane in a dedicated process."""
    return _LaneController(validated,cancel_fd=cancel_fd).run()


_RESULT_SCHEMA_V1 = json.loads(r"""{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:mojobpf:controller-result-v1",
  "$comment": "SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception",
  "title": "Disposable controller result, including incomplete attempts",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "contract",
    "run_id",
    "lane_id",
    "bindings",
    "terminal",
    "outcome",
    "failure",
    "attempts",
    "lease_disposition",
    "projection",
    "journal",
    "artifacts"
  ],
  "properties": {
    "schema_version": {
      "const": 1,
      "type": "integer"
    },
    "contract": {
      "const": "controller-result-v1"
    },
    "run_id": {
      "anyOf": [
        {
          "$ref": "#/$defs/identifier"
        },
        {
          "type": "null"
        }
      ]
    },
    "lane_id": {
      "anyOf": [
        {
          "$ref": "#/$defs/identifier"
        },
        {
          "type": "null"
        }
      ]
    },
    "bindings": {
      "$ref": "#/$defs/bindings"
    },
    "terminal": {
      "type": "boolean"
    },
    "outcome": {
      "enum": [
        "PASS",
        "FAIL",
        "INFRA_ERROR",
        "NOT_RUN"
      ]
    },
    "failure": {
      "anyOf": [
        {
          "$ref": "#/$defs/failure"
        },
        {
          "type": "null"
        }
      ]
    },
    "attempts": {
      "type": "array",
      "maxItems": 3,
      "prefixItems": [
        {
          "allOf": [
            {
              "$ref": "#/$defs/attempt"
            },
            {
              "properties": {
                "phase": {
                  "const": "main"
                }
              }
            }
          ]
        },
        {
          "allOf": [
            {
              "$ref": "#/$defs/attempt"
            },
            {
              "properties": {
                "phase": {
                  "const": "interrupted"
                }
              }
            }
          ]
        },
        {
          "allOf": [
            {
              "$ref": "#/$defs/attempt"
            },
            {
              "properties": {
                "phase": {
                  "const": "fresh"
                }
              }
            }
          ]
        }
      ],
      "items": false
    },
    "lease_disposition": {
      "enum": [
        "ACTIVE",
        "RELEASABLE",
        "QUARANTINED"
      ]
    },
    "projection": {
      "$ref": "#/$defs/nullableReference"
    },
    "journal": {
      "$ref": "#/$defs/nullableReference"
    },
    "artifacts": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/reference"
      },
      "uniqueItems": true
    }
  },
  "allOf": [
    {
      "if": {
        "properties": {
          "outcome": {
            "const": "PASS"
          }
        }
      },
      "then": {
        "properties": {
          "run_id": {
            "$ref": "#/$defs/identifier"
          },
          "lane_id": {
            "$ref": "#/$defs/identifier"
          },
          "terminal": {
            "const": true
          },
          "failure": {
            "type": "null"
          },
          "lease_disposition": {
            "const": "RELEASABLE"
          },
          "projection": {
            "$ref": "#/$defs/reference"
          },
          "journal": {
            "$ref": "#/$defs/reference"
          },
          "bindings": {
            "properties": {
              "proposal": {
                "$ref": "#/$defs/binding"
              },
              "approval": {
                "$ref": "#/$defs/binding"
              },
              "lease": {
                "$ref": "#/$defs/binding"
              },
              "capture_contract": {
                "$ref": "#/$defs/binding"
              },
              "recovery_plan": {
                "$ref": "#/$defs/binding"
              },
              "controller_distribution": {
                "$ref": "#/$defs/binding"
              },
              "original_closure": {
                "$ref": "#/$defs/binding"
              },
              "supplemental_closure": {
                "$ref": "#/$defs/binding"
              }
            }
          },
          "attempts": {
            "minItems": 3,
            "prefixItems": [
              {
                "properties": {
                  "started": {
                    "const": true
                  },
                  "terminal": {
                    "const": true
                  },
                  "outcome": {
                    "const": "PASS"
                  }
                }
              },
              {
                "properties": {
                  "started": {
                    "const": true
                  },
                  "terminal": {
                    "const": true
                  },
                  "outcome": {
                    "const": "INFRA_ERROR"
                  },
                  "runner_exit": {
                    "const": -9
                  },
                  "guest": {
                    "$ref": "#/$defs/guest"
                  },
                  "target_fingerprint": {
                    "$ref": "#/$defs/hash"
                  },
                  "processes": {
                    "minItems": 2
                  },
                  "projection": {
                    "$ref": "#/$defs/reference"
                  },
                  "streams": {
                    "properties": {
                      "overflow": {
                        "const": false
                      }
                    }
                  }
                }
              },
              {
                "properties": {
                  "started": {
                    "const": true
                  },
                  "terminal": {
                    "const": true
                  },
                  "outcome": {
                    "const": "PASS"
                  }
                }
              }
            ]
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "outcome": {
            "enum": [
              "FAIL",
              "INFRA_ERROR"
            ]
          }
        }
      },
      "then": {
        "properties": {
          "failure": {
            "$ref": "#/$defs/failure"
          },
          "projection": {
            "type": "null"
          }
        }
      }
    },
    {
      "if": {
        "properties": {
          "lease_disposition": {
            "const": "RELEASABLE"
          }
        }
      },
      "then": {
        "properties": {
          "terminal": {
            "const": true
          },
          "outcome": {
            "enum": [
              "PASS",
              "FAIL",
              "INFRA_ERROR"
            ]
          },
          "failure": {
            "$ref": "#/$defs/releasableFailure"
          },
          "attempts": {
            "minItems": 1,
            "minContains": 1,
            "contains": {
              "properties": {
                "started": {
                  "const": true
                }
              }
            },
            "items": {
              "allOf": [
                {
                  "properties": {
                    "terminal": {
                      "const": true
                    },
                    "failure": {
                      "$ref": "#/$defs/releasableFailure"
                    }
                  }
                },
                {
                  "if": {
                    "properties": {
                      "started": {
                        "const": true
                      }
                    }
                  },
                  "then": {
                    "properties": {
                      "cleanup": {
                        "$ref": "#/$defs/cleanProof"
                      }
                    }
                  }
                }
              ]
            }
          }
        }
      }
    }
  ],
  "$defs": {
    "identifier": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]*$"
    },
    "hash": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$",
      "not": {
        "const": "0000000000000000000000000000000000000000000000000000000000000000"
      }
    },
    "relativePath": {
      "type": "string",
      "minLength": 1,
      "pattern": "^(?!/)(?!.*(?:^|/)\\.\\.?(?:/|$))(?!.*//)(?!.*\\\\)(?!.*\u0000)[^/]+(?:/[^/]+)*$"
    },
    "reference": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "path",
        "sha256"
      ],
      "properties": {
        "path": {
          "$ref": "#/$defs/relativePath"
        },
        "sha256": {
          "$ref": "#/$defs/hash"
        }
      }
    },
    "nullableReference": {
      "anyOf": [
        {
          "$ref": "#/$defs/reference"
        },
        {
          "type": "null"
        }
      ]
    },
    "binding": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "path",
        "file_sha256",
        "canonical_sha256"
      ],
      "properties": {
        "path": {
          "$ref": "#/$defs/relativePath"
        },
        "file_sha256": {
          "$ref": "#/$defs/hash"
        },
        "canonical_sha256": {
          "anyOf": [
            {
              "$ref": "#/$defs/hash"
            },
            {
              "type": "null"
            }
          ]
        }
      }
    },
    "bindings": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "proposal",
        "approval",
        "lease",
        "capture_contract",
        "recovery_plan",
        "controller_distribution",
        "original_closure",
        "supplemental_closure"
      ],
      "properties": {
        "proposal": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        },
        "approval": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        },
        "lease": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        },
        "capture_contract": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        },
        "recovery_plan": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        },
        "controller_distribution": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        },
        "original_closure": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        },
        "supplemental_closure": {
          "anyOf": [
            {
              "$ref": "#/$defs/binding"
            },
            {
              "type": "null"
            }
          ]
        }
      }
    },
    "failure": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "code",
        "detail",
        "errno",
        "predecessor"
      ],
      "properties": {
        "code": {
          "enum": [
            "ADMISSION_REFUSED",
            "LEASE_REQUIRED",
            "OWNERSHIP_UNKNOWN",
            "STARTUP_TIMEOUT",
            "MARKER_TIMEOUT",
            "ATTEMPT_TIMEOUT",
            "CANCELLED",
            "EVIDENCE_INVALID",
            "IO_FAILED",
            "CLEANUP_INCOMPLETE"
          ]
        },
        "detail": {
          "type": "string",
          "minLength": 1
        },
        "errno": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 1
        },
        "predecessor": {
          "anyOf": [
            {
              "$ref": "#/$defs/identifier"
            },
            {
              "type": "null"
            }
          ]
        }
      }
    },
    "releasableFailure": {
      "anyOf": [
        {
          "type": "null"
        },
        {
          "allOf": [
            {
              "$ref": "#/$defs/failure"
            },
            {
              "properties": {
                "code": {
                  "enum": [
                    "STARTUP_TIMEOUT",
                    "MARKER_TIMEOUT",
                    "ATTEMPT_TIMEOUT",
                    "CANCELLED",
                    "EVIDENCE_INVALID"
                  ]
                }
              }
            }
          ]
        }
      ]
    },
    "identity": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "pid",
        "start_ticks",
        "host_boot_id"
      ],
      "properties": {
        "pid": {
          "type": "integer",
          "minimum": 1
        },
        "start_ticks": {
          "type": "integer",
          "minimum": 1
        },
        "host_boot_id": {
          "type": "string",
          "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        }
      }
    },
    "signalEvent": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "time",
        "signal",
        "sent",
        "errno"
      ],
      "properties": {
        "time": {
          "type": "number",
          "minimum": 0
        },
        "signal": {
          "type": "integer",
          "minimum": 1
        },
        "sent": {
          "type": "boolean"
        },
        "errno": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 1
        }
      }
    },
    "process": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "sequence",
        "time",
        "identity",
        "role",
        "ownership_basis",
        "parent",
        "raw_stat",
        "raw_fdinfo",
        "signals",
        "pidfd_exited",
        "wait_status",
        "pidfd_diagnostic"
      ],
      "properties": {
        "sequence": {
          "type": "integer",
          "minimum": 1
        },
        "time": {
          "type": "number",
          "minimum": 0
        },
        "identity": {
          "$ref": "#/$defs/identity"
        },
        "role": {
          "enum": [
            "runner",
            "qemu",
            "descendant"
          ]
        },
        "ownership_basis": {
          "enum": [
            "spawn-child",
            "observed-descendant",
            "adopted-child"
          ]
        },
        "parent": {
          "anyOf": [
            {
              "$ref": "#/$defs/identity"
            },
            {
              "type": "null"
            }
          ]
        },
        "raw_stat": {
          "type": "array",
          "minItems": 1,
          "items": {
            "$ref": "#/$defs/reference"
          }
        },
        "raw_fdinfo": {
          "type": "array",
          "minItems": 1,
          "items": {
            "$ref": "#/$defs/reference"
          }
        },
        "signals": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/signalEvent"
          }
        },
        "pidfd_exited": {
          "type": "boolean"
        },
        "wait_status": {
          "type": [
            "integer",
            "null"
          ]
        },
        "pidfd_diagnostic": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 0
        }
      }
    },
    "cleanup": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "status",
        "subreaper_readback",
        "scans",
        "adoptions",
        "final_echild",
        "unresolved_live",
        "all_pidfds_exited",
        "mountinfo_before",
        "mountinfo_after"
      ],
      "properties": {
        "status": {
          "enum": [
            "CLEAN",
            "INCOMPLETE"
          ]
        },
        "subreaper_readback": {
          "type": [
            "boolean",
            "null"
          ]
        },
        "scans": {
          "type": "integer",
          "minimum": 0
        },
        "adoptions": {
          "type": "integer",
          "minimum": 0
        },
        "final_echild": {
          "type": "boolean"
        },
        "unresolved_live": {
          "type": "integer",
          "minimum": 0
        },
        "all_pidfds_exited": {
          "type": "boolean"
        },
        "mountinfo_before": {
          "$ref": "#/$defs/nullableReference"
        },
        "mountinfo_after": {
          "$ref": "#/$defs/nullableReference"
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "status": {
                "const": "CLEAN"
              }
            }
          },
          "then": {
            "properties": {
              "subreaper_readback": {
                "const": true
              },
              "final_echild": {
                "const": true
              },
              "unresolved_live": {
                "const": 0
              },
              "all_pidfds_exited": {
                "const": true
              },
              "mountinfo_before": {
                "$ref": "#/$defs/reference"
              },
              "mountinfo_after": {
                "$ref": "#/$defs/reference"
              }
            }
          }
        }
      ]
    },
    "cleanProof": {
      "allOf": [
        {
          "$ref": "#/$defs/cleanup"
        },
        {
          "properties": {
            "status": {
              "const": "CLEAN"
            }
          }
        }
      ]
    },
    "invocation": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "argv",
        "cwd",
        "environment_policy",
        "environment",
        "environment_sha256"
      ],
      "properties": {
        "argv": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "string",
            "minLength": 1
          }
        },
        "cwd": {
          "type": "string",
          "pattern": "^/"
        },
        "environment_policy": {
          "const": "admitted-sanitized-with-approved-overrides"
        },
        "environment": {
          "type": "object",
          "additionalProperties": {
            "type": "string"
          }
        },
        "environment_sha256": {
          "$ref": "#/$defs/hash"
        }
      }
    },
    "timings": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "wall_start",
        "wall_end",
        "monotonic_start",
        "monotonic_end"
      ],
      "properties": {
        "wall_start": {
          "type": [
            "number",
            "null"
          ]
        },
        "wall_end": {
          "type": [
            "number",
            "null"
          ]
        },
        "monotonic_start": {
          "type": [
            "number",
            "null"
          ],
          "minimum": 0
        },
        "monotonic_end": {
          "type": [
            "number",
            "null"
          ],
          "minimum": 0
        }
      }
    },
    "guest": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "attempt_id",
        "guest_id",
        "boot_id",
        "session_id"
      ],
      "properties": {
        "attempt_id": {
          "$ref": "#/$defs/identifier"
        },
        "guest_id": {
          "$ref": "#/$defs/identifier"
        },
        "boot_id": {
          "type": "string",
          "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        },
        "session_id": {
          "type": "integer",
          "minimum": 1
        }
      }
    },
    "streams": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "stdout",
        "stderr",
        "limit_bytes",
        "overflow"
      ],
      "properties": {
        "stdout": {
          "$ref": "#/$defs/nullableReference"
        },
        "stderr": {
          "$ref": "#/$defs/nullableReference"
        },
        "limit_bytes": {
          "const": 67108864
        },
        "overflow": {
          "type": "boolean"
        }
      }
    },
    "guestFile": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "name",
        "reference"
      ],
      "properties": {
        "name": {
          "$ref": "#/$defs/relativePath"
        },
        "reference": {
          "$ref": "#/$defs/reference"
        }
      }
    },
    "attempt": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "phase",
        "attempt_id",
        "started",
        "terminal",
        "invocation",
        "timings",
        "runner_exit",
        "reason",
        "outcome",
        "failure",
        "guest",
        "target_fingerprint",
        "processes",
        "cleanup",
        "streams",
        "guest_files",
        "projection"
      ],
      "properties": {
        "phase": {
          "enum": [
            "main",
            "interrupted",
            "fresh"
          ]
        },
        "attempt_id": {
          "$ref": "#/$defs/identifier"
        },
        "started": {
          "type": "boolean"
        },
        "terminal": {
          "type": "boolean"
        },
        "invocation": {
          "anyOf": [
            {
              "$ref": "#/$defs/invocation"
            },
            {
              "type": "null"
            }
          ]
        },
        "timings": {
          "$ref": "#/$defs/timings"
        },
        "runner_exit": {
          "type": [
            "integer",
            "null"
          ]
        },
        "reason": {
          "type": "string",
          "minLength": 1
        },
        "outcome": {
          "enum": [
            "PASS",
            "FAIL",
            "INFRA_ERROR",
            "NOT_RUN"
          ]
        },
        "failure": {
          "anyOf": [
            {
              "$ref": "#/$defs/failure"
            },
            {
              "type": "null"
            }
          ]
        },
        "guest": {
          "anyOf": [
            {
              "$ref": "#/$defs/guest"
            },
            {
              "type": "null"
            }
          ]
        },
        "target_fingerprint": {
          "anyOf": [
            {
              "$ref": "#/$defs/hash"
            },
            {
              "type": "null"
            }
          ]
        },
        "processes": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/process"
          }
        },
        "cleanup": {
          "anyOf": [
            {
              "$ref": "#/$defs/cleanup"
            },
            {
              "type": "null"
            }
          ]
        },
        "streams": {
          "$ref": "#/$defs/streams"
        },
        "guest_files": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/guestFile"
          }
        },
        "projection": {
          "$ref": "#/$defs/nullableReference"
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "started": {
                "const": false
              },
              "phase": {
                "enum": [
                  "interrupted",
                  "fresh"
                ]
              }
            }
          },
          "then": {
            "properties": {
              "failure": {
                "allOf": [
                  {
                    "$ref": "#/$defs/failure"
                  },
                  {
                    "properties": {
                      "predecessor": {
                        "$ref": "#/$defs/identifier"
                      }
                    }
                  }
                ]
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "outcome": {
                "const": "NOT_RUN"
              }
            }
          },
          "then": {
            "properties": {
              "started": {
                "const": false
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "started": {
                "const": false
              }
            }
          },
          "then": {
            "properties": {
              "outcome": {
                "const": "NOT_RUN"
              },
              "runner_exit": {
                "type": "null"
              },
              "guest": {
                "type": "null"
              },
              "target_fingerprint": {
                "type": "null"
              },
              "processes": {
                "maxItems": 0
              },
              "cleanup": {
                "type": "null"
              },
              "projection": {
                "type": "null"
              },
              "guest_files": {
                "maxItems": 0
              },
              "timings": {
                "properties": {
                  "wall_start": {
                    "type": "null"
                  },
                  "wall_end": {
                    "type": "null"
                  },
                  "monotonic_start": {
                    "type": "null"
                  },
                  "monotonic_end": {
                    "type": "null"
                  }
                }
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "started": {
                "const": true
              }
            }
          },
          "then": {
            "properties": {
              "invocation": {
                "$ref": "#/$defs/invocation"
              },
              "timings": {
                "properties": {
                  "wall_start": {
                    "type": "number"
                  },
                  "monotonic_start": {
                    "type": "number"
                  }
                }
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "outcome": {
                "const": "PASS"
              }
            }
          },
          "then": {
            "properties": {
              "started": {
                "const": true
              },
              "terminal": {
                "const": true
              },
              "runner_exit": {
                "const": 0
              },
              "failure": {
                "type": "null"
              },
              "guest": {
                "$ref": "#/$defs/guest"
              },
              "target_fingerprint": {
                "$ref": "#/$defs/hash"
              },
              "cleanup": {
                "$ref": "#/$defs/cleanProof"
              },
              "projection": {
                "$ref": "#/$defs/reference"
              },
              "processes": {
                "minItems": 2
              },
              "streams": {
                "properties": {
                  "overflow": {
                    "const": false
                  }
                }
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "projection": {
                "type": "object"
              }
            }
          },
          "then": {
            "properties": {
              "started": {
                "const": true
              },
              "terminal": {
                "const": true
              },
              "guest": {
                "$ref": "#/$defs/guest"
              },
              "target_fingerprint": {
                "$ref": "#/$defs/hash"
              },
              "cleanup": {
                "$ref": "#/$defs/cleanProof"
              }
            }
          }
        }
      ]
    }
  }
}""")
_RESULT_SCHEMA_V2 = json.loads(json.dumps(_RESULT_SCHEMA_V1))
_RESULT_SCHEMA_V2["$id"] = "urn:mojobpf:controller-result-v2"
_RESULT_SCHEMA_V2["title"] = "Durable disposable controller completion result"
_RESULT_SCHEMA_V2["properties"]["schema_version"]["const"] = 2
_RESULT_SCHEMA_V2["properties"]["contract"]["const"] = CONTROLLER_CONTRACT_V2
for _completion_name in ("completion_journal", "completion_receipt"):
    _cleanup_shape = _RESULT_SCHEMA_V2["$defs"]["cleanup"]
    _cleanup_shape["required"].append(_completion_name)
    _cleanup_shape["properties"][_completion_name] = {"$ref": "#/$defs/nullableReference"}
    _cleanup_shape["allOf"][0]["then"]["properties"][_completion_name] = {"$ref": "#/$defs/reference"}


def _schema_matches(value, schema, root):
    if type(schema) is bool:
        return schema
    if "$ref" in schema:
        target = root
        for component in schema["$ref"][2:].split("/"):
            target = target[component]
        if not _schema_matches(value, target, root):
            return False
    types = {"object": lambda x: type(x) is dict and all(type(key) is str for key in x),
             "array": lambda x: type(x) is list, "string": lambda x: type(x) is str,
             "integer": lambda x: type(x) is int, "number": lambda x: type(x) in (int, float) and math.isfinite(x),
             "boolean": lambda x: type(x) is bool, "null": lambda x: x is None}
    if "type" in schema:
        names = schema["type"] if type(schema["type"]) is list else [schema["type"]]
        if not any(types[name](value) for name in names):
            return False
    if "const" in schema and not json_equal(value, schema["const"]):
        return False
    if "enum" in schema and not any(json_equal(value, option) for option in schema["enum"]):
        return False
    if "not" in schema and _schema_matches(value, schema["not"], root):
        return False
    if "allOf" in schema and not all(_schema_matches(value, child, root) for child in schema["allOf"]):
        return False
    if "anyOf" in schema and not any(_schema_matches(value, child, root) for child in schema["anyOf"]):
        return False
    if "if" in schema and _schema_matches(value, schema["if"], root) and not _schema_matches(value, schema.get("then", True), root):
        return False
    if type(value) is dict:
        properties = schema.get("properties", {})
        if not set(schema.get("required", ())) <= set(value):
            return False
        for key, item in value.items():
            child = properties.get(key, schema.get("additionalProperties", True))
            if not _schema_matches(item, child, root):
                return False
    elif type(value) is list:
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            return False
        if schema.get("uniqueItems") and any(json_equal(item, prior) for i, item in enumerate(value) for prior in value[:i]):
            return False
        prefix = schema.get("prefixItems", ())
        for index, item in enumerate(value):
            child = prefix[index] if index < len(prefix) else schema.get("items", True)
            if not _schema_matches(item, child, root):
                return False
        if "contains" in schema and sum(_schema_matches(item, schema["contains"], root) for item in value) < schema.get("minContains", 1):
            return False
    elif type(value) is str:
        if len(value) < schema.get("minLength", 0) or "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
    elif type(value) in (int, float):
        if "minimum" in schema and value < schema["minimum"] or "maximum" in schema and value > schema["maximum"]:
            return False
    return True


def validate_result(record: dict) -> dict:
    """Check a closed versioned sidecar shape; this does not grant authority.

    Durable artifact/context acceptance additionally requires validate_result_bundle.
    Legacy v1 remains read-only. No installed schema resource is required.
    """
    try:
        raw = json.dumps(_thaw(_freeze(record)), allow_nan=False).encode()
        _require(len(raw) <= JSON_LIMIT, "result exceeds JSON byte bound", "EVIDENCE_INVALID")
        _require(type(record) is dict and type(record.get("schema_version")) is int
                 and record["schema_version"] in (1, 2), "unknown result version", "EVIDENCE_INVALID")
        schema = _RESULT_SCHEMA_V1 if record["schema_version"] == 1 else _RESULT_SCHEMA_V2
        _require(_schema_matches(record, schema, schema), "invalid versioned result shape", "EVIDENCE_INVALID")
        return _thaw(_freeze(record))
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ControllerError("EVIDENCE_INVALID", "result cannot be represented safely") from exc


@dataclass(frozen=True)
class BytePin:
    """An independently retained absolute pathname and file-byte SHA-256."""
    path: str
    sha256: str


@dataclass(frozen=True)
class DispatcherCompletionObservation:
    """Trusted caller observation, never constructed by sidecar/replay loaders.

    The dispatcher supplies this only after independently observing the exact
    controller's normal termination and successful final checked readback.
    This represents a caller provenance precondition, not a signed attestation.
    """
    run_id: str
    lane_id: str
    lease_id: str
    proposal_sha256: str
    approval_sha256: str
    lease_sha256: str
    controller_distribution_sha256: str
    controller_identity: ProcessIdentity
    normal_exit: bool
    exit_code: int
    final_readback_acknowledged: bool
    result: BytePin
    journal: BytePin


class _BundleReader:
    """Read fixed controller-owned evidence through retained no-follow handles."""
    def __init__(self, validated, *, _budget=None):
        self.v, self.directories, self.observations, self.inodes = validated, {}, {}, {}
        self.budget=_budget
        self.root = str(Path(validated.paths.controller_output).relative_to(validated.paths.output_root))
        parent = None
        try:
            parent = _open_parent(validated.paths.controller_output)
            fd = os.open(Path(validated.paths.controller_output).name,
                         os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            self.directories[""] = (fd,None)
            self.directories[""] = (fd, self._directory(os.fstat(fd)))
            self._verify_directories()
        except BaseException:
            self.close()
            raise
        finally:
            if parent is not None: os.close(parent)

    def _directory(self, info):
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.v.lock.owner_uid
                 and stat.S_IMODE(info.st_mode) == 0o700, "bundle directory is not controller-owned", "EVIDENCE_INVALID")
        return _stat_identity(info) + (info.st_uid, info.st_gid)

    def _verify_directories(self):
        for path, (fd, identity) in self.directories.items():
            if self.budget is not None:self.budget.check()
            if path:
                parent, name = path.rsplit("/",1) if "/" in path else ("",path)
                named = os.stat(name,dir_fd=self.directories[parent][0],follow_symlinks=False)
            else:
                parent_fd = _open_parent(self.v.paths.controller_output)
                try: named = os.stat(Path(self.v.paths.controller_output).name,dir_fd=parent_fd,follow_symlinks=False)
                finally: os.close(parent_fd)
            _require(self._directory(os.fstat(fd)) == self._directory(named) == identity,
                     "bundle directory identity changed", "EVIDENCE_INVALID")
            if self.budget is not None:self.budget.check()

    def read(self, reference, *, maximum=JSON_LIMIT, capture=True):
        _mapping(reference,{"path","sha256"},"EVIDENCE_INVALID")
        path = _bounded_path(reference["path"],relative=True); _hash(reference["sha256"],"EVIDENCE_INVALID")
        _require(path.startswith(self.root+"/"), "artifact escapes controller-only directory", "EVIDENCE_INVALID")
        relative = path[len(self.root)+1:]
        parent, name = relative.rsplit("/",1) if "/" in relative else ("",relative)
        prefix = ""
        for component in parent.split("/") if parent else ():
            new = prefix+"/"+component if prefix else component
            if new not in self.directories:
                fd = os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.directories[prefix][0])
                self.directories[new] = (fd,None)
                self.directories[new] = (fd,self._directory(os.fstat(fd)))
            prefix = new
        self._verify_directories()
        fd = os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.directories[parent][0])
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==self.v.lock.owner_uid
                     and stat.S_IMODE(before.st_mode)==0o600 and before.st_size<=maximum,
                     "artifact is not bounded controller-owned single-link data", "EVIDENCE_INVALID")
            inode = (before.st_dev,before.st_ino)
            _require(inode not in self.inodes or self.inodes[inode]==path, "distinct artifacts alias one inode", "EVIDENCE_INVALID")
            self.inodes[inode] = path
            chunks, size, digest = [], 0, hashlib.sha256()
            while True:
                if self.budget is not None:self.budget.check()
                raw = os.read(fd,min(65536,maximum-size+1))
                if self.budget is not None:self.budget.check()
                if not raw: break
                size += len(raw); _require(size<=maximum,"artifact byte bound exceeded","EVIDENCE_INVALID")
                digest.update(raw)
                if capture: chunks.append(raw)
            after = os.fstat(fd); named = os.stat(name,dir_fd=self.directories[parent][0],follow_symlinks=False)
            identity = _stat_identity(after)+(after.st_uid,after.st_gid)
            _require(_stat_identity(before)+(before.st_uid,before.st_gid)==identity
                     ==_stat_identity(named)+(named.st_uid,named.st_gid) and size==before.st_size
                     and digest.hexdigest()==reference["sha256"], "artifact bytes or identity changed", "EVIDENCE_INVALID")
            prior = self.observations.get(path)
            _require(prior is None or prior==(identity,reference["sha256"],maximum),"artifact changed between reads","EVIDENCE_INVALID")
            self.observations[path]=(identity,reference["sha256"],maximum)
            self._verify_directories()
            return b"".join(chunks) if capture else None
        finally: os.close(fd)

    def revalidate(self):
        for path, (_, digest, maximum) in tuple(self.observations.items()):
            self.read({"path":path,"sha256":digest},maximum=maximum,capture=False)

    def close(self):
        failures = []
        for path,(fd,_) in reversed(tuple(self.directories.items())):
            del self.directories[path]
            try: os.close(fd)
            except OSError as exc: failures.append(exc)
        if failures: raise failures[0]


def _provisional_for(validated):
    return {"schema_version":1,"run_id":validated.run_id,"lane_id":validated.lane_id,
            "lease":{"id":validated.lease_id,"owner":validated.owner,"exclusive":True,"record_sha256":validated.lease_sha256,
                     "rootfs_read_only":True,"guest_pin_root":"/sys/fs/bpf/mojobpf/"+validated.run_id,
                     "host_write_paths":[validated.paths.output_root,validated.paths.tmp_root]},"expected":dict(validated.expected)}


def _transition_records(raw, validated, result):
    _require(0<len(raw)<=JSON_LIMIT and raw.endswith(b"\n") and raw.count(b"\n")<=65536,
             "controller journal bounds or final newline failed", "EVIDENCE_INVALID")
    records = [_strict_json(line) for line in raw.splitlines()]
    fields = {"schema_version","contract","sequence","time","run_id","lane_id","lease_sha256","proposal_sha256",
              "controller_distribution_sha256","event","phase","attempt_id","data"}
    context = {"run_id":validated.run_id,"lane_id":validated.lane_id,"lease_sha256":validated.lease_sha256,
               "proposal_sha256":validated.proposal_sha256,
               "controller_distribution_sha256":dict((n,b.file_sha256) for n,b,_ in validated.inputs)["controller_distribution"]}
    event_fields = {"lease-active":{"state","run_id","lane_id","lease_sha256","controller_identity"},
        "controller-cache-before":{"path","dev","ino","entries","empty"},"controller-cache-after":{"path","dev","ino","entries","empty"},
        "nice-inherited":{"before","after"},"closure-refreshed":{"files","inventories","wheel_members","unique_bytes"},
        "attempt-open":{"expected_guardian_sequence"},"cache-before":{"path","dev","ino","entries","empty"},
        "cache-after":{"path","dev","ino","entries","empty"},"spawn-intent":{"argv"},"runner-retained":set(),
        "qemu-observed":{"sequence","identity","image"},
        "completion-committed":{"epoch_first_sequence","epoch_last_sequence","completion_journal","completion_receipt"},
        "attempt-terminal":{"outcome","failure","projection"},"lane-terminal":{"outcome","lease_disposition","attempts","projection","artifacts"}}
    lane_events = {"lease-active","controller-cache-before","controller-cache-after","nice-inherited","lane-terminal"}
    by_attempt, previous = {i.attempt_id:[] for i in validated.invocations}, -1
    for sequence, record in enumerate(records,1):
        _mapping(record,fields,"EVIDENCE_INVALID")
        _require(type(record["schema_version"]) is int and record["schema_version"]==2
                 and record["contract"]=="controller-transition-v2" and type(record["sequence"]) is int
                 and record["sequence"]==sequence and all(record[k]==v for k,v in context.items()),
                 "controller journal context/sequence differs", "EVIDENCE_INVALID")
        moment = record["time"]
        _require(type(moment) in (int,float) and math.isfinite(moment) and moment>=previous,
                 "controller journal chronology is invalid", "EVIDENCE_INVALID"); previous=moment
        event = record["event"]
        _require(type(event) is str and event in event_fields,"unknown controller event","EVIDENCE_INVALID")
        _mapping(record["data"],event_fields[event],"EVIDENCE_INVALID")
        if event in lane_events:
            _require(record["phase"] is None and record["attempt_id"] is None,"lane event has an attempt","EVIDENCE_INVALID")
        else:
            invocation = next((i for i in validated.invocations if i.attempt_id==record["attempt_id"]),None)
            _require(invocation is not None and record["phase"]==invocation.phase,"foreign controller attempt","EVIDENCE_INVALID")
            by_attempt[invocation.attempt_id].append(record)
        if event in {"cache-before","cache-after","controller-cache-before","controller-cache-after"}:
            data = record["data"]
            wanted = validated.paths.controller_pycache if event.startswith("controller") else dict(invocation.env_overrides)["PYTHONPYCACHEPREFIX"]
            _require(data["path"]==wanted and type(data["dev"]) is int and data["dev"]>=0 and type(data["ino"]) is int
                     and data["ino"]>0 and data["entries"]==[] and data["empty"] is True,"cache observation is not empty and owned","EVIDENCE_INVALID")
    def one(event):
        found=[r for r in records if r["event"]==event]
        _require(len(found)==1,"missing/repeated controller event: "+event,"EVIDENCE_INVALID")
        return found[0]
    opening, terminal = one("lease-active"),one("lane-terminal")
    _require(opening is records[0] and terminal is records[-1],"controller journal is not complete","EVIDENCE_INVALID")
    active=opening["data"]
    _require(active["state"]=="ACTIVE" and all(active[k]==context[k] for k in ("run_id","lane_id","lease_sha256")),
             "lease was not ACTIVE before execution","EVIDENCE_INVALID")
    _mapping(active["controller_identity"],{"pid","start_ticks","host_boot_id"},"EVIDENCE_INVALID")
    identity=active["controller_identity"]
    _integer(identity["pid"],1,"EVIDENCE_INVALID");_integer(identity["start_ticks"],1,"EVIDENCE_INVALID")
    _require(identity["host_boot_id"]==validated.host_boot_id,"foreign controller host","EVIDENCE_INVALID")
    nice=one("nice-inherited")
    _require(all(type(value) is int for value in nice["data"].values())
             and nice["data"]["after"]==nice["data"]["before"]+10,"nice inheritance differs","EVIDENCE_INVALID")
    before,after=one("controller-cache-before"),one("controller-cache-after")
    _require(opening["sequence"]<before["sequence"]<nice["sequence"]<after["sequence"]<terminal["sequence"]
             and all(before["data"][k]==after["data"][k] for k in ("path","dev","ino")),
             "controller cache/nice chronology differs","EVIDENCE_INVALID")
    expected_terminal={k:result[k] for k in ("outcome","lease_disposition","attempts","projection")}
    expected_terminal["artifacts"]=[ref for ref in result["artifacts"] if ref!=result["journal"]]
    _require(json_equal(terminal["data"],expected_terminal),"terminal journal disagrees with sidecar","EVIDENCE_INVALID")
    previous_terminal=nice["sequence"]
    for invocation,attempt in zip(validated.invocations,result["attempts"]):
        events=by_attempt[invocation.attempt_id]
        if not attempt["started"]:
            _require(not events,"NOT_RUN attempt has execution events","EVIDENCE_INVALID");continue
        names=[r["event"] for r in events]
        _require(len(set(names))==len(names) and names[:2]==["closure-refreshed","attempt-open"]
                 and names[-1]=="attempt-terminal" and events[0]["sequence"]>previous_terminal,
                 "attempt transition order or boundary differs","EVIDENCE_INVALID")
        previous_terminal=events[-1]["sequence"]
        _require(previous_terminal<after["sequence"],"attempt follows controller terminal capture","EVIDENCE_INVALID")
        order={name:index for index,name in enumerate(("closure-refreshed","attempt-open","cache-before","spawn-intent","runner-retained",
               "qemu-observed","completion-committed","cache-after","attempt-terminal"))}
        _require(all(name in order for name in names) and [order[n] for n in names]==sorted(order[n] for n in names),
                 "attempt event ordering differs","EVIDENCE_INVALID")
        end=events[-1]["data"]
        _require(json_equal(end,{k:attempt[k] for k in ("outcome","failure","projection")}),"attempt terminal differs","EVIDENCE_INVALID")
        for event in events:
            if event["event"]=="spawn-intent":
                _require(event["data"]["argv"]==list(invocation.argv),"spawn intent argv differs","EVIDENCE_INVALID")
            if event["event"]=="closure-refreshed":
                _require(all(type(v) is int and v>=0 for v in event["data"].values()),"closure observation is invalid","EVIDENCE_INVALID")
            if event["event"]=="attempt-open":_integer(event["data"]["expected_guardian_sequence"],1,"EVIDENCE_INVALID")
    return records,by_attempt,identity


def _inspect_result_record(validated, result, *, result_document=None, _budget=None):
    authority=_execution_authority(validated)
    result=validate_result(result)
    _require(result["schema_version"]==2 and result["run_id"]==validated.run_id and result["lane_id"]==validated.lane_id
             and result["terminal"] is True and len(result["attempts"])==3,"result context/attempt count differs","EVIDENCE_INVALID")
    reader=None
    try:
        reader=_BundleReader(validated,_budget=_budget)
        expected_path=str(Path(validated.paths.controller_output)/"controller-result.json")
        result_path=str(Path(expected_path).relative_to(validated.paths.output_root))
        if result_document is not None:
            consumed=result_document.consumed
            _require(consumed.path==expected_path,"result is not the admitted controller destination","EVIDENCE_INVALID")
            result_ref={"path":result_path,"sha256":consumed.file_sha256}
            _require(reader.read(result_ref)==consumed.raw,"result changed after independent pin","EVIDENCE_INVALID")
        inventory={}
        _require(len(result["artifacts"])<=65536,"artifact count exceeds bound","EVIDENCE_INVALID")
        for ref in result["artifacts"]:
            _require(ref["path"] not in inventory and ref["path"]!=result_path,"duplicate/self-referenced artifact","EVIDENCE_INVALID")
            inventory[ref["path"]]=ref
        def read(ref, maximum=JSON_LIMIT):
            _require(ref is not None and json_equal(inventory.get(ref["path"]),ref),"reference missing/inconsistent in inventory","EVIDENCE_INVALID")
            return reader.read(ref,maximum=maximum)
        bindings={name:(doc.consumed,digest_of(_document(doc))) for name,doc in zip(("proposal","approval","lease"),authority)}
        bindings.update({n:(b,c) for n,b,c in validated.inputs if n in result["bindings"]})
        maxima={}
        for name,binding in result["bindings"].items():
            consumed,canonical=bindings[name]
            _require(binding is not None and binding["file_sha256"]==consumed.file_sha256 and binding["canonical_sha256"]==canonical,
                     "input binding differs from prior authority","EVIDENCE_INVALID")
            ref={"path":binding["path"],"sha256":binding["file_sha256"]}
            maximum=_INPUT_BYTE_LIMITS.get(name,JSON_LIMIT);maxima[ref["path"]]=maximum
            _require(read(ref,maximum)==consumed.raw,"consumed input bytes differ","EVIDENCE_INVALID")
        journal=read(result["journal"])
        transitions,by_attempt,controller_identity=_transition_records(journal,validated,result)
        previous_prefix,previous_last,completed=[],0,[]
        provisional=_provisional_for(validated)
        stopping=None
        for invocation,attempt in zip(validated.invocations,result["attempts"]):
            _require(attempt["phase"]==invocation.phase and attempt["attempt_id"]==invocation.attempt_id,
                     "sidecar attempt differs from issued invocation","EVIDENCE_INVALID")
            if not attempt["started"]:
                _require(stopping is not None and attempt["failure"]["predecessor"]==stopping["attempt_id"]
                         and all(attempt["failure"][k]==stopping["failure"][k] for k in ("code","detail","errno")),
                         "NOT_RUN successor lacks causal failure","EVIDENCE_INVALID")
                stopping=attempt;continue
            _require(stopping is None,"attempt started after terminal failure","EVIDENCE_INVALID")
            expected_invocation={"argv":list(invocation.argv),"cwd":invocation.cwd,
                "environment_policy":"admitted-sanitized-with-approved-overrides","environment":dict(invocation.env_overrides),
                "environment_sha256":digest_of(dict(invocation.env_overrides))}
            _require(json_equal(attempt["invocation"],expected_invocation),"measured invocation differs","EVIDENCE_INVALID")
            timings=attempt["timings"]
            _require(all(type(v) in (int,float) and math.isfinite(v) for v in timings.values())
                     and timings["wall_start"]<=timings["wall_end"] and timings["monotonic_start"]<=timings["monotonic_end"],
                     "attempt timings are not observed and ordered","EVIDENCE_INVALID")
            events=by_attempt[invocation.attempt_id]
            commits=[r for r in events if r["event"]=="completion-committed"]
            cleanup=attempt["cleanup"]
            if cleanup is None or cleanup["status"]!="CLEAN":
                _require(not commits and attempt["projection"] is None,"unsealed attempt claims caller completion","EVIDENCE_INVALID")
                stopping=attempt;continue
            _require(len(commits)==1,"CLEAN has no durable caller commit","EVIDENCE_INVALID")
            caches={r["event"]:r for r in events if r["event"] in {"cache-before","cache-after"}}
            _require(set(caches)=={"cache-before","cache-after"}
                     and all(caches["cache-before"]["data"][k]==caches["cache-after"]["data"][k] for k in ("path","dev","ino")),
                     "attempt cache identity/readback differs","EVIDENCE_INVALID")
            commit=commits[0];data=commit["data"]
            _require(all(json_equal(data[k],cleanup[k]) for k in ("completion_journal","completion_receipt")),
                     "cleanup pair differs from caller commit","EVIDENCE_INVALID")
            prefix=read(cleanup["completion_journal"],_GUARDIAN_PREFIX_LIMIT);receipt_raw=read(cleanup["completion_receipt"],4096)
            maxima[cleanup["completion_journal"]["path"]]=_GUARDIAN_PREFIX_LIMIT
            maxima[cleanup["completion_receipt"]["path"]]=4096
            receipt=_strict_json(receipt_raw);records=[_strict_json(line) for line in prefix.splitlines()]
            first,last=receipt["epoch_first_sequence"],receipt["epoch_last_sequence"]
            opening=next(r for r in events if r["event"]=="attempt-open")
            _require(type(first) is int and type(last) is int and first==previous_last+1
                     and first==opening["data"]["expected_guardian_sequence"] and records[0]["sequence"]==1
                     and last==records[-1]["sequence"] and prefix.endswith(b"\n")
                     and data["epoch_first_sequence"]==first and type(data["epoch_first_sequence"]) is int
                     and data["epoch_last_sequence"]==last and type(data["epoch_last_sequence"]) is int
                     and sum(r["event"]=="prepared" for r in records)==len(completed)+1
                     and (not previous_prefix or prefix.startswith(previous_prefix)),
                     "caller epoch/full-prefix range differs","EVIDENCE_INVALID")
            replay=_CompletionBarrier._replay(prefix,receipt_raw);physical=replay["physical_drain"]
            _require(json_equal(records[first-1]["controller_identity"],controller_identity)
                     and opening["time"]<=records[first-1]["time"] and receipt["acknowledged_at"]<=commit["time"]<receipt["deadline"]
                     and commit["time"]<=timings["monotonic_end"]<receipt["deadline"],
                     "controller identity or commit chronology differs","EVIDENCE_INVALID")
            for _,old_receipt in completed:_CompletionBarrier._replay(prefix,old_receipt)
            for key in ("subreaper_readback","scans","adoptions","final_echild","unresolved_live","all_pidfds_exited"):
                _require(json_equal(cleanup[key],physical[key]),"sidecar physical cleanup differs","EVIDENCE_INVALID")
            for key in ("mountinfo_before","mountinfo_after"):
                _require(read(cleanup[key])==physical[key].encode(),"externalized raw mount bytes differ","EVIDENCE_INVALID")
            _require(json_equal(attempt["runner_exit"],physical["runner_exit"]),"signed runner status differs","EVIDENCE_INVALID")
            epoch=records[first-1:last];retained={r["entry_sequence"]:r for r in epoch if r["event"]=="retained"}
            entered=next(r for r in epoch if r["event"]=="cleanup-entered")
            _require(type(entered.get("cancelled")) is bool,"retained cancellation observation is not boolean","EVIDENCE_INVALID")
            _require(not entered["cancelled"] or (attempt["outcome"]!="PASS" and attempt["projection"] is None
                     and result["outcome"]!="PASS" and result["projection"] is None),
                     "retained external cancellation contradicts successful projection","EVIDENCE_INVALID")
            runners=[p for p in physical["processes"] if p["role"]=="runner"]
            if runners:
                observed={r["event"]:r for r in events if r["event"] in {"spawn-intent","runner-retained"}}
                _require(set(observed)=={"spawn-intent","runner-retained"}
                         and observed["spawn-intent"]["time"]<=retained[runners[0]["sequence"]]["time"]
                         <=observed["runner-retained"]["time"]<=entered["time"],
                         "runner lacks causal spawn/retention commitment","EVIDENCE_INVALID")
            qemus=[r for r in events if r["event"]=="qemu-observed"]
            qemu_sequence=None
            if qemus:
                qemu=qemus[0]["data"];qemu_sequence=qemu["sequence"]
                _require(type(qemu_sequence) is int and qemu_sequence in retained
                         and json_equal(qemu["identity"],retained[qemu_sequence]["identity"])
                         and json_equal(qemu["image"],vars(validated.qemu.image)),"observed QEMU binding differs","EVIDENCE_INVALID")
            processes={p["sequence"]:p for p in physical["processes"]}
            _require(len(attempt["processes"])==len(processes),"sidecar omitted retained identities","EVIDENCE_INVALID")
            expected_processes=[]
            for process in physical["processes"]:
                sequence=process["sequence"];record=next((p for p in attempt["processes"] if p["sequence"]==sequence),None)
                _require(record is not None,"sidecar retained identity missing","EVIDENCE_INVALID")
                for key in ("raw_stat","raw_fdinfo"):
                    _require(len(record[key])==len(process[key]) and all(read(ref)==raw.encode() for ref,raw in zip(record[key],process[key])),
                             "externalized raw process bytes differ","EVIDENCE_INVALID")
                parent=processes.get(process["parent_sequence"]);wait=process["wait_status"]
                expected_processes.append({"sequence":sequence,"time":retained[sequence]["time"],"identity":process["identity"],
                    "role":"qemu" if sequence==qemu_sequence else process["role"],"ownership_basis":process["ownership_basis"],
                    "parent":None if parent is None else parent["identity"],"raw_stat":record["raw_stat"],"raw_fdinfo":record["raw_fdinfo"],
                    "signals":[{k:r[k] for k in ("time","signal","errno","sent")} for r in epoch if r["event"]=="signal" and r["entry_sequence"]==sequence],
                    "pidfd_exited":process["exited"],"wait_status":None if wait is None else wait["exit_code"],"pidfd_diagnostic":None})
            _require(json_equal(attempt["processes"],expected_processes),"sidecar retained process facts differ","EVIDENCE_INVALID")
            if attempt["projection"] is not None:
                guest_files={}
                for row in attempt["guest_files"]:
                    _require(row["name"] not in guest_files and "/" not in row["name"],"guest file inventory ambiguous","EVIDENCE_INVALID")
                    guest_files[row["name"]]=row["reference"]
                semantic_names={"guest-identity.json","target.json","positive.json","pin_root_absence.json","ready-to-interrupt.json",
                                "guest-cleanup.json","permission_negative.json","permission_context.json"}
                guest_records={name[:-5]:_strict_json(read(ref)) for name,ref in guest_files.items() if name in semantic_names}
                projected=_strict_json(read(attempt["projection"]))
                expected_names={"execution","cleanup","target","positive","pin_root_absence"}|({"trigger"} if invocation.phase=="interrupted" else {"permission_negative","permission_context"})
                _mapping(projected,expected_names,"EVIDENCE_INVALID")
                execution_record,cleanup_record,guest,fingerprint=_projection_records(validated,provisional,invocation,attempt,guest_records,{"processes":physical["processes"],"cleanup":physical})
                _require(json_equal(attempt["guest"],guest) and attempt["target_fingerprint"]==fingerprint
                         and json_equal(_strict_json(read(projected["execution"])),execution_record)
                         and json_equal(_strict_json(read(projected["cleanup"])),cleanup_record),"v1 projection disagrees with measured facts","EVIDENCE_INVALID")
                for name in expected_names-{"execution","cleanup"}:
                    guest_name="ready-to-interrupt.json" if name=="trigger" else name+".json"
                    _require(json_equal(projected[name],guest_files.get(guest_name)),"projection guest reference differs","EVIDENCE_INVALID")
            intentional=(invocation.phase=="interrupted" and attempt["projection"] is not None and attempt["failure"] is not None
                         and attempt["failure"]["code"]=="CANCELLED" and attempt["failure"]["detail"]=="intentional interruption" and attempt["runner_exit"]==-9)
            if attempt["failure"] is not None and not intentional:stopping=attempt
            previous_prefix,previous_last=prefix,last;completed.append((prefix,receipt_raw))
        if completed:
            _require(transitions[-1]["time"]<receipt["deadline"],"terminal persistence exceeded original cleanup deadline","EVIDENCE_INVALID")
        if result["outcome"]=="PASS":
            _require(stopping is None and len(completed)==3 and result["failure"] is None
                     and all(a["projection"] is not None for a in result["attempts"]),"success lacks three complete measured phases","EVIDENCE_INVALID")
            wrapper=_strict_json(read(result["projection"]))
            maps=[_strict_json(read(a["projection"])) for a in result["attempts"]]
            _mapping(wrapper,{"schema_version","run_id","lane_id","lease_id","provisional_sha256","evidence"},"EVIDENCE_INVALID")
            _require(type(wrapper["schema_version"]) is int and wrapper["schema_version"]==1
                     and all(wrapper[k]==provisional[k] for k in ("run_id","lane_id")) and wrapper["lease_id"]==validated.lease_id
                     and wrapper["provisional_sha256"]==digest_of(provisional),"final v1 wrapper context differs","EVIDENCE_INVALID")
            _mapping(wrapper["evidence"],set(maps[0])|{"recovery"},"EVIDENCE_INVALID")
            _require(json_equal({k:v for k,v in wrapper["evidence"].items() if k!="recovery"},maps[0]),"main projection map differs","EVIDENCE_INVALID")
            recovery=_strict_json(read(wrapper["evidence"]["recovery"]))
            _mapping(recovery,{"outcome","terminal","plan_sha256","interrupted_attempt","fresh_attempt"},"EVIDENCE_INVALID")
            _require(recovery["outcome"]=="PASS" and recovery["terminal"] is True and recovery["plan_sha256"]==dict(validated.expected)["recovery_plan_sha256"]
                     and json_equal(_strict_json(read(recovery["interrupted_attempt"])),maps[1])
                     and json_equal(_strict_json(read(recovery["fresh_attempt"])),maps[2]),"recovery projection differs","EVIDENCE_INVALID")
            guests=[a["guest"] for a in result["attempts"]]
            identities=[(p["identity"]["pid"],p["identity"]["start_ticks"]) for a in result["attempts"] for p in a["processes"]]
            _require(all(len({g[k] for g in guests})==3 for k in ("guest_id","boot_id","session_id"))
                     and len(set(identities))==len(identities),"recovery reused measured identity","EVIDENCE_INVALID")
        else:
            _require(result["failure"] is not None and result["projection"] is None,"failed lane invents success projection","EVIDENCE_INVALID")
        for attempt in result["attempts"]:
            for name in ("stdout","stderr"):
                ref=attempt["streams"][name]
                if ref is not None:maxima[ref["path"]]=_STREAM_LIMIT
        # Check even unprojected diagnostics; no unverified inventory member is accepted.
        for path,ref in inventory.items():reader.read(ref,maximum=maxima.get(path,JSON_LIMIT),capture=False)
        reader.revalidate()
        return {"integrity":"VALID","release_authority":False,"controller_identity":controller_identity,"result":result}
    except (OSError,GuardianError,KeyError,ValueError,TypeError,OverflowError,RecursionError,StopIteration) as exc:
        raise ControllerError("EVIDENCE_INVALID","fixed-byte result bundle cannot be accepted: "+str(exc),errno=getattr(exc,"errno",None)) from exc
    finally:
        if reader is not None:
            try:reader.close()
            except OSError as exc:raise ControllerError("IO_FAILED","bundle reader release failed",errno=exc.errno) from exc
            if _budget is not None:_budget.check()


def inspect_result_bundle(validated, result_document):
    """Inspect admitted context and byte integrity without granting release.

    A CLEAN replay alone cannot establish completed dispatcher provenance.
    Legacy results remain available through validate_result, never this API.
    """
    return _inspect_result_record(validated,_document(result_document),result_document=result_document)


def validate_result_bundle(validated, result_document, *, completed_controller=None):
    """Require trusted completed-controller provenance before lease eligibility.

    READY still requires the separately pinned frozen bootstrap assessor.
    A visible terminal file or RELEASABLE hint alone never satisfies this API.
    """
    _execution_authority(validated)
    observation=completed_controller
    _require(type(observation) is DispatcherCompletionObservation,"trusted completed-controller observation is required","LEASE_REQUIRED")
    _require(observation.normal_exit is True and observation.final_readback_acknowledged is True
             and type(observation.exit_code) is int and observation.exit_code in (0,3),"controller termination/readback is unacknowledged or abnormal","LEASE_REQUIRED")
    _require(type(observation.controller_identity) is ProcessIdentity,"typed controller identity is required","LEASE_REQUIRED")
    _integer(observation.controller_identity.pid,1,"LEASE_REQUIRED")
    _integer(observation.controller_identity.start_ticks,1,"LEASE_REQUIRED")
    _boot(observation.controller_identity.host_boot_id,"LEASE_REQUIRED")
    for name in ("run_id","lane_id","lease_id","proposal_sha256","approval_sha256","lease_sha256"):
        _require(type(getattr(observation,name)) is str and getattr(observation,name)==getattr(validated,name),"completed observation context differs","LEASE_REQUIRED")
    distribution=dict((n,b.file_sha256) for n,b,_ in validated.inputs)["controller_distribution"]
    _require(type(observation.controller_distribution_sha256) is str and observation.controller_distribution_sha256==distribution,
             "completed controller distribution differs","LEASE_REQUIRED")
    for pin in (observation.result,observation.journal):
        _require(type(pin) is BytePin,"independent typed byte pins are required","LEASE_REQUIRED")
        _absolute_path(pin.path,"LEASE_REQUIRED");_hash(pin.sha256,"LEASE_REQUIRED")
    inspected=inspect_result_bundle(validated,result_document);result=inspected["result"]
    _require(json_equal(vars(observation.controller_identity),inspected["controller_identity"])
             and observation.result.path==result_document.consumed.path and observation.result.sha256==result_document.consumed.file_sha256
             and observation.journal.path==str(Path(validated.paths.output_root)/result["journal"]["path"])
             and observation.journal.sha256==result["journal"]["sha256"],"independently observed controller/result/journal differs","LEASE_REQUIRED")
    _require(observation.exit_code==(0 if result["outcome"]=="PASS" else 3)
             and result["lease_disposition"]=="RELEASABLE" and any(a["started"] for a in result["attempts"])
             and all(not a["started"] or a["cleanup"] is not None and a["cleanup"]["status"]=="CLEAN" for a in result["attempts"])
             and all(a["failure"] is None or a["failure"]["code"] not in _QUARANTINE_CODES for a in result["attempts"])
             and (result["failure"] is None or result["failure"]["code"] not in _QUARANTINE_CODES),
             "terminal semantics refuse lease release","LEASE_REQUIRED")
    return {"release_eligible":True,"assessment":"NOT_RUN","result":result}


def project_attempt(validated, result_document, *, phase="main"):
    """Return an existing validated measured v1 map, without release or READY."""
    result=inspect_result_bundle(validated,result_document)["result"]
    _require(phase in {"main","interrupted","fresh"},"unknown projection phase","EVIDENCE_INVALID")
    attempt=next(a for a in result["attempts"] if a["phase"]==phase)
    _require(attempt["projection"] is not None,"attempt has no valid v1 projection","EVIDENCE_INVALID")
    return dict(attempt["projection"])


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
        if arguments.validate_only:
            print(json.dumps({"contract": "controller-validation-v1", "outcome": "NOT_RUN", "run_id": validated.run_id,
                              "lane_id": validated.lane_id, "proposal_sha256": validated.proposal_sha256}, sort_keys=True))
            return 0
        _execution_authority(validated)
        result=run_lane(validated,cancel_fd=arguments.cancel_fd)
        # Emitted only after the checked final readback and handle releases.
        print(_json_bytes(result).decode("utf-8"))
        return 0 if result["outcome"]=="PASS" else 3
    except ControllerError as exc:
        print(json.dumps({"code": exc.code, "detail": exc.detail, "errno": exc.errno}, sort_keys=True), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
