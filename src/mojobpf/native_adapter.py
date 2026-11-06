# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Explicit candidate bridge and independently pinned native runtime closure.

The standalone copy loads only its byte-identical execution sibling. Its v1
wire uses six request fields and four response fields. The caller supplies
the canonical native pin record through ``MOJOBPF_NATIVE_ADMISSION``; a
descriptor's self-reported hashes never supply admission. Loader inventories
are observations until separately reviewed and pinned by that caller.

All paths are captured once. The pinned ELF interpreter observes dependency
resolution with --list and executes the native entry directly. Every object,
link and loader control is rechecked before execution. Concurrent replacement
by the same account remains the trusted-local-filesystem limit of the shared
execution contract. Native tools must not load plugins or selected libraries.
"""

from __future__ import annotations

import argparse
import os
import sys

if not __package__:
    # A direct source invocation must not import the sibling inspect.py as
    # Python's stdlib inspect. The prepared service imports only its pinned
    # execution.py through an absolute file spec below.
    _service_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path = [item for item in sys.path
                if os.path.abspath(item or os.curdir) != _service_dir]

import dataclasses
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time

ROUTE_ID = "parsed-xdp-array-candidate-v1"
MODEL_ID = "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1"
PROFILE_ID = "linux-bpfel-v3"
LICENSE = "Apache-2.0 WITH LLVM-exception"
ADMISSION_ENV = "MOJOBPF_NATIVE_ADMISSION"
MAX_ADMISSION = 65536
MAX_JSON = 1 << 20
MAX_IR = 32 << 20
MAX_OBJECTS = 256
MAX_EDGES = 2048
TIMEOUT = 60
MAX_STREAM = 1 << 20
PIN_KEYS = frozenset({"adapter_path", "service_sha256",
    "execution_sibling_sha256", "bundle_descriptor_path",
    "bundle_descriptor_sha256", "runtime_closure_path",
    "runtime_closure_sha256", "route_id", "qualified"})
REQUEST_KEYS = frozenset({"schema_version", "input_ir", "manifest_path",
                         "profile_id", "output_dir", "diagnostic_mode"})
REPORT_KEYS = frozenset({"schema_version", "mode", "model_id", "ok",
    "input_digest", "spec_digest", "output_digest", "target_facts",
    "proof_obligations", "transformations", "diagnostics", "runtime_qualified",
    "unproved", "unproved_total", "unproved_truncated"})
DIAGNOSTIC_KEYS = frozenset({"code", "stage", "severity", "explanation",
                            "location", "remedy"})


class NativeAdapterError(ValueError):
    """A closed admission/protocol boundary, never a fallback request."""

    def __init__(self, detail, code="MBPF212", stage="adapter.request"):
        super().__init__(detail)
        self.code, self.stage = code, stage

    def diagnostic(self):
        return {"code": self.code, "stage": self.stage, "severity": "error",
                "explanation": str(self)[:2000], "location": None,
                "remedy": "restore independently admitted inputs and retry"}


def canonical_json(document):
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _object(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise NativeAdapterError("invalid %s fields" % label)
    return value


def _integer(value):
    return type(value) is int


def _text(value, label):
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise NativeAdapterError("invalid %s string" % label)
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) or value == "0" * 64:
        raise NativeAdapterError("missing or invalid SHA256 pin")
    return value


def _absolute(value):
    _text(value, "path")
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise NativeAdapterError("native path must be an absolute normalized locator")
    return value


def strict_json(raw, limit=MAX_JSON):
    if not isinstance(raw, bytes) or len(raw) > limit or b"\x00" in raw:
        raise NativeAdapterError("JSON input exceeds its bound or contains NUL")

    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise NativeAdapterError("duplicate JSON field %r" % name)
            result[name] = value
        return result

    def constant(value):
        raise NativeAdapterError("nonfinite JSON number %s" % value)

    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise NativeAdapterError("nonfinite JSON number %s" % value)
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=finite_float)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise NativeAdapterError("unusable JSON: %s" % str(exc)[:500]) from None


def _read(path, limit=MAX_JSON):
    # Do not follow an output symlink or read a device/FIFO as a protocol file.
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise NativeAdapterError("input is not a bounded regular file: %s" % path)
            raw = handle.read(limit + 1)
    except OSError as exc:
        raise NativeAdapterError("cannot read %s: %s" % (path, exc)) from None
    if len(raw) > limit:
        raise NativeAdapterError("file exceeds bound: %s" % path)
    return raw


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_candidate_record(record):
    _object(record, PIN_KEYS, "native adapter pin record")
    if record["route_id"] != ROUTE_ID or record["qualified"] is not False:
        raise NativeAdapterError("unsupported or falsely qualified native route")
    for name in ("adapter_path", "bundle_descriptor_path", "runtime_closure_path"):
        _absolute(record[name])
    for name in ("service_sha256", "execution_sibling_sha256",
                 "bundle_descriptor_sha256", "runtime_closure_sha256"):
        _digest(record[name])
    if len(canonical_json(record)) > MAX_ADMISSION:
        raise NativeAdapterError("native adapter pin record exceeds bound")
    return dict(record)


def derive_native_spec(canonical_manifest: bytes, profile_id: str) -> bytes:
    """Validate captured JSON and derive the strict single-program native spec."""
    doc = strict_json(canonical_manifest)
    if canonical_json(doc) != canonical_manifest:
        raise NativeAdapterError("captured manifest is not canonical JSON")
    _object(doc, {"schema_version", "project", "target", "artifact", "programs", "maps"}, "manifest")
    if not _integer(doc["schema_version"]) or doc["schema_version"] != 1:
        raise NativeAdapterError("unsupported captured manifest version")
    _object(doc["project"], {"name"}, "project")
    _text(doc["project"]["name"], "project name")
    target = _object(doc["target"], {"profile", "core"}, "target")
    if profile_id != PROFILE_ID or target["profile"] != profile_id or target["core"] is not False:
        raise NativeAdapterError("native candidate requires linux-bpfel-v3 without CO-RE")
    artifact = _object(doc["artifact"], {"name", "source_license", "kernel_license"}, "artifact")
    _text(artifact["name"], "artifact name")
    if artifact["kernel_license"] != LICENSE or artifact["source_license"] != LICENSE:
        raise NativeAdapterError("native candidate requires the unchanged source/kernel license declaration")
    programs = doc["programs"]
    if not isinstance(programs, list) or len(programs) != 1:
        raise NativeAdapterError("native v1 requires exactly one program")
    program = _object(programs[0], {"source", "entry", "program_type", "section"}, "program")
    _text(program["source"], "source")
    entry = _text(program["entry"], "entry")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", entry) or len(entry) > 128:
        raise NativeAdapterError("invalid native entry symbol")
    if program["program_type"] != "xdp" or program["section"] != "xdp":
        raise NativeAdapterError("native candidate requires an xdp program/section")
    spec = {"schema_version": 1, "model_id": MODEL_ID, "profile_id": profile_id,
            "entry": entry, "program_type": "xdp", "section": "xdp",
            "kernel_license": artifact["kernel_license"], "map": None}
    maps = doc["maps"]
    if not isinstance(maps, list) or len(maps) > 1:
        raise NativeAdapterError("native candidate permits zero maps or one array")
    if maps:
        mapping = _object(maps[0], {"name", "map_type", "key_type", "value_type", "max_entries"}, "map")
        expected = {"name": "mojobpf_map0", "map_type": "array", "key_type": "u32", "value_type": "u64", "max_entries": 1}
        if mapping != expected or not _integer(mapping["max_entries"]):
            raise NativeAdapterError("native candidate requires mojobpf_map0 array/u32/u64/max1/flags0")
        spec["map"] = {"symbol": "mojobpf_map0", "type": 2, "key_bits": 32,
                       "value_bits": 64, "max_entries": 1, "flags": 0}
    return canonical_json(spec)


def _execution():
    if __package__:
        from . import execution
        return execution
    # Absolute sibling import, so cwd/PYTHONPATH cannot replace the boundary.
    name = "_mojobpf_native_execution"
    if name in sys.modules:
        return sys.modules[name]
    sibling = Path(__file__).resolve().with_name("execution.py")
    spec = importlib.util.spec_from_file_location(name, sibling)
    if spec is None or spec.loader is None:
        raise NativeAdapterError("missing execution sibling")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _loader_variable(name):
    return (name.startswith(("LD_", "DYLD_")) or
            name in {"GLIBC_TUNABLES", "LIBPATH", "SHLIB_PATH"})


def _reject_loader_overrides():
    names = [name for name, value in os.environ.items()
             if _loader_variable(name) and value]
    if names:
        raise NativeAdapterError("unadmitted loader environment override: " +
                                 ", ".join(sorted(names)), "MBPF102", "build.setup")


def _harden(execution):
    # Derive a fresh immutable execution overlay; the original admission stays
    # untouched. The public summary uses the same canonical digest vocabulary.
    boundary = _execution()
    unset = set(execution.env_unset) | {name for name in os.environ if _loader_variable(name)}
    unset.update({"GLIBC_TUNABLES", "LIBPATH", "SHLIB_PATH"})
    record = dataclasses.replace(execution, env_unset=tuple(sorted(unset)))
    summary = boundary.summarize(record)
    summary.pop("digest")
    digest = hashlib.sha256(json.dumps(summary, sort_keys=True,
                            separators=(",", ":")).encode("utf-8")).hexdigest()
    return dataclasses.replace(record, digest=digest)


def _bounded_run(execution, suffix, timeout=TIMEOUT):
    """Bound both streams and the whole process group through shared admission."""
    _reject_loader_overrides()
    boundary = _execution()
    execution = _harden(execution)
    start = time.monotonic()
    # The driver creates a fresh session/group for the standalone bridge.
    # Helpers in that bridge inherit it, so outer timeout/cancellation reaches
    # the entire nested invocation. Imported API callers get a new tool group.
    # Admitted lower/frame tools do not spawn external descendants; introducing
    # such behavior requires a revised execution/runtime contract.
    inherited_group = not __package__ and os.getpgrp() == os.getpid()
    try:
        process = boundary.popen_admitted(execution, suffix, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, start_new_session=not inherited_group)
    except (OSError, boundary.AdmissionError) as exc:
        raise NativeAdapterError("admitted native spawn refused: %s" % exc,
                                 "MBPF102", "adapter.transform") from None
    chunks = [bytearray(), bytearray()]
    overflow = threading.Event()
    errors = []

    def drain(stream, slot):
        try:
            while True:
                part = stream.read(65536)
                if not part:
                    break
                room = MAX_STREAM - len(chunks[slot])
                chunks[slot].extend(part[:max(room, 0)])
                if len(part) > room:
                    overflow.set()
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
        finally:
            stream.close()

    threads = [threading.Thread(target=drain, args=(stream, slot), daemon=True)
               for slot, stream in enumerate((process.stdout, process.stderr))]
    for thread in threads:
        thread.start()
    status = "ok"
    deadline = start + timeout
    try:
        while process.poll() is None or any(thread.is_alive() for thread in threads):
            if overflow.is_set() or errors or time.monotonic() >= deadline:
                status = "truncated" if overflow.is_set() else ("capture_failed" if errors else "timeout")
                try:
                    _kill_native_group(process, inherited_group)
                except ProcessLookupError:
                    pass
                break
            time.sleep(0.005)
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
    except BaseException:
        try:
            _kill_native_group(process, inherited_group)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        raise
    if any(thread.is_alive() for thread in threads) or errors:
        status = "capture_failed"
    if overflow.is_set():
        status = "truncated"
    if status == "ok" and process.returncode != 0:
        status = "failed"
    try:
        stdout, stderr = (bytes(chunk).decode("utf-8") for chunk in chunks)
    except UnicodeDecodeError:
        raise NativeAdapterError("native process emitted undecodable output", stage="adapter.transform") from None
    record = {"argv": list(execution.argv_prefix) + list(suffix),
              "status": status, "exit_code": process.returncode,
              "duration_s": time.monotonic() - start,
              "stdout_sha256": _sha(bytes(chunks[0])),
              "stderr_sha256": _sha(bytes(chunks[1])),
              "execution_digest": execution.digest}
    return record, stdout, stderr


def _kill_native_group(process, inherited_group):
    boundary = _execution()
    boundary.signal_child_pidfd(process)
    if not inherited_group:
        if boundary.child_pins_group(process.pid, process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
        return
    # This is the standalone bridge's fresh owned group, not the caller's
    # group. Retire its helper members individually; never signal the bridge
    # itself or an unrelated group. Recheck each member's group before kill.
    group = os.getpid()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == group:
            continue
        try:
            data = (entry / "stat").read_text()
            fields = data[data.rindex(")") + 2:].split()
            if int(fields[2]) == group and os.getpgid(int(entry.name)) == group:
                os.kill(int(entry.name), signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


def _links(path):
    links, seen = [], set()
    pending = Path(path).parts[1:]
    resolved = Path("/")
    while pending:
        resolved = resolved / pending[0]
        pending = pending[1:]
        if resolved.is_symlink():
            if str(resolved) in seen or len(links) >= 32:
                raise NativeAdapterError("cyclic or excessive native symlink chain")
            seen.add(str(resolved))
            target = os.readlink(resolved)
            links.append({"path": str(resolved), "target": target})
            candidate = Path(os.path.normpath(str(resolved.parent / target)))
            pending = candidate.parts[1:] + pending
            resolved = Path("/")
    return links


def _object_record(path, role):
    _absolute(path)
    boundary = _execution()
    try:
        identity = boundary.identify_file(path)
    except boundary.AdmissionError as exc:
        raise NativeAdapterError("native identity unavailable: %s" % exc, "MBPF102", "build.setup") from None
    return {"role": role, "path": path, "realpath": identity.realpath,
            "sha256": identity.sha256, "size": identity.size, "links": _links(path)}


def _control_record(path, role):
    _absolute(path)
    if not os.path.lexists(path):
        return {"role": role, "path": path, "present": False, "sha256": None, "size": 0}
    raw = _read(path, 16 << 20)
    if role == "preload" and raw:
        raise NativeAdapterError("nonempty system preload configuration", "MBPF102", "build.setup")
    return {"role": role, "path": path, "present": True, "sha256": _sha(raw), "size": len(raw)}


def _mapping(stdout):
    result = {}
    for line in stdout.splitlines():
        line = line.strip()
        if re.fullmatch(r"linux-vdso\.so\.1 \(0x[0-9a-fA-F]+\)", line):
            continue
        match = re.fullmatch(r"(\S+) => (/[^(]+) \(0x[0-9a-fA-F]+\)", line)
        if match:
            name, path = match.groups()
        else:
            match = re.fullmatch(r"(/\S+) \(0x[0-9a-fA-F]+\)", line)
            if not match:
                raise NativeAdapterError("unresolved or unreadable pinned loader mapping: " + line)
            path = match[1]
            name = os.path.basename(path)
        _text(name, "dependency name")
        _absolute(path)
        if name in result:
            raise NativeAdapterError("duplicate pinned loader dependency name")
        result[name] = path
    if not result:
        raise NativeAdapterError("pinned loader produced no dependency mapping")
    return result


def _native_execution(path, digest):
    boundary = _execution()
    try:
        return boundary.admit_execution(boundary.ExecutionRequest(
            name="native-runtime", argv0=path, allow_path_lookup=False,
            forms=(boundary.FORM_BINARY,), trust_root="runtime-closure:" + digest),
            boundary.ExecutionPins(entry_sha256=digest))
    except boundary.AdmissionError as exc:
        raise NativeAdapterError("native executable pin refused: %s" % exc,
                                 "MBPF102", "build.setup") from None


def _inspect_elf(inspector, path):
    record, stdout, stderr = _bounded_run(inspector, ["-W", "-l", "-d", path])
    if record["status"] != "ok" or stderr.strip():
        raise NativeAdapterError("admitted ELF inspection unavailable: " + stderr[:500])
    interpreters = re.findall(r"\[Requesting program interpreter: ([^\]]+)\]", stdout)
    if len(interpreters) > 1:
        raise NativeAdapterError("ambiguous native ELF interpreter")
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", stdout)
    if len(needed) != len(set(needed)) or len(needed) > MAX_OBJECTS:
        raise NativeAdapterError("ambiguous or excessive ELF dependencies")
    return interpreters[0] if interpreters else None, needed, dict(record, stdout=stdout, stderr=stderr)


def observe_runtime_closure(admitted_inspection_tools, native_paths):
    """Observe explicit native entries using already admitted distribution tools.

    The result is NOT a trust root. A different caller/controller must pin the
    exact descriptor bytes before ``admit_runtime_closure`` is used as proof.
    """
    _reject_loader_overrides()
    if not isinstance(native_paths, dict) or not native_paths or len(native_paths) > 2:
        raise NativeAdapterError("runtime observation requires one or two named entries")
    inspector = admitted_inspection_tools.get("readelf")
    if inspector is None:
        raise NativeAdapterError("missing independently admitted readelf inspection tool")
    controls = [_control_record("/etc/ld.so.cache", "loader-cache"),
                _control_record("/etc/ld.so.preload", "preload")]
    objects, entries, observations = {}, [], []
    for name, path in sorted(native_paths.items()):
        if name not in {"lower", "frame"}:
            raise NativeAdapterError("unknown runtime entry role")
        entry = _object_record(path, "native-entry")
        objects[entry["realpath"]] = entry
        interpreter, _needed, record = _inspect_elf(inspector, entry["realpath"])
        observations.append(record)
        if interpreter is None:
            raise NativeAdapterError("native candidate requires an explicit dynamic ELF interpreter")
        loader = _object_record(interpreter, "interpreter")
        objects[loader["realpath"]] = loader
        loader_exec = _native_execution(loader["path"], loader["sha256"])
        record, stdout, stderr = _bounded_run(loader_exec, ["--list", entry["realpath"]])
        observations.append(dict(record, stdout=stdout, stderr=stderr))
        if record["status"] != "ok" or stderr.strip():
            raise NativeAdapterError("pinned loader observation failed: " + stderr[:500])
        resolved = _mapping(stdout)
        for dependency in resolved.values():
            obj = _object_record(dependency, "library")
            if obj["realpath"] not in objects:
                objects[obj["realpath"]] = obj
        edges, pending, visited = [], [entry["realpath"]], set()
        while pending:
            owner = pending.pop()
            if owner in visited:
                continue
            visited.add(owner)
            _interpreter, needed, record = _inspect_elf(inspector, owner)
            observations.append(record)
            for soname in needed:
                candidate = resolved.get(soname)
                if candidate is None:
                    raise NativeAdapterError("loader did not resolve required dependency " + soname)
                real = os.path.realpath(candidate)
                edges.append({"owner": owner, "needed": soname, "path": candidate})
                pending.append(real)
        entries.append({"name": name, "path": entry["path"], "interpreter": loader["path"],
                        "resolved": [{"name": key, "path": value} for key, value in sorted(resolved.items())],
                        "edges": sorted(edges, key=lambda row: (row["owner"], row["needed"]))})
    result = {"schema_version": 1, "kind": "RuntimeClosureV1",
              "objects": sorted(objects.values(), key=lambda row: row["realpath"]),
              "entries": entries, "controls": controls, "observations": observations}
    # Check the complete observation against live inputs without re-running it.
    admitted = _parse_closure(canonical_json(result), _sha(canonical_json(result)))
    admitted.verify()
    return result


@dataclasses.dataclass(frozen=True)
class AdmittedRuntimeClosure:
    raw: bytes
    sha256: str
    identities: tuple
    loader_executions: tuple = ()
    observer_records: tuple = ()

    @property
    def document(self):
        return strict_json(self.raw)

    @property
    def content_sha256(self):
        doc = self.document
        by_path = {path: row for row in doc["objects"] for path in (row["path"], row["realpath"])}
        objects = sorted(({"role": row["role"], "sha256": row["sha256"], "size": row["size"]}
                          for row in doc["objects"]), key=lambda row: (row["role"], row["sha256"]))
        entries = []
        for row in doc["entries"]:
            entries.append({"name": row["name"], "sha256": by_path[row["path"]]["sha256"],
                "interpreter_sha256": by_path[row["interpreter"]]["sha256"],
                "edges": sorted(({"owner_sha256": by_path[edge["owner"]]["sha256"],
                                  "needed": edge["needed"], "sha256": by_path[edge["path"]]["sha256"]}
                                 for edge in row["edges"]), key=lambda edge: (edge["owner_sha256"], edge["needed"])),
                "resolved": [{"name": item["name"], "sha256": by_path[item["path"]]["sha256"]}
                             for item in row["resolved"]]})
        controls = [{key: row[key] for key in ("role", "present", "sha256", "size")} for row in doc["controls"]]
        return _sha(canonical_json({"kind": "RuntimeClosureV1", "objects": objects,
                                    "entries": entries, "controls": controls}))

    def verify(self):
        _reject_loader_overrides()
        for row in self.document["objects"]:
            if _object_record(row["path"], row["role"]) != row:
                raise NativeAdapterError("native runtime object/link identity changed: " + row["path"], "MBPF102", "build.setup")
        for row in self.document["controls"]:
            if _control_record(row["path"], row["role"]) != row:
                raise NativeAdapterError("native loader control pin changed: " + row["path"], "MBPF102", "build.setup")
        boundary = _execution()
        # Shared stat/hash checks retain byte-identical replacement refusals.
        if self.identities:
            loader = next(row for row in self.document["objects"] if row["role"] == "interpreter")
            execution = _native_execution(loader["path"], loader["sha256"])
            modules = tuple(boundary.ModuleIdentity(str(index), identity)
                            for index, identity in enumerate(self.identities))
            try:
                boundary.verify_spawn(dataclasses.replace(execution, modules=modules))
            except boundary.AdmissionError as exc:
                raise NativeAdapterError("native runtime identity changed: %s" % exc,
                                         "MBPF102", "build.setup") from None

    def run(self, name, suffix, timeout=TIMEOUT):
        self.verify()
        entries = {row["name"]: row for row in self.document["entries"]}
        if name not in entries:
            raise NativeAdapterError("unadmitted native entry role")
        loader = dict(self.loader_executions).get(name)
        if loader is None:
            raise NativeAdapterError("native closure has no admitted loader mapping")
        # Absolute pinned loader is the actual executor; no PATH or ELF
        # interpreter discovery occurs here. Check once more at the spawn.
        self.verify()
        return _bounded_run(loader, [entries[name]["path"], *suffix], timeout)


def _parse_closure(raw, digest):
    try:
        return _parse_closure_fields(raw, digest)
    except NativeAdapterError:
        raise
    except (OSError, ValueError, TypeError, KeyError, _execution().AdmissionError) as exc:
        raise NativeAdapterError("unusable runtime closure: %s" % str(exc)[:500], "MBPF102", "build.setup") from None


def _parse_closure_fields(raw, digest):
    _digest(digest)
    if _sha(raw) != digest:
        raise NativeAdapterError("runtime closure descriptor pin mismatch", "MBPF102", "build.setup")
    doc = _object(strict_json(raw), {"schema_version", "kind", "objects", "entries", "controls", "observations"}, "runtime closure")
    if not _integer(doc["schema_version"]) or doc["schema_version"] != 1 or doc["kind"] != "RuntimeClosureV1":
        raise NativeAdapterError("unsupported runtime closure schema")
    objects = doc["objects"]
    if not isinstance(objects, list) or not 2 <= len(objects) <= MAX_OBJECTS:
        raise NativeAdapterError("missing or excessive runtime closure objects")
    by_path, by_real = {}, {}
    for row in objects:
        _object(row, {"role", "path", "realpath", "sha256", "size", "links"}, "runtime object")
        if row["role"] not in {"interpreter", "native-entry", "library"}:
            raise NativeAdapterError("unknown runtime object role")
        _absolute(row["path"])
        _absolute(row["realpath"])
        _digest(row["sha256"])
        if not _integer(row["size"]) or not 0 < row["size"] <= 1 << 30:
            raise NativeAdapterError("invalid runtime object size")
        if row["realpath"] in by_real:
            raise NativeAdapterError("duplicate runtime object identity")
        by_real[row["realpath"]] = row
        for path in {row["path"], row["realpath"]}:
            if path in by_path:
                raise NativeAdapterError("ambiguous runtime object locator")
            by_path[path] = row
        if not isinstance(row["links"], list) or len(row["links"]) > 32:
            raise NativeAdapterError("invalid runtime symlink inventory")
        link_paths = set()
        for link in row["links"]:
            _object(link, {"path", "target"}, "symlink")
            _absolute(link["path"])
            _text(link["target"], "symlink target")
            if link["path"] in link_paths:
                raise NativeAdapterError("duplicate runtime symlink")
            link_paths.add(link["path"])
    controls = doc["controls"]
    expected_controls = {"loader-cache": "/etc/ld.so.cache", "preload": "/etc/ld.so.preload"}
    if not isinstance(controls, list) or len(controls) != 2:
        raise NativeAdapterError("missing native loader resolution controls")
    for row in controls:
        _object(row, {"role", "path", "present", "sha256", "size"}, "loader control")
        if expected_controls.pop(row["role"], None) != row["path"]:
            raise NativeAdapterError("unknown/duplicate loader control")
        if type(row["present"]) is not bool or not _integer(row["size"]) or not 0 <= row["size"] <= 16 << 20:
            raise NativeAdapterError("invalid loader control identity")
        if row["present"]:
            _digest(row["sha256"])
        elif row["sha256"] is not None or row["size"] != 0:
            raise NativeAdapterError("absent loader control claims bytes")
        if row["role"] == "preload" and (row["size"] or (row["present"] and row["sha256"] != _sha(b""))):
            raise NativeAdapterError("nonempty pinned preload configuration")
    entries = doc["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 2:
        raise NativeAdapterError("invalid native closure entries")
    used, names = set(), set()
    for entry in entries:
        _object(entry, {"name", "path", "interpreter", "resolved", "edges"}, "runtime entry")
        if entry["name"] not in {"lower", "frame"} or entry["name"] in names:
            raise NativeAdapterError("unknown/duplicate native closure entry")
        names.add(entry["name"])
        start, loader = by_path.get(entry["path"]), by_path.get(entry["interpreter"])
        if start is None or start["role"] != "native-entry" or loader is None or loader["role"] != "interpreter":
            raise NativeAdapterError("native entry/interpreter has no role-labelled pin")
        if not isinstance(entry["resolved"], list) or not 1 <= len(entry["resolved"]) <= MAX_OBJECTS:
            raise NativeAdapterError("missing/excessive resolved dependency mapping")
        resolved = {}
        for row in entry["resolved"]:
            _object(row, {"name", "path"}, "resolved dependency")
            _text(row["name"], "dependency name")
            if row["name"] in resolved or row["path"] not in by_path:
                raise NativeAdapterError("unmapped/duplicate resolved dependency")
            resolved[row["name"]] = row["path"]
        edges = entry["edges"]
        if not isinstance(edges, list) or len(edges) > MAX_EDGES:
            raise NativeAdapterError("invalid/excessive native dependency edges")
        graph, edge_names = {}, set()
        for edge in edges:
            _object(edge, {"owner", "needed", "path"}, "dependency edge")
            if edge["owner"] not in by_real or edge["needed"] not in resolved or edge["path"] != resolved[edge["needed"]]:
                raise NativeAdapterError("unresolved native dependency edge")
            key = (edge["owner"], edge["needed"])
            if key in edge_names:
                raise NativeAdapterError("duplicate native dependency edge")
            edge_names.add(key)
            graph.setdefault(edge["owner"], []).append(edge)
        reachable, pending = set(), [start["realpath"]]
        while pending:
            owner = pending.pop()
            if owner in reachable:
                continue
            reachable.add(owner)
            pending += [by_path[edge["path"]]["realpath"] for edge in graph.get(owner, [])]
        if set(graph) - reachable:
            raise NativeAdapterError("unreachable native dependency owner")
        needed = {edge["needed"] for edge in edges}
        if any(name not in needed and by_path[path]["realpath"] != loader["realpath"] for name, path in resolved.items()):
            raise NativeAdapterError("incomplete native dependency edge inventory")
        mapped = {by_path[path]["realpath"] for path in resolved.values()}
        if mapped != (reachable - {start["realpath"]}) | {loader["realpath"]}:
            raise NativeAdapterError("native dependency closure is incomplete")
        used |= reachable | {loader["realpath"]}
    if "lower" not in names or used != set(by_real):
        raise NativeAdapterError("missing lower entry or unused/unpinned runtime objects")
    observations = doc["observations"]
    if not isinstance(observations, list) or not observations or len(observations) > MAX_EDGES:
        raise NativeAdapterError("missing/bounded runtime observations")
    for row in observations:
        _object(row, {"argv", "status", "exit_code", "duration_s", "stdout_sha256", "stderr_sha256", "execution_digest", "stdout", "stderr"}, "runtime observation")
        if not isinstance(row["argv"], list) or not row["argv"] or len(row["argv"]) > 32:
            raise NativeAdapterError("invalid observation argv")
        for value in row["argv"]:
            _text(value, "observer argument")
        if row["status"] != "ok" or not _integer(row["exit_code"]) or row["exit_code"] != 0 or type(row["duration_s"]) not in (int, float) or row["duration_s"] < 0:
            raise NativeAdapterError("runtime observation was not successful")
        for name in ("stdout_sha256", "stderr_sha256", "execution_digest"):
            _digest(row[name])
        for stream in ("stdout", "stderr"):
            if not isinstance(row[stream], str) or len(row[stream].encode("utf-8")) > MAX_STREAM or _sha(row[stream].encode("utf-8")) != row[stream + "_sha256"]:
                raise NativeAdapterError("runtime observation output identity mismatch")
    boundary = _execution()
    identities = tuple(boundary.identify_file(row["path"]) for row in objects)
    identities += tuple(boundary.identify_file(row["path"]) for row in controls if row["present"])
    return AdmittedRuntimeClosure(raw, digest, identities)


def admit_runtime_closure(raw, independently_pinned_sha256):
    """Hash all independently inventoried inputs before the pinned loader probe."""
    _reject_loader_overrides()
    admitted = _parse_closure(raw, independently_pinned_sha256)
    admitted.verify()
    by_path = {path: row for row in admitted.document["objects"] for path in (row["path"], row["realpath"])}
    loaders, observations = [], []
    for entry in admitted.document["entries"]:
        loader = by_path[entry["interpreter"]]
        execution = _native_execution(loader["path"], loader["sha256"])
        admitted.verify()
        record, stdout, stderr = _bounded_run(execution, ["--list", entry["path"]])
        observations.append(dict(record, stdout=stdout, stderr=stderr))
        if record["status"] != "ok" or stderr.strip():
            raise NativeAdapterError("pinned loader mapping observation failed: " + stderr[:500])
        expected = {row["name"]: row["path"] for row in entry["resolved"]}
        if _mapping(stdout) != expected:
            raise NativeAdapterError("pinned loader mapping differs from complete admitted inventory", "MBPF102", "build.setup")
        admitted.verify()
        loaders.append((entry["name"], execution))
    return dataclasses.replace(admitted, loader_executions=tuple(loaders), observer_records=tuple(observations))


@dataclasses.dataclass(frozen=True)
class AdmittedNativeBundle:
    pins_bytes: bytes
    descriptor_bytes: bytes
    closure: AdmittedRuntimeClosure
    adapter_execution: object

    @property
    def record(self):
        return strict_json(self.pins_bytes, MAX_ADMISSION)

    @property
    def content_sha256(self):
        doc = strict_json(self.descriptor_bytes)
        for role in ("service", "execution", "runtime_closure"):
            doc[role].pop("file")
        doc["runtime_closure"] = {"content_sha256": self.closure.content_sha256}
        for tool in doc["native_tools"].values():
            tool.pop("path")
        return _sha(canonical_json(doc))

    def verify(self):
        pins = self.record
        for path, digest in ((pins["adapter_path"], pins["service_sha256"]),
            (str(Path(pins["adapter_path"]).with_name("execution.py")), pins["execution_sibling_sha256"]),
            (pins["bundle_descriptor_path"], pins["bundle_descriptor_sha256"]),
            (pins["runtime_closure_path"], pins["runtime_closure_sha256"])):
            if _sha(_read(path)) != digest:
                raise NativeAdapterError("native bundle pin changed: " + path, "MBPF102", "build.setup")
        self.closure.verify()
        boundary = _execution()
        try:
            boundary.verify_spawn(self.adapter_execution)
        except boundary.AdmissionError as exc:
            raise NativeAdapterError("native service identity changed: %s" % exc,
                                     "MBPF102", "build.setup") from None


def admit_native_bundle(candidate_record, explicit_adapter_path):
    """Admit the caller-pinned bridge, bundle and complete closure, before probes."""
    _reject_loader_overrides()
    pins = validate_candidate_record(candidate_record)
    if explicit_adapter_path != pins["adapter_path"] or Path(explicit_adapter_path).name != "native_adapter.py":
        raise NativeAdapterError("native record requires its exact explicit adapter selection", "MBPF102", "build.setup")
    service_raw = _read(pins["adapter_path"])
    sibling_path = str(Path(explicit_adapter_path).with_name("execution.py"))
    sibling_raw = _read(sibling_path)
    descriptor_raw = _read(pins["bundle_descriptor_path"])
    closure_raw = _read(pins["runtime_closure_path"])
    for raw, name in ((service_raw, "service_sha256"), (sibling_raw, "execution_sibling_sha256"),
                      (descriptor_raw, "bundle_descriptor_sha256"), (closure_raw, "runtime_closure_sha256")):
        if _sha(raw) != pins[name]:
            raise NativeAdapterError("native bundle does not match independently supplied " + name, "MBPF102", "build.setup")
    doc = _object(strict_json(descriptor_raw), {"schema_version", "route_id", "model_id", "profile_id",
        "runtime_qualified", "service", "execution", "runtime_closure", "native_tools", "transform_source_index_sha256"}, "native bundle")
    if not _integer(doc["schema_version"]) or doc["schema_version"] != 1 or doc["route_id"] != ROUTE_ID or doc["model_id"] != MODEL_ID or doc["profile_id"] != PROFILE_ID or doc["runtime_qualified"] is not False:
        raise NativeAdapterError("unsupported/falsely qualified native bundle contract")
    _digest(doc["transform_source_index_sha256"])
    root = Path(explicit_adapter_path).parent
    for name, raw, path in (("service", service_raw, pins["adapter_path"]),
                           ("execution", sibling_raw, sibling_path),
                           ("runtime_closure", closure_raw, pins["runtime_closure_path"])):
        item = _object(doc[name], {"file", "sha256", "size"}, "bundle " + name)
        _text(item["file"], "bundle file")
        if Path(item["file"]).name != item["file"] or str(root / item["file"]) != path or item["sha256"] != _sha(raw) or not _integer(item["size"]) or item["size"] != len(raw):
            raise NativeAdapterError("bundle file pin/locator disagrees with admitted inputs")
    tools = doc["native_tools"]
    if not isinstance(tools, dict) or "lower" not in tools or set(tools) - {"lower", "frame"}:
        raise NativeAdapterError("unsupported native tool set")
    # Inspect the descriptor shape and all native role bindings before the
    # runtime loader can be probed. Closure pins are independently supplied.
    parsed = _parse_closure(closure_raw, pins["runtime_closure_sha256"])
    parsed.verify()
    entries = {row["name"]: row for row in parsed.document["entries"]}
    objects = {row["path"]: row for row in parsed.document["objects"]}
    if set(entries) != set(tools):
        raise NativeAdapterError("bundle tools and runtime closure entries disagree")
    for name, tool in tools.items():
        _object(tool, {"path", "sha256", "size"}, "native tool")
        _absolute(tool["path"])
        _digest(tool["sha256"])
        item = objects.get(tool["path"])
        if tool["path"] != entries[name]["path"] or item is None or tool["sha256"] != item["sha256"] or not _integer(tool["size"]) or tool["size"] != item["size"]:
            raise NativeAdapterError("native tool has no complete independent runtime pin")
    boundary = _execution()
    try:
        adapter = boundary.admit_script_data(name="native-adapter", interpreter_path=sys.executable,
            script_path=explicit_adapter_path, script_sha256=pins["service_sha256"],
            sibling_shas={"execution.py": pins["execution_sibling_sha256"]},
            sibling_names=("execution.py",), trust_root="native-lock:" + _sha(canonical_json(pins)))
        extra = tuple(boundary.ModuleIdentity(name, boundary.identify_file(path))
            for name, path in (("bundle-descriptor", pins["bundle_descriptor_path"]),
                               ("runtime-closure", pins["runtime_closure_path"])))
        adapter = _harden(dataclasses.replace(adapter, modules=adapter.modules + extra))
    except boundary.AdmissionError as exc:
        raise NativeAdapterError("native service admission refused: %s" % exc, "MBPF102", "build.setup") from None
    closure = admit_runtime_closure(closure_raw, pins["runtime_closure_sha256"])
    result = AdmittedNativeBundle(canonical_json(pins), descriptor_raw, closure, adapter)
    result.verify()
    return result


def parse_admission_value(value):
    if not isinstance(value, str):
        raise NativeAdapterError("missing caller-admitted native pin record")
    raw = value.encode("utf-8")
    record = validate_candidate_record(strict_json(raw, MAX_ADMISSION))
    if canonical_json(record) != raw:
        raise NativeAdapterError("native admission value must be canonical captured JSON")
    return record


@dataclasses.dataclass(frozen=True)
class NativeCacheIdentity:
    route_id: str
    model_id: str
    transform_source_index_sha256: str
    bundle_content_sha256: str
    runtime_closure_content_sha256: str
    canonical_spec_sha256: str
    object_backend_argv: tuple
    frame_backend_argv: tuple

    def __post_init__(self):
        if self.route_id != ROUTE_ID or self.model_id != MODEL_ID:
            raise NativeAdapterError("unsupported native cache route/model")
        for name in ("transform_source_index_sha256", "bundle_content_sha256",
                     "runtime_closure_content_sha256", "canonical_spec_sha256"):
            _digest(getattr(self, name))
        for name in ("object_backend_argv", "frame_backend_argv"):
            values = tuple(getattr(self, name))
            if not values or len(values) > 32:
                raise NativeAdapterError("invalid native backend option vector")
            for value in values:
                _text(value, "backend option")
                if os.path.isabs(value):
                    raise NativeAdapterError("native cache options contain a locator")
            object.__setattr__(self, name, values)

    def to_dict(self):
        doc = dataclasses.asdict(self)
        doc["object_backend_argv"] = list(self.object_backend_argv)
        doc["frame_backend_argv"] = list(self.frame_backend_argv)
        return doc


def _diagnostics(rows):
    if not isinstance(rows, list) or len(rows) > 128:
        raise NativeAdapterError("invalid native diagnostics")
    for row in rows:
        _object(row, DIAGNOSTIC_KEYS, "diagnostic")
        if type(row["code"]) is not str or not re.fullmatch(r"MBPF[1-7][0-9]{2}", row["code"]) or type(row["severity"]) is not str or row["severity"] not in {"error", "warning", "note"}:
            raise NativeAdapterError("invalid native diagnostic vocabulary")
        _text(row["stage"], "diagnostic stage")
        _text(row["explanation"], "diagnostic explanation")
        for name in ("location", "remedy"):
            if row[name] is not None:
                _text(row[name], "diagnostic " + name)
    return rows


def _layout_fields(row):
    for name in ("store_size", "alloc_size", "abi_alignment", "preferred_alignment"):
        if not _integer(row[name]) or not 0 < row[name] <= 1 << 20:
            raise NativeAdapterError("invalid native layout fact")
    for name in ("abi_alignment", "preferred_alignment"):
        if row[name] & (row[name] - 1):
            raise NativeAdapterError("native layout alignment is not a power of two")


def _typed_fields(row, fields, label, partial=False, *, empty_strings=()):
    if not isinstance(row, dict) or set(row) - set(fields) or (not partial and set(row) != set(fields)):
        raise NativeAdapterError("invalid %s fields" % label, stage="adapter.transform")
    for name, value in row.items():
        allowed = fields[name] if isinstance(fields[name], tuple) else (fields[name],)
        if type(value) not in allowed:
            raise NativeAdapterError("invalid %s %s type" % (label, name), stage="adapter.transform")
        if type(value) is str and not (value == "" and name in empty_strings):
            _text(value, label + " " + name)
    return row


def _typed_rows(rows, fields, label, bound=16384, *, empty_strings=()):
    if not isinstance(rows, list) or len(rows) > bound:
        raise NativeAdapterError("invalid %s inventory" % label, stage="adapter.transform")
    for row in rows:
        _typed_fields(row, fields, label, empty_strings=empty_strings)


_TRANSFORM_TYPES = {
    "key": {"kind": str, "literal": int, "source": str, "source_ordinal": int, "target": str},
    "map": {"kind": str, "literal": int, "source": str, "source_ordinal": int, "target": str},
    "value": {"kind": str, "literal": int, "source": str, "source_ordinal": int, "target": str},
    "helper": {"kind": str, "callee": str, "helper_id": int, "source": str, "source_ordinal": int},
    "value-map": {"kind": str, "source": str, "target": str, "value_kind": str},
    "target": {"kind": str, "triple": str, "cpu": str, "layout": str, "section": str},
    "map-metadata": {"kind": str, "symbol": str, "alignment": int, "size": int, "language": str,
                     "producer_authenticated": bool, "source_lines": bool},
}


def _sparse_failure_payload(report):
    """Validate producer phase shapes without requiring success-only proofs."""
    facts = report["target_facts"]
    if facts is not None:
        _typed_fields(facts, {"input_triple": str, "input_layout": str, "target_triple": str, "target_layout": str,
            "pointer_bits": int, "index_bits": int, "pointer_alignment_bits": int, "little_endian": bool,
            "target_cpu": str, "optimization_pipeline": str, "entry_abi": dict, "prefix": dict,
            "types": list, "attributes": list, "gep_offsets": list, "instruction_count": int,
            "basic_block_count": int, "producer_authenticated": bool, "source_audit": dict}, "failure target facts", partial=True)
        layout = {name: int for name in ("store_size", "alloc_size", "abi_alignment", "preferred_alignment")}
        if "entry_abi" in facts:
            _typed_fields(facts["entry_abi"], {"symbol": str, "calling_convention": int, "signature": str}, "failure entry ABI")
        if "prefix" in facts:
            prefix = _typed_fields(facts["prefix"], dict(layout, offsets=list), "failure prefix")
            if len(prefix["offsets"]) != 2 or any(not _integer(value) for value in prefix["offsets"]):
                raise NativeAdapterError("invalid failure prefix offset types", stage="adapter.transform")
        for name, fields in (("types", dict(layout, type=str)),
            ("attributes", {"owner": str, "slot": int, "attribute": str}),
            ("gep_offsets", {"source_type": str, "offset": int, "inbounds": bool})):
            if name in facts:
                # An unnamed declaration has an empty F.getName() owner in
                # failure facts. Other strings retain their nonempty contract.
                _typed_rows(facts[name], fields, "failure " + name,
                            empty_strings=("owner",) if name == "attributes" else ())
        if "source_audit" in facts:
            audit = _typed_fields(facts["source_audit"], {"scratch_cells": list, "key_consumers": list,
                "helper_calls": int, "module_flag": (int, type(None)), "source_mutated": bool,
                "address_control_taint": str}, "failure source audit")
            _typed_rows(audit["scratch_cells"], {"value": str, "origin": str, "offset": int, "size": int,
                "preparation": bool, "literal": int}, "failure scratch", 4096)
            _typed_rows(audit["key_consumers"], {"call": str, "buffer": str, "preparation": str,
                "literal": int, "freshness": str}, "failure key consumer", 4096)
    proofs = report["proof_obligations"]
    extras = {name: {} for name in ("endian_pointer_index", "gep_alignment", "attributes",
        "scratch_contracts", "calls_runtime", "debug_metadata", "target_transition")}
    extras.update(producer_reader={"producer_binding": str}, integer_semantics={"native_control": str},
        struct_entry_abi={"native_control": str}, pointer_provenance={"backend_guest_proof": str})
    if not isinstance(proofs, list) or len(proofs) > len(extras):
        raise NativeAdapterError("invalid failure proof inventory", stage="adapter.transform")
    seen = set()
    for row in proofs:
        if not isinstance(row, dict):
            raise NativeAdapterError("invalid failure proof row", stage="adapter.transform")
        name = _text(row.get("id"), "failure proof id")
        if name not in extras or name in seen:
            raise NativeAdapterError("unknown/duplicate failure proof id", stage="adapter.transform")
        seen.add(name)
        _typed_fields(row, dict(extras[name], id=str, status=str, runtime_qualified=bool), "failure proof")
        if row["runtime_qualified"] is not False:
            raise NativeAdapterError("falsely qualified failure proof", stage="adapter.transform")
    transforms = report["transformations"]
    if not isinstance(transforms, list) or len(transforms) > 16384:
        raise NativeAdapterError("invalid failure transformation inventory", stage="adapter.transform")
    for row in transforms:
        if not isinstance(row, dict):
            raise NativeAdapterError("invalid failure transformation row", stage="adapter.transform")
        kind = _text(row.get("kind"), "failure transformation kind")
        if kind not in _TRANSFORM_TYPES:
            raise NativeAdapterError("unknown failure transformation", stage="adapter.transform")
        _typed_fields(row, _TRANSFORM_TYPES[kind], "failure transformation")


def validate_native_report(report_raw, spec_bytes, input_digest, output_digest=None, exit_code=0):
    try:
        return _validate_native_report_fields(report_raw, spec_bytes, input_digest, output_digest, exit_code)
    except NativeAdapterError:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise NativeAdapterError("unusable native report: %s" % str(exc)[:500], stage="adapter.transform") from None


def _validate_native_report_fields(report_raw, spec_bytes, input_digest, output_digest=None, exit_code=0):
    """Check native report v1 completeness and exact *file byte* bindings."""
    report = strict_json(report_raw)
    keys = REPORT_KEYS if exit_code == 0 else REPORT_KEYS - {"output_digest"}
    _object(report, keys, "native report")
    if not _integer(report["schema_version"]) or report["schema_version"] != 1 or report["mode"] != "lower" or report["model_id"] != MODEL_ID or report["runtime_qualified"] is not False:
        raise NativeAdapterError("unsupported or falsely qualified native report", stage="adapter.transform")
    if report["input_digest"] != input_digest or report["spec_digest"] != _sha(spec_bytes):
        raise NativeAdapterError("native report input/spec file digest mismatch", stage="adapter.transform")
    if (not isinstance(report["unproved"], list) or report["unproved"]
            or not _integer(report["unproved_total"]) or report["unproved_total"] != 0
            or report["unproved_truncated"] is not False):
        raise NativeAdapterError("native report carries unproved obligations", stage="adapter.transform")
    diagnostics = _diagnostics(report["diagnostics"])
    if exit_code != 0:
        if exit_code != 4 or report["ok"] is not False or not diagnostics or not any(row["severity"] == "error" for row in diagnostics):
            raise NativeAdapterError("contradictory native failure report", stage="adapter.transform")
        _sparse_failure_payload(report)
        return report
    if report["ok"] is not True or any(row["severity"] == "error" for row in diagnostics) or report["output_digest"] != output_digest:
        raise NativeAdapterError("native report outcome/output file digest mismatch", stage="adapter.transform")
    spec = strict_json(spec_bytes)
    facts = _object(report["target_facts"], {"input_triple", "input_layout", "target_triple", "target_layout",
        "pointer_bits", "index_bits", "pointer_alignment_bits", "little_endian", "target_cpu",
        "optimization_pipeline", "entry_abi", "prefix", "types", "attributes", "gep_offsets",
        "instruction_count", "basic_block_count", "producer_authenticated", "source_audit"}, "native target facts")
    if facts["target_triple"] != "bpfel-unknown-none" or facts["target_cpu"] != "v3" or facts["optimization_pipeline"] != "none" or facts["little_endian"] is not True or facts["producer_authenticated"] is not False:
        raise NativeAdapterError("incomplete/unsupported native target facts")
    for name in ("pointer_bits", "index_bits", "pointer_alignment_bits"):
        if not _integer(facts[name]) or facts[name] != 64:
            raise NativeAdapterError("native pointer/index fact mismatch")
    for name, bound in (("instruction_count", 4096), ("basic_block_count", 128)):
        if not _integer(facts[name]) or not 0 < facts[name] <= bound:
            raise NativeAdapterError("invalid native resource facts")
    for name in ("input_triple", "input_layout", "target_layout"):
        _text(facts[name], "native " + name)
    abi = _object(facts["entry_abi"], {"symbol", "calling_convention", "signature"}, "entry ABI")
    if abi["symbol"] != spec["entry"] or not _integer(abi["calling_convention"]) or abi["calling_convention"] != 0 or abi["signature"] != "i32 (ptr)":
        raise NativeAdapterError("native entry ABI does not match captured specification")
    prefix = _object(facts["prefix"], {"store_size", "alloc_size", "abi_alignment", "preferred_alignment", "offsets"}, "prefix facts")
    if prefix["offsets"] != [0, 4] or any(not _integer(value) for value in prefix["offsets"]):
        raise NativeAdapterError("invalid native prefix offsets")
    for name in ("store_size", "alloc_size", "abi_alignment", "preferred_alignment"):
        if not _integer(prefix[name]) or prefix[name] <= 0:
            raise NativeAdapterError("invalid native prefix layout fact")
    for name in ("types", "attributes", "gep_offsets"):
        if not isinstance(facts[name], list) or len(facts[name]) > 16384:
            raise NativeAdapterError("invalid native fact inventory")
    seen_types = set()
    for row in facts["types"]:
        _object(row, {"type", "store_size", "alloc_size", "abi_alignment", "preferred_alignment"}, "type layout")
        if row["type"] not in {"i1", "i8", "i16", "i32", "i64", "ptr"} or row["type"] in seen_types:
            raise NativeAdapterError("unknown/duplicate native scalar type")
        seen_types.add(row["type"])
        _layout_fields(row)
    if not {"i32", "ptr"} <= seen_types:
        raise NativeAdapterError("native entry type facts are missing")
    for row in facts["attributes"]:
        _object(row, {"owner", "slot", "attribute"}, "attribute fact")
        _text(row["owner"], "attribute owner")
        _text(row["attribute"], "attribute")
        if not _integer(row["slot"]) or not 0 <= row["slot"] <= 0xffffffff:
            raise NativeAdapterError("invalid native attribute slot")
    for row in facts["gep_offsets"]:
        _object(row, {"source_type", "offset", "inbounds"}, "GEP fact")
        _text(row["source_type"], "GEP source type")
        if not _integer(row["offset"]) or not -(1 << 63) <= row["offset"] < (1 << 63) or type(row["inbounds"]) is not bool:
            raise NativeAdapterError("invalid native GEP fact")
    audit = _object(facts["source_audit"], {"scratch_cells", "key_consumers", "helper_calls", "module_flag", "source_mutated", "address_control_taint"}, "source audit")
    if audit["source_mutated"] is not False or audit["address_control_taint"] != "retained" or not _integer(audit["helper_calls"]) or not 0 <= audit["helper_calls"] <= 4096 or (audit["module_flag"] is not None and (not _integer(audit["module_flag"]) or audit["module_flag"] != 3)):
        raise NativeAdapterError("incomplete native source audit")
    for name in ("scratch_cells", "key_consumers"):
        if not isinstance(audit[name], list) or len(audit[name]) > 4096:
            raise NativeAdapterError("invalid native source audit inventory")
    for row in audit["scratch_cells"]:
        _object(row, {"value", "origin", "offset", "size", "preparation", "literal"}, "scratch fact")
        _text(row["value"], "scratch value")
        if row["origin"] not in {"shared r10 frame", "independent lookup"} or type(row["preparation"]) is not bool or not _integer(row["offset"]) or not _integer(row["size"]) or row["size"] not in (4, 8) or not _integer(row["literal"]):
            raise NativeAdapterError("invalid native scratch facts")
    for row in audit["key_consumers"]:
        _object(row, {"call", "buffer", "preparation", "literal", "freshness"}, "key consumer fact")
        for name in ("call", "buffer", "preparation"):
            _text(row[name], "key consumer " + name)
        if not _integer(row["literal"]) or row["freshness"] != "proved":
            raise NativeAdapterError("invalid native key freshness facts")
    proofs = report["proof_obligations"]
    statuses = {name: "admitted-semantic-subset" for name in ("integer_semantics", "endian_pointer_index",
        "gep_alignment", "struct_entry_abi", "attributes", "pointer_provenance", "scratch_contracts", "calls_runtime", "debug_metadata")}
    statuses.update(producer_reader="reader-verified", target_transition="lowered-verified-host-only")
    if not isinstance(proofs, list) or len(proofs) != len(statuses):
        raise NativeAdapterError("incomplete native proof obligations")
    for row in proofs:
        if not isinstance(row, dict):
            raise NativeAdapterError("invalid native proof row")
        name = row.get("id")
        extra = ({"producer_binding"} if name == "producer_reader" else
                 {"native_control"} if name in {"integer_semantics", "struct_entry_abi"} else
                 {"backend_guest_proof"} if name == "pointer_provenance" else set())
        _object(row, {"id", "status", "runtime_qualified"} | extra, "proof obligation")
        if name not in statuses or row["status"] != statuses.pop(name) or row["runtime_qualified"] is not False:
            raise NativeAdapterError("unknown/contradictory native proof obligation")
        for field in extra:
            _text(row[field], "proof obligation")
    transforms = report["transformations"]
    if not isinstance(transforms, list) or not transforms or len(transforms) > 16384:
        raise NativeAdapterError("missing/bounded native transformation ledger")
    targets, maps = [], []
    for row in transforms:
        if not isinstance(row, dict) or row.get("kind") not in _TRANSFORM_TYPES:
            raise NativeAdapterError("unknown native transformation")
        kind = row["kind"]
        _typed_fields(row, _TRANSFORM_TYPES[kind], "transformation")
        for name in ("source", "target", "callee"):
            if name in row:
                _text(row[name], "transformation " + name)
        if "source_ordinal" in row and (not _integer(row["source_ordinal"]) or not 0 <= row["source_ordinal"] < 4096):
            raise NativeAdapterError("invalid native transformation ordinal")
        if "literal" in row and not _integer(row["literal"]):
            raise NativeAdapterError("invalid native primitive literal")
        if kind == "value-map" and row["value_kind"] not in {"entry-block", "block", "argument", "instruction"}:
            raise NativeAdapterError("unknown native value mapping role")
        if kind == "target":
            targets.append(row)
        if kind == "map-metadata":
            maps.append(row)
        if kind == "helper" and (not _integer(row["helper_id"]) or row["helper_id"] not in (1, 2)):
            raise NativeAdapterError("native report claims an unsupported helper")
    if len(targets) != 1 or targets[0] != {"kind": "target", "triple": facts["target_triple"], "cpu": "v3", "layout": facts["target_layout"], "section": spec["section"]}:
        raise NativeAdapterError("native target transformation mismatch")
    if (spec["map"] is None and maps) or (spec["map"] is not None and len(maps) != 1):
        raise NativeAdapterError("native map metadata differs from captured declaration")
    if maps and maps[0] != {"kind": "map-metadata", "symbol": "mojobpf_map0", "alignment": 8,
        "size": 32, "language": "Mojo", "producer_authenticated": False, "source_lines": False}:
        raise NativeAdapterError("native map metadata facts are incomplete")
    return report


def read_native_outputs(output_dir, spec_bytes, source_ir, expected_output=None):
    """Re-read fixed owned outputs, independently of a service success claim."""
    spec_path, report_path = str(Path(output_dir) / "native-spec.json"), str(Path(output_dir) / "native-report.json")
    output_path = str(Path(output_dir) / "adapted.ll")
    if expected_output is not None and expected_output != output_path:
        raise NativeAdapterError("native response selected an unexpected output locator")
    if _read(spec_path) != spec_bytes:
        raise NativeAdapterError("native materialized specification bytes changed")
    input_sha, output_sha = _sha(_read(source_ir, MAX_IR)), _sha(_read(output_path, MAX_IR))
    report_raw = _read(report_path)
    report = validate_native_report(report_raw, spec_bytes, input_sha, output_sha)
    return {"spec_sha256": _sha(spec_bytes), "input_ir_sha256": input_sha,
            "adapted_ir_sha256": output_sha, "native_report_file_sha256": _sha(report_raw),
            "native_report_json_sha256": _sha(canonical_json(report)), "native_report": report}


def _write_owned(path, raw):
    try:
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                getattr(os, "O_NOFOLLOW", 0), 0o600), "wb") as handle:
            handle.write(raw)
    except OSError as exc:
        raise NativeAdapterError("cannot write fresh owned file %s: %s" % (path, exc)) from None


def handle_request(request_path, response_path):
    """Serve v1: 0 usable success, 1 written failure, 2 unusable invocation."""
    response = {"schema_version": 1, "ok": False, "outputs": {}, "diagnostics": []}
    try:
        request = _object(strict_json(_read(request_path)), REQUEST_KEYS, "adapter request")
        if not _integer(request["schema_version"]) or request["schema_version"] != 1 or request["profile_id"] != PROFILE_ID or request["diagnostic_mode"] != "text":
            raise NativeAdapterError("unsupported native adapter request version/profile/mode")
        for name in ("input_ir", "manifest_path", "output_dir"):
            _absolute(request[name])
        pins = parse_admission_value(os.environ.get(ADMISSION_ENV))
        bundle = admit_native_bundle(pins, os.path.abspath(__file__))
        manifest_raw = _read(request["manifest_path"])
        spec_bytes = derive_native_spec(manifest_raw, request["profile_id"])
        input_sha = _sha(_read(request["input_ir"], MAX_IR))
        output = Path(request["output_dir"])
        if output.is_symlink():
            raise NativeAdapterError("native output directory is a symlink")
        output.mkdir(parents=True, exist_ok=True)
        spec_path, report_path, adapted = output / "native-spec.json", output / "native-report.json", output / "adapted.ll"
        if any(os.path.lexists(path) for path in (spec_path, report_path, adapted)):
            raise NativeAdapterError("native output staging already contains a specification/report/output")
        _write_owned(str(spec_path), spec_bytes)
        bundle.verify()
        record, stdout, stderr = bundle.closure.run("lower", ["--mode", "lower", "--input", request["input_ir"],
            "--spec", str(spec_path), "--output", str(adapted), "--report", str(report_path), "--emit", "llvm"])
        # This is a retained command observation, not another v1 response field.
        sys.stdout.write(canonical_json({"native_command": record, "stdout": stdout, "stderr": stderr}).decode("ascii"))
        if record["status"] not in {"ok", "failed"} or record["exit_code"] not in (0, 4) or (record["exit_code"] == 0 and record["status"] != "ok"):
            raise NativeAdapterError("native execution failed without a trustworthy bounded report", stage="adapter.transform")
        bundle.verify()
        if _sha(_read(request["input_ir"], MAX_IR)) != input_sha or _read(request["manifest_path"]) != manifest_raw or _read(str(spec_path)) != spec_bytes:
            raise NativeAdapterError("native captured input/specification changed during execution", stage="adapter.transform")
        if record["exit_code"] == 4:
            report = validate_native_report(_read(str(report_path)), spec_bytes, input_sha, exit_code=4)
            response["diagnostics"] = report["diagnostics"]
        else:
            result = read_native_outputs(str(output), spec_bytes, request["input_ir"], str(adapted))
            response.update(ok=True, outputs={"adapted_ir": str(adapted)}, diagnostics=result["native_report"]["diagnostics"])
    except NativeAdapterError as exc:
        response["diagnostics"] = [exc.diagnostic()]
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        response["diagnostics"] = [NativeAdapterError("unusable native invocation: %s" % str(exc)[:500]).diagnostic()]
    try:
        _write_owned(response_path, canonical_json(response))
    except NativeAdapterError as exc:
        sys.stderr.write("native adapter: %s\n" % exc)
        return 2
    return 0 if response["ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Serve an explicitly admitted native adapter request.")
    parser.add_argument("--request", required=True)
    parser.add_argument("--response", required=True)
    args = parser.parse_args(argv)
    return handle_request(args.request, args.response)


if __name__ == "__main__":
    sys.exit(main())
