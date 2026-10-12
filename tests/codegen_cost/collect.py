# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Targetless, unprivileged structural cost accounting for captured BPF ELF.

Run from a source checkout with ``PYTHONPATH=src python3
tests/codegen_cost/collect.py object --help``. ``--out`` names a NEW run
directory, containing captured inputs and a deterministic ``report.json``.
The collector reads inputs once and never builds, executes, loads or attaches
anything. Slots include both halves of LD_IMM64; reachability is a static
union for one explicitly selected entry, not a dynamic instruction count.

Completeness covers the fixed object measurement scope only. Stack, runtime,
decompressed debug and duplicate-body costs are explicitly unavailable.
Qualifying producer, report and budget consumption requires independently
selected InvocationAuthority pins and complete retained capture closure.
Supporting package identity is a separate trusted-launcher precondition.
The CLI publishes an exact report/admission byte pair when admitted, and can
associate synthetic targets with frozen validation cost records. Real target
observation mapping remains unavailable; exports state NOT_RUN. Plain real
inspection remains incomplete. Approved object budgets require explicit report
carriers and separate approval authority; no numeric product budget is bundled.
ELF64 little-endian ET_REL/EM_BPF is the current container scope.

Parser work limits bound hostile inputs, rather than setting size budgets.
Only the Python standard library and the installed/source mojobpf readers
and frozen validation formatting are used.
"""

from __future__ import annotations

import argparse
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import struct
import stat
import sys
import tomllib
from types import MappingProxyType

from mojobpf.elf_reader import ElfError, parse_elf, section_bytes
from mojobpf.evidence import EvidenceError, qualify_artifacts
from mojobpf.validation.models import ContractError, CostRecord, RunPlan, TargetManifest, canonical_json

MAX_OBJECT_BYTES = 32 * 1024 * 1024
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_SECTIONS = 4096
MAX_SYMBOLS = 65536
MAX_RELOCATIONS = 65536
MAX_SLOTS = 262144
MAX_CASES = 1024
MAX_FUNCTIONS = 16384
MAX_CAPTURE_ENTRIES = 4096
MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_VALUES = 100000
# Linux UAPI helper IDs with dynamic program/callback execution. Their
# callees cannot be inferred from ordinary helper fallthrough accounting.
DYNAMIC_CALL_HELPERS = {12: "tail_call", 164: "for_each_map_elem", 170: "timer_set_callback",
                        180: "find_vma", 181: "loop", 209: "user_ringbuf_drain"}

METRIC_UNITS = {
    "elf_bytes": "bytes", "section_file_bytes": "bytes", "section_logical_bytes": "bytes",
    "executable_bytes": "bytes", "reachable_slots": "slots", "reachable_bytes": "bytes",
    "reachable_subprograms": "count", "call_depth": "count", "btf_bytes": "bytes",
    "btf_ext_bytes": "bytes", "debug_bytes": "bytes", "relocation_bytes": "bytes",
    "other_section_bytes": "bytes", "non_section_bytes": "bytes",
    "decompressed_debug_bytes": "bytes", "duplicate_subprogram_bytes": "bytes",
    "compiler_stack_bytes": "bytes", "verifier_stack_bytes": "bytes",
    "translated_bytes": "bytes", "jit_bytes": "bytes", "verifier_processed_instructions": "count",
    "verifier_states": "count", "verifier_duration_ns": "ns", "load_duration_ns": "ns",
    "attach_duration_ns": "ns", "runtime_duration_ns": "ns",
}
REQUIRED_OBJECT_METRICS = frozenset({
    "elf_bytes", "section_file_bytes", "section_logical_bytes", "executable_bytes",
    "reachable_slots", "reachable_bytes", "reachable_subprograms", "call_depth",
})
REACHABLE_METRICS = frozenset({"reachable_slots", "reachable_bytes", "reachable_subprograms", "call_depth"})
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class CollectionError(ValueError):
    """A structured failure: usage=2, unavailable=3, object/identity=4."""

    def __init__(self, code: str, explanation: str, *, stage: str = "schema", exit_code: int = 2):
        super().__init__(explanation)
        self.code, self.stage, self.exit_code = code, stage, exit_code
        self.explanation = explanation

    def issue(self) -> dict:
        return {"code": self.code, "stage": self.stage, "explanation": self.explanation}


def _error(code: str, reason: str, stage: str = "schema", exit_code: int = 2):
    raise CollectionError(code, reason, stage=stage, exit_code=exit_code)


def _sha(image: bytes) -> str:
    return hashlib.sha256(image).hexdigest()


def _bytes(image: bytes, limit: int, what: str) -> None:
    if type(image) is not bytes:
        _error("immutable-input-required", what + " must be captured immutable bytes")
    if len(image) > limit:
        _error("input-limit", what + " exceeds the parser work limit", "unsupported", 3)


def _keys(value, required, optional=(), what="record") -> None:
    if not isinstance(value, dict):
        _error("schema-shape", what + " must be an object")
    if any(not isinstance(key, str) for key in value):
        _error("schema-shape", what + " field names must be strings")
    missing = set(required) - value.keys()
    extra = value.keys() - set(required) - set(optional)
    if missing or extra:
        _error("schema-fields", "%s missing fields %s; unknown fields %s" % (what, sorted(missing), sorted(extra)))


def _text(value, what: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value:
        _error("schema-value", what + " must be a nonempty string without NUL")
    return value


def _digest(value, what: str, *, nullable=False):
    if nullable and value is None:
        return
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        _error("schema-digest", what + " must be lowercase SHA256")


def _integer(value, what: str) -> int:
    if type(value) is not int or value < 0:
        _error("schema-number", what + " must be an exact nonnegative integer")
    return value


def _relative(value: str) -> str:
    _text(value, "relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value or path.as_posix() != value or value == ".":
        _error("evidence-path", "evidence/reference paths must be normalized relative paths")
    return value


def _json(image: bytes, what: str):
    _bytes(image, MAX_CATALOG_BYTES, what)
    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                _error("schema-duplicate", "duplicate JSON key " + key)
            result[key] = value
        return result

    def nonfinite(value):
        _error("schema-number", "non-finite JSON number " + value)

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            nonfinite(value)
        return number

    try:
        value = json.loads(image, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, CollectionError):
            raise
        _error("schema-json", "cannot decode %s: %s" % (what, exc))
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_VALUES:
            _error("input-limit", what + " exceeds JSON depth/value limits", "unsupported", 3)
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


class _CapturedProvenance(dict):
    """Opaque file capture with identity checks, without producer admission."""

    def __init__(self, mapping: dict, image: bytes):
        super().__init__(mapping)
        self.image = image


def _case(case: dict, metric_names: set[str]) -> None:
    _keys(case, ("case_id", "family", "producer", "route", "profile", "entry", "source_refs", "corpus_ref",
                 "oracle_ref", "semantic_contract", "semantic_contract_sha256", "object_sha256",
                 "measurement_scope", "required_metrics", "status", "pending_reason", "prerequisites"), what="case")
    if not ID_RE.fullmatch(_text(case["case_id"], "case_id")):
        _error("schema-value", "invalid case_id")
    _text(case["family"], "family")
    _text(case["profile"], "profile")
    if case["producer"] not in ("c", "mojo", "rust", "synthetic") or case["route"] not in ("legacy", "parsed", "native", "reference", "synthetic"):
        _error("schema-value", "unknown producer or route")
    if (case["producer"] == "synthetic") != (case["route"] == "synthetic"):
        _error("schema-value", "synthetic producer and route must occur together")
    if case["producer"] == "synthetic" and (case["family"] != "accounting-control" or not case["case_id"].startswith("control.")):
        _error("schema-value", "synthetic is reserved for declared accounting controls")
    if case["measurement_scope"] != "object" or case["status"] not in ("ready", "pending"):
        _error("schema-value", "unsupported measurement scope or prerequisite status")
    pending = case["status"] == "pending"
    _keys(case["entry"], ("section", "symbol"), what="entry selection")
    for value in case["entry"].values():
        if value is not None or not pending:
            _text(value, "entry selection")
    if not isinstance(case["source_refs"], list) or not isinstance(case["prerequisites"], list):
        _error("schema-value", "source_refs and prerequisites must be arrays")
    for value in case["source_refs"]:
        _relative(value)
    for value in case["prerequisites"]:
        _text(value, "prerequisite")
    for key in ("corpus_ref", "oracle_ref"):
        if case[key] is not None:
            _relative(case[key])
    if not pending and (not case["source_refs"] or case["oracle_ref"] is None):
        _error("schema-value", "ready cases need source and independent oracle references")
    if pending:
        _text(case["pending_reason"], "pending_reason")
    elif case["pending_reason"] is not None:
        _error("schema-value", "ready case pending_reason must be null")
    for key in ("semantic_contract_sha256", "object_sha256"):
        _digest(case[key], key, nullable=pending or case["producer"] != "synthetic")
    semantic = case["semantic_contract"]
    if semantic is not None:
        if not isinstance(semantic, dict) or not semantic:
            _error("schema-value", "semantic_contract must be a nonempty object")
        if _sha(canonical_json(semantic)) != case["semantic_contract_sha256"]:
            _error("semantic-identity", "semantic contract digest mismatch", "evidence", 4)
    elif not pending:
        _error("schema-value", "ready case needs a captured semantic contract")
    elif case["semantic_contract_sha256"] is not None:
        _error("schema-value", "uncaptured pending semantic contract cannot declare a digest")
    required = case["required_metrics"]
    if not isinstance(required, list) or any(not isinstance(name, str) for name in required) or len(set(required)) != len(required):
        _error("schema-value", "required_metrics must be a unique string array")
    if not REQUIRED_OBJECT_METRICS <= set(required):
        _error("required-metrics", "required object metric minima cannot be omitted: " + ", ".join(sorted(REQUIRED_OBJECT_METRICS - set(required))))
    if not set(required) <= metric_names:
        _error("required-metrics", "required metric missing from catalog metric definitions")


def load_cases(image: bytes) -> dict:
    """Validate captured catalog bytes and return detached, byte-bound cases.

    The two private capture fields are supplied by this function only, never
    permitted in the input JSON. collect_object revalidates their contents.
    """
    _bytes(image, MAX_CATALOG_BYTES, "catalog")
    data = _json(image, "catalog")
    _keys(data, ("schema_version", "metrics", "cases"), what="catalog")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _error("schema-version", "catalog reads schema_version 1 only")
    if not isinstance(data["metrics"], list) or len(data["metrics"]) > len(METRIC_UNITS):
        _error("schema-value", "invalid metric definitions")
    names = set()
    for metric in data["metrics"]:
        _keys(metric, ("name", "unit"), what="metric definition")
        name = _text(metric["name"], "metric name")
        if name in names or METRIC_UNITS.get(name) != metric["unit"]:
            _error("metric-identity", "duplicate or unknown metric/unit")
        names.add(name)
    if not REQUIRED_OBJECT_METRICS <= names:
        _error("required-metrics", "catalog omits required object metrics")
    if not isinstance(data["cases"], list) or not 0 < len(data["cases"]) <= MAX_CASES:
        _error("input-limit", "catalog needs a bounded nonempty case array")
    ids = set()
    for case in data["cases"]:
        _case(case, names)
        if case["case_id"] in ids:
            _error("case-identity", "duplicate case_id")
        ids.add(case["case_id"])
    for case in data["cases"]:
        case["_catalog_image"], case["_catalog_sha256"] = image, _sha(image)
    return data


def _bound_case(case: dict) -> dict:
    if not isinstance(case, dict) or "_catalog_image" not in case or "_catalog_sha256" not in case:
        _error("catalog-capture-required", "select a case returned by load_cases", "evidence", 4)
    image = case["_catalog_image"]
    if type(image) is not bytes or _sha(image) != case["_catalog_sha256"]:
        _error("catalog-identity", "catalog capture digest mismatch", "evidence", 4)
    candidates = load_cases(image)["cases"]
    plain = {key: value for key, value in case.items() if key not in ("_catalog_image", "_catalog_sha256")}
    match = next((candidate for candidate in candidates if candidate["case_id"] == plain.get("case_id")), None)
    if match is None or canonical_json(plain) != canonical_json({key: value for key, value in match.items() if not key.startswith("_catalog_")}):
        _error("catalog-identity", "selected case changed after catalog capture", "evidence", 4)
    if match["status"] != "ready":
        _error("pending-case", match["pending_reason"], "unavailable", 3)
    return match


def _elf(image: bytes):
    _bytes(image, MAX_OBJECT_BYTES, "object")
    if len(image) < 64 or image[:4] != b"\x7fELF":
        _error("elf-header", "not a complete ELF header", "object", 4)
    if image[4] != 2 or image[5] != 1:
        _error("unsupported-elf-encoding", "only ELF64 little-endian accounting is implemented", "unsupported", 3)
    objtype, machine, version = struct.unpack_from("<HHI", image, 16)
    shoff = struct.unpack_from("<Q", image, 40)[0]
    ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHHH", image, 52)
    if image[6] != 1 or version != 1 or objtype != 1 or machine != 247 or ehsize != 64 or shentsize < 64 or shnum == 0 or shoff < 64 or phnum != 0:
        _error("elf-header", "expected version-1 ET_REL/EM_BPF with real section-header stride and no program headers", "object", 4)
    if shnum > MAX_SECTIONS:
        _error("input-limit", "section count exceeds parser work limit", "unsupported", 3)
    if shoff + shnum * shentsize > len(image):
        _error("elf-header", "section header table runs past captured bytes", "object", 4)
    # Bound the shared reader's symbol loops before it decodes untrusted tables.
    total_symbols = 0
    for index in range(shnum):
        fields = struct.unpack_from("<IIQQQQIIQQ", image, shoff + index * shentsize)
        kind, size, stride = fields[1], fields[5], fields[9]
        if kind == 2:
            if stride < 24 or size % stride:
                _error("symbol-table", "symbol table needs a real, coherent entry stride", "object", 4)
            total_symbols += size // stride
    if total_symbols > MAX_SYMBOLS:
        _error("input-limit", "symbol count exceeds parser work limit", "unsupported", 3)
    try:
        result = parse_elf(image, "captured-object")
    except ElfError as exc:
        _error("elf-structure", exc.explanation, "object", 4)
    if result.sections[0].type != 0 or result.sections[0].size != 0 or result.sections[shstrndx].type != 3:
        _error("elf-structure", "invalid null section or section-name string table", "object", 4)
    occupied = [(0, 64), (shoff, shoff + shnum * shentsize)]
    for section in result.sections:
        if section.type == 2 and result.sections[section.link].type != 3:
            _error("symbol-table", "symbol table must link a string table", "object", 4)
        if section.type != 8 and section.size:
            occupied.append((section.offset, section.offset + section.size))
        if section.flags & 4 and (section.type == 8 or section.size % 8):
            _error("executable-section", "executable payload must be file-backed eight-byte slots", "object", 4)
    occupied.sort()
    for left, right in zip(occupied, occupied[1:]):
        if left[1] > right[0]:
            _error("section-overlap", "ELF headers and file-backed section payloads must not overlap", "object", 4)
    return result


def _category(section) -> str:
    if section.type in (4, 9):
        return "relocation"
    if section.flags & 4:
        return "executable"
    if section.name == ".BTF":
        return "btf"
    if section.name == ".BTF.ext":
        return "btf_ext"
    if section.name.startswith((".debug_", ".zdebug_")) or section.name in (".eh_frame", ".debug_frame"):
        return "debug"
    return "other"


def _instructions(elf) -> dict:
    total = sum(section.size // 8 for section in elf.sections if section.flags & 4)
    if total > MAX_SLOTS:
        _error("input-limit", "instruction slots exceed parser work limit", "unsupported", 3)
    decoded = {}
    for section in elf.sections:
        if not section.flags & 4:
            continue
        data, entries, offset = section_bytes(elf, section), {}, 0
        while offset < len(data):
            opcode, registers, displacement, immediate = struct.unpack_from("<BBhi", data, offset)
            width = 16 if opcode == 0x18 else 8
            if width == 16:
                if offset + 16 > len(data):
                    _error("wide-load", "truncated LD_IMM64", "object", 4)
                reserved = struct.unpack_from("<BBh", data, offset + 8)
                if reserved != (0, 0, 0):
                    _error("wide-load", "LD_IMM64 continuation has nonzero reserved fields", "object", 4)
            entries[offset] = (opcode, registers, displacement, immediate, width)
            offset += width
        decoded[section.index] = entries
    return decoded


def _symbol_tables(elf) -> dict:
    tables, cursor = {}, 0
    for section in elf.sections:
        if section.type == 2:
            count = section.size // section.entsize
            tables[section.index] = elf.symbols[cursor:cursor + count]
            cursor += count
    return tables


def _relocations(elf, decoded: dict, tables: dict) -> dict:
    records, count = {}, 0
    for section in elf.sections:
        if section.type not in (4, 9):
            continue
        want = 24 if section.type == 4 else 16
        if section.entsize < want or section.size % section.entsize or section.info <= 0 or section.info >= len(elf.sections) or section.link not in tables:
            _error("relocation-table", "bad relocation stride, target section or symbol table", "object", 4)
        count += section.size // section.entsize
        if count > MAX_RELOCATIONS:
            _error("input-limit", "relocations exceed parser work limit", "unsupported", 3)
        target = elf.sections[section.info]
        symbols = tables[section.link]
        for offset in range(0, section.size, section.entsize):
            site, info = struct.unpack_from("<QQ", elf.image, section.offset + offset)
            ordinal, kind = info >> 32, info & 0xFFFFFFFF
            identity = (target.index, site)
            if ordinal >= len(symbols) or site >= target.size or identity in records:
                _error("relocation-record", "invalid symbol ordinal, site bounds or duplicate relocation site", "object", 4)
            if target.flags & 4 and (site % 8 or site not in decoded[target.index]):
                _error("relocation-site", "relocation site must be an instruction start, never a continuation", "object", 4)
            records[identity] = {"kind": kind, "form": section.type, "symbol": symbols[ordinal],
                                 "symbol_table_index": section.link, "symbol_ordinal": ordinal}
    return records


class _ReachabilityUnavailable(Exception):
    def __init__(self, code, reason):
        self.code, self.reason = code, reason


def _unreachable(code, reason):
    raise _ReachabilityUnavailable(code, reason)


def _functions(elf, decoded):
    functions = {}
    for symbol in elf.symbols:
        if symbol.type != 2 or symbol.shndx not in decoded:
            continue
        start, size = symbol.value, symbol.size
        section = elf.sections[symbol.shndx]
        if size == 0 or start % 8 or size % 8 or start + size > section.size:
            _unreachable("function-boundary", "executable STT_FUNC ranges need aligned, nonzero, in-section extents")
        if start not in decoded[symbol.shndx] or (start + size != section.size and start + size not in decoded[symbol.shndx]):
            _unreachable("continuation-target", "function boundary enters an LD_IMM64 continuation")
        functions.setdefault((symbol.shndx, start, size), []).append(symbol.name)
    if len(functions) > MAX_FUNCTIONS:
        _unreachable("input-limit", "function ranges exceed parser work limit")
    ranges = sorted(functions)
    for left, right in zip(ranges, ranges[1:]):
        if left[0] == right[0] and left[1] + left[2] > right[1]:
            _unreachable("function-overlap", "partially overlapping function extents are ambiguous")
    return functions


def _walk(elf, decoded, relocations, selection):
    functions = _functions(elf, decoded)
    candidates = [key for key, aliases in functions.items()
                  if elf.sections[key[0]].name == selection["section"] and selection["symbol"] in aliases]
    if len(candidates) != 1:
        _unreachable("missing-entry" if not candidates else "ambiguous-entry", "entry must resolve to one selected section/STT_FUNC range")
    entry = candidates[0]
    starts = {(key[0], key[1]): key for key in functions}
    queue, visited, slots, reached_functions, edges = deque([(entry, entry[1])]), set(), set(), {entry}, []
    graph = {}

    def successor(function, address, *, fallthrough=False):
        section, start, size = function
        if not start <= address < start + size:
            _unreachable("cross-function-fallthrough" if fallthrough else "branch-outside-function", "CFG successor escapes its proven function extent")
        if address not in decoded[section]:
            _unreachable("continuation-target", "CFG successor enters an LD_IMM64 continuation")
        queue.append((function, address))

    while queue:
        function, offset = queue.popleft()
        section = function[0]
        address = (section, offset)
        if address in visited:
            continue
        visited.add(address)
        opcode, registers, displacement, immediate, width = decoded[section][offset]
        slots.add(address)
        if width == 16:
            slots.add((section, offset + 8))
        next_offset = offset + width
        relocation = relocations.get(address)
        instruction_class = opcode & 7
        operation = opcode & 0xF0
        if opcode == 0x95:
            if registers or displacement or immediate or relocation is not None:
                _unreachable("unsupported-control-flow", "noncanonical or relocated exit")
            continue
        if instruction_class in (5, 6) and operation == 0x80:
            if opcode != 0x85 or displacement != 0 or registers & 0xF:
                _unreachable("unsupported-call", "unknown reachable call encoding or indirect callback")
            source = registers >> 4
            if source == 0:
                if immediate in DYNAMIC_CALL_HELPERS:
                    _unreachable("unsupported-call", "dynamic program/callback helper " + DYNAMIC_CALL_HELPERS[immediate] + " needs separate accounting")
                if relocation is not None:
                    _unreachable("unsupported-relocation", "helper calls cannot acquire an unresolved code relocation")
                successor(function, next_offset, fallthrough=True)
                continue
            if source != 1:
                _unreachable("unsupported-call", "kfunc/BTF and unknown call forms need separate accounting")
            if relocation is None:
                destination = (section, offset + 8 * (immediate + 1))
                metadata = {"symbol_table_index": None, "symbol_ordinal": None}
            else:
                if relocation["form"] != 9 or relocation["kind"] != 10:
                    _unreachable("unsupported-relocation", "direct calls support SHT_REL/R_BPF_64_32 only")
                symbol = relocation["symbol"]
                if symbol.type not in (2, 3) or symbol.shndx not in decoded:
                    _unreachable("unresolved-call", "call relocation has no defined executable function/section symbol")
                destination = (symbol.shndx, symbol.value + 8 * (immediate + 1))
                metadata = {key: relocation[key] for key in ("symbol_table_index", "symbol_ordinal")}
            if destination[0] in decoded and destination[1] not in decoded[destination[0]] and 0 <= destination[1] < elf.sections[destination[0]].size:
                _unreachable("continuation-target", "direct call enters an LD_IMM64 continuation")
            callee = starts.get(destination)
            if callee is None:
                _unreachable("unresolved-call", "direct call destination is not a proven function start")
            edges.append({"source": [section, offset], "target": list(destination), **metadata})
            graph.setdefault(function, set()).add(callee)
            reached_functions.add(callee)
            queue.append((callee, callee[1]))
            successor(function, next_offset, fallthrough=True)
            continue
        if relocation is not None:
            symbol = relocation["symbol"]
            # Ordinary map/data references never introduce executable roots.
            if opcode != 0x18 or relocation["form"] != 9 or relocation["kind"] != 1 or symbol.shndx in decoded or registers >> 4 not in (1, 2):
                _unreachable("unsupported-relocation", "unresolved reachable code reference or unsupported data relocation")
            if not 0 < symbol.shndx < len(elf.sections) or symbol.type not in (1, 3):
                _unreachable("unresolved-data-reference", "map/data relocation has no defined object/section symbol")
        if opcode == 0x18:
            if registers >> 4 not in (0, 1, 2):
                _unreachable("unsupported-code-reference", "function pointers, BTF and unknown wide-load pseudo sources are unsupported")
            if registers >> 4 in (1, 2) and relocation is None:
                _unreachable("unresolved-data-reference", "pseudo map reference has no captured relocation")
            successor(function, next_offset, fallthrough=True)
        elif instruction_class in (5, 6):
            if operation == 0:
                if opcode == 0x05:
                    target = offset + 8 * (displacement + 1)
                elif opcode == 0x06:
                    target = offset + 8 * (immediate + 1)
                else:
                    _unreachable("unsupported-control-flow", "unknown unconditional jump form")
                successor(function, target)
            elif operation in (0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0xA0, 0xB0, 0xC0, 0xD0) and (opcode & 8) in (0, 8):
                successor(function, offset + 8 * (displacement + 1))
                successor(function, next_offset, fallthrough=True)
            else:
                _unreachable("unsupported-control-flow", "unknown reachable branch or exit encoding")
        elif instruction_class == 0:
            _unreachable("unsupported-instruction", "unknown reachable LD encoding")
        elif instruction_class in (1, 2, 3, 4, 7):
            successor(function, next_offset, fallthrough=True)
        else:
            _unreachable("unsupported-instruction", "unknown reachable instruction class")

    # Iterative topological accounting: recursion cannot overflow Python's stack.
    indegree = {function: 0 for function in reached_functions}
    for callees in graph.values():
        for callee in callees:
            indegree[callee] += 1
    ready = deque(sorted(function for function in indegree if indegree[function] == 0))
    depths, processed = {entry: 0}, 0
    while ready:
        function = ready.popleft()
        processed += 1
        for callee in sorted(graph.get(function, ())):
            depths[callee] = max(depths.get(callee, 0), depths.get(function, 0) + 1)
            indegree[callee] -= 1
            if indegree[callee] == 0:
                ready.append(callee)
    recursion = processed != len(reached_functions)
    return entry, {"instruction_offsets": [list(address) for address in sorted(slots)],
                   "functions": [list(function) for function in sorted(reached_functions)],
                   "call_edges": sorted(edges, key=lambda edge: edge["source"])}, {
        "reachable_slots": len(slots), "reachable_bytes": len(slots) * 8,
        "reachable_subprograms": len(reached_functions) - 1,
        "call_depth": None if recursion else max(depths.values()),
    }, recursion


def _freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value):
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class InvocationAuthority:
    """Trusted invocation pins selected independently before reading payloads.

    Supporting package readback is the embedding launcher's separate precondition.
    Submitted carriers never supply this context or authorize its replacement.
    """
    contract_version: int
    evidence_class: str
    validator_source_sha256: str
    producer_admission_sha256: Mapping
    target_admission_sha256: str | None = None
    budget_approval_sha256: str | None = None

    def __post_init__(self):
        if type(self.contract_version) is not int or self.contract_version != 1:
            _error("schema-version", "unsupported invocation authority version")
        if self.evidence_class not in ("real", "synthetic"):
            _error("schema-value", "unknown invocation evidence class")
        if not isinstance(self.producer_admission_sha256, Mapping):
            _error("schema-shape", "producer authority slots must be a mapping")
        pins = dict(self.producer_admission_sha256)
        _keys(pins, ("candidate", "baseline", "reference"), what="producer authority")
        for role, pin in pins.items():
            _digest(pin, role + " producer pin", nullable=role != "candidate")
        for pin in (self.validator_source_sha256,):
            _digest(pin, "validator pin")
        for pin in (self.target_admission_sha256, self.budget_approval_sha256):
            _digest(pin, "operation pin", nullable=True)
        object.__setattr__(self, "producer_admission_sha256", MappingProxyType(pins))


def _immutable_blobs(blobs):
    if not isinstance(blobs, Mapping) or any(not isinstance(key, str) or type(value) is not bytes for key, value in blobs.items()):
        _error("immutable-input-required", "captured blobs must map string IDs to immutable bytes")
    return MappingProxyType(dict(blobs))


@dataclass(frozen=True)
class ValidatedProducerProvenance:
    provenance_raw: bytes
    inventory_raw: bytes
    admission_raw: bytes
    blobs: Mapping
    catalog_raw: bytes
    case_id: str
    object_image: bytes

    def __post_init__(self):
        object.__setattr__(self, "blobs", _immutable_blobs(self.blobs))

    @property
    def provenance(self):
        return _json(self.provenance_raw, "retained provenance")


@dataclass(frozen=True)
class CapturedReport:
    report_raw: bytes
    report_admission_raw: bytes
    report: Mapping
    producer_binding: ValidatedProducerProvenance

    def __post_init__(self):
        object.__setattr__(self, "report", _freeze(self.report))

    def to_dict(self):
        return _thaw(self.report)


@dataclass(frozen=True)
class ReportSet:
    candidate: CapturedReport
    baseline: CapturedReport
    reference: CapturedReport | None = None


@dataclass(frozen=True)
class ValidatedTargetBinding:
    captured_report: CapturedReport
    binding_raw: bytes
    target_raw: bytes
    plan_raw: bytes
    inventory_raw: bytes
    blobs: Mapping
    target: TargetManifest
    plan: RunPlan

    def __post_init__(self):
        object.__setattr__(self, "blobs", _immutable_blobs(self.blobs))


@dataclass(frozen=True)
class ValidatedBudgetAdmission:
    approval_raw: bytes
    policy_raw: bytes
    policy_inventory_raw: bytes
    policy_blobs: Mapping
    budget: Mapping
    reports: ReportSet

    def __post_init__(self):
        object.__setattr__(self, "policy_blobs", _immutable_blobs(self.policy_blobs))
        object.__setattr__(self, "budget", _freeze(self.budget))


def _identity(actual, expected, what):
    if actual != expected:
        _error("admission-identity", what + " differs from independently bound evidence", "evidence", 4)


def _record(raw, kind, fields):
    value = _json(raw, kind)
    _keys(value, ("schema_version", "kind", *fields), what=kind)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["kind"] != kind:
        _error("schema-version", "unsupported " + kind + " version/kind")
    return value


def _authority_pin(authority, raw, *, role=None, operation=None):
    if authority is None:
        _error("admission-unavailable", "qualifying consumption requires independent invocation authority", "unavailable", 3)
    if not isinstance(authority, InvocationAuthority):
        _error("schema-shape", "authority must be InvocationAuthority")
    # Recheck all context fields; a typed label or diagnostic cache is insufficient.
    InvocationAuthority(authority.contract_version, authority.evidence_class, authority.validator_source_sha256,
                        authority.producer_admission_sha256, authority.target_admission_sha256, authority.budget_approval_sha256)
    _bytes(raw, MAX_CATALOG_BYTES, "admission")
    if role is not None:
        if role not in ("candidate", "baseline", "reference"):
            _error("schema-value", "unknown producer authority role")
        pin = authority.producer_admission_sha256[role]
    else:
        pin = getattr(authority, operation + "_sha256")
    if pin is None:
        _error("admission-unavailable", "invocation has no authority for this role/operation", "unavailable", 3)
    _identity(_sha(raw), pin, "raw admission pin")
    # The trusted source is bounded separately from parser limits used by fixtures.
    _identity(_sha(_read(Path(__file__), limit=4 * 1024 * 1024)), authority.validator_source_sha256, "loaded validator source")


def _validator(record, authority, name):
    _identity(record["evidence_class"], authority.evidence_class, "evidence class")
    _keys(record["validator"], ("name", "source_sha256"), what="validator")
    _identity(record["validator"]["name"], name, "validator name")
    _digest(record["validator"]["source_sha256"], "validator source")
    _identity(record["validator"]["source_sha256"], authority.validator_source_sha256, "admitted validator source")


CAPTURE_ROLES = frozenset("source import sdk manifest profile adapter_source corpus oracle tool_capture dependency_manifest command frontend_ir lowered_ir lower_report lower_spec object driver_evidence review dirty_manifest target_observation comparison_policy source_capture".split())
BLOB_ROLES = frozenset("source import sdk adapter_source frontend_ir lowered_ir object".split())
FORBIDDEN_INVENTORY_KINDS = frozenset({"object-provenance-v1", "cost-producer-admission-v1", "object-cost", "report-admission-v1",
                                    "cost-target-admission-v1", "cost-budget-approval-v1", "cost-export-status", "cost-budget-assessment-v1"})


def _inventory_index(raw, *, scope):
    inventory = _record(raw, "cost-capture-inventory-v1", ("entries",))
    entries = inventory["entries"]
    if not isinstance(entries, list):
        _error("schema-shape", "inventory entries must be an array")
    if len(entries) > MAX_CAPTURE_ENTRIES:
        _error("input-limit", "inventory entry limit exceeded", "unsupported", 3)
    indexed, paths, sizes = {}, set(), {}
    permitted = {"producer": CAPTURE_ROLES - {"target_observation", "comparison_policy"},
                 "observation": {"target_observation", "review"}, "policy": {"comparison_policy", "review"}}[scope]
    for entry in entries:
        _keys(entry, ("id", "relative_path", "sha256", "size", "role"), what="capture entry")
        ref = _text(entry["id"], "capture ID")
        path = _relative(entry["relative_path"])
        _digest(entry["sha256"], "capture digest")
        _integer(entry["size"], "capture size")
        if not isinstance(entry["role"], str) or entry["role"] not in permitted:
            _error("schema-value", "inventory role is not permitted for " + scope)
        if ref in indexed or path in paths:
            _error("capture-alias", "duplicate capture ID/path", "evidence", 4)
        indexed[ref], paths = entry, paths | {path}
        limit = MAX_OBJECT_BYTES if entry["role"] in BLOB_ROLES else MAX_CATALOG_BYTES
        if entry["size"] > limit:
            _error("input-limit", "declared companion size exceeds its capture limit", "unsupported", 3)
        if entry["sha256"] in sizes and sizes[entry["sha256"]] != entry["size"]:
            _error("capture-identity", "same digest has conflicting declared sizes", "evidence", 4)
        sizes[entry["sha256"]] = entry["size"]
    if sum(sizes.values()) > MAX_CAPTURE_BYTES:
        _error("input-limit", "unique captured byte limit exceeded", "unsupported", 3)
    return indexed


def _inventory(raw, blobs, *, scope):
    indexed = _inventory_index(raw, scope=scope)
    blobs = _immutable_blobs(blobs)
    _identity(set(blobs), set(indexed), "exact captured inventory ID set")
    # Check all byte limits before hashing any supplied oversized companion.
    for ref, entry in indexed.items():
        _bytes(blobs[ref], MAX_OBJECT_BYTES if entry["role"] in BLOB_ROLES else MAX_CATALOG_BYTES, "capture " + ref)
    for ref, entry in indexed.items():
        image = blobs[ref]
        _identity(len(image), entry["size"], "captured companion size")
        _identity(_sha(image), entry["sha256"], "captured companion digest")
        object_record = False
        if len(image) <= MAX_CATALOG_BYTES:
            try:
                object_record = image.decode(json.detect_encoding(image)).lstrip().startswith("{")
            except UnicodeError:
                pass  # Opaque source/blob bytes are not JSON records.
        if object_record:
            try:
                record = _json(image, "inventory companion")
            except CollectionError as exc:
                if exc.exit_code == 3 or entry["role"] not in {"review", "source", "import", "sdk", "adapter_source"}:
                    raise
            else:
                kind = record.get("kind") if isinstance(record, dict) else None
                if isinstance(record, dict) and "kind" in record:
                    _text(kind, "inventory record kind")
                if kind in FORBIDDEN_INVENTORY_KINDS:
                    _error("inventory-backedge", "inventory contains a dependent report/admission/output", "evidence", 4)
                if isinstance(record, dict) and (set(BUDGET_FIELDS) <= record.keys() or
                        (record.get("kind") == "cost-comparison-policy-v1" and (scope != "policy" or entry["role"] != "comparison_policy"))):
                    _error("inventory-backedge", "inventory contains final budget or misplaced comparison policy", "evidence", 4)
    return indexed


def _ref(ref, roles, index, blobs, *, nullable=False):
    if ref is None and nullable:
        return None
    _text(ref, "capture reference")
    if ref not in index or index[ref]["role"] not in roles:
        _error("capture-closure", "missing or wrong-role captured reference " + ref, "evidence", 4)
    return blobs[ref]


def _strings(value, what, *, unique=False, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value):
        _error("schema-shape", what + " must be an array" + (" with entries" if nonempty else ""))
    for item in value:
        _text(item, what + " item")
    if unique and len(set(value)) != len(value):
        _error("schema-value", "duplicate " + what)
    return value


PROVENANCE_FIELDS = tuple("case_id catalog_sha256 semantic_contract_sha256 object_sha256 producer route profile source_repository primary_source_ref source_refs import_refs sdk_refs manifest_ref corpus_ref oracle_ref profile_ref tool_capture_refs command_refs flags optimization debug_policy link_policy llvm_lineage_refs inventory_ref adapter".split())
PRODUCER_ADMISSION_FIELDS = tuple("evidence_class provenance_sha256 inventory_sha256 catalog_sha256 case_id object_sha256 producer route adapter_kind review_ref scope validator".split())
ADAPTER_MAPS = {
    "synthetic-accounting-v1": {},
    "driver-evidence-v4": {"sidecar": {"driver_evidence"}, "published_outputs": None},
    "parsed-native-capture-v1": {"source_capture": {"source_capture"}, "frontend_command": {"command"},
        "frontend_ir": {"frontend_ir"}, "lower_command": {"command"}, "lower_report": {"lower_report"},
        "lower_spec": {"lower_spec"}, "lowered_ir": {"lowered_ir"}, "backend_command": {"command"}, "object": {"object"}},
    "reference-command-capture-v1": {"compile_command": {"command"}, "primary_source": {"source"}, "object": {"object"}},
}


def validate_producer_evidence(provenance_raw, inventory_raw, blobs, admission_raw, *, authority, producer_role, case, object_image):
    _authority_pin(authority, admission_raw, role=producer_role)
    case = _bound_case(case)
    _bytes(object_image, MAX_OBJECT_BYTES, "object")
    admission = _record(admission_raw, "cost-producer-admission-v1", PRODUCER_ADMISSION_FIELDS)
    _validator(admission, authority, "validate_producer_evidence_v1")
    _identity(admission["scope"], "object_provenance_only", "producer admission scope")
    _bytes(provenance_raw, MAX_CATALOG_BYTES, "provenance")
    _bytes(inventory_raw, MAX_CATALOG_BYTES, "inventory")
    _identity(admission["provenance_sha256"], _sha(provenance_raw), "provenance bytes")
    _identity(admission["inventory_sha256"], _sha(inventory_raw), "inventory bytes")
    index = _inventory(inventory_raw, blobs, scope="producer")
    provenance = _record(provenance_raw, "object-provenance-v1", PROVENANCE_FIELDS)
    for key, expected in (("case_id", case["case_id"]), ("catalog_sha256", case["_catalog_sha256"]),
                          ("semantic_contract_sha256", case["semantic_contract_sha256"]), ("object_sha256", _sha(object_image)),
                          ("producer", case["producer"]), ("route", case["route"]), ("profile", case["profile"])):
        _identity(provenance[key], expected, "provenance " + key)
        if key in admission:
            _identity(admission[key], expected, "admission " + key)
    _ref(admission["review_ref"], {"review"}, index, blobs)
    repository = provenance["source_repository"]
    _keys(repository, ("repository_id", "commit", "tree", "dirty_manifest_ref"), what="source repository")
    _text(repository["repository_id"], "repository identity")
    for key in ("commit", "tree"):
        if not isinstance(repository[key], str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", repository[key]):
            _error("schema-digest", "source repository must contain exact Git object IDs")
    _ref(repository["dirty_manifest_ref"], {"dirty_manifest"}, index, blobs, nullable=True)
    for name, role in (("source_refs", "source"), ("import_refs", "import"), ("sdk_refs", "sdk"),
                       ("tool_capture_refs", "tool_capture"), ("command_refs", "command"), ("llvm_lineage_refs", "tool_capture")):
        refs = _strings(provenance[name], name, unique=True, nonempty=name == "source_refs")
        for ref in refs:
            _ref(ref, {role}, index, blobs)
    _ref(provenance["primary_source_ref"], {"source"}, index, blobs)
    if provenance["primary_source_ref"] not in provenance["source_refs"]:
        _error("capture-closure", "primary source is outside captured source closure", "evidence", 4)
    for name, role, nullable in (("manifest_ref", "manifest", True), ("corpus_ref", "corpus", True),
                                 ("oracle_ref", "oracle", False), ("profile_ref", "profile", False)):
        _ref(provenance[name], {role}, index, blobs, nullable=nullable)
    _strings(provenance["flags"], "ordered flags")
    for key in ("optimization", "debug_policy", "link_policy", "inventory_ref"):
        _text(provenance[key], key)
    adapter = provenance["adapter"]
    _keys(adapter, ("kind", "artifact_name", "output_names", "entry", "frontend_emit", "evidence_refs"), what="producer adapter")
    if not isinstance(adapter["kind"], str) or adapter["kind"] not in ADAPTER_MAPS:
        _error("adapter-unavailable", "producer adapter is unsupported", "unavailable", 3)
    _keys(adapter["entry"], ("section", "symbol"), what="adapter entry")
    _identity(adapter["entry"], case["entry"], "adapter selected entry")
    _identity(admission["adapter_kind"], adapter["kind"], "admitted adapter kind")
    _strings(adapter["output_names"], "adapter output names", unique=True)
    if adapter["artifact_name"] is not None:
        _text(adapter["artifact_name"], "artifact name")
    if adapter["frontend_emit"] not in (None, "llvm", "llvm-bitcode"):
        _error("schema-value", "unknown frontend emit mode")
    _keys(adapter["evidence_refs"], ADAPTER_MAPS[adapter["kind"]], what="adapter role map")
    for name, roles in ADAPTER_MAPS[adapter["kind"]].items():
        if roles is not None:
            _ref(adapter["evidence_refs"][name], roles, index, blobs)
    if provenance["producer"] == "synthetic":
        _identity(authority.evidence_class, "synthetic", "synthetic producer class")
        _identity(provenance["route"], "synthetic", "synthetic route")
        _identity(adapter["kind"], "synthetic-accounting-v1", "synthetic adapter")
        if not case["case_id"].startswith("control.") or case["family"] != "accounting-control":
            _error("synthetic-only", "synthetic admission accepts explicitly named accounting controls only")
        if adapter["output_names"] or adapter["artifact_name"] is not None or adapter["frontend_emit"] is not None:
            _error("schema-value", "synthetic accounting has no build outputs or emit mode")
    else:
        if provenance["producer"] == "rust" or provenance["route"] == "native":
            _error("adapter-unavailable", "Rust and native compiler routes have no admitted adapter", "unavailable", 3)
        _validate_adapter(provenance, index, blobs, object_image)
    return ValidatedProducerProvenance(provenance_raw, inventory_raw, admission_raw, blobs,
                                      case["_catalog_image"], case["case_id"], object_image)


TOOL_FIELDS = tuple("tool_id role executable_sha256 distribution_sha256 version_text llvm_lineage origin_location dependency_manifest_ref origin_record_refs claim_map".split())
COMMAND_FIELDS = tuple("argv exit_code cwd files environment stdout stderr".split())
NATIVE_MODEL = "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1"


def _json_pointer(record, pointer):
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        _error("schema-value", "tool claim must use an RFC6901 JSON pointer")
    value = record
    for token in pointer.split("/")[1:] if pointer else []:
        if re.search(r"~(?![01])", token):
            _error("schema-value", "invalid JSON pointer escape")
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token) and int(token) < len(value):
            value = value[int(token)]
        else:
            _error("tool-claim-identity", "tool claim pointer does not resolve", "evidence", 4)
    if isinstance(value, (dict, list)):
        _error("tool-claim-identity", "normalized tool claims require original scalar values", "evidence", 4)
    return value


def _scalars(value):
    pending, found = [value], []
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        else:
            found.append(item)
    return found


def _tools(provenance, index, blobs):
    if not provenance["tool_capture_refs"] or not provenance["command_refs"]:
        _error("tool-capture-unavailable", "producer requires original executed-tool and command closure", "unavailable", 3)
    tools, ids = {}, set()
    for ref in provenance["tool_capture_refs"]:
        tool = _record(_ref(ref, {"tool_capture"}, index, blobs), "cost-tool-capture-v1", TOOL_FIELDS)
        _text(tool["tool_id"], "tool ID")
        if tool["tool_id"] in ids or tool["role"] not in ("producer", "lowerer", "backend", "assembler", "linker", "inspector"):
            _error("schema-value", "duplicate tool ID or unknown tool role")
        ids.add(tool["tool_id"])
        _digest(tool["executable_sha256"], "executed tool identity")
        _digest(tool["distribution_sha256"], "tool distribution", nullable=True)
        for key in ("version_text", "origin_location"):
            _text(tool[key], key)
        if tool["llvm_lineage"] is not None:
            _text(tool["llvm_lineage"], "LLVM lineage")
        origins = _strings(tool["origin_record_refs"], "original tool captures", unique=True, nonempty=True)
        original = {}
        for origin in origins:
            record = _json(_ref(origin, {"tool_capture"}, index, blobs), "original tool capture")
            if isinstance(record, dict) and record.get("kind") == "cost-tool-capture-v1":
                _error("tool-claim-identity", "normalized tool records cannot serve as original capture", "evidence", 4)
            original[origin] = record
        _ref(tool["dependency_manifest_ref"], {"dependency_manifest"}, index, blobs, nullable=True)
        if tool["role"] in ("producer", "lowerer", "backend", "assembler", "linker") and (tool["distribution_sha256"] is None or tool["dependency_manifest_ref"] is None or tool["llvm_lineage"] is None):
            _error("tool-capture-unavailable", "compiler/backend dependency, distribution and LLVM closure is required", "unavailable", 3)
        claims = tool["claim_map"]
        if not isinstance(claims, list) or not claims:
            _error("schema-shape", "tool normalization requires explicit original scalar claims")
        fields = set()
        for claim in claims:
            _keys(claim, ("field", "origin_ref", "json_pointer"), what="tool claim")
            field = claim["field"]
            if not isinstance(field, str) or field not in ("executable_sha256", "distribution_sha256", "version_text", "llvm_lineage") or field in fields:
                _error("schema-value", "unknown or duplicate normalized tool claim")
            fields.add(field)
            if not isinstance(claim["origin_ref"], str) or claim["origin_ref"] not in original:
                _error("capture-closure", "tool claim is outside retained original capture", "evidence", 4)
            _identity(_json_pointer(original[claim["origin_ref"]], claim["json_pointer"]), tool[field], "normalized tool " + field)
        if any(tool[field] is not None and field not in fields for field in ("executable_sha256", "distribution_sha256", "version_text", "llvm_lineage")):
            _error("capture-closure", "normalized tool field lacks an original scalar claim", "evidence", 4)
        tools[ref] = (tool, original)
    if any(ref not in tools or tools[ref][0]["llvm_lineage"] is None for ref in provenance["llvm_lineage_refs"]):
        _error("capture-closure", "LLVM lineage is outside executed tool closure", "evidence", 4)
    return tools


def _commands(provenance, index, blobs, tools):
    commands = {}
    for ref in provenance["command_refs"]:
        command = _json(_ref(ref, {"command"}, index, blobs), "original command")
        _keys(command, COMMAND_FIELDS, what="original command")
        _strings(command["argv"], "original argv", nonempty=True)
        _text(command["cwd"], "historical command cwd")
        if type(command["exit_code"]) is not int:
            _error("schema-number", "original command exit code must be an integer")
        if command["exit_code"] != 0:
            _error("producer-phase-unavailable", "producing command did not succeed", "unavailable", 3)
        if not isinstance(command["environment"], dict) or any(not isinstance(key, str) or not key or not isinstance(value, str) for key, value in command["environment"].items()):
            _error("schema-shape", "original command environment must map names to strings")
        if any(not isinstance(command[key], str) for key in ("stdout", "stderr")):
            _error("schema-shape", "raw command logs must be strings")
        if not isinstance(command["files"], list):
            _error("schema-shape", "command files must be an array")
        seen = set()
        for file in command["files"]:
            _keys(file, ("phase", "path", "sha256"), what="command file")
            _text(file["path"], "historical file path")
            _digest(file["sha256"], "historical file digest")
            if file["phase"] not in ("before", "after") or (file["phase"], file["path"]) in seen:
                _error("schema-value", "unknown or duplicate command-file phase/path")
            seen.add((file["phase"], file["path"]))
            known = any(entry["sha256"] == file["sha256"] for entry in index.values()) or any(tool[0]["executable_sha256"] == file["sha256"] for tool in tools.values())
            if not known:
                _error("capture-closure", "command file has no retained companion/tool identity", "evidence", 4)
        # The path scalar is retained in explicitly selected original tool records.
        # Its semantic attribution is externally reviewed, not inferred from PATH.
        matched = [(key, tool) for key, (tool, origins) in tools.items()
                   if any(command["argv"][0] == scalar for record in origins.values() for scalar in _scalars(record))]
        if len(matched) != 1:
            _error("tool-command-identity", "original argv has missing or ambiguous admitted executable attribution", "evidence", 4)
        commands[ref] = (command, matched[0][0], matched[0][1])
    return commands


def _command_flag(command, flag):
    positions = [index for index, token in enumerate(command["argv"]) if token == flag]
    if len(positions) != 1 or positions[0] + 1 == len(command["argv"]):
        _error("command-identity", "missing/ambiguous historical option " + flag, "evidence", 4)
    return command["argv"][positions[0] + 1]


def _historical_path(command, value):
    parsed = PurePosixPath(value)
    return str(parsed if parsed.is_absolute() else PurePosixPath(command["cwd"]) / parsed)


def _phase_file(command, path, digest, *, input):
    for phase in ("before", "after") if input else ("after",):
        records = [file for file in command["files"] if _historical_path(command, file["path"]) == _historical_path(command, path) and file["phase"] == phase]
        if len(records) != 1:
            _error("phase-capture-unavailable", "required historical before/after file capture is missing", "unavailable", 3)
        _identity(records[0]["sha256"], digest, "historical phase input/output")


def _flags_in_order(flags, argv):
    cursor = 0
    for flag in flags:
        try:
            cursor = argv.index(flag, cursor) + 1
        except ValueError:
            _error("command-identity", "ordered build flags differ from original commands", "evidence", 4)


def _object_license(image):
    elf = _elf(image)
    sections = [section for section in elf.sections if section.name == "license"]
    if len(sections) != 1:
        _error("license-capture-unavailable", "an exact ELF license declaration is required", "unavailable", 3)
    raw = section_bytes(elf, sections[0])
    if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
        _error("license-identity", "ELF license is not one NUL-terminated string", "evidence", 4)
    try:
        return _text(raw[:-1].decode("utf-8"), "ELF license")
    except UnicodeError:
        _error("license-identity", "ELF license is not UTF-8", "evidence", 4)


def _phase_closure(command, refs, blobs):
    for ref in refs:
        digest = _sha(blobs[ref])
        paths = [file["path"] for file in command["files"] if file["phase"] == "before" and file["sha256"] == digest]
        if not paths:
            _error("phase-capture-unavailable", "declared source/import/SDK input lacks producing phase capture", "unavailable", 3)
        for path in paths:
            _phase_file(command, path, digest, input=True)


def _native_lower_evidence(report, spec):
    obligations = report["proof_obligations"]
    names = {"producer_reader", "integer_semantics", "endian_pointer_index", "gep_alignment", "struct_entry_abi", "attributes",
             "pointer_provenance", "scratch_contracts", "calls_runtime", "debug_metadata", "target_transition"}
    if not isinstance(obligations, list):
        _error("schema-shape", "native proof obligations must be an array")
    seen = set()
    for row in obligations:
        _keys(row, ("id", "status", "runtime_qualified"), ("producer_binding", "native_control", "backend_guest_proof"), what="native proof obligation")
        name = _text(row["id"], "native proof ID")
        if name not in names or name in seen:
            _error("capture-closure", "unknown/duplicate native proof obligation", "evidence", 4)
        seen.add(name)
        status = {"producer_reader": "reader-verified", "target_transition": "lowered-verified-host-only"}.get(name, "admitted-semantic-subset")
        _identity(row["status"], status, "native proof status")
        if type(row["runtime_qualified"]) is not bool or row["runtime_qualified"]:
            _error("schema-value", "native proofs require exact runtime_qualified=false")
        for key in ("producer_binding", "native_control", "backend_guest_proof"):
            if key in row:
                _text(row[key], "native proof " + key)
    _identity(seen, names, "complete native proof obligations")
    transformations = report["transformations"]
    if not isinstance(transformations, list) or not transformations:
        _error("capture-closure", "native transformation evidence is missing", "evidence", 4)
    targets = []
    for row in transformations:
        if not isinstance(row, dict):
            _error("schema-shape", "native transformation must be an object")
        kind = _text(row.get("kind"), "native transformation kind")
        if kind == "target":
            _keys(row, ("kind", "triple", "cpu", "section"), ("layout",), what="native target transformation")
            for key, expected in (("triple", "bpfel-unknown-none"), ("cpu", "v3"), ("section", spec["section"])):
                _identity(row[key], expected, "native target transformation " + key)
            if "layout" in row:
                _text(row["layout"], "native target layout")
            targets.append(row)
        elif kind in ("key", "value", "map", "helper", "value-map", "map-metadata"):
            fields = {"key": ("source", "source_ordinal", "target", "literal"), "value": ("source", "source_ordinal", "target", "literal"),
                "map": ("source", "source_ordinal", "target", "literal"), "helper": ("source", "source_ordinal", "callee", "helper_id"),
                "value-map": ("source", "target", "value_kind"), "map-metadata": ("symbol", "size", "alignment", "language", "source_lines", "producer_authenticated")}[kind]
            _keys(row, ("kind", *fields), what="native transformation")
            for key in fields:
                if key in ("source_ordinal", "helper_id", "size", "alignment"):
                    _integer(row[key], "native transformation " + key)
                elif key == "literal":
                    if type(row[key]) is not int:
                        _error("schema-number", "native transformation literal must be an integer")
                elif key in ("source_lines", "producer_authenticated"):
                    if type(row[key]) is not bool or row[key]:
                        _error("schema-value", "native map metadata cannot claim source/authentication proof")
                else:
                    _text(row[key], "native transformation " + key)
        else:
            _error("native-capture-unavailable", "unsupported native transformation format", "unavailable", 3)
    _identity(len(targets), 1, "one native target transformation")


def _native_adapter(provenance, index, blobs, image, tools, commands):
    _identity(provenance["producer"], "mojo", "parsed native producer")
    _identity(provenance["route"], "parsed", "parsed native route")
    adapter, refs = provenance["adapter"], provenance["adapter"]["evidence_refs"]
    _identity(adapter["output_names"], [], "parsed native published output names")
    _identity(adapter["artifact_name"], None, "parsed native artifact name")
    _identity(blobs[refs["object"]], image, "parsed native object")
    phases = [refs[name] for name in ("frontend_command", "lower_command", "backend_command")]
    if len(set(phases)) != 3 or any(ref not in commands for ref in phases):
        _error("capture-closure", "native phases are missing or ambiguous", "evidence", 4)
    _identity(sorted(phases, key=provenance["command_refs"].index), phases, "native execution order")
    frontend, frontend_ref, producer = commands[phases[0]]
    lower, _, lowerer = commands[phases[1]]
    backend, backend_ref, backend_tool = commands[phases[2]]
    for tool, role in ((producer, "producer"), (lowerer, "lowerer"), (backend_tool, "backend")):
        _identity(tool["role"], role, "native executed-tool role")
    if "mojo" not in producer["version_text"].lower():
        _error("producer-identity", "parsed source capture requires the admitted Mojo producer", "evidence", 4)
    if frontend_ref not in provenance["llvm_lineage_refs"] or backend_ref not in provenance["llvm_lineage_refs"]:
        _error("capture-closure", "native frontend/backend LLVM lineages are missing", "evidence", 4)
    capture = _json(blobs[refs["source_capture"]], "native source capture")
    _keys(capture, ("source", "source_sha256", "sdk_import_closure", "producer_sha256", "emit", "producer_optimization"), what="native source capture")
    _text(capture["source"], "historical primary source")
    source_path = str(PurePosixPath(capture["source"]) if PurePosixPath(capture["source"]).is_absolute() else PurePosixPath(frontend["cwd"]) / capture["source"])
    _identity(capture["source_sha256"], _sha(blobs[provenance["primary_source_ref"]]), "native primary source bytes")
    _identity(capture["producer_sha256"], producer["executable_sha256"], "native producer executable")
    _identity(capture["emit"], adapter["frontend_emit"], "native source emit mode")
    _identity(_command_flag(frontend, "--emit"), capture["emit"], "original frontend emit mode")
    if source_path not in [_historical_path(frontend, token) for token in frontend["argv"]] or frontend["argv"][1:2] != ["build"]:
        _error("producer-identity", "original Mojo command does not consume the primary source", "evidence", 4)
    _phase_file(frontend, source_path, capture["source_sha256"], input=True)
    _phase_closure(frontend, provenance["source_refs"] + provenance["import_refs"] + provenance["sdk_refs"], blobs)
    closure = capture["sdk_import_closure"]
    if not isinstance(closure, dict) or not provenance["sdk_refs"]:
        _error("capture-closure", "native SDK/import source closure is missing", "evidence", 4)
    for path, digest in closure.items():
        _text(path, "historical SDK path")
        _digest(digest, "historical SDK digest")
    _identity(sorted(closure.values()), sorted(_sha(blobs[ref]) for ref in provenance["sdk_refs"] + provenance["import_refs"]), "native SDK/import closure")
    for path, digest in closure.items():
        _phase_file(frontend, path, digest, input=True)
    frontend_opts = [token for token in frontend["argv"] if re.fullmatch(r"-O[0-3sz]", token)]
    want_optimization = frontend_opts[-1] if frontend_opts else "default (no explicit optimization option)"
    _identity(capture["producer_optimization"], want_optimization, "native frontend optimization capture")
    frontend_path = _command_flag(frontend, "-o")
    _phase_file(frontend, frontend_path, _sha(blobs[refs["frontend_ir"]]), input=False)
    spec = _json(blobs[refs["lower_spec"]], "native request")
    _keys(spec, ("schema_version", "model_id", "profile_id", "entry", "program_type", "section", "kernel_license", "map"), what="native request")
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        _error("schema-version", "unsupported native request version")
    for key, expected in (("model_id", NATIVE_MODEL), ("profile_id", provenance["profile"]),
                          ("entry", adapter["entry"]["symbol"]), ("section", adapter["entry"]["section"]), ("kernel_license", _object_license(image))):
        _identity(spec[key], expected, "native request " + key)
    _identity(spec["program_type"], "xdp", "native selected program type")
    _identity(spec["profile_id"], "linux-bpfel-v3", "native selected model profile")
    if spec["map"] is not None:
        _keys(spec["map"], ("symbol", "type", "key_bits", "value_bits", "max_entries", "flags"), what="native map request")
        _text(spec["map"]["symbol"], "native map symbol")
        for key in ("type", "key_bits", "value_bits", "max_entries", "flags"):
            _integer(spec["map"][key], "native map " + key)
        _identity(spec["map"], {"symbol": "mojobpf_map0", "type": 2, "key_bits": 32, "value_bits": 64, "max_entries": 1, "flags": 0},
                  "native selected array-map contract")
    report = _json(blobs[refs["lower_report"]], "native lower report")
    _keys(report, ("schema_version", "model_id", "ok", "mode", "runtime_qualified", "input_digest", "spec_digest", "output_digest",
                   "diagnostics", "proof_obligations", "target_facts", "transformations"), what="native lower report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        _error("schema-version", "unsupported native lower report version")
    for key, expected in (("model_id", spec["model_id"]), ("ok", True), ("mode", "lower"), ("runtime_qualified", False),
                          ("input_digest", _sha(blobs[refs["frontend_ir"]])), ("spec_digest", _sha(blobs[refs["lower_spec"]])),
                          ("output_digest", _sha(blobs[refs["lowered_ir"]])), ("diagnostics", [])):
        if key in ("ok", "runtime_qualified") and type(report[key]) is not bool:
            _error("schema-value", "native status fields require exact booleans")
        _identity(report[key], expected, "native lower report " + key)
    _native_lower_evidence(report, spec)
    facts = report["target_facts"]
    if not isinstance(facts, dict) or not isinstance(facts.get("entry_abi"), dict):
        _error("schema-shape", "native target facts/entry ABI must be objects")
    if type(facts.get("little_endian")) is not bool:
        _error("schema-value", "native little_endian must be an exact boolean")
    for actual, expected in ((facts.get("entry_abi", {}).get("symbol"), spec["entry"]), (facts.get("target_triple"), "bpfel-unknown-none"),
                             (facts.get("target_cpu"), "v3"), (facts.get("little_endian"), True)):
        _identity(actual, expected, "native target facts")
    _identity(_command_flag(lower, "--mode"), "lower", "native lower mode")
    _identity(_command_flag(lower, "--input"), frontend_path, "native frontend/lower path continuity")
    _phase_file(lower, frontend_path, report["input_digest"], input=True)
    _phase_file(lower, _command_flag(lower, "--spec"), report["spec_digest"], input=True)
    _phase_file(lower, _command_flag(lower, "--report"), _sha(blobs[refs["lower_report"]]), input=False)
    lowered_path = _command_flag(lower, "--output")
    _phase_file(lower, lowered_path, report["output_digest"], input=False)
    _identity(_command_flag(lower, "--emit"), "llvm", "native backend input emit mode")
    if len(backend["argv"]) != 8:
        _error("native-command-unavailable", "unsupported native backend command format", "unavailable", 3)
    _identity(backend["argv"][1:5], ["-mtriple=bpfel", "-mcpu=v3", "-O2", "-filetype=obj"], "native backend target/CPU/optimization")
    _identity(backend["argv"][5], lowered_path, "native lower/backend path continuity")
    _phase_file(backend, lowered_path, report["output_digest"], input=True)
    _phase_file(backend, _command_flag(backend, "-o"), _sha(image), input=False)
    _flags_in_order(provenance["flags"], backend["argv"])


def _driver_adapter(provenance, index, blobs, image, tools, commands):
    _identity(provenance["producer"], "mojo", "driver producer")
    _identity(provenance["route"], "legacy", "driver route")
    adapter, refs = provenance["adapter"], provenance["adapter"]["evidence_refs"]
    outputs = refs["published_outputs"]
    if not isinstance(outputs, dict) or not outputs or any(not isinstance(name, str) for name in outputs):
        _error("capture-closure", "driver output map is empty or malformed", "evidence", 4)
    _identity(set(outputs), set(adapter["output_names"]), "exact driver published output names")
    objects = {name: _ref(ref, {"object"}, index, blobs) for name, ref in outputs.items()}
    sidecar_raw = blobs[refs["sidecar"]]
    sidecar = _json(sidecar_raw, "driver sidecar")
    if not isinstance(sidecar, dict) or type(sidecar.get("schema_version")) is not int or sidecar["schema_version"] != 4:
        _error("schema-version", "driver adapter accepts existing evidence v4 only")
    try:
        qualified = qualify_artifacts({adapter["artifact_name"]: sidecar_raw}, objects)
    except EvidenceError as exc:
        _error("driver-evidence-identity", str(exc), "evidence", 4)
    if not any(row.object_sha256 == _sha(image) and row.object_size == len(image) for row in qualified.artifacts):
        _error("capture-closure", "selected object is outside the exact qualified driver output set", "evidence", 4)
    inputs = sidecar["inputs"]
    for name, refs_name in (("source", "source_refs"), ("imports", "import_refs"), ("sdk", "sdk_refs")):
        expected = [(_sha(blobs[ref]), len(blobs[ref])) for ref in provenance[refs_name]]
        _identity([(row["sha256"], row["size"]) for row in inputs[name]], expected, "driver captured " + name)
    manifest_raw = _ref(provenance["manifest_ref"], {"manifest"}, index, blobs)
    _identity((inputs["manifest"]["sha256"], inputs["manifest"]["size"]), (_sha(manifest_raw), len(manifest_raw)), "driver manifest capture")
    _identity(inputs["flags"], provenance["flags"], "driver ordered flags")
    _identity(inputs["profile_id"], provenance["profile"], "driver profile")
    _identity(inputs["profile_sha256"], _sha(blobs[provenance["profile_ref"]]), "driver profile definition")
    tool_records = [tool for tool, _ in tools.values()]
    expected_tools = [tool["tool_id"] + " " + tool["version_text"] + " " + tool["executable_sha256"] for tool in tool_records]
    _identity(inputs["compiler"][:len(expected_tools)], expected_tools, "driver executed compiler/tool identities")
    original_scalars = []
    for tool, origins in tools.values():
        for original in origins.values():
            original_scalars.extend(_scalars(original))
        if tool["dependency_manifest_ref"] is not None:
            original_scalars.extend(_scalars(_json(blobs[tool["dependency_manifest_ref"]], "tool dependency capture")))
    if any(record not in original_scalars for record in inputs["compiler"][len(expected_tools):]):
        _error("capture-closure", "driver compiler dependency/environment identity lacks original capture", "evidence", 4)
    for key in ("tool_version", "sdk_version"):
        if inputs[key] not in original_scalars:
            _error("capture-closure", "driver " + key + " lacks original capture", "evidence", 4)
    adapter_digests = [item.rsplit(" ", 1)[-1] for item in inputs["adapter"]]
    _identity(sorted(adapter_digests), sorted(entry["sha256"] for entry in index.values() if entry["role"] == "adapter_source"), "driver adapter source identity")
    if not adapter_digests or not provenance["sdk_refs"]:
        _error("capture-closure", "driver adapter/SDK source closure is missing", "evidence", 4)
    try:
        manifest = _json(manifest_raw, "manifest") if manifest_raw.lstrip().startswith(b"{") else tomllib.loads(manifest_raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, CollectionError):
            raise
        _error("schema-value", "captured manifest cannot be decoded")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifact"), dict):
        _error("capture-closure", "driver source license declaration is missing", "evidence", 4)
    _identity(sidecar["source_license"], manifest["artifact"].get("source_license"), "full source grant")
    _identity(sidecar["kernel_license"], manifest["artifact"].get("kernel_license"), "manifest ELF license declaration")
    _identity(sidecar["kernel_license"], _object_license(image), "unchanged ELF license declaration")
    _flags_in_order(provenance["flags"], [token for command, _, _ in commands.values() for token in command["argv"]])


def _reference_target_options(argv, profile):
    """Decode explicit selectors, never infer a target from unrelated operands."""
    targets, cpus, position = [], [], 1
    operand_options = {"-D", "-U", "-I", "-include", "-imacros", "-isystem", "-iquote", "-idirafter", "-o"}
    opaque_selectors = {"-Xclang", "-Xarch", "-cc1", "-arch", "-march", "-mattr", "-triple", "-target-cpu", "-target-feature", "--mcpu"}
    opaque_prefixes = ("-Xclang=", "-Xarch_", "-arch=", "-march=", "-mattr=", "-triple=", "-target-cpu=",
                       "-target-feature=", "--mcpu=", "--config", "--driver-mode")
    while position < len(argv):
        token = argv[position]
        if token == "--":
            break
        if token in operand_options:
            if position + 1 == len(argv):
                _error("command-identity", "C command option lacks its operand", "evidence", 4)
            position += 2
            continue
        if token.startswith("@") or token in opaque_selectors or token.startswith(opaque_prefixes):
            _error("reference-command-unavailable", "unsupported response/config/forwarded target selection", "unavailable", 3)
        selected = None
        for names, values in ((("-target", "--target"), targets), (("-mcpu",), cpus)):
            if token in names:
                if position + 1 == len(argv) or argv[position + 1].startswith("-"):
                    _error("command-identity", "C target/CPU option lacks its value", "evidence", 4)
                selected = argv[position + 1]
                position += 1
            else:
                selected = next((token[len(name) + 1:] for name in names if token.startswith(name + "=")), None)
            if selected is not None:
                if not selected:
                    _error("command-identity", "C target/CPU selection is empty", "evidence", 4)
                values.append(selected)
                break
        position += 1
    if len(targets) != 1 or len(cpus) != 1:
        _error("command-identity", "C reference requires one unambiguous target and CPU selection", "evidence", 4)
    if not re.fullmatch(r"(?:bpf|bpfel)(?:-[A-Za-z0-9_.]+){0,3}", targets[0]) or cpus[0] != "v3" or profile != "linux-bpfel-v3":
        _error("command-identity", "C target/CPU selection differs from the admitted little-endian BPF profile", "evidence", 4)


def _reference_adapter(provenance, index, blobs, image, tools, commands):
    _identity(provenance["producer"], "c", "reference producer")
    _identity(provenance["route"], "reference", "reference route")
    adapter, refs = provenance["adapter"], provenance["adapter"]["evidence_refs"]
    _identity(refs["primary_source"], provenance["primary_source_ref"], "C reference primary source")
    _identity(blobs[refs["object"]], image, "C reference object")
    if refs["compile_command"] not in commands:
        _error("capture-closure", "C producing command is missing", "evidence", 4)
    command, tool_ref, tool = commands[refs["compile_command"]]
    if tool["role"] != "producer" or "clang" not in tool["version_text"].lower() or tool_ref not in provenance["llvm_lineage_refs"]:
        _error("producer-identity", "C reference requires recorded Clang/LLVM attribution", "evidence", 4)
    _identity(adapter["artifact_name"], None, "C reference artifact name")
    _identity(adapter["output_names"], [], "C reference published output names")
    _identity(adapter["frontend_emit"], None, "C reference frontend emit mode")
    _flags_in_order(provenance["flags"], command["argv"])
    _reference_target_options(command["argv"], provenance["profile"])
    if "-c" not in command["argv"]:
        _error("command-identity", "C reference lacks explicit BPF target/CPU/object flags", "evidence", 4)
    argv_paths = [_historical_path(command, token) for token in command["argv"]]
    sources = [file for file in command["files"] if file["phase"] == "before" and file["sha256"] == _sha(blobs[refs["primary_source"]]) and _historical_path(command, file["path"]) in argv_paths]
    if len(sources) != 1:
        _error("capture-closure", "C primary source path/capture is ambiguous or missing", "evidence", 4)
    _phase_file(command, sources[0]["path"], sources[0]["sha256"], input=True)
    _phase_closure(command, provenance["source_refs"] + provenance["import_refs"] + provenance["sdk_refs"], blobs)
    _phase_file(command, _command_flag(command, "-o"), _sha(image), input=False)


def _validate_adapter(provenance, index, blobs, image):
    tools = _tools(provenance, index, blobs)
    commands = _commands(provenance, index, blobs, tools)
    kind = provenance["adapter"]["kind"]
    if kind == "parsed-native-capture-v1":
        _native_adapter(provenance, index, blobs, image, tools, commands)
    elif kind == "driver-evidence-v4":
        _driver_adapter(provenance, index, blobs, image, tools, commands)
    elif kind == "reference-command-capture-v1":
        _reference_adapter(provenance, index, blobs, image, tools, commands)
    else:
        _error("admission-identity", "synthetic adapter cannot admit another producer", "evidence", 4)


def _revalidate_producer(binding, authority, role):
    if not isinstance(binding, ValidatedProducerProvenance):
        _error("schema-shape", "producer binding must retain validated captured payloads")
    _authority_pin(authority, binding.admission_raw, role=role)
    cases = load_cases(binding.catalog_raw)
    case = next((item for item in cases["cases"] if item["case_id"] == binding.case_id), None)
    if case is None:
        _error("admission-identity", "retained producer case is missing", "evidence", 4)
    return validate_producer_evidence(binding.provenance_raw, binding.inventory_raw, binding.blobs, binding.admission_raw,
        authority=authority, producer_role=role, case=case, object_image=binding.object_image)


def collect_object(image: bytes, *, case: dict, provenance: dict | None,
                   admission: ValidatedProducerProvenance | None = None,
                   authority: InvocationAuthority | None = None, producer_role="candidate") -> dict:
    """Measure only immutable captured bytes for one byte-bound catalog case."""
    case = _bound_case(case)
    _bytes(image, MAX_OBJECT_BYTES, "object")
    admitted = admission is not None
    if admitted:
        binding = _revalidate_producer(admission, authority, producer_role)
        _identity(image, binding.object_image, "collected admitted object bytes")
        _identity(case["_catalog_image"], binding.catalog_raw, "collected admitted catalog bytes")
        _identity(case["case_id"], binding.case_id, "collected admitted case")
        if provenance is not None:
            _identity(canonical_json(provenance), canonical_json(binding.provenance), "supplied admitted provenance")
            if isinstance(provenance, _CapturedProvenance):
                _identity(provenance.image, binding.provenance_raw, "captured admitted provenance bytes")
        provenance = _CapturedProvenance(binding.provenance, binding.provenance_raw)
    identity = _sha(image)
    if case["object_sha256"] is not None and case["object_sha256"] != identity:
        _error("object-identity", "captured object does not match declared case digest", "evidence", 4)
    provenance_digest = None
    if provenance is not None:
        if not isinstance(provenance, dict):
            _error("schema-shape", "provenance must be a JSON object or null")
        # This is capture/identity checking only, never producer admission.
        if "profile" not in provenance:
            _error("provenance-identity", "supplied provenance is missing the captured case profile", "evidence", 4)
        for key, want in (("object_sha256", identity), ("profile", case["profile"]),
                          ("producer", case["producer"]), ("route", case["route"]), ("case_id", case["case_id"])):
            if key in provenance and provenance[key] != want:
                _error("provenance-identity", "provenance %s differs from captured case/object" % key, "evidence", 4)
        try:
            raw = provenance.image if isinstance(provenance, _CapturedProvenance) else canonical_json(provenance)
            if canonical_json(_json(raw, "provenance")) != canonical_json(provenance):
                _error("provenance-identity", "provenance mapping changed after capture", "evidence", 4)
        except (ValueError, TypeError, RecursionError) as exc:
            if isinstance(exc, CollectionError):
                raise
            _error("schema-json", "provenance is not finite JSON")
        provenance_digest = _sha(raw)
    elf = _elf(image)
    decoded = _instructions(elf)
    relocations = _relocations(elf, decoded, _symbol_tables(elf))
    sections = [{"index": section.index, "name": section.name, "type": section.type, "flags": section.flags,
                 "logical_bytes": section.size, "file_bytes": len(section_bytes(elf, section)), "category": _category(section)}
                for section in elf.sections]
    costs = {"elf_bytes": len(image), "section_file_bytes": sum(section["file_bytes"] for section in sections),
             "section_logical_bytes": sum(section["logical_bytes"] for section in sections)}
    for category, name in (("executable", "executable_bytes"), ("btf", "btf_bytes"), ("btf_ext", "btf_ext_bytes"),
                           ("debug", "debug_bytes"), ("relocation", "relocation_bytes"), ("other", "other_section_bytes")):
        costs[name] = sum(section["file_bytes"] for section in sections if section["category"] == category)
    costs["non_section_bytes"] = len(image) - costs["section_file_bytes"]
    reasons = {
        "decompressed_debug_bytes": "decompressed debug size was not independently measured",
        "duplicate_subprogram_bytes": "exact duplicate-body/relocation-meaning accounting is not implemented",
        "compiler_stack_bytes": "no matching compiler/backend stack report is admitted",
        "verifier_stack_bytes": "no target verifier stack evidence is admitted",
    }
    for name in METRIC_UNITS.keys() - costs.keys() - REACHABLE_METRICS - reasons.keys():
        reasons[name] = "no admitted runtime evidence for " + name
    entry = {"section_index": None, "section_name": case["entry"]["section"], "symbol": case["entry"]["symbol"], "byte_offset": None}
    reachable = {"instruction_offsets": [], "functions": [], "call_edges": []}
    issues = []
    try:
        function, reachable, measurements, recursion = _walk(elf, decoded, relocations, case["entry"])
        entry["section_index"], entry["byte_offset"] = function[:2]
        costs.update(measurements)
        if recursion:
            reasons["call_depth"] = "reachable direct-call recursion prevents a finite call depth"
            issues.append({"code": "recursive-call", "stage": "unsupported", "explanation": reasons["call_depth"]})
    except _ReachabilityUnavailable as exc:
        issues.append({"code": exc.code, "stage": "unsupported", "explanation": exc.reason})
        for name in REACHABLE_METRICS:
            reasons[name] = exc.reason
    if case["producer"] != "synthetic" and not admitted:
        issues.append({"code": "provenance-admission-unavailable", "stage": "evidence",
                       "explanation": "independently admitted real producer provenance is absent; this is an incomplete inspection"})
    required = set(case["required_metrics"])
    report = {
        "schema_version": 1, "kind": "object-cost", "case_id": case["case_id"], "profile": case["profile"],
        "semantic_contract_sha256": case["semantic_contract_sha256"],
        "artifact": {"sha256": identity, "size_bytes": len(image), "producer": case["producer"], "route": case["route"],
                     "provenance_sha256": provenance_digest},
        "catalog_sha256": case["_catalog_sha256"], "entry": entry,
        "metrics": [{"name": name, "unit": unit, "value": costs.get(name),
                     "unavailable_reason": reasons.get(name) if costs.get(name) is None else None}
                    for name, unit in METRIC_UNITS.items()],
        "sections": sections, "reachable": reachable,
        "evidence": [{"role": "object", "sha256": identity, "relative_path": "object.o"},
                     {"role": "catalog", "sha256": case["_catalog_sha256"], "relative_path": "cases.json"}],
        "complete": not issues and all(costs.get(name) is not None for name in required), "issues": issues,
    }
    if provenance_digest is not None:
        report["evidence"].append({"role": "provenance", "sha256": provenance_digest, "relative_path": "provenance.json"})
    return validate_report(report)


def validate_report(report: dict, *, evidence_root: Path | None = None) -> dict:
    """Reject malformed values; missing fixed object metrics force incomplete.

    When evidence_root is supplied, references are contained, bounded and rehashed.
    This verifies captured-file identity only; it never admits a runtime target.
    """
    _keys(report, ("schema_version", "kind", "case_id", "profile", "semantic_contract_sha256", "artifact",
                   "catalog_sha256", "entry", "metrics", "sections", "reachable", "evidence", "complete", "issues"), what="report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1 or report["kind"] != "object-cost" or type(report["complete"]) is not bool:
        _error("schema-version", "invalid object report version/kind/completeness")
    _text(report["case_id"], "case_id")
    _text(report["profile"], "profile")
    for key in ("semantic_contract_sha256", "catalog_sha256"):
        _digest(report[key], key)
    artifact = report["artifact"]
    _keys(artifact, ("sha256", "size_bytes", "producer", "route", "provenance_sha256"), what="artifact")
    _digest(artifact["sha256"], "object digest")
    _digest(artifact["provenance_sha256"], "provenance digest", nullable=True)
    _integer(artifact["size_bytes"], "artifact size")
    if artifact["producer"] not in ("c", "mojo", "rust", "synthetic") or artifact["route"] not in ("legacy", "parsed", "native", "reference", "synthetic"):
        _error("schema-value", "unknown artifact producer/route")
    _keys(report["entry"], ("section_index", "section_name", "symbol", "byte_offset"), what="report entry")
    for key in ("section_name", "symbol"):
        _text(report["entry"][key], key)
    for key in ("section_index", "byte_offset"):
        if report["entry"][key] is not None:
            _integer(report["entry"][key], key)
    if not isinstance(report["metrics"], list):
        _error("schema-shape", "metrics must be an array")
    names, values = set(), {}
    for metric in report["metrics"]:
        _keys(metric, ("name", "unit", "value", "unavailable_reason"), what="measurement")
        name = _text(metric["name"], "metric name")
        if name in names or METRIC_UNITS.get(name) != metric["unit"]:
            _error("metric-identity", "duplicate or unknown report metric/unit")
        names.add(name)
        value, reason = metric["value"], metric["unavailable_reason"]
        if value is None:
            _text(reason, "unavailable_reason")
        elif metric["unit"] == "ns":
            if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)) or value < 0 or reason is not None:
                _error("schema-number", "timings need a finite nonnegative number and null reason")
        else:
            _integer(value, name)
            if reason is not None:
                _error("schema-value", "measured costs must have null unavailable_reason")
        values[name] = value
    if not isinstance(report["sections"], list):
        _error("schema-shape", "sections must be an array")
    for section in report["sections"]:
        _keys(section, ("index", "name", "type", "flags", "logical_bytes", "file_bytes", "category"), what="section")
        if not isinstance(section["name"], str):
            _error("schema-shape", "section name must be a string")
        for key in ("index", "type", "flags", "logical_bytes", "file_bytes"):
            _integer(section[key], key)
        if section["category"] not in ("executable", "btf", "btf_ext", "debug", "relocation", "other"):
            _error("schema-value", "unknown section accounting category")
    _keys(report["reachable"], ("instruction_offsets", "functions", "call_edges"), what="reachable")
    for key, length in (("instruction_offsets", 2), ("functions", 3)):
        if not isinstance(report["reachable"][key], list):
            _error("schema-shape", "reachability must be arrays")
        for address in report["reachable"][key]:
            if not isinstance(address, list) or len(address) != length:
                _error("schema-shape", "invalid reachability address/extent")
            for value in address:
                _integer(value, "reachability address/extent")
    if not isinstance(report["reachable"]["call_edges"], list):
        _error("schema-shape", "call_edges must be an array")
    for edge in report["reachable"]["call_edges"]:
        _keys(edge, ("source", "target", "symbol_table_index", "symbol_ordinal"), what="call edge")
        for key in ("source", "target"):
            if not isinstance(edge[key], list) or len(edge[key]) != 2:
                _error("schema-shape", "call address must have section and byte offset")
            for value in edge[key]:
                _integer(value, "call address")
        for key in ("symbol_table_index", "symbol_ordinal"):
            if edge[key] is not None:
                _integer(edge[key], key)
    if not isinstance(report["evidence"], list) or not isinstance(report["issues"], list):
        _error("schema-shape", "evidence and issues must be arrays")
    roles = set()
    required = set(REQUIRED_OBJECT_METRICS)
    for evidence in report["evidence"]:
        _keys(evidence, ("role", "sha256", "relative_path"), what="evidence")
        _digest(evidence["sha256"], "evidence digest")
        _relative(evidence["relative_path"])
        role = evidence["role"]
        if role not in ("object", "catalog", "provenance") or role in roles:
            _error("evidence-identity", "unknown or duplicate evidence role")
        roles.add(role)
        want = {"object": artifact["sha256"], "catalog": report["catalog_sha256"], "provenance": artifact["provenance_sha256"]}[role]
        if evidence["sha256"] != want:
            _error("evidence-identity", "companion evidence digest mismatch", "evidence", 4)
        if evidence_root is not None:
            root = Path(evidence_root).absolute()
            path = root / evidence["relative_path"]
            image = _read(path, limit=MAX_OBJECT_BYTES if role == "object" else MAX_CATALOG_BYTES)
            if _sha(image) != evidence["sha256"]:
                _error("evidence-identity", "retrieved evidence bytes differ from captured digest", "evidence", 4)
            if role == "object" and len(image) != artifact["size_bytes"]:
                _error("object-identity", "artifact size differs from captured object", "evidence", 4)
            if role == "catalog":
                case = next((case for case in load_cases(image)["cases"] if case["case_id"] == report["case_id"]), None)
                if case is None or case["profile"] != report["profile"] or case["semantic_contract_sha256"] != report["semantic_contract_sha256"] or case["producer"] != artifact["producer"] or case["route"] != artifact["route"] or case["entry"]["section"] != report["entry"]["section_name"] or case["entry"]["symbol"] != report["entry"]["symbol"] or (case["object_sha256"] is not None and case["object_sha256"] != artifact["sha256"]):
                    _error("catalog-identity", "report case/profile/semantic/producer/route/entry/object identity differs from captured catalog", "evidence", 4)
                required.update(case["required_metrics"])
    for item in report["issues"]:
        _keys(item, ("code", "stage", "explanation"), what="issue")
        for value in item.values():
            _text(value, "issue field")
    detached = _json(canonical_json(report), "report")
    if not all(values.get(name) is not None for name in required) or not {"object", "catalog"} <= roles or detached["issues"]:
        detached["complete"] = False
    return detached


def _synthetic_cost_records_for_tests(report: dict, *, target: TargetManifest) -> tuple[CostRecord, ...]:
    """Private unit formatting control. No runtime admission or CLI export."""
    report = validate_report(report)
    if not isinstance(target, TargetManifest):
        _error("synthetic-only", "private formatter requires an explicitly synthetic TargetManifest")
    target = TargetManifest.from_dict(target.to_dict())
    if report["artifact"]["producer"] != "synthetic" or report["artifact"]["route"] != "synthetic" or not report["case_id"].startswith("control.") or target.data["kernel"]["release"] != "synthetic-control" or target.data["build_host"]["identity"] != "synthetic-test":
        _error("synthetic-only", "private formatter accepts explicit synthetic accounting/report/target fixtures only")
    if target.data["byte_order"] != "le" or report["profile"] != "linux-bpfel-" + target.data["instruction_profile"]:
        _error("synthetic-profile", "synthetic target/profile identity mismatch", "evidence", 4)
    records = []
    for metric in report["metrics"]:
        data = {"schema_version": 1, "case_id": report["case_id"], "target_fingerprint": target.fingerprint,
                "metric": metric["name"], "unit": metric["unit"], "value": metric["value"],
                "basis": {"object_sha256": report["artifact"]["sha256"], "profile": report["profile"]}}
        if metric["value"] is None:
            data["unavailable_reason"] = metric["unavailable_reason"]
        records.append(CostRecord.from_dict(data))
    return tuple(records)


REPORT_ADMISSION_FIELDS = tuple("evidence_class report_raw_sha256 report_canonical_sha256 producer_admission_sha256 provenance_sha256 inventory_sha256 catalog_sha256 case_id object_sha256".split())


def _reproduce_report(binding, authority, role):
    binding = _revalidate_producer(binding, authority, role)
    case = next(item for item in load_cases(binding.catalog_raw)["cases"] if item["case_id"] == binding.case_id)
    return collect_object(binding.object_image, case=case, provenance=None, admission=binding, authority=authority, producer_role=role)


def _report_envelope(report, raw, binding, authority):
    return {"schema_version": 1, "kind": "report-admission-v1", "evidence_class": authority.evidence_class,
            "report_raw_sha256": _sha(raw), "report_canonical_sha256": _sha(canonical_json(report)),
            "producer_admission_sha256": _sha(binding.admission_raw), "provenance_sha256": _sha(binding.provenance_raw),
            "inventory_sha256": _sha(binding.inventory_raw), "catalog_sha256": _sha(binding.catalog_raw),
            "case_id": binding.case_id, "object_sha256": _sha(binding.object_image)}


def capture_report(report_raw: bytes, report_admission_raw: bytes, *, producer_binding, authority, producer_role):
    """Retain an explicit actual raw pair and reproduce its deterministic content."""
    _bytes(report_raw, MAX_CATALOG_BYTES, "report")
    _bytes(report_admission_raw, MAX_CATALOG_BYTES, "report admission")
    binding = _revalidate_producer(producer_binding, authority, producer_role)
    parsed = _json(report_raw, "report")
    report = validate_report(parsed)
    # Inspection may normalize completeness; an imported identity cannot change.
    _identity(canonical_json(report), canonical_json(parsed), "strict imported report parse")
    envelope = _record(report_admission_raw, "report-admission-v1", REPORT_ADMISSION_FIELDS)
    _identity(envelope, _report_envelope(report, report_raw, binding, authority), "explicit report admission envelope")
    reproduced = _reproduce_report(binding, authority, producer_role)
    _identity(canonical_json(report), canonical_json(reproduced), "reproduced report content")
    return CapturedReport(report_raw, report_admission_raw, report, binding)


def prepare_captured_report(report: dict, *, producer_binding, authority, producer_role):
    """Prepare new canonical bytes once; imported encodings use capture_report."""
    binding = _revalidate_producer(producer_binding, authority, producer_role)
    report = validate_report(report)
    _identity(canonical_json(report), canonical_json(_reproduce_report(binding, authority, producer_role)), "prepared report content")
    report_raw = canonical_json(report) + b"\n"
    envelope_raw = canonical_json(_report_envelope(report, report_raw, binding, authority)) + b"\n"
    return capture_report(report_raw, envelope_raw, producer_binding=binding, authority=authority, producer_role=producer_role)


def _revalidate_report(captured, authority, role):
    if not isinstance(captured, CapturedReport):
        _error("schema-shape", "qualifying consumption requires an explicit CapturedReport")
    reproduced = capture_report(captured.report_raw, captured.report_admission_raw, producer_binding=captured.producer_binding,
                                authority=authority, producer_role=role)
    try:
        cached = canonical_json(captured.to_dict())
    except (ValueError, TypeError, RecursionError):
        _error("schema-json", "cached report is not finite JSON")
    _identity(cached, canonical_json(_json(captured.report_raw, "retained report")), "cached strict report parse")
    return reproduced


TARGET_ADMISSION_FIELDS = tuple("evidence_class report_raw_sha256 report_canonical_sha256 report_admission_sha256 producer_admission_sha256 case_id catalog_sha256 semantic_contract_sha256 object_sha256 source_sha256 corpus_sha256 profile flags target_raw_sha256 target_fingerprint plan_raw_sha256 plan_hash observation_inventory_sha256 observation_refs review_ref scope validator".split())


def validate_target_binding(captured_report, binding_raw, target_raw, plan_raw, inventory_raw, blobs, *, authority):
    """Associate static costs with synthetic validation targets; real mapping is pending."""
    _authority_pin(authority, binding_raw, operation="target_admission")
    captured = _revalidate_report(captured_report, authority, "candidate")
    binding = _record(binding_raw, "cost-target-admission-v1", TARGET_ADMISSION_FIELDS)
    _validator(binding, authority, "validate_cost_target_binding_v1")
    _identity(binding["scope"], "static_object_cost_association", "target association scope")
    _bytes(target_raw, MAX_CATALOG_BYTES, "target")
    _bytes(plan_raw, MAX_CATALOG_BYTES, "plan")
    _bytes(inventory_raw, MAX_CATALOG_BYTES, "observation inventory")
    try:
        target = TargetManifest.from_dict(_json(target_raw, "target"))
        plan = RunPlan.from_dict(_json(plan_raw, "plan"))
    except ContractError as exc:
        _error("target-contract", str(exc))
    index = _inventory(inventory_raw, blobs, scope="observation")
    _ref(binding["review_ref"], {"review"}, index, blobs)
    observations = _strings(binding["observation_refs"], "target observation references", unique=True)
    for ref in observations:
        _ref(ref, {"target_observation"}, index, blobs)
    report, producer = captured.to_dict(), captured.producer_binding
    provenance = producer.provenance
    if provenance["corpus_ref"] is None:
        _error("target-input-unavailable", "target association requires the captured corpus", "unavailable", 3)
    expected = {"report_raw_sha256": _sha(captured.report_raw), "report_canonical_sha256": _sha(canonical_json(report)),
                "report_admission_sha256": _sha(captured.report_admission_raw), "producer_admission_sha256": _sha(producer.admission_raw),
                "case_id": report["case_id"], "catalog_sha256": report["catalog_sha256"],
                "semantic_contract_sha256": report["semantic_contract_sha256"], "object_sha256": report["artifact"]["sha256"],
                "source_sha256": _sha(producer.blobs[provenance["primary_source_ref"]]),
                "corpus_sha256": _sha(producer.blobs[provenance["corpus_ref"]]), "profile": report["profile"],
                "flags": provenance["flags"], "target_raw_sha256": _sha(target_raw), "target_fingerprint": target.fingerprint,
                "plan_raw_sha256": _sha(plan_raw), "plan_hash": plan.plan_hash, "observation_inventory_sha256": _sha(inventory_raw)}
    for key, value in expected.items():
        _identity(binding[key], value, "target binding " + key)
    _strings(binding["flags"], "target ordered flags")
    selected_target = next((item for item in plan.targets if item.fingerprint == target.fingerprint), None)
    if selected_target is None:
        _error("target-plan-identity", "target is absent from selected plan", "evidence", 4)
    _identity(selected_target.to_dict(), target.to_dict(), "complete plan target")
    selected_case = next((item for item in plan.cases if item.case_id == report["case_id"]), None)
    if selected_case is None or target.fingerprint not in selected_case.targets:
        _error("target-plan-identity", "case/target association is absent from selected plan", "evidence", 4)
    for key in ("source_sha256", "object_sha256", "corpus_sha256"):
        _identity(getattr(selected_case, key), expected[key], "planned " + key)
    if target.data["byte_order"] != "le" or report["profile"] != "linux-bpfel-" + target.data["instruction_profile"]:
        _error("target-profile-identity", "target byte order/instruction profile differs from producer", "evidence", 4)
    if authority.evidence_class == "real":
        _error("observation-adapter-unavailable", "actual target observation mapping has not been admitted", "unavailable", 3)
    return ValidatedTargetBinding(captured, binding_raw, target_raw, plan_raw, inventory_raw, blobs, target, plan)


def _revalidate_target(binding, authority):
    if not isinstance(binding, ValidatedTargetBinding):
        _error("schema-shape", "export requires a typed captured target binding")
    reproduced = validate_target_binding(binding.captured_report, binding.binding_raw, binding.target_raw, binding.plan_raw,
                                        binding.inventory_raw, binding.blobs, authority=authority)
    if not isinstance(binding.target, TargetManifest) or not isinstance(binding.plan, RunPlan):
        _error("schema-shape", "malformed cached target/plan")
    _identity(binding.target.to_dict(), reproduced.target.to_dict(), "cached target")
    _identity(binding.plan.to_dict(), reproduced.plan.to_dict(), "cached plan")
    return reproduced


def _pair_identity(captured):
    return (_sha(captured.report_raw), _sha(canonical_json(captured.to_dict())), _sha(captured.report_admission_raw))


def export_cost_records(captured_report, *, binding, authority):
    binding = _revalidate_target(binding, authority)
    captured = _revalidate_report(captured_report, authority, "candidate")
    _identity(_pair_identity(captured), _pair_identity(binding.captured_report), "explicit export report pair")
    report = captured.to_dict()
    if not report["complete"]:
        _error("report-incomplete", "export requires a complete reproduced object report", "unavailable", 3)
    flags = captured.producer_binding.provenance["flags"]
    rows = []
    for metric in report["metrics"]:
        value = {"schema_version": 1, "case_id": report["case_id"], "target_fingerprint": binding.target.fingerprint,
                 "metric": metric["name"], "unit": metric["unit"], "value": metric["value"],
                 "basis": {"object_sha256": report["artifact"]["sha256"], "profile": report["profile"], "flags": list(flags)}}
        if metric["value"] is None:
            value["unavailable_reason"] = metric["unavailable_reason"]
        try:
            rows.append(CostRecord.from_dict(value))
        except ContractError as exc:
            _error("cost-contract", str(exc))
    return tuple(rows)


BUDGET_FIELDS = tuple("schema_version budget_id case_id semantic_contract_sha256 profile metric unit baseline_report_sha256 baseline_value absolute_ceiling max_increase max_ratio reference_report_sha256 rationale owner approval_evidence_sha256".split())


def _number(value, what, *, positive=False):
    if type(value) not in (int, float) or (type(value) is float and not math.isfinite(value)) or value < 0 or (positive and value == 0):
        _error("schema-number", what + " must be a finite " + ("positive" if positive else "nonnegative") + " number")
    try:
        spelling = str(value)
    except ValueError:
        _error("input-limit", what + " exceeds the runtime's bounded integer serialization", "unsupported", 3)
    if len(spelling) > MAX_CATALOG_BYTES:
        _error("input-limit", what + " exceeds the numeric capture limit", "unsupported", 3)
    return value


def validate_budget(data):
    _keys(data, BUDGET_FIELDS, what="size budget")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        _error("schema-version", "unsupported size budget version")
    for key in ("budget_id", "case_id", "profile", "metric", "unit", "rationale", "owner"):
        _text(data[key], key)
    for key in ("semantic_contract_sha256", "baseline_report_sha256", "approval_evidence_sha256"):
        _digest(data[key], key)
    _digest(data["reference_report_sha256"], "reference report", nullable=True)
    if METRIC_UNITS.get(data["metric"]) != data["unit"]:
        _error("metric-identity", "budget metric/unit does not match object measurement registry")
    _number(data["baseline_value"], "baseline value")
    constraints = []
    for key in ("absolute_ceiling", "max_increase", "max_ratio"):
        if data[key] is not None:
            _number(data[key], key, positive=key == "max_ratio")
            constraints.append(key)
    if not constraints:
        _error("schema-value", "budget requires at least one numeric constraint")
    if data["max_ratio"] is not None and data["reference_report_sha256"] is None:
        _error("schema-value", "ratio budget requires an exact reference report digest")
    return _thaw(_freeze(data))


ASSESSMENT_IDENTITY_FIELDS = tuple("approval_raw_sha256 baseline_producer_admission_sha256 baseline_report_admission_sha256 baseline_report_raw_sha256 baseline_report_sha256 budget_canonical_sha256 budget_raw_sha256 candidate_producer_admission_sha256 candidate_report_admission_sha256 candidate_report_raw_sha256 candidate_report_sha256 comparison_policy_raw_sha256 reference_producer_admission_sha256 reference_report_admission_sha256 reference_report_raw_sha256 reference_report_sha256".split())
POLICY_FIELDS = tuple("evidence_class measurement_scope case_id semantic_contract_sha256 profile metric unit target_context candidate_baseline_conditions reference_conditions review_ref".split())
CONDITION_FIELDS = tuple("producer route profile_definition_sha256 tool_capture_digests flags optimization debug_policy link_policy sdk_closure_sha256 adapter_identity_sha256 entry_policy_sha256".split())
BUDGET_APPROVAL_FIELDS = tuple("evidence_class budget_terms_sha256 baseline_report_sha256 baseline_report_raw_sha256 baseline_report_admission_sha256 baseline_producer_admission_sha256 reference_report_sha256 reference_report_raw_sha256 reference_report_admission_sha256 reference_producer_admission_sha256 comparison_policy_sha256 policy_inventory_sha256 rationale owner review_ref scope validator".split())


def _closure_digest(refs, blobs):
    if not refs:
        return None
    return _sha(canonical_json([{"id": ref, "sha256": _sha(blobs[ref]), "size": len(blobs[ref])} for ref in refs]))


def _build_conditions(binding):
    provenance = binding.provenance
    index = _inventory(binding.inventory_raw, binding.blobs, scope="producer")
    adapter_refs = sorted(ref for ref, entry in index.items() if entry["role"] == "adapter_source")
    return {"producer": provenance["producer"], "route": provenance["route"],
            "profile_definition_sha256": _sha(binding.blobs[provenance["profile_ref"]]),
            "tool_capture_digests": [_sha(binding.blobs[ref]) for ref in provenance["tool_capture_refs"]],
            "flags": provenance["flags"], "optimization": provenance["optimization"], "debug_policy": provenance["debug_policy"],
            "link_policy": provenance["link_policy"], "sdk_closure_sha256": _closure_digest(provenance["sdk_refs"], binding.blobs),
            "adapter_identity_sha256": _closure_digest(adapter_refs, binding.blobs),
            "entry_policy_sha256": _sha(canonical_json(provenance["adapter"]["entry"]))}


def _validate_conditions(conditions):
    _keys(conditions, CONDITION_FIELDS, what="comparable build conditions")
    for key in ("producer", "route", "optimization", "debug_policy", "link_policy"):
        _text(conditions[key], key)
    for key in ("profile_definition_sha256", "entry_policy_sha256"):
        _digest(conditions[key], key)
    for key in ("sdk_closure_sha256", "adapter_identity_sha256"):
        _digest(conditions[key], key, nullable=True)
    _strings(conditions["flags"], "comparison ordered flags")
    for digest in _strings(conditions["tool_capture_digests"], "comparison tool captures", unique=True):
        _digest(digest, "comparison tool capture")


def _revalidate_report_set(reports, authority):
    if reports is None:
        _error("report-carrier-unavailable", "explicit candidate/baseline ReportSet is required", "unavailable", 3)
    if not isinstance(reports, ReportSet):
        _error("schema-shape", "reports must be an explicit ReportSet")
    if reports.candidate is None or reports.baseline is None:
        _error("report-carrier-unavailable", "required candidate/baseline carrier is missing", "unavailable", 3)
    return ReportSet(_revalidate_report(reports.candidate, authority, "candidate"),
                     _revalidate_report(reports.baseline, authority, "baseline"),
                     _revalidate_report(reports.reference, authority, "reference") if reports.reference is not None else None)


def _metric_value(report, name):
    return next((metric["value"] for metric in report["metrics"] if metric["name"] == name), None)


def validate_budget_admission_v1(budget, approval_raw, policy_raw, reports, policy_inventory_raw, policy_blobs, *, authority):
    _authority_pin(authority, approval_raw, operation="budget_approval")
    budget = validate_budget(budget)
    reports = _revalidate_report_set(reports, authority)
    if budget["reference_report_sha256"] is not None and reports.reference is None:
        _error("report-carrier-unavailable", "selected reference carrier is missing", "unavailable", 3)
    approval = _record(approval_raw, "cost-budget-approval-v1", BUDGET_APPROVAL_FIELDS)
    _validator(approval, authority, "validate_budget_admission_v1")
    _identity(approval["scope"], "object_budget_only", "budget approval scope")
    terms = {key: value for key, value in budget.items() if key != "approval_evidence_sha256"}
    _identity(_sha(approval_raw), budget["approval_evidence_sha256"], "final budget approval bytes")
    _identity(approval["budget_terms_sha256"], _sha(canonical_json(terms)), "approved budget terms")
    _bytes(policy_raw, MAX_CATALOG_BYTES, "comparison policy")
    _bytes(policy_inventory_raw, MAX_CATALOG_BYTES, "policy inventory")
    _identity(approval["comparison_policy_sha256"], _sha(policy_raw), "comparison policy bytes")
    _identity(approval["policy_inventory_sha256"], _sha(policy_inventory_raw), "policy inventory bytes")
    index = _inventory(policy_inventory_raw, policy_blobs, scope="policy")
    policy = _record(policy_raw, "cost-comparison-policy-v1", POLICY_FIELDS)
    if not any(entry["role"] == "comparison_policy" and policy_blobs[ref] == policy_raw for ref, entry in index.items()):
        _error("capture-closure", "exact comparison policy is not retained in policy inventory", "evidence", 4)
    _ref(approval["review_ref"], {"review"}, index, policy_blobs)
    _ref(policy["review_ref"], {"review"}, index, policy_blobs)
    _identity(policy["evidence_class"], authority.evidence_class, "comparison evidence class")
    _identity(policy["measurement_scope"], "object", "comparison measurement scope")
    for key in ("rationale", "owner"):
        _text(approval[key], key)
        _identity(approval[key], budget[key], "approved " + key)
    for key in ("case_id", "semantic_contract_sha256", "profile", "metric", "unit"):
        _identity(policy[key], budget[key], "comparison policy " + key)
    _validate_conditions(policy["candidate_baseline_conditions"])
    if policy["reference_conditions"] is not None:
        _validate_conditions(policy["reference_conditions"])
    if (reports.reference is None) != (policy["reference_conditions"] is None) or (reports.reference is None) != (budget["reference_report_sha256"] is None):
        _error("admission-identity", "reference report/policy/approval nullness differs", "evidence", 4)
    candidate = reports.candidate.to_dict()
    baseline = reports.baseline.to_dict()
    for report in (candidate, baseline):
        for key in ("case_id", "semantic_contract_sha256", "profile"):
            _identity(report[key], budget[key], "producer-specific budget " + key)
    for carrier in (reports.candidate, reports.baseline):
        _identity(_build_conditions(carrier.producer_binding), policy["candidate_baseline_conditions"], "candidate/baseline build policy")
    left, right = reports.candidate.producer_binding, reports.baseline.producer_binding
    _identity(left.provenance["source_repository"]["repository_id"], right.provenance["source_repository"]["repository_id"], "baseline source series")
    for key in ("corpus_ref", "oracle_ref"):
        left_ref, right_ref = left.provenance[key], right.provenance[key]
        _identity(_sha(left.blobs[left_ref]) if left_ref is not None else None,
                  _sha(right.blobs[right_ref]) if right_ref is not None else None, "candidate/baseline " + key)
    _identity(_sha(canonical_json(baseline)), budget["baseline_report_sha256"], "actual baseline report")
    for role in ("baseline", "reference"):
        carrier = getattr(reports, role)
        identities = {"report_sha256": _sha(canonical_json(carrier.to_dict())) if carrier else None,
                      "report_raw_sha256": _sha(carrier.report_raw) if carrier else None,
                      "report_admission_sha256": _sha(carrier.report_admission_raw) if carrier else None,
                      "producer_admission_sha256": _sha(carrier.producer_binding.admission_raw) if carrier else None}
        for suffix, expected in identities.items():
            key = role + "_" + suffix
            _digest(approval[key], key, nullable=role == "reference")
            _identity(approval[key], expected, "approved " + key)
    if reports.reference is not None:
        reference = reports.reference.to_dict()
        _identity(_sha(canonical_json(reference)), budget["reference_report_sha256"], "actual reference report")
        for key in ("semantic_contract_sha256", "profile"):
            _identity(reference[key], budget[key], "comparable reference " + key)
        _identity(_build_conditions(reports.reference.producer_binding), policy["reference_conditions"], "reviewed reference build policy")
        ref_binding = reports.reference.producer_binding
        for key in ("corpus_ref", "oracle_ref"):
            candidate_ref, reference_ref = left.provenance[key], ref_binding.provenance[key]
            _identity(_sha(left.blobs[candidate_ref]) if candidate_ref is not None else None,
                      _sha(ref_binding.blobs[reference_ref]) if reference_ref is not None else None, "comparable reference " + key)
    if policy["target_context"] is not None:
        _keys(policy["target_context"], ("target_fingerprint", "target_admission_sha256"), what="comparison target context")
        for digest in policy["target_context"].values():
            _digest(digest, "comparison target context")
        _error("target-context-unavailable", "target-associated budget adapters are not admitted", "unavailable", 3)
    actual_baseline = _metric_value(baseline, budget["metric"])
    if actual_baseline is None:
        _error("budget-metric-unavailable", "actual baseline metric is unavailable", "unavailable", 3)
    _identity(actual_baseline, budget["baseline_value"], "actual approved baseline value")
    if any(not carrier.to_dict()["complete"] for carrier in (reports.candidate, reports.baseline, reports.reference) if carrier is not None):
        _error("report-incomplete", "budget requires complete reproduced object reports", "unavailable", 3)
    return ValidatedBudgetAdmission(approval_raw, policy_raw, policy_inventory_raw, policy_blobs, budget, reports)


def assess_budget(report, baseline, budget, *, reference=None, admission=None, reports=None, authority=None):
    """Assess every approved rule using exact rational operands, without runtime claims."""
    budget = validate_budget(budget)
    supplied_reports = report, baseline, reference
    report, baseline = validate_report(report), validate_report(baseline)
    if reference is not None:
        reference = validate_report(reference)
    if admission is not None and reports is not None and authority is not None:
        for supplied, validated in zip(supplied_reports, (report, baseline, reference)):
            if supplied is not None:
                _identity(canonical_json(supplied), canonical_json(validated), "strict supplied budget report")
    identities = {key: None for key in ASSESSMENT_IDENTITY_FIELDS}
    identities.update(candidate_report_sha256=_sha(canonical_json(report)), baseline_report_sha256=_sha(canonical_json(baseline)),
                      budget_canonical_sha256=_sha(canonical_json(budget)),
                      reference_report_sha256=_sha(canonical_json(reference)) if reference is not None else None)
    rules = [{"rule": key, "status": "UNAVAILABLE", "actual": {"candidate": None, "baseline": None, "reference": None},
              "limit": budget[key], "reason": "independent admission and explicit report carriers are required"}
             for key in ("absolute_ceiling", "max_increase", "max_ratio") if budget[key] is not None]
    assessment = {"schema_version": 1, "kind": "cost-budget-assessment-v1", "evidence_class": authority.evidence_class if isinstance(authority, InvocationAuthority) else ("synthetic" if report["artifact"]["producer"] == "synthetic" else "real"),
            "scope": "object_budget_only", "status": "UNAVAILABLE", "identities": identities, "rules": rules,
            "issues": [{"code": "budget-admission-unavailable", "explanation": "independent approval, authority and reproduced carriers are required"}]}
    if admission is None or reports is None or authority is None:
        return assessment
    if not isinstance(admission, ValidatedBudgetAdmission):
        _error("schema-shape", "budget admission must retain validated approval/policy payloads")
    try:
        reports = _revalidate_report_set(reports, authority)
    except CollectionError as exc:
        if exc.exit_code != 3:
            raise
        assessment["issues"] = [{"code": exc.code, "explanation": exc.explanation}]
        return assessment
    for supplied, carrier, role in ((report, reports.candidate, "candidate"), (baseline, reports.baseline, "baseline"),
                                    (reference, reports.reference, "reference")):
        if (supplied is None) != (carrier is None):
            _error("admission-identity", "positional report/reference carrier nullness differs", "evidence", 4)
        if carrier is not None:
            _identity(canonical_json(supplied), canonical_json(carrier.to_dict()), "positional " + role + " report")
            identities[role + "_report_raw_sha256"] = _sha(carrier.report_raw)
            identities[role + "_report_admission_sha256"] = _sha(carrier.report_admission_raw)
            identities[role + "_producer_admission_sha256"] = _sha(carrier.producer_binding.admission_raw)
    identities["approval_raw_sha256"] = _sha(admission.approval_raw)
    identities["comparison_policy_raw_sha256"] = _sha(admission.policy_raw)
    cached_budget = validate_budget(_thaw(admission.budget))
    _identity(canonical_json(cached_budget), canonical_json(budget), "cached admitted budget")
    unavailable, can_measure = [], True
    try:
        validate_budget_admission_v1(budget, admission.approval_raw, admission.policy_raw, reports,
                                    admission.policy_inventory_raw, admission.policy_blobs, authority=authority)
    except CollectionError as exc:
        if exc.exit_code != 3:
            raise
        unavailable.append({"code": exc.code, "explanation": exc.explanation})
        can_measure = exc.code in ("report-incomplete", "budget-metric-unavailable")
    candidate_value = _metric_value(report, budget["metric"])
    baseline_value = _metric_value(baseline, budget["metric"])
    reference_value = _metric_value(reference, budget["metric"]) if reference is not None else None
    for rule in rules:
        name = rule["rule"]
        rule["actual"] = {"candidate": candidate_value, "baseline": baseline_value if name == "max_increase" else None,
                          "reference": reference_value if name == "max_ratio" else None}
        missing = not can_measure or candidate_value is None or (name == "max_increase" and baseline_value is None) or (name == "max_ratio" and (reference_value is None or reference_value <= 0))
        if missing:
            rule["reason"] = "required admitted metric/approval is unavailable or reference denominator is not positive"
            continue
        # Fraction of the canonical decimal spelling avoids division and float overflow.
        candidate_number, limit = Fraction(str(candidate_value)), Fraction(str(rule["limit"]))
        if name == "absolute_ceiling":
            passed = candidate_number <= limit
        elif name == "max_increase":
            passed = candidate_number - Fraction(str(baseline_value)) <= limit
        else:
            passed = candidate_number <= limit * Fraction(str(reference_value))
        rule["status"] = "PASS" if passed else "FAIL"
        rule["reason"] = ("signed delta" if name == "max_increase" else name) + (" satisfies the approved limit" if passed else " exceeds the approved limit")
    if unavailable or any(rule["status"] == "UNAVAILABLE" for rule in rules):
        assessment["status"] = "UNAVAILABLE"
    else:
        assessment["status"] = "FAIL" if any(rule["status"] == "FAIL" for rule in rules) else "PASS"
    assessment["issues"] = unavailable
    return assessment


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        _error("usage", message)


def _read(path: Path, *, limit: int, on_open=None) -> bytes:
    """Open regular files without following any path component; read at most cap+1."""
    descriptor = None
    try:
        descriptor = _open_checked(path, directory=False)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _error("capture-file-kind", "required input must be a regular file", "evidence", 4)
        if on_open is not None:
            on_open(before)
        if before.st_size > limit:
            _error("input-limit", "input " + path.name + " exceeds the capture limit", "unsupported", 3)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            image = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            _error("capture-changed", "required input changed during bounded capture", "evidence", 4)
    except OSError as exc:
        _error("input-unavailable", "cannot capture %s: %s" % (path.name, exc), "evidence", 3)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    _bytes(image, limit, "input " + path.name)
    return image


def _open_checked(path, *, directory):
    path = Path(path).absolute()
    if ".." in path.parts:
        _error("capture-path", "capture paths cannot contain traversal", "evidence", 4)
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for position, name in enumerate(path.parts[1:]):
            final = position == len(path.parts) - 2
            flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory or not final else os.O_NONBLOCK)
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except OSError as exc:
                if exc.errno in (20, 40):  # ENOTDIR/ELOOP: symlink or non-directory ancestor.
                    _error("capture-path", "capture path contains a symlink/non-directory component", "evidence", 4)
                raise
            os.close(descriptor)
            descriptor = child
        result, descriptor = descriptor, None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


class _FileCapture:
    """One invocation's immutable images; aliases are refused, exact reuse is read once."""
    def __init__(self):
        self.images, self.inodes = {}, {}
        self.content, self.retained_bytes = {}, 0

    def directory(self, root):
        descriptor = _open_checked(root, directory=True)
        os.close(descriptor)

    def read(self, path, *, limit):
        path = Path(path).absolute()
        if path in self.images:
            image = self.images[path]
            _bytes(image, limit, "reused captured input")
            return image
        inode = None

        def opened(metadata):
            nonlocal inode
            inode = metadata.st_dev, metadata.st_ino
            if inode in self.inodes:
                _error("capture-alias", "input paths alias the same captured file", "evidence", 4)

        image = _read(path, limit=limit, on_open=opened)
        if inode is None:
            _error("capture-identity", "opened file identity is unavailable", "evidence", 4)
        # Each physical file is read and hashed before sharing immutable content.
        digest = _sha(image)
        if digest in self.content:
            shared = self.content[digest]
            _identity(image, shared, "verified duplicate capture bytes")
            image = shared
        else:
            if self.retained_bytes + len(image) > MAX_CAPTURE_BYTES:
                _error("input-limit", "actual retained capture byte limit exceeded", "unsupported", 3)
            self.content[digest] = image
            self.retained_bytes += len(image)
        self.inodes[inode], self.images[path] = path, image
        return image


def _capture_inventory(raw, root, capture, *, scope):
    index = _inventory_index(raw, scope=scope)
    capture.directory(root)
    blobs, unique = {}, {}
    for ref, entry in index.items():
        image = capture.read(Path(root) / entry["relative_path"], limit=MAX_OBJECT_BYTES if entry["role"] in BLOB_ROLES else MAX_CATALOG_BYTES)
        _identity(len(image), entry["size"], "captured companion size")
        digest = _sha(image)
        _identity(digest, entry["sha256"], "captured companion digest")
        blobs[ref] = unique.setdefault(digest, image)
    _inventory(raw, blobs, scope=scope)
    return blobs


def _retain_inventory(raw, blobs, output, *, scope):
    for ref, entry in _inventory_index(raw, scope=scope).items():
        path = output / entry["relative_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(blobs[ref])
        _identity(_read(path, limit=MAX_OBJECT_BYTES if entry["role"] in BLOB_ROLES else MAX_CATALOG_BYTES), blobs[ref], "retained capture bytes")


def _publish(path: Path, data: dict | bytes) -> None:
    # A new, exclusively owned run directory prevents overwriting earlier attempts.
    image = data if type(data) is bytes else canonical_json(data) + b"\n"
    _bytes(image, MAX_CATALOG_BYTES, "published JSON")
    temporary = path.with_name("." + path.name + ".pending")
    if path.exists():
        raise FileExistsError("refusing to overwrite a published document")
    try:
        with temporary.open("xb") as stream:
            stream.write(image)
        temporary.rename(path)
        _identity(_read(path, limit=MAX_CATALOG_BYTES), image, "actual published bytes")
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("object", help="inspect captured ELF; qualifying operations require independent admission pins")
    for name in ("cases", "case", "object", "provenance", "out"):
        command.add_argument("--" + name, required=True, help="new run directory" if name == "out" else None)
    producer_names = ("producer-admission", "capture-inventory", "evidence-root", "expected-producer-admission-sha256", "expected-validator-sha256", "evidence-class")
    target_names = ("target", "binding", "plan", "observation-inventory", "target-evidence-root", "expected-binding-sha256")
    for name in (*producer_names, *target_names):
        command.add_argument("--" + name, help="all-or-none producer admission or target association group",
                             **({"choices": ("real", "synthetic")} if name == "evidence-class" else {}))
    output, inspection = None, None
    try:
        args = parser.parse_args(argv)
        producer_options = [getattr(args, name.replace("-", "_")) for name in producer_names]
        target_options = [getattr(args, name.replace("-", "_")) for name in target_names]
        if any(producer_options) and not all(producer_options):
            _error("usage", "all producer admission options must occur together")
        if any(target_options) and (not all(target_options) or not all(producer_options)):
            _error("usage", "all target options require the complete producer admission group")
        # Freeze invocation authority before decoding any supplied payload record.
        authority = InvocationAuthority(1, args.evidence_class, args.expected_validator_sha256,
            {"candidate": args.expected_producer_admission_sha256, "baseline": None, "reference": None},
            args.expected_binding_sha256, None) if all(producer_options) else None
        output = Path(args.out)
        try:
            descriptor = _open_checked(output.parent, directory=True)
            os.close(descriptor)
            output.mkdir()
        except OSError as exc:
            output = None
            _error("output-exists", "--out must name a new creatable run directory: %s" % exc)
        capture = _FileCapture()
        catalog_image = capture.read(Path(args.cases), limit=MAX_CATALOG_BYTES)
        image = capture.read(Path(args.object), limit=MAX_OBJECT_BYTES)
        provenance_image = capture.read(Path(args.provenance), limit=MAX_CATALOG_BYTES)
        cases = load_cases(catalog_image)
        case = next((case for case in cases["cases"] if case["case_id"] == args.case), None)
        if case is None:
            _error("unknown-case", "case_id is absent from captured catalog")
        provenance = _json(provenance_image, "provenance")
        if isinstance(provenance, dict):
            provenance = _CapturedProvenance(provenance, provenance_image)
        for name, content in (("cases.json", catalog_image), ("object.o", image),
                              ("provenance.json", provenance_image)):
            with (output / name).open("xb") as stream:
                stream.write(content)
        inspection = collect_object(image, case=case, provenance=provenance)
        report, carrier = inspection, None
        if authority is not None:
            admission_raw = capture.read(Path(args.producer_admission), limit=MAX_CATALOG_BYTES)
            _authority_pin(authority, admission_raw, role="candidate")
            producer_admission = _record(admission_raw, "cost-producer-admission-v1", PRODUCER_ADMISSION_FIELDS)
            _validator(producer_admission, authority, "validate_producer_evidence_v1")
            inventory_raw = capture.read(Path(args.capture_inventory), limit=MAX_CATALOG_BYTES)
            with (output / "producer-admission.json").open("xb") as stream:
                stream.write(admission_raw)
            with (output / "capture-inventory.json").open("xb") as stream:
                stream.write(inventory_raw)
            # Reject an unadmitted inventory before any companion parsing/capture.
            _digest(producer_admission["inventory_sha256"], "admitted inventory digest")
            _identity(_sha(inventory_raw), producer_admission["inventory_sha256"], "admitted inventory bytes")
            blobs = _capture_inventory(inventory_raw, Path(args.evidence_root), capture, scope="producer")
            _retain_inventory(inventory_raw, blobs, output / "producer-inputs", scope="producer")
            binding = validate_producer_evidence(provenance_image, inventory_raw, blobs, admission_raw,
                authority=authority, producer_role="candidate", case=case, object_image=image)
            report = collect_object(image, case=case, provenance=provenance, admission=binding, authority=authority)
            carrier = prepare_captured_report(report, producer_binding=binding, authority=authority, producer_role="candidate")
        report = validate_report(report, evidence_root=output)
        _publish(output / "report.json", carrier.report_raw if carrier is not None else report)
        if carrier is not None:
            _publish(output / "report-admission.json", carrier.report_admission_raw)
        _publish(output / "report-identity.json", {"report_sha256": _sha(canonical_json(report))})
        if all(target_options):
            binding_raw = capture.read(Path(args.binding), limit=MAX_CATALOG_BYTES)
            _authority_pin(authority, binding_raw, operation="target_admission")
            target_raw = capture.read(Path(args.target), limit=MAX_CATALOG_BYTES)
            plan_raw = capture.read(Path(args.plan), limit=MAX_CATALOG_BYTES)
            observations_raw = capture.read(Path(args.observation_inventory), limit=MAX_CATALOG_BYTES)
            for name, raw in (("target-admission.json", binding_raw), ("target.json", target_raw),
                              ("plan.json", plan_raw), ("observation-inventory.json", observations_raw)):
                with (output / name).open("xb") as stream:
                    stream.write(raw)
            observed = _capture_inventory(observations_raw, Path(args.target_evidence_root), capture, scope="observation")
            _retain_inventory(observations_raw, observed, output / "observation-inputs", scope="observation")
            target_binding = validate_target_binding(carrier, binding_raw, target_raw, plan_raw, observations_raw, observed, authority=authority)
            records = export_cost_records(carrier, binding=target_binding, authority=authority)
            records_raw = canonical_json([record.to_dict() for record in records]) + b"\n"
            status = {"schema_version": 1, "kind": "cost-export-status", "evidence_class": authority.evidence_class,
                "report_raw_sha256": _sha(carrier.report_raw), "report_canonical_sha256": _sha(canonical_json(report)),
                "report_admission_sha256": _sha(carrier.report_admission_raw), "producer_admission_sha256": _sha(carrier.producer_binding.admission_raw),
                "binding_sha256": _sha(binding_raw), "target_raw_sha256": _sha(target_raw), "target_fingerprint": target_binding.target.fingerprint,
                "plan_raw_sha256": _sha(plan_raw), "plan_hash": target_binding.plan.plan_hash, "cost_records_raw_sha256": _sha(records_raw),
                "outcome": "NOT_RUN", "scope": "static_object_cost_association"}
            _publish(output / "cost-records.json", records_raw)
            _publish(output / "export-status.json", status)
        if not report["complete"]:
            _publish(output / "attempt.json", {"schema_version": 1, "complete": False, "exit_code": 3, "issues": report["issues"] or [
                {"code": "required-metric-unavailable", "stage": "unavailable", "explanation": "a declared required measurement is unavailable"}]})
            return 3
        return 0
    except CollectionError as exc:
        attempt = {"schema_version": 1, "complete": False, "exit_code": exc.exit_code, "issues": [exc.issue()]}
        if output is not None:
            try:
                if inspection is not None and not (output / "report.json").exists():
                    _publish(output / "report.json", inspection)
                    _publish(output / "report-identity.json", {"report_sha256": _sha(canonical_json(inspection))})
                _publish(output / "attempt.json", attempt)
            except (OSError, CollectionError):
                pass  # Structured stderr remains authoritative on publication failure.
        print(canonical_json(attempt).decode("ascii"), file=sys.stderr)
        return exc.exit_code
    except OSError as exc:
        failure = CollectionError("publication-failed", "captured output publication failed: %s" % exc, stage="evidence", exit_code=4)
        attempt = {"schema_version": 1, "complete": False, "exit_code": 4, "issues": [failure.issue()]}
        if output is not None:
            try:
                _publish(output / "attempt.json", attempt)
            except (OSError, CollectionError):
                pass  # The structured stderr record survives an unwritable output.
        print(canonical_json(attempt).decode("ascii"), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
