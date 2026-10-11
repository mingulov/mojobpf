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
Real producer provenance admission and actual target-bound export are not
implemented. Reserved export options always return required-unavailable;
there is no trust override. Reports are observations, not support or budget
verdicts. ELF64 little-endian ET_REL/EM_BPF is the current container scope.

Parser work limits bound hostile inputs, rather than setting size budgets.
Only the Python standard library and the installed/source mojobpf readers
and frozen validation formatting are used.
"""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import struct
import sys

from mojobpf.elf_reader import ElfError, parse_elf, section_bytes
from mojobpf.validation.models import CostRecord, TargetManifest, canonical_json

MAX_OBJECT_BYTES = 32 * 1024 * 1024
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_SECTIONS = 4096
MAX_SYMBOLS = 65536
MAX_RELOCATIONS = 65536
MAX_SLOTS = 262144
MAX_CASES = 1024
MAX_FUNCTIONS = 16384
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
        return json.loads(image, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, CollectionError):
            raise
        _error("schema-json", "cannot decode %s: %s" % (what, exc))


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


def collect_object(image: bytes, *, case: dict, provenance: dict | None) -> dict:
    """Measure only immutable captured bytes for one byte-bound catalog case."""
    case = _bound_case(case)
    _bytes(image, MAX_OBJECT_BYTES, "object")
    identity = _sha(image)
    if case["object_sha256"] is not None and case["object_sha256"] != identity:
        _error("object-identity", "captured object does not match declared case digest", "evidence", 4)
    provenance_digest = None
    if provenance is not None:
        if not isinstance(provenance, dict):
            _error("schema-shape", "provenance must be a JSON object or null")
        # This is capture/identity checking only, never producer admission.
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
    if case["producer"] != "synthetic":
        issues.append({"code": "provenance-admission-unavailable", "stage": "evidence",
                       "explanation": "real producer provenance admission is not implemented; this is an incomplete inspection, not a baseline"})
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

    When evidence_root is supplied, every reference is contained and rehashed.
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
            root = evidence_root.resolve()
            path = (root / evidence["relative_path"]).resolve()
            if not path.is_relative_to(root):
                _error("evidence-path", "evidence symlink escapes captured root", "evidence", 4)
            try:
                image = path.read_bytes()
            except OSError as exc:
                _error("evidence-unavailable", "cannot retrieve captured evidence: %s" % exc, "evidence", 3)
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


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        _error("usage", message)


def _read(path: Path, *, limit: int) -> bytes:
    try:
        with path.open("rb") as stream:
            image = stream.read(limit + 1)
    except OSError as exc:
        _error("input-unavailable", "cannot capture %s: %s" % (path.name, exc), "evidence", 3)
    _bytes(image, limit, "input " + path.name)
    return image


def _publish(path: Path, data: dict) -> None:
    # A new, exclusively owned run directory prevents overwriting earlier attempts.
    image = canonical_json(data) + b"\n"
    temporary = path.with_name("." + path.name + ".pending")
    if path.exists():
        raise FileExistsError("refusing to overwrite a published document")
    try:
        with temporary.open("xb") as stream:
            stream.write(image)
        temporary.rename(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("object", help="account for one captured ELF entry without a runtime target")
    for name in ("cases", "case", "object", "provenance", "out"):
        command.add_argument("--" + name, required=True, help="new run directory" if name == "out" else None)
    for name in ("target", "binding", "evidence-root"):
        command.add_argument("--" + name, help="reserved actual export: admission validator is unavailable")
    output = None
    try:
        args = parser.parse_args(argv)
        export_options = [args.target, args.binding, args.evidence_root]
        if any(export_options) and not all(export_options):
            _error("usage", "reserved --target, --binding and --evidence-root must occur together")
        output = Path(args.out)
        try:
            output.mkdir()
        except OSError as exc:
            output = None
            _error("output-exists", "--out must name a new creatable run directory: %s" % exc)
        catalog_image = _read(Path(args.cases), limit=MAX_CATALOG_BYTES)
        image = _read(Path(args.object), limit=MAX_OBJECT_BYTES)
        provenance_image = _read(Path(args.provenance), limit=MAX_CATALOG_BYTES)
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
        report = collect_object(image, case=case, provenance=provenance)
        if any(export_options):
            _error("admission-validator-unavailable", "actual target-bound cost export requires a separately admitted evidence validator; matching strings cannot admit evidence", "unavailable", 3)
        report = validate_report(report, evidence_root=output)
        _publish(output / "report.json", report)
        _publish(output / "report-identity.json", {"report_sha256": _sha(canonical_json(report))})
        if not report["complete"]:
            _publish(output / "attempt.json", {"schema_version": 1, "complete": False, "exit_code": 3, "issues": report["issues"] or [
                {"code": "required-metric-unavailable", "stage": "unavailable", "explanation": "a declared required measurement is unavailable"}]})
            return 3
        return 0
    except CollectionError as exc:
        attempt = {"schema_version": 1, "complete": False, "exit_code": exc.exit_code, "issues": [exc.issue()]}
        if output is not None:
            _publish(output / "attempt.json", attempt)
        print(canonical_json(attempt).decode("ascii"), file=sys.stderr)
        return exc.exit_code
    except OSError as exc:
        failure = CollectionError("publication-failed", "captured output publication failed: %s" % exc, stage="evidence", exit_code=4)
        attempt = {"schema_version": 1, "complete": False, "exit_code": 4, "issues": [failure.issue()]}
        if output is not None:
            try:
                _publish(output / "attempt.json", attempt)
            except OSError:
                pass  # The structured stderr record survives an unwritable output.
        print(canonical_json(attempt).decode("ascii"), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
