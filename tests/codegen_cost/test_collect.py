# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Independent literal ELF controls; no compiler, disassembler or loader."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest

from mojobpf.validation.models import TargetManifest, canonical_json

COLLECT_PATH = Path(__file__).with_name("collect.py")


def collector():
    # Absence is an assertion failure in RED, rather than an import error.
    assert COLLECT_PATH.is_file(), "the object cost collector is not implemented"
    if "object_cost_collector" in sys.modules:
        return sys.modules["object_cost_collector"]
    spec = importlib.util.spec_from_file_location("object_cost_collector", COLLECT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXIT = bytes.fromhex("95 00 00 00 00 00 00 00")
MOV = bytes.fromhex("b7 00 00 00 02 00 00 00")
WIDE = bytes.fromhex("18 01 00 00 29 00 00 00 00 00 00 00 00 00 00 00")
MINIMUM = [
    "elf_bytes", "section_file_bytes", "section_logical_bytes", "executable_bytes",
    "reachable_slots", "reachable_bytes", "reachable_subprograms", "call_depth",
]
METRICS = {
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


def sha(image):
    return hashlib.sha256(image).hexdigest()


def elf(sections, tables=None, relocations=None):
    """Assemble an ELF container from literal data, independently of collection.

    Sections: (name, type, flags, bytes-or-NOBITS-size).
    Symbols: (name, info, section-index, byte-value, byte-size), in table-local order.
    Relocations: (name, type, target-index, table-number, literal-record-bytes, stride).
    This helper handles only the container; expected instruction addresses/counts
    in the tests are manually specified literals.
    """
    rows = [("", 0, 0, b"", 0, 0, 0)]
    rows.extend((name, kind, flags, data, 0, 0, 0) for name, kind, flags, data in sections)
    table_indices = []
    for number, symbols in enumerate(tables or [[("main", 0x12, 1, 0, 24)]]):
        strings = bytearray(b"\0")
        entries = bytearray(24)
        for name, info, section, value, size in symbols:
            offset = len(strings)
            strings.extend(name.encode("ascii") + b"\0")
            entries.extend(struct.pack("<IBBHQQ", offset, info, 0, section, value, size))
        index = len(rows)
        table_indices.append(index)
        rows.append((".symtab%d" % number, 2, 0, bytes(entries), index + 1, 1, 24))
        rows.append((".strtab%d" % number, 3, 0, bytes(strings), 0, 0, 0))
    for name, kind, target, table, data, stride in relocations or []:
        rows.append((name, kind, 0, data, table_indices[table], target, stride))
    names = bytearray(b"\0")
    offsets = [0]
    for name, *_ in rows[1:]:
        offsets.append(len(names))
        names.extend(name.encode("ascii") + b"\0")
    offsets.append(len(names))
    names.extend(b".shstrtab\0")
    name_index = len(rows)
    rows.append((".shstrtab", 3, 0, bytes(names), 0, 0, 0))
    image = bytearray(64)
    headers = []
    for ordinal, (_, kind, flags, data, link, info, stride) in enumerate(rows):
        location = len(image) if ordinal else 0
        size = data if kind == 8 else len(data)
        if kind != 8:
            image.extend(data)
        headers.append(struct.pack("<IIQQQQIIQQ", offsets[ordinal], kind, flags, 0,
                                   location, size, link, info, 1, stride))
    while len(image) % 8:
        image.append(0)
    section_offset = len(image)
    image.extend(b"".join(headers))
    image[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<HHIQQQIHHHHHH", image, 16, 1, 247, 1, 0, 0,
                     section_offset, 0, 64, 0, 0, 64, len(rows), name_index)
    return bytes(image)


def control(code=WIDE + EXIT, symbols=None, extra=None, relocations=None, tables=None):
    return elf([("xdp", 1, 6, code)] + (extra or []),
               tables=tables if tables is not None else [symbols or [("main", 0x12, 1, 0, len(code))]],
               relocations=relocations)


def catalog_image(image, *, symbol="main", section="xdp", producer="synthetic", changes=None):
    semantic = {"oracle_version": 1, "domain": "literal ELF accounting controls",
                "observable": "static slots, section sizes and direct-call graph"}
    case = {
        "case_id": "control.wide.synthetic.linux-bpfel-v3", "family": "accounting-control",
        "producer": producer, "route": "synthetic" if producer == "synthetic" else "reference",
        "profile": "linux-bpfel-v3", "entry": {"section": section, "symbol": symbol},
        "source_refs": ["tests/codegen_cost/test_collect.py"], "corpus_ref": None,
        "oracle_ref": "tests/codegen_cost/test_collect.py",
        "semantic_contract": semantic, "semantic_contract_sha256": sha(canonical_json(semantic)),
        "object_sha256": sha(image), "measurement_scope": "object", "required_metrics": list(MINIMUM),
        "status": "ready", "pending_reason": None, "prerequisites": [],
    }
    if changes:
        case.update(changes)
    return canonical_json({"schema_version": 1, "metrics": [
        {"name": name, "unit": unit} for name, unit in METRICS.items()], "cases": [case]})


def collect(image, **options):
    mod = collector()
    raw = catalog_image(image, **options)
    case = mod.load_cases(raw)["cases"][0]
    return mod.collect_object(image, case=case, provenance=None)


def values(report):
    return {metric["name"]: metric["value"] for metric in report["metrics"]}


def issue(report, code):
    assert not report["complete"]
    assert code in {entry["code"] for entry in report["issues"]}, report["issues"]


def test_wide_immediate_counts_two_slots():
    report = collect(control())
    assert report["complete"]
    assert values(report)["reachable_slots"] == 3
    assert values(report)["reachable_bytes"] == 24
    assert report["reachable"]["instruction_offsets"] == [[1, 0], [1, 8], [1, 16]]
    assert "target_fingerprint" not in report


def test_entry_reachability_deduplicates_shared_callee():
    image = control(bytes.fromhex("85 10 00 00 04 00 00 00 85 10 00 00 03 00 00 00") + EXIT +
                    bytes.fromhex("85 10 00 00 01 00 00 00") + EXIT + MOV + EXIT + MOV + EXIT,
                    symbols=[("A", 0x12, 1, 0, 24), ("B", 0x12, 1, 24, 16),
                             ("shared", 0x12, 1, 40, 16), ("unrelated", 0x12, 1, 56, 16)])
    first, second = collect(image, symbol="A"), collect(image, symbol="B")
    assert first["complete"] and second["complete"]
    assert values(first)["reachable_slots"] == 5
    assert values(second)["reachable_slots"] == 4
    assert values(first)["executable_bytes"] == 72
    assert values(first)["reachable_subprograms"] == 1
    assert values(first)["call_depth"] == 1
    assert first["reachable"]["instruction_offsets"] == [[1, 0], [1, 8], [1, 16], [1, 40], [1, 48]]


def test_jump_skips_unreachable_block():
    report = collect(control(bytes.fromhex("05 00 01 00 00 00 00 00") + MOV + EXIT))
    assert report["complete"]
    assert values(report)["reachable_slots"] == 2
    assert values(report)["executable_bytes"] == 24
    assert report["reachable"]["instruction_offsets"] == [[1, 0], [1, 16]]


@pytest.mark.parametrize("symbol_info,symbol_value,immediate", [(0x12, 24, -1), (0x03, 0, 2)])
def test_rel_call_resolves_function_and_section_symbols(symbol_info, symbol_value, immediate):
    caller = bytes.fromhex("05 00 01 00 00 00 00 00") + MOV + struct.pack("<BBhi", 0x85, 0x10, 0, immediate) + EXIT
    image = control(caller, extra=[(".text", 1, 6, MOV + EXIT + EXIT + MOV + EXIT)],
                    symbols=[("main", 0x12, 1, 0, 32), ("target", 0x12, 2, 24, 16),
                             ("reloc", symbol_info, 2, symbol_value, 16 if symbol_info == 0x12 else 0)],
                    relocations=[(".relxdp", 9, 1, 0, struct.pack("<QQ", 16, (3 << 32) | 10), 16)])
    report = collect(image)
    assert report["complete"]
    assert values(report)["reachable_slots"] == 5
    assert report["reachable"]["instruction_offsets"] == [[1, 0], [1, 16], [1, 24], [2, 24], [2, 32]]
    assert report["reachable"]["call_edges"][0]["target"] == [2, 24]


def test_symbol_table_ordinals_are_local():
    image = control(bytes.fromhex("85 10 00 00 ff ff ff ff") + EXIT,
                    extra=[(".text", 1, 6, MOV + EXIT + WIDE + EXIT)],
                    tables=[[("main", 0x12, 1, 0, 16), ("wrong", 0x12, 2, 0, 16)],
                            [("padding", 0x03, 2, 0, 0), ("right", 0x12, 2, 16, 24)]],
                    relocations=[(".relxdp", 9, 1, 1, struct.pack("<QQ", 0, (2 << 32) | 10), 16)])
    report = collect(image)
    assert report["complete"]
    assert values(report)["reachable_slots"] == 5
    assert report["reachable"]["call_edges"][0]["target"] == [2, 16]
    assert report["reachable"]["call_edges"][0]["symbol_ordinal"] == 2
    assert report["reachable"]["call_edges"][0]["symbol_table_index"] == 5


def test_section_costs_separate_metadata():
    image = control(extra=[(".BTF", 1, 0, b"B" * 12), (".BTF.ext", 1, 0, b"E" * 20),
                           (".debug_info", 1, 0, b"D" * 7), (".bss", 8, 3, 64)])
    report = collect(image)
    cost = values(report)
    assert report["complete"]
    assert (cost["executable_bytes"], cost["btf_bytes"], cost["btf_ext_bytes"], cost["debug_bytes"]) == (24, 12, 20, 7)
    assert report["sections"][5]["logical_bytes"] == 64
    assert report["sections"][5]["file_bytes"] == 0
    assert cost["elf_bytes"] == len(image)
    assert cost["non_section_bytes"] + cost["section_file_bytes"] == len(image)
    assert cost["section_logical_bytes"] == cost["section_file_bytes"] + 64
    assert values(collect(control()))["reachable_bytes"] == cost["reachable_bytes"] == 24


def test_absent_runtime_and_stack_are_unavailable():
    mod = collector()
    report = collect(control())
    for metric in report["metrics"]:
        if metric["name"] in {"compiler_stack_bytes", "verifier_stack_bytes", "duplicate_subprogram_bytes",
                              "decompressed_debug_bytes", "translated_bytes", "jit_bytes", "verifier_processed_instructions",
                              "verifier_states", "verifier_duration_ns", "load_duration_ns", "attach_duration_ns", "runtime_duration_ns"}:
            assert metric["value"] is None and metric["unavailable_reason"]
        else:
            assert metric["unavailable_reason"] is None
    assert report["complete"]
    damaged = copy.deepcopy(report)
    damaged["metrics"] = [m for m in damaged["metrics"] if m["name"] != "reachable_slots"]
    assert not mod.validate_report(damaged)["complete"]
    with pytest.raises(mod.CollectionError, match="required.*reachable_slots"):
        mod.load_cases(catalog_image(control(), changes={"required_metrics": [m for m in MINIMUM if m != "reachable_slots"]}))


def test_capture_binds_measured_bytes(tmp_path):
    mod = collector()
    path = tmp_path / "object.o"
    original = control()
    path.write_bytes(original)
    captured = path.read_bytes()
    path.write_bytes(control(MOV + EXIT))
    case = mod.load_cases(catalog_image(original))["cases"][0]
    report = mod.collect_object(captured, case=case, provenance=None)
    assert report["artifact"]["sha256"] == sha(original)
    assert values(report)["reachable_bytes"] == 24
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(path.read_bytes(), case=case, provenance=None)
    assert error.value.stage == "evidence" and error.value.exit_code == 4


@pytest.mark.parametrize("code", [WIDE[:8], WIDE[:8] + bytes.fromhex("01 00 00 00 00 00 00 00") + EXIT])
def test_malformed_wide_load_is_structural_failure(code):
    mod = collector()
    with pytest.raises(mod.CollectionError) as error:
        collect(control(code))
    assert error.value.stage == "object" and error.value.exit_code == 4


@pytest.mark.parametrize("code,code_name", [
    (bytes.fromhex("05 00 01 00 00 00 00 00") + WIDE + EXIT, "continuation-target"),
    (bytes.fromhex("05 00 08 00 00 00 00 00") + EXIT, "branch-outside-function"),
    (bytes.fromhex("85 20 00 00 01 00 00 00") + EXIT, "unsupported-call"),
    (bytes.fromhex("8d 00 00 00 00 00 00 00") + EXIT, "unsupported-call"),
])
def test_unsupported_reachable_control_flow_is_not_counted(code, code_name):
    report = collect(control(code))
    issue(report, code_name)
    assert values(report)["reachable_slots"] is None


@pytest.mark.parametrize("symbols,symbol,code_name", [
    ([("other", 0x12, 1, 0, 24)], "main", "missing-entry"),
    ([("main", 0x12, 1, 0, 0)], "main", "function-boundary"),
    ([("main", 0x12, 1, 0, 24), ("overlap", 0x12, 1, 16, 8)], "main", "function-overlap"),
    ([("main", 0x12, 1, 8, 16)], "main", "continuation-target"),
])
def test_unproved_function_extents_are_unavailable(symbols, symbol, code_name):
    issue(collect(control(symbols=symbols), symbol=symbol), code_name)


def test_exact_function_aliases_collapse():
    report = collect(control(symbols=[("main", 0x12, 1, 0, 24), ("alias", 0x12, 1, 0, 24)]))
    assert report["complete"] and report["reachable"]["functions"] == [[1, 0, 24]]


def test_cross_function_fallthrough_is_unavailable():
    issue(collect(control(MOV + EXIT, symbols=[("main", 0x12, 1, 0, 8), ("other", 0x12, 1, 8, 8)])), "cross-function-fallthrough")


def test_recursion_keeps_slots_but_depth_is_unavailable():
    report = collect(control(bytes.fromhex("85 10 00 00 ff ff ff ff") + EXIT))
    issue(report, "recursive-call")
    assert values(report)["reachable_slots"] == 2
    assert values(report)["call_depth"] is None


@pytest.mark.parametrize("field,value,code_name", [(58, 0, "elf-header"), (58, 32, "elf-header"),
                                                   (16, 2, "elf-header"), (18, 62, "elf-header")])
def test_invalid_elf_header_is_structural_failure(field, value, code_name):
    mod = collector()
    image = bytearray(control())
    struct.pack_into("<H", image, field, value)
    with pytest.raises(mod.CollectionError) as error:
        collect(bytes(image))
    assert error.value.code == code_name and error.value.exit_code == 4


@pytest.mark.parametrize("offset,value,stage", [(6, 0, "object"), (20, 0, "object"), (5, 2, "unsupported"), (4, 1, "unsupported")])
def test_version_and_encoding_rejection_is_explicit(offset, value, stage):
    mod = collector()
    image = bytearray(control())
    image[offset] = value
    with pytest.raises(mod.CollectionError) as error:
        collect(bytes(image))
    assert error.value.stage == stage
    assert error.value.exit_code == (3 if stage == "unsupported" else 4)


@pytest.mark.parametrize("site,ordinal,kind,stride,duplicate", [
    (1, 1, 10, 16, False), (24, 1, 10, 16, False), (0, 77, 10, 16, False),
    (0, 1, 10, 8, False), (0, 1, 10, 16, True),
])
def test_bad_relocation_records_are_structural_failure(site, ordinal, kind, stride, duplicate):
    mod = collector()
    raw = struct.pack("<QQ", site, (ordinal << 32) | kind)
    image = control(bytes.fromhex("85 10 00 00 ff ff ff ff") + EXIT,
                    relocations=[(".relxdp", 9, 1, 0, raw * (2 if duplicate else 1), stride)])
    with pytest.raises(mod.CollectionError) as error:
        collect(image)
    assert error.value.stage == "object" and error.value.exit_code == 4


def test_rela_and_unknown_control_relocations_are_unavailable():
    for kind, raw, stride in [(4, struct.pack("<QQq", 0, (1 << 32) | 10, 0), 24),
                              (9, struct.pack("<QQ", 0, (1 << 32) | 77), 16)]:
        report = collect(control(bytes.fromhex("85 10 00 00 ff ff ff ff") + EXIT,
                                 relocations=[(".relxdp", kind, 1, 0, raw, stride)]))
        issue(report, "unsupported-relocation")


def test_unresolved_call_symbol_is_unavailable():
    image = control(bytes.fromhex("85 10 00 00 ff ff ff ff") + EXIT,
                    symbols=[("main", 0x12, 1, 0, 16), ("unresolved", 0x12, 0, 0, 0)],
                    relocations=[(".relxdp", 9, 1, 0, struct.pack("<QQ", 0, (2 << 32) | 10), 16)])
    issue(collect(image), "unresolved-call")


def test_cfg_loops_terminate_and_conditional_successors_both_count():
    image = control(bytes.fromhex("15 00 01 00 00 00 00 00 05 00 fe ff 00 00 00 00") + EXIT)
    report = collect(image)
    assert report["complete"] and values(report)["reachable_slots"] == 3


def test_helper_calls_fallthrough_without_executable_roots():
    report = collect(control(bytes.fromhex("85 00 00 00 01 00 00 00") + EXIT))
    assert report["complete"] and values(report)["reachable_subprograms"] == 0
    assert values(report)["call_depth"] == 0


@pytest.mark.parametrize("change", [{"unexpected": 1}, {"schema_version": True}, {"schema_version": 2}])
def test_unknown_catalog_fields_and_versions_fail(change):
    mod = collector()
    data = json.loads(catalog_image(control()))
    data.update(change)
    with pytest.raises(mod.CollectionError) as error:
        mod.load_cases(canonical_json(data))
    assert error.value.exit_code == 2


def test_duplicate_metric_and_case_identities_fail():
    mod = collector()
    for key in ("metrics", "cases"):
        data = json.loads(catalog_image(control()))
        data[key].append(data[key][0])
        with pytest.raises(mod.CollectionError):
            mod.load_cases(canonical_json(data))


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), -1, 2.5])
def test_invalid_report_counts_fail(value):
    mod = collector()
    report = collect(control())
    report["metrics"][0]["value"] = value
    with pytest.raises(mod.CollectionError):
        mod.validate_report(report)


def synthetic_target():
    body = {
        "schema_version": 1,
        "kernel": {"source_commit": "a" * 40, "release": "synthetic-control", "build_id": "synthetic", "config_sha256": "b" * 64},
        "btf": {"vmlinux_sha256": "c" * 64, "modules": []},
        "image": {"digest": "sha256:" + "d" * 64, "packages": {}},
        "cpu": {"architecture": "x86-64", "model": "synthetic", "features": [], "page_size": 4096, "cpus": 1},
        "execution_mode": "tcg", "byte_order": "le", "instruction_profile": "v3",
        "jit": {"state": "disabled", "hardening": []},
        "boot": {"parameters": [], "lsms": [], "lockdown": "none"},
        "privileges": {"capabilities": [], "token": "none", "delegation": "synthetic", "rlimits": {}},
        "mounts": {"tracefs": "/synthetic/tracefs", "bpffs": "/synthetic/bpffs", "cgroup": "/synthetic/cgroup", "namespaces": []},
        "build_host": {"identity": "synthetic-test", "flags": []},
    }
    body["fingerprint"] = TargetManifest.fingerprint_of(body)
    return TargetManifest.from_dict(body)


def test_private_synthetic_conversion_preserves_cost_contract():
    mod = collector()
    report = collect(control())
    target = synthetic_target()
    records = mod._synthetic_cost_records_for_tests(report, target=target)
    by_name = {record.to_dict()["metric"]: record.to_dict() for record in records}
    assert by_name["reachable_slots"]["value"] == 3
    assert by_name["reachable_slots"]["target_fingerprint"] == target.fingerprint
    assert by_name["runtime_duration_ns"]["value"] is None
    assert by_name["runtime_duration_ns"]["unavailable_reason"]
    report["artifact"]["producer"] = "c"
    with pytest.raises(mod.CollectionError):
        mod._synthetic_cost_records_for_tests(report, target=target)


def cli_inputs(tmp_path):
    image = control()
    paths = {name: tmp_path / name for name in ("cases.json", "object.o", "provenance.json")}
    paths["cases.json"].write_bytes(catalog_image(image))
    paths["object.o"].write_bytes(image)
    paths["provenance.json"].write_text("null")
    output = tmp_path / "run"
    argv = ["object", "--cases", str(paths["cases.json"]), "--case", "control.wide.synthetic.linux-bpfel-v3",
            "--object", str(paths["object.o"]), "--provenance", str(paths["provenance.json"]), "--out", str(output)]
    return argv, paths, output


def test_cli_object_only_uses_fresh_output_and_never_launches_tools(tmp_path, monkeypatch):
    mod = collector()
    import subprocess
    def forbid(*args, **kwargs):
        raise AssertionError("collector must never launch a process")
    monkeypatch.setattr(subprocess, "Popen", forbid)
    argv, paths, output = cli_inputs(tmp_path)
    assert mod.main(argv) == 0
    report = json.loads((output / "report.json").read_bytes())
    assert report["complete"] and "target_fingerprint" not in report and "records" not in report
    assert (output / "object.o").read_bytes() == paths["object.o"].read_bytes()
    assert mod.main(argv) == 2


def test_actual_export_rejects_even_matching_target_binding(tmp_path):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    target = synthetic_target()
    target_path = tmp_path / "target.json"
    binding_path = tmp_path / "binding.json"
    target_path.write_bytes(canonical_json(target.to_dict()))
    binding_path.write_bytes(canonical_json({"target_fingerprint": target.fingerprint,
        "object_sha256": sha(paths["object.o"].read_bytes()), "case_id": "control.wide.synthetic.linux-bpfel-v3"}))
    assert mod.main(argv + ["--target", str(target_path), "--binding", str(binding_path), "--evidence-root", str(tmp_path)]) == 3
    attempt = json.loads((output / "attempt.json").read_bytes())
    assert not attempt["complete"]
    assert attempt["issues"][0]["code"] == "admission-validator-unavailable"
    assert not (output / "report.json").exists()


def test_pending_case_does_not_invent_fixture_or_complete_accounting(tmp_path):
    mod = collector()
    data = mod.load_cases(Path(__file__).with_name("cases.json").read_bytes())
    families = {case["family"] for case in data["cases"] if case["status"] == "pending"}
    assert {"classifier-counter", "array", "percpu", "hash", "core", "event-output", "event-reserve", "subprogram", "single-uprobe"} <= families
    for family in families:
        assert {case["producer"] for case in data["cases"] if case["family"] == family} >= {"c", "mojo", "rust"}
    pending = next(case for case in data["cases"] if case["status"] == "pending")
    assert pending["pending_reason"]
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(control(), case=pending, provenance=None)
    assert error.value.exit_code == 3


def test_report_profile_is_required_and_bound_to_captured_catalog(tmp_path):
    mod = collector()
    argv, _, output = cli_inputs(tmp_path)
    assert mod.main(argv) == 0
    report = json.loads((output / "report.json").read_bytes())
    missing = copy.deepcopy(report)
    del missing["profile"]
    with pytest.raises(mod.CollectionError):
        mod.validate_report(missing)
    wrong = copy.deepcopy(report)
    wrong["profile"] = "linux-bpfel-v4"
    with pytest.raises(mod.CollectionError) as error:
        mod.validate_report(wrong, evidence_root=output)
    assert error.value.stage == "evidence" and error.value.exit_code == 4


def test_provenance_profile_mismatch_is_identity_failure():
    mod = collector()
    image = control()
    case = mod.load_cases(catalog_image(image))["cases"][0]
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(image, case=case, provenance={"profile": "linux-bpfel-v4"})
    assert error.value.stage == "evidence" and error.value.exit_code == 4


def test_capture_preserves_raw_companion_bytes_and_rejects_replaced_evidence(tmp_path):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    raw = b'{\n  "profile" : "linux-bpfel-v3"\n}\n'
    paths["provenance.json"].write_bytes(raw)
    assert mod.main(argv) == 0
    report = json.loads((output / "report.json").read_bytes())
    assert (output / "provenance.json").read_bytes() == raw
    assert report["artifact"]["provenance_sha256"] == sha(raw)
    (output / "object.o").write_bytes(control(MOV + EXIT))
    with pytest.raises(mod.CollectionError) as error:
        mod.validate_report(report, evidence_root=output)
    assert error.value.stage == "evidence" and error.value.exit_code == 4


@pytest.mark.parametrize("field,bad", [("metrics", None), ("sections", 1), ("evidence", {}),
                                      ("issues", "wrong"), ("reachable", []), ("artifact", False)])
def test_malformed_report_containers_fail_structurally(field, bad):
    mod = collector()
    report = collect(control())
    report[field] = bad
    with pytest.raises(mod.CollectionError):
        mod.validate_report(report)


def test_report_duplicate_metrics_unknown_fields_and_nonfinite_timings_fail():
    mod = collector()
    for mutation in ("duplicate", "unknown", "timing"):
        report = collect(control())
        if mutation == "duplicate":
            report["metrics"].append(copy.deepcopy(report["metrics"][0]))
        elif mutation == "unknown":
            report["artifact"]["trusted"] = True
        else:
            item = next(metric for metric in report["metrics"] if metric["name"] == "runtime_duration_ns")
            item["value"], item["unavailable_reason"] = float("inf"), None
        with pytest.raises(mod.CollectionError):
            mod.validate_report(report)


def test_fixed_minima_survive_post_capture_case_tampering():
    mod = collector()
    image = control()
    case = mod.load_cases(catalog_image(image))["cases"][0]
    case["required_metrics"].remove("reachable_slots")
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(image, case=case, provenance=None)
    assert error.value.stage == "evidence"


def test_more_required_metrics_cannot_be_removed_to_manufacture_completeness(tmp_path):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    data = json.loads(paths["cases.json"].read_bytes())
    data["cases"][0]["required_metrics"].append("runtime_duration_ns")
    paths["cases.json"].write_bytes(canonical_json(data))
    assert mod.main(argv) == 3
    report = json.loads((output / "report.json").read_bytes())
    assert not report["complete"]
    report["complete"] = True
    report["metrics"] = [metric for metric in report["metrics"] if metric["name"] != "runtime_duration_ns"]
    assert not mod.validate_report(report, evidence_root=output)["complete"]


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a/../b", "a\\b", "a//b"])
def test_catalog_reference_paths_cannot_escape(path):
    mod = collector()
    with pytest.raises(mod.CollectionError):
        mod.load_cases(catalog_image(control(), changes={"source_refs": [path]}))


def test_report_evidence_symlinks_cannot_escape_root(tmp_path):
    mod = collector()
    argv, _, output = cli_inputs(tmp_path)
    assert mod.main(argv) == 0
    report = json.loads((output / "report.json").read_bytes())
    saved = tmp_path / "saved.o"
    saved.write_bytes((output / "object.o").read_bytes())
    (output / "object.o").unlink()
    (output / "object.o").symlink_to(saved)
    with pytest.raises(mod.CollectionError) as error:
        mod.validate_report(report, evidence_root=output)
    assert error.value.stage == "evidence" and error.value.exit_code == 4


def test_parser_limits_and_immutable_input_are_enforced(monkeypatch):
    mod = collector()
    image = control()
    with pytest.raises(mod.CollectionError):
        mod.load_cases(bytearray(catalog_image(image)))
    case = mod.load_cases(catalog_image(image))["cases"][0]
    with pytest.raises(mod.CollectionError):
        mod.collect_object(bytearray(image), case=case, provenance=None)
    monkeypatch.setattr(mod, "MAX_OBJECT_BYTES", len(image) - 1)
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(image, case=case, provenance=None)
    assert error.value.code == "input-limit" and error.value.exit_code == 3


def test_metadata_relocations_keep_their_own_category():
    image = control(extra=[(".BTF", 1, 0, b"B" * 12)],
                    relocations=[(".rel.BTF", 9, 2, 0, struct.pack("<QQ", 0, (1 << 32) | 4), 16)])
    report = collect(image)
    assert report["complete"]
    assert values(report)["relocation_bytes"] == 16
    assert values(report)["btf_bytes"] == 12
    assert values(report)["executable_bytes"] == 24


def test_map_relocation_does_not_add_executable_roots():
    image = control(bytes.fromhex("18 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00") + EXIT,
                    extra=[(".maps", 1, 3, b"\0" * 32), (".text", 1, 6, MOV + EXIT)],
                    symbols=[("main", 0x12, 1, 0, 24), ("map", 0x11, 2, 0, 32), ("unrelated", 0x12, 3, 0, 16)],
                    relocations=[(".relxdp", 9, 1, 0, struct.pack("<QQ", 0, (2 << 32) | 1), 16)])
    report = collect(image)
    assert report["complete"]
    assert values(report)["reachable_slots"] == 3
    assert values(report)["reachable_subprograms"] == 0
    assert values(report)["executable_bytes"] == 40


def test_unresolved_map_relocation_is_unavailable():
    image = control(bytes.fromhex("18 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00") + EXIT,
                    symbols=[("main", 0x12, 1, 0, 24), ("map", 0x11, 0, 0, 0)],
                    relocations=[(".relxdp", 9, 1, 0, struct.pack("<QQ", 0, (2 << 32) | 1), 16)])
    issue(collect(image), "unresolved-data-reference")


def test_real_producer_without_admitted_provenance_is_incomplete():
    report = collect(control(), producer="c")
    issue(report, "provenance-admission-unavailable")
    assert values(report)["reachable_bytes"] == 24


def test_cli_structural_failure_retains_attempt_and_captured_object(tmp_path):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    malformed = control(WIDE[:8])
    paths["object.o"].write_bytes(malformed)
    paths["cases.json"].write_bytes(catalog_image(malformed))
    assert mod.main(argv) == 4
    attempt = json.loads((output / "attempt.json").read_bytes())
    assert attempt["exit_code"] == 4 and not attempt["complete"]
    assert attempt["issues"][0]["stage"] == "object"
    assert (output / "object.o").read_bytes() == malformed
    assert not (output / "report.json").exists()


def test_section_payload_overlap_is_structural_failure():
    mod = collector()
    image = bytearray(control(extra=[(".BTF", 1, 0, b"B" * 12)]))
    section_offset = struct.unpack_from("<Q", image, 40)[0]
    code_offset = struct.unpack_from("<Q", image, section_offset + 64 + 24)[0]
    struct.pack_into("<Q", image, section_offset + 128 + 24, code_offset + 8)
    with pytest.raises(mod.CollectionError) as error:
        collect(bytes(image))
    assert error.value.code == "section-overlap"


def test_control_flow_relocation_into_wide_continuation_is_structural_failure():
    mod = collector()
    image = control(relocations=[(".relxdp", 9, 1, 0, struct.pack("<QQ", 8, (1 << 32) | 10), 16)])
    with pytest.raises(mod.CollectionError) as error:
        collect(image)
    assert error.value.code == "relocation-site"


def test_call_into_wide_continuation_is_unavailable():
    image = control(bytes.fromhex("85 10 00 00 01 00 00 00") + WIDE + EXIT)
    issue(collect(image), "continuation-target")


@pytest.mark.parametrize("helper", [12, 164, 170, 180, 181, 209])
def test_dynamic_call_and_callback_helpers_are_explicitly_unavailable(helper):
    issue(collect(control(struct.pack("<BBhi", 0x85, 0, 0, helper) + EXIT)), "unsupported-call")


def test_function_pointer_wide_load_is_explicitly_unavailable():
    image = control(bytes.fromhex("18 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00") + EXIT)
    issue(collect(image), "unsupported-code-reference")


def test_synthetic_formatter_rejects_different_target_profile():
    mod = collector()
    target = synthetic_target().to_dict()
    target["instruction_profile"] = "v4"
    target["fingerprint"] = TargetManifest.fingerprint_of(target)
    with pytest.raises(mod.CollectionError):
        mod._synthetic_cost_records_for_tests(collect(control()), target=TargetManifest.from_dict(target))


def test_report_hash_covers_all_fields_and_is_relocation_independent(tmp_path):
    mod = collector()
    argv, _, output = cli_inputs(tmp_path)
    assert mod.main(argv) == 0
    report = json.loads((output / "report.json").read_bytes())
    assert json.loads((output / "report-identity.json").read_bytes())["report_sha256"] == sha(canonical_json(report))
    report["issues"].append({"code": "new", "stage": "unavailable", "explanation": "new captured observation"})
    assert sha(canonical_json(report)) != json.loads((output / "report-identity.json").read_bytes())["report_sha256"]


@pytest.mark.parametrize("part,index", [("sections", 0), ("reachable", None)])
def test_report_nested_unknown_fields_fail(part, index):
    mod = collector()
    report = collect(control())
    selected = report[part] if index is None else report[part][index]
    selected["unknown"] = True
    with pytest.raises(mod.CollectionError):
        mod.validate_report(report)


def test_report_cannot_rebind_case_producer_route_entry_or_object(tmp_path):
    mod = collector()
    argv, _, output = cli_inputs(tmp_path)
    assert mod.main(argv) == 0
    original = json.loads((output / "report.json").read_bytes())
    for mutation in ("producer", "route", "entry", "object"):
        report = copy.deepcopy(original)
        if mutation == "producer":
            report["artifact"]["producer"] = "c"
        elif mutation == "route":
            report["artifact"]["route"] = "native"
        elif mutation == "entry":
            report["entry"]["symbol"] = "another"
        else:
            replacement = control(MOV + EXIT)
            (output / "object.o").write_bytes(replacement)
            report["artifact"]["sha256"] = sha(replacement)
            report["artifact"]["size_bytes"] = len(replacement)
            next(item for item in report["evidence"] if item["role"] == "object")["sha256"] = sha(replacement)
        with pytest.raises(mod.CollectionError) as error:
            mod.validate_report(report, evidence_root=output)
        assert error.value.stage == "evidence" and error.value.exit_code == 4


def test_publication_failure_never_leaves_a_report_and_keeps_an_attempt(tmp_path, monkeypatch):
    mod = collector()
    argv, _, output = cli_inputs(tmp_path)
    original_rename = Path.rename
    def fail_report(self, destination):
        if Path(destination).name == "report.json":
            raise OSError("controlled atomic-publication failure")
        return original_rename(self, destination)
    monkeypatch.setattr(Path, "rename", fail_report)
    assert mod.main(argv) == 4
    assert not (output / "report.json").exists()
    assert not list(output.glob("*.pending"))
    attempt = json.loads((output / "attempt.json").read_bytes())
    assert attempt["issues"][0]["code"] == "publication-failed" and not attempt["complete"]


@pytest.mark.parametrize("member,size", [("MAX_SECTIONS", 1), ("MAX_SYMBOLS", 1), ("MAX_SLOTS", 2), ("MAX_FUNCTIONS", 0)])
def test_each_structural_work_limit_stops_the_affected_accounting(member, size, monkeypatch):
    mod = collector()
    image = control()
    case = mod.load_cases(catalog_image(image))["cases"][0]
    monkeypatch.setattr(mod, member, size)
    if member == "MAX_FUNCTIONS":
        issue(mod.collect_object(image, case=case, provenance=None), "input-limit")
    else:
        with pytest.raises(mod.CollectionError) as error:
            mod.collect_object(image, case=case, provenance=None)
        assert error.value.code == "input-limit" and error.value.exit_code == 3


def test_catalog_semantic_digest_and_opaque_provenance_object_digest_are_checked():
    mod = collector()
    image = control()
    with pytest.raises(mod.CollectionError) as error:
        mod.load_cases(catalog_image(image, changes={"semantic_contract_sha256": "f" * 64}))
    assert error.value.stage == "evidence"
    case = mod.load_cases(catalog_image(image))["cases"][0]
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(image, case=case, provenance={"object_sha256": "f" * 64})
    assert error.value.stage == "evidence"


def test_json_decimal_overflow_cannot_enter_semantic_or_provenance_capture():
    mod = collector()
    raw = catalog_image(control())
    raw = raw.replace(b'"oracle_version":1', b'"oracle_version":1e999')
    with pytest.raises(mod.CollectionError) as error:
        mod.load_cases(raw)
    assert error.value.exit_code == 2


def test_finite_integer_timing_is_not_coerced_to_a_float():
    mod = collector()
    report = collect(control())
    metric = next(metric for metric in report["metrics"] if metric["name"] == "runtime_duration_ns")
    metric["value"], metric["unavailable_reason"] = 10 ** 400, None
    checked = mod.validate_report(report)
    assert next(metric for metric in checked["metrics"] if metric["name"] == "runtime_duration_ns")["value"] == 10 ** 400
