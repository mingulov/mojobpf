# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Independent literal ELF controls; no compiler, disassembler or loader."""

from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest

from mojobpf.validation.models import RunPlan, TargetManifest, canonical_json

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


def test_reserved_export_flags_require_complete_admission_groups(tmp_path):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    target = synthetic_target()
    target_path = tmp_path / "target.json"
    binding_path = tmp_path / "binding.json"
    target_path.write_bytes(canonical_json(target.to_dict()))
    binding_path.write_bytes(canonical_json({"target_fingerprint": target.fingerprint,
        "object_sha256": sha(paths["object.o"].read_bytes()), "case_id": "control.wide.synthetic.linux-bpfel-v3"}))
    assert mod.main(argv + ["--target", str(target_path), "--binding", str(binding_path), "--evidence-root", str(tmp_path)]) == 2
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
        mod.collect_object(image, case=case, provenance={"profile": case["profile"], "object_sha256": "f" * 64})
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


def observe_reads(monkeypatch, path):
    """Observe real I/O, including an accidental unbounded Path.read_bytes()."""
    reads = []
    original_open = Path.open
    observed_path = path.resolve()

    class ObservedStream:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            image = self.stream.read(size)
            reads.append({"requested_bytes": size, "returned_bytes": len(image)})
            return image

    def observed_open(self, mode="r", *args, **kwargs):
        stream = original_open(self, mode, *args, **kwargs)
        if mode == "rb" and self.resolve() == observed_path:
            return ObservedStream(stream)
        return stream

    monkeypatch.setattr(Path, "open", observed_open)
    return reads


@pytest.mark.parametrize("role", ["object", "catalog", "provenance"])
@pytest.mark.parametrize("matching_digest", [False, True])
def test_evidence_readback_is_bounded_before_hash_or_parse(role, matching_digest, tmp_path, monkeypatch):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    paths["provenance.json"].write_bytes(b'{"profile":"linux-bpfel-v3"}')
    assert mod.main(argv) == 0
    report = json.loads((output / "report.json").read_bytes())
    evidence = next(item for item in report["evidence"] if item["role"] == role)
    path = output / evidence["relative_path"]
    cap = 4096
    original = path.read_bytes()
    assert len(original) <= cap
    oversized = original + b" " * (cap + 17 - len(original))
    path.write_bytes(oversized)
    if matching_digest:
        evidence["sha256"] = sha(oversized)
        if role == "object":
            report["artifact"]["sha256"] = sha(oversized)
            report["artifact"]["size_bytes"] = len(oversized)
        elif role == "catalog":
            report["catalog_sha256"] = sha(oversized)
        else:
            report["artifact"]["provenance_sha256"] = sha(oversized)
    monkeypatch.setattr(mod, "MAX_OBJECT_BYTES" if role == "object" else "MAX_CATALOG_BYTES", cap)
    reads = observe_reads(monkeypatch, path)
    hashed_lengths = []
    original_sha = mod._sha

    def observed_sha(image):
        hashed_lengths.append(len(image))
        return original_sha(image)

    monkeypatch.setattr(mod, "_sha", observed_sha)
    failure = None
    try:
        mod.validate_report(report, evidence_root=output)
    except mod.CollectionError as exc:
        failure = exc
    (tmp_path / "read-observations.json").write_bytes(canonical_json({
        "role": role, "cap_bytes": cap, "input_bytes": len(oversized), "matching_digest": matching_digest,
        "reads": reads, "hashed_lengths": hashed_lengths, "failure_code": getattr(failure, "code", None),
    }))
    assert failure is not None, "oversized evidence was accepted"
    assert failure.code == "input-limit" and failure.exit_code == 3
    assert all(0 <= read["requested_bytes"] <= cap + 1 for read in reads)
    assert sum(read["returned_bytes"] for read in reads) <= cap + 1
    assert all(length <= cap for length in hashed_lengths), "oversized evidence was hashed before rejection"


@pytest.mark.parametrize("role,filename", [("catalog", "cases.json"), ("object", "object.o"),
                                         ("provenance", "provenance.json")])
def test_cli_capture_uses_the_same_bounded_input_reads(role, filename, tmp_path, monkeypatch):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    cap = 4096
    original = paths[filename].read_bytes()
    paths[filename].write_bytes(original + b" " * (cap + 17 - len(original)))
    monkeypatch.setattr(mod, "MAX_OBJECT_BYTES" if role == "object" else "MAX_CATALOG_BYTES", cap)
    reads = observe_reads(monkeypatch, paths[filename])
    assert mod.main(argv) == 3
    attempt = json.loads((output / "attempt.json").read_bytes())
    assert attempt["issues"][0]["code"] == "input-limit" and not attempt["complete"]
    assert not (output / "report.json").exists()
    assert all(0 <= read["requested_bytes"] <= cap + 1 for read in reads)
    assert sum(read["returned_bytes"] for read in reads) <= cap + 1
    (tmp_path / "read-observations.json").write_bytes(canonical_json({
        "role": role, "cap_bytes": cap, "input_bytes": cap + 17, "reads": reads, "exit_code": 3,
    }))


@pytest.mark.parametrize("provenance", [{}, {"object_sha256": sha(control())}])
def test_supplied_provenance_requires_profile_identity(provenance):
    mod = collector()
    image = control()
    case = mod.load_cases(catalog_image(image))["cases"][0]
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(image, case=case, provenance=provenance)
    assert error.value.code == "provenance-identity"
    assert error.value.stage == "evidence" and error.value.exit_code == 4


@pytest.mark.parametrize("provenance", [None, {"profile": "linux-bpfel-v3"}])
def test_synthetic_optional_provenance_and_matching_profile_are_allowed(provenance):
    mod = collector()
    image = control()
    case = mod.load_cases(catalog_image(image))["cases"][0]
    assert mod.collect_object(image, case=case, provenance=provenance)["complete"]


@pytest.mark.parametrize("provenance", [{}, {"object_sha256": sha(control())}, {"profile": "linux-bpfel-v4"}])
def test_cli_supplied_provenance_requires_matching_profile(provenance, tmp_path):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    raw = canonical_json(provenance)
    paths["provenance.json"].write_bytes(raw)
    assert mod.main(argv) == 4
    attempt = json.loads((output / "attempt.json").read_bytes())
    assert attempt["issues"][0]["code"] == "provenance-identity"
    assert attempt["issues"][0]["stage"] == "evidence" and not attempt["complete"]
    assert (output / "provenance.json").read_bytes() == raw
    assert not (output / "report.json").exists()


@pytest.mark.parametrize("bad", [None, {}, "", 0, False])
def test_report_call_edges_must_be_an_array(bad):
    mod = collector()
    report = collect(control())
    report["reachable"]["call_edges"] = bad
    with pytest.raises(mod.CollectionError) as error:
        mod.validate_report(report)
    assert error.value.code == "schema-shape"
    assert error.value.stage == "schema" and error.value.exit_code == 2


@pytest.mark.parametrize("bad", [None, {"not": "a string"}, [], 0, False])
def test_report_section_names_must_be_strings(bad):
    mod = collector()
    report = collect(control())
    report["sections"][1]["name"] = bad
    with pytest.raises(mod.CollectionError) as error:
        mod.validate_report(report)
    assert error.value.code == "schema-shape"
    assert error.value.stage == "schema" and error.value.exit_code == 2


def test_report_null_section_empty_name_and_empty_call_edges_are_allowed():
    mod = collector()
    report = collect(control())
    assert report["sections"][0]["name"] == ""
    assert report["reachable"]["call_edges"] == []
    assert mod.validate_report(report)["complete"]


def admitted_collector():
    mod = collector()
    assert hasattr(mod, "validate_producer_evidence"), "independently pinned producer admission is not implemented"
    return mod


def seal_fixture(fixture):
    """Seal test-owned payload data without changing any invocation authority."""
    entries = [{"id": ref, "relative_path": "inputs/" + ref, "role": role, "sha256": sha(image), "size": len(image)}
               for ref, (role, image) in fixture["files"].items()]
    fixture["blobs"] = {ref: image for ref, (_, image) in fixture["files"].items()}
    fixture["inventory_raw"] = canonical_json({"schema_version": 1, "kind": "cost-capture-inventory-v1", "entries": entries})
    provenance = fixture["provenance"]
    fixture["provenance_raw"] = canonical_json(provenance)
    fixture["admission_raw"] = canonical_json({
        "schema_version": 1, "kind": "cost-producer-admission-v1", "evidence_class": fixture["evidence_class"],
        "provenance_sha256": sha(fixture["provenance_raw"]), "inventory_sha256": sha(fixture["inventory_raw"]),
        "catalog_sha256": provenance["catalog_sha256"], "case_id": provenance["case_id"],
        "object_sha256": provenance["object_sha256"], "producer": provenance["producer"], "route": provenance["route"],
        "adapter_kind": provenance["adapter"]["kind"], "review_ref": "review", "scope": "object_provenance_only",
        "validator": {"name": "validate_producer_evidence_v1", "source_sha256": sha(COLLECT_PATH.read_bytes())},
    })
    return fixture


def producer_fixture(slots=3, *, case_id=None, source=b"synthetic algorithm input\n", code=None):
    image = control(MOV * (slots - 1) + EXIT if code is None else code)
    changes = {"case_id": case_id} if case_id else None
    catalog = catalog_image(image, changes=changes)
    case = json.loads(catalog)["cases"][0]
    provenance = {
        "schema_version": 1, "kind": "object-provenance-v1", "case_id": case["case_id"],
        "catalog_sha256": sha(catalog), "semantic_contract_sha256": case["semantic_contract_sha256"],
        "object_sha256": sha(image), "producer": "synthetic", "route": "synthetic", "profile": case["profile"],
        "source_repository": {"repository_id": "synthetic-controls", "commit": "1" * 40, "tree": "2" * 40,
                              "dirty_manifest_ref": None},
        "primary_source_ref": "source", "source_refs": ["source"], "import_refs": [], "sdk_refs": [],
        "manifest_ref": None, "corpus_ref": "corpus", "oracle_ref": "oracle", "profile_ref": "profile",
        "tool_capture_refs": [], "command_refs": [], "flags": ["-O2", "-O2"],
        "optimization": "O2", "debug_policy": "none", "link_policy": "unlinked", "llvm_lineage_refs": [],
        "inventory_ref": "captured-inputs", "adapter": {"kind": "synthetic-accounting-v1", "artifact_name": None,
            "output_names": [], "entry": case["entry"], "frontend_emit": None, "evidence_refs": {}},
    }
    return seal_fixture({"image": image, "catalog_raw": catalog, "provenance": provenance,
                         "evidence_class": "synthetic", "files": {
                             "source": ("source", source), "oracle": ("oracle", b"literal static slot oracle\n"),
                             "corpus": ("corpus", b"synthetic deterministic corpus\n"),
                             "profile": ("profile", canonical_json({"id": "linux-bpfel-v3", "byte_order": "le"})),
                             "object": ("object", image), "review": ("review", b"synthetic attribution control; no real admission\n"),
                         }})


def fixture_authority(candidate, baseline=None, reference=None, *, target=None, budget=None, evidence_class="synthetic"):
    # Test-owned invocation pins are selected before consumption, outside payloads.
    return admitted_collector().InvocationAuthority(
        contract_version=1, evidence_class=evidence_class, validator_source_sha256=sha(COLLECT_PATH.read_bytes()),
        producer_admission_sha256={"candidate": sha(candidate["admission_raw"]),
                                  "baseline": sha(baseline["admission_raw"]) if baseline else None,
                                  "reference": sha(reference["admission_raw"]) if reference else None},
        target_admission_sha256=sha(target) if target is not None else None,
        budget_approval_sha256=sha(budget) if budget is not None else None,
    )


def authority_snapshot(authority):
    return (authority.contract_version, authority.evidence_class, authority.validator_source_sha256,
            tuple(authority.producer_admission_sha256.items()), authority.target_admission_sha256,
            authority.budget_approval_sha256)


def bind_fixture(fixture, authority, role="candidate"):
    mod = admitted_collector()
    return mod.validate_producer_evidence(fixture["provenance_raw"], fixture["inventory_raw"], fixture["blobs"],
        fixture["admission_raw"], authority=authority, producer_role=role,
        case=mod.load_cases(fixture["catalog_raw"])["cases"][0], object_image=fixture["image"])


def captured_fixture(fixture, authority, role="candidate"):
    mod = admitted_collector()
    producer = bind_fixture(fixture, authority, role)
    report = mod.collect_object(fixture["image"], case=mod.load_cases(fixture["catalog_raw"])["cases"][0],
        provenance=fixture["provenance"], admission=producer, authority=authority, producer_role=role)
    return mod.prepare_captured_report(report, producer_binding=producer, authority=authority, producer_role=role)


def test_admitted_synthetic_producer_is_pinned_and_still_object_only():
    mod = admitted_collector()
    fixture = producer_fixture()
    authority = fixture_authority(fixture)
    snapshot = authority_snapshot(authority)
    captured = captured_fixture(fixture, authority)
    assert captured.to_dict()["complete"]
    assert values(captured.to_dict())["reachable_slots"] == 3
    assert values(captured.to_dict())["runtime_duration_ns"] is None
    assert captured.report_raw == canonical_json(captured.to_dict()) + b"\n"
    assert authority_snapshot(authority) == snapshot
    with pytest.raises(TypeError):
        authority.producer_admission_sha256["candidate"] = "f" * 64
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(fixture["image"], case=mod.load_cases(fixture["catalog_raw"])["cases"][0],
                           provenance=fixture["provenance"], admission=captured.producer_binding)
    assert error.value.exit_code == 3


@pytest.mark.parametrize("replacement", ["partial", "complete"])
def test_fixed_producer_authority_refuses_payload_substitution(replacement):
    mod = admitted_collector()
    original = producer_fixture()
    authority = fixture_authority(original)
    snapshot = authority_snapshot(authority)
    binding = bind_fixture(original, authority)
    changed = producer_fixture(4, source=b"replacement attribution; no independent admission\n")
    forged = replace(binding, provenance_raw=changed["provenance_raw"])
    if replacement == "complete":
        changed = adapter_fixture("reference-command-capture-v1", slots=4, source=b"replacement source/tool/route attribution\n")
        changed["provenance"]["source_repository"].update(commit="3" * 40, tree="4" * 40)
        seal_fixture(changed)
        forged = mod.ValidatedProducerProvenance(changed["provenance_raw"], changed["inventory_raw"], changed["admission_raw"],
            changed["blobs"], changed["catalog_raw"], changed["provenance"]["case_id"], changed["image"])
    with pytest.raises(mod.CollectionError) as error:
        mod.collect_object(changed["image"], case=mod.load_cases(changed["catalog_raw"])["cases"][0],
                           provenance=changed["provenance"], admission=forged, authority=authority)
    assert error.value.exit_code == 4
    assert authority_snapshot(authority) == snapshot


def test_admitted_provenance_cannot_remove_unavailable_required_metrics():
    mod = admitted_collector()
    fixture = producer_fixture(code=bytes.fromhex("85 20 00 00 00 00 00 00") + EXIT)
    captured = captured_fixture(fixture, fixture_authority(fixture))
    issue(captured.to_dict(), "unsupported-call")
    assert values(captured.to_dict())["reachable_slots"] is None


@pytest.mark.parametrize("change", ["inventory", "provenance", "class", "validator", "role", "backedge"])
def test_closed_producer_records_reject_mutation_or_missing_authority(change):
    mod = admitted_collector()
    fixture = producer_fixture()
    authority = fixture_authority(fixture)
    if change == "inventory":
        fixture["blobs"]["source"] += b"changed"
    elif change == "provenance":
        fixture["provenance_raw"] = fixture["provenance_raw"].replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
    elif change == "class":
        authority = replace(authority, evidence_class="real")
    elif change == "validator":
        authority = replace(authority, validator_source_sha256="f" * 64)
    elif change == "role":
        with pytest.raises(mod.CollectionError):
            bind_fixture(fixture, authority, "reference")
        return
    else:
        fixture["files"]["later"] = ("review", canonical_json({"schema_version": 1, "kind": "report-admission-v1"}))
        seal_fixture(fixture)
        authority = fixture_authority(fixture)
    with pytest.raises(mod.CollectionError):
        bind_fixture(fixture, authority)


def test_report_pair_preserves_actual_encoding_and_rejects_old_envelope():
    mod = admitted_collector()
    fixture = producer_fixture()
    authority = fixture_authority(fixture)
    captured = captured_fixture(fixture, authority)
    raw = json.dumps(captured.to_dict(), indent=2).encode() + b"\n"
    assert sha(raw) != sha(captured.report_raw)
    assert sha(canonical_json(json.loads(raw))) == sha(canonical_json(captured.to_dict()))
    with pytest.raises(mod.CollectionError) as error:
        mod.capture_report(raw, captured.report_admission_raw, producer_binding=captured.producer_binding,
                           authority=authority, producer_role="candidate")
    assert error.value.exit_code == 4
    envelope = json.loads(captured.report_admission_raw)
    envelope["report_raw_sha256"] = sha(raw)
    admission_raw = canonical_json(envelope) + b"\n"
    imported = mod.capture_report(raw, admission_raw, producer_binding=captured.producer_binding,
                                  authority=authority, producer_role="candidate")
    assert imported.report_raw == raw and imported.report_admission_raw == admission_raw
    assert imported.to_dict() == captured.to_dict()
    editable = imported.to_dict()
    editable["complete"] = False
    assert imported.to_dict()["complete"]


def test_report_pair_requires_explicit_bytes_and_reproduced_values():
    mod = admitted_collector()
    fixture = producer_fixture()
    authority = fixture_authority(fixture)
    captured = captured_fixture(fixture, authority)
    changed = captured.to_dict()
    next(metric for metric in changed["metrics"] if metric["name"] == "reachable_slots")["value"] = 999
    with pytest.raises(mod.CollectionError) as error:
        mod.prepare_captured_report(changed, producer_binding=captured.producer_binding, authority=authority, producer_role="candidate")
    assert error.value.exit_code == 4
    with pytest.raises((mod.CollectionError, TypeError)):
        mod.capture_report(captured.to_dict(), producer_binding=captured.producer_binding, authority=authority, producer_role="candidate")


def target_fixture(captured):
    target = synthetic_target()
    source = captured.producer_binding.blobs["source"]
    corpus = captured.producer_binding.blobs["corpus"]
    report = captured.to_dict()
    body = {"schema_version": 1, "contract_version": "test-contracts-v1", "plan_id": "control.cost.plan",
        "revisions": {"repository_commit": "1" * 40, "package": "synthetic", "tool": "synthetic"},
        "targets": [target.to_dict()], "cases": [{"case_id": report["case_id"], "fixture_id": "control.cost",
            "targets": [target.fingerprint], "expectation": "positive", "required": True,
            "consumers": [{"name": "synthetic", "version": "control", "artifact_sha256": sha(b"synthetic consumer")}],
            "source_sha256": sha(source), "object_sha256": report["artifact"]["sha256"], "corpus_sha256": sha(corpus),
            "expected_attempts": 1, "expected": {"outcome": "PASS", "failure_stage": None}}]}
    body["plan_hash"] = RunPlan.hash_of(body)
    plan = RunPlan.from_dict(body)
    target_raw, plan_raw = canonical_json(target.to_dict()), canonical_json(plan.to_dict())
    review = b"synthetic target association; execution NOT_RUN\n"
    inventory_raw = canonical_json({"schema_version": 1, "kind": "cost-capture-inventory-v1", "entries": [
        {"id": "review", "relative_path": "review.txt", "role": "review", "sha256": sha(review), "size": len(review)}]})
    binding = {"schema_version": 1, "kind": "cost-target-admission-v1", "evidence_class": "synthetic",
        "report_raw_sha256": sha(captured.report_raw), "report_canonical_sha256": sha(canonical_json(report)),
        "report_admission_sha256": sha(captured.report_admission_raw),
        "producer_admission_sha256": sha(captured.producer_binding.admission_raw), "case_id": report["case_id"],
        "catalog_sha256": report["catalog_sha256"], "semantic_contract_sha256": report["semantic_contract_sha256"],
        "object_sha256": report["artifact"]["sha256"], "source_sha256": sha(source), "corpus_sha256": sha(corpus),
        "profile": report["profile"], "flags": ["-O2", "-O2"], "target_raw_sha256": sha(target_raw),
        "target_fingerprint": target.fingerprint, "plan_raw_sha256": sha(plan_raw), "plan_hash": plan.plan_hash,
        "observation_inventory_sha256": sha(inventory_raw), "observation_refs": [], "review_ref": "review",
        "scope": "static_object_cost_association", "validator": {"name": "validate_cost_target_binding_v1",
        "source_sha256": sha(COLLECT_PATH.read_bytes())}}
    return {"binding_raw": canonical_json(binding), "target_raw": target_raw, "plan_raw": plan_raw,
            "inventory_raw": inventory_raw, "blobs": {"review": review}}


def bind_target(captured, target, authority):
    return admitted_collector().validate_target_binding(captured, target["binding_raw"], target["target_raw"],
        target["plan_raw"], target["inventory_raw"], target["blobs"], authority=authority)


def test_synthetic_target_export_roundtrips_frozen_cost_records_and_nulls():
    mod = admitted_collector()
    fixture = producer_fixture()
    captured = captured_fixture(fixture, fixture_authority(fixture))
    target = target_fixture(captured)
    authority = fixture_authority(fixture, target=target["binding_raw"])
    binding = bind_target(captured, target, authority)
    records = mod.export_cost_records(captured, binding=binding, authority=authority)
    rows = {row.to_dict()["metric"]: row.to_dict() for row in records}
    assert rows["reachable_slots"]["value"] == 3
    assert rows["reachable_slots"]["basis"]["flags"] == ["-O2", "-O2"]
    assert rows["runtime_duration_ns"]["value"] is None and rows["runtime_duration_ns"]["unavailable_reason"]
    assert rows["reachable_slots"]["target_fingerprint"] == synthetic_target().fingerprint


@pytest.mark.parametrize("change", ["complete-reseal", "report-encoding", "parsed-target", "mixed-carrier"])
def test_fixed_target_authority_and_exact_pair_refuse_substitution(change):
    mod = admitted_collector()
    fixture = producer_fixture()
    captured = captured_fixture(fixture, fixture_authority(fixture))
    target = target_fixture(captured)
    authority = fixture_authority(fixture, target=target["binding_raw"])
    snapshot = authority_snapshot(authority)
    binding = bind_target(captured, target, authority)
    if change == "parsed-target":
        altered = binding.target.to_dict()
        altered["cpu"]["cpus"] = 2
        altered["fingerprint"] = TargetManifest.fingerprint_of(altered)
        binding = replace(binding, target=TargetManifest.from_dict(altered))
    else:
        raw = json.dumps(captured.to_dict(), indent=2).encode()
        envelope = json.loads(captured.report_admission_raw)
        envelope["report_raw_sha256"] = sha(raw)
        replacement = mod.capture_report(raw, canonical_json(envelope), producer_binding=captured.producer_binding,
                                          authority=authority, producer_role="candidate")
        if change == "report-encoding":
            captured = replacement
        else:
            replaced_target = target_fixture(replacement)
            binding = mod.ValidatedTargetBinding(replacement, replaced_target["binding_raw"], replaced_target["target_raw"],
                replaced_target["plan_raw"], replaced_target["inventory_raw"], replaced_target["blobs"],
                synthetic_target(), RunPlan.from_dict(json.loads(replaced_target["plan_raw"])))
            if change == "complete-reseal":
                captured = replacement
    with pytest.raises(mod.CollectionError) as error:
        mod.export_cost_records(captured, binding=binding, authority=authority)
    assert error.value.exit_code == 4
    assert authority_snapshot(authority) == snapshot


def simple_budget(report, baseline, *, increase=2, ceiling=None, ratio=None, reference=None):
    return {"schema_version": 1, "budget_id": "control.object-slots", "case_id": report["case_id"],
        "semantic_contract_sha256": report["semantic_contract_sha256"], "profile": report["profile"],
        "metric": "reachable_slots", "unit": "slots", "baseline_report_sha256": sha(canonical_json(baseline)),
        "baseline_value": 10, "absolute_ceiling": ceiling, "max_increase": increase, "max_ratio": ratio,
        "reference_report_sha256": sha(canonical_json(reference)) if reference is not None else None,
        "rationale": "synthetic arithmetic example only", "owner": "synthetic-control",
        "approval_evidence_sha256": "0" * 64}


def test_budget_schema_is_closed_and_dict_only_assessment_is_unavailable():
    mod = admitted_collector()
    assert hasattr(mod, "assess_budget"), "independently approved object budget assessment is not implemented"
    candidate, baseline = collect(control(MOV * 11 + EXIT)), collect(control(MOV * 9 + EXIT))
    budget = simple_budget(candidate, baseline)
    schema_path = COLLECT_PATH.parents[2] / "schemas/size-budget.schema.json"
    assert schema_path.is_file(), "standalone budget schema is not implemented"
    schema = json.loads(schema_path.read_bytes())
    assert len(schema["required"]) == 16 and set(schema["properties"]) == set(budget)
    assert schema["additionalProperties"] is False
    assert mod.validate_budget(budget) == budget
    assessment = mod.assess_budget(candidate, baseline, budget)
    assert assessment["status"] == "UNAVAILABLE" and assessment["scope"] == "object_budget_only"
    assert assessment["identities"]["budget_raw_sha256"] is None


@pytest.mark.parametrize("field,bad", [("max_ratio", 0), ("max_increase", -1), ("baseline_value", True),
    ("max_increase", float("inf")), ("max_increase", float("nan")), ("schema_version", True), ("unit", "count")])
def test_budget_values_and_metric_units_fail_closed(field, bad):
    mod = admitted_collector()
    assert hasattr(mod, "validate_budget"), "closed budget validation is not implemented"
    budget = simple_budget(collect(control(MOV * 11 + EXIT)), collect(control(MOV * 9 + EXIT)))
    budget[field] = bad
    with pytest.raises(mod.CollectionError):
        mod.validate_budget(budget)


def synthetic_conditions(fixture):
    return {"producer": "synthetic", "route": "synthetic", "profile_definition_sha256": sha(fixture["blobs"]["profile"]),
            "tool_capture_digests": [], "flags": ["-O2", "-O2"], "optimization": "O2", "debug_policy": "none",
            "link_policy": "unlinked", "sdk_closure_sha256": None, "adapter_identity_sha256": None,
            "entry_policy_sha256": sha(canonical_json({"section": "xdp", "symbol": "main"}))}


def budget_fixture(*, increase=2, ceiling=None, ratio=None, candidate_slots=12, metric="reachable_slots", reference_fixture=None):
    mod = admitted_collector()
    assert hasattr(mod, "validate_budget_admission_v1"), "separately pinned budget approval is not implemented"
    candidate, baseline = producer_fixture(candidate_slots, source=b"synthetic candidate\n"), producer_fixture(10, source=b"synthetic baseline\n")
    reference = (reference_fixture or producer_fixture(8, case_id="control.reference.synthetic.linux-bpfel-v3")) if ratio is not None else None
    authority = fixture_authority(candidate, baseline, reference)
    reports = mod.ReportSet(captured_fixture(candidate, authority), captured_fixture(baseline, authority, "baseline"),
                            captured_fixture(reference, authority, "reference") if reference else None)
    report, base = reports.candidate.to_dict(), reports.baseline.to_dict()
    ref = reports.reference.to_dict() if reports.reference else None
    budget = simple_budget(report, base, increase=increase, ceiling=ceiling, ratio=ratio, reference=ref)
    if metric == "call_depth":
        budget.update(metric="call_depth", unit="count", baseline_value=0)
    policy = {"schema_version": 1, "kind": "cost-comparison-policy-v1", "evidence_class": "synthetic",
        "measurement_scope": "object", "case_id": report["case_id"], "semantic_contract_sha256": report["semantic_contract_sha256"],
        "profile": report["profile"], "metric": budget["metric"], "unit": budget["unit"], "target_context": None,
        "candidate_baseline_conditions": synthetic_conditions(candidate),
        "reference_conditions": synthetic_conditions(reference) if reference else None, "review_ref": "review"}
    if reference is not None and reference["provenance"]["producer"] == "c":
        policy["reference_conditions"].update(producer="c", route="reference", flags=["-target", "bpfel", "-mcpu=v3", "-O2", "-c"],
            tool_capture_digests=[sha(reference["blobs"]["tool-clang"])])
    policy_raw, review = canonical_json(policy), b"synthetic comparison review; no numeric product approval\n"
    inventory_raw = canonical_json({"schema_version": 1, "kind": "cost-capture-inventory-v1", "entries": [
        {"id": name, "relative_path": name + ".json", "role": role, "sha256": sha(raw), "size": len(raw)}
        for name, role, raw in (("policy", "comparison_policy", policy_raw), ("review", "review", review))]})
    approval = {"schema_version": 1, "kind": "cost-budget-approval-v1", "evidence_class": "synthetic",
        "budget_terms_sha256": sha(canonical_json({key: value for key, value in budget.items() if key != "approval_evidence_sha256"})),
        "baseline_report_sha256": sha(canonical_json(base)), "baseline_report_raw_sha256": sha(reports.baseline.report_raw),
        "baseline_report_admission_sha256": sha(reports.baseline.report_admission_raw),
        "baseline_producer_admission_sha256": sha(baseline["admission_raw"]),
        "reference_report_sha256": sha(canonical_json(ref)) if ref else None,
        "reference_report_raw_sha256": sha(reports.reference.report_raw) if ref else None,
        "reference_report_admission_sha256": sha(reports.reference.report_admission_raw) if ref else None,
        "reference_producer_admission_sha256": sha(reference["admission_raw"]) if ref else None,
        "comparison_policy_sha256": sha(policy_raw), "policy_inventory_sha256": sha(inventory_raw),
        "rationale": budget["rationale"], "owner": budget["owner"], "review_ref": "review", "scope": "object_budget_only",
        "validator": {"name": "validate_budget_admission_v1", "source_sha256": sha(COLLECT_PATH.read_bytes())}}
    approval_raw = canonical_json(approval)
    budget["approval_evidence_sha256"] = sha(approval_raw)
    authority = fixture_authority(candidate, baseline, reference, budget=approval_raw)
    admission = mod.validate_budget_admission_v1(budget, approval_raw, policy_raw, reports, inventory_raw,
                                                {"policy": policy_raw, "review": review}, authority=authority)
    return {"budget": budget, "reports": reports, "admission": admission, "authority": authority,
            "candidate": candidate, "baseline": baseline, "reference": reference}


def assess_fixture(fixture, **changes):
    reports = fixture["reports"]
    arguments = {"reference": reports.reference.to_dict() if reports.reference else None,
                 "reports": reports, "admission": fixture["admission"], "authority": fixture["authority"]}
    arguments.update(changes)
    return admitted_collector().assess_budget(reports.candidate.to_dict(), reports.baseline.to_dict(), fixture["budget"], **arguments)


@pytest.mark.parametrize("increase,ceiling,ratio,want", [(2, None, None, "PASS"), (1, None, None, "FAIL"),
    (2, None, 1.5, "PASS"), (2, 11, 1.5, "FAIL")])
def test_approved_budget_evaluates_every_exact_rule(increase, ceiling, ratio, want):
    fixture = budget_fixture(increase=increase, ceiling=ceiling, ratio=ratio)
    assessment = assess_fixture(fixture)
    assert assessment["status"] == want
    assert assessment["identities"]["budget_raw_sha256"] is None
    assert assessment["rules"][0]["actual"]["candidate"] == 12
    if ceiling is not None:
        assert [rule["status"] for rule in assessment["rules"]] == ["FAIL", "PASS", "PASS"]
    assert assessment["scope"] == "object_budget_only" and assessment["evidence_class"] == "synthetic"


@pytest.mark.parametrize("missing", ["reports", "admission", "authority"])
def test_budget_cannot_pass_without_explicit_carriers_authority_and_approval(missing):
    fixture = budget_fixture()
    assert assess_fixture(fixture, **{missing: None})["status"] == "UNAVAILABLE"


def test_budget_zero_reference_is_unavailable_and_decrease_is_signed():
    fixture = budget_fixture(ratio=1.5, metric="call_depth")
    assessment = assess_fixture(fixture)
    assert assessment["status"] == "UNAVAILABLE"
    assert assessment["rules"][-1]["status"] == "UNAVAILABLE"
    assert assessment["rules"][-1]["actual"]["reference"] == 0
    decrease = budget_fixture(candidate_slots=8, increase=0)
    result = assess_fixture(decrease)
    assert result["status"] == "PASS"
    assert result["rules"][0]["actual"] == {"candidate": 8, "baseline": 10, "reference": None}


def test_budget_large_finite_limits_do_not_overflow_into_a_pass():
    fixture = budget_fixture(increase=10 ** 400, ceiling=11, ratio=1e300)
    assessment = assess_fixture(fixture)
    assert assessment["status"] == "FAIL"
    assert [rule["status"] for rule in assessment["rules"]] == ["FAIL", "PASS", "PASS"]


@pytest.mark.parametrize("change", ["cached-metric", "positional-dict", "role-swap", "reference-nullness", "approval-reseal"])
def test_budget_fixed_context_refuses_reconstructed_caches_and_terms(change):
    mod = admitted_collector()
    fixture = budget_fixture(ratio=1.5)
    authority = fixture["authority"]
    snapshot = authority_snapshot(authority)
    reports = fixture["reports"]
    candidate, baseline, budget = reports.candidate.to_dict(), reports.baseline.to_dict(), copy.deepcopy(fixture["budget"])
    reference = reports.reference.to_dict()
    admission = fixture["admission"]
    if change in ("cached-metric", "positional-dict"):
        next(metric for metric in candidate["metrics"] if metric["name"] == "reachable_slots")["value"] = 13
        if change == "cached-metric":
            reports = replace(reports, candidate=replace(reports.candidate, report=candidate))
    elif change == "role-swap":
        reports = replace(reports, candidate=reports.baseline, baseline=reports.candidate)
    elif change == "reference-nullness":
        reference = None
    else:
        budget["max_increase"] = 100
        approval = json.loads(admission.approval_raw)
        approval["budget_terms_sha256"] = sha(canonical_json({key: value for key, value in budget.items() if key != "approval_evidence_sha256"}))
        raw = canonical_json(approval)
        budget["approval_evidence_sha256"] = sha(raw)
        admission = mod.ValidatedBudgetAdmission(raw, admission.policy_raw, admission.policy_inventory_raw,
                                                admission.policy_blobs, budget, reports)
    with pytest.raises(mod.CollectionError) as error:
        mod.assess_budget(candidate, baseline, budget, reference=reference, reports=reports, admission=admission, authority=authority)
    assert error.value.exit_code == 4
    assert authority_snapshot(authority) == snapshot


def test_budget_approved_baseline_raw_pair_cannot_be_reformatted():
    mod = admitted_collector()
    fixture = budget_fixture()
    original = fixture["reports"].baseline
    raw = json.dumps(original.to_dict(), indent=2).encode() + b"\n"
    envelope = json.loads(original.report_admission_raw)
    envelope["report_raw_sha256"] = sha(raw)
    replacement = mod.capture_report(raw, canonical_json(envelope), producer_binding=original.producer_binding,
                                    authority=fixture["authority"], producer_role="baseline")
    reports = replace(fixture["reports"], baseline=replacement)
    with pytest.raises(mod.CollectionError) as error:
        assess_fixture(fixture, reports=reports)
    assert error.value.exit_code == 4


def add_tool_capture(fixture, tool_id, role):
    origin_id, ref, dependency = "origin-" + tool_id, "tool-" + tool_id, "dependencies-" + tool_id
    executable, distribution = sha(("synthetic executable " + tool_id).encode()), sha(("synthetic distribution " + tool_id).encode())
    version = "synthetic " + ("Mojo 1.1.0" if tool_id == "mojo" else "clang 21" if tool_id == "clang" else tool_id + " 21")
    path = "/captured/bin/" + tool_id
    original = {"path": path, "exe": executable, "dist": distribution, "version": version, "llvm": "LLVM 21.1 synthetic"}
    record = {"schema_version": 1, "kind": "cost-tool-capture-v1", "tool_id": tool_id, "role": role,
        "executable_sha256": executable, "distribution_sha256": distribution, "version_text": version,
        "llvm_lineage": original["llvm"], "origin_location": "retained:synthetic-tool/" + tool_id,
        "dependency_manifest_ref": dependency, "origin_record_refs": [origin_id],
        "claim_map": [{"field": field, "origin_ref": origin_id, "json_pointer": "/" + key} for field, key in
                      (("executable_sha256", "exe"), ("distribution_sha256", "dist"), ("version_text", "version"), ("llvm_lineage", "llvm"))]}
    fixture["files"][origin_id] = ("tool_capture", canonical_json(original))
    fixture["files"][dependency] = ("dependency_manifest", canonical_json({"synthetic_dependency_sha256": sha(b"synthetic dependency"),
        "tool_version": "0.2.0", "sdk_version": "0.1", "compiler_records": []}))
    fixture["files"][ref] = ("tool_capture", canonical_json(record))
    fixture["provenance"]["tool_capture_refs"].append(ref)
    fixture["provenance"]["llvm_lineage_refs"].append(ref)
    return ref, path, executable


def capture_command(fixture, ref, argv, inputs, outputs):
    files = [{"phase": phase, "path": path, "sha256": sha(fixture["files"][name][1])}
             for phase in ("before", "after") for name, path in inputs]
    files.extend({"phase": "after", "path": path, "sha256": sha(fixture["files"][name][1])} for name, path in outputs)
    command = {"argv": argv, "exit_code": 0, "cwd": "/captured/project", "files": files,
               "environment": {"SYNTHETIC_CAPTURE": "true"}, "stdout": "", "stderr": ""}
    fixture["files"][ref] = ("command", canonical_json(command))
    fixture["provenance"]["command_refs"].append(ref)


def adapter_fixture(adapter, *, slots=3, source=b"synthetic algorithm input\n", case_id=None):
    fixture = producer_fixture(slots, source=source, case_id=case_id)
    producer, route = ("c", "reference") if adapter == "reference-command-capture-v1" else ("mojo", "legacy" if adapter == "driver-evidence-v4" else "parsed")
    catalog = json.loads(fixture["catalog_raw"])
    catalog["cases"][0].update(producer=producer, route=route)
    fixture["catalog_raw"] = canonical_json(catalog)
    provenance = fixture["provenance"]
    provenance.update(producer=producer, route=route, catalog_sha256=sha(fixture["catalog_raw"]))
    provenance["adapter"]["kind"] = adapter
    compiler_ref, compiler_path, executable = add_tool_capture(fixture, "clang" if producer == "c" else "mojo", "producer")
    if producer == "c":
        provenance["flags"] = ["-target", "bpfel", "-mcpu=v3", "-O2", "-c"]
        argv = [compiler_path, *provenance["flags"], "/captured/project/source.c", "-o", "/captured/work/object.o"]
        capture_command(fixture, "compile", argv, [("source", "/captured/project/source.c")], [("object", "/captured/work/object.o")])
        provenance["adapter"]["evidence_refs"] = {"compile_command": "compile", "primary_source": "source", "object": "object"}
    else:
        fixture["files"]["sdk"] = ("sdk", b"synthetic captured SDK input\n")
        provenance["sdk_refs"] = ["sdk"]
        if adapter == "driver-evidence-v4":
            license_name = "Apache-2.0 WITH LLVM-exception"
            fixture["image"] = control(MOV * (slots - 1) + EXIT, extra=[("license", 1, 0, license_name.encode() + b"\0")])
            fixture["files"]["object"] = ("object", fixture["image"])
            provenance["object_sha256"] = sha(fixture["image"])
            catalog["cases"][0]["object_sha256"] = sha(fixture["image"])
            fixture["catalog_raw"] = canonical_json(catalog)
            provenance["catalog_sha256"] = sha(fixture["catalog_raw"])
            manifest = canonical_json({"artifact": {"source_license": license_name, "kernel_license": license_name}})
            fixture["files"]["manifest"] = ("manifest", manifest)
            fixture["files"]["adapter-source"] = ("adapter_source", b"synthetic captured legacy adapter\n")
            provenance["manifest_ref"] = "manifest"
            _, backend_path, _ = add_tool_capture(fixture, "llc", "backend")
            capture_command(fixture, "compile", [compiler_path, "build", "-O2", "source", "-o", "ir"],
                            [("source", "source"), ("sdk", "sdk")], [])
            capture_command(fixture, "backend", [backend_path, "-O2", "ir", "-o", "control.bpf.o"], [], [("object", "control.bpf.o")])
            hashed = lambda ref: {"path": ref, "sha256": sha(fixture["files"][ref][1]), "size": len(fixture["files"][ref][1])}
            tools = [json.loads(fixture["files"][ref][1]) for ref in provenance["tool_capture_refs"]]
            sidecar = {"schema_version": 4, "artifact": "control", "profile_id": "linux-bpfel-v3", "success": True,
                "inputs": {"source": [hashed("source")], "imports": [], "sdk": [hashed("sdk")], "manifest": hashed("manifest"),
                    "compiler": [tool["tool_id"] + " " + tool["version_text"] + " " + tool["executable_sha256"] for tool in tools],
                    "flags": provenance["flags"], "profile_id": "linux-bpfel-v3", "profile_sha256": sha(fixture["files"]["profile"][1]),
                    "adapter": ["adapter-source " + sha(fixture["files"]["adapter-source"][1])], "tool_version": "0.2.0", "sdk_version": "0.1"},
                "outputs": [{"path": "control.bpf.o", "sha256": sha(fixture["image"]), "size": len(fixture["image"])}],
                "transforms": ["synthetic legacy capture"], "source_license": license_name, "kernel_license": license_name,
                "license_mapping_version": 1, "tool_version": "0.2.0", "sdk_version": "0.1", "commands": [], "environment": []}
            fixture["files"]["sidecar"] = ("driver_evidence", canonical_json(sidecar))
            provenance["adapter"].update(artifact_name="control", output_names=["control.bpf.o"],
                                         evidence_refs={"sidecar": "sidecar", "published_outputs": {"control.bpf.o": "object"}})
        else:
            _, lower_path, _ = add_tool_capture(fixture, "lower", "lowerer")
            _, backend_path, _ = add_tool_capture(fixture, "llc", "backend")
            fixture["files"]["adapter-source"] = ("adapter_source", b"synthetic captured parsed lowerer source\n")
            fixture["files"]["frontend"] = ("frontend_ir", b"synthetic frontend IR capture\n")
            fixture["files"]["lowered"] = ("lowered_ir", b"synthetic backend IR capture\n")
            capture = {"source": "source.mojo", "source_sha256": sha(fixture["files"]["source"][1]),
                "sdk_import_closure": {"sdk": sha(fixture["files"]["sdk"][1])}, "producer_sha256": executable,
                "emit": "llvm", "producer_optimization": "default (no explicit optimization option)"}
            fixture["files"]["source-capture"] = ("source_capture", canonical_json(capture))
            spec = {"schema_version": 1, "model_id": "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1", "profile_id": "linux-bpfel-v3",
                "entry": "main", "program_type": "xdp", "section": "xdp", "kernel_license": "Apache-2.0 WITH LLVM-exception", "map": None}
            fixture["image"] = control(MOV * (slots - 1) + EXIT, extra=[("license", 1, 0, spec["kernel_license"].encode() + b"\0")])
            fixture["files"]["object"] = ("object", fixture["image"])
            provenance["object_sha256"] = sha(fixture["image"])
            catalog["cases"][0]["object_sha256"] = sha(fixture["image"])
            fixture["catalog_raw"] = canonical_json(catalog)
            provenance["catalog_sha256"] = sha(fixture["catalog_raw"])
            fixture["files"]["spec"] = ("lower_spec", canonical_json(spec))
            report = {"schema_version": 1, "model_id": spec["model_id"], "ok": True, "mode": "lower", "runtime_qualified": False,
                "input_digest": sha(fixture["files"]["frontend"][1]), "spec_digest": sha(fixture["files"]["spec"][1]),
                "output_digest": sha(fixture["files"]["lowered"][1]), "diagnostics": [],
                "proof_obligations": [{"id": "producer_reader", "status": "reader-verified", "runtime_qualified": False},
                    *[{"id": name, "status": "admitted-semantic-subset", "runtime_qualified": False} for name in
                      ("integer_semantics", "endian_pointer_index", "gep_alignment", "struct_entry_abi", "attributes",
                       "pointer_provenance", "scratch_contracts", "calls_runtime", "debug_metadata")],
                    {"id": "target_transition", "status": "lowered-verified-host-only", "runtime_qualified": False}],
                "target_facts": {"entry_abi": {"symbol": "main"}, "target_triple": "bpfel-unknown-none", "target_cpu": "v3", "little_endian": True},
                "transformations": [{"kind": "target", "triple": "bpfel-unknown-none", "cpu": "v3", "section": "xdp"}]}
            fixture["files"]["lower-report"] = ("lower_report", canonical_json(report))
            provenance["adapter"].update(frontend_emit="llvm", evidence_refs={"source_capture": "source-capture", "frontend_command": "frontend-command",
                "frontend_ir": "frontend", "lower_command": "lower-command", "lower_report": "lower-report", "lower_spec": "spec",
                "lowered_ir": "lowered", "backend_command": "backend-command", "object": "object"})
            capture_command(fixture, "frontend-command", [compiler_path, "build", "--emit", "llvm", "-I", "/captured/sdk", "-o", "/captured/work/frontend.ll", "/captured/project/source.mojo"],
                            [("source", "/captured/project/source.mojo"), ("sdk", "sdk")], [("frontend", "/captured/work/frontend.ll")])
            capture_command(fixture, "lower-command", [lower_path, "--mode", "lower", "--input", "/captured/work/frontend.ll", "--spec", "/captured/work/spec.json",
                "--report", "/captured/work/lower.report.json", "--output", "/captured/work/lowered.ll", "--emit", "llvm"],
                [("frontend", "/captured/work/frontend.ll"), ("spec", "/captured/work/spec.json")], [("lower-report", "/captured/work/lower.report.json"), ("lowered", "/captured/work/lowered.ll")])
            capture_command(fixture, "backend-command", [backend_path, "-mtriple=bpfel", "-mcpu=v3", "-O2", "-filetype=obj", "/captured/work/lowered.ll", "-o", "/captured/work/object.o"],
                            [("lowered", "/captured/work/lowered.ll")], [("object", "/captured/work/object.o")])
            provenance["flags"] = ["-mtriple=bpfel", "-mcpu=v3", "-O2", "-filetype=obj"]
    return seal_fixture(fixture)


@pytest.mark.parametrize("adapter", ["driver-evidence-v4", "parsed-native-capture-v1", "reference-command-capture-v1"])
def test_strict_producer_adapters_validate_retained_synthetic_chains(adapter):
    fixture = adapter_fixture(adapter)
    captured = captured_fixture(fixture, fixture_authority(fixture))
    assert captured.to_dict()["complete"] and values(captured.to_dict())["reachable_slots"] == 3
    assert captured.to_dict()["artifact"]["producer"] == fixture["provenance"]["producer"]
    assert captured.to_dict()["artifact"]["route"] == fixture["provenance"]["route"]


@pytest.mark.parametrize("change", ["source", "sdk", "compiler", "flags", "adapter", "profile", "outputs", "version", "license"])
def test_v4_adapter_refuses_each_detached_capture_class(change):
    mod = admitted_collector()
    fixture = adapter_fixture("driver-evidence-v4")
    sidecar = json.loads(fixture["files"]["sidecar"][1])
    if change in ("source", "sdk"):
        sidecar["inputs"][change][0]["sha256"] = "f" * 64
    elif change == "compiler":
        sidecar["inputs"]["compiler"][0] = "unrecorded replacement compiler"
    elif change == "flags":
        sidecar["inputs"]["flags"] = ["-O3"]
    elif change == "adapter":
        sidecar["inputs"]["adapter"] = ["changed " + "f" * 64]
    elif change == "profile":
        sidecar["inputs"]["profile_sha256"] = "f" * 64
    elif change == "outputs":
        fixture["provenance"]["adapter"]["evidence_refs"]["published_outputs"] = {}
    elif change == "version":
        sidecar["schema_version"] = 5
    else:
        sidecar["kernel_license"] = "GPL"
    fixture["files"]["sidecar"] = ("driver_evidence", canonical_json(sidecar))
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.code != "adapter-unavailable"


@pytest.mark.parametrize("change", ["source-capture", "frontend", "spec", "lowered", "report", "backend", "tool", "route", "pressure", "before-after", "command-order"])
def test_native_adapter_rejects_each_discontinuous_phase(change):
    mod = admitted_collector()
    fixture = adapter_fixture("parsed-native-capture-v1")
    if change in ("frontend", "lowered"):
        role, image = fixture["files"][change]
        fixture["files"][change] = (role, image + b"changed")
    elif change == "source-capture":
        record = json.loads(fixture["files"]["source-capture"][1])
        record["source_sha256"] = "f" * 64
        fixture["files"]["source-capture"] = ("source_capture", canonical_json(record))
    elif change == "spec":
        record = json.loads(fixture["files"]["spec"][1])
        record["entry"] = "another"
        fixture["files"]["spec"] = ("lower_spec", canonical_json(record))
    elif change == "report":
        record = json.loads(fixture["files"]["lower-report"][1])
        record["runtime_qualified"] = True
        fixture["files"]["lower-report"] = ("lower_report", canonical_json(record))
    elif change in ("backend", "before-after"):
        record = json.loads(fixture["files"]["backend-command"][1])
        if change == "backend":
            record["argv"][2] = "-mcpu=v4"
        else:
            record["files"][1]["sha256"] = "f" * 64
        fixture["files"]["backend-command"] = ("command", canonical_json(record))
    elif change == "tool":
        record = json.loads(fixture["files"]["tool-mojo"][1])
        record["claim_map"][0]["json_pointer"] = "/dist"
        fixture["files"]["tool-mojo"] = ("tool_capture", canonical_json(record))
    elif change == "route":
        fixture["provenance"]["route"] = "legacy"
        catalog = json.loads(fixture["catalog_raw"])
        catalog["cases"][0]["route"] = "legacy"
        fixture["catalog_raw"] = canonical_json(catalog)
        fixture["provenance"]["catalog_sha256"] = sha(fixture["catalog_raw"])
    elif change == "pressure":
        record = json.loads(fixture["files"]["source-capture"][1])
        record["source"] = "/captured/work/frontend.ll"
        fixture["files"]["source-capture"] = ("source_capture", canonical_json(record))
    else:
        fixture["provenance"]["command_refs"].reverse()
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.code != "adapter-unavailable"


def admitted_cli_inputs(tmp_path, fixture=None):
    fixture = fixture or producer_fixture()
    argv, paths, output = cli_inputs(tmp_path)
    paths["cases.json"].write_bytes(fixture["catalog_raw"])
    paths["object.o"].write_bytes(fixture["image"])
    paths["provenance.json"].write_bytes(fixture["provenance_raw"])
    argv[argv.index("--case") + 1] = fixture["provenance"]["case_id"]
    root = tmp_path / "evidence"
    root.mkdir()
    for entry in json.loads(fixture["inventory_raw"])["entries"]:
        path = root / entry["relative_path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture["blobs"][entry["id"]])
    inventory, admission = tmp_path / "inventory.json", tmp_path / "admission.json"
    inventory.write_bytes(fixture["inventory_raw"])
    admission.write_bytes(fixture["admission_raw"])
    argv.extend(["--producer-admission", str(admission), "--capture-inventory", str(inventory), "--evidence-root", str(root),
                 "--expected-producer-admission-sha256", sha(fixture["admission_raw"]),
                 "--expected-validator-sha256", sha(COLLECT_PATH.read_bytes()), "--evidence-class", "synthetic"])
    return argv, paths, output, fixture, root


def test_cli_admitted_pair_and_synthetic_export_publish_actual_exact_buffers(tmp_path):
    mod = admitted_collector()
    argv, _, output, fixture, _ = admitted_cli_inputs(tmp_path)
    captured = captured_fixture(fixture, fixture_authority(fixture))
    target = target_fixture(captured)
    observation = tmp_path / "observation"
    observation.mkdir()
    (observation / "review.txt").write_bytes(target["blobs"]["review"])
    for flag, key in (("target", "target_raw"), ("binding", "binding_raw"), ("plan", "plan_raw"), ("observation-inventory", "inventory_raw")):
        path = tmp_path / (flag + ".json")
        path.write_bytes(target[key])
        argv.extend(["--" + flag, str(path)])
    argv.extend(["--target-evidence-root", str(observation), "--expected-binding-sha256", sha(target["binding_raw"])])
    assert mod.main(argv) == 0
    assert (output / "report.json").read_bytes() == captured.report_raw
    assert (output / "report-admission.json").read_bytes() == captured.report_admission_raw
    status = json.loads((output / "export-status.json").read_bytes())
    assert status["outcome"] == "NOT_RUN" and status["scope"] == "static_object_cost_association"
    assert status["evidence_class"] == "synthetic"
    assert status["report_raw_sha256"] == sha(captured.report_raw)
    assert status["cost_records_raw_sha256"] == sha((output / "cost-records.json").read_bytes())
    rows = json.loads((output / "cost-records.json").read_bytes())
    assert next(row for row in rows if row["metric"] == "reachable_slots")["value"] == 3
    assert next(row for row in rows if row["metric"] == "runtime_duration_ns")["value"] is None


@pytest.mark.parametrize("failure", ["changed-LF", "second-file-failure"])
def test_cli_pair_publication_failure_retains_attempt_and_prevents_export(failure, tmp_path, monkeypatch):
    mod = admitted_collector()
    argv, _, output, _, _ = admitted_cli_inputs(tmp_path)
    original = Path.rename

    def controlled_rename(self, destination):
        path = Path(destination)
        if path.name == "report-admission.json" and failure == "second-file-failure":
            raise OSError("controlled second publication failure")
        result = original(self, destination)
        if path.name == "report.json" and failure == "changed-LF":
            path.write_bytes(path.read_bytes().rstrip(b"\n"))
        return result

    monkeypatch.setattr(Path, "rename", controlled_rename)
    assert mod.main(argv) == 4
    attempt = json.loads((output / "attempt.json").read_bytes())
    assert attempt["exit_code"] == 4 and not attempt["complete"]
    assert not (output / "cost-records.json").exists() and not (output / "export-status.json").exists()


@pytest.mark.parametrize("symlink", ["file", "ancestor"])
def test_cli_capture_refuses_symlink_files_and_ancestors(symlink, tmp_path):
    mod = collector()
    argv, paths, output = cli_inputs(tmp_path)
    if symlink == "file":
        saved = tmp_path / "saved.o"
        paths["object.o"].rename(saved)
        paths["object.o"].symlink_to(saved)
    else:
        link = tmp_path / "alias"
        link.symlink_to(tmp_path, target_is_directory=True)
        argv[argv.index("--object") + 1] = str(link / "object.o")
    assert mod.main(argv) == 4
    assert json.loads((output / "attempt.json").read_bytes())["exit_code"] == 4


def test_cli_capture_refuses_hardlink_inventory_aliases(tmp_path):
    import os
    mod = admitted_collector()
    fixture = producer_fixture()
    fixture["files"]["extra-review"] = ("review", fixture["files"]["review"][1])
    seal_fixture(fixture)
    argv, _, output, _, root = admitted_cli_inputs(tmp_path, fixture)
    (root / "inputs/extra-review").unlink()
    os.link(root / "inputs/review", root / "inputs/extra-review")
    assert mod.main(argv) == 4
    assert json.loads((output / "attempt.json").read_bytes())["issues"][0]["code"] == "capture-alias"


def test_cli_capture_reads_each_input_once_and_uses_captured_bytes(tmp_path, monkeypatch):
    mod = admitted_collector()
    argv, paths, output, fixture, root = admitted_cli_inputs(tmp_path)
    # The explicit object and its inventory reference intentionally share one path.
    argv[argv.index("--object") + 1] = str(root / "inputs/object")
    read = mod._read
    calls = []

    def mutate_after_capture(path, *, limit, **kwargs):
        image = read(path, limit=limit, **kwargs)
        calls.append(str(path))
        if Path(path) == root / "inputs/object":
            Path(path).write_bytes(b"replaced after immutable capture")
        return image

    monkeypatch.setattr(mod, "_read", mutate_after_capture)
    assert mod.main(argv) == 0
    assert calls.count(str(root / "inputs/object")) == 1
    assert (output / "object.o").read_bytes() == fixture["image"]


@pytest.mark.parametrize("change", ["role-container", "entries-cap", "unique-bytes-cap", "record-depth", "record-values"])
def test_capture_work_limits_and_nested_shapes_fail_structurally(change, monkeypatch):
    mod = admitted_collector()
    fixture = producer_fixture()
    if change == "role-container":
        inventory = json.loads(fixture["inventory_raw"])
        inventory["entries"][0]["role"] = {}
        fixture["inventory_raw"] = canonical_json(inventory)
        admission = json.loads(fixture["admission_raw"])
        admission["inventory_sha256"] = sha(fixture["inventory_raw"])
        fixture["admission_raw"] = canonical_json(admission)
    elif change == "entries-cap":
        monkeypatch.setattr(mod, "MAX_CAPTURE_ENTRIES", 1)
    elif change == "unique-bytes-cap":
        monkeypatch.setattr(mod, "MAX_CAPTURE_BYTES", 1)
    else:
        monkeypatch.setattr(mod, "MAX_JSON_DEPTH" if change == "record-depth" else "MAX_JSON_VALUES", 1)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == (2 if change == "role-container" else 3)


def test_relocated_cli_capture_preserves_both_raw_report_identities(tmp_path):
    mod = admitted_collector()
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    fixture = producer_fixture()
    argv1, _, out1, _, _ = admitted_cli_inputs(first, fixture)
    argv2, _, out2, _, _ = admitted_cli_inputs(second, fixture)
    assert mod.main(argv1) == mod.main(argv2) == 0
    assert (out1 / "report.json").read_bytes() == (out2 / "report.json").read_bytes()
    assert (out1 / "report-admission.json").read_bytes() == (out2 / "report-admission.json").read_bytes()


def test_budget_missing_required_carrier_is_unavailable():
    fixture = budget_fixture()
    reports = replace(fixture["reports"], candidate=None)
    assert assess_fixture(fixture, reports=reports)["status"] == "UNAVAILABLE"


def fabricated_pair(fixture):
    """Reconstruct every data/cache field without obtaining replacement authority."""
    mod = admitted_collector()
    case = mod.load_cases(fixture["catalog_raw"])["cases"][0]
    report = mod.collect_object(fixture["image"], case=case, provenance=fixture["provenance"])
    # A plain real producer inspection differs only by its required admission issue.
    report["issues"] = [issue for issue in report["issues"] if issue["code"] != "provenance-admission-unavailable"]
    report["complete"] = not report["issues"]
    raw = canonical_json(report) + b"\n"
    binding = mod.ValidatedProducerProvenance(fixture["provenance_raw"], fixture["inventory_raw"], fixture["admission_raw"],
        fixture["blobs"], fixture["catalog_raw"], fixture["provenance"]["case_id"], fixture["image"])
    envelope = {"schema_version": 1, "kind": "report-admission-v1", "evidence_class": fixture["evidence_class"],
        "report_raw_sha256": sha(raw), "report_canonical_sha256": sha(canonical_json(report)),
        "producer_admission_sha256": sha(fixture["admission_raw"]), "provenance_sha256": sha(fixture["provenance_raw"]),
        "inventory_sha256": sha(fixture["inventory_raw"]), "catalog_sha256": sha(fixture["catalog_raw"]),
        "case_id": report["case_id"], "object_sha256": sha(fixture["image"])}
    return mod.CapturedReport(raw, canonical_json(envelope) + b"\n", report, binding)


def test_budget_complete_candidate_source_tool_route_reseal_fails_original_context():
    mod = admitted_collector()
    fixture = budget_fixture()
    snapshot = authority_snapshot(fixture["authority"])
    replacement = adapter_fixture("reference-command-capture-v1", slots=13, source=b"replacement synthetic C attribution\n")
    replacement["provenance"]["source_repository"].update(commit="3" * 40, tree="4" * 40)
    seal_fixture(replacement)
    forged = fabricated_pair(replacement)
    reports = replace(fixture["reports"], candidate=forged)
    with pytest.raises(mod.CollectionError) as error:
        mod.assess_budget(forged.to_dict(), reports.baseline.to_dict(), fixture["budget"],
                         reports=reports, admission=fixture["admission"], authority=fixture["authority"])
    assert error.value.exit_code == 4
    assert authority_snapshot(fixture["authority"]) == snapshot


def test_native_capture_resolves_relative_sdk_paths_in_historical_cwd():
    fixture = adapter_fixture("parsed-native-capture-v1")
    record = json.loads(fixture["files"]["frontend-command"][1])
    for file in record["files"]:
        if file["path"] == "sdk":
            file["path"] = "/captured/project/sdk"
    fixture["files"]["frontend-command"] = ("command", canonical_json(record))
    seal_fixture(fixture)
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_json_deep_records_are_bounded_across_encodings(encoding):
    mod = admitted_collector()
    raw = ("[" * 20000 + "0" + "]" * 20000).encode(encoding)
    with pytest.raises(mod.CollectionError) as error:
        mod._json(raw, "deep captured record")
    assert error.value.code == "input-limit" and error.value.exit_code == 3
    # Brackets and escaped quotes inside strings do not increase nesting.
    text = "[" * 2000 + '\\"}' * 2000
    assert mod._json(json.dumps({"text": text}).encode(encoding), "quoted capture") == {"text": text}


@pytest.mark.parametrize("scope, payload", [("policy", "budget"), ("producer", "policy"), ("observation", "policy")])
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_inventories_refuse_hidden_dependent_records(scope, payload, encoding):
    mod = admitted_collector()
    fixture = budget_fixture()
    raw = canonical_json(fixture["budget"]) if payload == "budget" else fixture["admission"].policy_raw
    raw = raw.decode().encode(encoding)
    inventory = canonical_json({"schema_version": 1, "kind": "cost-capture-inventory-v1", "entries": [
        {"id": "hidden", "relative_path": "review.json", "sha256": sha(raw), "size": len(raw), "role": "review"}]})
    with pytest.raises(mod.CollectionError) as error:
        mod._inventory(inventory, {"hidden": raw}, scope=scope)
    assert error.value.code == "inventory-backedge" and error.value.exit_code == 4


@pytest.mark.parametrize("change", ["proof-string", "proof-runtime", "proof-bool", "proof-missing", "proof-duplicate", "transition", "transformation-string", "transformation-target", "endian-bool", "import-closure"])
def test_native_adapter_rejects_nested_or_incomplete_proof_evidence(change):
    mod = admitted_collector()
    fixture = adapter_fixture("parsed-native-capture-v1")
    record = json.loads(fixture["files"]["lower-report"][1])
    if change == "proof-string":
        record["proof_obligations"] = ["claimed proof"]
    elif change in ("proof-runtime", "proof-bool"):
        record["proof_obligations"][0]["runtime_qualified"] = True if change == "proof-runtime" else 0
    elif change == "proof-missing":
        record["proof_obligations"] = record["proof_obligations"][:1]
    elif change == "proof-duplicate":
        record["proof_obligations"].append(copy.deepcopy(record["proof_obligations"][0]))
    elif change == "transition":
        record["proof_obligations"][-1]["status"] = "not-performed"
    elif change == "transformation-string":
        record["transformations"] = ["claimed target transform"]
    elif change == "transformation-target":
        record["transformations"][0]["cpu"] = "v2"
    elif change == "endian-bool":
        record["target_facts"]["little_endian"] = 1
    else:
        fixture["files"]["import"] = ("import", b"uncaptured native import phase\n")
        fixture["provenance"]["import_refs"] = ["import"]
    fixture["files"]["lower-report"] = ("lower_report", canonical_json(record))
    # Reseal every affected command-output digest, isolating the nested check.
    command = json.loads(fixture["files"]["lower-command"][1])
    for file in command["files"]:
        if file["path"] == "/captured/work/lower.report.json":
            file["sha256"] = sha(fixture["files"]["lower-report"][1])
    fixture["files"]["lower-command"] = ("command", canonical_json(command))
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code in (2, 3, 4)


def test_complete_target_plan_observation_reseal_cannot_replace_invocation_authority():
    mod = admitted_collector()
    fixture = producer_fixture()
    original = captured_fixture(fixture, fixture_authority(fixture))
    target = target_fixture(original)
    authority = fixture_authority(fixture, target=target["binding_raw"])
    snapshot = authority_snapshot(authority)
    original_binding = bind_target(original, target, authority)
    raw = json.dumps(original.to_dict(), indent=2).encode()
    envelope = json.loads(original.report_admission_raw)
    envelope["report_raw_sha256"] = sha(raw)
    replacement = mod.capture_report(raw, canonical_json(envelope), producer_binding=original.producer_binding,
                                     authority=authority, producer_role="candidate")
    changed = target_fixture(replacement)
    target_body = json.loads(changed["target_raw"])
    target_body["cpu"]["cpus"] = 2
    target_body["kernel"]["release"] = "replacement-synthetic-control"
    target_body["fingerprint"] = TargetManifest.fingerprint_of(target_body)
    target_model = TargetManifest.from_dict(target_body)
    changed["target_raw"] = canonical_json(target_model.to_dict())
    plan_body = json.loads(changed["plan_raw"])
    plan_body["targets"] = [target_model.to_dict()]
    plan_body["cases"][0]["targets"] = [target_model.fingerprint]
    plan_body["revisions"]["repository_commit"] = "3" * 40
    plan_body["plan_hash"] = RunPlan.hash_of(plan_body)
    plan_model = RunPlan.from_dict(plan_body)
    changed["plan_raw"] = canonical_json(plan_model.to_dict())
    changed["blobs"] = {"review": b"replacement synthetic observation review\n"}
    inventory = json.loads(changed["inventory_raw"])
    inventory["entries"][0].update(sha256=sha(changed["blobs"]["review"]), size=len(changed["blobs"]["review"]))
    changed["inventory_raw"] = canonical_json(inventory)
    binding = json.loads(changed["binding_raw"])
    binding.update(target_raw_sha256=sha(changed["target_raw"]), target_fingerprint=target_model.fingerprint,
        plan_raw_sha256=sha(changed["plan_raw"]), plan_hash=plan_model.plan_hash,
        observation_inventory_sha256=sha(changed["inventory_raw"]))
    changed["binding_raw"] = canonical_json(binding)
    forged = mod.ValidatedTargetBinding(replacement, changed["binding_raw"], changed["target_raw"], changed["plan_raw"],
        changed["inventory_raw"], changed["blobs"], target_model, plan_model)
    for supplied, selected in ((replacement, forged), (original, forged), (replacement, original_binding)):
        with pytest.raises(mod.CollectionError) as error:
            mod.export_cost_records(supplied, binding=selected, authority=authority)
        assert error.value.exit_code == 4
    assert authority_snapshot(authority) == snapshot


def reconstructed_budget(fixture, *, reports=None, policy=None, budget=None, extra=None):
    """Rebuild hostile payload caches without selecting replacement authority."""
    mod = admitted_collector()
    original = fixture["admission"]
    reports = reports or fixture["reports"]
    budget = copy.deepcopy(budget or fixture["budget"])
    policy = copy.deepcopy(policy or json.loads(original.policy_raw))
    policy_raw = canonical_json(policy)
    blobs = dict(original.policy_blobs)
    blobs["policy"] = policy_raw
    inventory = json.loads(original.policy_inventory_raw)
    for entry in inventory["entries"]:
        entry.update(sha256=sha(blobs[entry["id"]]), size=len(blobs[entry["id"]]))
    if extra:
        blobs["dependent"] = extra
        inventory["entries"].append({"id": "dependent", "relative_path": "dependent.json", "role": "review", "sha256": sha(extra), "size": len(extra)})
    inventory_raw = canonical_json(inventory)
    approval = json.loads(original.approval_raw)
    budget["baseline_report_sha256"] = sha(canonical_json(reports.baseline.to_dict()))
    budget["baseline_value"] = next(row["value"] for row in reports.baseline.to_dict()["metrics"] if row["name"] == budget["metric"])
    budget["reference_report_sha256"] = sha(canonical_json(reports.reference.to_dict())) if reports.reference else None
    for role in ("baseline", "reference"):
        carrier = getattr(reports, role)
        approval.update({role + "_report_sha256": sha(canonical_json(carrier.to_dict())) if carrier else None,
            role + "_report_raw_sha256": sha(carrier.report_raw) if carrier else None,
            role + "_report_admission_sha256": sha(carrier.report_admission_raw) if carrier else None,
            role + "_producer_admission_sha256": sha(carrier.producer_binding.admission_raw) if carrier else None})
    approval.update(budget_terms_sha256=sha(canonical_json({key: value for key, value in budget.items() if key != "approval_evidence_sha256"})),
                    comparison_policy_sha256=sha(policy_raw), policy_inventory_sha256=sha(inventory_raw))
    raw = canonical_json(approval)
    budget["approval_evidence_sha256"] = sha(raw)
    return mod.ValidatedBudgetAdmission(raw, policy_raw, inventory_raw, blobs, budget, reports), budget


@pytest.mark.parametrize("change", ["baseline", "reference", "policy", "raw-baseline"])
def test_complete_approved_budget_replacements_fail_original_invocation(change):
    mod = admitted_collector()
    fixture = budget_fixture(ratio=1.5)
    authority = fixture["authority"]
    snapshot = authority_snapshot(authority)
    reports = fixture["reports"]
    policy = json.loads(fixture["admission"].policy_raw)
    if change == "policy":
        policy["candidate_baseline_conditions"]["debug_policy"] = "replacement-debug-policy"
    elif change == "raw-baseline":
        carrier = reports.baseline
        raw = json.dumps(carrier.to_dict(), indent=2).encode()
        envelope = json.loads(carrier.report_admission_raw)
        envelope["report_raw_sha256"] = sha(raw)
        rebuilt = mod.capture_report(raw, canonical_json(envelope), producer_binding=carrier.producer_binding,
                                     authority=authority, producer_role="baseline")
        reports = replace(reports, baseline=rebuilt)
    else:
        replacement = producer_fixture(9, case_id=fixture[change]["provenance"]["case_id"], source=b"replacement fully sealed source\n")
        replacement["provenance"]["source_repository"].update(commit="5" * 40, tree="6" * 40)
        seal_fixture(replacement)
        reports = replace(reports, **{change: fabricated_pair(replacement)})
    admission, budget = reconstructed_budget(fixture, reports=reports, policy=policy)
    assert admission.approval_raw != fixture["admission"].approval_raw
    with pytest.raises(mod.CollectionError) as error:
        mod.assess_budget(reports.candidate.to_dict(), reports.baseline.to_dict(), budget,
            reference=reports.reference.to_dict(), reports=reports, admission=admission, authority=authority)
    assert error.value.exit_code == 4
    assert authority_snapshot(authority) == snapshot


def test_budget_allows_reviewed_different_case_cross_producer_reference():
    reference = adapter_fixture("reference-command-capture-v1", slots=8, case_id="control.reference.c.linux-bpfel-v3")
    fixture = budget_fixture(ratio=1.5, reference_fixture=reference)
    assert fixture["reports"].candidate.to_dict()["case_id"] != fixture["reports"].reference.to_dict()["case_id"]
    assert reference["provenance"]["llvm_lineage_refs"] == ["tool-clang"]
    result = assess_fixture(fixture)
    assert result["status"] == "PASS"
    assert next(row for row in result["rules"] if row["rule"] == "max_ratio")["actual"]["reference"] == 8


@pytest.mark.parametrize("change", ["baseline-case", "producer-policy", "semantic", "policy-flags"])
def test_budget_rejects_wrong_case_producer_semantic_and_policy(change):
    mod = admitted_collector()
    fixture = budget_fixture(ratio=1.5)
    policy = json.loads(fixture["admission"].policy_raw)
    budget = copy.deepcopy(fixture["budget"])
    if change == "baseline-case":
        budget["case_id"] = "control.wrong-case"
        policy["case_id"] = budget["case_id"]
    elif change == "semantic":
        budget["semantic_contract_sha256"] = "a" * 64
        policy["semantic_contract_sha256"] = budget["semantic_contract_sha256"]
    elif change == "policy-flags":
        policy["candidate_baseline_conditions"]["flags"].reverse()
        policy["candidate_baseline_conditions"]["flags"].append("-g")
    else:
        policy["candidate_baseline_conditions"]["producer"] = "c"
    admission, budget = reconstructed_budget(fixture, policy=policy, budget=budget)
    # Separate initially selected malformed approval isolates its cross-joins.
    authority = fixture_authority(fixture["candidate"], fixture["baseline"], fixture["reference"], budget=admission.approval_raw)
    with pytest.raises(mod.CollectionError) as error:
        mod.validate_budget_admission_v1(budget, admission.approval_raw, admission.policy_raw, fixture["reports"],
                                        admission.policy_inventory_raw, admission.policy_blobs, authority=authority)
    assert error.value.exit_code == 4


@pytest.mark.parametrize("change", ["report-raw", "admission-raw", "stale-envelope", "dict", "cached-set"])
def test_qualifying_carrier_requires_explicit_well_formed_actual_pair(change):
    mod = admitted_collector()
    fixture = producer_fixture()
    authority = fixture_authority(fixture)
    captured = captured_fixture(fixture, authority)
    if change == "dict":
        selected = captured.to_dict()
    elif change == "report-raw":
        selected = replace(captured, report_raw=None)
    elif change == "admission-raw":
        selected = replace(captured, report_admission_raw=None)
    elif change == "stale-envelope":
        other = fabricated_pair(producer_fixture(4))
        selected = replace(captured, report_admission_raw=other.report_admission_raw)
    else:
        report = captured.to_dict()
        report["metrics"][0]["value"] = {1, 2}
        selected = replace(captured, report=report)
    with pytest.raises(mod.CollectionError) as error:
        mod._revalidate_report(selected, authority, "candidate")
    assert error.value.exit_code in (2, 4)


def test_report_companion_validation_refuses_symlink_ancestor(tmp_path):
    mod = admitted_collector()
    fixture = producer_fixture()
    report = captured_fixture(fixture, fixture_authority(fixture)).to_dict()
    real = tmp_path / "real"
    real.mkdir()
    (real / "object.o").write_bytes(fixture["image"])
    (real / "cases.json").write_bytes(fixture["catalog_raw"])
    (real / "provenance.json").write_bytes(fixture["provenance_raw"])
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(mod.CollectionError) as error:
        mod.validate_report(report, evidence_root=linked)
    assert error.value.exit_code == 4


@pytest.mark.parametrize("role", ["corpus", "oracle"])
def test_budget_reference_requires_same_workload_and_oracle_capture(role):
    mod = admitted_collector()
    reference = adapter_fixture("reference-command-capture-v1", slots=8, case_id="control.reference.c.linux-bpfel-v3")
    reference["files"][role] = (role, b"unrelated comparison input\n")
    seal_fixture(reference)
    with pytest.raises(mod.CollectionError) as error:
        budget_fixture(ratio=1.5, reference_fixture=reference)
    assert error.value.exit_code == 4


def test_ratio_assessment_with_missing_reference_carrier_is_unavailable():
    fixture = budget_fixture(ratio=1.5)
    reports = replace(fixture["reports"], reference=None)
    assert assess_fixture(fixture, reports=reports, reference=None)["status"] == "UNAVAILABLE"


@pytest.mark.parametrize("change", ["profile", "flags", "source", "corpus", "object", "catalog", "semantic", "case", "plan", "target"])
def test_target_association_checks_every_cross_binding(change):
    mod = admitted_collector()
    fixture = producer_fixture()
    captured = captured_fixture(fixture, fixture_authority(fixture))
    target = target_fixture(captured)
    binding = json.loads(target["binding_raw"])
    if change in ("profile", "case"):
        binding["profile" if change == "profile" else "case_id"] += ".changed"
    elif change == "flags":
        binding["flags"] = ["-O2"]
    else:
        key = {"source": "source_sha256", "corpus": "corpus_sha256", "object": "object_sha256", "catalog": "catalog_sha256",
               "semantic": "semantic_contract_sha256", "plan": "plan_hash", "target": "target_fingerprint"}[change]
        binding[key] = "e" * 64
    target["binding_raw"] = canonical_json(binding)
    authority = fixture_authority(fixture, target=target["binding_raw"])
    with pytest.raises(mod.CollectionError) as error:
        bind_target(captured, target, authority)
    assert error.value.exit_code == 4


@pytest.mark.parametrize("change", ["partial-producer", "partial-target", "producer-pin", "validator-pin"])
def test_cli_admission_group_usage_and_pin_shapes_refuse_before_capture(change, tmp_path, capsys):
    mod = admitted_collector()
    argv, _, output, _, _ = admitted_cli_inputs(tmp_path)
    if change == "partial-producer":
        i = argv.index("--capture-inventory")
        del argv[i:i + 2]
    elif change == "partial-target":
        argv.extend(["--target", "unused-target.json"])
    else:
        flag = "--expected-producer-admission-sha256" if change == "producer-pin" else "--expected-validator-sha256"
        argv[argv.index(flag) + 1] = "malformed"
    assert mod.main(argv) == 2
    assert not output.exists()
    record = json.loads(capsys.readouterr().err)
    assert record["complete"] is False and record["exit_code"] == 2


def test_cli_target_identity_refusal_retains_exact_pair_without_export(tmp_path):
    mod = admitted_collector()
    argv, _, output, fixture, _ = admitted_cli_inputs(tmp_path)
    captured = captured_fixture(fixture, fixture_authority(fixture))
    target = target_fixture(captured)
    original_pin = sha(target["binding_raw"])
    binding = json.loads(target["binding_raw"])
    binding["target_fingerprint"] = "e" * 64
    target["binding_raw"] = canonical_json(binding)
    observation = tmp_path / "observation"
    observation.mkdir()
    (observation / "review.txt").write_bytes(target["blobs"]["review"])
    for flag, key in (("target", "target_raw"), ("binding", "binding_raw"), ("plan", "plan_raw"), ("observation-inventory", "inventory_raw")):
        path = tmp_path / (flag + ".json")
        path.write_bytes(target[key])
        argv.extend(["--" + flag, str(path)])
    argv.extend(["--target-evidence-root", str(observation), "--expected-binding-sha256", original_pin])
    assert mod.main(argv) == 4
    assert (output / "report.json").read_bytes() == captured.report_raw
    assert (output / "report-admission.json").read_bytes() == captured.report_admission_raw
    assert json.loads((output / "attempt.json").read_bytes())["exit_code"] == 4
    assert not (output / "cost-records.json").exists() and not (output / "export-status.json").exists()


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_capture_rejects_non_regular_files_without_blocking(kind, tmp_path):
    mod = admitted_collector()
    path = tmp_path / kind
    if kind == "directory":
        path.mkdir()
    else:
        mod.os.mkfifo(path)
    with pytest.raises(mod.CollectionError) as error:
        mod._read(path, limit=100)
    assert error.value.code == "capture-file-kind" and error.value.exit_code == 4


def test_unserializable_large_integer_budget_is_a_structured_refusal():
    mod = admitted_collector()
    report = collect(control())
    budget = simple_budget(report, report)
    budget["absolute_ceiling"] = 10 ** 10000
    with pytest.raises(mod.CollectionError) as error:
        mod.assess_budget(report, report, budget)
    assert error.value.exit_code == 3 and error.value.code == "input-limit"


@pytest.mark.parametrize("adapter, ref, basename", [("parsed-native-capture-v1", "frontend-command", "source.mojo"),
                                                   ("reference-command-capture-v1", "compile", "source.c")])
def test_original_source_argv_can_be_relative_to_retained_command_cwd(adapter, ref, basename):
    fixture = adapter_fixture(adapter)
    command = json.loads(fixture["files"][ref][1])
    command["argv"][command["argv"].index("/captured/project/" + basename)] = basename
    fixture["files"][ref] = ("command", canonical_json(command))
    seal_fixture(fixture)
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


@pytest.mark.parametrize("change", ["map", "program"])
def test_native_selected_request_cannot_claim_unsupported_contract(change):
    mod = admitted_collector()
    fixture = adapter_fixture("parsed-native-capture-v1")
    spec = json.loads(fixture["files"]["spec"][1])
    if change == "map":
        spec["map"] = {"symbol": "mojobpf_map0", "type": 2, "key_bits": 32, "value_bits": 64, "max_entries": 2, "flags": 0}
    else:
        spec["program_type"] = "socket"
    fixture["files"]["spec"] = ("lower_spec", canonical_json(spec))
    report = json.loads(fixture["files"]["lower-report"][1])
    report["spec_digest"] = sha(fixture["files"]["spec"][1])
    fixture["files"]["lower-report"] = ("lower_report", canonical_json(report))
    command = json.loads(fixture["files"]["lower-command"][1])
    for file in command["files"]:
        if file["path"].endswith("/spec.json"):
            file["sha256"] = sha(fixture["files"]["spec"][1])
        elif file["path"].endswith("/lower.report.json"):
            file["sha256"] = sha(fixture["files"]["lower-report"][1])
    fixture["files"]["lower-command"] = ("command", canonical_json(command))
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 4


def test_imported_report_complete_flag_cannot_be_normalized_before_identity():
    mod = admitted_collector()
    fixture = producer_fixture(code=bytes.fromhex("85 20 00 00 00 00 00 00") + EXIT)
    authority = fixture_authority(fixture)
    before = authority_snapshot(authority)
    original = captured_fixture(fixture, authority)
    submitted = original.to_dict()
    submitted["complete"] = True
    raw = canonical_json(submitted) + b"\n"
    envelope = json.loads(original.report_admission_raw)
    envelope["report_raw_sha256"] = sha(raw)
    with pytest.raises(mod.CollectionError) as error:
        mod.capture_report(raw, canonical_json(envelope) + b"\n", producer_binding=original.producer_binding,
                           authority=authority, producer_role="candidate")
    assert error.value.exit_code == 4
    assert authority_snapshot(authority) == before


def test_cached_incomplete_report_flag_must_equal_actual_raw_parse():
    mod = admitted_collector()
    fixture = producer_fixture(code=bytes.fromhex("85 20 00 00 00 00 00 00") + EXIT)
    authority = fixture_authority(fixture)
    before = authority_snapshot(authority)
    original = captured_fixture(fixture, authority)
    cached = original.to_dict()
    cached["complete"] = True
    with pytest.raises(mod.CollectionError) as error:
        mod._revalidate_report(replace(original, report=cached), authority, "candidate")
    assert error.value.exit_code == 4
    assert authority_snapshot(authority) == before


def test_opaque_review_kind_container_has_structured_cli_refusal(tmp_path):
    mod = admitted_collector()
    fixture = producer_fixture()
    fixture["files"]["review"] = ("review", canonical_json({"kind": ["human-review"], "text": "opaque review"}))
    seal_fixture(fixture)
    argv, _, output, _, _ = admitted_cli_inputs(tmp_path, fixture)
    assert mod.main(argv) == 2
    attempt = json.loads((output / "attempt.json").read_bytes())
    assert attempt["exit_code"] == 2 and not attempt["complete"]
    assert (output / "report.json").is_file()


def test_mixed_native_closure_values_have_structured_refusal():
    mod = admitted_collector()
    fixture = adapter_fixture("parsed-native-capture-v1")
    capture = json.loads(fixture["files"]["source-capture"][1])
    capture["sdk_import_closure"]["malformed"] = None
    fixture["files"]["source-capture"] = ("source_capture", canonical_json(capture))
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 2 and error.value.code == "schema-digest"


def test_unadmitted_inventory_substitution_preserves_original_pin_and_attempt(tmp_path):
    mod = admitted_collector()
    fixture = producer_fixture()
    argv, _, output, _, root = admitted_cli_inputs(tmp_path, fixture)
    original_admission = fixture["admission_raw"]
    original_pin = argv[argv.index("--expected-producer-admission-sha256") + 1]
    review = canonical_json({"kind": ["unadmitted-substitution"]})
    (root / "inputs/review").write_bytes(review)
    path = Path(argv[argv.index("--capture-inventory") + 1])
    inventory = json.loads(path.read_bytes())
    next(row for row in inventory["entries"] if row["id"] == "review").update(sha256=sha(review), size=len(review))
    path.write_bytes(canonical_json(inventory))
    assert mod.main(argv) == 4
    assert argv[argv.index("--expected-producer-admission-sha256") + 1] == original_pin == sha(original_admission)
    assert Path(argv[argv.index("--producer-admission") + 1]).read_bytes() == original_admission
    assert json.loads((output / "attempt.json").read_bytes())["exit_code"] == 4
    assert (output / "report.json").is_file()


def test_c_reference_target_cannot_be_an_unrelated_macro_token():
    mod = admitted_collector()
    fixture = adapter_fixture("reference-command-capture-v1")
    command = json.loads(fixture["files"]["compile"][1])
    flags = ["-D", "bpfel", "-target", "x86_64", "-mcpu=v3", "-O2", "-c"]
    command["argv"] = [command["argv"][0], *flags, "/captured/project/source.c", "-o", "/captured/work/object.o"]
    fixture["provenance"]["flags"] = flags
    fixture["files"]["compile"] = ("command", canonical_json(command))
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 4


def test_capture_alias_check_uses_opened_descriptor_before_reading(tmp_path, monkeypatch):
    mod = admitted_collector()
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_bytes(b"captured review bytes\n")
    second.write_bytes(b"different regular input\n")
    capture = mod._FileCapture()
    capture.read(first, limit=100)
    original_read, fdopen = mod._read, mod.os.fdopen
    consumed = []

    def swapped_at_read(path, *, limit, **kwargs):
        if Path(path) == second:
            second.unlink()
            mod.os.link(first, second)
        return original_read(path, limit=limit, **kwargs)

    def observed_fdopen(*args, **kwargs):
        consumed.append(args[0])
        return fdopen(*args, **kwargs)

    monkeypatch.setattr(mod, "_read", swapped_at_read)
    monkeypatch.setattr(mod.os, "fdopen", observed_fdopen)
    with pytest.raises(mod.CollectionError) as error:
        capture.read(second, limit=100)
    assert error.value.code == "capture-alias" and error.value.exit_code == 4
    assert consumed == []
    assert set(capture.images) == {first.absolute()}


def retained_capture_buffers(blobs, capture):
    pending, seen, buffers = [blobs, vars(capture)], set(), {}
    while pending:
        value = pending.pop()
        if id(value) in seen:
            continue
        seen.add(id(value))
        if type(value) is bytes:
            buffers[id(value)] = value
        elif isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, (tuple, list)):
            pending.extend(value)
    return buffers


def test_content_deduplication_bounds_all_capture_buffer_owners(tmp_path, monkeypatch):
    mod = admitted_collector()
    payload = b"x" * 4096
    entries = []
    for number in range(4):
        name = "copy" + str(number)
        (tmp_path / name).write_bytes(payload)
        entries.append({"id": name, "relative_path": name, "role": "source", "size": len(payload), "sha256": sha(payload)})
    raw = canonical_json({"schema_version": 1, "kind": "cost-capture-inventory-v1", "entries": entries})
    monkeypatch.setattr(mod, "MAX_CAPTURE_BYTES", len(payload))
    capture = mod._FileCapture()
    blobs = mod._capture_inventory(raw, tmp_path, capture, scope="producer")
    buffers = retained_capture_buffers(blobs, capture)
    assert len(capture.images) == len(blobs) == 4
    assert len(buffers) == 1 and sum(len(value) for value in buffers.values()) == mod.MAX_CAPTURE_BYTES


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_legitimate_incomplete_pair_preserves_strict_identity_and_inspection_normalization(encoding):
    mod = admitted_collector()
    fixture = producer_fixture(code=bytes.fromhex("85 20 00 00 00 00 00 00") + EXIT)
    authority = fixture_authority(fixture)
    before = authority_snapshot(authority)
    original = captured_fixture(fixture, authority)
    report = original.to_dict()
    assert not report["complete"]
    raw = json.dumps(report, indent=2).encode(encoding)
    envelope = json.loads(original.report_admission_raw)
    envelope["report_raw_sha256"] = sha(raw)
    actual = mod.capture_report(raw, canonical_json(envelope), producer_binding=original.producer_binding,
                                authority=authority, producer_role="candidate")
    assert actual.report_raw == raw
    assert actual.to_dict() == json.loads(raw)
    assert sha(canonical_json(actual.to_dict())) == envelope["report_canonical_sha256"]
    assert mod._revalidate_report(actual, authority, "candidate").to_dict() == report
    report["complete"] = True
    assert mod.validate_report(report)["complete"] is False
    assert report["complete"] is True
    assert authority_snapshot(authority) == before


@pytest.mark.parametrize("kind", [None, False, 1, {}, []])
def test_inventory_record_kind_requires_string_before_membership(kind):
    mod = admitted_collector()
    fixture = producer_fixture()
    fixture["files"]["review"] = ("review", canonical_json({"kind": kind}))
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 2 and error.value.code == "schema-value"


def test_opaque_review_with_unknown_string_kind_remains_valid():
    fixture = producer_fixture()
    fixture["files"]["review"] = ("review", canonical_json({"kind": "human-review", "text": "opaque review"}))
    seal_fixture(fixture)
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


@pytest.mark.parametrize("digest", [None, False, 1, [], {}])
def test_native_closure_digest_types_are_checked_before_ordering(digest):
    mod = admitted_collector()
    fixture = adapter_fixture("parsed-native-capture-v1")
    capture = json.loads(fixture["files"]["source-capture"][1])
    capture["sdk_import_closure"]["extra"] = digest
    fixture["files"]["source-capture"] = ("source_capture", canonical_json(capture))
    seal_fixture(fixture)
    with pytest.raises(mod.CollectionError) as error:
        bind_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 2 and error.value.code == "schema-digest"


def reference_selector_fixture(target, cpu, extra=()):
    fixture = adapter_fixture("reference-command-capture-v1")
    command = json.loads(fixture["files"]["compile"][1])
    flags = [*extra, *target, *cpu, "-O2", "-c"]
    command["argv"] = [command["argv"][0], *flags, "/captured/project/source.c", "-o", "/captured/work/object.o"]
    fixture["provenance"]["flags"] = flags
    fixture["files"]["compile"] = ("command", canonical_json(command))
    return seal_fixture(fixture)


@pytest.mark.parametrize("target", [["-target", "bpfel"], ["--target", "bpfel"], ["-target=bpfel"], ["--target=bpfel"],
                                    ["-target", "bpf"], ["--target=bpfel-unknown-none"]])
@pytest.mark.parametrize("cpu", [["-mcpu=v3"], ["-mcpu", "v3"]])
def test_c_reference_explicit_target_and_cpu_forms_are_unambiguous(target, cpu):
    fixture = reference_selector_fixture(target, cpu, extra=["-D", "bpfel"])
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


@pytest.mark.parametrize("target, cpu, extra", [
    ([], ["-mcpu=v3"], ["-D", "bpfel"]),
    (["-target", "x86_64"], ["-mcpu=v3"], ["-D", "bpfel"]),
    (["--target=bpfeb"], ["-mcpu=v3"], ["-D", "bpfel"]),
    (["-target", "bpfel", "--target=x86_64"], ["-mcpu=v3"], []),
    (["-target", "x86_64", "--target=bpfel"], ["-mcpu=v3"], []),
    (["-target", "bpfel", "--target=bpfel"], ["-mcpu=v3"], []),
    (["--target=bpfel"], ["-mcpu=v2", "-mcpu=v3"], []),
    (["--target=bpfel"], ["-mcpu=v3", "-mcpu=v3"], []),
    (["--target=bpfel"], ["-mcpu=v2"], []),
    (["--target=bpfel"], [], ["-D", "-mcpu=v3"]),
    (["--target="], ["-mcpu=v3"], ["-D", "bpfel"]),
    (["--target=bpfel"], ["-mcpu="], []),
    (["--target=bpfel"], ["-mcpu=v3"], ["-Xclang", "-triple", "-Xclang", "x86_64"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["@recorded-response.args"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["--config=recorded-target.cfg"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["-march=x86_64"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["-Xclang=-triple", "-Xclang=x86_64"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["-target-cpu=v2"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["-triple=x86_64"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["--mcpu=v2"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["-D", "@recorded-response.args"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["-o", "@recorded-response.args"]),
    (["--target=bpfel"], [], ["-MT", "-mcpu=v3"]),
    (["--target=bpfel"], [], ["-MF", "-mcpu=v3"]),
    (["-MF", "--target=bpfel"], ["-mcpu=v3"], []),
    (["--target=bpfel"], ["-mcpu=v3"], ["-Wp,-triple,x86_64"]),
    (["--target=bpfel"], ["-mcpu=v3"], ["-Wp"]),
    (["--target=bpfel"], [], ["-Xpreprocessor", "-mcpu=v3"]),
])
def test_c_reference_target_selection_refuses_missing_conflicting_or_hidden_options(target, cpu, extra):
    mod = admitted_collector()
    fixture = reference_selector_fixture(target, cpu, extra)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code in (3, 4)


@pytest.mark.parametrize("extra", [
    ["-MT", "object-target"],
    ["-MF", "deps.d", "-MQ", "object-target"],
    ["-x", "c"],
    ["-Xlinker", "-z", "-e", "entry", "-u", "symbol", "-T", "script.lds"],
    ["-MJ", "compile-commands-fragment.json"],
    ["--sysroot", "/"],
    ["-resource-dir", "/resource"],
    ["-L", "/lib", "-l", "m"],
    ["-B", "/prefix", "-z", "relro"],
    ["-rpath", "/runpath", "-F", "/frameworks"],
    ["-Xlinker", "-mcpu=v2"],
    ["-ccc-install-dir", "/gcc"],
    ["-b", "x86_64-pc-linux-gnu"],
    ["-G", "8"],
    ["-lazy_framework", "Cocoa", "-seg1addr", "0x1000"],
    ["--dyld-prefix", "/usr/lib", "--serialize-diagnostics", "diag.dat"],
])
def test_c_reference_legit_operand_options_do_not_change_target_selection(extra):
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=extra)
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


# Every flag here consumes the following token in real clang (verified against
# clang 21.1.8: cc1 selection changes and exit 0 with a swallowed -mcpu=v3).
# Each row must refuse: removing consumption for any one flag must fail it.
@pytest.mark.parametrize("flag", [
    "-MQ", "-x", "-Xlinker", "-e", "-u", "-T",
    "-isysroot", "-z", "-L", "-B",
    "-l", "--sysroot", "-F", "-resource-dir", "-rpath", "-A", "-MJ",
    "-cxx-isystem", "-isystem-after", "-stdlib++-isystem",
    "-iframework", "-iframeworkwithsysroot",
    "-iprefix", "-iwithprefix", "-iwithprefixbefore", "-iwithsysroot",
    "-include-pch", "-vfsoverlay",
    "-dependency-file", "-dependency-dot", "-module-dependency-dir",
    "-object-file-name", "-dumpdir", "-dsym-dir", "-serialize-diagnostics",
    "-mllvm", "-mmlir",
    "-meabi", "-mthread-model", "-fnew-alignment", "-ivfsoverlay",
    "-fdebug-compilation-dir", "-fmodules-user-build-path", "-ftrapv-handler",
    "-fexperimental-openacc-macro-override", "-hlsl-entry", "-iapinotes-modules",
    "-darwin-target-variant", "-darwin-target-variant-triple",
    "--analyzer-output", "--no-system-header-prefix", "--system-header-prefix",
    "--library-directory", "--prefix", "-framework", "-undefined", "-filelist",
    "-ccc-gcc-name", "-ccc-install-dir",
    "-dylib_file", "-bundle_loader", "-client_name", "-compatibility_version",
    "-current_version", "-install_name", "-force_load", "-dylinker_install_name",
    "-unexported_symbols_list", "-exported_symbols_list",
    "-pagezero_size", "-image_base", "-read_only_relocs", "-multiply_defined",
    "--for-linker",
    "--include-directory", "--include-directory-after", "--output", "--param",
    "--stdlib", "--rtlib",
    "--define-macro", "--undefine-macro", "--imacros", "--include", "--std",
    "-b", "-G",
    "-alias_list", "-arch_only", "-init", "-lazy_framework", "-lazy_library",
    "-multiply_defined_unused", "-reexport_framework", "-reexport_library",
    "-segs_read_only_addr", "-segs_read_write_addr", "-sub_library", "-sub_umbrella",
    "-umbrella", "-weak_framework", "-weak_library", "-seg1addr",
    "--dyld-prefix", "--include-prefix", "--include-with-prefix",
    "--include-with-prefix-before", "--include-with-prefix-after",
    "--serialize-diagnostics",
    "-gen-cdb-fragment-path", "-working-directory",
])
def test_c_reference_operand_option_consumes_selector_lookalike_operand(flag):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], [], extra=[flag, "-mcpu=v3"])
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code in (3, 4)


# Real clang splits these joined forms into separate cc1 arguments and then
# expands the @file (verified: -D -U -I -include -isystem -iquote -idirafter
# -imacros -isysroot). The parser refuses FLAG@ for every modeled operand flag.
@pytest.mark.parametrize("operands", [
    ["-segaddr", "A"],
    ["-sectcreate", "A", "B"],
    ["-segprot", "A", "B"],
    ["-sectalign", "A", "B"],
    ["-sectorder", "A", "B"],
    ["-segcreate", "A", "B"],
    ["-sectobjectsymbols", "A"],
])
def test_c_reference_multi_operand_options_skip_exact_arity(operands):
    # Accept proves the exact arity: skipping one fewer would count -mcpu=v2
    # as a conflicting CPU, skipping one more would eat --target=bpfel.
    fixture = reference_selector_fixture(
        ["--target=bpfel"], ["-mcpu=v3"], extra=[*operands, "-mcpu=v2"])
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


@pytest.mark.parametrize("operands", [
    ["-segaddr", "A"],
    ["-sectcreate", "A", "B"],
    ["-segprot", "A", "B"],
    ["-sectalign", "A", "B"],
    ["-sectorder", "A", "B"],
    ["-segcreate", "A", "B"],
    ["-sectobjectsymbols", "A"],
])
def test_c_reference_multi_operand_options_hide_cpu_selection(operands):
    mod = admitted_collector()
    fixture = reference_selector_fixture(
        ["--target=bpfel"], [], extra=[*operands, "-mcpu=v3"])
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code in (3, 4)


@pytest.mark.parametrize("token", [
    "-D@recorded-response.args",
    "-U@recorded-response.args",
    "-I@recorded-response.args",
    "-include@recorded-response.args",
    "-isysroot@recorded-response.args",
    "-mllvm@recorded-response.args",
    "-mllvm=@recorded-response.args",
    "-resource-dir=@recorded-response.args",
    "--sysroot=@recorded-response.args",
    "--std=@recorded-response.args",
    "-D=@recorded-response.args",
    "-foptimization-record-file=@recorded-response.args",
    "--include=@recorded-response.args",
])
def test_c_reference_joined_response_operand_is_refused(token):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=[token])
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code in (3, 4)


@pytest.mark.parametrize("extra", [
    ["-Xassembler", "-mcpu=v3"],
    ["-Xcuda-fatbinary", "-mcpu=v3"],
    ["-Xcuda-ptxas", "-mcpu=v3"],
    ["-Xopenmp-target", "-mcpu=v3"],
])
def test_c_reference_tool_forwarding_cannot_fabricate_selectors(extra):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], [], extra=extra)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code in (3, 4)


@pytest.mark.parametrize("extra", [
    ["-Xassembler", "-C"],
    ["-Xpreprocessor", "-C"],
    ["-cc1as"],
])
def test_c_reference_forwarding_and_mode_flags_are_opaque(extra):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=extra)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 3
    assert error.value.code == "reference-command-unavailable"


@pytest.mark.parametrize("extra", [
    ["-D", "@recorded-response.args"],
    ["-o", "@recorded-response.args"],
    ["-D@recorded-response.args"],
])
def test_c_reference_response_smuggling_refuses_at_target_layer(extra):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=extra)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 3
    assert error.value.code == "reference-command-unavailable"


# -miamcu retargets to i586-intel-elfiamcu and -EB flips the ELF data
# encoding, both silently under --target=bpfel (verified against clang
# 21.1.8). The allowlist refuses them as unknown dash-led tokens.
@pytest.mark.parametrize("extra", [
    ["-miamcu"],
    ["-EB"],
])
def test_c_reference_silent_target_divergence_is_refused(extra):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=extra)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 3
    assert error.value.code == "reference-command-unavailable"


# Joined operand spellings carry their operand inside the token, so real
# clang never consumes the following argv entry for them. Each row must
# accept: the fixture places --target/--mcpu after extra, so skipping
# even one token past the joined spelling would eat the target or CPU.
@pytest.mark.parametrize("extra", [
    ["-DFOO=1"],
    ["-I/usr/include"],
    ["-oout.o"],
    ["--std=c++17"],
    ["--sysroot=/"],
    ["-G8"],
    ["-emit-llvm"],
    ["-"],
    ["--includeheader.h"],
    ["--imacrosmacros.h"],
    ["--sysrootX"],
    ["--std="],
])
def test_c_reference_joined_operand_spellings_do_not_consume(extra):
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=extra)
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


# Exact operand matches win over the joined-spelling rule: these flags
# share a prefix with a shorter operand flag (-u, -l) but consume the
# following token in real clang, so the swallowed -mcpu=v3 must refuse.
@pytest.mark.parametrize("extra", [
    ["-unexported_symbols_list", "-mcpu=v3"],
    ["-lazy_framework", "-mcpu=v3"],
])
def test_c_reference_exact_operand_wins_over_joined_prefix(extra):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], [], extra=extra)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code in (3, 4)


# Unknown dash-led tokens fail closed instead of being assumed
# target-neutral: toolchain additions refuse until re-verified. Longer
# spellings over a known stem (--sysrootX, --std=) are accepted as
# accepted-erroring input instead: real clang rejects them downstream.
@pytest.mark.parametrize("extra", [
    ["-fthis-flag-does-not-exist-1"],
    ["-W@recorded-response.args"],
    ["-O@2"],
    ["--offload-arch=sm_80"],
    ["--cuda-feature=+ptx80"],
    ["--config-user-dir=/cfg"],
    ["-specs=/specs"],
    ["-V=1"],
    ["-print-file-name=libc.a"],
    ["-fopenmp-targets=nvptx64"],
    ["-fuse-cuid=1234"],
    ["-multi-lib-config=/ml.cfg"],
    ["--hip-version=6.0"],
    ["-fplugin=/retarget.so"],
    ["-fpass-plugin=/retarget.so"],
    ["-fplugin"],
    ["-fpass-plugin"],
])
def test_c_reference_unknown_dashled_options_are_refused(extra):
    mod = admitted_collector()
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=extra)
    with pytest.raises(mod.CollectionError) as error:
        captured_fixture(fixture, fixture_authority(fixture))
    assert error.value.exit_code == 3
    assert error.value.code == "reference-command-unavailable"


# Joined-only spellings take their value exclusively with '=' (verified:
# each stem keeps Target: bpfel with --target=bpfel given, and its bare form
# is unknown to the driver). Target-adjacent families (offload/cuda/hip/gpu,
# config, print/dump modes, specs) stay refused.
@pytest.mark.parametrize("extra", [
    ["--cuda-path=/a"],
    ["--embed-dir=/a"],
    ["--extract-api-ignores=1"],
    ["--gcc-install-dir=/a"],
    ["--gcc-toolchain=1"],
    ["--gcc-triple=1"],
    ["--hip-path=/a"],
    ["--rocm-path=/a"],
    ["--rsp-quoting=1"],
    ["--symbol-graph-dir=/a"],
    ["--unwindlib=1"],
    ["--warning-suppression-mappings=/a"],
    ["-cl-ext=1"],
    ["-cl-std=c11"],
    ["-fallow-runtime-check-skip-hot-cutoff=1"],
    ["-faltivec-src-compat=1"],
    ["-fapinotes-swift-version=1"],
    ["-fbasic-block-sections=1"],
    ["-fbinutils-version=1"],
    ["-fbuild-session-file=/a"],
    ["-fbuild-session-timestamp=1"],
    ["-fc++-abi=1"],
    ["-fcaret-diagnostics-max-lines=1"],
    ["-fclang-abi-compat=1"],
    ["-fcomment-block-commands=1"],
    ["-fcomplex-arithmetic=full"],
    ["-fconstexpr-backtrace-limit=1"],
    ["-fconstexpr-depth=1"],
    ["-fconstexpr-steps=1"],
    ["-fcoverage-compilation-dir=/a"],
    ["-fcoverage-prefix-map=/a"],
    ["-fcrash-diagnostics-dir=/a"],
    ["-fdebug-default-version=1"],
    ["-fdebug-prefix-map=/a"],
    ["-fdiagnostics-hotness-threshold=1"],
    ["-fdiagnostics-misexpect-tolerance=1"],
    ["-femit-dwarf-unwind=1"],
    ["-fexcess-precision=standard"],
    ["-fexperimental-sanitize-metadata=1"],
    ["-fexperimental-sanitize-metadata-ignorelist=/a"],
    ["-fextend-arguments=1"],
    ["-ffile-compilation-dir=/a"],
    ["-ffile-prefix-map=/a"],
    ["-ffp-contract=fast"],
    ["-ffp-eval-method=source"],
    ["-ffp-exception-behavior=strict"],
    ["-ffp-model=precise"],
    ["-ffuchsia-api-level=1"],
    ["-fgnuc-version=1"],
    ["-finline-max-stacksize=1"],
    ["-finput-charset=/a"],
    ["-flto-jobs=1"],
    ["-flto-partitions=1"],
    ["-fmacro-backtrace-limit=1"],
    ["-fmacro-prefix-map=/a"],
    ["-fmax-tokens=1"],
    ["-fmax-type-align=1"],
    ["-fmemory-profile-use=/a"],
    ["-fmessage-length=1"],
    ["-fmodule-file=/a"],
    ["-fmodule-map-file=/a"],
    ["-fmodule-name=1"],
    ["-fmodules-cache-path=/a"],
    ["-fmodules-ignore-macro=1"],
    ["-fmodules-prune-after=1"],
    ["-fmodules-prune-interval=1"],
    ["-fms-compatibility-version=1"],
    ["-fms-runtime-lib=1"],
    ["-fms-secure-hotpatch-functions-file=/a"],
    ["-fms-secure-hotpatch-functions-list=/a"],
    ["-fmsc-version=1"],
    ["-fno-experimental-sanitize-metadata=1"],
    ["-fno-sanitize-coverage=1"],
    ["-fobjc-runtime=1"],
    ["-fopenmp-version=1"],
    ["-foperator-arrow-depth=1"],
    ["-foptimization-record-file=/a"],
    ["-foptimization-record-passes=1"],
    ["-fpatchable-function-entry=1"],
    ["-fprebuilt-module-path=/a"],
    ["-fprofile-dir=/a"],
    ["-fprofile-exclude-files=/a"],
    ["-fprofile-filter-files=/a"],
    ["-fprofile-function-groups=/a"],
    ["-fprofile-list=/a"],
    ["-fprofile-remapping-file=/a"],
    ["-fprofile-sample-use=/a"],
    ["-fprofile-selected-function-group=/a"],
    ["-fprofile-update=/a"],
    ["-frandomize-layout-seed=42"],
    ["-frandomize-layout-seed-file=/a"],
    ["-fsanitize=address"],
    ["-fsanitize-address-destructor=1"],
    ["-fsanitize-address-field-padding=1"],
    ["-fsanitize-address-use-after-return=1"],
    ["-fsanitize-blacklist=/a"],
    ["-fsanitize-coverage=trace-pc-guard"],
    ["-fsanitize-coverage-allowlist=/a"],
    ["-fsanitize-coverage-ignorelist=/a"],
    ["-fsanitize-coverage-stack-depth-callback-min=1"],
    ["-fsanitize-hwaddress-abi=1"],
    ["-fsanitize-ignorelist=/a"],
    ["-fsanitize-memtag-mode=1"],
    ["-fsanitize-skip-hot-cutoff=1"],
    ["-fsanitize-system-ignorelist=/a"],
    ["-fsanitize-undefined-ignore-overflow-pattern=1"],
    ["-fsanitize-undefined-strip-path-components=/a"],
    ["-fshow-overloads=1"],
    ["-fspell-checking-limit=1"],
    ["-fstrict-flex-arrays=1"],
    ["-fswift-async-fp=1"],
    ["-ftemplate-backtrace-limit=1"],
    ["-ftemplate-depth=1"],
    ["-fthin-link-bitcode=1"],
    ["-fthinlto-distributor=1"],
    ["-fthinlto-index=1"],
    ["-ftime-trace-granularity=1"],
    ["-ftrap-function=1"],
    ["-ftrivial-auto-var-init=1"],
    ["-ftrivial-auto-var-init-max-size=1"],
    ["-ftrivial-auto-var-init-stop-after=1"],
    ["-funique-source-file-identifier=/a"],
    ["-fuse-ld=lld"],
    ["-fveclib=1"],
    ["-fvisibility=hidden"],
    ["-fvisibility-dllexport=1"],
    ["-fvisibility-externs-dllimport=1"],
    ["-fvisibility-externs-nodllstorageclass=1"],
    ["-fvisibility-global-new-delete=1"],
    ["-fvisibility-nodllstorageclass=1"],
    ["-fwinx64-eh-unwindv2=1"],
    ["-fxray-always-instrument=1"],
    ["-fxray-attr-list=/a"],
    ["-fxray-function-groups=1"],
    ["-fxray-instruction-threshold=1"],
    ["-fxray-instrumentation-bundle=1"],
    ["-fxray-modes=1"],
    ["-fxray-never-instrument=1"],
    ["-fxray-selected-function-group=1"],
    ["-fzero-call-used-regs=1"],
    ["-mabi=1"],
    ["-malign-branch=1"],
    ["-malign-branch-boundary=1"],
    ["-mapx-features=/a"],
    ["-mbranch-protection=1"],
    ["-mcf-branch-label-scheme=1"],
    ["-mcode-object-version=1"],
    ["-mdefault-visibility-export-mapping=/a"],
    ["-mdouble=1"],
    ["-mexec-model=1"],
    ["-mframe-chain=1"],
    ["-mfunction-return=1"],
    ["-mguard=1"],
    ["-mharden-sls=1"],
    ["-mhvx-length=1"],
    ["-mindirect-jump=/a"],
    ["-mios-version-min=1"],
    ["-mmacos-version-min=1"],
    ["-mno-apx-features=1"],
    ["-mpad-max-prefix-size=/a"],
    ["-mprefer-vector-width=1"],
    ["-mprintf-kind=1"],
    ["-mrvv-vector-bits=1"],
    ["-msign-return-address=1"],
    ["-msimd=1"],
    ["-msmall-data-limit=1"],
    ["-mstack-alignment=1"],
    ["-mstack-probe-size=1"],
    ["-mstack-protector-guard=1"],
    ["-mstack-protector-guard-offset=1"],
    ["-mstack-protector-guard-reg=1"],
    ["-mstack-protector-guard-symbol=1"],
    ["-msve-streaming-vector-bits=1"],
    ["-msve-vector-bits=1"],
    ["-mtargetos=1"],
    ["-mtls-dialect=1"],
    ["-mtls-size=1"],
    ["-mtp=1"],
    ["-mtune=1"],
    ["-mxcoff-build-id=1"],
    ["-mzos-hlq-clang=1"],
    ["-mzos-hlq-csslib=1"],
    ["-mzos-hlq-le=1"],
    ["-mzos-sys-include=1"],
    ["-mzos-target=1"],
    ["-rtlib=1"],
    ["-std=c11"],
    ["-sycl-std=c11"],
])
def test_c_reference_joined_only_spellings_are_accepted(extra):
    fixture = reference_selector_fixture(["--target=bpfel"], ["-mcpu=v3"], extra=extra)
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


# Inverted non-consumption proof: every allowlisted spelling is followed by
# -mcpu=v3 with no other CPU, so each row must accept. If any spelling ever
# consumed its successor, the CPU would vanish and the row would refuse.
@pytest.mark.parametrize("extra", [
    ["--analyze", "-mcpu=v3"],
    ["--coverage", "-mcpu=v3"],
    ["--cuda-compile-host-device", "-mcpu=v3"],
    ["--cuda-device-only", "-mcpu=v3"],
    ["--cuda-host-only", "-mcpu=v3"],
    ["--cuda-noopt-device-debug", "-mcpu=v3"],
    ["--cuda-path-ignore-env", "-mcpu=v3"],
    ["--emit-extension-symbol-graphs", "-mcpu=v3"],
    ["--emit-static-lib", "-mcpu=v3"],
    ["--end-no-unused-arguments", "-mcpu=v3"],
    ["--gpu-bundle-output", "-mcpu=v3"],
    ["--gpu-use-aux-triple-only", "-mcpu=v3"],
    ["--hip-link", "-mcpu=v3"],
    ["--hipstdpar", "-mcpu=v3"],
    ["--hipstdpar-interpose-alloc", "-mcpu=v3"],
    ["--no-cuda-version-check", "-mcpu=v3"],
    ["--no-default-config", "-mcpu=v3"],
    ["--no-gpu-bundle-output", "-mcpu=v3"],
    ["--no-offload-inc", "-mcpu=v3"],
    ["--no-offload-new-driver", "-mcpu=v3"],
    ["--no-offloadlib", "-mcpu=v3"],
    ["--no-wasm-opt", "-mcpu=v3"],
    ["--offload-compress", "-mcpu=v3"],
    ["--offload-device-only", "-mcpu=v3"],
    ["--offload-host-device", "-mcpu=v3"],
    ["--offload-host-only", "-mcpu=v3"],
    ["--offload-inc", "-mcpu=v3"],
    ["--offload-link", "-mcpu=v3"],
    ["--offload-new-driver", "-mcpu=v3"],
    ["--offloadlib", "-mcpu=v3"],
    ["--optimize", "-mcpu=v3"],
    ["--precompile", "-mcpu=v3"],
    ["--pretty-sgf", "-mcpu=v3"],
    ["--start-no-unused-arguments", "-mcpu=v3"],
    ["--verify-debug-info", "-mcpu=v3"],
    ["--wasm-opt", "-mcpu=v3"],
    ["-C", "-mcpu=v3"],
    ["-CC", "-mcpu=v3"],
    ["-E", "-mcpu=v3"],
    ["-EL", "-mcpu=v3"],
    ["-H", "-mcpu=v3"],
    ["-I-", "-mcpu=v3"],
    ["-K", "-mcpu=v3"],
    ["-M", "-mcpu=v3"],
    ["-MD", "-mcpu=v3"],
    ["-MG", "-mcpu=v3"],
    ["-MM", "-mcpu=v3"],
    ["-MMD", "-mcpu=v3"],
    ["-MP", "-mcpu=v3"],
    ["-MV", "-mcpu=v3"],
    ["-ObjC++", "-mcpu=v3"],
    ["-P", "-mcpu=v3"],
    ["-Q", "-mcpu=v3"],
    ["-Qn", "-mcpu=v3"],
    ["-Qunused-arguments", "-mcpu=v3"],
    ["-Qy", "-mcpu=v3"],
    ["-R", "-mcpu=v3"],
    ["-Rpass", "-mcpu=v3"],
    ["-Rpass-analysis", "-mcpu=v3"],
    ["-Rpass-missed", "-mcpu=v3"],
    ["-S", "-mcpu=v3"],
    ["-Z", "-mcpu=v3"],
    ["-all_load", "-mcpu=v3"],
    ["-ansi", "-mcpu=v3"],
    ["-bind_at_load", "-mcpu=v3"],
    ["-bundle", "-mcpu=v3"],
    ["-c", "-mcpu=v3"],
    ["-canonical-prefixes", "-mcpu=v3"],
    ["-cl-denorms-are-zero", "-mcpu=v3"],
    ["-cl-fast-relaxed-math", "-mcpu=v3"],
    ["-cl-finite-math-only", "-mcpu=v3"],
    ["-cl-fp32-correctly-rounded-divide-sqrt", "-mcpu=v3"],
    ["-cl-kernel-arg-info", "-mcpu=v3"],
    ["-cl-mad-enable", "-mcpu=v3"],
    ["-cl-no-signed-zeros", "-mcpu=v3"],
    ["-cl-no-stdinc", "-mcpu=v3"],
    ["-cl-opt-disable", "-mcpu=v3"],
    ["-cl-single-precision-constant", "-mcpu=v3"],
    ["-cl-strict-aliasing", "-mcpu=v3"],
    ["-cl-uniform-work-group-size", "-mcpu=v3"],
    ["-cl-unsafe-math-optimizations", "-mcpu=v3"],
    ["-clangir-disable-passes", "-mcpu=v3"],
    ["-clangir-disable-verifier", "-mcpu=v3"],
    ["-coverage", "-mcpu=v3"],
    ["-d", "-mcpu=v3"],
    ["-dD", "-mcpu=v3"],
    ["-dI", "-mcpu=v3"],
    ["-dM", "-mcpu=v3"],
    ["-dead_strip", "-mcpu=v3"],
    ["-dumpbase", "-mcpu=v3"],
    ["-dyld-prefix", "-mcpu=v3"],
    ["-dylib", "-mcpu=v3"],
    ["-dynamic-linker", "-mcpu=v3"],
    ["-dynamiclib", "-mcpu=v3"],
    ["-emit-ast", "-mcpu=v3"],
    ["-emit-cir", "-mcpu=v3"],
    ["-emit-interface-stubs", "-mcpu=v3"],
    ["-emit-llvm", "-mcpu=v3"],
    ["-emit-merged-ifs", "-mcpu=v3"],
    ["-emit-symbol-graph", "-mcpu=v3"],
    ["-extract-api", "-mcpu=v3"],
    ["-faapcs-bitfield-load", "-mcpu=v3"],
    ["-faapcs-bitfield-width", "-mcpu=v3"],
    ["-faarch64-jump-table-hardening", "-mcpu=v3"],
    ["-faddrsig", "-mcpu=v3"],
    ["-falign-loops", "-mcpu=v3"],
    ["-faligned-allocation", "-mcpu=v3"],
    ["-fallow-editor-placeholders", "-mcpu=v3"],
    ["-fansi-escape-codes", "-mcpu=v3"],
    ["-fapinotes", "-mcpu=v3"],
    ["-fapinotes-modules", "-mcpu=v3"],
    ["-fapple-kext", "-mcpu=v3"],
    ["-fapple-link-rtlib", "-mcpu=v3"],
    ["-fapple-pragma-pack", "-mcpu=v3"],
    ["-fapplication-extension", "-mcpu=v3"],
    ["-fapprox-func", "-mcpu=v3"],
    ["-fassume-nothrow-exception-dtor", "-mcpu=v3"],
    ["-fasync-exceptions", "-mcpu=v3"],
    ["-fatomic-fine-grained-memory", "-mcpu=v3"],
    ["-fatomic-ignore-denormal-mode", "-mcpu=v3"],
    ["-fatomic-remote-memory", "-mcpu=v3"],
    ["-fauto-import", "-mcpu=v3"],
    ["-fbasic-block-address-map", "-mcpu=v3"],
    ["-fblocks", "-mcpu=v3"],
    ["-fborland-extensions", "-mcpu=v3"],
    ["-fbuiltin-module-map", "-mcpu=v3"],
    ["-fc++-static-destructors", "-mcpu=v3"],
    ["-fcall-saved-x10", "-mcpu=v3"],
    ["-fcall-saved-x11", "-mcpu=v3"],
    ["-fcall-saved-x12", "-mcpu=v3"],
    ["-fcall-saved-x13", "-mcpu=v3"],
    ["-fcall-saved-x14", "-mcpu=v3"],
    ["-fcall-saved-x15", "-mcpu=v3"],
    ["-fcall-saved-x18", "-mcpu=v3"],
    ["-fcall-saved-x8", "-mcpu=v3"],
    ["-fcall-saved-x9", "-mcpu=v3"],
    ["-fcf-protection", "-mcpu=v3"],
    ["-fchar8_t", "-mcpu=v3"],
    ["-fcheck-new", "-mcpu=v3"],
    ["-fclangir", "-mcpu=v3"],
    ["-fcodegen-data-generate", "-mcpu=v3"],
    ["-fcodegen-data-use", "-mcpu=v3"],
    ["-fcolor-diagnostics", "-mcpu=v3"],
    ["-fcommon", "-mcpu=v3"],
    ["-fcomplete-member-pointers", "-mcpu=v3"],
    ["-fconvergent-functions", "-mcpu=v3"],
    ["-fcoro-aligned-allocation", "-mcpu=v3"],
    ["-fcoroutines", "-mcpu=v3"],
    ["-fcoverage-mapping", "-mcpu=v3"],
    ["-fcoverage-mcdc", "-mcpu=v3"],
    ["-fcrash-diagnostics", "-mcpu=v3"],
    ["-fcreate-profile", "-mcpu=v3"],
    ["-fcs-profile-generate", "-mcpu=v3"],
    ["-fcuda-short-ptr", "-mcpu=v3"],
    ["-fcx-fortran-rules", "-mcpu=v3"],
    ["-fcx-limited-range", "-mcpu=v3"],
    ["-fcxx-exceptions", "-mcpu=v3"],
    ["-fcxx-modules", "-mcpu=v3"],
    ["-fdata-sections", "-mcpu=v3"],
    ["-fdebug-info-for-profiling", "-mcpu=v3"],
    ["-fdebug-macro", "-mcpu=v3"],
    ["-fdebug-ranges-base-address", "-mcpu=v3"],
    ["-fdebug-types-section", "-mcpu=v3"],
    ["-fdeclspec", "-mcpu=v3"],
    ["-fdefine-target-os-macros", "-mcpu=v3"],
    ["-fdelayed-template-parsing", "-mcpu=v3"],
    ["-fdelete-null-pointer-checks", "-mcpu=v3"],
    ["-fdiagnostics-absolute-paths", "-mcpu=v3"],
    ["-fdiagnostics-color", "-mcpu=v3"],
    ["-fdiagnostics-parseable-fixits", "-mcpu=v3"],
    ["-fdiagnostics-print-source-range-info", "-mcpu=v3"],
    ["-fdiagnostics-show-hotness", "-mcpu=v3"],
    ["-fdiagnostics-show-note-include-stack", "-mcpu=v3"],
    ["-fdiagnostics-show-option", "-mcpu=v3"],
    ["-fdiagnostics-show-template-tree", "-mcpu=v3"],
    ["-fdigraphs", "-mcpu=v3"],
    ["-fdirect-access-external-data", "-mcpu=v3"],
    ["-fdisable-block-signature-string", "-mcpu=v3"],
    ["-fdiscard-value-names", "-mcpu=v3"],
    ["-fdollars-in-identifiers", "-mcpu=v3"],
    ["-fdwarf-exceptions", "-mcpu=v3"],
    ["-feliminate-unused-debug-types", "-mcpu=v3"],
    ["-fembed-bitcode", "-mcpu=v3"],
    ["-fembed-bitcode-marker", "-mcpu=v3"],
    ["-femit-all-decls", "-mcpu=v3"],
    ["-femit-compact-unwind-non-canonical", "-mcpu=v3"],
    ["-femulated-tls", "-mcpu=v3"],
    ["-fenable-matrix", "-mcpu=v3"],
    ["-fexceptions", "-mcpu=v3"],
    ["-fexperimental-late-parse-attributes", "-mcpu=v3"],
    ["-fexperimental-library", "-mcpu=v3"],
    ["-fexperimental-new-constant-interpreter", "-mcpu=v3"],
    ["-fexperimental-relative-c++-abi-vtables", "-mcpu=v3"],
    ["-fexperimental-strict-floating-point", "-mcpu=v3"],
    ["-fextend-variable-liveness", "-mcpu=v3"],
    ["-ffast-math", "-mcpu=v3"],
    ["-ffat-lto-objects", "-mcpu=v3"],
    ["-ffile-reproducible", "-mcpu=v3"],
    ["-ffine-grained-bitfield-accesses", "-mcpu=v3"],
    ["-ffinite-loops", "-mcpu=v3"],
    ["-ffinite-math-only", "-mcpu=v3"],
    ["-ffixed-a0", "-mcpu=v3"],
    ["-ffixed-a1", "-mcpu=v3"],
    ["-ffixed-a2", "-mcpu=v3"],
    ["-ffixed-a3", "-mcpu=v3"],
    ["-ffixed-a4", "-mcpu=v3"],
    ["-ffixed-a5", "-mcpu=v3"],
    ["-ffixed-a6", "-mcpu=v3"],
    ["-ffixed-d0", "-mcpu=v3"],
    ["-ffixed-d1", "-mcpu=v3"],
    ["-ffixed-d2", "-mcpu=v3"],
    ["-ffixed-d3", "-mcpu=v3"],
    ["-ffixed-d4", "-mcpu=v3"],
    ["-ffixed-d5", "-mcpu=v3"],
    ["-ffixed-d6", "-mcpu=v3"],
    ["-ffixed-d7", "-mcpu=v3"],
    ["-ffixed-g1", "-mcpu=v3"],
    ["-ffixed-g2", "-mcpu=v3"],
    ["-ffixed-g3", "-mcpu=v3"],
    ["-ffixed-g4", "-mcpu=v3"],
    ["-ffixed-g5", "-mcpu=v3"],
    ["-ffixed-g6", "-mcpu=v3"],
    ["-ffixed-g7", "-mcpu=v3"],
    ["-ffixed-i0", "-mcpu=v3"],
    ["-ffixed-i1", "-mcpu=v3"],
    ["-ffixed-i2", "-mcpu=v3"],
    ["-ffixed-i3", "-mcpu=v3"],
    ["-ffixed-i4", "-mcpu=v3"],
    ["-ffixed-i5", "-mcpu=v3"],
    ["-ffixed-l0", "-mcpu=v3"],
    ["-ffixed-l1", "-mcpu=v3"],
    ["-ffixed-l2", "-mcpu=v3"],
    ["-ffixed-l3", "-mcpu=v3"],
    ["-ffixed-l4", "-mcpu=v3"],
    ["-ffixed-l5", "-mcpu=v3"],
    ["-ffixed-l6", "-mcpu=v3"],
    ["-ffixed-l7", "-mcpu=v3"],
    ["-ffixed-o0", "-mcpu=v3"],
    ["-ffixed-o1", "-mcpu=v3"],
    ["-ffixed-o2", "-mcpu=v3"],
    ["-ffixed-o3", "-mcpu=v3"],
    ["-ffixed-o4", "-mcpu=v3"],
    ["-ffixed-o5", "-mcpu=v3"],
    ["-ffixed-point", "-mcpu=v3"],
    ["-ffixed-r19", "-mcpu=v3"],
    ["-ffixed-r9", "-mcpu=v3"],
    ["-ffixed-x1", "-mcpu=v3"],
    ["-ffixed-x10", "-mcpu=v3"],
    ["-ffixed-x11", "-mcpu=v3"],
    ["-ffixed-x12", "-mcpu=v3"],
    ["-ffixed-x13", "-mcpu=v3"],
    ["-ffixed-x14", "-mcpu=v3"],
    ["-ffixed-x15", "-mcpu=v3"],
    ["-ffixed-x16", "-mcpu=v3"],
    ["-ffixed-x17", "-mcpu=v3"],
    ["-ffixed-x18", "-mcpu=v3"],
    ["-ffixed-x19", "-mcpu=v3"],
    ["-ffixed-x2", "-mcpu=v3"],
    ["-ffixed-x20", "-mcpu=v3"],
    ["-ffixed-x21", "-mcpu=v3"],
    ["-ffixed-x22", "-mcpu=v3"],
    ["-ffixed-x23", "-mcpu=v3"],
    ["-ffixed-x24", "-mcpu=v3"],
    ["-ffixed-x25", "-mcpu=v3"],
    ["-ffixed-x26", "-mcpu=v3"],
    ["-ffixed-x27", "-mcpu=v3"],
    ["-ffixed-x28", "-mcpu=v3"],
    ["-ffixed-x29", "-mcpu=v3"],
    ["-ffixed-x3", "-mcpu=v3"],
    ["-ffixed-x30", "-mcpu=v3"],
    ["-ffixed-x31", "-mcpu=v3"],
    ["-ffixed-x4", "-mcpu=v3"],
    ["-ffixed-x5", "-mcpu=v3"],
    ["-ffixed-x6", "-mcpu=v3"],
    ["-ffixed-x7", "-mcpu=v3"],
    ["-ffixed-x8", "-mcpu=v3"],
    ["-ffixed-x9", "-mcpu=v3"],
    ["-fforce-check-cxx20-modules-input-files", "-mcpu=v3"],
    ["-fforce-dwarf-frame", "-mcpu=v3"],
    ["-fforce-emit-vtables", "-mcpu=v3"],
    ["-fforce-enable-int128", "-mcpu=v3"],
    ["-ffreestanding", "-mcpu=v3"],
    ["-ffunction-sections", "-mcpu=v3"],
    ["-fglobal-isel", "-mcpu=v3"],
    ["-fgnu-keywords", "-mcpu=v3"],
    ["-fgnu-runtime", "-mcpu=v3"],
    ["-fgnu89-inline", "-mcpu=v3"],
    ["-fgpu-allow-device-init", "-mcpu=v3"],
    ["-fgpu-approx-transcendentals", "-mcpu=v3"],
    ["-fgpu-defer-diag", "-mcpu=v3"],
    ["-fgpu-exclude-wrong-side-overloads", "-mcpu=v3"],
    ["-fgpu-flush-denormals-to-zero", "-mcpu=v3"],
    ["-fgpu-rdc", "-mcpu=v3"],
    ["-fgpu-sanitize", "-mcpu=v3"],
    ["-fheinous-gnu-extensions", "-mcpu=v3"],
    ["-fhip-emit-relocatable", "-mcpu=v3"],
    ["-fhip-fp32-correctly-rounded-divide-sqrt", "-mcpu=v3"],
    ["-fhip-kernel-arg-name", "-mcpu=v3"],
    ["-fhip-new-launch-api", "-mcpu=v3"],
    ["-fhlsl-strict-availability", "-mcpu=v3"],
    ["-fhonor-infinities", "-mcpu=v3"],
    ["-fhonor-nans", "-mcpu=v3"],
    ["-fignore-exceptions", "-mcpu=v3"],
    ["-fimplicit-module-maps", "-mcpu=v3"],
    ["-fincremental-extensions", "-mcpu=v3"],
    ["-finit-global-zero", "-mcpu=v3"],
    ["-finline-functions", "-mcpu=v3"],
    ["-finline-hint-functions", "-mcpu=v3"],
    ["-finstrument-function-entry-bare", "-mcpu=v3"],
    ["-finstrument-functions", "-mcpu=v3"],
    ["-finstrument-functions-after-inlining", "-mcpu=v3"],
    ["-fintegrated-as", "-mcpu=v3"],
    ["-fintegrated-cc1", "-mcpu=v3"],
    ["-fintegrated-objemitter", "-mcpu=v3"],
    ["-fjmc", "-mcpu=v3"],
    ["-fjump-tables", "-mcpu=v3"],
    ["-fkeep-persistent-storage-variables", "-mcpu=v3"],
    ["-fkeep-static-consts", "-mcpu=v3"],
    ["-fkeep-system-includes", "-mcpu=v3"],
    ["-flat_namespace", "-mcpu=v3"],
    ["-flax-vector-conversions", "-mcpu=v3"],
    ["-floop-interchange", "-mcpu=v3"],
    ["-flto", "-mcpu=v3"],
    ["-fmath-errno", "-mcpu=v3"],
    ["-fmemory-profile", "-mcpu=v3"],
    ["-fmerge-all-constants", "-mcpu=v3"],
    ["-fminimize-whitespace", "-mcpu=v3"],
    ["-fmodule-header", "-mcpu=v3"],
    ["-fmodule-output", "-mcpu=v3"],
    ["-fmodulemap-allow-subdirectory-search", "-mcpu=v3"],
    ["-fmodules", "-mcpu=v3"],
    ["-fmodules-decluse", "-mcpu=v3"],
    ["-fmodules-disable-diagnostic-validation", "-mcpu=v3"],
    ["-fmodules-embed-all-files", "-mcpu=v3"],
    ["-fmodules-force-validate-user-headers", "-mcpu=v3"],
    ["-fmodules-reduced-bmi", "-mcpu=v3"],
    ["-fmodules-search-all", "-mcpu=v3"],
    ["-fmodules-strict-decluse", "-mcpu=v3"],
    ["-fmodules-validate-input-files-content", "-mcpu=v3"],
    ["-fmodules-validate-once-per-build-session", "-mcpu=v3"],
    ["-fmodules-validate-system-headers", "-mcpu=v3"],
    ["-fms-compatibility", "-mcpu=v3"],
    ["-fms-define-stdc", "-mcpu=v3"],
    ["-fms-extensions", "-mcpu=v3"],
    ["-fms-hotpatch", "-mcpu=v3"],
    ["-fms-volatile", "-mcpu=v3"],
    ["-fnew-infallible", "-mcpu=v3"],
    ["-fno-aapcs-bitfield-width", "-mcpu=v3"],
    ["-fno-access-control", "-mcpu=v3"],
    ["-fno-addrsig", "-mcpu=v3"],
    ["-fno-apinotes", "-mcpu=v3"],
    ["-fno-apinotes-modules", "-mcpu=v3"],
    ["-fno-assume-sane-operator-new", "-mcpu=v3"],
    ["-fno-assume-unique-vtables", "-mcpu=v3"],
    ["-fno-assumptions", "-mcpu=v3"],
    ["-fno-atomic-fine-grained-memory", "-mcpu=v3"],
    ["-fno-atomic-ignore-denormal-mode", "-mcpu=v3"],
    ["-fno-atomic-remote-memory", "-mcpu=v3"],
    ["-fno-auto-import", "-mcpu=v3"],
    ["-fno-autolink", "-mcpu=v3"],
    ["-fno-builtin", "-mcpu=v3"],
    ["-fno-builtin-", "-mcpu=v3"],
    ["-fno-c++-static-destructors", "-mcpu=v3"],
    ["-fno-char8_t", "-mcpu=v3"],
    ["-fno-clangir", "-mcpu=v3"],
    ["-fno-color-diagnostics", "-mcpu=v3"],
    ["-fno-common", "-mcpu=v3"],
    ["-fno-complete-member-pointers", "-mcpu=v3"],
    ["-fno-constant-cfstrings", "-mcpu=v3"],
    ["-fno-coverage-mapping", "-mcpu=v3"],
    ["-fno-coverage-mcdc", "-mcpu=v3"],
    ["-fno-crash-diagnostics", "-mcpu=v3"],
    ["-fno-cx-fortran-rules", "-mcpu=v3"],
    ["-fno-cx-limited-range", "-mcpu=v3"],
    ["-fno-cxx-modules", "-mcpu=v3"],
    ["-fno-debug-macro", "-mcpu=v3"],
    ["-fno-declspec", "-mcpu=v3"],
    ["-fno-define-target-os-macros", "-mcpu=v3"],
    ["-fno-delayed-template-parsing", "-mcpu=v3"],
    ["-fno-delete-null-pointer-checks", "-mcpu=v3"],
    ["-fno-diagnostics-fixit-info", "-mcpu=v3"],
    ["-fno-diagnostics-show-line-numbers", "-mcpu=v3"],
    ["-fno-digraphs", "-mcpu=v3"],
    ["-fno-direct-access-external-data", "-mcpu=v3"],
    ["-fno-disable-block-signature-string", "-mcpu=v3"],
    ["-fno-discard-value-names", "-mcpu=v3"],
    ["-fno-dollars-in-identifiers", "-mcpu=v3"],
    ["-fno-elide-constructors", "-mcpu=v3"],
    ["-fno-elide-type", "-mcpu=v3"],
    ["-fno-eliminate-unused-debug-types", "-mcpu=v3"],
    ["-fno-exceptions", "-mcpu=v3"],
    ["-fno-experimental-late-parse-attributes", "-mcpu=v3"],
    ["-fno-experimental-relative-c++-abi-vtables", "-mcpu=v3"],
    ["-fno-fat-lto-objects", "-mcpu=v3"],
    ["-fno-file-reproducible", "-mcpu=v3"],
    ["-fno-fine-grained-bitfield-accesses", "-mcpu=v3"],
    ["-fno-finite-loops", "-mcpu=v3"],
    ["-fno-fixed-point", "-mcpu=v3"],
    ["-fno-force-enable-int128", "-mcpu=v3"],
    ["-fno-global-isel", "-mcpu=v3"],
    ["-fno-gnu-inline-asm", "-mcpu=v3"],
    ["-fno-gpu-allow-device-init", "-mcpu=v3"],
    ["-fno-gpu-approx-transcendentals", "-mcpu=v3"],
    ["-fno-gpu-defer-diag", "-mcpu=v3"],
    ["-fno-gpu-exclude-wrong-side-overloads", "-mcpu=v3"],
    ["-fno-hip-emit-relocatable", "-mcpu=v3"],
    ["-fno-hip-fp32-correctly-rounded-divide-sqrt", "-mcpu=v3"],
    ["-fno-hip-kernel-arg-name", "-mcpu=v3"],
    ["-fno-hip-new-launch-api", "-mcpu=v3"],
    ["-fno-init-global-zero", "-mcpu=v3"],
    ["-fno-integrated-as", "-mcpu=v3"],
    ["-fno-integrated-cc1", "-mcpu=v3"],
    ["-fno-integrated-objemitter", "-mcpu=v3"],
    ["-fno-jump-tables", "-mcpu=v3"],
    ["-fno-keep-persistent-storage-variables", "-mcpu=v3"],
    ["-fno-keep-static-consts", "-mcpu=v3"],
    ["-fno-knr-functions", "-mcpu=v3"],
    ["-fno-loop-interchange", "-mcpu=v3"],
    ["-fno-lto", "-mcpu=v3"],
    ["-fno-memory-profile", "-mcpu=v3"],
    ["-fno-merge-all-constants", "-mcpu=v3"],
    ["-fno-modules-check-relocated", "-mcpu=v3"],
    ["-fno-modules-force-validate-user-headers", "-mcpu=v3"],
    ["-fno-modules-validate-textual-header-includes", "-mcpu=v3"],
    ["-fno-ms-tls-guards", "-mcpu=v3"],
    ["-fno-new-infallible", "-mcpu=v3"],
    ["-fno-objc-avoid-heapify-local-blocks", "-mcpu=v3"],
    ["-fno-objc-infer-related-result-type", "-mcpu=v3"],
    ["-fno-offload-lto", "-mcpu=v3"],
    ["-fno-offload-uniform-block", "-mcpu=v3"],
    ["-fno-offload-via-llvm", "-mcpu=v3"],
    ["-fno-openmp-extensions", "-mcpu=v3"],
    ["-fno-openmp-new-driver", "-mcpu=v3"],
    ["-fno-operator-names", "-mcpu=v3"],
    ["-fno-optimize-sibling-calls", "-mcpu=v3"],
    ["-fno-pch-codegen", "-mcpu=v3"],
    ["-fno-pch-debuginfo", "-mcpu=v3"],
    ["-fno-plt", "-mcpu=v3"],
    ["-fno-preserve-as-comments", "-mcpu=v3"],
    ["-fno-profile-generate", "-mcpu=v3"],
    ["-fno-profile-instr-generate", "-mcpu=v3"],
    ["-fno-profile-instr-use", "-mcpu=v3"],
    ["-fno-pseudo-probe-for-profiling", "-mcpu=v3"],
    ["-fno-raw-string-literals", "-mcpu=v3"],
    ["-fno-register-global-dtors-with-atexit", "-mcpu=v3"],
    ["-fno-rtlib-add-rpath", "-mcpu=v3"],
    ["-fno-rtlib-defaultlib", "-mcpu=v3"],
    ["-fno-rtti", "-mcpu=v3"],
    ["-fno-rtti-data", "-mcpu=v3"],
    ["-fno-sanitize-address-globals-dead-stripping", "-mcpu=v3"],
    ["-fno-sanitize-address-outline-instrumentation", "-mcpu=v3"],
    ["-fno-sanitize-address-poison-custom-array-cookie", "-mcpu=v3"],
    ["-fno-sanitize-address-use-after-scope", "-mcpu=v3"],
    ["-fno-sanitize-address-use-odr-indicator", "-mcpu=v3"],
    ["-fno-sanitize-annotate-debug-info", "-mcpu=v3"],
    ["-fno-sanitize-cfi-canonical-jump-tables", "-mcpu=v3"],
    ["-fno-sanitize-cfi-cross-dso", "-mcpu=v3"],
    ["-fno-sanitize-hwaddress-experimental-aliasing", "-mcpu=v3"],
    ["-fno-sanitize-ignorelist", "-mcpu=v3"],
    ["-fno-sanitize-memory-param-retval", "-mcpu=v3"],
    ["-fno-sanitize-memory-track-origins", "-mcpu=v3"],
    ["-fno-sanitize-memory-use-after-dtor", "-mcpu=v3"],
    ["-fno-sanitize-merge", "-mcpu=v3"],
    ["-fno-sanitize-recover", "-mcpu=v3"],
    ["-fno-sanitize-stable-abi", "-mcpu=v3"],
    ["-fno-sanitize-stats", "-mcpu=v3"],
    ["-fno-sanitize-thread-atomics", "-mcpu=v3"],
    ["-fno-sanitize-thread-func-entry-exit", "-mcpu=v3"],
    ["-fno-sanitize-thread-memory-access", "-mcpu=v3"],
    ["-fno-sanitize-trap", "-mcpu=v3"],
    ["-fno-short-wchar", "-mcpu=v3"],
    ["-fno-show-column", "-mcpu=v3"],
    ["-fno-show-source-location", "-mcpu=v3"],
    ["-fno-signed-char", "-mcpu=v3"],
    ["-fno-signed-zeros", "-mcpu=v3"],
    ["-fno-skip-odr-check-in-gmf", "-mcpu=v3"],
    ["-fno-spell-checking", "-mcpu=v3"],
    ["-fno-split-machine-functions", "-mcpu=v3"],
    ["-fno-split-stack", "-mcpu=v3"],
    ["-fno-stack-clash-protection", "-mcpu=v3"],
    ["-fno-stack-protector", "-mcpu=v3"],
    ["-fno-standalone-debug", "-mcpu=v3"],
    ["-fno-strict-aliasing", "-mcpu=v3"],
    ["-fno-strict-float-cast-overflow", "-mcpu=v3"],
    ["-fno-strict-return", "-mcpu=v3"],
    ["-fno-swift-version-independent-apinotes", "-mcpu=v3"],
    ["-fno-sycl", "-mcpu=v3"],
    ["-fno-temp-file", "-mcpu=v3"],
    ["-fno-threadsafe-statics", "-mcpu=v3"],
    ["-fno-trigraphs", "-mcpu=v3"],
    ["-fno-unified-lto", "-mcpu=v3"],
    ["-fno-unique-section-names", "-mcpu=v3"],
    ["-fno-unroll-loops", "-mcpu=v3"],
    ["-fno-use-cxa-atexit", "-mcpu=v3"],
    ["-fno-use-init-array", "-mcpu=v3"],
    ["-fno-verify-intermediate-code", "-mcpu=v3"],
    ["-fno-visibility-inlines-hidden-static-local-var", "-mcpu=v3"],
    ["-fno-xray-function-index", "-mcpu=v3"],
    ["-fno-zero-initialized-in-bss", "-mcpu=v3"],
    ["-fno-zos-extensions", "-mcpu=v3"],
    ["-fobjc-arc", "-mcpu=v3"],
    ["-fobjc-arc-exceptions", "-mcpu=v3"],
    ["-fobjc-avoid-heapify-local-blocks", "-mcpu=v3"],
    ["-fobjc-disable-direct-methods-for-testing", "-mcpu=v3"],
    ["-fobjc-encode-cxx-class-template-spec", "-mcpu=v3"],
    ["-fobjc-exceptions", "-mcpu=v3"],
    ["-fobjc-weak", "-mcpu=v3"],
    ["-foffload-implicit-host-device-templates", "-mcpu=v3"],
    ["-foffload-lto", "-mcpu=v3"],
    ["-foffload-uniform-block", "-mcpu=v3"],
    ["-foffload-via-llvm", "-mcpu=v3"],
    ["-fomit-frame-pointer", "-mcpu=v3"],
    ["-fopenacc", "-mcpu=v3"],
    ["-fopenmp", "-mcpu=v3"],
    ["-fopenmp-assume-no-nested-parallelism", "-mcpu=v3"],
    ["-fopenmp-assume-no-thread-state", "-mcpu=v3"],
    ["-fopenmp-enable-irbuilder", "-mcpu=v3"],
    ["-fopenmp-extensions", "-mcpu=v3"],
    ["-fopenmp-force-usm", "-mcpu=v3"],
    ["-fopenmp-new-driver", "-mcpu=v3"],
    ["-fopenmp-offload-mandatory", "-mcpu=v3"],
    ["-fopenmp-simd", "-mcpu=v3"],
    ["-fopenmp-target-debug", "-mcpu=v3"],
    ["-fopenmp-target-jit", "-mcpu=v3"],
    ["-fpack-struct", "-mcpu=v3"],
    ["-fpascal-strings", "-mcpu=v3"],
    ["-fpcc-struct-return", "-mcpu=v3"],
    ["-fpch-codegen", "-mcpu=v3"],
    ["-fpch-debuginfo", "-mcpu=v3"],
    ["-fpch-instantiate-templates", "-mcpu=v3"],
    ["-fpch-validate-input-files-content", "-mcpu=v3"],
    ["-fplugin-arg-", "-mcpu=v3"],
    ["-fprebuilt-implicit-modules", "-mcpu=v3"],
    ["-fproc-stat-report", "-mcpu=v3"],
    ["-fprofile-arcs", "-mcpu=v3"],
    ["-fprofile-continuous", "-mcpu=v3"],
    ["-fprofile-generate", "-mcpu=v3"],
    ["-fprofile-generate-cold-function-coverage", "-mcpu=v3"],
    ["-fprofile-instr-generate", "-mcpu=v3"],
    ["-fprofile-instr-use", "-mcpu=v3"],
    ["-fprofile-sample-accurate", "-mcpu=v3"],
    ["-fprofile-use", "-mcpu=v3"],
    ["-fprotect-parens", "-mcpu=v3"],
    ["-fpseudo-probe-for-profiling", "-mcpu=v3"],
    ["-fptrauth-auth-traps", "-mcpu=v3"],
    ["-fptrauth-block-descriptor-pointers", "-mcpu=v3"],
    ["-fptrauth-calls", "-mcpu=v3"],
    ["-fptrauth-elf-got", "-mcpu=v3"],
    ["-fptrauth-function-pointer-type-discrimination", "-mcpu=v3"],
    ["-fptrauth-indirect-gotos", "-mcpu=v3"],
    ["-fptrauth-init-fini", "-mcpu=v3"],
    ["-fptrauth-init-fini-address-discrimination", "-mcpu=v3"],
    ["-fptrauth-intrinsics", "-mcpu=v3"],
    ["-fptrauth-objc-class-ro", "-mcpu=v3"],
    ["-fptrauth-objc-interface-sel", "-mcpu=v3"],
    ["-fptrauth-objc-isa", "-mcpu=v3"],
    ["-fptrauth-returns", "-mcpu=v3"],
    ["-fptrauth-type-info-vtable-pointer-discrimination", "-mcpu=v3"],
    ["-fptrauth-vtable-pointer-address-discrimination", "-mcpu=v3"],
    ["-fptrauth-vtable-pointer-type-discrimination", "-mcpu=v3"],
    ["-fraw-string-literals", "-mcpu=v3"],
    ["-freciprocal-math", "-mcpu=v3"],
    ["-frecord-command-line", "-mcpu=v3"],
    ["-freg-struct-return", "-mcpu=v3"],
    ["-fregister-global-dtors-with-atexit", "-mcpu=v3"],
    ["-fropi", "-mcpu=v3"],
    ["-frtlib-add-rpath", "-mcpu=v3"],
    ["-frtlib-defaultlib", "-mcpu=v3"],
    ["-frwpi", "-mcpu=v3"],
    ["-fsafe-buffer-usage-suggestions", "-mcpu=v3"],
    ["-fsample-profile-use-profi", "-mcpu=v3"],
    ["-fsanitize-address-globals-dead-stripping", "-mcpu=v3"],
    ["-fsanitize-address-outline-instrumentation", "-mcpu=v3"],
    ["-fsanitize-address-poison-custom-array-cookie", "-mcpu=v3"],
    ["-fsanitize-address-use-after-scope", "-mcpu=v3"],
    ["-fsanitize-address-use-odr-indicator", "-mcpu=v3"],
    ["-fsanitize-annotate-debug-info", "-mcpu=v3"],
    ["-fsanitize-cfi-canonical-jump-tables", "-mcpu=v3"],
    ["-fsanitize-cfi-cross-dso", "-mcpu=v3"],
    ["-fsanitize-cfi-icall-experimental-normalize-integers", "-mcpu=v3"],
    ["-fsanitize-cfi-icall-generalize-pointers", "-mcpu=v3"],
    ["-fsanitize-hwaddress-experimental-aliasing", "-mcpu=v3"],
    ["-fsanitize-kcfi-arity", "-mcpu=v3"],
    ["-fsanitize-memory-param-retval", "-mcpu=v3"],
    ["-fsanitize-memory-track-origins", "-mcpu=v3"],
    ["-fsanitize-memory-use-after-dtor", "-mcpu=v3"],
    ["-fsanitize-merge", "-mcpu=v3"],
    ["-fsanitize-recover", "-mcpu=v3"],
    ["-fsanitize-stable-abi", "-mcpu=v3"],
    ["-fsanitize-stats", "-mcpu=v3"],
    ["-fsanitize-thread-atomics", "-mcpu=v3"],
    ["-fsanitize-thread-func-entry-exit", "-mcpu=v3"],
    ["-fsanitize-thread-memory-access", "-mcpu=v3"],
    ["-fsanitize-trap", "-mcpu=v3"],
    ["-fsave-optimization-record", "-mcpu=v3"],
    ["-fseh-exceptions", "-mcpu=v3"],
    ["-fseparate-named-sections", "-mcpu=v3"],
    ["-fshort-enums", "-mcpu=v3"],
    ["-fshort-wchar", "-mcpu=v3"],
    ["-fshow-skipped-includes", "-mcpu=v3"],
    ["-fsigned-char", "-mcpu=v3"],
    ["-fsized-deallocation", "-mcpu=v3"],
    ["-fsjlj-exceptions", "-mcpu=v3"],
    ["-fskip-odr-check-in-gmf", "-mcpu=v3"],
    ["-fslp-vectorize", "-mcpu=v3"],
    ["-fsplit-dwarf-inlining", "-mcpu=v3"],
    ["-fsplit-lto-unit", "-mcpu=v3"],
    ["-fsplit-machine-functions", "-mcpu=v3"],
    ["-fsplit-stack", "-mcpu=v3"],
    ["-fstack-clash-protection", "-mcpu=v3"],
    ["-fstack-protector", "-mcpu=v3"],
    ["-fstack-protector-all", "-mcpu=v3"],
    ["-fstack-protector-strong", "-mcpu=v3"],
    ["-fstack-size-section", "-mcpu=v3"],
    ["-fstack-usage", "-mcpu=v3"],
    ["-fstandalone-debug", "-mcpu=v3"],
    ["-fstrict-aliasing", "-mcpu=v3"],
    ["-fstrict-enums", "-mcpu=v3"],
    ["-fstrict-float-cast-overflow", "-mcpu=v3"],
    ["-fstrict-vtable-pointers", "-mcpu=v3"],
    ["-fswift-version-independent-apinotes", "-mcpu=v3"],
    ["-fsycl", "-mcpu=v3"],
    ["-fsycl-device-only", "-mcpu=v3"],
    ["-fsycl-host-only", "-mcpu=v3"],
    ["-fsyntax-only", "-mcpu=v3"],
    ["-fsystem-module", "-mcpu=v3"],
    ["-ftemporal-profile", "-mcpu=v3"],
    ["-ftest-coverage", "-mcpu=v3"],
    ["-ftime-report", "-mcpu=v3"],
    ["-ftime-trace", "-mcpu=v3"],
    ["-ftime-trace-verbose", "-mcpu=v3"],
    ["-ftrapv", "-mcpu=v3"],
    ["-ftrigraphs", "-mcpu=v3"],
    ["-funified-lto", "-mcpu=v3"],
    ["-funique-basic-block-section-names", "-mcpu=v3"],
    ["-funique-internal-linkage-names", "-mcpu=v3"],
    ["-funique-source-file-names", "-mcpu=v3"],
    ["-funroll-loops", "-mcpu=v3"],
    ["-funsafe-math-optimizations", "-mcpu=v3"],
    ["-fuse-line-directives", "-mcpu=v3"],
    ["-fvalidate-ast-input-files-content", "-mcpu=v3"],
    ["-fvectorize", "-mcpu=v3"],
    ["-fverbose-asm", "-mcpu=v3"],
    ["-fverify-intermediate-code", "-mcpu=v3"],
    ["-fvirtual-function-elimination", "-mcpu=v3"],
    ["-fvisibility-from-dllstorageclass", "-mcpu=v3"],
    ["-fvisibility-global-new-delete-hidden", "-mcpu=v3"],
    ["-fvisibility-inlines-hidden", "-mcpu=v3"],
    ["-fvisibility-inlines-hidden-static-local-var", "-mcpu=v3"],
    ["-fvisibility-ms-compat", "-mcpu=v3"],
    ["-fwasm-exceptions", "-mcpu=v3"],
    ["-fwhole-program-vtables", "-mcpu=v3"],
    ["-fwrapv", "-mcpu=v3"],
    ["-fwrapv-pointer", "-mcpu=v3"],
    ["-fwritable-strings", "-mcpu=v3"],
    ["-fxl-pragma-pack", "-mcpu=v3"],
    ["-fxray-always-emit-customevents", "-mcpu=v3"],
    ["-fxray-always-emit-typedevents", "-mcpu=v3"],
    ["-fxray-ignore-loops", "-mcpu=v3"],
    ["-fxray-instrument", "-mcpu=v3"],
    ["-fxray-link-deps", "-mcpu=v3"],
    ["-fxray-shared", "-mcpu=v3"],
    ["-fzos-extensions", "-mcpu=v3"],
    ["-fzvector", "-mcpu=v3"],
    ["-ibuiltininc", "-mcpu=v3"],
    ["-ignore-pch", "-mcpu=v3"],
    ["-linker", "-mcpu=v3"],
    ["-load", "-mcpu=v3"],
    ["-m16", "-mcpu=v3"],
    ["-m32", "-mcpu=v3"],
    ["-m64", "-mcpu=v3"],
    ["-mabicalls", "-mcpu=v3"],
    ["-maix-shared-lib-tls-model-opt", "-mcpu=v3"],
    ["-maix-small-local-dynamic-tls", "-mcpu=v3"],
    ["-maix-small-local-exec-tls", "-mcpu=v3"],
    ["-maix-struct-return", "-mcpu=v3"],
    ["-malign-double", "-mcpu=v3"],
    ["-maltivec", "-mcpu=v3"],
    ["-mamdgpu-ieee", "-mcpu=v3"],
    ["-mamdgpu-precise-memory-op", "-mcpu=v3"],
    ["-mannotate-tablejump", "-mcpu=v3"],
    ["-mapx-inline-asm-use-gpr32", "-mcpu=v3"],
    ["-marm", "-mcpu=v3"],
    ["-marm64x", "-mcpu=v3"],
    ["-mbackchain", "-mcpu=v3"],
    ["-mbranches-within-32B-boundaries", "-mcpu=v3"],
    ["-mcabac", "-mcpu=v3"],
    ["-mcmse", "-mcpu=v3"],
    ["-mconstructor-aliases", "-mcpu=v3"],
    ["-mcrbits", "-mcpu=v3"],
    ["-mcrc", "-mcpu=v3"],
    ["-mcumode", "-mcpu=v3"],
    ["-mdaz-ftz", "-mcpu=v3"],
    ["-mdiv32", "-mcpu=v3"],
    ["-membedded-data", "-mcpu=v3"],
    ["-menable-experimental-extensions", "-mcpu=v3"],
    ["-mexecute-only", "-mcpu=v3"],
    ["-mextern-sdata", "-mcpu=v3"],
    ["-mfentry", "-mcpu=v3"],
    ["-mfix-cmse-cve-2021-35465", "-mcpu=v3"],
    ["-mfix-cortex-a53-835769", "-mcpu=v3"],
    ["-mfix-cortex-a53-843419", "-mcpu=v3"],
    ["-mfix-cortex-a57-aes-1742098", "-mcpu=v3"],
    ["-mfix-cortex-a72-aes-1655431", "-mcpu=v3"],
    ["-mfix-gr712rc", "-mcpu=v3"],
    ["-mfix-ut700", "-mcpu=v3"],
    ["-mfp32", "-mcpu=v3"],
    ["-mfp64", "-mcpu=v3"],
    ["-mfpxx", "-mcpu=v3"],
    ["-mfrecipe", "-mcpu=v3"],
    ["-mgeneral-regs-only", "-mcpu=v3"],
    ["-mglobal-merge", "-mcpu=v3"],
    ["-mgpopt", "-mcpu=v3"],
    ["-mhvx", "-mcpu=v3"],
    ["-mhvx-ieee-fp", "-mcpu=v3"],
    ["-mhvx-qfloat", "-mcpu=v3"],
    ["-mignore-xcoff-visibility", "-mcpu=v3"],
    ["-mincremental-linker-compatible", "-mcpu=v3"],
    ["-mindirect-branch-cs-prefix", "-mcpu=v3"],
    ["-mips1", "-mcpu=v3"],
    ["-mips2", "-mcpu=v3"],
    ["-mips3", "-mcpu=v3"],
    ["-mips32", "-mcpu=v3"],
    ["-mips32r2", "-mcpu=v3"],
    ["-mips32r3", "-mcpu=v3"],
    ["-mips32r5", "-mcpu=v3"],
    ["-mips32r6", "-mcpu=v3"],
    ["-mips4", "-mcpu=v3"],
    ["-mips5", "-mcpu=v3"],
    ["-mips64", "-mcpu=v3"],
    ["-mips64r2", "-mcpu=v3"],
    ["-mips64r3", "-mcpu=v3"],
    ["-mips64r5", "-mcpu=v3"],
    ["-mips64r6", "-mcpu=v3"],
    ["-mlam-bh", "-mcpu=v3"],
    ["-mlamcas", "-mcpu=v3"],
    ["-mlasx", "-mcpu=v3"],
    ["-mld-seq-sa", "-mcpu=v3"],
    ["-mlink-builtin-bitcode-postopt", "-mcpu=v3"],
    ["-mlittle-endian", "-mcpu=v3"],
    ["-mlocal-sdata", "-mcpu=v3"],
    ["-mlong-calls", "-mcpu=v3"],
    ["-mlong-double-128", "-mcpu=v3"],
    ["-mlong-double-64", "-mcpu=v3"],
    ["-mlong-double-80", "-mcpu=v3"],
    ["-mlr-for-calls-only", "-mcpu=v3"],
    ["-mlsx", "-mcpu=v3"],
    ["-mlvi-cfi", "-mcpu=v3"],
    ["-mlvi-hardening", "-mcpu=v3"],
    ["-mmadd4", "-mcpu=v3"],
    ["-mmark-bti-property", "-mcpu=v3"],
    ["-mmemops", "-mcpu=v3"],
    ["-mms-bitfields", "-mcpu=v3"],
    ["-mmsa", "-mcpu=v3"],
    ["-mmt", "-mcpu=v3"],
    ["-mno-abicalls", "-mcpu=v3"],
    ["-mno-amdgpu-precise-memory-op", "-mcpu=v3"],
    ["-mno-annotate-tablejump", "-mcpu=v3"],
    ["-mno-bti-at-return-twice", "-mcpu=v3"],
    ["-mno-constructor-aliases", "-mcpu=v3"],
    ["-mno-crc", "-mcpu=v3"],
    ["-mno-cumode", "-mcpu=v3"],
    ["-mno-daz-ftz", "-mcpu=v3"],
    ["-mno-div32", "-mcpu=v3"],
    ["-mno-embedded-data", "-mcpu=v3"],
    ["-mno-execute-only", "-mcpu=v3"],
    ["-mno-extern-sdata", "-mcpu=v3"],
    ["-mno-fix-cmse-cve-2021-35465", "-mcpu=v3"],
    ["-mno-fix-cortex-a53-835769", "-mcpu=v3"],
    ["-mno-fix-cortex-a53-843419", "-mcpu=v3"],
    ["-mno-fix-cortex-a57-aes-1742098", "-mcpu=v3"],
    ["-mno-fix-cortex-a72-aes-1655431", "-mcpu=v3"],
    ["-mno-fmv", "-mcpu=v3"],
    ["-mno-frecipe", "-mcpu=v3"],
    ["-mno-gather", "-mcpu=v3"],
    ["-mno-global-merge", "-mcpu=v3"],
    ["-mno-gpopt", "-mcpu=v3"],
    ["-mno-hvx", "-mcpu=v3"],
    ["-mno-hvx-ieee-fp", "-mcpu=v3"],
    ["-mno-hvx-qfloat", "-mcpu=v3"],
    ["-mno-implicit-float", "-mcpu=v3"],
    ["-mno-incremental-linker-compatible", "-mcpu=v3"],
    ["-mno-lam-bh", "-mcpu=v3"],
    ["-mno-lamcas", "-mcpu=v3"],
    ["-mno-lasx", "-mcpu=v3"],
    ["-mno-ld-seq-sa", "-mcpu=v3"],
    ["-mno-local-sdata", "-mcpu=v3"],
    ["-mno-long-calls", "-mcpu=v3"],
    ["-mno-lsx", "-mcpu=v3"],
    ["-mno-lvi-cfi", "-mcpu=v3"],
    ["-mno-lvi-hardening", "-mcpu=v3"],
    ["-mno-madd4", "-mcpu=v3"],
    ["-mno-memops", "-mcpu=v3"],
    ["-mno-movt", "-mcpu=v3"],
    ["-mno-ms-bitfields", "-mcpu=v3"],
    ["-mno-msa", "-mcpu=v3"],
    ["-mno-mt", "-mcpu=v3"],
    ["-mno-neg-immediates", "-mcpu=v3"],
    ["-mno-nvj", "-mcpu=v3"],
    ["-mno-nvs", "-mcpu=v3"],
    ["-mno-odd-spreg", "-mcpu=v3"],
    ["-mno-outline", "-mcpu=v3"],
    ["-mno-outline-atomics", "-mcpu=v3"],
    ["-mno-packets", "-mcpu=v3"],
    ["-mno-pic-data-is-text-relative", "-mcpu=v3"],
    ["-mno-regnames", "-mcpu=v3"],
    ["-mno-relax", "-mcpu=v3"],
    ["-mno-relax-pic-calls", "-mcpu=v3"],
    ["-mno-restrict-it", "-mcpu=v3"],
    ["-mno-save-restore", "-mcpu=v3"],
    ["-mno-scalar-strict-align", "-mcpu=v3"],
    ["-mno-scatter", "-mcpu=v3"],
    ["-mno-scq", "-mcpu=v3"],
    ["-mno-seses", "-mcpu=v3"],
    ["-mno-stack-arg-probe", "-mcpu=v3"],
    ["-mno-strict-align", "-mcpu=v3"],
    ["-mno-tgsplit", "-mcpu=v3"],
    ["-mno-tls-direct-seg-refs", "-mcpu=v3"],
    ["-mno-tocdata", "-mcpu=v3"],
    ["-mno-unaligned-access", "-mcpu=v3"],
    ["-mno-unaligned-symbols", "-mcpu=v3"],
    ["-mno-v8plus", "-mcpu=v3"],
    ["-mno-vector-strict-align", "-mcpu=v3"],
    ["-mno-wavefrontsize64", "-mcpu=v3"],
    ["-mnocrc", "-mcpu=v3"],
    ["-mnop-mcount", "-mcpu=v3"],
    ["-mnvj", "-mcpu=v3"],
    ["-mnvs", "-mcpu=v3"],
    ["-modd-spreg", "-mcpu=v3"],
    ["-module-file-info", "-mcpu=v3"],
    ["-momit-leaf-frame-pointer", "-mcpu=v3"],
    ["-moutline", "-mcpu=v3"],
    ["-moutline-atomics", "-mcpu=v3"],
    ["-mpacked-stack", "-mcpu=v3"],
    ["-mpackets", "-mcpu=v3"],
    ["-mpic-data-is-text-relative", "-mcpu=v3"],
    ["-mqdsp6-compat", "-mcpu=v3"],
    ["-mrecip", "-mcpu=v3"],
    ["-mrecord-mcount", "-mcpu=v3"],
    ["-mregnames", "-mcpu=v3"],
    ["-mrelax", "-mcpu=v3"],
    ["-mrelax-all", "-mcpu=v3"],
    ["-mrelax-pic-calls", "-mcpu=v3"],
    ["-mrestrict-it", "-mcpu=v3"],
    ["-mrtd", "-mcpu=v3"],
    ["-msave-reg-params", "-mcpu=v3"],
    ["-msave-restore", "-mcpu=v3"],
    ["-mscalar-strict-align", "-mcpu=v3"],
    ["-mscq", "-mcpu=v3"],
    ["-mseses", "-mcpu=v3"],
    ["-mskip-rax-setup", "-mcpu=v3"],
    ["-msoft-float", "-mcpu=v3"],
    ["-msse2avx", "-mcpu=v3"],
    ["-mstack-arg-probe", "-mcpu=v3"],
    ["-mstackrealign", "-mcpu=v3"],
    ["-mstrict-align", "-mcpu=v3"],
    ["-msvr4-struct-return", "-mcpu=v3"],
    ["-mtgsplit", "-mcpu=v3"],
    ["-mthumb", "-mcpu=v3"],
    ["-mtls-direct-seg-refs", "-mcpu=v3"],
    ["-mtocdata", "-mcpu=v3"],
    ["-munaligned-access", "-mcpu=v3"],
    ["-munaligned-symbols", "-mcpu=v3"],
    ["-mv8plus", "-mcpu=v3"],
    ["-mvector-strict-align", "-mcpu=v3"],
    ["-mvevpu", "-mcpu=v3"],
    ["-mwavefrontsize64", "-mcpu=v3"],
    ["-mx32", "-mcpu=v3"],
    ["-mxcoff-roptr", "-mcpu=v3"],
    ["-no-canonical-prefixes", "-mcpu=v3"],
    ["-no-hip-rt", "-mcpu=v3"],
    ["-nobuiltininc", "-mcpu=v3"],
    ["-nodefaultlibs", "-mcpu=v3"],
    ["-nohipwrapperinc", "-mcpu=v3"],
    ["-nostartfiles", "-mcpu=v3"],
    ["-nostdinc", "-mcpu=v3"],
    ["-nostdinc++", "-mcpu=v3"],
    ["-nostdlib", "-mcpu=v3"],
    ["-nostdlibinc", "-mcpu=v3"],
    ["-order_file", "-mcpu=v3"],
    ["-p", "-mcpu=v3"],
    ["-pedantic", "-mcpu=v3"],
    ["-pg", "-mcpu=v3"],
    ["-pie", "-mcpu=v3"],
    ["-pipe", "-mcpu=v3"],
    ["-print-enabled-extensions", "-mcpu=v3"],
    ["-print-ivar-layout", "-mcpu=v3"],
    ["-print-rocm-search-dirs", "-mcpu=v3"],
    ["-print-supported-cpus", "-mcpu=v3"],
    ["-print-supported-extensions", "-mcpu=v3"],
    ["-pthread", "-mcpu=v3"],
    ["-r", "-mcpu=v3"],
    ["-rdynamic", "-mcpu=v3"],
    ["-regcall4", "-mcpu=v3"],
    ["-relocatable-pch", "-mcpu=v3"],
    ["-rewrite-legacy-objc", "-mcpu=v3"],
    ["-rewrite-objc", "-mcpu=v3"],
    ["-s", "-mcpu=v3"],
    ["-save-stats", "-mcpu=v3"],
    ["-save-temps", "-mcpu=v3"],
    ["-shared", "-mcpu=v3"],
    ["-shared-libsan", "-mcpu=v3"],
    ["-static", "-mcpu=v3"],
    ["-static-libclosure", "-mcpu=v3"],
    ["-static-libsan", "-mcpu=v3"],
    ["-static-openmp", "-mcpu=v3"],
    ["-stdlib", "-mcpu=v3"],
    ["-t", "-mcpu=v3"],
    ["-time", "-mcpu=v3"],
    ["-traditional", "-mcpu=v3"],
    ["-traditional-cpp", "-mcpu=v3"],
    ["-trigraphs", "-mcpu=v3"],
    ["-twolevel_namespace", "-mcpu=v3"],
    ["-undef", "-mcpu=v3"],
    ["-unwindlib", "-mcpu=v3"],
    ["-use-ld", "-mcpu=v3"],
    ["-v", "-mcpu=v3"],
    ["-verify-pch", "-mcpu=v3"],
    ["-via-file-asm", "-mcpu=v3"],
    ["-w", "-mcpu=v3"],
    ["-whyload", "-mcpu=v3"],
    ["-y", "-mcpu=v3"],
    ["--cuda-path=/a", "-mcpu=v3"],
    ["--embed-dir=/a", "-mcpu=v3"],
    ["--extract-api-ignores=1", "-mcpu=v3"],
    ["--gcc-install-dir=/a", "-mcpu=v3"],
    ["--gcc-toolchain=1", "-mcpu=v3"],
    ["--gcc-triple=1", "-mcpu=v3"],
    ["--hip-path=/a", "-mcpu=v3"],
    ["--rocm-path=/a", "-mcpu=v3"],
    ["--rsp-quoting=1", "-mcpu=v3"],
    ["--symbol-graph-dir=/a", "-mcpu=v3"],
    ["--unwindlib=1", "-mcpu=v3"],
    ["--warning-suppression-mappings=/a", "-mcpu=v3"],
    ["-cl-ext=1", "-mcpu=v3"],
    ["-cl-std=c11", "-mcpu=v3"],
    ["-fallow-runtime-check-skip-hot-cutoff=1", "-mcpu=v3"],
    ["-faltivec-src-compat=1", "-mcpu=v3"],
    ["-fapinotes-swift-version=1", "-mcpu=v3"],
    ["-fbasic-block-sections=1", "-mcpu=v3"],
    ["-fbinutils-version=1", "-mcpu=v3"],
    ["-fbuild-session-file=/a", "-mcpu=v3"],
    ["-fbuild-session-timestamp=1", "-mcpu=v3"],
    ["-fc++-abi=1", "-mcpu=v3"],
    ["-fcaret-diagnostics-max-lines=1", "-mcpu=v3"],
    ["-fclang-abi-compat=1", "-mcpu=v3"],
    ["-fcomment-block-commands=1", "-mcpu=v3"],
    ["-fcomplex-arithmetic=full", "-mcpu=v3"],
    ["-fconstexpr-backtrace-limit=1", "-mcpu=v3"],
    ["-fconstexpr-depth=1", "-mcpu=v3"],
    ["-fconstexpr-steps=1", "-mcpu=v3"],
    ["-fcoverage-compilation-dir=/a", "-mcpu=v3"],
    ["-fcoverage-prefix-map=/a", "-mcpu=v3"],
    ["-fcrash-diagnostics-dir=/a", "-mcpu=v3"],
    ["-fdebug-default-version=1", "-mcpu=v3"],
    ["-fdebug-prefix-map=/a", "-mcpu=v3"],
    ["-fdiagnostics-hotness-threshold=1", "-mcpu=v3"],
    ["-fdiagnostics-misexpect-tolerance=1", "-mcpu=v3"],
    ["-femit-dwarf-unwind=1", "-mcpu=v3"],
    ["-fexcess-precision=standard", "-mcpu=v3"],
    ["-fexperimental-sanitize-metadata=1", "-mcpu=v3"],
    ["-fexperimental-sanitize-metadata-ignorelist=/a", "-mcpu=v3"],
    ["-fextend-arguments=1", "-mcpu=v3"],
    ["-ffile-compilation-dir=/a", "-mcpu=v3"],
    ["-ffile-prefix-map=/a", "-mcpu=v3"],
    ["-ffp-contract=fast", "-mcpu=v3"],
    ["-ffp-eval-method=source", "-mcpu=v3"],
    ["-ffp-exception-behavior=strict", "-mcpu=v3"],
    ["-ffp-model=precise", "-mcpu=v3"],
    ["-ffuchsia-api-level=1", "-mcpu=v3"],
    ["-fgnuc-version=1", "-mcpu=v3"],
    ["-finline-max-stacksize=1", "-mcpu=v3"],
    ["-finput-charset=/a", "-mcpu=v3"],
    ["-flto-jobs=1", "-mcpu=v3"],
    ["-flto-partitions=1", "-mcpu=v3"],
    ["-fmacro-backtrace-limit=1", "-mcpu=v3"],
    ["-fmacro-prefix-map=/a", "-mcpu=v3"],
    ["-fmax-tokens=1", "-mcpu=v3"],
    ["-fmax-type-align=1", "-mcpu=v3"],
    ["-fmemory-profile-use=/a", "-mcpu=v3"],
    ["-fmessage-length=1", "-mcpu=v3"],
    ["-fmodule-file=/a", "-mcpu=v3"],
    ["-fmodule-map-file=/a", "-mcpu=v3"],
    ["-fmodule-name=1", "-mcpu=v3"],
    ["-fmodules-cache-path=/a", "-mcpu=v3"],
    ["-fmodules-ignore-macro=1", "-mcpu=v3"],
    ["-fmodules-prune-after=1", "-mcpu=v3"],
    ["-fmodules-prune-interval=1", "-mcpu=v3"],
    ["-fms-compatibility-version=1", "-mcpu=v3"],
    ["-fms-runtime-lib=1", "-mcpu=v3"],
    ["-fms-secure-hotpatch-functions-file=/a", "-mcpu=v3"],
    ["-fms-secure-hotpatch-functions-list=/a", "-mcpu=v3"],
    ["-fmsc-version=1", "-mcpu=v3"],
    ["-fno-experimental-sanitize-metadata=1", "-mcpu=v3"],
    ["-fno-sanitize-coverage=1", "-mcpu=v3"],
    ["-fobjc-runtime=1", "-mcpu=v3"],
    ["-fopenmp-version=1", "-mcpu=v3"],
    ["-foperator-arrow-depth=1", "-mcpu=v3"],
    ["-foptimization-record-file=/a", "-mcpu=v3"],
    ["-foptimization-record-passes=1", "-mcpu=v3"],
    ["-fpatchable-function-entry=1", "-mcpu=v3"],
    ["-fprebuilt-module-path=/a", "-mcpu=v3"],
    ["-fprofile-dir=/a", "-mcpu=v3"],
    ["-fprofile-exclude-files=/a", "-mcpu=v3"],
    ["-fprofile-filter-files=/a", "-mcpu=v3"],
    ["-fprofile-function-groups=/a", "-mcpu=v3"],
    ["-fprofile-list=/a", "-mcpu=v3"],
    ["-fprofile-remapping-file=/a", "-mcpu=v3"],
    ["-fprofile-sample-use=/a", "-mcpu=v3"],
    ["-fprofile-selected-function-group=/a", "-mcpu=v3"],
    ["-fprofile-update=/a", "-mcpu=v3"],
    ["-frandomize-layout-seed=42", "-mcpu=v3"],
    ["-frandomize-layout-seed-file=/a", "-mcpu=v3"],
    ["-fsanitize=address", "-mcpu=v3"],
    ["-fsanitize-address-destructor=1", "-mcpu=v3"],
    ["-fsanitize-address-field-padding=1", "-mcpu=v3"],
    ["-fsanitize-address-use-after-return=1", "-mcpu=v3"],
    ["-fsanitize-blacklist=/a", "-mcpu=v3"],
    ["-fsanitize-coverage=trace-pc-guard", "-mcpu=v3"],
    ["-fsanitize-coverage-allowlist=/a", "-mcpu=v3"],
    ["-fsanitize-coverage-ignorelist=/a", "-mcpu=v3"],
    ["-fsanitize-coverage-stack-depth-callback-min=1", "-mcpu=v3"],
    ["-fsanitize-hwaddress-abi=1", "-mcpu=v3"],
    ["-fsanitize-ignorelist=/a", "-mcpu=v3"],
    ["-fsanitize-memtag-mode=1", "-mcpu=v3"],
    ["-fsanitize-skip-hot-cutoff=1", "-mcpu=v3"],
    ["-fsanitize-system-ignorelist=/a", "-mcpu=v3"],
    ["-fsanitize-undefined-ignore-overflow-pattern=1", "-mcpu=v3"],
    ["-fsanitize-undefined-strip-path-components=/a", "-mcpu=v3"],
    ["-fshow-overloads=1", "-mcpu=v3"],
    ["-fspell-checking-limit=1", "-mcpu=v3"],
    ["-fstrict-flex-arrays=1", "-mcpu=v3"],
    ["-fswift-async-fp=1", "-mcpu=v3"],
    ["-ftemplate-backtrace-limit=1", "-mcpu=v3"],
    ["-ftemplate-depth=1", "-mcpu=v3"],
    ["-fthin-link-bitcode=1", "-mcpu=v3"],
    ["-fthinlto-distributor=1", "-mcpu=v3"],
    ["-fthinlto-index=1", "-mcpu=v3"],
    ["-ftime-trace-granularity=1", "-mcpu=v3"],
    ["-ftrap-function=1", "-mcpu=v3"],
    ["-ftrivial-auto-var-init=1", "-mcpu=v3"],
    ["-ftrivial-auto-var-init-max-size=1", "-mcpu=v3"],
    ["-ftrivial-auto-var-init-stop-after=1", "-mcpu=v3"],
    ["-funique-source-file-identifier=/a", "-mcpu=v3"],
    ["-fuse-ld=lld", "-mcpu=v3"],
    ["-fveclib=1", "-mcpu=v3"],
    ["-fvisibility=hidden", "-mcpu=v3"],
    ["-fvisibility-dllexport=1", "-mcpu=v3"],
    ["-fvisibility-externs-dllimport=1", "-mcpu=v3"],
    ["-fvisibility-externs-nodllstorageclass=1", "-mcpu=v3"],
    ["-fvisibility-global-new-delete=1", "-mcpu=v3"],
    ["-fvisibility-nodllstorageclass=1", "-mcpu=v3"],
    ["-fwinx64-eh-unwindv2=1", "-mcpu=v3"],
    ["-fxray-always-instrument=1", "-mcpu=v3"],
    ["-fxray-attr-list=/a", "-mcpu=v3"],
    ["-fxray-function-groups=1", "-mcpu=v3"],
    ["-fxray-instruction-threshold=1", "-mcpu=v3"],
    ["-fxray-instrumentation-bundle=1", "-mcpu=v3"],
    ["-fxray-modes=1", "-mcpu=v3"],
    ["-fxray-never-instrument=1", "-mcpu=v3"],
    ["-fxray-selected-function-group=1", "-mcpu=v3"],
    ["-fzero-call-used-regs=1", "-mcpu=v3"],
    ["-mabi=1", "-mcpu=v3"],
    ["-malign-branch=1", "-mcpu=v3"],
    ["-malign-branch-boundary=1", "-mcpu=v3"],
    ["-mapx-features=/a", "-mcpu=v3"],
    ["-mbranch-protection=1", "-mcpu=v3"],
    ["-mcf-branch-label-scheme=1", "-mcpu=v3"],
    ["-mcode-object-version=1", "-mcpu=v3"],
    ["-mdefault-visibility-export-mapping=/a", "-mcpu=v3"],
    ["-mdouble=1", "-mcpu=v3"],
    ["-mexec-model=1", "-mcpu=v3"],
    ["-mframe-chain=1", "-mcpu=v3"],
    ["-mfunction-return=1", "-mcpu=v3"],
    ["-mguard=1", "-mcpu=v3"],
    ["-mharden-sls=1", "-mcpu=v3"],
    ["-mhvx-length=1", "-mcpu=v3"],
    ["-mindirect-jump=/a", "-mcpu=v3"],
    ["-mios-version-min=1", "-mcpu=v3"],
    ["-mmacos-version-min=1", "-mcpu=v3"],
    ["-mno-apx-features=1", "-mcpu=v3"],
    ["-mpad-max-prefix-size=/a", "-mcpu=v3"],
    ["-mprefer-vector-width=1", "-mcpu=v3"],
    ["-mprintf-kind=1", "-mcpu=v3"],
    ["-mrvv-vector-bits=1", "-mcpu=v3"],
    ["-msign-return-address=1", "-mcpu=v3"],
    ["-msimd=1", "-mcpu=v3"],
    ["-msmall-data-limit=1", "-mcpu=v3"],
    ["-mstack-alignment=1", "-mcpu=v3"],
    ["-mstack-probe-size=1", "-mcpu=v3"],
    ["-mstack-protector-guard=1", "-mcpu=v3"],
    ["-mstack-protector-guard-offset=1", "-mcpu=v3"],
    ["-mstack-protector-guard-reg=1", "-mcpu=v3"],
    ["-mstack-protector-guard-symbol=1", "-mcpu=v3"],
    ["-msve-streaming-vector-bits=1", "-mcpu=v3"],
    ["-msve-vector-bits=1", "-mcpu=v3"],
    ["-mtargetos=1", "-mcpu=v3"],
    ["-mtls-dialect=1", "-mcpu=v3"],
    ["-mtls-size=1", "-mcpu=v3"],
    ["-mtp=1", "-mcpu=v3"],
    ["-mtune=1", "-mcpu=v3"],
    ["-mxcoff-build-id=1", "-mcpu=v3"],
    ["-mzos-hlq-clang=1", "-mcpu=v3"],
    ["-mzos-hlq-csslib=1", "-mcpu=v3"],
    ["-mzos-hlq-le=1", "-mcpu=v3"],
    ["-mzos-sys-include=1", "-mcpu=v3"],
    ["-mzos-target=1", "-mcpu=v3"],
    ["-rtlib=1", "-mcpu=v3"],
    ["-std=c11", "-mcpu=v3"],
    ["-sycl-std=c11", "-mcpu=v3"],
    ["-", "-mcpu=v3"],
])
def test_c_reference_allowlisted_spellings_consume_nothing(extra):
    fixture = reference_selector_fixture(["--target=bpfel"], [], extra=extra)
    assert captured_fixture(fixture, fixture_authority(fixture)).to_dict()["complete"]


def test_capture_actual_retention_limit_includes_independent_input_files(tmp_path, monkeypatch):
    mod = admitted_collector()
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_bytes(b"a" * 4096)
    second.write_bytes(b"b" * 4096)
    monkeypatch.setattr(mod, "MAX_CAPTURE_BYTES", 4096)
    capture = mod._FileCapture()
    original = capture.read(first, limit=4096)
    with pytest.raises(mod.CollectionError) as error:
        capture.read(second, limit=4096)
    assert error.value.code == "input-limit" and error.value.exit_code == 3
    assert list(capture.images.values()) == [original]
    assert sum(len(value) for value in retained_capture_buffers({}, capture).values()) == 4096


def test_capture_duplicate_files_are_each_read_and_hashed_before_sharing(tmp_path, monkeypatch):
    mod = admitted_collector()
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_bytes(b"equal independent bytes\n")
    second.write_bytes(first.read_bytes())
    read, digest = mod._read, mod._sha
    reads, hashed = [], []

    def actual_read(path, *, limit, **kwargs):
        image = read(path, limit=limit, **kwargs)
        reads.append(Path(path))
        return image

    def actual_digest(image):
        hashed.append(id(image))
        return digest(image)

    monkeypatch.setattr(mod, "_read", actual_read)
    monkeypatch.setattr(mod, "_sha", actual_digest)
    capture = mod._FileCapture()
    a, b = capture.read(first, limit=100), capture.read(second, limit=100)
    assert a is b
    assert reads == [first, second] and len(hashed) == 2
    assert len(set(hashed)) == 2
    assert capture.read(second, limit=100) is a and len(reads) == 2


def test_declared_duplicate_digest_does_not_skip_or_admit_different_file_bytes(tmp_path):
    mod = admitted_collector()
    (tmp_path / "first").write_bytes(b"expected\n")
    (tmp_path / "second").write_bytes(b"different\n")
    raw = canonical_json({"schema_version": 1, "kind": "cost-capture-inventory-v1", "entries": [
        {"id": name, "relative_path": name, "role": "source", "size": 9, "sha256": sha(b"expected\n")}
        for name in ("first", "second")]})
    with pytest.raises(mod.CollectionError) as error:
        mod._capture_inventory(raw, tmp_path, mod._FileCapture(), scope="producer")
    assert error.value.exit_code == 4


@pytest.mark.parametrize("failure", ["alias", "limit", "changed"])
def test_capture_failure_closes_opened_descriptor(failure, tmp_path, monkeypatch):
    mod = admitted_collector()
    first, second = tmp_path / "first", tmp_path / "second"
    first.write_bytes(b"bounded input\n")
    second.write_bytes(b"another input\n")
    capture = mod._FileCapture()
    capture.read(first, limit=100)
    if failure == "alias":
        second.unlink()
        mod.os.link(first, second)
    checked = mod._open_checked
    descriptors = []

    def actual_open(path, *, directory):
        fd = checked(path, directory=directory)
        if Path(path) == second and not directory:
            descriptors.append(fd)
        return fd

    monkeypatch.setattr(mod, "_open_checked", actual_open)
    if failure == "changed":
        fdopen = mod.os.fdopen

        class MutatedRead:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                self.stream.__enter__()
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def fileno(self):
                return self.stream.fileno()
            def read(self, size):
                image = self.stream.read(size)
                second.write_bytes(b"changed while descriptor is open\n")
                return image

        monkeypatch.setattr(mod.os, "fdopen", lambda *args, **kwargs: MutatedRead(fdopen(*args, **kwargs)))
    with pytest.raises(mod.CollectionError) as error:
        capture.read(second, limit=1 if failure == "limit" else 100)
    assert error.value.exit_code == (3 if failure == "limit" else 4)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        mod.os.fstat(descriptors[0])
    assert second not in capture.images


def test_qualifying_budget_dict_flag_must_equal_its_incomplete_carrier():
    mod = admitted_collector()
    fixture = budget_fixture()
    candidate = producer_fixture(code=bytes.fromhex("85 20 00 00 00 00 00 00") + EXIT)
    authority = fixture_authority(candidate, fixture["baseline"], budget=fixture["admission"].approval_raw)
    before = authority_snapshot(authority)
    reports = replace(fixture["reports"], candidate=captured_fixture(candidate, authority))
    raw_parse = reports.candidate.to_dict()
    assert not raw_parse["complete"]
    assert mod.assess_budget(raw_parse, reports.baseline.to_dict(), fixture["budget"], reports=reports,
                             admission=fixture["admission"], authority=authority)["status"] == "UNAVAILABLE"
    submitted = copy.deepcopy(raw_parse)
    submitted["complete"] = True
    with pytest.raises(mod.CollectionError) as error:
        mod.assess_budget(submitted, reports.baseline.to_dict(), fixture["budget"], reports=reports,
                          admission=fixture["admission"], authority=authority)
    assert error.value.exit_code == 4
    assert authority_snapshot(authority) == before
