# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Shared-cell analysis with bindings independent of the source recognizer.

The unchanged legacy file supplies actual regression inputs. Its own
assertions remain in force while collecting them; this suite's verdicts
come from the independent JSON case ledger and the native implementation.
Numeric identifiers are alpha-renamed to avoid legacy numbering defects;
that does not repair the two intentionally invalid dominance fixtures.
"""

import importlib.util
import json
import os
from pathlib import Path
import re

import pytest

from test_target_model import (ATTRS, CASES, DECLS, EQUAL_REACHABILITY_CASES, KEY, MAP_BODY, ROOT,
                               check, checked, digest, llvm_tool, lower_tool,
                               equal_reachability_payload, module, predicate_payload,
                               refusal, run, spec, success)


def legacy_inputs():
    path = ROOT / "tests/ir/test_audit.py"
    assert digest(path) == CASES["legacy_corpus_sha256"], "legacy corpus changed without ledger review"
    loader = importlib.util.spec_from_file_location("model_legacy_fixtures", path)
    legacy = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(legacy)
    original = legacy.audit.validate
    cases = []
    for row in CASES["legacy_cases"]:
        collected = []

        def collect(text, *args, **kwargs):
            collected.append(text)
            return original(text, *args, **kwargs)

        legacy.audit.validate = collect
        try:
            getattr(legacy, row["id"])()
        finally:
            legacy.audit.validate = original
        assert collected, row["id"]
        for index, text in enumerate(collected):
            # LLVM textual numbering is syntax, not a program semantic fact.
            text = re.sub(r"%(\d+)\b", r"%legacy\1", text)
            text = re.sub(r"(?m)^(\d+):", r"legacy\1:", text)
            cases.append((row, index, text))
    return cases


LEGACY_INPUTS = legacy_inputs()


def independent_bindings(text):
    """Test-owned fixture contracts, deliberately not the C++ recognizer.

    These claims only bind cell analysis. They never confer emission or
    whole-program acceptance, and other program families remain unsupported.
    """
    scratch, key_uses, calls = [], [], []
    key_literals = {}
    for line in text.splitlines():
        definition = re.match(r"\s*(%[A-Za-z0-9_]+) = call\b", line)
        if not definition:
            continue
        name = definition[1]
        calls.append(name)
        if "*(u32 *)(r0 + 0) = r1" in line:
            literal = int(re.search(r"\(i32 (\d+)\)", line)[1])
            scratch.append({"value": name, "kind": "key", "offset": -4,
                            "size": 4, "literal": literal, "preparation": True})
            key_literals[name] = literal
        elif "r0 += -16" in line:
            scratch.append({"value": name, "kind": "value", "offset": -16,
                            "size": 8, "preparation": False})
        elif 'asm "", "=r,0"' in line and "call ptr" in line:
            scratch.append({"value": name, "kind": "disjoint", "offset": 0,
                            "size": 8, "preparation": False})
        elif re.search(r"@__mojobpf_(?:lookup|update|delete_elem)_v1\(", line):
            buffer = re.search(r"i64 [^,]+, ptr (%[A-Za-z0-9_]+)", line)[1]
            key_uses.append({"call": name, "buffer": buffer,
                             "preparation": buffer, "literal": None})
    for use in key_uses:
        use["literal"] = key_literals[use["preparation"]]
    preparations = {cell["value"] for cell in scratch if cell["preparation"]}
    consumers = {use["call"] for use in key_uses}
    entry = re.search(r"define [^\n]*@([A-Za-z_][A-Za-z0-9_]*)\(", text)[1]
    return {"entry": entry, "scratch": scratch, "key_uses": key_uses,
            "pointer_roots": [use["call"] for use in key_uses if "lookup" in next(line for line in text.splitlines() if line.lstrip().startswith(use["call"] + " ="))],
            "inert_calls": [name for name in calls if name not in preparations | consumers]}


def analysis(tmp_path, text, bindings=None, phase="key-freshness", *, bitcode=False):
    executable = Path(os.environ.get("MOJOBPF_AUDIT_DRIVER") or lower_tool().with_name("mojobpf-audit-driver"))
    assert executable.is_file(), "analysis driver is not implemented"
    source = tmp_path / "analysis.ll"
    source.write_text(text)
    if bitcode:
        compiled = tmp_path / "analysis.bc"
        checked([llvm_tool("llvm-as"), source, "-o", compiled])
        source = compiled
    path = tmp_path / "bindings.json"
    path.write_text(json.dumps(bindings or independent_bindings(text)))
    result = run([executable, "--analysis", phase, "--input", source, "--bindings", path])
    parsed = json.loads(result.stdout)
    assert parsed["schema_version"] == 1
    assert parsed["whole_program_admitted"] is False and parsed["runtime_qualified"] is False
    return result, parsed


@pytest.mark.parametrize("row,index,text", LEGACY_INPUTS,
                         ids=[f'{r["id"]}-{i}' for r, i, _ in LEGACY_INPUTS])
def test_original_case_ledger_has_real_typed_analysis(tmp_path, row, index, text):
    source = tmp_path / "independent.ll"
    source.write_text(text)
    verification = run([llvm_tool("opt"), "-passes=verify", "-disable-output", source])
    assert (verification.returncode == 0) is row["llvm_valid"], (row, verification.stderr)
    phase = "pointer-stores" if row["id"].startswith("test_ptrstore_") else "key-freshness"
    result, report = analysis(tmp_path, text, phase=phase)
    expected_core = row.get("pointer_analysis", row["key_analysis"])
    if not row["llvm_valid"]:
        assert result.returncode == 4 and report["diagnostics"][0]["stage"] == "adapter.verify"
    elif expected_core in {"MBPF318", "MBPF316"}:
        assert result.returncode == 4 and report["diagnostics"][0]["code"] == expected_core, (row, report)
    else:
        assert result.returncode == 0 and report["ok"] is True, (row, report)

    # Give the full recognizer the producer-model attributes rather than
    # letting the legacy synthetic v3 attribute conceal the actual invariant.
    normalized = text.replace('attributes #0 = { "target-cpu"="v3" }', ATTRS.strip())
    full_result, full_report = check(tmp_path, normalized, spec(True, independent_bindings(text)["entry"]))
    expected = row.get("variant_source_admission", {}).get(str(index), row["source_admission"])
    if expected == "accept":
        success(full_result, full_report)
    elif expected.startswith("MBPF"):
        refusal(full_result, full_report, expected)
    else:
        pytest.fail(f"case ledger lacks an exact whole-source expectation: {row}")


def test_ledger_covers_every_assigned_case_group():
    path = ROOT / "tests/ir/test_audit.py"
    actual = set(re.findall(r"^def (test_(?:keyfresh|ptrstore|liveness)_\w+)\(", path.read_text(), re.M))
    expected = {row["id"] for row in CASES["legacy_cases"] if row["id"].startswith(("test_keyfresh_", "test_ptrstore_", "test_liveness_"))}
    assert actual == expected


def test_analysis_reader_failure_is_typed_before_bindings(tmp_path):
    body = "entry:\n br label %next\nnext:\n ret i32 %later\norphan:\n %later = add i32 1, 2\n ret i32 2\n"
    result, report = analysis(tmp_path, module(body))
    assert result.returncode == 4
    assert report["diagnostics"][0]["code"] == "MBPF106"
    assert report["diagnostics"][0]["stage"] == "adapter.verify"


def test_analysis_cannot_accept_a_reader_discarded_debug_graph(tmp_path):
    text = module() + '!llvm.dbg.cu = !{!1}\n!1 = !{i32 1}\n'
    result, report = analysis(tmp_path, text)
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF319"


@pytest.mark.parametrize("insert,code", [
    ("store ptr %value, ptr %ptr, align 8", "MBPF316"),
    ("store ptr inttoptr (i64 7 to ptr), ptr %value, align 8", "MBPF316"),
    ("%bits = zext i1 %null to i64\n store i64 %bits, ptr %value, align 8", "MBPF316"),
    ("%bits = trunc i64 %found to i32\n %wide = zext i32 %bits to i64\n store i64 %wide, ptr %value, align 8", "MBPF316"),
    ("%bits = add i64 %found, 0\n store i64 %bits, ptr %value, align 8", "MBPF316"),
    ("%bits = select i1 %null, i64 0, i64 %found\n store i64 %bits, ptr %value, align 8", "MBPF316"),
])
def test_recognizer_rejects_pointer_and_boolean_laundering(tmp_path, insert, code):
    body = MAP_BODY.replace("  %key2 =", "  " + insert + "\n  %key2 =")
    refusal(*check(tmp_path, module(body, DECLS), spec(True)), code)


@pytest.mark.parametrize("alias", [
    "%alias = getelementptr i8, ptr %key, i32 0",
    "%alias = freeze ptr %key",
    "%aggregate = insertvalue {ptr} {ptr null}, ptr %key, 0\n %alias = extractvalue {ptr} %aggregate, 0",
    "%alias = select i1 true, ptr %key, ptr %key",
])
def test_independent_alias_bindings_find_key_corruption(tmp_path, alias):
    body = MAP_BODY.replace("  %map =", "  " + alias + "\n store i8 1, ptr %alias, align 1\n  %map =")
    result, report = analysis(tmp_path, module(body, DECLS))
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF318"


def test_core_fresh_across_cfg_join_and_stale_same_literal(tmp_path):
    # Both predecessor paths preserve the same preparation identity.
    body = MAP_BODY.replace("  %map =", "  br i1 true, label %left, label %right\nleft:\n br label %join\nright:\n br label %join\njoin:\n  %map =")
    result, report = analysis(tmp_path, module(body, DECLS))
    assert result.returncode == 0 and report["ok"] is True
    body = body.replace("right:\n br", "right:\n %reprepare = " + KEY + "\n br")
    result, report = analysis(tmp_path, module(body, DECLS))
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF318"


def test_recognizer_straight_line_preparation_and_disjoint_map_write(tmp_path):
    body = MAP_BODY.replace("  %map2 =", "  br label %consume\nconsume:\n  %map2 =")
    success(*check(tmp_path, module(body, DECLS), spec(True)))
    body = body.replace("  %updated =", "  store i64 %old, ptr %ptr, align 8\n  %updated =")
    success(*check(tmp_path, module(body, DECLS), spec(True)))


@pytest.mark.parametrize("bits", [8, 16, 32])
def test_key_analysis_rejects_non64_index_layout(tmp_path, bits):
    # The cell resolver accumulates into 64-bit APInts, which the
    # accumulator requires to match the index width exactly. The
    # standalone driver reaches key analysis without the admission
    # layout guard, so narrow layouts must fail closed here.
    text = module(MAP_BODY, DECLS)
    narrow = re.sub(r'(?m)^target datalayout = "[^"]*"$',
                    'target datalayout = "e-m:e-p:%d:%d-i64:64-n32:64-S128"'
                    % (bits, bits), text, count=1)
    assert narrow != text
    result, report = analysis(tmp_path, narrow)
    assert result.returncode == 4
    assert report["diagnostics"][0]["code"] == "MBPF319"
    assert report["diagnostics"][0]["explanation"] == \
        "key analysis requires 64-bit AS0 GEP index width"


def test_analysis_budget_is_failure_not_iteration_success(tmp_path):
    text = module(MAP_BODY, DECLS)
    bindings = independent_bindings(text)
    bindings["analysis_budget"] = 1
    result, report = analysis(tmp_path, text, bindings)
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF320"


def test_unknown_memory_writer_invalidates_cell(tmp_path):
    text = module(MAP_BODY.replace("  %map =", '  %unknown = call i64 @writer(ptr %key)\n  %map ='), DECLS + 'declare i64 @writer(ptr)\n')
    bindings = independent_bindings(text)
    bindings["inert_calls"].remove("%unknown")
    result, report = analysis(tmp_path, text, bindings)
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF318"


def test_aggregate_alias_depth_has_typed_resource_failure(tmp_path):
    # Follow untouched field 0 through many field-1 insertions. The depth
    # bound protects the production resolver rather than capping success.
    chain = '%a0 = insertvalue {ptr,i32} {ptr null,i32 0}, ptr %key, 0\n'
    chain += ''.join(f'%a{i} = insertvalue {{ptr,i32}} %a{i-1}, i32 {i}, 1\n' for i in range(1, 400))
    chain += '%alias = extractvalue {ptr,i32} %a399, 0\n store i8 1, ptr %alias, align 1\n'
    text = module(MAP_BODY.replace("  %map =", chain + "  %map ="), DECLS)
    result, report = analysis(tmp_path, text)
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF320"


@pytest.mark.parametrize("bitcode", [False, True])
@pytest.mark.parametrize("encoding,ordinary,same_value,expected", [
    ("select", False, False, "MBPF316"),
    ("phi", False, False, "MBPF316"),
    ("select", True, False, "accept"),
    ("phi", True, False, "accept"),
    ("phi", False, True, "accept"),
])
def test_independent_pointer_analysis_tracks_phi_edge_selection(
        tmp_path, bitcode, encoding, ordinary, same_value, expected):
    # The input contains reserved calls, but these independent test bindings
    # supply only the actual address root. No recognizer constructs the taint.
    bindings = {"entry": "xdp_entry", "scratch": [], "key_uses": [],
                "inert_calls": [], "pointer_roots": ["%found"]}
    result, report = analysis(tmp_path, predicate_payload(
        encoding, ordinary=ordinary, same_value=same_value), bindings,
        phase="pointer-stores", bitcode=bitcode)
    if expected == "accept":
        assert result.returncode == 0 and report["ok"] is True
    else:
        assert result.returncode == 4 and report["diagnostics"][0]["code"] == expected


@pytest.mark.parametrize("bitcode", [False, True])
def test_pointer_control_reachability_has_a_finite_budget(tmp_path, bitcode):
    bindings = {"entry": "xdp_entry", "scratch": [], "key_uses": [],
                "inert_calls": [], "pointer_roots": ["%found"], "analysis_budget": 200}
    result, report = analysis(tmp_path, predicate_payload("phi", path_blocks=90),
                              bindings, phase="pointer-stores", bitcode=bitcode)
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF320"
    assert report["diagnostics"][0]["stage"] == "adapter.resource"


@pytest.mark.parametrize("bitcode", [False, True])
@pytest.mark.parametrize("predicate,same_value,guard,expected", EQUAL_REACHABILITY_CASES)
def test_independent_pointer_analysis_refuses_equal_reachability_waiver(
        tmp_path, bitcode, predicate, same_value, guard, expected):
    roots = ["%found", "%wide"] if guard == "range" else ["%found"]
    bindings = {"entry": "xdp_entry", "scratch": [], "key_uses": [],
                "inert_calls": [], "pointer_roots": roots}
    text = equal_reachability_payload(predicate, same_value=same_value, guard=guard)
    result, report = analysis(tmp_path, text, bindings, phase="pointer-stores", bitcode=bitcode)
    if expected == "accept":
        assert result.returncode == 0 and report["ok"] is True
    else:
        assert result.returncode == 4 and report["diagnostics"][0]["code"] == expected


@pytest.mark.parametrize("bitcode", [False, True])
@pytest.mark.parametrize("predicate", ["true", "scalar"])
def test_equal_reachability_analysis_retains_finite_work(tmp_path, bitcode, predicate):
    bindings = {"entry": "xdp_entry", "scratch": [], "key_uses": [],
                "inert_calls": [], "pointer_roots": ["%found"], "analysis_budget": 200}
    text = equal_reachability_payload(predicate, path_blocks=90)
    result, report = analysis(tmp_path, text, bindings, phase="pointer-stores", bitcode=bitcode)
    assert result.returncode == 4 and report["diagnostics"][0]["code"] == "MBPF320"
    assert report["diagnostics"][0]["stage"] == "adapter.resource"
