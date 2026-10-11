# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Typed target admission, genuine producer controls and failure boundaries.

Dependencies: Python 3.11+, pytest, CMake, C++17, LLVM 21.1.8 and the
admitted Mojo 1.1.0 environment on PATH. All operations are unprivileged.
MOJOBPF_LOWER selects an existing build; otherwise a temporary build is used.
MOJOBPF_TEST_EVIDENCE optionally retains actual commands and captured files.
Missing required tools fail. Native controls are not BPF runtime tests.
"""

import functools
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "compiler/tests/target_model_cases.json").read_text())
MODEL = CASES["model_id"]
LAYOUT = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
ATTRS = ('attributes #0 = { "target-cpu"="znver4" "target-features"="'
         + CASES["producer"]["features"] + '" }\n')
KEY = 'call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)'
MAP = 'call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()'
VALUE = 'call ptr asm sideeffect "r0 = r10\\0Ar0 += -16", "={r0}"()'
TIED = 'call ptr asm "", "=r,0"(i64 %found)'
MAP_BODY = f'''entry:
  %key = {KEY}
  %map = {MAP}
  %found = call i64 @__mojobpf_lookup_v1(i64 %map, ptr %key)
  %null = icmp eq i64 %found, 0
  br i1 %null, label %done, label %hit
hit:
  %value = {VALUE}
  %ptr = {TIED}
  %old = load i64, ptr %ptr, align 8
  %sum = add i64 %old, 1
  store i64 %sum, ptr %value, align 8
  %key2 = {KEY}
  %map2 = {MAP}
  %updated = call i64 @__mojobpf_update_v1(i64 %map2, ptr %key2, ptr %value, i64 0)
  br label %done
done:
  ret i32 2
'''
DECLS = 'declare i64 @__mojobpf_lookup_v1(i64, ptr) #0\ndeclare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0\n'


def module(body="entry:\n  ret i32 2\n", declarations="", header="i32 @xdp_entry(ptr noundef %ctx)"):
    return (f'target datalayout = "{LAYOUT}"\ntarget triple = "x86_64-unknown-linux-gnu"\n'
            f'define {header} #0 {{\n{body}}}\n{declarations}{ATTRS}'
            '!llvm.module.flags = !{!0}\n!0 = !{i32 2, !"Debug Info Version", i32 3}\n')


def spec(has_map=False, entry="xdp_entry"):
    return {"schema_version": 1, "model_id": MODEL, "profile_id": "linux-bpfel-v3",
            "entry": entry, "program_type": "xdp", "section": "xdp",
            "kernel_license": "Apache-2.0 WITH LLVM-exception",
            "map": {"symbol": "mojobpf_map0", "type": 2, "key_bits": 32,
                    "value_bits": 64, "max_entries": 1, "flags": 0} if has_map else None}


def predicate_payload(encoding, *, ordinary=False, same_value=False, path_blocks=0):
    """A selection of payload values through SSA or predecessor edges.

    The lookup result is the address root. A checked load is ordinary data;
    storing that data under a guard must remain valid. Different constants
    selected by the lookup-null predicate materialize an address bit.
    """
    body = f'''entry:
  %key = {KEY}
  %map = {MAP}
  %value = {VALUE}
  %found = call i64 @__mojobpf_lookup_v1(i64 %map, ptr %key)
  %null = icmp eq i64 %found, 0
'''
    condition = "%null"
    if ordinary:
        body += f'''  br i1 %null, label %done, label %dispatch
dispatch:
  %ptr = {TIED}
  %old = load i64, ptr %ptr, align 8
  %ordinary = icmp eq i64 %old, 0
'''
        condition = "%ordinary"
    left, right = ("7", "7") if same_value else ("1", "0")
    if encoding == "select":
        body += f"  %materialized = select i1 {condition}, i64 {left}, i64 {right}\n"
    else:
        assert encoding == "phi"
        body += f"  br i1 {condition}, label %yes, label %no\nyes:\n"
        predecessor = "yes"
        for index in range(path_blocks):
            next_block = f"yes_path_{index}"
            body += f"  br label %{next_block}\n{next_block}:\n"
            predecessor = next_block
        body += f'''  br label %join
no:
  br label %join
join:
  %materialized = phi i64 [{left}, %{predecessor}], [{right}, %no]
'''
    body += f'''  store i64 %materialized, ptr %value, align 8
  %key2 = {KEY}
  %map2 = {MAP}
  %updated = call i64 @__mojobpf_update_v1(i64 %map2, ptr %key2, ptr %value, i64 0)
'''
    body += "  br label %done\ndone:\n  ret i32 2\n" if ordinary else "  ret i32 2\n"
    return module(body, DECLS)


EQUAL_REACHABILITY_CASES = [
    (predicate, same_value, guard, expected)
    for predicate in ("true", "false", "scalar")
    for same_value, guard, expected in ((False, "none", "MBPF316"),
                                        (True, "none", "accept"),
                                        (False, "null", "accept"))
] + [("scalar", False, "range", "accept")]


def equal_reachability_payload(predicate, *, same_value=False, guard="none", path_blocks=0):
    """Reversed scalar branches obscure a PHI's address-dependent selection.

    Both structural outcomes reach both unequal incoming values. Literal
    predicates materialize the address bit directly; an independent loaded
    predicate can reverse it. Equal values and one-outcome guards do not.
    """
    assert predicate in {"true", "false", "scalar"} and guard in {"none", "null", "range"}
    text = predicate_payload("phi", ordinary=guard != "none", same_value=same_value,
                             path_blocks=path_blocks)
    condition = "%ordinary" if guard != "none" else "%null"
    selector = predicate
    if predicate == "scalar":
        selector = "%independent"
        text = text.replace("entry:\n", '''entry:
  %input_data = load i32, ptr %ctx, align 4
  %input_wide = zext i32 %input_data to i64
  %input_endptr = getelementptr i32, ptr %ctx, i32 1
  %input_end = load i32, ptr %input_endptr, align 4
  %input_endwide = zext i32 %input_end to i64
  %input_limit = add i64 %input_wide, 15
  %input_short = icmp ugt i64 %input_limit, %input_endwide
  br i1 %input_short, label %input_unavailable, label %input_read
input_unavailable:
  ret i32 2
input_read:
  %input_pointer = call ptr asm "", "=r,0"(i64 %input_wide)
  %input_offset = getelementptr inbounds i8, ptr %input_pointer, i32 14
  %raw = load i8, ptr %input_offset, align 1
  %independent = icmp eq i8 %raw, 0
''', 1)
    text = text.replace(f"  br i1 {condition}, label %yes, label %no\nyes:\n", f'''  br i1 {condition}, label %left, label %right
left:
  br i1 {selector}, label %yes, label %no
right:
  br i1 {selector}, label %no, label %yes
yes:
''')
    if guard == "range":
        text = text.replace("entry:\n", '''entry:
  %data = load i32, ptr %ctx, align 4
  %wide = zext i32 %data to i64
  %endptr = getelementptr i32, ptr %ctx, i32 1
  %end = load i32, ptr %endptr, align 4
  %endwide = zext i32 %end to i64
  %limit = add i64 %wide, 15
  %short = icmp ugt i64 %limit, %endwide
''', 1)
        text = text.replace("  br i1 %null, label %done, label %dispatch\ndispatch:\n", '''  br i1 %null, label %done, label %range_check
range_check:
  br i1 %short, label %done, label %dispatch
dispatch:
''')
    return text


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, **kwargs):
    evidence = os.environ.get("MOJOBPF_TEST_EVIDENCE")
    identities = []
    def retain(phase):
        if not evidence:
            return
        for argument in argv:
            path = Path(str(argument))
            if (path.suffix not in {".ll", ".bc", ".json", ".mojo", ".c", ".s"}
                    or not path.is_file()):
                continue
            data = path.read_bytes()
            identity = hashlib.sha256(data).hexdigest()
            blob = Path(evidence) / "files" / identity
            blob.parent.mkdir(parents=True, exist_ok=True)
            if not blob.exists():
                blob.write_bytes(data)
            identities.append({"phase": phase, "path": str(path), "sha256": identity})
    retain("before")
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                            timeout=600, **kwargs)
    retain("after")
    if evidence:
        directory = Path(evidence)
        directory.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix="command-", suffix=".json", dir=directory)
        with os.fdopen(fd, "w") as stream:
            json.dump({"argv": [str(a) for a in argv], "exit_code": result.returncode,
                       "cwd": str(Path.cwd()), "files": identities,
                       "environment": {key: os.environ.get(key) for key in
                                       ("MODULAR_HOME", "CONDA_PREFIX", "PATH")},
                       "stdout": result.stdout, "stderr": result.stderr}, stream, indent=2)
    return result


def checked(argv, **kwargs):
    result = run(argv, **kwargs)
    assert result.returncode == 0, f"{argv}: {result.stdout}{result.stderr}"
    return result


@functools.lru_cache(maxsize=1)
def lower_tool():
    executable = os.environ.get("MOJOBPF_LOWER")
    if executable:
        assert Path(executable).is_file(), "ENVIRONMENT FAILURE: MOJOBPF_LOWER missing"
        return Path(executable)
    directory = tempfile.TemporaryDirectory(prefix="mojobpf-model-build-")
    # Keep the owner alive for the complete process; its finalizer cleans up.
    lower_tool.owner = directory
    config = os.environ.get("MOJOBPF_LLVM_CONFIG") or shutil.which("llvm-config")
    assert config, "ENVIRONMENT FAILURE: llvm-config missing"
    cmakedir = checked([config, "--cmakedir"]).stdout.strip()
    checked(["cmake", "-S", ROOT / "compiler", "-B", directory.name,
             "-DLLVM_DIR=" + cmakedir, "-DBUILD_TESTING=OFF"])
    checked(["cmake", "--build", directory.name, "--parallel", "2"])
    return Path(directory.name) / "mojobpf-lower"


def llvm_tool(name):
    config = os.environ.get("MOJOBPF_LLVM_CONFIG") or shutil.which("llvm-config")
    assert config, "ENVIRONMENT FAILURE: llvm-config missing"
    assert digest(config) == CASES["tools"]["llvm-config"], "unadmitted LLVM reader"
    executable = Path(checked([config, "--bindir"]).stdout.strip()) / name
    assert digest(executable) == CASES["tools"][name], "unadmitted LLVM tool"
    return executable


def check(tmp_path, text, request=None, *, bitcode=False, extra=()):
    source = tmp_path / "input.ll"
    source.write_text(text)
    if bitcode:
        compiled = tmp_path / "input.bc"
        checked([llvm_tool("llvm-as"), source, "-o", compiled])
        source = compiled
    request_path = tmp_path / "spec.json"
    request_path.write_text(json.dumps(request if request is not None else spec()))
    report_path = tmp_path / "report.json"
    result = run([lower_tool(), "--mode", "check-target", "--input", source,
                  "--spec", request_path, "--report", report_path, *extra])
    report = json.loads(report_path.read_text()) if report_path.exists() else None
    return result, report


def success(result, report):
    assert result.returncode == 0, result.stdout + result.stderr
    assert report is not None, "missing report is failure"
    assert report["schema_version"] == 1 and report["ok"] is True
    assert report["mode"] == "check-target" and report["model_id"] == MODEL
    assert report["runtime_qualified"] is False and report["transformations"] == []
    assert report["diagnostics"] == []
    assert len(report["input_digest"]) == 64
    assert len(report["spec_digest"]) == 64
    assert {row["id"] for row in report["proof_obligations"]} == {row["id"] for row in CASES["obligations"]}


def refusal(result, report, code):
    assert result.returncode == 4, result.stdout + result.stderr
    assert report is not None and report["ok"] is False
    assert report["runtime_qualified"] is False
    diagnostic = report["diagnostics"][0]
    assert set(diagnostic) == {"code", "stage", "severity", "explanation", "location", "remedy"}
    assert diagnostic["code"] == code, diagnostic
    assert diagnostic["explanation"] and diagnostic["remedy"]


def admitted_producer(executable=None):
    mojo = Path(executable or shutil.which("mojo") or "/missing-mojo")
    assert mojo.is_file(), "ENVIRONMENT FAILURE: Mojo missing"
    assert digest(mojo) == CASES["producer"]["mojo_sha256"], "unadmitted producer identity"
    prefix = mojo.resolve().parents[1]
    assert digest(prefix / "lib/mojo/std.mojoc") == CASES["producer"]["stdlib_sha256"], "unadmitted stdlib"
    assert digest(prefix / "share/max/modular.cfg") == CASES["producer"]["config_sha256"], "unadmitted compiler configuration"
    for identity in CASES["producer"]["dynamic_closure"].values():
        path = prefix / identity["relative"] if identity["kind"] == "prefix" else Path(identity["relative"])
        assert digest(path) == identity["sha256"], "unadmitted producer dynamic closure"
    assert checked([mojo, "--version"]).stdout.strip() == "Mojo 1.1.0 (8189361e)"
    return mojo


def capture(tmp_path, source, emit):
    mojo = admitted_producer()
    output = tmp_path / (source.stem + (".bc" if emit == "llvm-bitcode" else ".ll"))
    before = digest(source)
    imports = {str(path.relative_to(ROOT)): digest(path)
               for path in (ROOT / "src/mojobpf/resources/sdk").rglob("*.mojo")}
    evidence = os.environ.get("MOJOBPF_TEST_EVIDENCE")
    if evidence:
        snapshot = {"source": str(source.relative_to(ROOT)), "source_sha256": before,
                    "sdk_import_closure": imports, "producer_sha256": digest(mojo),
                    "emit": emit, "producer_optimization": "default (no explicit optimization option)"}
        fd, name = tempfile.mkstemp(prefix="capture-", suffix=".json", dir=evidence)
        with os.fdopen(fd, "w") as stream:
            json.dump(snapshot, stream, indent=2)
        for name in imports:
            path = ROOT / name
            blob = Path(evidence) / "files" / imports[name]
            blob.parent.mkdir(parents=True, exist_ok=True)
            if not blob.exists():
                blob.write_bytes(path.read_bytes())
    checked([mojo, "build", "--emit", emit, "-I", ROOT / "src/mojobpf/resources/sdk", "-o", output, source])
    assert digest(source) == before
    assert {str(path.relative_to(ROOT)): digest(path)
            for path in (ROOT / "src/mojobpf/resources/sdk").rglob("*.mojo")} == imports
    checked([llvm_tool("opt"), "-passes=verify", "-disable-output", output])
    return output


def test_mode_and_report_are_non_mutating(tmp_path):
    text = module(MAP_BODY, DECLS)
    result, report = check(tmp_path, text, spec(True))
    success(result, report)
    assert (tmp_path / "input.ll").read_text() == text
    facts = report["target_facts"]
    assert facts["input_triple"] == "x86_64-unknown-linux-gnu"
    assert facts["target_triple"] == "bpfel-unknown-none"
    assert facts["producer_authenticated"] is False
    assert facts["pointer_bits"] == facts["index_bits"] == facts["pointer_alignment_bits"] == 64
    assert facts["prefix"] == {"store_size": 8, "alloc_size": 8, "abi_alignment": 4, "preferred_alignment": 8, "offsets": [0, 4]}
    assert len(facts["source_audit"]["key_consumers"]) == 2
    assert facts["source_audit"]["source_mutated"] is False


@pytest.mark.parametrize("bitcode", [False, True])
def test_layout_properties_and_identifier_order_are_semantic(tmp_path, bitcode):
    text = module(MAP_BODY, DECLS).replace(LAYOUT, "e-p:64:64-i64:64-i128:128-n8:16:32:64-S128")
    text = text.replace("xdp_entry", "renamed_entry").replace("%key", "%fresh").replace("hit", "taken")
    text = text.replace(DECLS, "\n".join(reversed(DECLS.splitlines())) + "\n")
    result, report = check(tmp_path, text, spec(True, "renamed_entry"), bitcode=bitcode)
    success(result, report)


@pytest.mark.parametrize("source", ["examples/xdp_pass/xdp_pass.mojo", "tests/compile/map_roundtrip.mojo", "tests/compile/map_roundtrip_mutated.mojo"])
def test_genuine_text_and_native_bitcode_have_same_typed_facts(tmp_path, source):
    reports = []
    for emit in ("llvm", "llvm-bitcode"):
        captured = capture(tmp_path, ROOT / source, emit)
        input_identity = digest(captured)
        request = tmp_path / "spec.json"
        request.write_text(json.dumps(spec("map_roundtrip" in source)))
        report = tmp_path / (emit + ".report.json")
        result = run([lower_tool(), "--mode", "check-target", "--input", captured, "--spec", request, "--report", report])
        parsed = json.loads(report.read_text()) if report.exists() else None
        success(result, parsed)
        assert digest(captured) == input_identity == parsed["input_digest"]
        reports.append(parsed)
    # Reader layout spelling may upgrade; all measured semantic facts agree.
    for key in ("types", "prefix", "attributes", "pointer_bits", "index_bits", "gep_offsets"):
        assert reports[0]["target_facts"][key] == reports[1]["target_facts"][key]


def test_wrong_producer_refuses_before_execution(tmp_path):
    fake = tmp_path / "mojo"
    marker = tmp_path / "executed"
    fake.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
    fake.chmod(0o700)
    with pytest.raises(AssertionError, match="unadmitted producer"):
        admitted_producer(fake)
    assert not marker.exists()


@pytest.mark.parametrize("change", [lambda s: s.update(schema_version=2), lambda s: s.update(extra=True), lambda s: s.update(schema_version=True), lambda s: s.update(schema_version=1.0), lambda s: s.update(entry=[]), lambda s: s.pop("entry"), lambda s: s.update(map={"symbol": "wrong"}), lambda s: s.update(map=dict(spec(True)["map"], flags=0.0))])
def test_malformed_spec_is_usage_and_preserves_sentinel(tmp_path, change):
    request = spec()
    change(request)
    report = tmp_path / "report.json"
    report.write_text("sentinel")
    source = tmp_path / "input.ll"
    source.write_text(module())
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(request))
    result = run([lower_tool(), "--mode", "check-target", "--input", source, "--spec", path, "--report", report])
    assert result.returncode == 2
    assert report.read_text() == "sentinel"


@pytest.mark.parametrize("text", ["{", "[]", "null"])
def test_malformed_json_spec_is_usage_and_preserves_sentinel(tmp_path, text):
    source, request, report = (tmp_path / name for name in ("input.ll", "spec.json", "report.json"))
    source.write_text(module())
    request.write_text(text)
    report.write_text("sentinel")
    result = run([lower_tool(), "--mode", "check-target", "--input", source, "--spec", request, "--report", report])
    assert result.returncode == 2 and report.read_text() == "sentinel"


@pytest.mark.parametrize("kind", ["same", "symlink", "hardlink", "dot", "spec"])
def test_path_aliases_are_usage_and_preserve_inputs(tmp_path, kind):
    source = tmp_path / "input.ll"
    source.write_text(module())
    request = tmp_path / "spec.json"
    request.write_text(json.dumps(spec()))
    alias = tmp_path / "alias.json"
    if kind == "symlink":
        alias.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, alias)
    else:
        alias = {"same": source, "dot": tmp_path / "." / "input.ll", "spec": request}[kind]
    hashes = digest(source), digest(request)
    result = run([lower_tool(), "--mode", "check-target", "--input", source, "--spec", request, "--report", alias])
    assert result.returncode == 2, result.stderr
    assert (digest(source), digest(request)) == hashes


def test_check_rejects_output_and_lower_is_not_implemented(tmp_path):
    output = tmp_path / "output.ll"
    output.write_text("sentinel")
    result, _ = check(tmp_path, module(), extra=("--output", output))
    assert result.returncode == 2
    result = run([lower_tool(), "--mode", "lower", "--input", tmp_path / "input.ll", "--spec", tmp_path / "spec.json", "--report", tmp_path / "lower.json", "--output", output])
    assert result.returncode == 4 and "MBPF319" in result.stderr
    assert output.read_text() == "sentinel"
    result = run([lower_tool(), "--mode", "lower", "--input", tmp_path / "input.ll", "--spec", tmp_path / "spec.json", "--report", output, "--output", output])
    assert result.returncode == 2 and output.read_text() == "sentinel"


@pytest.mark.parametrize("destination", ["directory", "missing_parent", "full"])
def test_report_open_write_failure_is_non_success(tmp_path, destination):
    source = tmp_path / "input.ll"
    source.write_text(module())
    request = tmp_path / "spec.json"
    request.write_text(json.dumps(spec()))
    report = tmp_path / "report.json"
    if destination == "directory":
        report.mkdir()
    elif destination == "missing_parent":
        report = tmp_path / "missing" / "report.json"
    else:
        assert Path("/dev/full").exists()
        report.symlink_to("/dev/full")
    result = run([lower_tool(), "--mode", "check-target", "--input", source, "--spec", request, "--report", report])
    assert result.returncode == 4 and "report" in result.stderr
    if destination == "full":
        assert not report.is_symlink()


@pytest.mark.parametrize("text,code", [
    (module().replace(LAYOUT, "E-p:64:64-i64:64"), "MBPF319"),
    (module().replace(LAYOUT, "e-p:32:32:32:32-i64:64"), "MBPF319"),
    (module().replace(LAYOUT, "e-p:64:64:64:32-i64:64"), "MBPF319"),
    (module().replace(LAYOUT, LAYOUT + "-ni:1").replace("ptr noundef", "ptr addrspace(1) noundef"), "MBPF311"),
    (module("entry:\n %x = add i128 1, 2\n ret i32 2\n"), "MBPF305"),
    (module("entry:\n %x = fadd float 1.0, 2.0\n ret i32 2\n"), "MBPF305"),
    (module("entry:\n %x = add <2 x i32> zeroinitializer, zeroinitializer\n ret i32 2\n"), "MBPF305"),
    (module("entry:\n %x = add <vscale x 2 x i32> zeroinitializer, zeroinitializer\n ret i32 2\n"), "MBPF305"),
    (module("entry:\n %x = add <1 x i32> zeroinitializer, zeroinitializer\n ret i32 2\n"), "MBPF305"),
    (module("entry:\n %x = load <vscale x 2 x i32>, ptr %ctx, align 4\n ret i32 2\n"), "MBPF305"),
    (module("entry:\n %p = getelementptr <vscale x 2 x i32>, ptr %ctx, i32 1\n ret i32 2\n"), "MBPF305"),
    (module("entry:\n %x = udiv i32 4, 0\n ret i32 %x\n"), "MBPF319"),
    (module("entry:\n ret i32 poison\n"), "MBPF311"),
    (module("entry:\n ret i32 undef\n"), "MBPF311"),
    (module(header="i32 @xdp_entry(ptr %ctx, i64 %hidden)"), "MBPF302"),
    (module(header="i32 @xdp_entry(ptr %ctx, ...)"), "MBPF302"),
    (module(header="fastcc i32 @xdp_entry(ptr %ctx)"), "MBPF302"),
    (module(header="i32 @xdp_entry({i32, i32} %ctx)"), "MBPF302"),
    (module(header="i32 @xdp_entry(ptr byval(i32) %ctx)"), "MBPF319"),
    (module(header="i32 @xdp_entry(ptr sret(i32) %ctx)"), "MBPF106"),
    (module(body="entry:\n ret void\n", header="void @xdp_entry(ptr sret(i32) %ctx)"), "MBPF302"),
    (module(header="i32 @xdp_entry(ptr inalloca(i32) %ctx)"), "MBPF319"),
    (module(body="entry:\n ret {i32,i32} zeroinitializer\n", header="{i32,i32} @xdp_entry(ptr %ctx)"), "MBPF302"),
    (module().replace('"target-cpu"="znver4"', '"target-cpu"="x86-64"'), "MBPF319"),
    (module().replace('"target-features"="', '"unknown-feature"="'), "MBPF319"),
    (module().replace("attributes #0 = {", "attributes #0 = { memory(none)"), "MBPF319"),
    (module().replace('!"Debug Info Version"', '!"target-abi"'), "MBPF319"),
    (module().replace('i32 3}', 'i32 4}'), "MBPF319"),
    (module() + "define i32 @extra(ptr %p) { ret i32 2 }\n", "MBPF309"),
    (module() + "@global = global i32 0\n", "MBPF309"),
    (module() + 'module asm "nop"\n', "MBPF304"),
    (module("entry:\n %x = alloca i32\n ret i32 2\n"), "MBPF310"),
    (module("entry:\n %x = call i32 @xdp_entry(ptr %ctx)\n ret i32 %x\n"), "MBPF312"),
    (module("entry:\n %x = call i32 @malloc(i64 8)\n ret i32 %x\n", "declare i32 @malloc(i64)\n"), "MBPF303"),
    # LLVM attaches intrinsic enum attributes while reading this declaration.
    # The frozen attribute contract rejects it before the runtime-call audit.
    (module("entry:\n %x = call ptr @llvm.stacksave()\n ret i32 2\n", "declare ptr @llvm.stacksave()\n"), "MBPF319"),
    (module("entry:\n %p = inttoptr i64 3 to ptr\n %x = load i8, ptr %p\n ret i32 2\n"), "MBPF311"),
    (module("entry:\n %p = addrspacecast ptr %ctx to ptr addrspace(270)\n ret i32 2\n"), "MBPF311"),
    (module("entry:\n %p = getelementptr i32, ptr %ctx, i32 2\n %x = load i32, ptr %p, align 4\n ret i32 2\n"), "MBPF317"),
    (module("entry:\n %x = load i32, ptr %ctx, align 8\n ret i32 2\n"), "MBPF319"),
    (module("entry:\n %x = load volatile i32, ptr %ctx, align 4\n ret i32 2\n"), "MBPF319"),
    (module("entry:\n %x = load atomic i32, ptr %ctx monotonic, align 4\n ret i32 2\n"), "MBPF319"),
    (module("entry:\n %x = load i1, ptr %ctx, align 1\n ret i32 2\n"), "MBPF319"),
    (module("entry:\n %p = getelementptr i8, ptr %ctx, i32 0\n %i = load i32, ptr %ctx, align 4\n %g = getelementptr i8, ptr %p, i32 %i\n ret i32 2\n"), "MBPF317"),
    (module(MAP_BODY.replace("  %key2 =", "  %n = trunc nuw i64 %old to i32\n  %key2 ="), DECLS), "MBPF319"),
    (module(MAP_BODY.replace("  %key2 =", "  %n = zext nneg i8 255 to i64\n  %key2 ="), DECLS), "MBPF319"),
    (module(MAP_BODY.replace("  %key2 =", "  %n = icmp samesign eq i64 %old, 0\n  %key2 ="), DECLS), "MBPF319"),
    (module(MAP_BODY.replace("  %key2 =", "  %n = or disjoint i64 %old, 1\n  %key2 ="), DECLS), "MBPF319"),
    (module(MAP_BODY.replace("  %key2 =", "  store i1 true, ptr %value, align 1\n  %key2 ="), DECLS), "MBPF319"),
    (module(MAP_BODY.replace('"={r0},{r1},~{memory}"', '"=r,r"'), DECLS), "MBPF306"),
    (module(MAP_BODY.replace("r0 += -4", "r0 += -8"), DECLS), "MBPF306"),
    (module(MAP_BODY.replace("asm sideeffect", "asm", 1), DECLS), "MBPF306"),
    (module(MAP_BODY.replace("asm sideeffect", "asm sideeffect inteldialect", 1), DECLS), "MBPF306"),
    (module(MAP_BODY.replace("asm sideeffect", "asm sideeffect alignstack", 1), DECLS), "MBPF306"),
    (module(MAP_BODY.replace('call ptr asm "",', 'call ptr asm sideeffect "",'), DECLS), "MBPF306"),
    (module(declarations="declare i32 @__mojobpf_lookup_v1(i64, ptr)\n"), "MBPF313"),
    (module(declarations="declare i64 @__mojobpf_lookup_v1(ptr, i64)\n"), "MBPF313"),
    (module(MAP_BODY.replace("store i64 %sum, ptr %value, align 8", "%small = trunc i64 %sum to i32\n store i32 %small, ptr %value, align 4"), DECLS), "MBPF314"),
    (module(MAP_BODY.replace("add i64 %old, 1", "add nuw i64 %old, 1"), DECLS), "MBPF319"),
    (module(MAP_BODY.replace("br i1 %null, label %done, label %hit", "br label %hit"), DECLS), "MBPF314"),
    (module(MAP_BODY.replace("store i64 %sum", "store i64 %found"), DECLS), "MBPF316"),
    (module(MAP_BODY.replace("%map, ptr %key", "42, ptr %key"), DECLS), "MBPF314"),
    (module(MAP_BODY.replace("ptr %value, i64 0)", "ptr %value, i64 1)"), DECLS), "MBPF314"),
])
def test_unknown_facts_and_behaviors_fail_typed(tmp_path, text, code):
    refusal(*check(tmp_path, text, spec("__mojobpf" in text)), code)


def test_resource_limit_and_cycle_are_typed(tmp_path):
    body = "entry:\n" + "".join(f"%n{i} = add i32 1, 2\n" for i in range(5000)) + "ret i32 2\n"
    refusal(*check(tmp_path, module(body)), "MBPF320")
    refusal(*check(tmp_path, module("entry:\n br label %cycle\ncycle:\n br label %cycle\n")), "MBPF319")


@pytest.mark.parametrize("address_space", [270, 271, 272])
def test_used_host_address_spaces_reject_even_when_unused_layout_entries_are_ok(tmp_path, address_space):
    refusal(*check(tmp_path, module(header=f"i32 @xdp_entry(ptr addrspace({address_space}) %ctx)")), "MBPF311")


@pytest.mark.parametrize("kind", ["bitcode", "dominance", "missing"])
def test_reader_and_verifier_failures_produce_non_success_report(tmp_path, kind):
    source = tmp_path / "invalid.bc"
    if kind == "bitcode":
        source.write_bytes(b"BC\xc0\xde\x00\xff\x00")
    elif kind == "dominance":
        source.write_text(module("entry:\n br label %next\nnext:\n ret i32 %later\nunreachable_block:\n %later = add i32 1, 2\n ret i32 2\n"))
    request = tmp_path / "spec.json"
    request.write_text(json.dumps(spec()))
    report = tmp_path / "report.json"
    result = run([lower_tool(), "--mode", "check-target", "--input", source, "--spec", request, "--report", report])
    refusal(result, json.loads(report.read_text()), "MBPF106")
    diagnostic = json.loads(report.read_text())["diagnostics"][0]
    assert diagnostic["stage"] == ("adapter.verify" if kind == "dominance" else "adapter.parse")


def test_invalid_debug_graph_cannot_be_stripped_into_admission(tmp_path):
    text = module() + '!llvm.dbg.cu = !{!1}\n!1 = !{i32 1}\n'
    refusal(*check(tmp_path, text), "MBPF319")


def test_context_address_cannot_be_narrowed_and_reinterpreted(tmp_path):
    body = '''entry:
 %data = load i32, ptr %ctx, align 4
 %wide = zext i32 %data to i64
 %narrow = trunc i64 %wide to i8
 %again = zext i8 %narrow to i64
 %pointer = call ptr asm "", "=r,0"(i64 %again)
 ret i32 2
'''
    refusal(*check(tmp_path, module(body)), "MBPF311")


def test_gep_wrap_flags_need_the_recorded_proof(tmp_path):
    body = "entry:\n %end = getelementptr nuw i32, ptr %ctx, i32 1\n ret i32 2\n"
    refusal(*check(tmp_path, module(body)), "MBPF319")


def test_caller_rejects_missing_malformed_and_contradictory_reports():
    result = subprocess.CompletedProcess([], 0, "", "")
    for report in (None, {}, {"schema_version": 1, "ok": False}):
        with pytest.raises((AssertionError, KeyError)):
            success(result, report)


def test_tied_empty_asm_preserves_register_and_emits_no_instructions(tmp_path):
    # A backend interface control only: no kernel algorithm or object is built.
    instructions = []
    for name, body in (("plain", "ret i64 %input"), ("tied", ' %p = call ptr asm "", "=r,0"(i64 %input)\n %bits = ptrtoint ptr %p to i64\n ret i64 %bits')):
        source, output = tmp_path / (name + ".ll"), tmp_path / (name + ".s")
        source.write_text(f'target triple = "bpfel-unknown-none"\ndefine i64 @{name}(i64 %input) {{\n{body}\n}}\n')
        checked([llvm_tool("opt"), "-passes=verify", "-disable-output", source])
        checked([llvm_tool("llc"), "-mtriple=bpfel", "-mcpu=v3", "-O2", "-filetype=asm", source, "-o", output])
        instructions.append([line.strip() for line in output.read_text().splitlines()
                             if re.match(r"\s+(r\d+\s*=|exit\b)", line)])
    assert instructions == [["r0 = r1", "exit"], ["r0 = r1", "exit"]]


@pytest.mark.parametrize("offset", [15, 2147483647])
def test_packet_flags_have_proved_domain_and_guarded_inbounds(tmp_path, offset):
    body = f'''entry:
 %data = load i32, ptr %ctx, align 4
 %wide = zext i32 %data to i64
 %endptr = getelementptr inbounds i32, ptr %ctx, i32 1
 %end = load i32, ptr %endptr, align 4
 %endwide = zext i32 %end to i64
 %limit = add nuw nsw i64 %wide, {offset}
 %short = icmp samesign ugt i64 %limit, %endwide
 br i1 %short, label %done, label %read
read:
 %pointer = call ptr asm "", "=r,0"(i64 %wide)
 %byteptr = getelementptr inbounds i8, ptr %pointer, i32 14
 %byte = load i8, ptr %byteptr, align 1
 %action = zext i8 %byte to i32
 br label %done
done:
 %result = phi i32 [2, %entry], [%action, %read]
 ret i32 %result
'''
    result, report = check(tmp_path, module(body))
    success(result, report)
    assert 0 <= (2**32 - 1) + offset < 2**63
    # Moving the inbounds address outside its range guard loses its proof.
    moved = body.replace('read:\n %pointer = call ptr asm "", "=r,0"(i64 %wide)\n %byteptr = getelementptr inbounds i8, ptr %pointer, i32 14\n', 'read:\n')
    moved = moved.replace(" %limit =", ' %pointer = call ptr asm "", "=r,0"(i64 %wide)\n %byteptr = getelementptr inbounds i8, ptr %pointer, i32 14\n %limit =')
    refusal(*check(tmp_path, module(moved)), "MBPF314")


def test_scalar_native_controls_match_independent_c_and_oracle(tmp_path):
    mojo = admitted_producer()
    clang = shutil.which("clang")
    assert clang and digest(clang) == CASES["tools"]["clang"], "unadmitted C control compiler"
    native = tmp_path / "mojo-native"
    reference = tmp_path / "c-native"
    runner = tmp_path / "native_runner.mojo"
    runner.write_text("from target_model_probe import run_native_control\ndef main():\n    run_native_control()\n")
    checked([mojo, "build", "-I", ROOT / "compiler/tests", runner, "-o", native])
    checked([clang, "-std=c11", "-O2", ROOT / "compiler/tests/target_model_control.c", "-o", reference])
    left = checked([native]).stdout
    right = checked([reference]).stdout
    assert left == right
    rows = dict(line.split(" ", 1) for line in left.splitlines())
    assert rows["PREFIX"] == "8 4 0 4 1 2 3 4 5 6 7 8"
    assert rows["WIDTHS"] == "64 64 8 8 16 16 32 32 64 64"
    assert rows["CASTS"] == "255 65535 4294967295 18446744073709551615 -128 -32768 -2147483648 -9223372036854775808"
    assert rows["WRAP"] == "0 1 9223372036854775809 18446744073709551615"
    assert rows["EXTEND"] == "255 18446744073709551615"
    assert rows["NARROW"] == "0 0 255"
    assert rows["EXTEND_BOUNDARY"] == "0 128 255 0 127 18446744073709551488"
    exported = capture(tmp_path, ROOT / "compiler/tests/target_model_probe.mojo", "llvm")
    text = exported.read_text()
    assert re.search(r"define .*i64 @scalar_wrap\(i64", text)
    assert "add i64" in text and "trunc i64" in text and "zext i8" in text and "sext i8" in text


@pytest.mark.parametrize("bitcode", [False, True])
@pytest.mark.parametrize("root", ["value", "ptr"])
@pytest.mark.parametrize("operation", ["load", "store"])
@pytest.mark.parametrize("width,offset,chained,expected", [
    (32, 1, False, "MBPF319"),
    (32, 2, False, "MBPF319"),
    (32, 4, False, "accept"),
    (32, 2, True, "MBPF319"),
    (32, 4, True, "accept"),
    (8, 1, False, "accept"),
])
def test_memory_alignment_follows_root_and_accumulated_offset(
        tmp_path, bitcode, root, operation, width, offset, chained, expected):
    # Both root cells guarantee eight-byte alignment. i32 claims align4;
    # offsets1/2 lose that guarantee while offset4 and byte accesses retain it.
    if chained:
        address = (f"  %first = getelementptr i8, ptr %{root}, i64 1\n"
                   f"  %access = getelementptr i8, ptr %first, i64 {offset - 1}\n")
    else:
        address = f"  %access = getelementptr i8, ptr %{root}, i64 {offset}\n"
    align = 4 if width == 32 else 1
    access = (f"  %read = load i{width}, ptr %access, align {align}\n" if operation == "load"
              else f"  store i{width} 7, ptr %access, align {align}\n")
    text = module(MAP_BODY.replace("  %key2 =", address + access + "  %key2 ="), DECLS)
    result, report = check(tmp_path, text, spec(True), bitcode=bitcode)
    if expected == "accept":
        success(result, report)
    else:
        refusal(result, report, expected)
        assert report["diagnostics"][0]["stage"] == "adapter.target"


@pytest.mark.parametrize("bitcode", [False, True])
@pytest.mark.parametrize("encoding,ordinary,same_value,expected", [
    ("select", False, False, "MBPF316"),
    ("phi", False, False, "MBPF316"),
    ("select", True, False, "accept"),
    ("phi", True, False, "accept"),
    ("phi", False, True, "accept"),
])
def test_pointer_predicate_selection_cannot_become_stored_payload(
        tmp_path, bitcode, encoding, ordinary, same_value, expected):
    result, report = check(tmp_path, predicate_payload(
        encoding, ordinary=ordinary, same_value=same_value), spec(True), bitcode=bitcode)
    if expected == "accept":
        success(result, report)
    else:
        refusal(result, report, expected)


@pytest.mark.parametrize("bitcode", [False, True])
@pytest.mark.parametrize("owner,kind", [(None, None), *[
    (owner, kind) for owner in ("entry", "lookup", "update")
    for kind in ("unproved", "kcfi_type")
]])
def test_function_metadata_requires_a_proved_contract(tmp_path, bitcode, owner, kind):
    text = module(MAP_BODY, DECLS)
    if owner:
        if owner == "entry":
            text = text.replace(" #0 {", f" #0 !{kind} !1 {{")
        else:
            declaration = next(line for line in DECLS.splitlines() if f"__mojobpf_{owner}_v1" in line)
            text = text.replace(declaration, declaration.replace("declare ", f"declare !{kind} !1 ", 1))
        text += "!1 = !{i32 123}\n"
    result, report = check(tmp_path, text, spec(True), bitcode=bitcode)
    if owner:
        refusal(result, report, "MBPF319")
        assert report["diagnostics"][0]["stage"] == "adapter.target"
    else:
        success(result, report)


@pytest.mark.parametrize("bitcode", [False, True])
@pytest.mark.parametrize("predicate,same_value,guard,expected", EQUAL_REACHABILITY_CASES)
def test_equal_reachability_does_not_prove_payload_independence(
        tmp_path, bitcode, predicate, same_value, guard, expected):
    text = equal_reachability_payload(predicate, same_value=same_value, guard=guard)
    result, report = check(tmp_path, text, spec(True), bitcode=bitcode)
    if expected == "accept":
        success(result, report)
    else:
        refusal(result, report, expected)
