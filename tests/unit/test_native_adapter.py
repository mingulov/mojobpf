# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Independent contract controls for the explicitly admitted native bridge."""

import copy
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import signal
import time

import pytest


LICENSE = "Apache-2.0 WITH LLVM-exception"
MODEL = "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1"
ROUTE = "parsed-xdp-array-candidate-v1"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def manifest_doc(entry="independent_entry", maps=False):
    return {
        "schema_version": 1,
        "project": {"name": "consumer"},
        "artifact": {"name": "consumer", "source_license": LICENSE,
                     "kernel_license": LICENSE},
        "target": {"profile": "linux-bpfel-v3", "core": False},
        "programs": [{"source": "kernel.mojo", "entry": entry,
                      "program_type": "xdp", "section": "xdp"}],
        "maps": ([{"name": "mojobpf_map0", "map_type": "array",
                   "key_type": "u32", "value_type": "u64",
                   "max_entries": 1}] if maps else []),
    }


def native_module():
    assert importlib.util.find_spec("mojobpf.native_adapter") is not None, (
        "the explicit native bridge is missing")
    return importlib.import_module("mojobpf.native_adapter")


@pytest.mark.parametrize("maps", [False, True])
def test_native_single_program_slice(maps):
    # A root-name allowlist or stale map spec would break these declarations.
    expected = {
        "schema_version": 1, "entry": "independent_entry",
        "model_id": MODEL, "profile_id": "linux-bpfel-v3",
        "program_type": "xdp", "section": "xdp", "kernel_license": LICENSE,
        "map": None,
    }
    if maps:
        expected["map"] = {"symbol": "mojobpf_map0", "type": 2,
                           "key_bits": 32, "value_bits": 64,
                           "max_entries": 1, "flags": 0}
    module = native_module()
    assert module.derive_native_spec(canonical(manifest_doc(maps=maps)),
                                     "linux-bpfel-v3") == canonical(expected)
    # Reusing this process for a map-less consumer must clear map declarations.
    assert json.loads(module.derive_native_spec(
        canonical(manifest_doc()), "linux-bpfel-v3"))["map"] is None


@pytest.mark.parametrize("change", [
    lambda d: d["programs"].append(copy.deepcopy(d["programs"][0])),
    lambda d: d["programs"].clear(),
    lambda d: d["target"].update(core=True),
    lambda d: d["target"].update(core=0),
    lambda d: d["target"].update(profile="linux-bpfel-core-v3"),
    lambda d: d["programs"][0].update(section="xdp/extra"),
    lambda d: d["programs"][0].update(program_type="tracepoint"),
    lambda d: d["programs"][0].update(entry="invalid/name"),
    lambda d: d["maps"][0].update(name="another_map"),
    lambda d: d["maps"][0].update(map_type="percpu_array"),
    lambda d: d["maps"][0].update(key_type="u64"),
    lambda d: d["maps"][0].update(value_type="u32"),
    lambda d: d["maps"][0].update(max_entries=2),
    lambda d: d["maps"][0].update(max_entries=True),
    lambda d: d["maps"][0].update(flags=0),
    lambda d: d["artifact"].update(kernel_license="GPL"),
    lambda d: d.update(schema_version=True),
    lambda d: d.update(unrecognized="field"),
])
def test_native_unsupported_declarations_fail_closed(change):
    module = native_module()
    doc = manifest_doc(maps=True)
    change(doc)
    with pytest.raises(module.NativeAdapterError):
        module.derive_native_spec(canonical(doc), "linux-bpfel-v3")


@pytest.mark.parametrize("raw", [
    b'{"schema_version":1,"schema_version":1}\n',
    b'{"schema_version":NaN}\n',
    json.dumps(manifest_doc()).encode(),
    canonical(manifest_doc()).rstrip(b"\n"),
])
def test_native_manifest_is_strict_canonical_json(raw):
    module = native_module()
    with pytest.raises(module.NativeAdapterError):
        module.derive_native_spec(raw, "linux-bpfel-v3")


def test_native_json_refuses_overflowing_float():
    module = native_module()
    with pytest.raises(module.NativeAdapterError):
        module.strict_json(b'{"duration_s":1e999}\n')


def admitted_readelf():
    from mojobpf.execution import ExecutionRequest, ExecutionPins, admit_execution
    path = "/usr/bin/readelf"
    assert Path(path).is_file(), "ENVIRONMENT FAILURE: readelf missing"
    return admit_execution(ExecutionRequest(name="readelf", argv0=path,
                           allow_path_lookup=False),
                           ExecutionPins(entry_sha256=hashlib.sha256(
                               Path(path).read_bytes()).hexdigest()))


@pytest.fixture
def marker_native(tmp_path):
    # A real same-version DSO, with separate constructor and entry markers.
    # --list must not execute either. Pins changed after capture must refuse.
    cc = "/usr/bin/cc"
    assert Path(cc).is_file(), "ENVIRONMENT FAILURE: C control compiler missing"
    library = tmp_path / "lib"
    library.mkdir()
    original = library / "libnative_marker.so.1.0"
    replacement = tmp_path / "libnative_marker.so.1.0"
    source = tmp_path / "marker.c"
    source.write_text('''#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void marker(void) {
  const char *p=getenv("MOJOBPF_CONSTRUCTOR_MARKER");
  if(p) { FILE *f=fopen(p,"w"); if(f){fputs(MARKER,f);fclose(f);} }
}
int same_version(void) { return 1; }
''')
    for path, text in [(original, '"original"'), (replacement, '"replacement"')]:
        subprocess.run([cc, "-fPIC", "-shared", "-Wl,-soname,libnative_marker.so.1",
                        "-DMARKER=" + text, str(source), "-o", str(path)], check=True)
    (library / "libnative_marker.so.1").symlink_to(original.name)
    (library / "libnative_marker.so").symlink_to("libnative_marker.so.1")
    entry_source = tmp_path / "entry.c"
    entry_source.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
extern int same_version(void);
int main(void) {
  const char *p=getenv("MOJOBPF_ENTRY_MARKER");
  if(p){FILE *f=fopen(p,"w");if(f){fputs("entered",f);fclose(f);}}
  p=getenv("MOJOBPF_NATIVE_PID_MARKER");
  if(p){FILE *f=fopen(p,"w");if(f){fprintf(f,"%ld",(long)getpid());fclose(f);}}
  if(getenv("MOJOBPF_NATIVE_HANG")) sleep(300);
  return same_version()==1 ? 0 : 9;
}
''')
    entry = tmp_path / "native-entry"
    subprocess.run([cc, str(entry_source), "-L" + str(library), "-lnative_marker",
                    "-Wl,-rpath," + str(library), "-o", str(entry)], check=True)
    module = native_module()
    assert hasattr(module, "observe_runtime_closure"), "native runtime closure observation is missing"
    closure = module.observe_runtime_closure({"readelf": admitted_readelf()}, {"lower": str(entry)})
    return entry, original, replacement, closure


def test_native_runtime_closure_mapping_is_observational(marker_native, tmp_path, monkeypatch):
    entry, _original, _replacement, closure = marker_native
    module = native_module()
    constructor, marker = tmp_path / "ctor", tmp_path / "entered"
    monkeypatch.setenv("MOJOBPF_CONSTRUCTOR_MARKER", str(constructor))
    monkeypatch.setenv("MOJOBPF_ENTRY_MARKER", str(marker))
    admitted = module.admit_runtime_closure(canonical(closure), hashlib.sha256(canonical(closure)).hexdigest())
    assert not constructor.exists() and not marker.exists()
    record, _stdout, _stderr = admitted.run("lower", [])
    assert record["exit_code"] == 0
    assert constructor.read_text() == "original"
    assert marker.read_text() == "entered"


def test_native_library_changed_before_probe_never_runs_constructor(marker_native, tmp_path, monkeypatch):
    _entry, original, replacement, closure = marker_native
    module = native_module()
    marker = tmp_path / "ctor"
    monkeypatch.setenv("MOJOBPF_CONSTRUCTOR_MARKER", str(marker))
    original.write_bytes(replacement.read_bytes())
    with pytest.raises(module.NativeAdapterError, match="changed|pin|identity"):
        module.admit_runtime_closure(canonical(closure), hashlib.sha256(canonical(closure)).hexdigest())
    assert not marker.exists()


def test_native_library_changed_after_mapping_never_runs_entry(marker_native, tmp_path, monkeypatch):
    _entry, original, replacement, closure = marker_native
    module = native_module()
    admitted = module.admit_runtime_closure(canonical(closure), hashlib.sha256(canonical(closure)).hexdigest())
    constructor, entry_marker = tmp_path / "ctor", tmp_path / "entered"
    monkeypatch.setenv("MOJOBPF_CONSTRUCTOR_MARKER", str(constructor))
    monkeypatch.setenv("MOJOBPF_ENTRY_MARKER", str(entry_marker))
    original.write_bytes(replacement.read_bytes())
    with pytest.raises(module.NativeAdapterError):
        admitted.run("lower", [])
    assert not constructor.exists() and not entry_marker.exists()


@pytest.mark.parametrize("variable", ["LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT",
                                     "LD_DEBUG", "GLIBC_TUNABLES", "DYLD_INSERT_LIBRARIES"])
def test_native_loader_override_refuses_before_constructor(marker_native, tmp_path, monkeypatch, variable):
    _entry, _original, replacement, closure = marker_native
    module = native_module()
    marker = tmp_path / "ctor"
    monkeypatch.setenv("MOJOBPF_CONSTRUCTOR_MARKER", str(marker))
    monkeypatch.setenv(variable, str(replacement))
    with pytest.raises(module.NativeAdapterError, match="loader"):
        module.admit_runtime_closure(canonical(closure), hashlib.sha256(canonical(closure)).hexdigest())
    assert not marker.exists()


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=2),
    lambda d: d.update(controls=[]),
    lambda d: d["controls"][0].update(sha256="1" * 64),
    lambda d: d["objects"][0].update(unknown="field"),
    lambda d: d["entries"][0]["resolved"].pop(),
    lambda d: d["entries"][0].update(edges=[]),
    lambda d: d["entries"][0]["edges"][0].update(needed="unresolved.so"),
    lambda d: d["objects"][0].update(role="unrecognized"),
])
def test_native_closure_incomplete_inventory_refuses_before_entry(marker_native, tmp_path, monkeypatch, change):
    _entry, _original, _replacement, closure = marker_native
    module = native_module()
    constructor, entry = tmp_path / "ctor", tmp_path / "entered"
    monkeypatch.setenv("MOJOBPF_CONSTRUCTOR_MARKER", str(constructor))
    monkeypatch.setenv("MOJOBPF_ENTRY_MARKER", str(entry))
    altered = copy.deepcopy(closure)
    change(altered)
    raw = canonical(altered)
    with pytest.raises(module.NativeAdapterError):
        module.admit_runtime_closure(raw, hashlib.sha256(raw).hexdigest())
    assert not constructor.exists() and not entry.exists()


def test_native_closure_descriptor_needs_external_pin(marker_native, tmp_path, monkeypatch):
    _entry, _original, _replacement, closure = marker_native
    module = native_module()
    marker = tmp_path / "entered"
    monkeypatch.setenv("MOJOBPF_ENTRY_MARKER", str(marker))
    with pytest.raises(module.NativeAdapterError, match="pin"):
        module.admit_runtime_closure(canonical(closure), "1" * 64)
    assert not marker.exists()


def test_native_symlink_repoint_before_mapping_refuses(marker_native, tmp_path, monkeypatch):
    _entry, original, replacement, closure = marker_native
    module = native_module()
    marker = tmp_path / "ctor"
    monkeypatch.setenv("MOJOBPF_CONSTRUCTOR_MARKER", str(marker))
    link = original.parent / "libnative_marker.so.1"
    link.unlink()
    link.symlink_to(replacement)
    with pytest.raises(module.NativeAdapterError):
        module.admit_runtime_closure(canonical(closure), hashlib.sha256(canonical(closure)).hexdigest())
    assert not marker.exists()


def fixture_bundle(tmp_path, closure, lower):
    module = native_module()
    root = tmp_path / "bundle"
    root.mkdir()
    service = root / "native_adapter.py"
    service.write_bytes(Path(module.__file__).read_bytes())
    from mojobpf import execution
    sibling = root / "execution.py"
    sibling.write_bytes(Path(execution.__file__).read_bytes())
    closure_path = root / "runtime-closure.json"
    closure_path.write_bytes(canonical(closure))

    def file_record(path):
        return {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size}

    descriptor = {"schema_version": 1, "route_id": ROUTE, "model_id": MODEL,
        "profile_id": "linux-bpfel-v3", "runtime_qualified": False,
        "service": file_record(service), "execution": file_record(sibling),
        "runtime_closure": file_record(closure_path),
        "native_tools": {"lower": {"path": str(lower), "sha256": hashlib.sha256(lower.read_bytes()).hexdigest(),
                                    "size": lower.stat().st_size}},
        "transform_source_index_sha256": "5" * 64}
    descriptor_path = root / "native-bundle.json"
    descriptor_path.write_bytes(canonical(descriptor))
    record = {"adapter_path": str(service), "service_sha256": descriptor["service"]["sha256"],
              "execution_sibling_sha256": descriptor["execution"]["sha256"],
              "bundle_descriptor_path": str(descriptor_path),
              "bundle_descriptor_sha256": hashlib.sha256(descriptor_path.read_bytes()).hexdigest(),
              "runtime_closure_path": str(closure_path),
              "runtime_closure_sha256": hashlib.sha256(closure_path.read_bytes()).hexdigest(),
              "route_id": ROUTE, "qualified": False}
    return service, record


def test_native_rejects_unpinned_chain_before_probe(marker_native, tmp_path, monkeypatch):
    lower, _original, _replacement, closure = marker_native
    module = native_module()
    service, record = fixture_bundle(tmp_path, closure, lower)
    assert hasattr(module, "admit_native_bundle"), "strict native bundle admission is missing"
    marker = tmp_path / "entered"
    monkeypatch.setenv("MOJOBPF_ENTRY_MARKER", str(marker))
    sibling = service.with_name("execution.py")
    sibling.write_bytes(sibling.read_bytes() + b"\n# replaced sibling\n")
    with pytest.raises(module.NativeAdapterError):
        module.admit_native_bundle(record, str(service))
    assert not marker.exists()


@pytest.mark.parametrize("value", [None, "{}", "\x00", "x" * 65537],
                         ids=["missing", "malformed", "nul", "oversized"])
def test_standalone_requires_independent_pin_record(tmp_path, value):
    module = native_module()
    # Request rejection cannot inherit a self-reported adjacent descriptor.
    manifest = tmp_path / "captured.json"
    manifest.write_bytes(canonical(manifest_doc()))
    ir = tmp_path / "source.ll"
    ir.write_text("; not executed\n")
    request = tmp_path / "request.json"
    request.write_bytes(canonical({"schema_version": 1, "input_ir": str(ir),
        "manifest_path": str(manifest), "profile_id": "linux-bpfel-v3",
        "output_dir": str(tmp_path / "out"), "diagnostic_mode": "text"}))
    response = tmp_path / "response.json"
    assert hasattr(module, "handle_request"), "standalone native v1 handler is missing"
    environment = dict(os.environ)
    environment.pop("MOJOBPF_NATIVE_ADMISSION", None)
    if value is not None and "\x00" not in value:
        environment["MOJOBPF_NATIVE_ADMISSION"] = value
    if value == "\x00":
        # OS environments cannot carry NUL; the public parser must reject it.
        with pytest.raises(module.NativeAdapterError):
            module.parse_admission_value(value)
        return
    proc = subprocess.run([sys.executable, module.__file__, "--request", str(request),
                           "--response", str(response)], env=environment,
                           capture_output=True, text=True, timeout=10)
    assert proc.returncode == 1, proc.stderr
    observed = json.loads(response.read_bytes())
    assert set(observed) == {"schema_version", "ok", "outputs", "diagnostics"}
    assert observed["ok"] is False and observed["outputs"] == {}
    assert set(observed["diagnostics"][0]) == {"code", "stage", "severity", "explanation", "location", "remedy"}
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("change", [
    lambda d: d.update(schema_version=True),
    lambda d: d.update(schema_version=1.0),
    lambda d: d.update(profile_id="unknown"),
    lambda d: d.update(diagnostic_mode="json"),
    lambda d: d.update(unknown="field"),
    lambda d: d.pop("manifest_path"),
])
def test_native_v1_request_consistency_controls(tmp_path, change):
    module = native_module()
    request = {"schema_version": 1, "input_ir": str(tmp_path / "raw.ll"),
               "manifest_path": str(tmp_path / "manifest.json"), "profile_id": "linux-bpfel-v3",
               "output_dir": str(tmp_path / "out"), "diagnostic_mode": "text"}
    change(request)
    req, resp = tmp_path / "request.json", tmp_path / "response.json"
    req.write_bytes(canonical(request))
    assert module.handle_request(str(req), str(resp)) == 1
    response = json.loads(resp.read_bytes())
    assert response["ok"] is False and response["outputs"] == {}
    assert response["diagnostics"][0]["code"] == "MBPF212"
    assert not (tmp_path / "out").exists()


def test_native_v1_duplicate_request_and_unusable_response(tmp_path):
    module = native_module()
    request, response = tmp_path / "request.json", tmp_path / "response.json"
    request.write_bytes(b'{"schema_version":1,"schema_version":1}\n')
    assert module.handle_request(str(request), str(response)) == 1
    assert json.loads(response.read_bytes())["ok"] is False
    response.unlink()
    response.mkdir()
    assert module.handle_request(str(request), str(response)) == 2
    assert response.is_dir()


def compiler_controls():
    # Reuse the public test-owned admitted producer-model fixture and native
    # build selector, never a private artifact path or production checker.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "compiler" / "tests"))
    return importlib.import_module("test_target_model")


@pytest.fixture
def real_bundle(tmp_path):
    controls = compiler_controls()
    lower = controls.lower_tool()
    module = native_module()
    supplied = os.environ.get("MOJOBPF_NATIVE_RUNTIME_CLOSURE")
    supplied_pin = os.environ.get("MOJOBPF_NATIVE_RUNTIME_SHA256")
    if supplied:
        raw = Path(supplied).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == supplied_pin, "ENVIRONMENT FAILURE: independently admitted runtime inventory differs"
        closure = json.loads(raw)
        assert closure["entries"][0]["path"] == str(lower)
    else:
        # Synthetic IR unit controls may use their test-owned observation.
        # Genuine-source qualification requires a separately supplied pin.
        closure = module.observe_runtime_closure({"readelf": admitted_readelf()}, {"lower": str(lower)})
    return fixture_bundle(tmp_path, closure, lower)


def serve_native(tmp_path, service, record, *, maps=False, bitcode=False, ir_override=None, expected_exit=0):
    controls = compiler_controls()
    raw = tmp_path / "source.ll"
    ir = controls.module(controls.MAP_BODY if maps else "entry:\n  ret i32 2\n",
                         controls.DECLS if maps else "",
                         header="i32 @independent_entry(ptr noundef %ctx)")
    if ir_override is not None:
        ir = ir_override
    raw.write_text(ir)
    if bitcode:
        raw_bc = tmp_path / "source.bc"
        controls.checked([controls.llvm_tool("opt"), "-passes=verify", raw, "-o", raw_bc])
        raw = raw_bc
    manifest = tmp_path / "captured-manifest.json"
    manifest.write_bytes(canonical(manifest_doc(maps=maps)))
    request = {"schema_version": 1, "input_ir": str(raw), "manifest_path": str(manifest),
               "profile_id": "linux-bpfel-v3", "output_dir": str(tmp_path / "out"), "diagnostic_mode": "text"}
    req_path, resp_path = tmp_path / "request.json", tmp_path / "response.json"
    req_path.write_bytes(canonical(request))
    environment = dict(os.environ, MOJOBPF_NATIVE_ADMISSION=canonical(record).decode("ascii"),
                       PYTHONPATH="/unadmitted/host/package", PYTHONSAFEPATH="1")
    completed = subprocess.run([sys.executable, str(service), "--request", str(req_path), "--response", str(resp_path)],
                    cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=20)
    assert completed.returncode == expected_exit, completed.stdout + completed.stderr + (resp_path.read_text() if resp_path.exists() else "no response")
    return raw, request, json.loads(resp_path.read_bytes()), completed


@pytest.mark.parametrize("maps,bitcode", [(False, False), (True, False), (False, True), (True, True)])
def test_native_v1_bridge(real_bundle, tmp_path, maps, bitcode):
    module = native_module()
    service, record = real_bundle
    assert hasattr(module, "handle_request"), "standalone bridge is missing"
    raw, request, response, completed = serve_native(tmp_path, service, record, maps=maps, bitcode=bitcode)
    assert set(request) == {"schema_version", "input_ir", "manifest_path", "profile_id", "output_dir", "diagnostic_mode"}
    assert set(response) == {"schema_version", "ok", "outputs", "diagnostics"}
    assert response["ok"] is True and response["diagnostics"] == []
    assert response["outputs"] == {"adapted_ir": str(tmp_path / "out" / "adapted.ll")}
    expected_spec = {"schema_version": 1, "model_id": MODEL, "profile_id": "linux-bpfel-v3",
                     "entry": "independent_entry", "program_type": "xdp", "section": "xdp",
                     "kernel_license": LICENSE, "map": None}
    if maps:
        expected_spec["map"] = {"symbol": "mojobpf_map0", "type": 2, "key_bits": 32,
                                "value_bits": 64, "max_entries": 1, "flags": 0}
    spec_path, report_path = tmp_path / "out" / "native-spec.json", tmp_path / "out" / "native-report.json"
    assert spec_path.read_bytes() == canonical(expected_spec)
    report = json.loads(report_path.read_bytes())
    assert report["input_digest"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert report["spec_digest"] == hashlib.sha256(spec_path.read_bytes()).hexdigest()
    assert report["output_digest"] == hashlib.sha256(Path(response["outputs"]["adapted_ir"]).read_bytes()).hexdigest()
    assert report["runtime_qualified"] is False
    assert "native_command" in completed.stdout


@pytest.mark.parametrize("field", ["input_digest", "spec_digest", "output_digest"])
def test_native_report_each_raw_digest_is_required(real_bundle, tmp_path, field):
    module = native_module()
    service, record = real_bundle
    raw, request, response, _completed = serve_native(tmp_path, service, record)
    report_path = tmp_path / "out" / "native-report.json"
    report = json.loads(report_path.read_bytes())
    report[field] = "0" * 64
    report_path.write_bytes(canonical(report))
    with pytest.raises(module.NativeAdapterError, match="digest"):
        module.read_native_outputs(request["output_dir"], (tmp_path / "out" / "native-spec.json").read_bytes(),
                                   str(raw), response["outputs"]["adapted_ir"])


@pytest.mark.parametrize("change", [
    lambda d: d["target_facts"].update(types=[{}]),
    lambda d: d["target_facts"].update(attributes=[{}]),
    lambda d: d["target_facts"].update(gep_offsets=[{}]),
    lambda d: d["target_facts"]["source_audit"].update(module_flag=3.0),
    lambda d: d["target_facts"]["source_audit"].update(scratch_cells=[{}]),
    lambda d: d["target_facts"]["source_audit"].update(key_consumers=[{}]),
    lambda d: d["transformations"].append({"kind": "key", "source": "%x", "target": "%y",
                                          "source_ordinal": True, "literal": []}),
])
def test_native_report_requires_complete_typed_facts(real_bundle, tmp_path, change):
    module = native_module()
    service, record = real_bundle
    raw, request, _response, _completed = serve_native(tmp_path, service, record)
    report_path = tmp_path / "out" / "native-report.json"
    report = json.loads(report_path.read_bytes())
    change(report)
    report_path.write_bytes(canonical(report))
    with pytest.raises(module.NativeAdapterError):
        module.read_native_outputs(request["output_dir"], (tmp_path / "out" / "native-spec.json").read_bytes(), str(raw))


@pytest.mark.parametrize("field,value", [("size", 32.0), ("alignment", 8.0),
                                        ("producer_authenticated", 0), ("source_lines", 0)])
def test_native_map_metadata_refuses_equal_but_wrong_types(real_bundle, tmp_path, field, value):
    module = native_module()
    service, record = real_bundle
    raw, request, _response, _completed = serve_native(tmp_path, service, record, maps=True)
    report_path = tmp_path / "out" / "native-report.json"
    report = json.loads(report_path.read_bytes())
    metadata = next(row for row in report["transformations"] if row["kind"] == "map-metadata")
    metadata[field] = value
    report_path.write_bytes(canonical(report))
    with pytest.raises(module.NativeAdapterError):
        module.read_native_outputs(request["output_dir"], (tmp_path / "out" / "native-spec.json").read_bytes(), str(raw))


def sparse_failure_report(spec_bytes):
    # Literal early reader-failure form from the native producer contract.
    return {"schema_version": 1, "mode": "lower", "model_id": MODEL, "ok": False,
            "input_digest": "a" * 64, "spec_digest": hashlib.sha256(spec_bytes).hexdigest(),
            "target_facts": None, "proof_obligations": [], "transformations": [],
            "diagnostics": [{"code": "MBPF106", "stage": "adapter.parse", "severity": "error",
                "explanation": "input parse failed", "location": "source.ll", "remedy": "restore valid IR"}],
            "runtime_qualified": False, "unproved": [], "unproved_total": 0,
            "unproved_truncated": False}


def sparse_attribute_failure(owner):
    # TargetModel records F.getName()/Owner.str(), including an unnamed
    # declaration's empty owner, before source audit rejects that declaration.
    # This partial report is a pure shape/diagnostic control, not native proof.
    module = native_module()
    spec = module.derive_native_spec(canonical(manifest_doc()), "linux-bpfel-v3")
    report = sparse_failure_report(spec)
    report["target_facts"] = {"attributes": [{"owner": owner, "slot": 0, "attribute": "noundef"}]}
    report["diagnostics"] = [{"code": "MBPF303", "stage": "adapter.audit", "severity": "error",
        "explanation": "unreserved declaration", "location": "@0", "remedy": "remove unsupported declaration"}]
    return spec, report


@pytest.mark.parametrize("owner", ["", "unreserved", "x" * 4096], ids=["unnamed", "named", "bounded"])
def test_sparse_attribute_owner_preserves_native_diagnostic(owner):
    module = native_module()
    spec, report = sparse_attribute_failure(owner)
    checked = module.validate_native_report(canonical(report), spec, "a" * 64, exit_code=4)
    assert checked["diagnostics"] == report["diagnostics"]
    assert [(row["code"], row["stage"]) for row in checked["diagnostics"]] == [("MBPF303", "adapter.audit")]
    assert checked["target_facts"]["attributes"][0]["owner"] == owner


@pytest.mark.parametrize("owner", [None, False, 0, 0.0, [], {}, "\x00", "x" * 4097],
                         ids=["null", "boolean", "integer", "float", "array", "object", "NUL", "oversize"])
def test_sparse_attribute_owner_refuses_malformed_value(owner):
    module = native_module()
    spec, report = sparse_attribute_failure(owner)
    with pytest.raises(module.NativeAdapterError):
        module.validate_native_report(canonical(report), spec, "a" * 64, exit_code=4)


@pytest.mark.parametrize("change", [
    lambda d: d["target_facts"]["attributes"][0].update(attribute=""),
    lambda d: d["target_facts"].update(input_triple=""),
    lambda d: d["target_facts"].update(entry_abi={"symbol": "", "signature": "i32 (ptr)", "calling_convention": 0}),
    lambda d: d.update(proof_obligations=[{"id": "", "status": "reader-verified", "runtime_qualified": False}]),
    lambda d: d.update(transformations=[{"kind": ""}]),
    lambda d: d["diagnostics"][0].update(explanation=""),
    lambda d: d["target_facts"]["attributes"][0].update(unknown=True),
    lambda d: d["target_facts"]["attributes"][0].update(slot=False),
    lambda d: d["target_facts"].update(attributes=[{"owner": "", "slot": 0, "attribute": "noundef"}] * 16385),
], ids=["attribute", "triple", "symbol", "proof-id", "transform-kind", "diagnostic", "unknown", "slot-type", "inventory-bound"])
def test_sparse_empty_owner_does_not_relax_other_fields(change):
    module = native_module()
    spec, report = sparse_attribute_failure("")
    change(report)
    with pytest.raises(module.NativeAdapterError):
        module.validate_native_report(canonical(report), spec, "a" * 64, exit_code=4)


@pytest.mark.parametrize("field,value", [("target_facts", []), ("proof_obligations", 0),
    ("transformations", True), ("target_facts", {"entry_abi": []}),
    ("target_facts", {"pointer_bits": 64.0}), ("proof_obligations", [True]),
    ("transformations", [32]), ("target_facts", {"unknown": "field"}),
    ("target_facts", {"little_endian": 1}),
    ("proof_obligations", [{"id": "producer_reader", "status": "reader-verified",
        "runtime_qualified": 0, "producer_binding": "external capture required"}]),
    ("transformations", [{"kind": "map-metadata", "symbol": "mojobpf_map0", "alignment": 8,
        "size": 32, "language": "Mojo", "producer_authenticated": 0, "source_lines": False}])])
def test_native_failure_report_refuses_wrong_sparse_shapes(field, value):
    module = native_module()
    spec_bytes = module.derive_native_spec(canonical(manifest_doc()), "linux-bpfel-v3")
    report = sparse_failure_report(spec_bytes)
    report[field] = value
    with pytest.raises(module.NativeAdapterError):
        module.validate_native_report(canonical(report), spec_bytes, "a" * 64, exit_code=4)


@pytest.mark.parametrize("case,code", [("reader", "MBPF106"), ("source-audit", "MBPF310")])
def test_native_sparse_producer_failure_keeps_diagnostics(real_bundle, tmp_path, case, code):
    controls = compiler_controls()
    ir = "not LLVM IR\n" if case == "reader" else controls.module(
        "entry:\n  %cell = alloca i32\n  ret i32 2\n", header="i32 @independent_entry(ptr noundef %ctx)")
    service, record = real_bundle
    raw, _request, response, _completed = serve_native(tmp_path, service, record, ir_override=ir, expected_exit=1)
    report = json.loads((tmp_path / "out" / "native-report.json").read_bytes())
    assert response["ok"] is False and response["outputs"] == {}
    assert response["diagnostics"] == report["diagnostics"]
    assert [row["code"] for row in response["diagnostics"]] == [code]
    assert report["input_digest"] == hashlib.sha256(raw.read_bytes()).hexdigest()
    assert report["proof_obligations"] == [] and report["transformations"] == []
    if case == "reader":
        assert report["target_facts"] is None
    else:
        assert isinstance(report["target_facts"], dict) and "source_audit" not in report["target_facts"]


def test_native_late_write_failure_keeps_full_list_payload(real_bundle, tmp_path):
    module = native_module()
    service, record = real_bundle
    raw, _request, _response, _completed = serve_native(tmp_path, service, record, maps=True)
    spec_path = tmp_path / "out" / "native-spec.json"
    unwritable_output = tmp_path / "output-directory"
    unwritable_output.mkdir()
    report_path = tmp_path / "late-write-report.json"
    bundle = module.admit_native_bundle(record, str(service))
    observed, _stdout, _stderr = bundle.closure.run("lower", ["--mode", "lower", "--input", str(raw),
        "--spec", str(spec_path), "--output", str(unwritable_output), "--report", str(report_path), "--emit", "llvm"])
    assert observed["exit_code"] == 4
    report = json.loads(report_path.read_bytes())
    checked = module.validate_native_report(report_path.read_bytes(), spec_path.read_bytes(),
        hashlib.sha256(raw.read_bytes()).hexdigest(), exit_code=4)
    assert checked["diagnostics"] == report["diagnostics"]
    assert [(row["code"], row["stage"]) for row in checked["diagnostics"]] == [("MBPF106", "adapter.write")]
    assert "source_audit" in report["target_facts"]
    assert len(report["proof_obligations"]) == 11 and report["transformations"]


def test_native_spec_digest_keeps_file_format(real_bundle, tmp_path):
    module = native_module()
    service, record = real_bundle
    raw, _request, _response, _completed = serve_native(tmp_path, service, record)
    canonical_spec = (tmp_path / "out" / "native-spec.json").read_bytes()
    formatted = tmp_path / "formatted.json"
    formatted.write_text(json.dumps(json.loads(canonical_spec), indent=2) + "\n")
    output, report_path = tmp_path / "formatted.ll", tmp_path / "formatted-report.json"
    bundle = module.admit_native_bundle(record, str(service))
    observed, _stdout, _stderr = bundle.closure.run("lower", ["--mode", "lower", "--input", str(raw),
        "--spec", str(formatted), "--output", str(output), "--report", str(report_path), "--emit", "llvm"])
    assert observed["exit_code"] == 0
    report = json.loads(report_path.read_bytes())
    assert report["spec_digest"] == hashlib.sha256(formatted.read_bytes()).hexdigest()
    assert report["spec_digest"] != hashlib.sha256(canonical_spec).hexdigest()
    # Replaying a differently formatted historical specification/report pair
    # against canonical bytes cannot satisfy the raw-file contract.
    with pytest.raises(module.NativeAdapterError, match="digest"):
        module.validate_native_report(report_path.read_bytes(), canonical_spec,
            hashlib.sha256(raw.read_bytes()).hexdigest(), hashlib.sha256(output.read_bytes()).hexdigest())


def live_pid(pid):
    try:
        data = Path("/proc/%d/stat" % pid).read_text()
        return data[data.rindex(")") + 2:].split()[0] != "Z"
    except FileNotFoundError:
        return False


@pytest.mark.parametrize("interrupt", [False, True], ids=["timeout", "cancel"])
def test_outer_bridge_failure_reaps_nested_native(marker_native, tmp_path, monkeypatch, interrupt):
    from mojobpf import build
    lower, _original, _replacement, closure = marker_native
    module = native_module()
    service, record = fixture_bundle(tmp_path, closure, lower)
    admitted = module.admit_native_bundle(record, str(service))
    pid_marker = tmp_path / "owned-native.pid"
    monkeypatch.setenv("MOJOBPF_NATIVE_PID_MARKER", str(pid_marker))
    monkeypatch.setenv("MOJOBPF_NATIVE_HANG", "1")
    manifest, ir = tmp_path / "captured.json", tmp_path / "raw.ll"
    manifest.write_bytes(canonical(manifest_doc()))
    ir.write_text("; native protocol control\n")
    request = tmp_path / "request.json"
    request.write_bytes(canonical({"schema_version": 1, "input_ir": str(ir),
        "manifest_path": str(manifest), "profile_id": "linux-bpfel-v3",
        "output_dir": str(tmp_path / "out"), "diagnostic_mode": "text"}))
    real_wait, interrupted = subprocess.Popen.wait, False

    def cancel_once(process, *args, **kwargs):
        nonlocal interrupted
        if not interrupted:
            deadline = time.monotonic() + 3
            while not pid_marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert pid_marker.exists(), "positive control never entered the native tool"
            interrupted = True
            raise KeyboardInterrupt
        return real_wait(process, *args, **kwargs)

    if interrupt:
        monkeypatch.setattr(subprocess.Popen, "wait", cancel_once)
    try:
        argv = [sys.executable, str(service), "--request", str(request), "--response", str(tmp_path / "response.json")]
        args = (argv, "build.adapter", 1, str(tmp_path / "bridge.log"), str(tmp_path))
        kwargs = {"execution": admitted.adapter_execution,
                  "env_extra": {"MOJOBPF_NATIVE_ADMISSION": canonical(record).decode("ascii")}}
        if interrupt:
            with pytest.raises(KeyboardInterrupt):
                build._run_step(*args, **kwargs)
        else:
            result, _stdout, _stderr, _marker = build._run_step(*args, **kwargs)
            assert result.status == "timeout"
        assert pid_marker.exists(), "positive control never entered the native tool"
        pid = int(pid_marker.read_text())
        deadline = time.monotonic() + 2
        while live_pid(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not live_pid(pid), "owned nested native process escaped outer cleanup"
    finally:
        # The RED attempt may leave precisely this owned fixture alive. Never
        # signal our parent or an unrelated group while retiring the reproducer.
        if pid_marker.exists():
            pid = int(pid_marker.read_text())
            if live_pid(pid):
                assert pid != os.getpid()
                os.kill(pid, signal.SIGKILL)


def test_native_reader_failure_is_not_a_complete_capture(marker_native, monkeypatch):
    from mojobpf import execution
    entry, _original, _replacement, closure = marker_native
    module = native_module()
    admitted = module.admit_runtime_closure(canonical(closure), hashlib.sha256(canonical(closure)).hexdigest())
    popen = execution.popen_admitted

    class BrokenReader:
        def __init__(self, stream):
            self.stream = stream

        def read(self, size):
            raise OSError("injected native pipe reader failure")

        def close(self):
            self.stream.close()

    def broken_pipe(*args, **kwargs):
        process = popen(*args, **kwargs)
        process.stdout = BrokenReader(process.stdout)
        return process

    monkeypatch.setattr(execution, "popen_admitted", broken_pipe)
    record, _stdout, _stderr = admitted.run("lower", [])
    assert record["status"] == "capture_failed", record


def test_direct_child_kill_uses_pidfd_not_numeric_pid(monkeypatch):
    # The native lane kills a live direct child through its
    # pidfd: the group sweep fails (mocked) and numeric kill is
    # never called, yet the child dies.
    from mojobpf import native_adapter

    process = subprocess.Popen(
        ["/bin/sleep", "30"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    calls = []

    def _no_numeric_kill(*args, **kwargs):
        calls.append("kill")
        raise AssertionError("numeric kill used")

    def _failing_sweep(*args, **kwargs):
        calls.append("killpg")
        raise OSError("sweep denied")

    monkeypatch.setattr(os, "kill", _no_numeric_kill)
    monkeypatch.setattr(os, "killpg", _failing_sweep)
    native_adapter._kill_native_group(process, False)
    assert process.wait(timeout=10) == -signal.SIGKILL, (
        process.returncode
    )
    assert calls == ["killpg"], calls
