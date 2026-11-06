# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Route dispatch between Lane-A and the parsed lowering (T4a-0).

The service selects the transform per admitted shape: qualified
shapes go parsed, unqualified shapes stay Lane-A, unknown shapes
refuse. All flags start false; per-shape flips come with their
migration phases. The parsed branch is exercised here through a
stub ``mojobpf-lower``; the real binary arrives with T4a-1.

Runnable directly (``python3 tests/compile/test_route_dispatch.py``)
or under pytest. Standard library only; no toolchain needed (the
LLVM verify step is stubbed at the service boundary).
"""

import importlib.util
import json
import os
import stat
import sys
import tempfile
import types

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
AUDIT = os.path.join(REPO_ROOT, "compiler", "audit.py")

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf import build as build_module  # noqa: E402

MODES = (
    "classifier", "classifier-loop", "map", "combined",
    "tracepoint", "event", "reserve", "subprog", "core",
    "uprobe", "skb",
)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stub_audit(qualified=(), entry="xdp_entry"):
    qualified = frozenset(qualified)
    return types.SimpleNamespace(
        ADMITTED_MODES=tuple(MODES),
        PARSED_QUALIFIED_MODES=qualified,
        parsed_qualified=lambda mode: mode in qualified,
        scan=lambda text: types.SimpleNamespace(entry=entry),
    )


def test_qualified_modes_match_migration():
    # Pinned per migration phase: T4a-1 qualifies classifier +
    # subprog, T4a-2 adds array map, T4a-3 adds combined (the
    # route flip stays evidence-gated per kind: array and
    # percpu flip, hash and lru combined stay Lane-A); each
    # later phase extends this set with its flip.
    audit = load_module("audit_route_flags", AUDIT)
    assert audit.PARSED_QUALIFIED_MODES == frozenset(
        {"classifier", "subprog", "map", "combined"}
    )
    assert tuple(audit.ADMITTED_MODES) == MODES
    for mode in MODES:
        assert audit.parsed_qualified(mode) is (
            mode in ("classifier", "subprog", "map", "combined")
        ), mode


def test_select_route_unqualified_is_lane_a():
    service = load_module("adapter_service_route_a", SERVICE)
    audit = stub_audit()
    for mode in MODES:
        assert service.select_route(mode, audit) == "lane-a", mode


def test_select_route_qualified_is_parsed():
    service = load_module("adapter_service_route_b", SERVICE)
    audit = stub_audit({"classifier"})
    assert service.select_route("classifier", audit) == "parsed"
    assert service.select_route("map", audit) == "lane-a"


def test_select_route_unknown_refuses():
    service = load_module("adapter_service_route_c", SERVICE)
    try:
        service.select_route("no-such-mode", stub_audit())
    except service.RouteRefused as exc:
        assert exc.code == "MBPF219", exc.code
    else:
        raise AssertionError("unknown mode must refuse with MBPF219")


# ---------------------------------------------------------------------------
# Driver response contract: success must name its route.
# ---------------------------------------------------------------------------

def _staged_output(root):
    path = os.path.join(root, "adapted.ll")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("; adapted\n")
    return path


def _interpret(response, root, **kwargs):
    diagnostics = []
    result = build_module._interpret_response(
        response, os.path.join(root, "response.json"), diagnostics,
        exit_code=0, adapter_dir=root, **kwargs
    )
    return result, diagnostics


def test_response_without_route_rejected():
    root = tempfile.mkdtemp(prefix="route-missing-")
    staged = _staged_output(root)
    result, diagnostics = _interpret({
        "schema_version": 1,
        "ok": True,
        "outputs": {"adapted_ir": staged},
        "diagnostics": [],
    }, root)
    assert result is None
    assert [item.code for item in diagnostics] == ["MBPF212"]
    assert "route" in diagnostics[0].explanation


def test_response_with_unknown_route_rejected():
    root = tempfile.mkdtemp(prefix="route-unknown-")
    staged = _staged_output(root)
    result, diagnostics = _interpret({
        "schema_version": 1,
        "ok": True,
        "outputs": {"adapted_ir": staged, "route": "side-channel"},
        "diagnostics": [],
    }, root)
    assert result is None
    assert [item.code for item in diagnostics] == ["MBPF212"]


def test_response_lane_a_route_accepted():
    root = tempfile.mkdtemp(prefix="route-lanea-")
    staged = _staged_output(root)
    result, diagnostics = _interpret({
        "schema_version": 1,
        "ok": True,
        "outputs": {"adapted_ir": staged, "route": "lane-a"},
        "diagnostics": [],
    }, root)
    assert result == (staged, "lane-a"), diagnostics
    assert diagnostics == []


def test_response_parsed_route_accepted():
    root = tempfile.mkdtemp(prefix="route-parsed-")
    staged = _staged_output(root)
    result, diagnostics = _interpret({
        "schema_version": 1,
        "ok": True,
        "outputs": {"adapted_ir": staged, "route": "parsed"},
        "diagnostics": [],
    }, root)
    assert result == (staged, "parsed"), diagnostics
    assert diagnostics == []


def test_transforms_for_mixed_routes_sorted():
    assert build_module._transforms_for_routes(
        ("parsed", "lane-a", "parsed")
    ) == (
        "mojo-frontend",
        "ir-adapter(lane-a)",
        "ir-adapter(parsed)",
        "llc-backend",
    )


def test_transforms_for_unknown_route_refuses():
    try:
        build_module._transforms_for_routes(("side-channel",))
    except ValueError as exc:
        assert "side-channel" in str(exc)
    else:
        raise AssertionError("unknown route must refuse")


def test_native_response_labels_native():
    root = tempfile.mkdtemp(prefix="route-native-")
    staged = _staged_output(root)
    result, diagnostics = _interpret({
        "schema_version": 1,
        "ok": True,
        "outputs": {"adapted_ir": staged},
        "diagnostics": [],
    }, root, native=True)
    assert result == (staged, "native"), diagnostics
    assert diagnostics == []


# ---------------------------------------------------------------------------
# Service end to end: dispatch reaches the right transform.
# ---------------------------------------------------------------------------

class _StubAdapterError(Exception):
    def to_diagnostic(self):
        raise AssertionError("stub adapter must not reject")


def _stub_adapter(mode, qualified, entry="xdp_entry"):
    audit = stub_audit(qualified, entry)
    scan = audit.scan
    audit.scan = lambda text: types.SimpleNamespace(
        entry=scan(text).entry, mode=mode, entries=1,
        percpu=False, hashkind=False, lrukind=False,
    )
    return types.SimpleNamespace(
        AdapterError=_StubAdapterError,
        audit=audit,
        validate=lambda text: mode,
        adapt=lambda text: "; lane-a adapted\n",
    )


def _service_request(root):
    input_ir = os.path.join(root, "input.ll")
    with open(input_ir, "w", encoding="utf-8") as handle:
        handle.write("; raw\n")
    manifest = os.path.join(root, "mojobpf.toml")
    with open(manifest, "w", encoding="utf-8") as handle:
        handle.write(CLASSIFIER_MANIFEST)
    out_dir = os.path.join(root, "out")
    request_path = os.path.join(root, "request.json")
    response_path = os.path.join(root, "response.json")
    service = load_module(
        "adapter_service_e2e_%s" % os.path.basename(root), SERVICE
    )
    with open(request_path, "w", encoding="utf-8") as handle:
        json.dump({
            "schema_version": service.ADAPTER_SCHEMA_VERSION,
            "input_ir": input_ir,
            "manifest_path": manifest,
            "profile_id": "linux-bpfel-v3",
            "output_dir": out_dir,
            "diagnostic_mode": "text",
        }, handle)
    return service, request_path, response_path


def _run_service(service, request_path, response_path, adapter):
    saved_loader = service._load_adapter
    saved_verify = service._verify_ir
    service._load_adapter = lambda: adapter
    service._verify_ir = lambda path: None
    try:
        code = service.handle_request(request_path, response_path)
    finally:
        service._load_adapter = saved_loader
        service._verify_ir = saved_verify
    with open(response_path, encoding="utf-8") as handle:
        return code, json.load(handle)


def test_classifier_gate_qualified_routes_parsed():
    # T4a-1 Step 5: the classifier (and subprog) migrated, so the
    # real audit routes them parsed.
    audit = load_module("audit_classifier_gate", AUDIT)
    assert audit.parsed_qualified("classifier") is True
    assert audit.parsed_qualified("subprog") is True
    service = load_module("adapter_service_classifier_gate", SERVICE)
    assert service.select_route("classifier", audit) == "parsed"
    assert service.select_route("subprog", audit) == "parsed"


def test_service_lane_a_response_carries_route():
    root = tempfile.mkdtemp(prefix="svc-lanea-")
    service, request_path, response_path = _service_request(root)
    code, document = _run_service(
        service, request_path, response_path,
        _stub_adapter("map", qualified=()),
    )
    assert code == 0, document
    assert document["ok"] is True, document
    assert document["outputs"]["route"] == "lane-a", document


def _write_stub_lower(root, body):
    path = os.path.join(root, "mojobpf-lower")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _write_manifest(root, body):
    path = os.path.join(root, "mojobpf.toml")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path


CLASSIFIER_MANIFEST = """\
schema_version = 1

[project]
name = "xdp-pass"

[target]
profile = "linux-bpfel-v3"

[artifact]
name = "xdp_pass"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "xdp_pass.mojo"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"
"""


def test_author_spec_classifier():
    service = load_module("adapter_service_spec_a", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-ok-")
    manifest = _write_manifest(root, CLASSIFIER_MANIFEST)
    spec, refusal = service._author_spec(
        "classifier", "xdp_entry", manifest, "linux-bpfel-v3",
    )
    assert refusal is None
    assert spec == {
        "schema_version": 1,
        "model_id": "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1",
        "profile_id": "linux-bpfel-v3",
        "entry": "xdp_entry",
        "program_type": "xdp",
        "section": "xdp",
        "kernel_license": "Apache-2.0 WITH LLVM-exception",
        "map": None,
    }, spec


def test_author_spec_missing_entry_refuses():
    service = load_module("adapter_service_spec_b", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-noentry-")
    manifest = _write_manifest(root, CLASSIFIER_MANIFEST)
    spec, refusal = service._author_spec(
        "classifier", "ghost_entry", manifest, "linux-bpfel-v3",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "ghost_entry" in refusal.explanation


def test_author_spec_with_maps_refuses():
    service = load_module("adapter_service_spec_c", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-maps-")
    manifest = _write_manifest(root, CLASSIFIER_MANIFEST + """\

[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
""")
    spec, refusal = service._author_spec(
        "classifier", "xdp_entry", manifest, "linux-bpfel-v3",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"


def test_author_spec_unreadable_manifest_refuses():
    service = load_module("adapter_service_spec_d", SERVICE)
    spec, refusal = service._author_spec(
        "classifier", "xdp_entry",
        "/nonexistent/mojobpf.toml", "linux-bpfel-v3",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"


def test_author_spec_non_classifier_refuses():
    service = load_module("adapter_service_spec_e", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-mapmode-")
    manifest = _write_manifest(root, CLASSIFIER_MANIFEST)
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"


SUBPROG_MANIFEST = """\
schema_version = 1

[project]
name = "subprog-call"

[target]
profile = "linux-bpfel-v3-subprog"

[artifact]
name = "subprog_decision"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "decision.mojo"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"
"""


def test_author_spec_subprog():
    service = load_module("adapter_service_spec_f", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-subprog-")
    manifest = _write_manifest(root, SUBPROG_MANIFEST)
    spec, refusal = service._author_spec(
        "subprog", "xdp_entry", manifest,
        "linux-bpfel-v3-subprog",
    )
    assert refusal is None
    assert spec == {
        "schema_version": 1,
        "model_id": "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1",
        "profile_id": "linux-bpfel-v3-subprog",
        "entry": "xdp_entry",
        "program_type": "xdp",
        "section": "xdp",
        "kernel_license": "Apache-2.0 WITH LLVM-exception",
        "map": None,
    }, spec


def test_service_spec_entry_comes_from_scan():
    # The parsed branch authors the spec entry from the audited IR
    # (scan), not from the request: a trace_entry scan against a
    # trace_entry manifest propagates end to end.
    root = tempfile.mkdtemp(prefix="svc-scanentry-")
    lower = _write_stub_lower(root, """#!/bin/sh
input=""; spec=""; output=""; report=""
while [ $# -gt 0 ]; do
  case "$1" in
    --input) input="$2"; shift 2;;
    --spec) spec="$2"; shift 2;;
    --output) output="$2"; shift 2;;
    --report) report="$2"; shift 2;;
    *) shift;;
  esac
done
cp "$input" "$output"
printf '{"mode":"lower"}\\n' > "$report"
""")
    service, request_path, response_path = _service_request(root)
    with open(os.path.join(root, "mojobpf.toml"), "w",
              encoding="utf-8") as handle:
        handle.write(CLASSIFIER_MANIFEST.replace(
            'entry = "xdp_entry"\nprogram_type = "xdp"\nsection = "xdp"',
            'entry = "trace_entry"\nprogram_type = "tracepoint"\nsection = "tracepoint"',
        ))
    adapter = _stub_adapter(
        "classifier", {"classifier"}, entry="trace_entry",
    )
    saved = os.environ.get(service.LOWER_ENV)
    os.environ[service.LOWER_ENV] = lower
    try:
        code, document = _run_service(
            service, request_path, response_path, adapter,
        )
    finally:
        if saved is None:
            del os.environ[service.LOWER_ENV]
        else:
            os.environ[service.LOWER_ENV] = saved
    assert code == 0, document
    assert document["ok"] is True, document
    assert document["outputs"]["route"] == "parsed", document
    with open(
        os.path.join(root, "out", "lower-spec.json"),
        encoding="utf-8",
    ) as handle:
        spec = json.load(handle)
    assert spec["entry"] == "trace_entry", spec
    assert spec["program_type"] == "tracepoint", spec


def test_service_parsed_branch_runs_lower():
    root = tempfile.mkdtemp(prefix="svc-parsed-")
    lower = _write_stub_lower(root, """#!/bin/sh
# Stub lowering: copy input to output, write a lower report.
input=""; spec=""; output=""; report=""
while [ $# -gt 0 ]; do
  case "$1" in
    --input) input="$2"; shift 2;;
    --spec) spec="$2"; shift 2;;
    --output) output="$2"; shift 2;;
    --report) report="$2"; shift 2;;
    *) shift;;
  esac
done
cp "$input" "$output"
printf '{"mode":"lower","spec":"%s"}\\n' "$spec" > "$report"
""")
    service, request_path, response_path = _service_request(root)
    saved = os.environ.get(service.LOWER_ENV)
    os.environ[service.LOWER_ENV] = lower
    try:
        code, document = _run_service(
            service, request_path, response_path,
            _stub_adapter("classifier", qualified={"classifier"}),
        )
    finally:
        if saved is None:
            del os.environ[service.LOWER_ENV]
        else:
            os.environ[service.LOWER_ENV] = saved
    assert code == 0, document
    assert document["ok"] is True, document
    assert document["outputs"]["route"] == "parsed", document
    assert os.path.isfile(document["outputs"]["adapted_ir"])
    with open(
        os.path.join(root, "out", "lower-spec.json"),
        encoding="utf-8",
    ) as handle:
        spec = json.load(handle)
    assert spec["model_id"] == (
        "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1"
    ), spec
    assert spec["entry"] == "xdp_entry", spec
    assert spec["map"] is None, spec


def test_service_parsed_branch_without_lower_refuses():
    root = tempfile.mkdtemp(prefix="svc-nolower-")
    service, request_path, response_path = _service_request(root)
    saved_lower = os.environ.pop(service.LOWER_ENV, None)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = root  # no mojobpf-lower here
    try:
        code, document = _run_service(
            service, request_path, response_path,
            _stub_adapter("classifier", qualified={"classifier"}),
        )
    finally:
        if saved_lower is not None:
            os.environ[service.LOWER_ENV] = saved_lower
        os.environ["PATH"] = saved_path
    assert code == 1, document
    assert document["ok"] is False, document
    codes = [item["code"] for item in document["diagnostics"]]
    assert codes == ["MBPF219"], document
    assert "lane-a" not in json.dumps(document["outputs"])


def test_service_parsed_branch_lower_failure_refuses():
    root = tempfile.mkdtemp(prefix="svc-badlower-")
    lower = _write_stub_lower(root, """#!/bin/sh
echo "lower: hostile input rejected" >&2
exit 3
""")
    service, request_path, response_path = _service_request(root)
    saved = os.environ.get(service.LOWER_ENV)
    os.environ[service.LOWER_ENV] = lower
    try:
        code, document = _run_service(
            service, request_path, response_path,
            _stub_adapter("classifier", qualified={"classifier"}),
        )
    finally:
        if saved is None:
            del os.environ[service.LOWER_ENV]
        else:
            os.environ[service.LOWER_ENV] = saved
    assert code == 1, document
    assert document["ok"] is False, document
    codes = [item["code"] for item in document["diagnostics"]]
    assert codes == ["MBPF219"], document


# ---------------------------------------------------------------------------
# T4a-1: unproved obligations surface as one MBPF220 warning.
# ---------------------------------------------------------------------------

def _write_python_stub_lower(root, document):
    body = "#!%s\n" % sys.executable
    body += (
        "import json, sys\n"
        "args = sys.argv[1:]\n"
        "input = args[args.index('--input') + 1]\n"
        "output = args[args.index('--output') + 1]\n"
        "report = args[args.index('--report') + 1]\n"
        "with open(input, 'rb') as handle:\n"
        "    data = handle.read()\n"
        "with open(output, 'wb') as handle:\n"
        "    handle.write(data)\n"
        "with open(report, 'w', encoding='utf-8') as handle:\n"
        "    json.dump(%r, handle)\n" % (document,)
    )
    return _write_stub_lower(root, body)


def _unproved_entry(code, location):
    return {
        "code": code,
        "stage": "adapter.audit",
        "severity": "warning",
        "explanation": "proof cannot establish %s" % code,
        "location": location,
        "remedy": "tighten the guard",
    }


def _run_parsed_with_report(root, report):
    lower = _write_python_stub_lower(root, report)
    service, request_path, response_path = _service_request(root)
    saved = os.environ.get(service.LOWER_ENV)
    os.environ[service.LOWER_ENV] = lower
    try:
        code, document = _run_service(
            service, request_path, response_path,
            _stub_adapter("classifier", qualified={"classifier"}),
        )
    finally:
        if saved is None:
            del os.environ[service.LOWER_ENV]
        else:
            os.environ[service.LOWER_ENV] = saved
    return code, document


def test_parsed_unproved_becomes_warning():
    # Unproved obligations do not fail the build: success carries
    # one MBPF220 warning naming the count and the proof codes.
    root = tempfile.mkdtemp(prefix="svc-unproved-")
    entries = [
        _unproved_entry("MBPF315", "instruction 12"),
        _unproved_entry("MBPF311", "instruction 20"),
    ]
    code, document = _run_parsed_with_report(root, {
        "mode": "lower",
        "unproved": entries,
        "unproved_total": 2,
        "unproved_truncated": False,
    })
    assert code == 0, document
    assert document["ok"] is True, document
    assert document["outputs"]["route"] == "parsed", document
    warnings = document["diagnostics"]
    assert len(warnings) == 1, document
    warning = warnings[0]
    assert warning["code"] == "MBPF220", warning
    assert warning["stage"] == "adapter.transform", warning
    assert warning["severity"] == "warning", warning
    assert "2" in warning["explanation"], warning
    assert "MBPF315" in warning["explanation"], warning
    assert "MBPF311" in warning["explanation"], warning
    assert warning["location"] == os.path.join(root, "input.ll"), warning
    assert warning["remedy"], warning


def test_parsed_unproved_truncation_noted():
    # The binary caps the recorded list; the warning says how many
    # exist beyond the recorded first entries.
    root = tempfile.mkdtemp(prefix="svc-unproved-trunc-")
    entries = [
        _unproved_entry("MBPF315", "instruction %d" % index)
        for index in range(8)
    ]
    code, document = _run_parsed_with_report(root, {
        "mode": "lower",
        "unproved": entries,
        "unproved_total": 13,
        "unproved_truncated": True,
    })
    assert code == 0, document
    assert document["ok"] is True, document
    warnings = document["diagnostics"]
    assert len(warnings) == 1, document
    assert warnings[0]["code"] == "MBPF220", warnings[0]
    assert "13" in warnings[0]["explanation"], warnings[0]
    assert "8" in warnings[0]["explanation"], warnings[0]


def test_parsed_malformed_unproved_refuses():
    # A lowering report whose unproved section is not a list of
    # shaped entries refuses: the service never forwards a
    # warning it cannot account for.
    root = tempfile.mkdtemp(prefix="svc-unproved-bad-")
    code, document = _run_parsed_with_report(root, {
        "mode": "lower",
        "unproved": [{"code": "MBPF315"}],
        "unproved_total": 1,
        "unproved_truncated": False,
    })
    assert code == 1, document
    assert document["ok"] is False, document
    codes = [item["code"] for item in document["diagnostics"]]
    assert codes == ["MBPF219"], document


def test_parsed_branch_passes_permissive_proof():
    # The production parsed route always lowers permissively:
    # qualified modes owe verdict parity, and obligations (not
    # refusals) are how the service keeps it.
    root = tempfile.mkdtemp(prefix="svc-permissive-argv-")
    record = os.path.join(root, "argv.json")
    body = "#!%s\n" % sys.executable
    body += (
        "import json, sys\n"
        "args = sys.argv[1:]\n"
        "with open(%r, 'w', encoding='utf-8') as handle:\n"
        "    json.dump(args, handle)\n"
        "input = args[args.index('--input') + 1]\n"
        "output = args[args.index('--output') + 1]\n"
        "report = args[args.index('--report') + 1]\n"
        "with open(input, 'rb') as handle:\n"
        "    data = handle.read()\n"
        "with open(output, 'wb') as handle:\n"
        "    handle.write(data)\n"
        "with open(report, 'w', encoding='utf-8') as handle:\n"
        "    json.dump({'mode': 'lower'}, handle)\n" % (record,)
    )
    lower = _write_stub_lower(root, body)
    service, request_path, response_path = _service_request(root)
    saved = os.environ.get(service.LOWER_ENV)
    os.environ[service.LOWER_ENV] = lower
    try:
        code, document = _run_service(
            service, request_path, response_path,
            _stub_adapter("classifier", qualified={"classifier"}),
        )
    finally:
        if saved is None:
            del os.environ[service.LOWER_ENV]
        else:
            os.environ[service.LOWER_ENV] = saved
    assert code == 0, document
    with open(record, encoding="utf-8") as handle:
        argv = json.load(handle)
    assert "--permissive-proof" in argv, argv


def test_driver_propagates_success_warnings():
    # The driver contract already forwards non-error diagnostics
    # on success; the MBPF220 warning survives the boundary.
    root = tempfile.mkdtemp(prefix="route-warn-")
    staged = _staged_output(root)
    result, diagnostics = _interpret({
        "schema_version": 1,
        "ok": True,
        "outputs": {"adapted_ir": staged, "route": "parsed"},
        "diagnostics": [{
            "code": "MBPF220",
            "stage": "adapter.transform",
            "severity": "warning",
            "explanation": "parsed lowering left 2 properties unproved",
            "location": os.path.join(root, "input.ll"),
            "remedy": "review the unproved properties",
        }],
    }, root)
    assert result == (staged, "parsed"), diagnostics
    assert [item.code for item in diagnostics] == ["MBPF220"]
    assert diagnostics[0].severity == "warning"


# ---------------------------------------------------------------------------
# T4a-2 map core: kind-gated dispatch + map spec contract.
#
# Array map programs route parsed; tagged kinds (percpu, hash, LRU)
# stay Lane-A (T4a-3 scope). The map spec carries the declared
# array contract (symbol/type/key/value from the manifest) with the
# entry count from the audited IR scan.
# ---------------------------------------------------------------------------

MAP_MANIFEST = """\
schema_version = 1

[project]
name = "map-roundtrip"

[target]
profile = "linux-bpfel-v3"

[artifact]
name = "roundtrip_obj"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "map_roundtrip.mojo"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"

[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""


def test_select_route_map_array_is_parsed():
    service = load_module("adapter_service_route_map", SERVICE)
    audit = stub_audit({"map"})
    assert service.select_route("map", audit) == "parsed"


def test_select_route_map_unflipped_kind_stays_lane_a():
    # The kind gate: unflipped kinds (and mixed programs) keep
    # building on Lane-A; each kind earns parsed explicitly.
    service = load_module("adapter_service_route_tag", SERVICE)
    audit = stub_audit({"map"})
    for kind in ("mixed", "ringbuf", "bogus"):
        assert service.select_route(
            "map", audit, map_kind=kind,
        ) == "lane-a", kind


def test_select_route_map_hash_kind_goes_parsed():
    # T4a-3 hash flip: hash-tagged map programs take the parsed
    # slice; the tag plus the hash spec contract carry the kind.
    service = load_module("adapter_service_route_hash", SERVICE)
    audit = stub_audit({"map"})
    assert service.select_route(
        "map", audit, map_kind="hash",
    ) == "parsed"


def test_select_route_map_lru_kind_goes_parsed():
    # T4a-3 LRU flip: LRU-tagged map programs take the parsed
    # slice; the tag plus the LRU spec contract carry the kind.
    service = load_module("adapter_service_route_lru", SERVICE)
    audit = stub_audit({"map"})
    assert service.select_route(
        "map", audit, map_kind="lru",
    ) == "parsed"


def test_select_route_map_percpu_kind_goes_parsed():
    # T4a-3 percpu flip: percpu-tagged map programs take the
    # parsed slice; the tag plus the percpu spec contract carry
    # the kind.
    service = load_module("adapter_service_route_percpu", SERVICE)
    audit = stub_audit({"map"})
    assert service.select_route(
        "map", audit, map_kind="percpu",
    ) == "parsed"


def test_select_route_combined_flipped_kinds_parse():
    # The combined flip is evidence-gated per kind: array and
    # percpu have combined fixtures with full equivalence, so
    # they route parsed.
    service = load_module("adapter_service_route_combined", SERVICE)
    audit = stub_audit({"map", "combined"})
    for kind in ("array", "percpu"):
        assert service.select_route(
            "combined", audit, map_kind=kind,
        ) == "parsed", kind


def test_select_route_combined_unflipped_kinds_stay_lane_a():
    # Hash and lru have no combined fixtures, so their
    # combined workloads stay Lane-A until their own
    # equivalence exists; mixed is never a parsed kind.
    service = load_module("adapter_service_route_combined_unflipped", SERVICE)
    audit = stub_audit({"map", "combined"})
    for kind in ("hash", "lru", "mixed"):
        assert service.select_route(
            "combined", audit, map_kind=kind,
        ) == "lane-a", kind


def test_select_route_map_mixed_kinds_stay_lane_a():
    # Mixed-kind programs stay Lane-A routed: Lane-A owns the
    # two-kinds diagnostic, the route never invents one.
    service = load_module("adapter_service_route_mixed", SERVICE)
    audit = stub_audit({"map"})
    assert service.select_route(
        "map", audit, map_kind="mixed",
    ) == "lane-a"


def test_select_route_map_core_profile_stays_lane_a():
    # CO-RE belongs to Lane-A until the CO-RE gate: the parsed
    # slice proves no core program, so a core profile keeps its
    # Lane-A relocation checks (MBPF216) instead of meeting a
    # parsed route refusal (MBPF219).
    service = load_module("adapter_service_route_core_map", SERVICE)
    audit = stub_audit({"map"})
    assert service.select_route(
        "map", audit, core_profile=True,
    ) == "lane-a"


def test_select_route_classifier_core_profile_stays_lane_a():
    # The core gate is about the profile, not the mode: even a
    # qualified classifier stays on Lane-A under a core profile.
    service = load_module("adapter_service_route_core_cls", SERVICE)
    audit = stub_audit({"classifier"})
    assert service.select_route(
        "classifier", audit, core_profile=True,
    ) == "lane-a"


def test_author_spec_map():
    service = load_module("adapter_service_spec_map", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-map-")
    manifest = _write_manifest(root, MAP_MANIFEST)
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3", entries=2,
    )
    assert refusal is None
    assert spec == {
        "schema_version": 1,
        "model_id": "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1",
        "profile_id": "linux-bpfel-v3",
        "entry": "xdp_entry",
        "program_type": "xdp",
        "section": "xdp",
        "kernel_license": "Apache-2.0 WITH LLVM-exception",
        "map": {
            "symbol": "mojobpf_map0",
            "type": 2,
            "key_bits": 32,
            "value_bits": 64,
            "max_entries": 2,
            "flags": 0,
        },
    }, spec


def test_author_spec_map_unflipped_kind_refuses():
    # An unflipped kind refuses at spec authoring even when
    # manifest and scan agree: only the four flipped single-map
    # kinds (array, hash, LRU, percpu) author a spec. Ringbuf
    # is the witness: a real spelling in map position that the
    # parsed slice never covers.
    service = load_module("adapter_service_spec_mk", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-mapkind-")
    manifest = _write_manifest(
        root, MAP_MANIFEST.replace(
            'map_type = "array"', 'map_type = "ringbuf"'),
    )
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3", entries=1,
        map_kind="ringbuf",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "array, hash, lru, and percpu maps only" in refusal.explanation
    assert "'ringbuf'" in refusal.explanation


def test_author_spec_map_hash():
    # T4a-3 hash flip: a hash manifest over hash-tagged IR
    # authors the type-1 spec block; entries still come from
    # the audited scan.
    service = load_module("adapter_service_spec_hash", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-hash-")
    manifest = _write_manifest(
        root, MAP_MANIFEST.replace('map_type = "array"', 'map_type = "hash"'),
    )
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3", entries=4,
        map_kind="hash",
    )
    assert refusal is None
    assert spec["map"] == {
        "symbol": "mojobpf_map0",
        "type": 1,
        "key_bits": 32,
        "value_bits": 64,
        "max_entries": 4,
        "flags": 0,
    }, spec


def test_author_spec_map_lru():
    # T4a-3 LRU flip: an LRU manifest over LRU-tagged IR
    # authors the type-9 spec block; entries still come from
    # the audited scan.
    service = load_module("adapter_service_spec_lru", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-lru-")
    manifest = _write_manifest(
        root, MAP_MANIFEST.replace(
            'map_type = "array"', 'map_type = "lru_hash"'),
    )
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3", entries=4,
        map_kind="lru",
    )
    assert refusal is None
    assert spec["map"] == {
        "symbol": "mojobpf_map0",
        "type": 9,
        "key_bits": 32,
        "value_bits": 64,
        "max_entries": 4,
        "flags": 0,
    }, spec


def test_author_spec_map_lru_mismatch_refuses():
    # The bidirectional contract holds per flipped kind: an
    # LRU declaration over untagged IR (or an array
    # declaration over LRU-tagged IR) is a contract refusal,
    # never a silent cross-kind lowering.
    service = load_module("adapter_service_spec_lru_mm", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-lru-mm-")
    lru_manifest = _write_manifest(
        root, MAP_MANIFEST.replace(
            'map_type = "array"', 'map_type = "lru_hash"'),
    )
    spec, refusal = service._author_spec(
        "map", "xdp_entry", lru_manifest, "linux-bpfel-v3", entries=1,
        map_kind="array",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "lru" in refusal.explanation and "array" in refusal.explanation
    array_manifest = _write_manifest(root, MAP_MANIFEST)
    spec, refusal = service._author_spec(
        "map", "xdp_entry", array_manifest, "linux-bpfel-v3", entries=1,
        map_kind="lru",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "array" in refusal.explanation and "lru" in refusal.explanation


def test_author_spec_map_percpu():
    # T4a-3 percpu flip: a percpu manifest over percpu-tagged
    # IR authors the type-6 spec block; entries still come from
    # the audited scan.
    service = load_module("adapter_service_spec_percpu", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-percpu-")
    manifest = _write_manifest(
        root, MAP_MANIFEST.replace(
            'map_type = "array"', 'map_type = "percpu_array"'),
    )
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3", entries=4,
        map_kind="percpu",
    )
    assert refusal is None
    assert spec["map"] == {
        "symbol": "mojobpf_map0",
        "type": 6,
        "key_bits": 32,
        "value_bits": 64,
        "max_entries": 4,
        "flags": 0,
    }, spec


def test_author_spec_map_percpu_mismatch_refuses():
    # The bidirectional contract holds per flipped kind: a
    # percpu declaration over untagged IR (or an array
    # declaration over percpu-tagged IR) is a contract
    # refusal, never a silent cross-kind lowering.
    service = load_module("adapter_service_spec_pcpu_mm", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-pcpu-mm-")
    percpu_manifest = _write_manifest(
        root, MAP_MANIFEST.replace(
            'map_type = "array"', 'map_type = "percpu_array"'),
    )
    spec, refusal = service._author_spec(
        "map", "xdp_entry", percpu_manifest, "linux-bpfel-v3",
        entries=1, map_kind="array",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "percpu" in refusal.explanation
    assert "array" in refusal.explanation
    array_manifest = _write_manifest(root, MAP_MANIFEST)
    spec, refusal = service._author_spec(
        "map", "xdp_entry", array_manifest, "linux-bpfel-v3",
        entries=1, map_kind="percpu",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "array" in refusal.explanation
    assert "percpu" in refusal.explanation


def test_author_spec_map_kind_mismatch_refuses():
    # Manifest and IR must agree on the kind in both
    # directions: a hash declaration over untagged IR (or an
    # array declaration over hash-tagged IR) is a contract
    # refusal, never a silent cross-kind lowering.
    service = load_module("adapter_service_spec_mismatch", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-mismatch-")
    hash_manifest = _write_manifest(
        root, MAP_MANIFEST.replace('map_type = "array"', 'map_type = "hash"'),
    )
    spec, refusal = service._author_spec(
        "map", "xdp_entry", hash_manifest, "linux-bpfel-v3", entries=1,
        map_kind="array",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "hash" in refusal.explanation and "array" in refusal.explanation
    array_manifest = _write_manifest(root, MAP_MANIFEST)
    spec, refusal = service._author_spec(
        "map", "xdp_entry", array_manifest, "linux-bpfel-v3", entries=1,
        map_kind="hash",
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"
    assert "array" in refusal.explanation and "hash" in refusal.explanation


def test_author_spec_map_missing_maps_refuses():
    service = load_module("adapter_service_spec_mm", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-maps-")
    manifest = _write_manifest(root, CLASSIFIER_MANIFEST)
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3", entries=1,
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"


def test_author_spec_map_multi_refuses():
    service = load_module("adapter_service_spec_m2", SERVICE)
    root = tempfile.mkdtemp(prefix="spec-maps2-")
    manifest = _write_manifest(root, MAP_MANIFEST + """\
[[maps]]
name = "mojobpf_map1"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
""")
    spec, refusal = service._author_spec(
        "map", "xdp_entry", manifest, "linux-bpfel-v3", entries=1,
    )
    assert spec is None
    assert refusal is not None and refusal.code == "MBPF219"


def _map_service_request(root):
    service, request_path, response_path = _service_request(root)
    with open(os.path.join(root, "mojobpf.toml"), "w",
              encoding="utf-8") as handle:
        handle.write(MAP_MANIFEST)
    return service, request_path, response_path


def _stub_map_adapter(qualified, entry="xdp_entry", entries=1,
                      tagged=False, mixed=False):
    audit = stub_audit(qualified, entry)
    scan = audit.scan
    audit.scan = lambda text: types.SimpleNamespace(
        entry=scan(text).entry, mode="map", entries=entries,
        percpu=tagged, hashkind=mixed, lrukind=False,
    )
    return types.SimpleNamespace(
        AdapterError=_StubAdapterError,
        audit=audit,
        validate=lambda text: "map",
        adapt=lambda text: "; lane-a adapted\n",
    )


def _run_with_lower_env(service, root, adapter):
    request_path = os.path.join(root, "request.json")
    response_path = os.path.join(root, "response.json")
    return _run_service(service, request_path, response_path, adapter)


def test_service_map_array_routes_parsed():
    # T4a-2 Step 5: array map migrates; the parsed branch authors
    # the map spec with entries from the scan.
    root = tempfile.mkdtemp(prefix="svc-map-")
    lower = _write_stub_lower(root, """#!/bin/sh
input=""; spec=""; output=""; report=""
while [ $# -gt 0 ]; do
  case "$1" in
    --input) input="$2"; shift 2;;
    --spec) spec="$2"; shift 2;;
    --output) output="$2"; shift 2;;
    --report) report="$2"; shift 2;;
    *) shift;;
  esac
done
cp "$input" "$output"
printf '{"mode":"lower"}\\n' > "$report"
""")
    service, request_path, response_path = _map_service_request(root)
    adapter = _stub_map_adapter({"map"}, entries=2)
    saved = os.environ.get(service.LOWER_ENV)
    os.environ[service.LOWER_ENV] = lower
    try:
        code, document = _run_service(
            service, request_path, response_path, adapter,
        )
    finally:
        if saved is None:
            del os.environ[service.LOWER_ENV]
        else:
            os.environ[service.LOWER_ENV] = saved
    assert code == 0, document
    assert document["ok"] is True, document
    assert document["outputs"]["route"] == "parsed", document
    with open(
        os.path.join(root, "out", "lower-spec.json"),
        encoding="utf-8",
    ) as handle:
        spec = json.load(handle)
    assert spec["map"] is not None, spec
    assert spec["map"]["max_entries"] == 2, spec
    assert spec["map"]["type"] == 2, spec


def test_service_map_mixed_routes_lane_a():
    # Mixed-kind map traffic never reaches the lowering: with
    # an unusable lowering binary the build still succeeds via
    # Lane-A. (All four single kinds flipped to parsed; mixed
    # is what remains Lane-A routed, with the two-kinds
    # diagnostic owned downstream.)
    root = tempfile.mkdtemp(prefix="svc-mapmix-")
    service, request_path, response_path = _map_service_request(root)
    adapter = _stub_map_adapter({"map"}, tagged=True, mixed=True)
    saved = os.environ.get(service.LOWER_ENV)
    os.environ[service.LOWER_ENV] = os.path.join(root, "no-such-lower")
    try:
        code, document = _run_service(
            service, request_path, response_path, adapter,
        )
    finally:
        if saved is None:
            del os.environ[service.LOWER_ENV]
        else:
            os.environ[service.LOWER_ENV] = saved
    assert code == 0, document
    assert document["ok"] is True, document
    assert document["outputs"]["route"] == "lane-a", document
    with open(document["outputs"]["adapted_ir"],
              encoding="utf-8") as handle:
        assert handle.read() == "; lane-a adapted\n"
