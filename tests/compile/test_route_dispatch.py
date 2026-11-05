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
    "classifier", "map", "combined", "tracepoint", "event",
    "reserve", "subprog", "core", "uprobe", "skb",
)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stub_audit(qualified=()):
    qualified = frozenset(qualified)
    return types.SimpleNamespace(
        ADMITTED_MODES=tuple(MODES),
        PARSED_QUALIFIED_MODES=qualified,
        parsed_qualified=lambda mode: mode in qualified,
    )


def test_qualified_defaults_empty():
    audit = load_module("audit_route_flags", AUDIT)
    assert audit.PARSED_QUALIFIED_MODES == frozenset()
    assert tuple(audit.ADMITTED_MODES) == MODES
    for mode in MODES:
        assert audit.parsed_qualified(mode) is False, mode


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


def _stub_adapter(mode, qualified):
    audit = stub_audit(qualified)
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
        handle.write("[project]\n")
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
