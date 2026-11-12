# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Emitter-vs-schema conformance sweep over schemas/*.schema.json.

One test per schema file: the emitter's output keys must cover the
schema's required properties and stay within its declared
properties (every schema here is closed), with value-type spot
checks on each covered key. An emitter adding a field without
its schema (or a schema gaining a property no emitter writes)
fails its test. Checks are top-level only; nested shapes belong
to the owning suites.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_<name>.py``).
Uses only the standard library.
"""

import ast
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import tomllib

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import evidence as evidence_module  # noqa: E402
from mojobpf.diagnostics import Diagnostic  # noqa: E402
from mojobpf.validation import (  # noqa: E402
    CaseResult,
    CostRecord,
    Fixture,
    SuiteResult,
    TargetManifest,
    aggregate,
    plan,
)

ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."
)
SCHEMAS = os.path.join(ROOT, "schemas")
EXAMPLES = os.path.join(ROOT, "examples")
REGISTRY = os.path.join(ROOT, "capabilities", "registry.json")
COLLECT_PATH = os.path.join(ROOT, "tests", "codegen_cost", "collect.py")

COMMIT = "a" * 40


def _sha(seed):
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _load_schema(name):
    with open(
        os.path.join(SCHEMAS, "%s.schema.json" % name),
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def _resolve(document):
    """Follow a top-level local $ref (result.schema.json)."""
    ref = document.get("$ref")
    if not ref:
        return document
    assert ref.startswith("#/$defs/"), ref
    return document["$defs"][ref[len("#/$defs/"):]]


def _check_value(spec, value, where):
    if "const" in spec:
        assert value == spec["const"], (where, value)
    if "enum" in spec:
        assert value in spec["enum"], (where, value)
    types = spec.get("type")
    if types is None:
        return
    if isinstance(types, str):
        types = [types]
    if value is None:
        assert "null" in types, (where, types)
        return
    if isinstance(value, bool):
        matched = "boolean" in types
    elif isinstance(value, int):
        matched = "integer" in types or "number" in types
    elif isinstance(value, float):
        matched = "number" in types
    elif isinstance(value, str):
        matched = "string" in types
    elif isinstance(value, dict):
        matched = "object" in types
    elif isinstance(value, (list, tuple)):
        matched = "array" in types
    else:
        matched = False
    assert matched, (where, types, type(value).__name__)


def _assert_conforms(schema, document, what):
    schema = _resolve(schema)
    required = schema.get("required", [])
    properties = schema.get("properties", {})
    missing = [key for key in required if key not in document]
    assert not missing, (what, missing)
    if schema.get("additionalProperties") is False:
        extra = [key for key in document if key not in properties]
        assert not extra, (what, extra)
    for key, value in document.items():
        if key in properties:
            _check_value(properties[key], value, "%s.%s" % (what, key))


def _assert_union_covered(schema, documents, what):
    """Fail when the schema declares a property no emitter writes.

    ``documents`` are representative emitter outputs (one per
    variant); every declared property must appear in at least one.
    """
    schema = _resolve(schema)
    properties = schema.get("properties", {})
    emitted = set()
    for document in documents:
        emitted.update(document.keys())
    unwritten = sorted(set(properties) - emitted)
    assert not unwritten, (what, unwritten)


def test_artifact_conforms():
    schema = _load_schema("artifact")
    published = evidence_module.PublishedArtifact(
        schema_version=evidence_module.ARTIFACT_SCHEMA_VERSION,
        role="object",
        name="demo.bpf.o",
        sha256="a" * 64,
        size=12,
    )
    document = published.to_dict()
    _assert_conforms(schema, document, "artifact")
    _assert_union_covered(schema, [document], "artifact")


def test_diagnostics_conform():
    schema = _load_schema("diagnostics")
    diagnostic = Diagnostic(
        code="MBPF704",
        stage="inspect.license",
        severity="error",
        explanation="the declaration pair has no mapping",
        location=None,
        remedy="declare a mapped pair",
    )
    document = diagnostic.to_dict()
    _assert_conforms(schema, document, "diagnostics")
    _assert_union_covered(schema, [document], "diagnostics")


def _sample_evidence():
    hashed = evidence_module.HashedFile(
        path="src/xdp.mojo", sha256="b" * 64, size=8
    )
    inputs = evidence_module.CacheInputs(
        source=(hashed,),
        imports=(),
        sdk=(),
        manifest=hashed,
        compiler=("mojo 9.9.9 " + "c" * 64,),
        flags=("--target-cpu",),
        profile_id="linux-bpfel-v3",
        profile_sha256="d" * 64,
        adapter=("adapter_service.py " + "e" * 64,),
        tool_version="0.2.0",
        sdk_version="0.2.0",
    )
    return evidence_module.Evidence(
        schema_version=evidence_module.EVIDENCE_SCHEMA_VERSION,
        artifact="demo",
        profile_id="linux-bpfel-v3",
        success=True,
        inputs=inputs,
        outputs=(hashed,),
        transforms=("frontend", "adapter", "backend"),
        source_license="Apache-2.0 WITH LLVM-exception",
        kernel_license="Apache-2.0 WITH LLVM-exception",
        license_mapping_version=1,
        tool_version="0.2.0",
        sdk_version="0.2.0",
        commands=(
            evidence_module.EvidenceCommand(
                stage="build.frontend",
                argv=("mojo", "build"),
                status="ok",
                exit_code=0,
            ),
        ),
        environment=(
            evidence_module.EnvironmentEntry(
                name="PATH", value="sha256:" + "f" * 64
            ),
        ),
    )


def test_evidence_conforms():
    schema = _load_schema("evidence")
    document = _sample_evidence().to_dict()
    _assert_conforms(schema, document, "evidence")
    _assert_union_covered(schema, [document], "evidence")


def test_capability_registry_conforms():
    schema = _load_schema("capability")
    with open(REGISTRY, encoding="utf-8") as handle:
        registry = json.load(handle)
    _assert_conforms(schema, registry, "capability")
    _assert_union_covered(schema, [registry], "capability")


CONSUMER = {
    "name": "stock-libbpf",
    "version": "1.7.0",
    "artifact_sha256": _sha("consumer:stock-libbpf:1.7.0"),
}

REVISIONS = {
    "repository_commit": COMMIT,
    "package": "mojobpf-0.2.0",
    "tool": "run-vm-tests-0.2.0",
}


def _make_target(**overrides):
    body = {
        "schema_version": 1,
        "kernel": {
            "source_commit": COMMIT,
            "release": "6.12.0-test",
            "build_id": "build-1",
            "config_sha256": _sha("config"),
        },
        "btf": {
            "vmlinux_sha256": _sha("vmlinux-btf"),
            "modules": [
                {"name": "bpf_testmod", "sha256": _sha("mod")}
            ],
        },
        "image": {
            "digest": "sha256:" + _sha("rootfs"),
            "packages": {"libc": "2.39"},
        },
        "cpu": {
            "architecture": "x86-64",
            "model": "qemu64",
            "features": ["x2apic"],
            "page_size": 4096,
            "cpus": 4,
        },
        "execution_mode": "tcg",
        "byte_order": "le",
        "instruction_profile": "v3",
        "jit": {"state": "enabled", "hardening": ["spectre"]},
        "boot": {
            "parameters": ["quiet"],
            "lsms": ["capability"],
            "lockdown": "none",
        },
        "privileges": {
            "capabilities": ["CAP_BPF"],
            "token": "none",
            "delegation": "exclusive-lease",
            "rlimits": {"memlock": "unlimited"},
        },
        "mounts": {
            "tracefs": "/sys/kernel/tracing",
            "bpffs": "/run/mojobpf-1/bpffs",
            "cgroup": "/sys/fs/cgroup/mojobpf-1",
            "namespaces": ["net:mojobpf-1"],
        },
        "build_host": {
            "identity": "mojo-1.1.0/x86-64",
            "flags": ["-O2"],
        },
    }
    body.update(overrides)
    body["fingerprint"] = TargetManifest.fingerprint_of(body)
    return body


def _make_case(case_id, target_fp):
    return {
        "case_id": case_id,
        "fixture_id": "fx-%s" % case_id.lower().replace("_", "-"),
        "targets": [target_fp],
        "expectation": "positive",
        "required": True,
        "consumers": [dict(CONSUMER)],
        "source_sha256": _sha("source:%s" % case_id),
        "object_sha256": _sha("object:%s" % case_id),
        "corpus_sha256": _sha("corpus:%s" % case_id),
        "expected_attempts": 1,
        "expected": {"outcome": "PASS", "failure_stage": None},
    }


def _make_result(run_plan, case_id, target_fp):
    case = next(
        item for item in run_plan.cases if item.case_id == case_id
    )
    return {
        "schema_version": 1,
        "run_id": "run-1",
        "case_id": case_id,
        "target_fingerprint": target_fp,
        "attempt": 1,
        "plan_hash": run_plan.plan_hash,
        "identities": {
            "repository_commit": run_plan.revisions[
                "repository_commit"
            ],
            "package": run_plan.revisions["package"],
            "tool": run_plan.revisions["tool"],
            "consumer": dict(CONSUMER),
            "object_sha256": case.object_sha256,
            "source_sha256": case.source_sha256,
            "workload": {
                "fixture_id": case.fixture_id,
                "corpus_sha256": case.corpus_sha256,
            },
        },
        "applicability": "APPLICABLE",
        "required": case.required,
        "expected": {"outcome": "PASS", "failure_stage": None},
        "observed": {"outcome": "PASS", "failure_stage": None},
        "outcome": "PASS",
        "failure_stage": None,
        "evidence": [
            {
                "path": "evidence/%s.log" % case_id,
                "sha256": _sha("log:%s" % case_id),
                "bytes": 10,
            }
        ],
        "cleanup": {"status": "CLEAN", "residue": []},
        "costs": [],
    }


def test_target_conforms():
    schema = _load_schema("target")
    manifest = TargetManifest.from_dict(_make_target())
    document = manifest.to_dict()
    _assert_conforms(schema, document, "target")
    qualified = _make_target()
    qualified["netdevice"] = {
        "driver": "ixgbe",
        "firmware": "0x800001",
        "queues": "8x8",
    }
    qualified["probed_process"] = {
        "architecture": "x86-64",
        "abi": "sysv",
        "executable_sha256": _sha("exe"),
    }
    qualified["fingerprint"] = TargetManifest.fingerprint_of(qualified)
    document2 = TargetManifest.from_dict(qualified).to_dict()
    _assert_conforms(schema, document2, "target-qualified")
    _assert_union_covered(schema, [document, document2], "target")


def test_fixture_conforms():
    schema = _load_schema("fixture")
    raw = {
        "schema_version": 1,
        "fixture_id": "fx-net-xdp-01",
        "object": {
            "path": "objects/xdp_counter.bpf.o",
            "sha256": _sha("object"),
            "bytes": 4096,
        },
        "entries": [
            {
                "symbol": "xdp_counter",
                "program_type": "xdp",
                "section": "xdp",
            }
        ],
        "maps": [
            {
                "name": "counts",
                "map_type": "PERCPU_ARRAY",
                "key": {"type": "u32", "bytes": 4},
                "value": {"type": "u64", "bytes": 8},
                "max_entries": 4,
            }
        ],
        "event_abi": None,
        "corpus": {
            "corpus_id": "packets-33",
            "sha256": _sha("corpus"),
            "record_count": 33,
        },
        "oracle": {"name": "packet-oracle", "version": "1.3.0"},
        "barriers": ["ready", "start", "stop", "drained"],
    }
    fixture = Fixture.from_dict(raw)
    document = fixture.to_dict()
    _assert_conforms(schema, document, "fixture")
    _assert_union_covered(schema, [document], "fixture")


def test_run_plan_conforms():
    schema = _load_schema("run-plan")
    target = _make_target()
    case = _make_case("NET-XDP-01", target["fingerprint"])
    run_plan = plan([case], [target], dict(REVISIONS))
    document = run_plan.to_dict()
    _assert_conforms(schema, document, "run-plan")
    _assert_union_covered(schema, [document], "run-plan")


def test_cost_conforms():
    schema = _load_schema("cost")
    raw = {
        "schema_version": 1,
        "case_id": "NET-XDP-01",
        "target_fingerprint": _sha("t"),
        "metric": "reachable_slots",
        "unit": "slots",
        "value": 128,
        "basis": {
            "object_sha256": _sha("o"),
            "profile": "linux-bpfel-v3",
            "flags": ["-O2"],
        },
    }
    record = CostRecord.from_dict(raw)
    good = record.to_dict()
    _assert_conforms(schema, good, "cost")
    unavailable = dict(raw)
    unavailable["value"] = None
    unavailable["unavailable_reason"] = "verifier metrics missing"
    record = CostRecord.from_dict(unavailable)
    nullish = record.to_dict()
    _assert_conforms(schema, nullish, "cost-null")
    _assert_union_covered(schema, [good, nullish], "cost")


def test_result_conforms():
    schema = _load_schema("result")
    target = _make_target()
    run_plan = plan(
        [_make_case("NET-XDP-01", target["fingerprint"])],
        [target],
        dict(REVISIONS),
    )
    raw = _make_result(run_plan, "NET-XDP-01", target["fingerprint"])
    result = CaseResult.from_dict(raw)
    case_document = result.to_dict()
    _assert_conforms(schema, case_document, "result")
    _assert_union_covered(schema, [case_document], "result")
    suite = aggregate(run_plan, [raw]).to_suite_dict()
    parsed = SuiteResult.from_dict(suite)
    suite_document = parsed.to_dict()
    _assert_conforms(
        schema["$defs"]["suite_result"], suite_document, "suite"
    )
    _assert_union_covered(
        schema["$defs"]["suite_result"], [suite_document], "suite"
    )


def test_manifest_examples_conform():
    schema = _load_schema("manifest")
    paths = []
    for entry in sorted(os.listdir(EXAMPLES)):
        candidate = os.path.join(EXAMPLES, entry, "mojobpf.toml")
        if os.path.isfile(candidate):
            paths.append(candidate)
    assert paths, "no example manifests to check"
    documents = []
    for path in paths:
        with open(path, "rb") as handle:
            document = tomllib.load(handle)
        _assert_conforms(schema, document, path)
        documents.append(document)
    _assert_union_covered(schema, documents, "manifest")


def _collector_module():
    name = "object_cost_collector"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, COLLECT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_size_budget_conforms():
    schema = _load_schema("size-budget")
    collector = _collector_module()
    required = schema.get("required", [])
    properties = schema.get("properties", {})
    assert sorted(required) == sorted(collector.BUDGET_FIELDS)
    assert sorted(properties) == sorted(collector.BUDGET_FIELDS)
    budget = {
        "schema_version": 1,
        "budget_id": "control.object-slots",
        "case_id": "NET-XDP-01",
        "semantic_contract_sha256": _sha("contract"),
        "profile": "linux-bpfel-v3",
        "metric": "reachable_slots",
        "unit": "slots",
        "baseline_report_sha256": _sha("baseline"),
        "baseline_value": 10,
        "absolute_ceiling": None,
        "max_increase": 2,
        "max_ratio": None,
        "reference_report_sha256": None,
        "rationale": "conformance probe",
        "owner": "schema-conformance",
        "approval_evidence_sha256": "0" * 64,
    }
    accepted = collector.validate_budget(budget)
    _assert_conforms(schema, accepted, "size-budget")
    _assert_union_covered(schema, [accepted], "size-budget")


_SWEEP_NESTED_SCOPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
)

_SWEEP_TERMINATORS = (
    ast.Return,
    ast.Raise,
    ast.Break,
    ast.Continue,
)

_SWEEP_ASSERTS = (
    "_assert_conforms",
    "_assert_union_covered",
)


def _sweep_load_literal(node):
    """Schema literal of a ``_load_schema`` call, else None."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_load_schema"
        and node.args
        and isinstance(node.args[0], ast.Constant)
    ):
        return None
    return node.args[0].value


def _sweep_assert_names(node, into):
    """Collect names flowing into an assert-helper call."""
    stack = list(node.args)
    stack.extend(
        keyword.value
        for keyword in node.keywords
        if keyword.value is not None
    )
    while stack:
        child = stack.pop()
        if isinstance(child, _SWEEP_NESTED_SCOPES):
            continue
        if isinstance(child, ast.Name):
            into.add(child.id)
        stack.extend(ast.iter_child_nodes(child))


def _sweep_covered_names(path):
    """Schema names the closed sweep credits in ``path``.

    Only module-level ``test_*`` bodies count (pytest parity:
    nested ``test_*`` defs never run). Inside them, only
    structurally live code counts: nested scopes
    (``def``/``lambda``) are not descended into, statements
    after a terminator (``return``/``raise``/``break``/
    ``continue``) in the same block are skipped, and constant
    ``if``/``while False`` branches are pruned. A load
    credits coverage only when its bound name flows into an
    assert-helper call (last binding wins). Dynamically
    conditional code stays conservatively visited.
    """
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    covered = set()
    for node in tree.body:
        if not (
            isinstance(node, ast.FunctionDef)
            and node.name.startswith("test_")
        ):
            continue
        bound = {}
        asserted_names = set()

        def _collect(child):
            if (
                isinstance(child, ast.Assign)
                and len(child.targets) == 1
                and isinstance(child.targets[0], ast.Name)
            ):
                literal = _sweep_load_literal(child.value)
                if literal is not None:
                    bound[child.targets[0].id] = literal
            elif (
                isinstance(child, ast.AnnAssign)
                and isinstance(child.target, ast.Name)
                and child.value is not None
            ):
                literal = _sweep_load_literal(child.value)
                if literal is not None:
                    bound[child.target.id] = literal
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in _SWEEP_ASSERTS
            ):
                _sweep_assert_names(child, asserted_names)

        def _walk_block(statements):
            for stmt in statements:
                if isinstance(stmt, _SWEEP_TERMINATORS):
                    for _field, entry in ast.iter_fields(stmt):
                        if isinstance(entry, ast.AST):
                            _walk_node(entry)
                    return
                _walk_node(stmt)

        def _walk_node(child):
            if isinstance(child, _SWEEP_NESTED_SCOPES):
                return
            if isinstance(child, ast.If) and isinstance(
                child.test, ast.Constant
            ):
                _walk_node(child.test)
                if child.test.value:
                    _walk_block(child.body)
                else:
                    _walk_block(child.orelse)
                return
            if (
                isinstance(child, ast.While)
                and isinstance(child.test, ast.Constant)
                and not child.test.value
            ):
                _walk_node(child.test)
                _walk_block(child.orelse)
                return
            _collect(child)
            for field, entry in ast.iter_fields(child):
                if (
                    field in ("body", "orelse", "finalbody")
                    and isinstance(entry, list)
                ):
                    _walk_block(entry)
                elif isinstance(entry, list):
                    for item in entry:
                        if isinstance(item, ast.AST):
                            _walk_node(item)
                elif isinstance(entry, ast.AST):
                    _walk_node(entry)

        _walk_block(node.body)
        for name in asserted_names:
            if name in bound:
                covered.add(bound[name])
    return covered


def test_sweep_credits_only_executed_module_level_loads():
    # Guard regression: loads and assertions inside nested
    # scopes (a helper def, a lambda) or inside a nested
    # test_* def never execute under pytest, so the closed
    # sweep must not credit them; only module-level test_
    # bodies count. Likewise structurally dead loads (after
    # a return, under ``if False``/``while False``) and loads
    # whose result never flows into an assert helper credit
    # nothing.
    probe = (
        "def test_outer():\n"
        "    schema = _load_schema(\"outer\")\n"
        "    def helper():\n"
        "        schema = _load_schema(\"inner\")\n"
        "        _assert_conforms(schema, {}, \"inner\")\n"
        "    _assert_conforms(schema, {}, \"outer\")\n"
        "    _assert_union_covered(schema, [{}], \"outer\")\n"
        "def factory():\n"
        "    def test_nested():\n"
        "        schema = _load_schema(\"nested\")\n"
        "        _assert_conforms(schema, {}, \"nested\")\n"
        "        _assert_union_covered(schema, [{}], \"nested\")\n"
        "def test_lambda():\n"
        "    schema = _load_schema(\"lam\")\n"
        "    _assert_conforms(schema, {}, \"lam\")\n"
        "    _assert_union_covered(schema, [{}], \"lam\")\n"
        "    thunk = lambda: _load_schema(\"laminner\")\n"
        "def test_dead():\n"
        "    schema = _load_schema(\"live\")\n"
        "    _assert_union_covered(schema, [{}], \"live\")\n"
        "    return _assert_conforms(schema, {}, \"live\")\n"
        "    schema = _load_schema(\"afterreturn\")\n"
        "def test_constif():\n"
        "    schema = _load_schema(\"live2\")\n"
        "    if False:\n"
        "        schema = _load_schema(\"iffalse\")\n"
        "    _assert_conforms(schema, {}, \"live2\")\n"
        "    _assert_union_covered(schema, [{}], \"live2\")\n"
        "def test_whilefalse():\n"
        "    schema = _load_schema(\"live3\")\n"
        "    while False:\n"
        "        schema = _load_schema(\"whilefalse\")\n"
        "    _assert_conforms(schema, {}, \"live3\")\n"
        "    _assert_union_covered(schema, [{}], \"live3\")\n"
        "def test_mismatch():\n"
        "    schema_a = _load_schema(\"unasserted\")\n"
        "    schema_b = _load_schema(\"asserted\")\n"
        "    _assert_conforms(schema_b, {}, \"asserted\")\n"
        "    _assert_union_covered(schema_b, [{}], \"asserted\")\n"
    )
    with tempfile.TemporaryDirectory(
        prefix="schema-sweep-probe-"
    ) as parent:
        path = os.path.join(parent, "probe_conform.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(probe)
        assert _sweep_covered_names(path) == {
            "outer", "lam", "live", "live2", "live3", "asserted",
        }


def test_every_schema_file_has_conformance_coverage():
    # Closed sweep: every schemas/*.schema.json at any depth
    # must be asserted by a conformance test above (a literal
    # _load_schema load bound to a name in a module-level
    # test_* body, whose value flows into an assert helper;
    # nested scopes and structurally dead code are pruned),
    # so a new schema file without a test fails here, never
    # silently. A bare load with no assertions does not
    # count. No src loader globs schemas/ (all use exact
    # names), so stray non-schema files stay inert and out
    # of scope.
    covered = _sweep_covered_names(__file__)
    on_disk = []
    for found, _, files in os.walk(SCHEMAS):
        for entry in sorted(files):
            if entry.endswith(".schema.json"):
                on_disk.append(
                    os.path.relpath(
                        os.path.join(found, entry), SCHEMAS
                    )[: -len(".schema.json")]
                )
    on_disk.sort()
    assert on_disk, "no schemas found"
    missing = [name for name in on_disk if name not in covered]
    assert not missing, missing


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )
    for name in names:
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
