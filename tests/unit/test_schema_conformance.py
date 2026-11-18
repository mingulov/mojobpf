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
            "identity": "mojo-1.2.0/x86-64",
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
    ast.ClassDef,
)

# ``type X = ...`` exists only on 3.12+; None below, where the
# statement is a syntax error and there is nothing to model.
_TYPE_ALIAS = getattr(ast, "TypeAlias", None)

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


_SWEEP_ABORTS = ("skip", "fail", "exit", "_exit")


def _sweep_stmt_abort_call(stmt):
    """Abort call ``stmt`` evaluates unconditionally, else None.

    Bare abort expression statements, assignments whose value
    is an abort call (the targets never bind: the call raises
    first), returns of an abort call, and ``if``/``while``
    statements whose test is an abort call (both branches are
    dead). Anything subtler (an abort buried in a container
    or a message expression) is not recognized.
    """
    if isinstance(stmt, ast.Expr):
        candidate = stmt.value
    elif isinstance(stmt, ast.Return):
        candidate = stmt.value
    elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        candidate = stmt.value
    elif isinstance(stmt, (ast.If, ast.While)):
        candidate = stmt.test
    else:
        return None
    if not isinstance(candidate, ast.Call):
        return None
    func = candidate.func
    if isinstance(func, ast.Name):
        abort = func.id in _SWEEP_ABORTS
    elif isinstance(func, ast.Attribute):
        abort = func.attr in _SWEEP_ABORTS
    else:
        abort = False
    return candidate if abort else None


def _sweep_is_abort_call(stmt):
    """Whether ``stmt`` unconditionally aborts the test.

    Matches ``pytest.skip``/``pytest.fail``/``sys.exit`` and
    their bare/``os`` spellings by call name. A helper that
    merely shares the name over-prunes (fail closed).
    """
    return _sweep_stmt_abort_call(stmt) is not None


def _sweep_is_skipped(decorators):
    """Whether decorators skip the test body entirely.

    Plain ``skip`` (any receiver, including bare) always
    skips; ``skipif``/``skipIf`` skip on a true constant,
    ``skipUnless`` on a false one, whether the condition
    is positional or a ``condition=`` keyword. Unknown
    decorators are assumed to run the body.
    """
    for decorator in decorators:
        if isinstance(decorator, ast.Call):
            func = decorator.func
            args = decorator.args
            keywords = decorator.keywords
        else:
            func = decorator
            args = []
            keywords = []
        if isinstance(func, ast.Attribute):
            name = func.attr
        elif isinstance(func, ast.Name):
            name = func.id
        else:
            continue
        if name == "skip":
            return True
        if name not in ("skipif", "skipIf", "skipUnless"):
            continue
        condition = _SWEEP_MISSING
        if args:
            condition = args[0]
        else:
            for keyword in keywords:
                if keyword.arg == "condition":
                    condition = keyword.value
                    break
        if not isinstance(condition, ast.Constant):
            continue
        if name == "skipUnless":
            if not condition.value:
                return True
        elif condition.value:
            return True
    return False


_SWEEP_MISSING = object()


def _sweep_merge_paths(env, paths):
    """Merge branch environments back into ``env``.

    A name keeps its binding only when every path binds
    the same literal; any divergence (including unbound
    on some path, or on every path while the pre-branch
    binding lingers in ``env``) drops the name, fail
    closed.
    """
    names = set(env)
    for path in paths:
        names |= set(path)
    for name in names:
        values = [path.get(name, _SWEEP_MISSING) for path in paths]
        if all(
            value is not _SWEEP_MISSING and value == values[0]
            for value in values
        ):
            env[name] = values[0]
        else:
            env.pop(name, None)


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


def _sweep_credit_call(node, env, covered):
    """Credit the bindings an assert-helper call observes.

    Only the schema position counts: the first positional
    argument, or an explicit ``schema=`` keyword. A bound
    name smuggled into the document, the label, or any
    other keyword is never the asserted schema. Inside the
    schema argument, names resolve in evaluation order: a
    walrus binds for later uses, comprehension loop
    variables shadow outer bindings (their first iterable
    still evaluates outside), and anything else resolves
    in ``env``. Conditional expressions (``IfExp``,
    ``BoolOp``) observe exactly one branch, so only names
    credited on every branch count, like branch joins.
    """
    arg_binds = {}

    def _join_branch_binds(branches):
        merged = {}
        names = set()
        for branch in branches:
            names |= set(branch)
        for name in names:
            first = branches[0].get(name, _SWEEP_MISSING)
            if first is not _SWEEP_MISSING and all(
                branch.get(name, _SWEEP_MISSING) == first
                for branch in branches
            ):
                merged[name] = first
        return merged

    def _args(child, shadowed, credit, binds):
        if isinstance(
            child,
            _SWEEP_NESTED_SCOPES + (ast.GeneratorExp,),
        ):
            return
        if isinstance(child, ast.NamedExpr) and isinstance(
            child.target, ast.Name
        ):
            _args(child.value, shadowed, credit, binds)
            literal = _sweep_load_literal(child.value)
            if literal is not None:
                binds[child.target.id] = literal
            else:
                binds.pop(child.target.id, None)
            return
        if isinstance(
            child,
            (
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
            ),
        ):
            for generator in child.generators:
                _args(generator.iter, shadowed, credit, binds)
                shadowed = shadowed | set(
                    found.id
                    for found in ast.walk(generator.target)
                    if isinstance(found, ast.Name)
                )
                for cond in generator.ifs:
                    _args(cond, shadowed, credit, binds)
            if isinstance(child, ast.DictComp):
                _args(child.key, shadowed, credit, binds)
                _args(child.value, shadowed, credit, binds)
            else:
                _args(child.elt, shadowed, credit, binds)
            return
        if isinstance(child, ast.IfExp):
            _args(child.test, shadowed, credit, binds)
            body_credit = set()
            orelse_credit = set()
            body_binds = dict(binds)
            orelse_binds = dict(binds)
            _args(
                child.body, shadowed, body_credit, body_binds
            )
            _args(
                child.orelse,
                shadowed,
                orelse_credit,
                orelse_binds,
            )
            credit |= body_credit & orelse_credit
            binds.clear()
            binds.update(
                _join_branch_binds([body_binds, orelse_binds])
            )
            return
        if isinstance(child, ast.BoolOp):
            branch_credits = []
            branch_binds = []
            for value in child.values:
                sub_credit = set()
                sub_binds = dict(binds)
                _args(value, shadowed, sub_credit, sub_binds)
                branch_credits.append(sub_credit)
                branch_binds.append(sub_binds)
            credit |= set.intersection(*branch_credits)
            binds.clear()
            binds.update(_join_branch_binds(branch_binds))
            return
        if isinstance(child, ast.Name):
            if child.id not in shadowed:
                if child.id in binds:
                    credit.add(binds[child.id])
                elif child.id in env:
                    credit.add(env[child.id])
            return
        for _field, entry in ast.iter_fields(child):
            if isinstance(entry, list):
                for item in entry:
                    if isinstance(item, ast.AST):
                        _args(item, shadowed, credit, binds)
            elif isinstance(entry, ast.AST):
                _args(entry, shadowed, credit, binds)

    if node.args:
        _args(node.args[0], frozenset(), covered, arg_binds)
    for keyword in node.keywords:
        if (
            keyword.arg == "schema"
            and keyword.value is not None
        ):
            _args(
                keyword.value, frozenset(), covered, arg_binds
            )


def _sweep_covered_names(path):
    """Schema names the closed sweep credits in ``path``.

    Only module-level sync ``test_*`` bodies count (pytest
    parity: nested ``test_*`` defs never run, and async
    tests skip without a plugin, so they fail closed).
    Test-class methods and ``test_*`` defs under any other
    statement are not swept either (pytest would collect
    ``Test*`` methods, so such coverage reports missing:
    keep it module-level). Skip-decorated bodies never
    credit. Inside a counted body, bindings flow in program
    order: each assert credits the schema in effect at its
    position (first argument, or ``schema=``), so
    sequential rebinds credit each value at its own
    assert. Divergent joins (``if``/``try``/loops/``match``
    branches, ``IfExp``/``BoolOp``/assert-message/
    comprehension-interior bindings) drop the name, fail
    closed; same-value joins keep it. Nested scopes
    (including class bodies), lazy generator expressions,
    post-terminator, post-``assert False`` and post-abort
    statements, and unsatisfiable constant guards are
    pruned. Comprehension loop variables shadow outer
    bindings (their first iterable still evaluates
    outside). Every live binding form counts (plain,
    multi-target, tuple-unpack, walrus, annotated);
    any other rebinding (including ``type`` aliases)
    poisons the name.
    """
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    covered = set()
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef):
            continue
        if not (
            isinstance(node, ast.FunctionDef)
            and node.name.startswith("test_")
        ):
            continue
        if _sweep_is_skipped(node.decorator_list):
            continue
        env = {}

        def _bind_target(target, value):
            if isinstance(target, ast.Name):
                literal = (
                    _sweep_load_literal(value)
                    if value is not None
                    else None
                )
                if literal is not None:
                    env[target.id] = literal
                else:
                    env.pop(target.id, None)
            elif (
                isinstance(target, (ast.Tuple, ast.List))
                and isinstance(value, (ast.Tuple, ast.List))
                and len(target.elts) == len(value.elts)
                and not any(
                    isinstance(elt, ast.Starred)
                    for elt in target.elts
                )
            ):
                for sub_target, sub_value in zip(
                    target.elts, value.elts
                ):
                    _bind_target(sub_target, sub_value)
            else:
                _poison_target(target)

        def _bound_names(target):
            # Only real bindings: subscript and attribute
            # targets mutate without rebinding.
            stack = [target]
            while stack:
                node = stack.pop()
                if isinstance(node, ast.Name):
                    yield node.id
                elif isinstance(node, (ast.Tuple, ast.List)):
                    stack.extend(node.elts)
                elif isinstance(node, ast.Starred):
                    stack.append(node.value)

        def _poison_target(target):
            for name in _bound_names(target):
                env.pop(name, None)

        def _collect(child):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    _bind_target(target, child.value)
            elif isinstance(child, ast.AnnAssign):
                if isinstance(
                    child.target, ast.Name
                ) and child.value is not None:
                    _bind_target(child.target, child.value)
            elif isinstance(child, ast.AugAssign):
                _poison_target(child.target)
            elif isinstance(child, ast.NamedExpr):
                if isinstance(child.target, ast.Name):
                    _bind_target(child.target, child.value)
            elif isinstance(child, ast.Delete):
                for target in child.targets:
                    _poison_target(target)
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id in _SWEEP_ASSERTS
            ):
                _sweep_credit_call(child, env, covered)

        def _walk_block(statements):
            for stmt in statements:
                if isinstance(stmt, _SWEEP_TERMINATORS):
                    for _field, entry in ast.iter_fields(stmt):
                        if isinstance(entry, ast.AST):
                            _walk_node(entry)
                    return
                if (
                    isinstance(stmt, ast.Assert)
                    and isinstance(stmt.test, ast.Constant)
                    and not stmt.test.value
                ):
                    for _field, entry in ast.iter_fields(stmt):
                        if isinstance(entry, ast.AST):
                            _walk_node(entry)
                    return
                abort = _sweep_stmt_abort_call(stmt)
                if abort is not None:
                    _walk_node(abort)
                    return
                _walk_node(stmt)

        def _walk_node(child):
            if isinstance(
                child,
                _SWEEP_NESTED_SCOPES + (ast.GeneratorExp,),
            ):
                return
            if isinstance(child, ast.If):
                _walk_node(child.test)
                if isinstance(child.test, ast.Constant):
                    if child.test.value:
                        _walk_block(child.body)
                    else:
                        _walk_block(child.orelse)
                    return
                body_env = dict(env)
                _walk_block_in(child.body, body_env)
                orelse_env = dict(env)
                _walk_block_in(child.orelse, orelse_env)
                _sweep_merge_paths(
                    env, [body_env, orelse_env]
                )
                return
            if isinstance(child, ast.While):
                _walk_node(child.test)
                if isinstance(child.test, ast.Constant):
                    if child.test.value:
                        _walk_block(child.body)
                        orelse_env = dict(env)
                        _walk_block_in(child.orelse, orelse_env)
                        _sweep_merge_paths(
                            env, [dict(env), orelse_env]
                        )
                    else:
                        _walk_block(child.orelse)
                    return
                body_env = dict(env)
                pre_env = dict(env)
                _walk_block_in(child.body, body_env)
                orelse_env = dict(env)
                _walk_block_in(child.orelse, orelse_env)
                _sweep_merge_paths(
                    env, [pre_env, body_env, orelse_env]
                )
                return
            if isinstance(child, (ast.For, ast.AsyncFor)):
                _walk_node(child.iter)
                body_env = dict(env)
                _poison_in_target(
                    child.target, body_env
                )
                _walk_block_in(child.body, body_env)
                orelse_env = dict(env)
                _walk_block_in(child.orelse, orelse_env)
                _sweep_merge_paths(
                    env, [dict(env), body_env, orelse_env]
                )
                return
            if isinstance(child, (ast.With, ast.AsyncWith)):
                # (AsyncWith is unreachable in real sync test
                # bodies -- a syntax error -- but probes
                # parse, so model it like With.)
                for item in child.items:
                    _walk_node(item.context_expr)
                    if item.optional_vars is not None:
                        _poison_target(item.optional_vars)
                _walk_block(child.body)
                return
            if isinstance(child, ast.Try):
                pre_env = dict(env)
                _walk_block(child.body)
                handler_envs = []
                for handler in child.handlers:
                    if handler.type is not None:
                        _walk_node(handler.type)
                    handler_env = dict(pre_env)
                    if handler.name:
                        handler_env.pop(handler.name, None)
                    _walk_block_in(handler.body, handler_env)
                    handler_envs.append(handler_env)
                orelse_env = dict(env)
                _walk_block_in(child.orelse, orelse_env)
                _sweep_merge_paths(
                    env, [dict(env), orelse_env] + handler_envs
                )
                _walk_block(child.finalbody)
                return
            if isinstance(child, ast.Match):
                _walk_node(child.subject)
                pre_env = dict(env)
                case_envs = []
                for case in child.cases:
                    if (
                        isinstance(case.guard, ast.Constant)
                        and not case.guard.value
                    ):
                        continue
                    case_env = dict(env)
                    _walk_node_in(case.pattern, case_env)
                    if case.guard is not None:
                        _walk_node_in(case.guard, case_env)
                    for found in ast.walk(case.pattern):
                        if isinstance(
                            found,
                            (ast.MatchAs, ast.MatchStar),
                        ):
                            if found.name:
                                case_env.pop(found.name, None)
                        elif isinstance(found, ast.MatchMapping):
                            if found.rest:
                                case_env.pop(found.rest, None)
                    _walk_block_in(case.body, case_env)
                    case_envs.append(case_env)
                _sweep_merge_paths(env, [pre_env] + case_envs)
                return
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                for entry in child.names:
                    if entry.name == "*":
                        # A star import may rebind any name
                        # (whatever the module exports), so
                        # drop every binding, fail closed.
                        # (Unreachable in real test bodies:
                        # a function-level star import is a
                        # syntax error.)
                        env.clear()
                        continue
                    bound = entry.asname or entry.name.split(
                        ".", 1
                    )[0]
                    env.pop(bound, None)
                return
            if _TYPE_ALIAS is not None and isinstance(
                child, _TYPE_ALIAS
            ):
                # The alias value evaluates lazily, so only
                # the rebinding matters: poison the target.
                if isinstance(child.name, ast.Name):
                    env.pop(child.name.id, None)
                return
            if isinstance(child, ast.IfExp):
                # The test always evaluates; each branch
                # binds conditionally, so join them.
                _walk_node(child.test)
                body_env = dict(env)
                _walk_node_in(child.body, body_env)
                orelse_env = dict(env)
                _walk_node_in(child.orelse, orelse_env)
                _sweep_merge_paths(
                    env, [body_env, orelse_env]
                )
                return
            if isinstance(child, ast.BoolOp):
                # The first operand always evaluates; each
                # later one binds conditionally, so join it
                # with the fall-through binding in turn.
                _walk_node(child.values[0])
                for value in child.values[1:]:
                    pre_env = dict(env)
                    branch_env = dict(env)
                    _walk_node_in(value, branch_env)
                    _sweep_merge_paths(
                        env, [pre_env, branch_env]
                    )
                return
            if isinstance(child, ast.Assert):
                # The message evaluates only when the test
                # is falsy, so its bindings join with the
                # fall-through ones. (Constant-false asserts
                # never reach here: _walk_block ends their
                # block first.)
                _walk_node(child.test)
                if child.msg is not None:
                    pre_env = dict(env)
                    msg_env = dict(env)
                    _walk_node_in(child.msg, msg_env)
                    _sweep_merge_paths(env, [pre_env, msg_env])
                return
            if isinstance(
                child,
                (
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                ),
            ):
                _walk_comprehension(child)
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

        def _walk_comprehension(child):
            # Eager comprehensions run inline, but their loop
            # variables shadow outer bindings everywhere
            # inside except the first iterable (which
            # evaluates outside). The loop may run zero
            # times, so bindings made inside join with the
            # pre-loop ones (same-value keeps, else drops);
            # a walrus to a loop variable drops the outer
            # binding, fail closed.
            generators = child.generators
            if generators:
                _walk_node(generators[0].iter)
            bound = set()
            for generator in generators:
                for found in ast.walk(generator.target):
                    if isinstance(found, ast.Name):
                        bound.add(found.id)
            tainted = set()
            for found in ast.walk(child):
                if (
                    isinstance(found, ast.NamedExpr)
                    and isinstance(found.target, ast.Name)
                    and found.target.id in bound
                ):
                    tainted.add(found.target.id)
            saved = {}
            pre_loop = dict(env)
            for name in bound:
                if name in env:
                    saved[name] = env.pop(name)
            try:
                for index, generator in enumerate(generators):
                    if index:
                        _walk_node(generator.iter)
                    for cond in generator.ifs:
                        _walk_node(cond)
                if isinstance(child, ast.DictComp):
                    _walk_node(child.key)
                    _walk_node(child.value)
                else:
                    _walk_node(child.elt)
            finally:
                inner = dict(env)
                for name in bound:
                    inner.pop(name, None)
                for name, value in saved.items():
                    if name not in tainted:
                        inner[name] = value
                _sweep_merge_paths(env, [pre_loop, inner])

        def _swap_env(foreign, action):
            saved = dict(env)
            env.clear()
            env.update(foreign)
            try:
                action()
            finally:
                foreign.clear()
                foreign.update(env)
                env.clear()
                env.update(saved)

        def _walk_block_in(statements, foreign):
            _swap_env(
                foreign, lambda: _walk_block(statements)
            )

        def _walk_node_in(single, foreign):
            _swap_env(
                foreign, lambda: _walk_node(single)
            )

        def _poison_in_target(target, foreign):
            for name in _bound_names(target):
                foreign.pop(name, None)

        for default in node.args.defaults:
            _walk_node(default)
        for default in node.args.kw_defaults:
            if default is not None:
                _walk_node(default)
        for decorator in node.decorator_list:
            _walk_node(decorator)
        _walk_block(node.body)
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
    assert _run_sweep_probe(probe) == {
        "outer", "lam", "live", "live2", "live3", "asserted",
    }


def _run_sweep_probe(probe):
    """Run the closed sweep over probe source; return covered names."""
    with tempfile.TemporaryDirectory(
        prefix="schema-sweep-probe-"
    ) as parent:
        path = os.path.join(parent, "probe_conform.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(probe)
        return _sweep_covered_names(path)


def test_sweep_pairs_loads_to_asserts_in_program_order():
    # Ordered flow: each assert credits the binding in
    # effect at its position. Sequential rebinds credit
    # each value at its own assert; divergent branch joins
    # credit nothing (fail closed); same-value joins credit.
    probe = (
        "def test_rebind_after_assert():\n"
        "    schema = _load_schema(\"r1\")\n"
        "    _assert_conforms(schema, {}, \"r1\")\n"
        "    _assert_union_covered(schema, [{}], \"r1\")\n"
        "    schema = _load_schema(\"r1dead\")\n"
        "def test_sequential_both():\n"
        "    schema = _load_schema(\"s1\")\n"
        "    _assert_conforms(schema, {}, \"s1\")\n"
        "    schema = _load_schema(\"s2\")\n"
        "    _assert_conforms(schema, {}, \"s2\")\n"
        "    _assert_union_covered(schema, [{}], \"s2\")\n"
        "def test_branch_diverge():\n"
        "    if cond:\n"
        "        schema = _load_schema(\"b1\")\n"
        "    else:\n"
        "        schema = _load_schema(\"b2\")\n"
        "    _assert_conforms(schema, {}, \"b\")\n"
        "    _assert_union_covered(schema, [{}], \"b\")\n"
        "def test_branch_same():\n"
        "    if cond:\n"
        "        schema = _load_schema(\"j1\")\n"
        "    else:\n"
        "        schema = _load_schema(\"j1\")\n"
        "    _assert_conforms(schema, {}, \"j1\")\n"
        "    _assert_union_covered(schema, [{}], \"j1\")\n"
        "def test_try_diverge():\n"
        "    try:\n"
        "        schema = _load_schema(\"t1\")\n"
        "    except ValueError:\n"
        "        schema = _load_schema(\"t2\")\n"
        "    _assert_conforms(schema, {}, \"t\")\n"
        "    _assert_union_covered(schema, [{}], \"t\")\n"
    )
    assert _run_sweep_probe(probe) == {"r1", "s1", "s2", "j1"}


def test_sweep_prunes_lazy_scopes_shadowing_aborts_and_dead_guards():
    # Execution, not lexical presence: lazy generator
    # expressions never credit (eager comprehensions do:
    # list here, set/dict in round two), a comprehension
    # loop variable shadowing a bound name credits nothing
    # (outer names still do), abort calls end their block,
    # and unsatisfiable match guards prune.
    probe = (
        "def test_genexp():\n"
        "    schema = _load_schema(\"g0\")\n"
        "    (_assert_conforms(schema, {}, \"g0\")"
        " for _ in [1])\n"
        "def test_listcomp():\n"
        "    schema = _load_schema(\"l1\")\n"
        "    [_assert_conforms(schema, {}, \"l1\")"
        " for _ in [1]]\n"
        "    _assert_union_covered(schema, [{}], \"l1\")\n"
        "def test_comp_shadow():\n"
        "    other = _load_schema(\"sh0\")\n"
        "    _assert_conforms(nothing,"
        " [other for other in docs])\n"
        "def test_comp_outer():\n"
        "    schema = _load_schema(\"c1\")\n"
        "    _assert_conforms(schema, [x for x in docs])\n"
        "    _assert_union_covered(schema, [{}], \"c1\")\n"
        "def test_abort():\n"
        "    schema = _load_schema(\"a1\")\n"
        "    _assert_conforms(schema, {}, \"a1\")\n"
        "    _assert_union_covered(schema, [{}], \"a1\")\n"
        "    pytest.skip(\"done\")\n"
        "    schema = _load_schema(\"adead\")\n"
        "def test_match():\n"
        "    schema = _load_schema(\"m1\")\n"
        "    _assert_conforms(schema, {}, \"m1\")\n"
        "    _assert_union_covered(schema, [{}], \"m1\")\n"
        "    match cmd:\n"
        "        case _ if False:\n"
        "            schema = _load_schema(\"mdead\")\n"
        "def test_match_live():\n"
        "    match cmd:\n"
        "        case _:\n"
        "            schema = _load_schema(\"m4\")\n"
        "            _assert_conforms(schema, {}, \"m4\")\n"
        "            _assert_union_covered(schema, [{}], \"m4\")\n"
    )
    assert _run_sweep_probe(probe) == {
        "l1", "c1", "a1", "m1", "m4",
    }


def test_sweep_binding_forms_and_decorators():
    # Live binding forms count (multi-target,
    # tuple-unpack, walrus, decorator walrus; annotated in
    # round two); rebinds without a load poison the name;
    # skip-decorated bodies never credit (skipif-False
    # still runs).
    probe = (
        "def test_multitarget():\n"
        "    s1 = s2 = _load_schema(\"mt1\")\n"
        "    _assert_conforms(s1, {}, \"mt1\")\n"
        "    _assert_union_covered(s2, [{}], \"mt1\")\n"
        "def test_tuple():\n"
        "    s1, s2 = _load_schema(\"t1\"), _load_schema(\"t2\")\n"
        "    _assert_conforms(s1, {}, \"t1\")\n"
        "    _assert_conforms(s2, {}, \"t2\")\n"
        "    _assert_union_covered(s2, [{}], \"t2\")\n"
        "def test_walrus():\n"
        "    if (schema := _load_schema(\"w1\")):\n"
        "        _assert_conforms(schema, {}, \"w1\")\n"
        "        _assert_union_covered(schema, [{}], \"w1\")\n"
        "def test_del():\n"
        "    schema = _load_schema(\"d0\")\n"
        "    del schema\n"
        "    _assert_conforms(schema, {}, \"d0\")\n"
        "def test_del_subscript():\n"
        "    schema = _load_schema(\"ds1\")\n"
        "    del schema[\"k\"]\n"
        "    _assert_conforms(schema, {}, \"ds1\")\n"
        "    _assert_union_covered(schema, [{}], \"ds1\")\n"
        "def test_for_poison():\n"
        "    schema = _load_schema(\"f0\")\n"
        "    for schema in docs:\n"
        "        pass\n"
        "    _assert_conforms(schema, {}, \"f0\")\n"
        "def test_with_poison():\n"
        "    schema = _load_schema(\"w0\")\n"
        "    with open(\"x\") as schema:\n"
        "        pass\n"
        "    _assert_conforms(schema, {}, \"w0\")\n"
        "def test_import_poison():\n"
        "    schema = _load_schema(\"i0\")\n"
        "    import schema\n"
        "    _assert_conforms(schema, {}, \"i0\")\n"
        "def test_except_name():\n"
        "    schema = _load_schema(\"e0\")\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError as schema:\n"
        "        _assert_conforms(schema, {}, \"e0\")\n"
        "def test_skipped():\n"
        "    schema = _load_schema(\"sk0\")\n"
        "    _assert_conforms(schema, {}, \"sk0\")\n"
        "    _assert_union_covered(schema, [{}], \"sk0\")\n"
        "@pytest.mark.skip\n"
        "def test_skipped_deco():\n"
        "    schema = _load_schema(\"sk1\")\n"
        "    _assert_conforms(schema, {}, \"sk1\")\n"
        "    _assert_union_covered(schema, [{}], \"sk1\")\n"
        "@pytest.mark.skipif(False)\n"
        "def test_skipif_false():\n"
        "    schema = _load_schema(\"sf1\")\n"
        "    _assert_conforms(schema, {}, \"sf1\")\n"
        "    _assert_union_covered(schema, [{}], \"sf1\")\n"
        "@dec(schema := _load_schema(\"dw0\"))\n"
        "def test_decorator_walrus():\n"
        "    _assert_conforms(schema, {}, \"dw0\")\n"
        "    _assert_union_covered(schema, [{}], \"dw0\")\n"
    )
    # NOTE: test_skipped above is intentionally NOT decorated
    # (its name alone skips nothing); only test_skipped_deco
    # is skipped. sk0 counts, sk1 does not.
    assert _run_sweep_probe(probe) == {
        "mt1", "t1", "t2", "w1", "sk0", "sf1", "dw0", "ds1",
    }


def test_sweep_ignores_async_tests():
    # Async test functions need a plugin to run at all
    # (bare pytest skips them), so the sweep fail-closes:
    # never credit, loudly missing if that was the only
    # coverage.
    probe = (
        "async def test_async():\n"
        "    schema = _load_schema(\"asy0\")\n"
        "    _assert_conforms(schema, {}, \"asy0\")\n"
        "    _assert_union_covered(schema, [{}], \"asy0\")\n"
    )
    assert _run_sweep_probe(probe) == set()


def test_sweep_abort_names():
    cases = {
        "pytest.skip(\"x\")": True,
        "pytest.fail(\"x\")": True,
        "sys.exit(1)": True,
        "exit(1)": True,
        "os._exit(1)": True,
        "x = pytest.skip(\"x\")": True,
        "x: int = pytest.fail(\"x\")": True,
        "return pytest.skip(\"x\")": True,
        "if pytest.skip(\"x\"): pass": True,
        "while sys.exit(1): pass": True,
        "print(\"x\")": False,
        "x = 1": False,
        "x = [pytest.skip(\"x\")]": False,
        "assert ok, pytest.skip(\"x\")": False,
    }
    for source, expected in cases.items():
        stmt = ast.parse(source).body[0]
        assert _sweep_is_abort_call(stmt) is expected, source


def test_sweep_skip_decorators():
    cases = {
        "@pytest.mark.skip\ndef f(): pass": True,
        "@skip\ndef f(): pass": True,
        "@unittest.skip(\"x\")\ndef f(): pass": True,
        "@pytest.mark.skipif(True)\ndef f(): pass": True,
        "@pytest.mark.skipif(False)\ndef f(): pass": False,
        "@pytest.mark.skipif(condition=True)\ndef f(): pass": True,
        "@pytest.mark.skipif(condition=False)\ndef f(): pass": False,
        "@pytest.mark.skipif(reason=\"x\")\ndef f(): pass": False,
        "@unittest.skipIf(True)\ndef f(): pass": True,
        "@unittest.skipUnless(False)\ndef f(): pass": True,
        "@unittest.skipUnless(True)\ndef f(): pass": False,
        "@unittest.skipUnless(condition=False)\ndef f(): pass": True,
        "@unittest.skipUnless(condition=True)\ndef f(): pass": False,
        "@pytest.mark.slow\ndef f(): pass": False,
        "def f(): pass": False,
    }
    for source, expected in cases.items():
        node = ast.parse(source).body[0]
        assert (
            _sweep_is_skipped(node.decorator_list) is expected
        ), source


def test_sweep_drops_names_unbound_on_every_path():
    # A name every path drops (both-branch del, or
    # both-branch non-load rebind) must not keep its stale
    # pre-branch binding; one-path drops already work.
    probe = (
        "def test_both_del():\n"
        "    schema = _load_schema(\"pre\")\n"
        "    if cond:\n"
        "        del schema\n"
        "    else:\n"
        "        del schema\n"
        "    _assert_conforms(schema, {}, \"pre\")\n"
        "def test_both_rebind():\n"
        "    schema = _load_schema(\"pre2\")\n"
        "    if cond:\n"
        "        schema = compute()\n"
        "    else:\n"
        "        schema = compute()\n"
        "    _assert_conforms(schema, {}, \"pre2\")\n"
        "def test_one_del():\n"
        "    schema = _load_schema(\"pre3\")\n"
        "    if cond:\n"
        "        del schema\n"
        "    else:\n"
        "        pass\n"
        "    _assert_conforms(schema, {}, \"pre3\")\n"
    )
    assert _run_sweep_probe(probe) == set()


def test_sweep_prunes_class_bodies():
    # Class bodies never execute in the test's scope: a
    # class-level load must not leak into the function env
    # (the equivalent real code NameErrors).
    probe = (
        "def test_cls():\n"
        "    class C:\n"
        "        schema = _load_schema(\"cls\")\n"
        "    _assert_conforms(schema, {}, \"cls\")\n"
    )
    assert _run_sweep_probe(probe) == set()


def test_sweep_abort_forms_end_their_block():
    # Abort calls end their block beyond bare expression
    # statements: assigned aborts (targets never bind) and
    # abort tests (both branches dead) prune what follows.
    probe = (
        "def test_abort_assign():\n"
        "    schema = _load_schema(\"a1\")\n"
        "    _assert_conforms(schema, {}, \"a1\")\n"
        "    x = pytest.skip(\"done\")\n"
        "    schema = _load_schema(\"adead\")\n"
        "    _assert_conforms(schema, {}, \"adead\")\n"
        "def test_abort_if():\n"
        "    schema = _load_schema(\"a2\")\n"
        "    _assert_conforms(schema, {}, \"a2\")\n"
        "    if pytest.skip(\"done\"):\n"
        "        schema = _load_schema(\"adead2\")\n"
        "    schema = _load_schema(\"adead3\")\n"
        "    _assert_conforms(schema, {}, \"adead3\")\n"
    )
    assert _run_sweep_probe(probe) == {"a1", "a2"}


def test_sweep_skip_condition_keyword():
    # pytest accepts the condition as a keyword too:
    # skipif(condition=True) and skipUnless(condition=False)
    # skip their bodies like the positional forms.
    probe = (
        "@pytest.mark.skipif(condition=True)\n"
        "def test_skip_kw():\n"
        "    schema = _load_schema(\"sk\")\n"
        "    _assert_conforms(schema, {}, \"sk\")\n"
        "@unittest.skipUnless(condition=False)\n"
        "def test_unless_kw():\n"
        "    schema = _load_schema(\"su\")\n"
        "    _assert_conforms(schema, {}, \"su\")\n"
    )
    assert _run_sweep_probe(probe) == set()


def test_sweep_credits_schema_position_only():
    # A bound name smuggled into the document argument or a
    # non-schema keyword is never the asserted schema: only
    # the first positional argument (and an explicit schema=
    # keyword) credit.
    probe = (
        "def test_smuggle():\n"
        "    real = _load_schema(\"real\")\n"
        "    smuggled = _load_schema(\"smuggled\")\n"
        "    _assert_conforms(real, {\"k\": smuggled}, \"real\")\n"
        "def test_smuggle_kw():\n"
        "    real = _load_schema(\"real2\")\n"
        "    smuggled = _load_schema(\"smuggled2\")\n"
        "    _assert_conforms(real, {}, \"w\", what=smuggled)\n"
        "def test_schema_kw():\n"
        "    real = _load_schema(\"real3\")\n"
        "    _assert_conforms({}, {}, \"w\", schema=real)\n"
    )
    assert _run_sweep_probe(probe) == {"real", "real2", "real3"}


def test_sweep_joins_conditional_expressions():
    # IfExp/BoolOp observe exactly one branch: only names
    # credited on every branch count (divergent joins drop,
    # like branch statements; same-value joins keep).
    probe = (
        "def test_ifexp():\n"
        "    s1 = _load_schema(\"i1\")\n"
        "    s2 = _load_schema(\"i2\")\n"
        "    _assert_conforms(s1 if cond else s2, {}, \"i\")\n"
        "def test_ifexp_same():\n"
        "    s1 = _load_schema(\"j1\")\n"
        "    _assert_conforms(s1 if cond else s1, {}, \"j\")\n"
        "def test_boolop():\n"
        "    s1 = _load_schema(\"b1\")\n"
        "    s2 = _load_schema(\"b2\")\n"
        "    _assert_conforms(s1 or s2, {}, \"b\")\n"
    )
    assert _run_sweep_probe(probe) == {"j1"}


def test_sweep_assert_false_ends_its_block():
    # ``assert False`` always raises: loads after it are
    # dead, while a live (non-constant) assert falls
    # through.
    probe = (
        "def test_af():\n"
        "    assert False\n"
        "    schema = _load_schema(\"af\")\n"
        "    _assert_conforms(schema, {}, \"af\")\n"
        "def test_live_assert():\n"
        "    schema = _load_schema(\"la\")\n"
        "    assert schema\n"
        "    _assert_conforms(schema, {}, \"la\")\n"
    )
    assert _run_sweep_probe(probe) == {"la"}


def test_sweep_type_alias_poisons():
    # ``type schema = ...`` (3.12+) rebinds the name: the
    # stale load must not survive. Below 3.12 the statement
    # is a syntax error, so there is nothing to pin.
    if _TYPE_ALIAS is None:
        return
    probe = (
        "def test_ta():\n"
        "    schema = _load_schema(\"o\")\n"
        "    type schema = int\n"
        "    _assert_conforms(schema, {}, \"o\")\n"
    )
    assert _run_sweep_probe(probe) == set()


def test_sweep_binding_forms_round_two():
    # Remaining binding forms: annotated assigns count,
    # augmented assigns poison, starred/mismatched unpacks
    # poison, a non-load walrus poisons, a walrus in assert
    # Name use, fail closed), subscript/attribute assigns
    # retain, set/dict comprehensions credit eagerly,
    # from/as/dotted imports poison, star imports drop
    # every binding, and async-with poisons like with.
    probe = (
        "def test_annassign():\n"
        "    schema: object = _load_schema(\"an1\")\n"
        "    _assert_conforms(schema, {}, \"an1\")\n"
        "def test_augassign():\n"
        "    schema = _load_schema(\"au0\")\n"
        "    schema += 1\n"
        "    _assert_conforms(schema, {}, \"au0\")\n"
        "def test_starred():\n"
        "    s1, *rest = _load_schema(\"st1\"), _load_schema(\"st2\")\n"
        "    _assert_conforms(s1, {}, \"st1\")\n"
        "def test_mismatch():\n"
        "    s1, s2 = _load_schema(\"mm1\"),\n"
        "    _assert_conforms(s1, {}, \"mm1\")\n"
        "def test_walrus_poison():\n"
        "    schema = _load_schema(\"wp0\")\n"
        "    if (schema := compute()):\n"
        "        pass\n"
        "    _assert_conforms(schema, {}, \"wp0\")\n"
        "def test_walrus_arg():\n"
        "    _assert_conforms((s := _load_schema(\"wa1\")), {}, \"wa1\")\n"
        "    _assert_conforms(s, {}, \"wa1\")\n"
        "def test_sub_attr():\n"
        "    schema = _load_schema(\"sa1\")\n"
        "    schema[\"k\"] = 1\n"
        "    namespace.attr = schema\n"
        "    _assert_conforms(schema, {}, \"sa1\")\n"
        "def test_setcomp():\n"
        "    schema = _load_schema(\"sc1\")\n"
        "    {_assert_conforms(schema, {}, \"sc1\") for _ in [1]}\n"
        "def test_dictcomp():\n"
        "    schema = _load_schema(\"dc1\")\n"
        "    {\"k\": _assert_conforms(schema, {}, \"dc1\")"
        " for _ in [1]}\n"
        "def test_importfrom():\n"
        "    schema = _load_schema(\"im0\")\n"
        "    from m import schema\n"
        "    _assert_conforms(schema, {}, \"im0\")\n"
        "def test_import_as():\n"
        "    schema = _load_schema(\"ia0\")\n"
        "    import m as schema\n"
        "    _assert_conforms(schema, {}, \"ia0\")\n"
        "def test_import_dotted():\n"
        "    schema = _load_schema(\"id0\")\n"
        "    import schema.sub\n"
        "    _assert_conforms(schema, {}, \"id0\")\n"
        "def test_import_star():\n"
        "    schema = _load_schema(\"is0\")\n"
        "    from m import *\n"
        "    _assert_conforms(schema, {}, \"is0\")\n"
        "def test_async_with():\n"
        "    schema = _load_schema(\"aw0\")\n"
        "    async with open(\"x\") as schema:\n"
        "        pass\n"
        "    _assert_conforms(schema, {}, \"aw0\")\n"
    )
    assert _run_sweep_probe(probe) == {
        "an1", "wa1", "sa1", "sc1", "dc1",
    }


def test_sweep_control_flow_round_two():
    # Remaining control flow: if-True/while-True run inline,
    # break/continue/raise end their block, while/for joins
    # keep same-value bindings and drop the rest, try
    # orelse/finally flow in order, except handlers poison
    # after the try too, and match captures poison.
    probe = (
        "def test_iftrue():\n"
        "    if True:\n"
        "        schema = _load_schema(\"it1\")\n"
        "    _assert_conforms(schema, {}, \"it1\")\n"
        "def test_whiletrue():\n"
        "    while True:\n"
        "        schema = _load_schema(\"wt1\")\n"
        "        break\n"
        "    _assert_conforms(schema, {}, \"wt1\")\n"
        "def test_break():\n"
        "    for i in docs:\n"
        "        schema = _load_schema(\"bk1\")\n"
        "        _assert_conforms(schema, {}, \"bk1\")\n"
        "        break\n"
        "        schema = _load_schema(\"bkdead\")\n"
        "def test_continue():\n"
        "    for i in docs:\n"
        "        schema = _load_schema(\"ct1\")\n"
        "        _assert_conforms(schema, {}, \"ct1\")\n"
        "        continue\n"
        "        schema = _load_schema(\"ctdead\")\n"
        "def test_raise():\n"
        "    schema = _load_schema(\"rz1\")\n"
        "    _assert_conforms(schema, {}, \"rz1\")\n"
        "    raise ValueError(\"x\")\n"
        "    schema = _load_schema(\"rzdead\")\n"
        "def test_for_same():\n"
        "    schema = _load_schema(\"fs1\")\n"
        "    for i in docs:\n"
        "        schema = _load_schema(\"fs1\")\n"
        "    _assert_conforms(schema, {}, \"fs1\")\n"
        "def test_for_diverge():\n"
        "    for i in docs:\n"
        "        schema = _load_schema(\"fd1\")\n"
        "    _assert_conforms(schema, {}, \"fd1\")\n"
        "def test_while_same():\n"
        "    schema = _load_schema(\"ws1\")\n"
        "    while cond:\n"
        "        schema = _load_schema(\"ws1\")\n"
        "    _assert_conforms(schema, {}, \"ws1\")\n"
        "def test_while_diverge():\n"
        "    while cond:\n"
        "        schema = _load_schema(\"wd1\")\n"
        "    _assert_conforms(schema, {}, \"wd1\")\n"
        "def test_try_finally():\n"
        "    try:\n"
        "        schema = _load_schema(\"tf1\")\n"
        "    finally:\n"
        "        schema = _load_schema(\"tf2\")\n"
        "    _assert_conforms(schema, {}, \"tf2\")\n"
        "def test_try_orelse():\n"
        "    try:\n"
        "        schema = _load_schema(\"to1\")\n"
        "    except ValueError:\n"
        "        schema = _load_schema(\"to1\")\n"
        "    else:\n"
        "        pass\n"
        "    _assert_conforms(schema, {}, \"to1\")\n"
        "def test_except_after():\n"
        "    schema = _load_schema(\"ea0\")\n"
        "    try:\n"
        "        pass\n"
        "    except ValueError as schema:\n"
        "        pass\n"
        "    _assert_conforms(schema, {}, \"ea0\")\n"
        "def test_match_as():\n"
        "    schema = _load_schema(\"mc0\")\n"
        "    match cmd:\n"
        "        case str() as schema:\n"
        "            pass\n"
        "    _assert_conforms(schema, {}, \"mc0\")\n"
        "def test_match_star():\n"
        "    schema = _load_schema(\"ms0\")\n"
        "    match cmd:\n"
        "        case [first, *schema]:\n"
        "            pass\n"
        "    _assert_conforms(schema, {}, \"ms0\")\n"
        "def test_match_rest():\n"
        "    schema = _load_schema(\"mr0\")\n"
        "    match cmd:\n"
        '        case {"k": value, **schema}:\n'
        "            pass\n"
        "    _assert_conforms(schema, {}, \"mr0\")\n"
    )
    assert _run_sweep_probe(probe) == {
        "it1", "wt1", "bk1", "ct1", "rz1", "fs1", "ws1",
        "tf2", "to1",
    }


def test_sweep_conditional_expression_bindings_join():
    # Bindings made in conditional-expression positions
    # join like branches: IfExp/BoolOp/assert-message
    # walrus and comprehension-interior walrus drop unless
    # the fall-through binding agrees; eager positions
    # (IfExp test, first BoolOp operand, first
    # comprehension iterable) bind unconditionally, and a
    # shadowed outer binding survives the comprehension.
    probe = (
        "def test_ifexp_walrus():\n"
        "    value = (u := _load_schema(\"u\")) if cond else other\n"
        "    _assert_conforms(u, {}, \"u\")\n"
        "def test_ifexp_walrus_same():\n"
        "    u = _load_schema(\"us\")\n"
        "    value = (u := _load_schema(\"us\")) if cond else other\n"
        "    _assert_conforms(u, {}, \"us\")\n"
        "def test_ifexp_test_walrus():\n"
        "    value = x if (u := _load_schema(\"ut\")) else y\n"
        "    _assert_conforms(u, {}, \"ut\")\n"
        "def test_boolop_walrus():\n"
        "    value = flag or (u := _load_schema(\"ub\"))\n"
        "    _assert_conforms(u, {}, \"ub\")\n"
        "def test_boolop_first_walrus():\n"
        "    value = (u := _load_schema(\"uf\")) or flag\n"
        "    _assert_conforms(u, {}, \"uf\")\n"
        "def test_assert_msg_walrus():\n"
        "    assert ok, (u := _load_schema(\"um\"))\n"
        "    _assert_conforms(u, {}, \"um\")\n"
        "def test_comp_walrus():\n"
        "    [(u := _load_schema(\"uc\")) for i in docs]\n"
        "    _assert_conforms(u, {}, \"uc\")\n"
        "def test_comp_first_walrus():\n"
        "    [x for i in (u := _load_schema(\"ue\"))]\n"
        "    _assert_conforms(u, {}, \"ue\")\n"
        "def test_comp_same():\n"
        "    u = _load_schema(\"uo\")\n"
        "    [(u := _load_schema(\"uo\")) for i in docs]\n"
        "    _assert_conforms(u, {}, \"uo\")\n"
        "def test_comp_shadow_survives():\n"
        "    other = _load_schema(\"ss\")\n"
        "    [x for other in docs]\n"
        "    _assert_conforms(other, {}, \"ss\")\n"
    )
    assert _run_sweep_probe(probe) == {
        "us", "ut", "uf", "ue", "uo", "ss",
    }


def test_sweep_statement_comprehension_shadows_loop_vars():
    # A comprehension loop variable shadows the outer
    # binding everywhere inside (not just in assert
    # arguments): the outer load credits nothing, while the
    # first iterable still evaluates outside.
    probe = (
        "def test_comp_stmt_shadow():\n"
        "    other = _load_schema(\"sh0\")\n"
        "    [_assert_conforms(other, {}, \"sh0\")"
        " for other in docs]\n"
        "def test_comp_first_iter_outer():\n"
        "    schema = _load_schema(\"fi1\")\n"
        "    [_assert_conforms(schema, {}, \"fi1\")"
        " for _ in schema]\n"
    )
    assert _run_sweep_probe(probe) == {"fi1"}


def test_every_schema_file_has_conformance_coverage():
    # Closed sweep: every schemas/*.schema.json at any depth
    # must be asserted by a conformance test above (a literal
    # _load_schema load bound to a name in a module-level
    # sync test_* body, whose value flows into an assert
    # helper in program order; nested scopes, lazy
    # generators, structurally dead code, divergent branch
    # joins, and skip-decorated bodies are pruned), so a
    # new schema file without a test fails here, never
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
