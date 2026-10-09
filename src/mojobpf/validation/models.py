# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Frozen validation contract models: targets, fixtures, plans and results.

This module implements ``test-contracts-v1`` (case/target/fixture/run-plan
records) and the ``suite-result-v1`` terminal record. The JSON schemas under
``schemas/`` are the frozen cross-consumer contract; the parsers here are the
Python enforcement. Every malformed input fails deterministically with a
stable ``MBPF3xx`` diagnostic code; unknown fields and unknown schema
versions are never partially interpreted.

Contract acquisition for standalone consumers (no sibling checkout needed,
works from an installed ``mojobpf`` package or an unpacked source archive
since the schemas ship with the distribution)::

    python3 -c "from mojobpf.validation import digest_of, export_schema_bundle; \\
        print(digest_of(export_schema_bundle('mojobpf-test-contracts')))"
    python3 -c "from mojobpf.validation import verify_schema_bundle; \\
        print(verify_schema_bundle('mojobpf-test-contracts', \\
        '<pinned-manifest-digest>'))"

Bootstrap: the publisher runs the export step and prints the canonical
SHA-256 manifest digest; each release publishes that digest alongside
the bundle. Consumers pin the published digest independently and pass
it to :func:`verify_schema_bundle`, which requires it: there is no
unpinned mode, since a self-consistent bundle can re-pin its own
tampered schemas. The bundle is tests-only support data; standalone
consumers gain no runtime dependency on this package beyond the
export step.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..diagnostics import (
    SEVERITY_ERROR,
    Diagnostic,
    MojobpfError,
)

SCHEMA_VERSION = 1
TEST_CONTRACTS_VERSION = "test-contracts-v1"
SUITE_RESULT_VERSION = "suite-result-v1"
BUNDLE_NAME = "mojobpf-test-contracts"
BUNDLE_VERSION = 1
SCHEMA_FILES = (
    "target.schema.json",
    "fixture.schema.json",
    "run-plan.schema.json",
    "result.schema.json",
    "cost.schema.json",
)

STAGE_CONTRACT = "validation.contract"
STAGE_BUNDLE = "validation.bundle"

# Execution outcomes, availability values and implementation states are the
# exact enums from validation spec section 3.3. Availability is independent
# of execution: a result carries both, and aggregation never lets a
# non-applicable cell increment PASS.
OUTCOME_PASS = "PASS"
OUTCOME_FAIL = "FAIL"
OUTCOME_INFRA_ERROR = "INFRA_ERROR"
OUTCOME_NOT_RUN = "NOT_RUN"
EXECUTION_OUTCOMES = frozenset(
    {OUTCOME_PASS, OUTCOME_FAIL, OUTCOME_INFRA_ERROR, OUTCOME_NOT_RUN}
)

AVAIL_APPLICABLE = "APPLICABLE"
AVAIL_NOT_APPLICABLE = "NOT_APPLICABLE"
AVAIL_UNKNOWN = "UNKNOWN"
AVAILABILITY = frozenset(
    {
        "APPLICABLE",
        "KERNEL_FEATURE_ABSENT",
        "CONFIG_DISABLED",
        "POLICY_DENIED",
        "TARGET_RESOURCE_ABSENT",
        "HARDWARE_MISSING",
        "TOOLCHAIN_UNAVAILABLE",
        "UPSTREAM_BLOCKED",
        "NOT_APPLICABLE",
        "UNKNOWN",
    }
)
# Cells in these states are observed but unavailable; they are blocked, and
# required ones keep the gate non-PASS without ever incrementing PASS.
BLOCKED_AVAILABILITY = frozenset(
    {
        "KERNEL_FEATURE_ABSENT",
        "CONFIG_DISABLED",
        "POLICY_DENIED",
        "TARGET_RESOURCE_ABSENT",
        "HARDWARE_MISSING",
        "TOOLCHAIN_UNAVAILABLE",
        "UPSTREAM_BLOCKED",
        "UNKNOWN",
    }
)

IMPLEMENTATION_STATES = frozenset(
    {"REPORTED", "AUDITED", "IN_PROGRESS", "IMPLEMENTED", "QUALIFIED"}
)

FAILURE_STAGES = frozenset(
    {
        "BUILD",
        "ARTIFACT_INSPECTION",
        "LOAD",
        "ATTACH",
        "TEST_RUN",
        "RUNTIME",
        "VERIFY",
        "CLEANUP",
        "COST",
        "INFRA",
    }
)

EXECUTION_MODES = frozenset({"physical", "hardware-vm", "tcg"})
BYTE_ORDERS = frozenset({"le", "be"})
EXPECTATIONS = frozenset({"positive", "denial"})
CLEANUP_STATUSES = frozenset({"CLEAN", "RESIDUE", "NOT_CHECKED"})
GATE_VERDICTS = frozenset({"PASS", "FAIL", "INCOMPLETE"})
BARRIERS = frozenset({"ready", "start", "stop", "drained"})

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ContractError(MojobpfError):
    """Stable contract violation carrying one MBPF3xx diagnostic."""

    def __init__(
        self,
        code: str,
        explanation: str,
        location: str | None = None,
        remedy: str | None = None,
        stage: str = STAGE_CONTRACT,
    ) -> None:
        super().__init__(
            Diagnostic(
                code=code,
                stage=stage,
                severity=SEVERITY_ERROR,
                explanation=explanation,
                location=location,
                remedy=remedy,
            )
        )
        self.code = code


def _fail(
    code: str,
    explanation: str,
    location: str | None = None,
    remedy: str | None = None,
    stage: str = STAGE_CONTRACT,
) -> ContractError:
    return ContractError(code, explanation, location, remedy, stage)


def canonical_json(value: Any) -> bytes:
    """Return the canonical JSON bytes used for all contract digests."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def digest_of(value: Any) -> str:
    """Return the SHA-256 hex digest of the canonical JSON of value."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _require_mapping(value: Any, what: str, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(
            "MBPF301", "%s must be a JSON object" % what, location=location
        )
    return value


def _check_keys(
    mapping: Mapping[str, Any],
    required: Sequence[str],
    optional: Sequence[str],
    location: str,
) -> None:
    for key in required:
        if key not in mapping:
            raise _fail(
                "MBPF303",
                "missing required field %r" % key,
                location=location,
            )
    allowed = set(required) | set(optional)
    for key in mapping:
        if key not in allowed:
            raise _fail(
                "MBPF302", "unknown field %r" % key, location=location
            )


def _check_version(mapping: Mapping[str, Any], location: str) -> None:
    if mapping.get("schema_version") != SCHEMA_VERSION:
        raise _fail(
            "MBPF304",
            "unsupported schema_version %r; test-contracts-v1 reads 1 only"
            % (mapping.get("schema_version"),),
            location=location,
        )


def _check_enum(
    value: Any, allowed: frozenset[str], what: str, location: str
) -> str:
    try:
        member = value in allowed
    except TypeError:
        member = False
    if not member:
        raise _fail(
            "MBPF305",
            "%s must be one of %s, got %r"
            % (what, sorted(allowed), value),
            location=location,
        )
    return value


def _check_str(
    value: Any, what: str, location: str, allow_empty: bool = False
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise _fail(
            "MBPF305",
            "%s must be a non-empty string" % what,
            location=location,
        )
    return value


def _check_pattern(
    value: Any, pattern: re.Pattern[str], what: str, location: str
) -> str:
    text = _check_str(value, what, location)
    if not pattern.match(text):
        raise _fail(
            "MBPF305", "%s has invalid shape: %r" % (what, text),
            location=location,
        )
    return text


def _check_int(
    value: Any,
    what: str,
    location: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _fail(
            "MBPF305", "%s must be an integer" % what, location=location
        )
    if minimum is not None and value < minimum:
        raise _fail(
            "MBPF305",
            "%s must be >= %d" % (what, minimum),
            location=location,
        )
    if maximum is not None and value > maximum:
        raise _fail(
            "MBPF305",
            "%s must be <= %d" % (what, maximum),
            location=location,
        )
    return value


def _check_str_list(value: Any, what: str, location: str) -> list[str]:
    """Require a JSON array of non-empty strings (never null/scalar)."""
    if not isinstance(value, list):
        raise _fail(
            "MBPF305", "%s must be an array" % what, location=location
        )
    return [
        _check_str(entry, "%s entry" % what, location) for entry in value
    ]


def _check_json_value(value: Any, what: str, location: str) -> Any:
    """Validate a JSON semantic value; return a detached copy."""
    stack: list[tuple[Any, str]] = [(value, what)]
    while stack:
        current, label = stack.pop()
        if current is None or isinstance(current, (str, bool, int)):
            continue
        if isinstance(current, float):
            if current != current or current in (
                float("inf"), float("-inf")
            ):
                raise _fail(
                    "MBPF305",
                    "%s must be a finite number" % label,
                    location=location,
                )
            continue
        if isinstance(current, list):
            stack.extend(
                (entry, "%s entry" % label) for entry in current
            )
            continue
        if isinstance(current, dict):
            for key, entry in current.items():
                if not isinstance(key, str):
                    raise _fail(
                        "MBPF305",
                        "%s object keys must be strings" % label,
                        location=location,
                    )
                stack.append((entry, "%s[%s]" % (label, key)))
            continue
        raise _fail(
            "MBPF305",
            "%s must be a JSON value (number, string, boolean, null, "
            "array or object)" % label,
            location=location,
        )
    return json.loads(canonical_json(value))


def _check_behavior(value: Any, location: str) -> dict[str, Any]:
    """Validate an expected/observed behavior record.

    ``outcome``/``failure_stage`` carry the execution verdict (stage
    null iff PASS). Optional ``value`` carries the observed semantic
    payload (for example the map value ``42`` in the 41→42 oracle);
    optional ``error_class`` carries the structured semantic error
    class for failures. Both are compared exactly: a PASS must
    observe its full expectation, and a denial must observe its
    planned failure including semantics.
    """
    mapping = _require_mapping(value, "behavior", location)
    _check_keys(
        mapping, ("outcome", "failure_stage"), ("value", "error_class"),
        location,
    )
    _check_enum(mapping["outcome"], EXECUTION_OUTCOMES, "outcome", location)
    stage = mapping["failure_stage"]
    if mapping["outcome"] == OUTCOME_PASS:
        if stage is not None:
            raise _fail(
                "MBPF305",
                "failure_stage must be null when outcome is PASS",
                location=location,
            )
    else:
        _check_enum(stage, FAILURE_STAGES, "failure_stage", location)
    checked: dict[str, Any] = {
        "outcome": mapping["outcome"], "failure_stage": stage
    }
    if "value" in mapping:
        checked["value"] = _check_json_value(
            mapping["value"], "value", location
        )
    if "error_class" in mapping:
        checked["error_class"] = _check_str(
            mapping["error_class"], "error_class", location
        )
    return checked


def _source_schemas_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "schemas"


def _packaged_schemas_dir() -> Path | None:
    try:
        from importlib import resources

        candidate = resources.files("mojobpf") / "schemas"
        if candidate.is_dir():
            return Path(str(candidate))
    except Exception:
        pass
    try:
        from importlib import metadata

        dist = metadata.distribution("mojobpf")
        for installed in dist.files or []:
            text = str(installed).replace("\\", "/")
            if text.endswith("mojobpf/schemas/result.schema.json"):
                located = Path(str(dist.locate_file(installed)))
                if located.is_file():
                    return located.parent
    except Exception:
        pass
    try:
        import sys

        for base in (sys.prefix, getattr(sys, "base_prefix", sys.prefix)):
            candidate = Path(base) / "share/mojobpf/schemas"
            if (candidate / "result.schema.json").is_file():
                return candidate
    except Exception:
        pass
    return None


def schemas_dir() -> Path:
    """Return the directory holding the frozen contract schemas.

    Prefers the installed distribution (package data or the
    ``share/mojobpf/schemas`` data files installed by the wheel),
    falling back to the source checkout. Works from an installed
    package or an unpacked source archive without a checkout.
    """
    packaged = _packaged_schemas_dir()
    if packaged is not None and (packaged / "result.schema.json").is_file():
        return packaged
    source = _source_schemas_dir()
    if (source / "result.schema.json").is_file():
        return source
    raise _fail(
        "MBPF307",
        "contract schemas not found (checked installed package data and %s)"
        % source,
        stage=STAGE_BUNDLE,
    )


def load_schema(name: str) -> dict[str, Any]:
    """Load one frozen schema document by short name.

    ``name`` is one of target, fixture, run-plan, result, cost.
    """
    filename = "%s.schema.json" % name
    if filename not in SCHEMA_FILES:
        raise _fail("MBPF307", "unknown schema %r" % name,
                    stage=STAGE_BUNDLE)
    path = schemas_dir() / filename
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise _fail(
            "MBPF307", "cannot load schema %s: %s" % (filename, exc),
            stage=STAGE_BUNDLE,
        )
    return _require_mapping(data, "schema %s" % filename, filename)  # type: ignore[return-value]


def schema_digest(name: str) -> str:
    """Return the SHA-256 hex digest of one frozen schema file's bytes."""
    filename = "%s.schema.json" % name
    if filename not in SCHEMA_FILES:
        raise _fail("MBPF307", "unknown schema %r" % name,
                    stage=STAGE_BUNDLE)
    try:
        raw = (schemas_dir() / filename).read_bytes()
    except OSError as exc:
        raise _fail(
            "MBPF307", "cannot read schema %s: %s" % (filename, exc),
            stage=STAGE_BUNDLE,
        )
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class TargetManifest:
    """Validated runtime target with a verified fingerprint."""

    fingerprint: str
    data: Mapping[str, Any] = field(compare=False)

    @staticmethod
    def fingerprint_of(data: Mapping[str, Any]) -> str:
        """Compute the fingerprint of a target record sans fingerprint."""
        body = {key: data[key] for key in data if key != "fingerprint"}
        return digest_of(body)

    @classmethod
    def from_dict(cls, value: Any) -> "TargetManifest":
        mapping = _require_mapping(value, "target manifest", "target")
        _check_keys(
            mapping,
            (
                "schema_version",
                "fingerprint",
                "kernel",
                "btf",
                "image",
                "cpu",
                "execution_mode",
                "byte_order",
                "instruction_profile",
                "jit",
                "boot",
                "privileges",
                "mounts",
                "build_host",
            ),
            ("netdevice", "probed_process"),
            "target",
        )
        _check_version(mapping, "target")
        fingerprint = _check_pattern(
            mapping["fingerprint"], SHA256_RE, "fingerprint", "target"
        )
        kernel = _require_mapping(mapping["kernel"], "kernel", "target.kernel")
        _check_keys(
            kernel,
            ("source_commit", "release", "build_id", "config_sha256"),
            (),
            "target.kernel",
        )
        _check_pattern(
            kernel["source_commit"],
            COMMIT_RE,
            "kernel.source_commit",
            "target.kernel",
        )
        _check_str(kernel["release"], "kernel.release", "target.kernel")
        _check_str(kernel["build_id"], "kernel.build_id", "target.kernel")
        _check_pattern(
            kernel["config_sha256"],
            SHA256_RE,
            "kernel.config_sha256",
            "target.kernel",
        )
        btf = _require_mapping(mapping["btf"], "btf", "target.btf")
        _check_keys(btf, ("vmlinux_sha256",), ("modules",), "target.btf")
        _check_pattern(
            btf["vmlinux_sha256"], SHA256_RE, "btf.vmlinux_sha256",
            "target.btf",
        )
        modules = btf.get("modules", [])
        if not isinstance(modules, list):
            raise _fail(
                "MBPF305",
                "btf.modules must be an array",
                location="target.btf",
            )
        for index, module in enumerate(modules):
            where = "target.btf.modules[%d]" % index
            entry = _require_mapping(module, "btf module", where)
            _check_keys(entry, ("name", "sha256"), (), where)
            _check_str(entry["name"], "module name", where)
            _check_pattern(entry["sha256"], SHA256_RE, "module sha256", where)
        image = _require_mapping(mapping["image"], "image", "target.image")
        _check_keys(image, ("digest", "packages"), (), "target.image")
        _check_str(image["digest"], "image.digest", "target.image")
        packages = _require_mapping(
            image["packages"], "image packages", "target.image.packages"
        )
        for name, version in packages.items():
            _check_str(version, "package %s" % name, "target.image.packages")
        cpu = _require_mapping(mapping["cpu"], "cpu", "target.cpu")
        _check_keys(
            cpu,
            ("architecture", "model", "features", "page_size", "cpus"),
            (),
            "target.cpu",
        )
        _check_str(cpu["architecture"], "cpu.architecture", "target.cpu")
        _check_str(cpu["model"], "cpu.model", "target.cpu")
        _check_str_list(cpu["features"], "cpu.features", "target.cpu")
        _check_int(cpu["page_size"], "cpu.page_size", "target.cpu", minimum=1)
        _check_int(cpu["cpus"], "cpu.cpus", "target.cpu", minimum=1)
        _check_enum(
            mapping["execution_mode"],
            EXECUTION_MODES,
            "execution_mode",
            "target",
        )
        _check_enum(mapping["byte_order"], BYTE_ORDERS, "byte_order", "target")
        _check_str(
            mapping["instruction_profile"],
            "instruction_profile",
            "target",
        )
        jit = _require_mapping(mapping["jit"], "jit", "target.jit")
        _check_keys(jit, ("state", "hardening"), (), "target.jit")
        _check_enum(
            jit["state"],
            frozenset({"enabled", "disabled", "unknown"}),
            "jit.state",
            "target.jit",
        )
        _check_str_list(
            jit["hardening"], "jit.hardening", "target.jit"
        )
        boot = _require_mapping(mapping["boot"], "boot", "target.boot")
        _check_keys(
            boot, ("parameters", "lsms", "lockdown"), (), "target.boot"
        )
        _check_str_list(
            boot["parameters"], "boot.parameters", "target.boot"
        )
        _check_str_list(boot["lsms"], "boot.lsms", "target.boot")
        _check_str(boot["lockdown"], "boot.lockdown", "target.boot")
        priv = _require_mapping(
            mapping["privileges"], "privileges", "target.privileges"
        )
        _check_keys(
            priv,
            ("capabilities", "token", "delegation", "rlimits"),
            (),
            "target.privileges",
        )
        _check_str_list(
            priv["capabilities"],
            "privileges.capabilities",
            "target.privileges",
        )
        _check_str(priv["token"], "privileges.token", "target.privileges")
        _check_str(
            priv["delegation"], "privileges.delegation", "target.privileges"
        )
        rlimits = _require_mapping(
            priv["rlimits"], "rlimits", "target.privileges.rlimits"
        )
        for name, limit in rlimits.items():
            _check_str(limit, "rlimit %s" % name,
                       "target.privileges.rlimits")
        mounts = _require_mapping(mapping["mounts"], "mounts", "target.mounts")
        _check_keys(
            mounts,
            ("tracefs", "bpffs", "cgroup", "namespaces"),
            (),
            "target.mounts",
        )
        _check_str(mounts["tracefs"], "mounts.tracefs", "target.mounts")
        _check_str(mounts["bpffs"], "mounts.bpffs", "target.mounts")
        _check_str(mounts["cgroup"], "mounts.cgroup", "target.mounts")
        _check_str_list(
            mounts["namespaces"], "mounts.namespaces", "target.mounts"
        )
        host = _require_mapping(
            mapping["build_host"], "build_host", "target.build_host"
        )
        _check_keys(host, ("identity", "flags"), (), "target.build_host")
        _check_str(host["identity"], "build_host.identity",
                   "target.build_host")
        _check_str_list(
            host["flags"], "build_host.flags", "target.build_host"
        )
        if mapping.get("netdevice") is not None:
            net = _require_mapping(
                mapping["netdevice"], "netdevice", "target.netdevice"
            )
            _check_keys(
                net, ("driver", "firmware", "queues"), (), "target.netdevice"
            )
            _check_str(net["driver"], "netdevice.driver", "target.netdevice")
            _check_str(
                net["firmware"], "netdevice.firmware", "target.netdevice"
            )
            _check_str(net["queues"], "netdevice.queues", "target.netdevice")
        if mapping.get("probed_process") is not None:
            probed = _require_mapping(
                mapping["probed_process"],
                "probed_process",
                "target.probed_process",
            )
            _check_keys(
                probed,
                ("architecture", "abi", "executable_sha256"),
                ("shared_objects",),
                "target.probed_process",
            )
            _check_str(
                probed["architecture"],
                "probed_process.architecture",
                "target.probed_process",
            )
            _check_str(
                probed["abi"], "probed_process.abi", "target.probed_process"
            )
            _check_pattern(
                probed["executable_sha256"],
                SHA256_RE,
                "probed_process.executable_sha256",
                "target.probed_process",
            )
            shared = probed.get("shared_objects", [])
            if not isinstance(shared, list):
                raise _fail(
                    "MBPF305",
                    "probed_process.shared_objects must be an array",
                    location="target.probed_process",
                )
            for index, item in enumerate(shared):
                where = "target.probed_process.shared_objects[%d]" % index
                entry = _require_mapping(item, "shared object", where)
                _check_keys(entry, ("path", "sha256"), (), where)
                _check_str(entry["path"], "shared object path", where)
                _check_pattern(
                    entry["sha256"], SHA256_RE, "shared object sha256", where
                )
        recomputed = cls.fingerprint_of(mapping)
        if recomputed != fingerprint:
            raise _fail(
                "MBPF306",
                "target fingerprint mismatch: stored %s, recomputed %s"
                % (fingerprint, recomputed),
                location="target",
            )
        return cls(
            fingerprint=fingerprint,
            data=json.loads(canonical_json(dict(mapping))),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached plain-data copy of this manifest."""
        try:
            return json.loads(canonical_json(dict(self.data)))
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed TargetManifest instance: %s" % (exc,),
                location="target",
            )


@dataclass(frozen=True)
class Fixture:
    """Validated fixture ABI record."""

    fixture_id: str
    data: Mapping[str, Any] = field(compare=False)

    @classmethod
    def from_dict(cls, value: Any) -> "Fixture":
        mapping = _require_mapping(value, "fixture", "fixture")
        _check_keys(
            mapping,
            (
                "schema_version",
                "fixture_id",
                "object",
                "entries",
                "maps",
                "corpus",
                "oracle",
                "barriers",
            ),
            ("event_abi",),
            "fixture",
        )
        _check_version(mapping, "fixture")
        fixture_id = _check_pattern(
            mapping["fixture_id"], ID_RE, "fixture_id", "fixture"
        )
        obj = _require_mapping(mapping["object"], "object", "fixture.object")
        _check_keys(obj, ("path", "sha256", "bytes"), (), "fixture.object")
        _check_str(obj["path"], "object.path", "fixture.object")
        _check_pattern(
            obj["sha256"], SHA256_RE, "object.sha256", "fixture.object"
        )
        _check_int(obj["bytes"], "object.bytes", "fixture.object", minimum=1)
        entries = mapping["entries"]
        if not isinstance(entries, list) or not entries:
            raise _fail(
                "MBPF305",
                "entries must be a non-empty array",
                location="fixture",
            )
        seen_entries: set[str] = set()
        for index, entry in enumerate(entries):
            where = "fixture.entries[%d]" % index
            item = _require_mapping(entry, "entry", where)
            _check_keys(
                item, ("symbol", "program_type", "section"), (), where
            )
            symbol = _check_pattern(
                item["symbol"], SYMBOL_RE, "entry symbol", where
            )
            if symbol in seen_entries:
                raise _fail(
                    "MBPF305",
                    "duplicate entry symbol %r" % symbol,
                    location=where,
                )
            seen_entries.add(symbol)
            _check_str(item["program_type"], "program_type", where)
            _check_str(item["section"], "section", where)
        maps = mapping["maps"]
        if not isinstance(maps, list):
            raise _fail(
                "MBPF305", "maps must be an array", location="fixture"
            )
        seen_maps: set[str] = set()
        for index, entry in enumerate(maps):
            where = "fixture.maps[%d]" % index
            item = _require_mapping(entry, "map", where)
            _check_keys(
                item,
                ("name", "map_type", "key", "value", "max_entries"),
                (),
                where,
            )
            name = _check_pattern(item["name"], SYMBOL_RE, "map name", where)
            if name in seen_maps:
                raise _fail(
                    "MBPF305", "duplicate map name %r" % name,
                    location=where,
                )
            seen_maps.add(name)
            _check_str(item["map_type"], "map_type", where)
            for side in ("key", "value"):
                layout = _require_mapping(
                    item[side], side, "%s.%s" % (where, side)
                )
                _check_keys(
                    layout, ("type", "bytes"), (), "%s.%s" % (where, side)
                )
                _check_str(
                    layout["type"], "%s.type" % side,
                    "%s.%s" % (where, side),
                )
                # Keyless/valueless map layouts (notably ring buffers,
                # whose kernel key/value sizes are both zero) use 0 bytes.
                _check_int(
                    layout["bytes"],
                    "%s.bytes" % side,
                    "%s.%s" % (where, side),
                    minimum=0,
                )
            _check_int(
                item["max_entries"],
                "max_entries",
                where,
                minimum=1,
                maximum=0xFFFFFFFF,
            )
        event_abi = mapping.get("event_abi")
        if event_abi is not None:
            abi = _require_mapping(
                event_abi, "event_abi", "fixture.event_abi"
            )
            _check_keys(
                abi, ("version", "record_bytes"), ("framing",),
                "fixture.event_abi",
            )
            _check_int(
                abi["version"], "event_abi.version", "fixture.event_abi",
                minimum=1,
            )
            _check_int(
                abi["record_bytes"],
                "event_abi.record_bytes",
                "fixture.event_abi",
                minimum=1,
            )
            if abi.get("framing") is not None:
                _check_str(
                    abi["framing"], "event_abi.framing", "fixture.event_abi"
                )
        corpus = _require_mapping(mapping["corpus"], "corpus",
                                  "fixture.corpus")
        _check_keys(
            corpus, ("corpus_id", "sha256", "record_count"), (),
            "fixture.corpus",
        )
        _check_str(corpus["corpus_id"], "corpus.corpus_id", "fixture.corpus")
        _check_pattern(
            corpus["sha256"], SHA256_RE, "corpus.sha256", "fixture.corpus"
        )
        _check_int(
            corpus["record_count"],
            "corpus.record_count",
            "fixture.corpus",
            minimum=1,
        )
        oracle = _require_mapping(mapping["oracle"], "oracle",
                                  "fixture.oracle")
        _check_keys(oracle, ("name", "version"), (), "fixture.oracle")
        _check_str(oracle["name"], "oracle.name", "fixture.oracle")
        _check_str(oracle["version"], "oracle.version", "fixture.oracle")
        barriers = mapping["barriers"]
        if not isinstance(barriers, list) or not barriers:
            raise _fail(
                "MBPF305",
                "barriers must be a non-empty array",
                location="fixture",
            )
        for barrier in barriers:
            _check_enum(barrier, BARRIERS, "barrier", "fixture")
        if len(set(barriers)) != len(barriers):
            raise _fail(
                "MBPF305", "barriers must be unique", location="fixture"
            )
        return cls(
            fixture_id=fixture_id,
            data=json.loads(canonical_json(dict(mapping))),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached plain-data copy of this fixture."""
        try:
            return json.loads(canonical_json(dict(self.data)))
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed Fixture instance: %s" % (exc,),
                location="fixture",
            )


@dataclass(frozen=True)
class RunPlanCase:
    """One expected case inside a run plan."""

    case_id: str
    fixture_id: str
    targets: tuple[str, ...]
    expectation: str
    denies: str | None
    required: bool
    consumers: tuple[tuple[str, str, str], ...]
    source_sha256: str
    object_sha256: str
    corpus_sha256: str
    expected_attempts: int
    expected: Mapping[str, Any] = field(compare=False)

    @classmethod
    def from_dict(cls, value: Any, location: str) -> "RunPlanCase":
        mapping = _require_mapping(value, "run plan case", location)
        _check_keys(
            mapping,
            (
                "case_id",
                "fixture_id",
                "targets",
                "expectation",
                "required",
                "consumers",
                "source_sha256",
                "object_sha256",
                "corpus_sha256",
                "expected_attempts",
            ),
            ("denies", "expected"),
            location,
        )
        case_id = _check_pattern(
            mapping["case_id"], ID_RE, "case_id", location
        )
        fixture_id = _check_pattern(
            mapping["fixture_id"], ID_RE, "fixture_id", location
        )
        targets = mapping["targets"]
        if not isinstance(targets, list) or not targets:
            raise _fail(
                "MBPF305",
                "targets must be a non-empty array of fingerprints",
                location=location,
            )
        checked_targets: list[str] = []
        for fingerprint in targets:
            checked_targets.append(
                _check_pattern(
                    fingerprint, SHA256_RE, "target fingerprint", location
                )
            )
        if len(set(checked_targets)) != len(checked_targets):
            raise _fail(
                "MBPF305", "case targets must be unique", location=location
            )
        expectation = _check_enum(
            mapping["expectation"], EXPECTATIONS, "expectation", location
        )
        denies = mapping.get("denies")
        if expectation == "denial":
            denies = _check_pattern(denies, ID_RE, "denies", location)
            if denies == case_id:
                raise _fail(
                    "MBPF305",
                    "a denial case cannot deny itself",
                    location=location,
                )
        elif denies is not None:
            raise _fail(
                "MBPF305",
                "denies is allowed only on denial cases",
                location=location,
            )
        required = mapping["required"]
        if not isinstance(required, bool):
            raise _fail(
                "MBPF305", "required must be a boolean", location=location
            )
        consumers = mapping["consumers"]
        if not isinstance(consumers, list) or not consumers:
            raise _fail(
                "MBPF305",
                "consumers must be a non-empty array",
                location=location,
            )
        checked_consumers: list[tuple[str, str, str]] = []
        for index, entry in enumerate(consumers):
            where = "%s.consumers[%d]" % (location, index)
            item = _require_mapping(entry, "consumer", where)
            _check_keys(
                item, ("name", "version", "artifact_sha256"), (), where
            )
            checked_consumers.append(
                (
                    _check_str(item["name"], "consumer name", where),
                    _check_str(item["version"], "consumer version", where),
                    _check_pattern(
                        item["artifact_sha256"],
                        SHA256_RE,
                        "consumer artifact_sha256",
                        where,
                    ),
                )
            )
        source_sha256 = _check_pattern(
            mapping["source_sha256"], SHA256_RE, "source_sha256", location
        )
        object_sha256 = _check_pattern(
            mapping["object_sha256"], SHA256_RE, "object_sha256", location
        )
        corpus_sha256 = _check_pattern(
            mapping["corpus_sha256"], SHA256_RE, "corpus_sha256", location
        )
        expected_attempts = _check_int(
            mapping["expected_attempts"],
            "expected_attempts",
            location,
            minimum=1,
        )
        expected = _check_behavior(
            mapping.get(
                "expected", {"outcome": OUTCOME_PASS, "failure_stage": None}
            ),
            "%s.expected" % location,
        )
        if expectation == "denial" and expected["outcome"] == OUTCOME_PASS:
            raise _fail(
                "MBPF305",
                "a denial case must expect a failure, not PASS",
                location="%s.expected" % location,
            )
        return cls(
            case_id=case_id,
            fixture_id=fixture_id,
            targets=tuple(checked_targets),
            expectation=expectation,
            denies=denies,
            required=required,
            consumers=tuple(checked_consumers),
            source_sha256=source_sha256,
            object_sha256=object_sha256,
            corpus_sha256=corpus_sha256,
            expected_attempts=expected_attempts,
            expected=expected,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached plain-data copy of this case."""
        try:
            data: dict[str, Any] = {
                "case_id": self.case_id,
                "fixture_id": self.fixture_id,
                "targets": list(self.targets),
                "expectation": self.expectation,
                "required": self.required,
                "consumers": [
                    {
                        "name": name,
                        "version": version,
                        "artifact_sha256": artifact,
                    }
                    for name, version, artifact in self.consumers
                ],
                "source_sha256": self.source_sha256,
                "object_sha256": self.object_sha256,
                "corpus_sha256": self.corpus_sha256,
                "expected_attempts": self.expected_attempts,
                "expected": dict(self.expected),
            }
            if self.denies is not None:
                data["denies"] = self.denies
            return data
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed RunPlanCase instance: %s" % (exc,),
                location="plan",
            )


@dataclass(frozen=True)
class RunPlan:
    """Validated immutable run plan with a verified plan hash."""

    plan_id: str
    revisions: Mapping[str, str] = field(compare=False)
    targets: tuple[TargetManifest, ...] = field(compare=False)
    cases: tuple[RunPlanCase, ...] = field(compare=False)
    plan_hash: str = ""

    @staticmethod
    def hash_of(body: Mapping[str, Any]) -> str:
        """Compute the plan hash of a plan body sans plan_hash."""
        trimmed = {key: body[key] for key in body if key != "plan_hash"}
        return digest_of(trimmed)

    @classmethod
    def from_dict(cls, value: Any) -> "RunPlan":
        mapping = _require_mapping(value, "run plan", "plan")
        _check_keys(
            mapping,
            (
                "schema_version",
                "contract_version",
                "plan_id",
                "revisions",
                "targets",
                "cases",
                "plan_hash",
            ),
            (),
            "plan",
        )
        _check_version(mapping, "plan")
        if mapping["contract_version"] != TEST_CONTRACTS_VERSION:
            raise _fail(
                "MBPF304",
                "unsupported contract_version %r; want %r"
                % (mapping["contract_version"], TEST_CONTRACTS_VERSION),
                location="plan",
            )
        plan_id = _check_pattern(
            mapping["plan_id"], ID_RE, "plan_id", "plan"
        )
        revisions = _require_mapping(
            mapping["revisions"], "revisions", "plan.revisions"
        )
        _check_keys(
            revisions,
            ("repository_commit", "package", "tool"),
            (),
            "plan.revisions",
        )
        checked_revisions = {
            "repository_commit": _check_pattern(
                revisions["repository_commit"],
                COMMIT_RE,
                "repository_commit",
                "plan.revisions",
            ),
            "package": _check_str(
                revisions["package"], "package", "plan.revisions"
            ),
            "tool": _check_str(revisions["tool"], "tool", "plan.revisions"),
        }
        raw_targets = mapping["targets"]
        if not isinstance(raw_targets, list) or not raw_targets:
            raise _fail(
                "MBPF305",
                "targets must be a non-empty array",
                location="plan",
            )
        targets = tuple(
            TargetManifest.from_dict(entry) for entry in raw_targets
        )
        fingerprints = [target.fingerprint for target in targets]
        if len(set(fingerprints)) != len(fingerprints):
            raise _fail(
                "MBPF305", "plan targets must be unique", location="plan"
            )
        raw_cases = mapping["cases"]
        if not isinstance(raw_cases, list) or not raw_cases:
            raise _fail(
                "MBPF305", "cases must be a non-empty array",
                location="plan",
            )
        cases = tuple(
            RunPlanCase.from_dict(entry, "plan.cases[%d]" % index)
            for index, entry in enumerate(raw_cases)
        )
        case_ids = [case.case_id for case in cases]
        if len(set(case_ids)) != len(case_ids):
            raise _fail(
                "MBPF305", "plan case_ids must be unique", location="plan"
            )
        by_id = {case.case_id: case for case in cases}
        for case in cases:
            for fingerprint in case.targets:
                if fingerprint not in fingerprints:
                    raise _fail(
                        "MBPF305",
                        "case %r references unknown plan target %s"
                        % (case.case_id, fingerprint),
                        location="plan",
                    )
            if case.denies is not None:
                guarded = by_id.get(case.denies)
                if guarded is None:
                    raise _fail(
                        "MBPF305",
                        "case %r denies unknown case %r"
                        % (case.case_id, case.denies),
                        location="plan",
                    )
                if guarded.expectation != "positive":
                    raise _fail(
                        "MBPF305",
                        "case %r must deny a positive case" % case.case_id,
                        location="plan",
                    )
        plan_hash = _check_pattern(
            mapping["plan_hash"], SHA256_RE, "plan_hash", "plan"
        )
        body = {
            "schema_version": SCHEMA_VERSION,
            "contract_version": TEST_CONTRACTS_VERSION,
            "plan_id": plan_id,
            "revisions": checked_revisions,
            "targets": [target.to_dict() for target in targets],
            "cases": [case.to_dict() for case in cases],
        }
        if cls.hash_of(body) != plan_hash:
            raise _fail(
                "MBPF306",
                "plan_hash mismatch: stored %s, recomputed %s"
                % (plan_hash, cls.hash_of(body)),
                location="plan",
            )
        return cls(
            plan_id=plan_id,
            revisions=checked_revisions,
            targets=targets,
            cases=cases,
            plan_hash=plan_hash,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached plain-data copy of this plan."""
        try:
            return {
                "schema_version": SCHEMA_VERSION,
                "contract_version": TEST_CONTRACTS_VERSION,
                "plan_id": self.plan_id,
                "revisions": dict(self.revisions),
                "targets": [target.to_dict() for target in self.targets],
                "cases": [case.to_dict() for case in self.cases],
                "plan_hash": self.plan_hash,
            }
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed RunPlan instance: %s" % (exc,),
                location="plan",
            )

    def cells(self) -> list[tuple[str, str]]:
        """Return every expected (case_id, target) cell in plan order."""
        ordered: list[tuple[str, str]] = []
        for case in self.cases:
            for fingerprint in case.targets:
                ordered.append((case.case_id, fingerprint))
        return ordered


def plan(
    cases: Sequence[Mapping[str, Any]],
    targets: Sequence[Mapping[str, Any]],
    revisions: Mapping[str, Any],
) -> RunPlan:
    """Build an immutable run plan and seal it with its plan hash.

    ``cases`` and ``targets`` accept plain mappings (fingerprints and
    hashes included); every entry is validated before the plan hash is
    computed, so a plan object is always self-consistent. The plan ID
    is derived deterministically from the validated content, so equal
    inputs always seal the same plan.
    """
    checked_targets = [
        TargetManifest.from_dict(entry) for entry in targets
    ]
    checked_cases = [
        RunPlanCase.from_dict(entry, "cases[%d]" % index)
        for index, entry in enumerate(cases)
    ]
    checked_revisions_raw = _require_mapping(
        revisions, "revisions", "revisions"
    )
    _check_keys(
        checked_revisions_raw,
        ("repository_commit", "package", "tool"),
        (),
        "revisions",
    )
    checked_revisions = {
        "repository_commit": _check_pattern(
            checked_revisions_raw["repository_commit"],
            COMMIT_RE,
            "repository_commit",
            "revisions",
        ),
        "package": _check_str(
            checked_revisions_raw["package"], "package", "revisions"
        ),
        "tool": _check_str(
            checked_revisions_raw["tool"], "tool", "revisions"
        ),
    }
    derived_id = "plan-" + digest_of(
        {
            "cases": [case.to_dict() for case in checked_cases],
            "targets": [target.to_dict() for target in checked_targets],
            "revisions": checked_revisions,
        }
    )[:16]
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "contract_version": TEST_CONTRACTS_VERSION,
        "plan_id": derived_id,
        "revisions": checked_revisions,
        "targets": [target.to_dict() for target in checked_targets],
        "cases": [case.to_dict() for case in checked_cases],
    }
    body["plan_hash"] = RunPlan.hash_of(body)
    # Re-parse so cross-references (unique IDs, target membership, denies
    # integrity) are enforced on exactly the sealed bytes.
    return RunPlan.from_dict(body)


@dataclass(frozen=True)
class CostRecord:
    """One measured cost: numeric value or explicit unavailability."""

    case_id: str
    data: Mapping[str, Any] = field(compare=False)

    @classmethod
    def from_dict(cls, value: Any, location: str = "cost") -> "CostRecord":
        mapping = _require_mapping(value, "cost record", location)
        _check_keys(
            mapping,
            (
                "schema_version",
                "case_id",
                "target_fingerprint",
                "metric",
                "unit",
                "value",
                "basis",
            ),
            ("unavailable_reason",),
            location,
        )
        _check_version(mapping, location)
        case_id = _check_pattern(
            mapping["case_id"], ID_RE, "case_id", location
        )
        _check_pattern(
            mapping["target_fingerprint"],
            SHA256_RE,
            "target_fingerprint",
            location,
        )
        _check_str(mapping["metric"], "metric", location)
        _check_str(mapping["unit"], "unit", location)
        cost_value = mapping["value"]
        reason = mapping.get("unavailable_reason")
        if cost_value is None:
            if not isinstance(reason, str) or not reason:
                raise _fail(
                    "MBPF305",
                    "unavailable_reason is required when value is null",
                    location=location,
                )
        else:
            if isinstance(cost_value, bool) or not isinstance(
                cost_value, (int, float)
            ):
                raise _fail(
                    "MBPF305",
                    "value must be a number or null",
                    location=location,
                )
            if reason is not None:
                raise _fail(
                    "MBPF305",
                    "unavailable_reason is allowed only when value is null",
                    location=location,
                )
        basis = _require_mapping(
            mapping["basis"], "basis", "%s.basis" % location
        )
        _check_keys(
            basis, ("object_sha256", "profile"), ("flags",),
            "%s.basis" % location,
        )
        _check_pattern(
            basis["object_sha256"],
            SHA256_RE,
            "basis.object_sha256",
            "%s.basis" % location,
        )
        _check_str(
            basis["profile"], "basis.profile", "%s.basis" % location
        )
        _check_str_list(
            basis.get("flags", []), "basis.flags", "%s.basis" % location
        )
        return cls(
            case_id=case_id,
            data=json.loads(canonical_json(dict(mapping))),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached plain-data copy of this cost record."""
        try:
            return json.loads(canonical_json(dict(self.data)))
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed CostRecord instance: %s" % (exc,),
                location="cost",
            )


@dataclass(frozen=True)
class CaseResult:
    """Validated single-attempt case result."""

    run_id: str
    case_id: str
    target_fingerprint: str
    attempt: int
    plan_hash: str
    identities: Mapping[str, Any] = field(compare=False)
    applicability: str = ""
    required: bool = False
    expected: Mapping[str, Any] = field(default_factory=dict, compare=False)
    observed: Mapping[str, Any] = field(default_factory=dict, compare=False)
    outcome: str = ""
    failure_stage: str | None = None
    evidence: tuple[Mapping[str, Any], ...] = ()
    cleanup: Mapping[str, Any] = field(
        default_factory=dict, compare=False
    )
    costs: tuple[CostRecord, ...] = ()

    @classmethod
    def from_dict(cls, value: Any) -> "CaseResult":
        mapping = _require_mapping(value, "case result", "result")
        _check_keys(
            mapping,
            (
                "schema_version",
                "run_id",
                "case_id",
                "target_fingerprint",
                "attempt",
                "plan_hash",
                "identities",
                "applicability",
                "required",
                "expected",
                "observed",
                "outcome",
                "failure_stage",
                "evidence",
                "cleanup",
            ),
            ("costs",),
            "result",
        )
        _check_version(mapping, "result")
        run_id = _check_str(mapping["run_id"], "run_id", "result")
        case_id = _check_pattern(
            mapping["case_id"], ID_RE, "case_id", "result"
        )
        target_fingerprint = _check_pattern(
            mapping["target_fingerprint"],
            SHA256_RE,
            "target_fingerprint",
            "result",
        )
        attempt = _check_int(mapping["attempt"], "attempt", "result",
                             minimum=1)
        plan_hash = _check_pattern(
            mapping["plan_hash"], SHA256_RE, "plan_hash", "result"
        )
        identities = _require_mapping(
            mapping["identities"], "identities", "result.identities"
        )
        _check_keys(
            identities,
            (
                "repository_commit",
                "package",
                "tool",
                "consumer",
                "object_sha256",
                "source_sha256",
                "workload",
            ),
            (),
            "result.identities",
        )
        checked_identities: dict[str, Any] = {
            "repository_commit": _check_pattern(
                identities["repository_commit"],
                COMMIT_RE,
                "repository_commit",
                "result.identities",
            ),
            "package": _check_str(
                identities["package"], "package", "result.identities"
            ),
            "tool": _check_str(
                identities["tool"], "tool", "result.identities"
            ),
            "object_sha256": _check_pattern(
                identities["object_sha256"],
                SHA256_RE,
                "object_sha256",
                "result.identities",
            ),
            "source_sha256": _check_pattern(
                identities["source_sha256"],
                SHA256_RE,
                "source_sha256",
                "result.identities",
            ),
        }
        consumer = _require_mapping(
            identities["consumer"], "consumer", "result.identities.consumer"
        )
        _check_keys(
            consumer,
            ("name", "version", "artifact_sha256"),
            (),
            "result.identities.consumer",
        )
        checked_identities["consumer"] = {
            "name": _check_str(
                consumer["name"], "consumer name",
                "result.identities.consumer",
            ),
            "version": _check_str(
                consumer["version"], "consumer version",
                "result.identities.consumer",
            ),
            "artifact_sha256": _check_pattern(
                consumer["artifact_sha256"],
                SHA256_RE,
                "consumer artifact_sha256",
                "result.identities.consumer",
            ),
        }
        workload = _require_mapping(
            identities["workload"], "workload", "result.identities.workload"
        )
        _check_keys(
            workload,
            ("fixture_id", "corpus_sha256"),
            (),
            "result.identities.workload",
        )
        checked_identities["workload"] = {
            "fixture_id": _check_pattern(
                workload["fixture_id"],
                ID_RE,
                "workload.fixture_id",
                "result.identities.workload",
            ),
            "corpus_sha256": _check_pattern(
                workload["corpus_sha256"],
                SHA256_RE,
                "workload.corpus_sha256",
                "result.identities.workload",
            ),
        }
        applicability = _check_enum(
            mapping["applicability"],
            AVAILABILITY,
            "applicability",
            "result",
        )
        required = mapping["required"]
        if not isinstance(required, bool):
            raise _fail(
                "MBPF305", "required must be a boolean", location="result"
            )
        expected = _check_behavior(mapping["expected"], "result.expected")
        observed = _check_behavior(mapping["observed"], "result.observed")
        outcome = _check_enum(
            mapping["outcome"], EXECUTION_OUTCOMES, "outcome", "result"
        )
        failure_stage = mapping["failure_stage"]
        if outcome == OUTCOME_PASS:
            if failure_stage is not None:
                raise _fail(
                    "MBPF305",
                    "failure_stage must be null when outcome is PASS",
                    location="result",
                )
        else:
            _check_enum(
                failure_stage, FAILURE_STAGES, "failure_stage", "result"
            )
        # The top-level verdict repeats the observed behavior; a mismatch
        # is a malformed record, rejected here rather than aggregated.
        if outcome != observed["outcome"] or (
            failure_stage != observed["failure_stage"]
        ):
            raise _fail(
                "MBPF305",
                "top-level outcome/failure_stage must equal observed",
                location="result",
            )
        evidence = mapping["evidence"]
        if not isinstance(evidence, list):
            raise _fail(
                "MBPF305", "evidence must be an array", location="result"
            )
        checked_evidence: list[dict[str, Any]] = []
        for index, entry in enumerate(evidence):
            where = "result.evidence[%d]" % index
            item = _require_mapping(entry, "evidence", where)
            _check_keys(item, ("path", "sha256", "bytes"), (), where)
            checked_evidence.append(
                {
                    "path": _check_str(item["path"], "evidence path", where),
                    "sha256": _check_pattern(
                        item["sha256"], SHA256_RE, "evidence sha256", where
                    ),
                    "bytes": _check_int(
                        item["bytes"], "evidence bytes", where, minimum=0
                    ),
                }
            )
        cleanup = _require_mapping(
            mapping["cleanup"], "cleanup", "result.cleanup"
        )
        _check_keys(cleanup, ("status", "residue"), (), "result.cleanup")
        cleanup_status = _check_enum(
            cleanup["status"], CLEANUP_STATUSES, "cleanup.status",
            "result.cleanup",
        )
        residue = cleanup["residue"]
        if not isinstance(residue, list):
            raise _fail(
                "MBPF305",
                "cleanup.residue must be an array",
                location="result.cleanup",
            )
        checked_residue = [
            _check_str(entry, "residue entry", "result.cleanup")
            for entry in residue
        ]
        if cleanup_status == "CLEAN" and checked_residue:
            raise _fail(
                "MBPF305",
                "CLEAN cleanup must carry no residue entries",
                location="result.cleanup",
            )
        if cleanup_status == "RESIDUE" and not checked_residue:
            raise _fail(
                "MBPF305",
                "RESIDUE cleanup must name its residue",
                location="result.cleanup",
            )
        if applicability == AVAIL_NOT_APPLICABLE and not checked_evidence:
            # Exclusion from the gate denominator needs proof: a bare
            # NOT_APPLICABLE claim cannot self-exclude a cell.
            raise _fail(
                "MBPF305",
                "a NOT_APPLICABLE result must carry evidence digests",
                location="result",
            )
        raw_costs = mapping.get("costs", [])
        if not isinstance(raw_costs, list):
            raise _fail(
                "MBPF305", "costs must be an array", location="result"
            )
        costs = tuple(
            CostRecord.from_dict(entry, "result.costs[%d]" % index)
            for index, entry in enumerate(raw_costs)
        )
        if outcome == OUTCOME_PASS:
            # A PASS without evidence is forged success text, and a PASS
            # that disagrees with its own expectation or leaves residue is
            # malformed: schema validation is the first rejecting layer.
            if observed != expected:
                raise _fail(
                    "MBPF305",
                    "a PASS result must observe exactly its expectation",
                    location="result",
                )
            if not checked_evidence:
                raise _fail(
                    "MBPF305",
                    "a PASS result must carry evidence digests",
                    location="result",
                )
            if cleanup_status != "CLEAN":
                raise _fail(
                    "MBPF305",
                    "a PASS result must report CLEAN cleanup",
                    location="result",
                )
        return cls(
            run_id=run_id,
            case_id=case_id,
            target_fingerprint=target_fingerprint,
            attempt=attempt,
            plan_hash=plan_hash,
            identities=checked_identities,
            applicability=applicability,
            required=required,
            expected=expected,
            observed=observed,
            outcome=outcome,
            failure_stage=failure_stage,
            evidence=tuple(checked_evidence),
            cleanup={"status": cleanup_status, "residue": checked_residue},
            costs=costs,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached plain-data copy of this result."""
        try:
            return {
                "schema_version": SCHEMA_VERSION,
                "run_id": self.run_id,
                "case_id": self.case_id,
                "target_fingerprint": self.target_fingerprint,
                "attempt": self.attempt,
                "plan_hash": self.plan_hash,
                "identities": json.loads(
                    canonical_json(dict(self.identities))
                ),
                "applicability": self.applicability,
                "required": self.required,
                "expected": dict(self.expected),
                "observed": dict(self.observed),
                "outcome": self.outcome,
                "failure_stage": self.failure_stage,
                "evidence": [dict(entry) for entry in self.evidence],
                "cleanup": {
                    "status": self.cleanup["status"],
                    "residue": list(self.cleanup["residue"]),
                },
                "costs": [cost.to_dict() for cost in self.costs],
            }
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed CaseResult instance: %s" % (exc,),
                location="result",
            )

    def digest(self) -> str:
        """Return the canonical digest binding this result to a suite."""
        try:
            return digest_of(self.to_dict())
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed CaseResult instance: %s" % (exc,),
                location="result",
            )


@dataclass(frozen=True)
class SuiteResult:
    """Terminal record binding every expected case and attempt."""

    run_id: str
    plan_hash: str
    result_digests: tuple[str, ...] = ()
    rejected_digests: tuple[str, ...] = ()
    attempts_preserved: int = 0
    ledger: Mapping[str, Any] = field(
        default_factory=dict, compare=False
    )
    decision: Mapping[str, Any] = field(
        default_factory=dict, compare=False
    )

    @classmethod
    def from_dict(cls, value: Any) -> "SuiteResult":
        mapping = _require_mapping(value, "suite result", "suite")
        _check_keys(
            mapping,
            (
                "schema_version",
                "suite_result_version",
                "run_id",
                "plan_hash",
                "result_digests",
                "rejected_digests",
                "attempts_preserved",
                "ledger",
                "decision",
            ),
            (),
            "suite",
        )
        _check_version(mapping, "suite")
        if mapping["suite_result_version"] != SUITE_RESULT_VERSION:
            raise _fail(
                "MBPF304",
                "unsupported suite_result_version %r; want %r"
                % (mapping["suite_result_version"], SUITE_RESULT_VERSION),
                location="suite",
            )
        run_id = _check_str(mapping["run_id"], "run_id", "suite")
        plan_hash = _check_pattern(
            mapping["plan_hash"], SHA256_RE, "plan_hash", "suite"
        )
        digests = mapping["result_digests"]
        if not isinstance(digests, list):
            raise _fail(
                "MBPF305", "result_digests must be an array",
                location="suite",
            )
        checked_digests = [
            _check_pattern(entry, SHA256_RE, "result digest", "suite")
            for entry in digests
        ]
        rejected = mapping["rejected_digests"]
        if not isinstance(rejected, list):
            raise _fail(
                "MBPF305", "rejected_digests must be an array",
                location="suite",
            )
        checked_rejected = [
            _check_pattern(entry, SHA256_RE, "rejected digest", "suite")
            for entry in rejected
        ]
        attempts = _check_int(
            mapping["attempts_preserved"], "attempts_preserved", "suite",
            minimum=0,
        )
        ledger = _require_mapping(mapping["ledger"], "ledger", "suite.ledger")
        _check_keys(
            ledger,
            (
                "required",
                "applicable",
                "executed",
                "passed",
                "failed",
                "blocked",
                "not_run",
            ),
            (),
            "suite.ledger",
        )
        checked_ledger: dict[str, Any] = {}
        for bucket in (
            "required",
            "applicable",
            "executed",
            "passed",
            "failed",
            "blocked",
            "not_run",
        ):
            entry = _require_mapping(
                ledger[bucket], bucket, "suite.ledger.%s" % bucket
            )
            _check_keys(
                entry, ("count", "cells"), (), "suite.ledger.%s" % bucket
            )
            count = _check_int(
                entry["count"], "count", "suite.ledger.%s" % bucket,
                minimum=0,
            )
            cells = entry["cells"]
            if not isinstance(cells, list):
                raise _fail(
                    "MBPF305",
                    "ledger cells must be an array",
                    location="suite.ledger.%s" % bucket,
                )
            for cell in cells:
                _check_str(cell, "ledger cell", "suite.ledger.%s" % bucket)
            if count != len(cells):
                raise _fail(
                    "MBPF305",
                    "ledger count must equal its cells for %s" % bucket,
                    location="suite.ledger.%s" % bucket,
                )
            checked_ledger[bucket] = {"count": count, "cells": list(cells)}
        decision = _require_mapping(
            mapping["decision"], "decision", "suite.decision"
        )
        _check_keys(decision, ("verdict", "reasons"), (), "suite.decision")
        verdict = _check_enum(
            decision["verdict"], GATE_VERDICTS, "verdict", "suite.decision"
        )
        reasons = decision["reasons"]
        if not isinstance(reasons, list):
            raise _fail(
                "MBPF305", "decision reasons must be an array",
                location="suite.decision",
            )
        checked_reasons = [
            _check_str(reason, "decision reason", "suite.decision")
            for reason in reasons
        ]
        return cls(
            run_id=run_id,
            plan_hash=plan_hash,
            result_digests=tuple(checked_digests),
            rejected_digests=tuple(checked_rejected),
            attempts_preserved=attempts,
            ledger=checked_ledger,
            decision={"verdict": verdict, "reasons": checked_reasons},
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a detached plain-data copy of this suite record."""
        try:
            return {
                "schema_version": SCHEMA_VERSION,
                "suite_result_version": SUITE_RESULT_VERSION,
                "run_id": self.run_id,
                "plan_hash": self.plan_hash,
                "result_digests": list(self.result_digests),
                "rejected_digests": list(self.rejected_digests),
                "attempts_preserved": self.attempts_preserved,
                "ledger": json.loads(canonical_json(dict(self.ledger))),
                "decision": {
                    "verdict": self.decision["verdict"],
                    "reasons": list(self.decision["reasons"]),
                },
            }
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise _fail(
                "MBPF305",
                "malformed SuiteResult instance: %s" % (exc,),
                location="suite",
            )


def export_schema_bundle(dest: str | Path) -> dict[str, Any]:
    """Export the versioned, digest-pinned tests-only schema bundle.

    Writes the five frozen schemas, a digest manifest (``bundle.json``)
    and acquisition notes (``README.txt``) into ``dest`` and returns the
    manifest. The publisher prints ``digest_of(manifest)`` and publishes
    it with the release; consumers verify with
    :func:`verify_schema_bundle` and that pinned digest before trusting
    any schema in the bundle.
    """
    dest_dir = Path(dest)
    dest_dir.mkdir(parents=True, exist_ok=True)
    entries: dict[str, Any] = {}
    for filename in SCHEMA_FILES:
        raw = (schemas_dir() / filename).read_bytes()
        (dest_dir / filename).write_bytes(raw)
        entries[filename] = {
            "version": SCHEMA_VERSION,
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    manifest = {
        "bundle": BUNDLE_NAME,
        "version": BUNDLE_VERSION,
        "contracts": [TEST_CONTRACTS_VERSION, SUITE_RESULT_VERSION],
        "schemas": entries,
    }
    (dest_dir / "bundle.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (dest_dir / "README.txt").write_text(
        "mojobpf test-contracts bundle (version %d)\n"
        "\n"
        "tests-only schema data for %s and %s.\n"
        "Verify against the release-published manifest digest before use\n"
        "(the pin is required; there is no unpinned mode):\n"
        "\n"
        "  python3 -c \"from mojobpf.validation import verify_schema_bundle;"
        " print(verify_schema_bundle('.', '<pinned-digest>'))\"\n"
        "\n"
        "Re-export from an installed mojobpf package or an unpacked source\n"
        "archive (no sibling checkout needed) and print the digest to\n"
        "publish with the release:\n"
        "\n"
        "  python3 -c \"from mojobpf.validation import digest_of,"
        " export_schema_bundle;"
        " print(digest_of(export_schema_bundle("
        "'mojobpf-test-contracts')))\"\n"
        % (BUNDLE_VERSION, TEST_CONTRACTS_VERSION, SUITE_RESULT_VERSION),
        encoding="utf-8",
    )
    return manifest


def verify_schema_bundle(
    bundle_dir: str | Path,
    expected_manifest_digest: str,
) -> dict[str, Any]:
    """Verify a schema bundle against its pinned manifest digest.

    Returns the manifest only when every schema matches its manifest
    entry and the manifest's canonical digest equals the independently
    pinned ``expected_manifest_digest`` (the SHA-256 hex of the
    canonical JSON of the trusted manifest, published with the
    release). The pin is required: a self-consistent bundle can
    re-pin its own tampered schemas, so an unpinned check proves
    nothing.
    """
    root = Path(bundle_dir)
    manifest_path = root / "bundle.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _fail(
            "MBPF307", "cannot read bundle manifest: %s" % exc,
            location=str(manifest_path),
            stage=STAGE_BUNDLE,
        )
    _require_mapping(manifest, "bundle manifest", str(manifest_path))
    if manifest.get("bundle") != BUNDLE_NAME:
        raise _fail(
            "MBPF307",
            "not a %s bundle: %r" % (BUNDLE_NAME, manifest.get("bundle")),
            location=str(manifest_path),
            stage=STAGE_BUNDLE,
        )
    if manifest.get("version") != BUNDLE_VERSION:
        raise _fail(
            "MBPF307",
            "unsupported bundle version %r" % (manifest.get("version"),),
            location=str(manifest_path),
            stage=STAGE_BUNDLE,
        )
    if manifest.get("contracts") != [
        TEST_CONTRACTS_VERSION,
        SUITE_RESULT_VERSION,
    ]:
        raise _fail(
            "MBPF307",
            "bundle contracts must be %r" % (
                [TEST_CONTRACTS_VERSION, SUITE_RESULT_VERSION],
            ),
            location=str(manifest_path),
            stage=STAGE_BUNDLE,
        )
    schemas = manifest.get("schemas")
    if not isinstance(schemas, Mapping):
        raise _fail(
            "MBPF307",
            "bundle manifest schemas must be a mapping",
            location=str(manifest_path),
            stage=STAGE_BUNDLE,
        )
    for filename in SCHEMA_FILES:
        entry = schemas.get(filename)
        if not isinstance(entry, Mapping):
            raise _fail(
                "MBPF307",
                "bundle is missing schema entry %s" % filename,
                location=str(manifest_path),
                stage=STAGE_BUNDLE,
            )
        if entry.get("version") != SCHEMA_VERSION:
            raise _fail(
                "MBPF307",
                "bundle schema %s has unsupported version %r"
                % (filename, entry.get("version")),
                location=str(manifest_path),
                stage=STAGE_BUNDLE,
            )
        try:
            raw = (root / filename).read_bytes()
        except OSError:
            raise _fail(
                "MBPF307",
                "bundle is missing schema file %s" % filename,
                location=str(root / filename),
                stage=STAGE_BUNDLE,
            )
        actual = hashlib.sha256(raw).hexdigest()
        if actual != entry.get("sha256"):
            raise _fail(
                "MBPF307",
                "bundle schema %s digest mismatch" % filename,
                location=str(root / filename),
                stage=STAGE_BUNDLE,
            )
    pinned = digest_of(manifest)
    if pinned != expected_manifest_digest:
        raise _fail(
            "MBPF307",
            "bundle manifest digest %s does not match the pinned "
            "digest %s" % (pinned, expected_manifest_digest),
            location=str(manifest_path),
            stage=STAGE_BUNDLE,
        )
    return json.loads(canonical_json(dict(manifest)))
