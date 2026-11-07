# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Versioned JSON file interface around the exact-match IR adapter.

The build driver invokes this service once per program as a plain
subprocess (file interface, never a long-lived compiler service)::

    python3 adapter_service.py --request req.json --response resp.json

The request names the input IR path, the manifest path, the target
profile ID, the output directory and the diagnostic mode. The response
names the generated adapted IR and carries structured diagnostics.
Every diagnostic dict uses the same six keys as the build driver's
``Diagnostic`` model (``code``, ``stage``, ``severity``,
``explanation``, ``location``, ``remedy``).

This service performs no transformation of its own: it validates the
request, delegates to :mod:`mojo_ir_adapter` (``validate`` then
``adapt``, imported from the sibling file in this directory), and
reports the outcome, with one in-lane tool step between the two: the
LLVM verifier (``opt -passes=verify``) runs over the input IR so
malformed modules fail here instead of deferring to llc. Its
transform semantics are therefore exactly the sibling's; this file
must never grow its own IR rewriting.

The service emits ``MBPF212`` for its own failures (malformed JSON,
unknown field, unsupported version, mode or profile, unreadable
input, unwritable output, unloadable adapter, internal transform
failure), ``MBPF106`` at ``adapter.verify`` when the LLVM verifier
rejects the input, ``MBPF103`` when no usable verifier resolves, and
propagates the audit's exact ``MBPF3xx`` diagnostics unchanged for
rejected input IR.

Stages: ``adapter.request`` (request validation),
``adapter.transform`` (shape validation, adaptation, output writing),
``adapter.verify`` (in-lane LLVM verification), and
``toolchain.discovery`` (verifier resolution).

Supported vocabulary is deliberately narrow and every unknown value
fails loudly: request ``schema_version`` must be 1, ``profile_id``
must name a target profile admitted by the sibling admission
descriptor (today the base, CO-RE, hash, reservation, subprogram,
and uprobe capability profiles), and ``diagnostic_mode`` must be
``text`` (plain explanations; the field is reserved for future
modes). Profile admission reads ``admission.json`` beside this
service fresh on every request -- the same bytes the host lookup
reads from the packaged lane -- with no import-environment
supplement: without the descriptor, no profile is admitted, in
every lane. Every descriptor entry is validated with the same
strictness as the host lookup (same required field set, same
per-field shapes, same key agreement): a malformed entry fails
the request closed instead of admitting by name alone.

Exit codes: 0 when the response reports success, 1 when a response
reporting failure was written, 2 when no response could be written
(unusable invocation or unwritable response path). Callers must treat
a missing or malformed response as a failure even when the exit code
is 0.

The service reads and writes regular files only. Its only
subprocesses are the verifier resolution (``llvm-config --bindir``,
skipped when ``MOJOBPF_OPT`` names the verifier directly) and the
verifier itself (``opt -passes=verify -disable-output`` over the
input IR, never over edited output); it needs no privilege and never
loads BPF programs.

Standard library only. The service never imports the host
package: admission comes solely from the sibling descriptor.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib

ADAPTER_SCHEMA_VERSION = 1

# Standalone admission descriptor (``admission.json``), generated
# from the authoritative capability registry at build time and
# shipped byte-identically beside this service in both lanes.
# Admission requires these bytes: every load below fails closed
# (a missing, malformed, or versioned descriptor admits
# nothing), and no import-environment lookup supplements it, so
# host lookup and this subprocess always agree.
ADMISSION_FILENAME = "admission.json"
ADMISSION_SCHEMA_VERSION = 1


def _admission_path():
    """Return the sibling admission descriptor path."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, ADMISSION_FILENAME)


_PROFILE_FIELD_NAMES = (
    "profile_id",
    "byte_order",
    "cpu",
    "allowed_pairs",
    "allowed_map_types",
    "allowed_key_types",
    "allowed_value_types",
    "allowed_max_entries",
    "allowed_ringbuf_sizes",
    "helper_ids",
    "btf_scope",
    "entry_return",
    "entry_parameters",
    "core_supported",
    "subprog_supported",
)


def _validate_admission_entry(profile_id, entry):
    """Validate one descriptor entry with host-lookup strictness.

    Duplicates the host ``mojobpf.capabilities`` entry
    validation exactly: the same required field set, the same
    per-field shapes, and the same key agreement. This service
    is stdlib-only and never imports the host package, so the
    rules are mirrored here instead of shared by import; the
    shared malformed-descriptor test proves both sides agree
    on malformed inputs. Raises ``ValueError`` on any drift.
    """
    if not isinstance(profile_id, str) or not profile_id:
        raise ValueError(
            "admission descriptor carries a bad profile id: %r"
            % (profile_id,)
        )
    if not isinstance(entry, dict) or set(entry) != set(
        _PROFILE_FIELD_NAMES
    ):
        raise ValueError(
            "admission descriptor entry %r is misshapen" % (profile_id,)
        )

    def _text(name):
        value = entry[name]
        if not isinstance(value, str) or not value:
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "non-empty string" % (profile_id, name)
            )
        return value

    def _strs(name):
        value = entry[name]
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "list of non-empty strings" % (profile_id, name)
            )
        return tuple(value)

    def _ints(name):
        value = entry[name]
        if not isinstance(value, list) or not all(
            _is_int(item) for item in value
        ):
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "list of integers" % (profile_id, name)
            )
        return tuple(value)

    def _flag(name):
        value = entry[name]
        if type(value) is not bool:
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "boolean" % (profile_id, name)
            )
        return value

    pairs = entry["allowed_pairs"]
    if not isinstance(pairs, list) or not all(
        isinstance(pair, list)
        and len(pair) == 2
        and all(isinstance(part, str) and part for part in pair)
        for pair in pairs
    ):
        raise ValueError(
            "admission descriptor entry %r field 'allowed_pairs' "
            "must be a list of string pairs" % (profile_id,)
        )
    _text("profile_id")
    _text("byte_order")
    _text("cpu")
    _strs("allowed_map_types")
    _strs("allowed_key_types")
    _strs("allowed_value_types")
    _ints("allowed_max_entries")
    _ints("allowed_ringbuf_sizes")
    _ints("helper_ids")
    _text("btf_scope")
    _text("entry_return")
    _strs("entry_parameters")
    _flag("core_supported")
    _flag("subprog_supported")
    if entry["profile_id"] != profile_id:
        raise ValueError(
            "admission descriptor entry %r disagrees with its key"
            % (profile_id,)
        )


def _load_admission_ids():
    """Return the admitted profile IDs from the sibling descriptor.

    Reads the descriptor fresh on every call and validates
    every entry with host-lookup strictness. Raises
    ``OSError`` when the descriptor cannot be read and
    ``ValueError`` when it is malformed: without these bytes,
    no profile is admitted.
    """
    path = _admission_path()
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "admission descriptor is not valid JSON: %s" % exc
        ) from None
    if not isinstance(document, dict):
        raise ValueError("admission descriptor must be a JSON object")
    version = document.get("schema_version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != ADMISSION_SCHEMA_VERSION
    ):
        raise ValueError(
            "admission descriptor schema_version %r is not %d"
            % (version, ADMISSION_SCHEMA_VERSION)
        )
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("admission descriptor names no profiles")
    for profile_id, entry in profiles.items():
        _validate_admission_entry(profile_id, entry)
    return tuple(profiles)


def __getattr__(name):
    # Lazy admission view: reading ``SUPPORTED_PROFILE_IDS``
    # loads the sibling descriptor fresh (failing closed when it
    # is missing or malformed), so importing this service never
    # performs admission I/O of its own -- ``--help`` and other
    # non-request uses run without the descriptor, while every
    # request resolves admission from current bytes.
    if name == "SUPPORTED_PROFILE_IDS":
        return _load_admission_ids()
    raise AttributeError(
        "module %r has no attribute %r" % (__name__, name)
    )

SUPPORTED_DIAGNOSTIC_MODES = ("text",)

STAGE_ADAPTER_REQUEST = "adapter.request"
STAGE_ADAPTER_TRANSFORM = "adapter.transform"
STAGE_ADAPTER_VERIFY = "adapter.verify"
STAGE_TOOLCHAIN_DISCOVERY = "toolchain.discovery"

CODE_RE = re.compile(r"^MBPF[1-7][0-9]{2}$")

ADAPTED_FILENAME = "adapted.ll"

# Bound a rejection message carried into a diagnostic explanation so a
# hostile multi-megabyte IR line cannot bloat the response document.
EXPLANATION_LIMIT = 2000

_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "input_ir",
        "manifest_path",
        "profile_id",
        "output_dir",
        "diagnostic_mode",
    }
)


def _diagnostic(
    code,
    stage,
    explanation,
    location=None,
    remedy=None,
    severity="error",
):
    assert CODE_RE.match(code), "invalid diagnostic code: %r" % (code,)
    return {
        "code": code,
        "stage": stage,
        "severity": severity,
        "explanation": explanation,
        "location": location,
        "remedy": remedy,
    }


def _request_failure(explanation, location=None, remedy=None):
    return _diagnostic(
        "MBPF212",
        STAGE_ADAPTER_REQUEST,
        explanation,
        location=location,
        remedy=remedy,
    )


LOWER_ENV = "MOJOBPF_LOWER"
LOWER_TIMEOUT_S = 300

# Producer model the parsed lowering is qualified against (mirrors
# the lowering's frozen ModelID; a new producer needs its own
# compatibility check, never a silent substitution here).
LOWER_MODEL_ID = "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1"

# Bound the manifest re-read for spec authoring; the driver seals
# the manifest separately, this is only the service's input cap.
MANIFEST_LIMIT = 1024 * 1024


class RouteRefused(ValueError):
    """Route dispatch refused; carries its stable MBPF219 code."""

    def __init__(self, explanation, remedy):
        super().__init__(explanation)
        self.code = "MBPF219"
        self.explanation = explanation
        self.remedy = remedy

    def to_diagnostic(self, location=None):
        return _diagnostic(
            self.code,
            STAGE_ADAPTER_TRANSFORM,
            self.explanation,
            location=location,
            remedy=self.remedy,
        )


def select_route(mode, audit_module, *, map_kind="array",
                 core_profile=False):
    """Dispatch a validated mode to its transform route.

    Qualified modes go ``parsed``; admitted-but-unqualified modes
    stay ``lane-a``; anything outside the audit's admitted modes
    refuses with MBPF219 (a new mode earns its route explicitly,
    it never inherits one). All four single-map kinds flip
    per kind commit (array, then hash, then LRU, then percpu);
    every other kind (mixed) stays ``lane-a``; the caller
    reports the kind from the audit scan. Mixed kinds stay
    routed (never refused): Lane-A owns the two-kinds
    diagnostic. Non-core modes on core profiles stay
    ``lane-a``: only the core mode's relocation proof is
    parsed, so other core-profile requests keep their Lane-A
    checks instead of meeting a parsed route refusal.
    Combined flips per kind: array and percpu route ``parsed``
    (each has combined fixtures with full equivalence); hash,
    lru, and mixed stay ``lane-a`` until their own combined
    equivalence exists. Tracepoint flips array-only (the
    tracepoint proof has no kind-tag rules). Event flips
    array-only (the event proof has no kind-tag rules).
    Uprobe flips array-only (the uprobe proof has no
    kind-tag rules). Reserve flips array-only (the
    reserve proof has no kind-tag rules). Core flips
    array-only (the relocation proof has no kind-tag
    rules); the core-profile pin below exempts the core
    mode itself, which is proven parsed.
    """
    if mode not in audit_module.ADMITTED_MODES:
        raise RouteRefused(
            "unknown program mode %r has no route" % (mode,),
            "admit the mode in the audit with its route before building",
        )
    if map_kind not in ("array", "hash", "lru", "percpu"):
        return "lane-a"
    if mode == "combined" and map_kind not in ("array", "percpu"):
        return "lane-a"
    if mode == "tracepoint" and map_kind != "array":
        return "lane-a"
    if mode == "event" and map_kind != "array":
        return "lane-a"
    if mode == "uprobe" and map_kind != "array":
        return "lane-a"
    if mode == "reserve" and map_kind != "array":
        return "lane-a"
    if mode == "core" and map_kind != "array":
        return "lane-a"
    if core_profile and mode != "core":
        return "lane-a"
    if audit_module.parsed_qualified(mode):
        return "parsed"
    return "lane-a"


# Manifest map_type spellings to canonical kinds. All four
# single-map kinds flip (array, then hash, then LRU, then
# percpu, one kind per commit); the rest refuse so each kind
# flip stays explicit.
MAP_TYPE_KINDS = {
    "array": "array",
    "hash": "hash",
    "lru_hash": "lru",
    "percpu_array": "percpu",
    "ringbuf": "ringbuf",
}
FLIPPED_MAP_TYPES = {"array": 2, "hash": 1, "lru": 9, "percpu": 6}


def _author_map_contract(maps, entries, map_kind):
    """Author the spec map block; return (block, None) or (None, refusal).

    The declared contract (symbol, kind, key/value types) comes
    from the manifest; the entry count comes from the audited IR
    scan (the emitted map must serve the dense keys the lowering
    verified). The declared kind must be flipped and must agree
    with the scanned kind in both directions: a mismatch is a
    contract refusal, never a silent cross-kind lowering.
    Manifest/emitted reconciliation stays with the driver's
    verify gate.
    """
    if (
        not isinstance(entries, int)
        or isinstance(entries, bool)
        or entries < 1
    ):
        return (
            None,
            RouteRefused(
                "map shape needs its audited entry count, got %r"
                % (entries,),
                "route map shapes through the audited scan",
            ),
        )
    if not isinstance(maps, list) or len(maps) != 1:
        return (
            None,
            RouteRefused(
                "map shape needs exactly one manifest map, got %d"
                % (len(maps) if isinstance(maps, list) else -1),
                "declare the single map in the manifest",
            ),
        )
    declared = maps[0]
    if not isinstance(declared, dict):
        return (
            None,
            RouteRefused(
                "manifest map is not a [[maps]] table",
                "declare the single map in the manifest",
            ),
        )
    claimed_kind = MAP_TYPE_KINDS.get(declared.get("map_type"))
    if claimed_kind not in FLIPPED_MAP_TYPES:
        return (
            None,
            RouteRefused(
                "parsed route lowers array, hash, lru, and percpu maps only, got %r"
                % (declared.get("map_type"),),
                "migrate the map kind before building it parsed",
            ),
        )
    if claimed_kind != map_kind:
        return (
            None,
            RouteRefused(
                "manifest declares %s but the IR scans as %s"
                % (claimed_kind, map_kind),
                "declare the scanned kind in the manifest",
            ),
        )
    if (
        declared.get("name") != "mojobpf_map0"
        or declared.get("key_type") != "u32"
        or declared.get("value_type") != "u64"
    ):
        return (
            None,
            RouteRefused(
                "manifest map is not the admitted mojobpf_map0 u32->u64 map",
                "declare name mojobpf_map0 with key_type u32, value_type u64",
            ),
        )
    claimed = declared.get("max_entries")
    if (
        not isinstance(claimed, int)
        or isinstance(claimed, bool)
        or claimed < 1
    ):
        return (
            None,
            RouteRefused(
                "manifest map names no positive max_entries",
                "declare max_entries in the manifest",
            ),
        )
    return (
        {
            "symbol": "mojobpf_map0",
            "type": FLIPPED_MAP_TYPES[claimed_kind],
            "key_bits": 32,
            "value_bits": 64,
            "max_entries": entries,
            "flags": 0,
        },
        None,
    )


def _author_core_map_contract(maps, entries, map_kind):
    """Author the core spec map block; return (block, None) or (None, refusal).

    The relocation probe reads exactly one 4096-byte array
    slot, so the audited entry count is pinned to one and the
    declared value type to ``bytes4096``; anything else is a
    contract refusal, never a silent cross-shape lowering.
    """
    if (
        not isinstance(entries, int)
        or isinstance(entries, bool)
        or entries != 1
    ):
        return (
            None,
            RouteRefused(
                "core shape needs its single audited entry, got %r"
                % (entries,),
                "route core shapes through the audited scan",
            ),
        )
    if not isinstance(maps, list) or len(maps) != 1:
        return (
            None,
            RouteRefused(
                "core shape needs exactly one manifest map, got %d"
                % (len(maps) if isinstance(maps, list) else -1),
                "declare the single map in the manifest",
            ),
        )
    declared = maps[0]
    if not isinstance(declared, dict):
        return (
            None,
            RouteRefused(
                "manifest map is not a [[maps]] table",
                "declare the single map in the manifest",
            ),
        )
    claimed_kind = MAP_TYPE_KINDS.get(declared.get("map_type"))
    if claimed_kind != "array" or claimed_kind != map_kind:
        return (
            None,
            RouteRefused(
                "core shape needs the scanned array map, got %r/%r"
                % (declared.get("map_type"), map_kind),
                "declare the scanned array map in the manifest",
            ),
        )
    if (
        declared.get("name") != "mojobpf_map0"
        or declared.get("key_type") != "u32"
        or declared.get("value_type") != "bytes4096"
    ):
        return (
            None,
            RouteRefused(
                "manifest map is not the admitted mojobpf_map0 u32->bytes4096 map",
                "declare name mojobpf_map0 with key_type u32, value_type bytes4096",
            ),
        )
    claimed = declared.get("max_entries")
    if (
        not isinstance(claimed, int)
        or isinstance(claimed, bool)
        or claimed < 1
    ):
        return (
            None,
            RouteRefused(
                "manifest map names no positive max_entries",
                "declare max_entries in the manifest",
            ),
        )
    return (
        {
            "symbol": "mojobpf_map0",
            "type": FLIPPED_MAP_TYPES["array"],
            "key_bits": 32,
            "value_bits": 32768,
            "max_entries": entries,
            "flags": 0,
        },
        None,
    )


def _author_ringbuf_pair_contract(maps, entries, map_kind, ring_size, shape):
    """Author the ringbuf-pair spec map block; return (block, None) or (None, refusal).

    The event and reservation shapes share the pair: the
    manifest must declare exactly the array state map plus
    the ring-buffer companion (in either order). The state map
    takes the single-map arm (declared contract from the
    manifest, entry count from the audited scan); the companion
    must name the scanned size tag exactly (the lowering stamps
    the tag into the emitted companion, so a manifest/tag
    disagreement refuses here instead of at the object gate).
    The spec map block stays the single array map: the
    companion rides the manifest/scan agreement here plus the
    object/manifest reconciliation in the driver's verify gate.
    Size membership stays with the lowering (tag admission)
    and the driver (object attributes); this arm proves
    agreement, not membership.
    """
    if not isinstance(maps, list) or len(maps) != 2:
        return (
            None,
            RouteRefused(
                "%s shape needs the array state map plus the "
                "ring-buffer companion, got %d manifest maps"
                % (shape, len(maps) if isinstance(maps, list) else -1),
                "declare mojobpf_map0 and mojobpf_map1 in the manifest",
            ),
        )
    by_name = {}
    for declared in maps:
        if isinstance(declared, dict) and isinstance(
            declared.get("name"), str
        ):
            by_name[declared["name"]] = declared
    state = by_name.get("mojobpf_map0")
    ring = by_name.get("mojobpf_map1")
    if state is None or ring is None:
        return (
            None,
            RouteRefused(
                "%s shape needs mojobpf_map0 plus mojobpf_map1, "
                "got %s" % (shape, sorted(by_name)),
                "declare mojobpf_map0 and mojobpf_map1 in the manifest",
            ),
        )
    block, refusal = _author_map_contract([state], entries, map_kind)
    if refusal is not None:
        return None, refusal
    if (
        not isinstance(ring_size, int)
        or isinstance(ring_size, bool)
    ):
        return (
            None,
            RouteRefused(
                "%s shape needs its audited ring-buffer size, "
                "got %r" % (shape, ring_size,),
                "route %s shapes through the audited scan" % (shape,),
            ),
        )
    if ring.get("map_type") != "ringbuf":
        return (
            None,
            RouteRefused(
                "event companion mojobpf_map1 must be a ringbuf map, "
                "got %r" % (ring.get("map_type"),),
                "declare mojobpf_map1 as a ringbuf map",
            ),
        )
    claimed = ring.get("max_entries")
    if claimed != ring_size:
        return (
            None,
            RouteRefused(
                "manifest ring-buffer size %r disagrees with the "
                "audited size tag %r"
                % (claimed, ring_size),
                "declare the audited ring-buffer size in the manifest",
            ),
        )
    return block, None


def _author_spec(mode, entry, manifest_path, profile_id, entries=None,
                map_kind="array", ring_size=None):
    """Author the lowering spec; return (spec, None) or (None, refusal).

    The entry (and, for map shapes, the entry count) comes from
    the audited IR (the caller's scan), the program contract from
    the request manifest: exactly one program must declare the
    entry; map, combined, tracepoint, and uprobe shapes
    additionally need the single declared map, the event and
    reserve shapes the state map plus
    the ring-buffer companion (with the scanned size tag),
    the core shape the single 4096-byte array map under the
    core capability profile, while other shapes carry none.
    Anything else refuses with MBPF219.
    """
    if mode not in ("classifier", "subprog", "map", "combined", "tracepoint",
                    "event", "uprobe", "reserve", "core"):
        return (
            None,
            RouteRefused(
                "parsed route has no lowering for mode %r yet" % (mode,),
                "migrate the mode before qualifying it",
            ),
        )
    try:
        with open(manifest_path, "rb") as handle:
            raw = handle.read(MANIFEST_LIMIT + 1)
    except OSError as exc:
        return (
            None,
            RouteRefused(
                "cannot read manifest for lowering spec: %s" % exc,
                "point manifest_path at the project manifest",
            ),
        )
    if len(raw) > MANIFEST_LIMIT:
        return (
            None,
            RouteRefused(
                "manifest exceeds %d bytes" % MANIFEST_LIMIT,
                "point manifest_path at the project manifest",
            ),
        )
    try:
        manifest = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return (
            None,
            RouteRefused(
                "manifest is not valid TOML: %s" % exc,
                "point manifest_path at the project manifest",
            ),
        )
    if not isinstance(manifest, dict):
        return (
            None,
            RouteRefused(
                "manifest is not a TOML table",
                "point manifest_path at the project manifest",
            ),
        )
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        return (
            None,
            RouteRefused(
                "manifest has no [artifact] table",
                "declare the artifact licenses in the manifest",
            ),
        )
    kernel_license = artifact.get("kernel_license")
    if not isinstance(kernel_license, str) or not kernel_license:
        return (
            None,
            RouteRefused(
                "manifest artifact names no kernel_license",
                "declare kernel_license in the manifest",
            ),
        )
    programs = manifest.get("programs")
    if not isinstance(programs, list):
        return (
            None,
            RouteRefused(
                "manifest has no [[programs]] list",
                "declare the entry program in the manifest",
            ),
        )
    matches = [
        program for program in programs
        if isinstance(program, dict) and program.get("entry") == entry
    ]
    if len(matches) != 1:
        return (
            None,
            RouteRefused(
                "manifest declares %d programs with entry %r; want 1"
                % (len(matches), entry),
                "declare the entry program exactly once",
            ),
        )
    program = matches[0]
    contract = {}
    for key in ("program_type", "section"):
        value = program.get(key)
        if not isinstance(value, str) or not value:
            return (
                None,
                RouteRefused(
                    "manifest program %r names no %s" % (entry, key),
                    "declare %s for the entry program" % key,
                ),
            )
        contract[key] = value
    maps = manifest.get("maps", [])
    if mode in ("event", "reserve"):
        contract_map, refusal = _author_ringbuf_pair_contract(
            maps, entries, map_kind, ring_size, mode,
        )
        if refusal is not None:
            return None, refusal
    elif mode in ("map", "combined", "tracepoint", "uprobe"):
        contract_map, refusal = _author_map_contract(
            maps, entries, map_kind,
        )
        if refusal is not None:
            return None, refusal
    elif mode == "core":
        if profile_id != "linux-bpfel-v3-core":
            return (
                None,
                RouteRefused(
                    "core mode needs the core capability profile, got %r"
                    % (profile_id,),
                    "build core programs under linux-bpfel-v3-core",
                ),
            )
        contract_map, refusal = _author_core_map_contract(
            maps, entries, map_kind,
        )
        if refusal is not None:
            return None, refusal
    else:
        if maps:
            return (
                None,
                RouteRefused(
                    "manifest declares maps but the classifier shape "
                    "carries none",
                    "migrate the map shape before building it parsed",
                ),
            )
        contract_map = None
    return (
        {
            "schema_version": 1,
            "model_id": LOWER_MODEL_ID,
            "profile_id": profile_id,
            "entry": entry,
            "program_type": contract["program_type"],
            "section": contract["section"],
            "kernel_license": kernel_license,
            "map": contract_map,
        },
        None,
    )


def _resolve_lower():
    """Resolve the parsed-lowering binary; return (path, None) or (None, refusal)."""
    override = os.environ.get(LOWER_ENV)
    if override:
        if _is_executable_file(override):
            return (override, None)
        return (
            None,
            RouteRefused(
                "%s names an unusable lowering binary: %r"
                % (LOWER_ENV, override),
                "point %s at the built mojobpf-lower" % LOWER_ENV,
            ),
        )
    candidate = shutil.which("mojobpf-lower")
    if candidate is not None and _is_executable_file(candidate):
        return (candidate, None)
    return (
        None,
        RouteRefused(
            "parsed route needs mojobpf-lower: not on PATH and %s is unset"
            % LOWER_ENV,
            "build the lowering (compiler/CMakeLists.txt) and set %s" % LOWER_ENV,
        ),
    )


def _unproved_warnings(report, input_ir):
    """Validate the report's unproved section; return (warnings, None) or (None, refusal).

    Unproved obligations surface as one MBPF220 warning naming the
    count and the proof codes; they never fail the build. A
    section the service cannot account for refuses with MBPF219.
    """
    if (
        "unproved" not in report
        and "unproved_total" not in report
        and "unproved_truncated" not in report
    ):
        return ([], None)
    unproved = report.get("unproved")
    total = report.get("unproved_total")
    truncated = report.get("unproved_truncated")
    malformed = (
        not isinstance(unproved, list)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or not isinstance(truncated, bool)
    )
    if not malformed:
        for entry in unproved:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("code"), str)
                or not isinstance(entry.get("explanation"), str)
                or not isinstance(entry.get("location"), str)
            ):
                malformed = True
                break
    if not malformed and (
        total < len(unproved) or bool(total) != bool(unproved)
    ):
        malformed = True
    if malformed:
        return (
            None,
            RouteRefused(
                "parsed lowering report has a malformed unproved section",
                "check the mojobpf-lower binary",
            ),
        )
    if not unproved:
        return ([], None)
    parts = [
        "%s at %s" % (entry["code"], entry["location"])
        for entry in unproved
    ]
    if total > len(unproved):
        explanation = (
            "parsed lowering left %d properties unproved, "
            "showing first %d: %s" % (total, len(unproved), "; ".join(parts))
        )
    else:
        explanation = "parsed lowering left %d %s unproved: %s" % (
            total,
            "property" if total == 1 else "properties",
            "; ".join(parts),
        )
    return (
        [
            _diagnostic(
                "MBPF220",
                STAGE_ADAPTER_TRANSFORM,
                _bounded(explanation),
                location=input_ir,
                remedy=(
                    "review each unproved property; rewrite the "
                    "flagged guard into the proved form to clear "
                    "the warning"
                ),
                severity="warning",
            )
        ],
        None,
    )


def _run_parsed_lowering(lower, spec, input_ir, output_dir):
    """Run the parsed lowering; return (adapted_path, warnings, refusal).

    The binary contract mirrors the parsed test harness: ``--mode
    lower --input <ll> --spec <json> --output <ll> --report
    <json> --permissive-proof`` with exit 0 and a ``mode ==
    "lower"`` report. Anything else refuses with MBPF219 (never
    a silent Lane-A fallback). Unproved obligations become
    warnings, never failures.
    """
    spec_path = os.path.join(output_dir, "lower-spec.json")
    output_path = os.path.join(output_dir, ADAPTED_FILENAME)
    report_path = os.path.join(output_dir, "lower-report.json")
    with open(spec_path, "w", encoding="utf-8") as handle:
        json.dump(spec, handle, sort_keys=True)
        handle.write("\n")
    try:
        proc = subprocess.run(
            [lower, "--mode", "lower", "--input", input_ir,
             "--spec", spec_path, "--output", output_path,
             "--report", report_path, "--permissive-proof"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=LOWER_TIMEOUT_S,
            env=_spawn_env(),
        )
    except subprocess.TimeoutExpired:
        return (
            None,
            [],
            RouteRefused(
                "parsed lowering timed out after %ds" % LOWER_TIMEOUT_S,
                "retry with a responsive lowering binary",
            ),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return (
            None,
            [],
            RouteRefused(
                "parsed lowering failed to run: %s" % exc,
                "check the mojobpf-lower binary",
            ),
        )
    if proc.returncode != 0:
        return (
            None,
            [],
            RouteRefused(
                "parsed lowering refused %s (exit %d): %s"
                % (spec.get("entry"), proc.returncode,
                   _bounded((proc.stderr or proc.stdout or "").strip())),
                "fix the reported lowering error; the log excerpt names it",
            ),
        )
    try:
        with open(report_path, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        return (
            None,
            [],
            RouteRefused(
                "parsed lowering emitted no report: %s" % exc,
                "check the mojobpf-lower binary",
            ),
        )
    if not isinstance(report, dict) or report.get("mode") != "lower":
        return (
            None,
            [],
            RouteRefused(
                "parsed lowering report is not a lower report",
                "check the mojobpf-lower binary",
            ),
        )
    if not os.path.isfile(output_path):
        return (
            None,
            [],
            RouteRefused(
                "parsed lowering produced no output IR",
                "check the mojobpf-lower binary",
            ),
        )
    warnings, refusal = _unproved_warnings(report, input_ir)
    if refusal is not None:
        return (None, [], refusal)
    return (output_path, warnings, None)


def _response(ok, outputs, diagnostics):
    return {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "ok": ok,
        "outputs": outputs,
        "diagnostics": diagnostics,
    }


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _load_adapter():
    """Import the sibling exact-match adapter from this directory."""
    here = os.path.dirname(os.path.abspath(__file__))
    sibling = os.path.join(here, "mojo_ir_adapter.py")
    spec = importlib.util.spec_from_file_location(
        "mojo_ir_adapter", sibling
    )
    if spec is None or spec.loader is None:
        raise OSError("cannot load sibling adapter: %s" % sibling)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bounded(text):
    if len(text) > EXPLANATION_LIMIT:
        return text[:EXPLANATION_LIMIT] + "...[truncated]"
    return text


# In-lane LLVM verification. After the audit admits the input IR and
# before exact-match editing, the service runs the LLVM verifier over
# the input file so malformed IR fails here with MBPF106 instead of
# deferring to llc. The verifier resolves like the test-owned
# llvm_tool helper: an explicit MOJOBPF_OPT path wins, otherwise
# llvm-config (MOJOBPF_LLVM_CONFIG or PATH) names the bindir holding
# opt. There is no PATH fallback: a missing or broken toolchain is
# loud (MBPF103), never silently substituted. Both environment inputs
# are unpinned tool paths, like MOJOBPF_LLVM_CONFIG before them; the
# production trust root is the driver's prior lockfile admission of
# the same LLVM family.
VERIFY_TIMEOUT_S = 120

# Spawn allowlist for the llvm-config/opt children (mirrors
# mojobpf.execution.SPAWN_ENV_ALLOW, inlined because this service
# is standalone stdlib-only): loader-injection and interpreter
# names never pass; only these names and prefixes do. No
# interpreter overlay: both children are native tools.
_SPAWN_ENV_ALLOW = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "MODULAR_HOME",
        "LANG",
        "TZ",
        "PYTHONHASHSEED",
    }
)
_SPAWN_ENV_ALLOW_PREFIXES = (
    "LC_",
    "MOJO_",
    "MODULAR_",
    "LLVM_",
    "MOJOBPF_",
)
_SPAWN_ENV_UNSET = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "BASH_ENV",
    "ENV",
)


def _spawn_env():
    """Filter the ambient down to the spawn allowlist."""
    child = {}
    for name, value in os.environ.items():
        if name in _SPAWN_ENV_UNSET:
            continue
        if name in _SPAWN_ENV_ALLOW or name.startswith(
            _SPAWN_ENV_ALLOW_PREFIXES
        ):
            child[name] = value
    return child


def _is_executable_file(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _resolve_verifier():
    """Return (opt_path, None) or (None, reason). Never raises."""
    override = os.environ.get("MOJOBPF_OPT")
    if override:
        if _is_executable_file(override):
            return (override, None)
        return (None, "MOJOBPF_OPT names an unusable verifier: %r" % (override,))
    config = os.environ.get("MOJOBPF_LLVM_CONFIG") or shutil.which(
        "llvm-config"
    )
    if not config:
        return (None, "llvm-config not found on PATH and MOJOBPF_OPT is unset")
    try:
        proc = subprocess.run(
            [config, "--bindir"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VERIFY_TIMEOUT_S,
            env=_spawn_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return (None, "llvm-config --bindir failed: %s" % exc)
    bindir = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0 or not bindir:
        return (None, "llvm-config --bindir failed (exit %d)" % proc.returncode)
    candidate = os.path.join(bindir[0], "opt")
    if _is_executable_file(candidate):
        return (candidate, None)
    return (None, "no executable opt beside llvm-config bindir %r" % (bindir[0],))


def _verify_ir(input_ir):
    """Run the LLVM verifier; return None or a failure diagnostic."""
    opt, reason = _resolve_verifier()
    if opt is None:
        return _diagnostic(
            "MBPF103",
            STAGE_TOOLCHAIN_DISCOVERY,
            "in-lane LLVM verification needs opt: %s" % _bounded(reason),
            location="tool:opt",
            remedy="install the pinned LLVM toolchain so llvm-config "
            "resolves, or point MOJOBPF_OPT at its opt",
        )
    try:
        proc = subprocess.run(
            [opt, "-passes=verify", "-disable-output", input_ir],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VERIFY_TIMEOUT_S,
            env=_spawn_env(),
        )
    except subprocess.TimeoutExpired:
        return _diagnostic(
            "MBPF103",
            STAGE_TOOLCHAIN_DISCOVERY,
            "in-lane LLVM verification timed out after %ds" % VERIFY_TIMEOUT_S,
            location="tool:opt",
            remedy="retry with a responsive toolchain; report a "
            "reproducible hang as a bug",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _diagnostic(
            "MBPF103",
            STAGE_TOOLCHAIN_DISCOVERY,
            "in-lane LLVM verification could not run opt: %s" % _bounded(str(exc)),
            location="tool:opt",
            remedy="install the pinned LLVM toolchain so llvm-config "
            "resolves, or point MOJOBPF_OPT at its opt",
        )
    if proc.returncode == 0:
        return None
    first = ""
    for line in (proc.stderr or "").splitlines():
        if line.strip():
            first = line.strip()
            break
    if not first:
        first = "exit %d with no error output" % proc.returncode
    return _diagnostic(
        "MBPF106",
        STAGE_ADAPTER_VERIFY,
        "LLVM verifier rejected the input IR: %s" % _bounded(first),
        location=input_ir,
        remedy="fix the reported IR error; the log excerpt names it",
    )


def handle_request(request_path, response_path):
    """Serve one JSON request; return the process exit code.

    A response document is written whenever the response path allows
    it, including for malformed requests. Returns 2 only when no
    response could be written.
    """
    try:
        with open(request_path, "r", encoding="utf-8") as handle:
            raw_request = handle.read()
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "cannot read adapter request: %s" % exc,
                        location=request_path,
                        remedy="check the request path and file permissions",
                    )
                ],
            ),
        )
    try:
        request = json.loads(raw_request)
    except json.JSONDecodeError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter request is not valid JSON: %s" % exc,
                        location=request_path,
                        remedy="send a JSON object with the documented "
                        "request fields",
                    )
                ],
            ),
        )
    if not isinstance(request, dict):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter request must be a JSON object",
                        location=request_path,
                        remedy="send a JSON object with the documented "
                        "request fields",
                    )
                ],
            ),
        )
    for key in request:
        if key not in _REQUEST_FIELDS:
            return _write_response(
                response_path,
                _response(
                    False,
                    {},
                    [
                        _request_failure(
                            "unknown adapter request field: %r" % (key,),
                            location="%s: %s" % (request_path, key),
                            remedy="remove the unknown field",
                        )
                    ],
                ),
            )
    missing = _REQUEST_FIELDS - set(request)
    if missing:
        name = sorted(missing)[0]
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter request lacks required field: %r" % (name,),
                        location="%s: %s" % (request_path, name),
                        remedy="provide all request fields: %s"
                        % ", ".join(sorted(_REQUEST_FIELDS)),
                    )
                ],
            ),
        )
    version = request["schema_version"]
    if not _is_int(version) or version != ADAPTER_SCHEMA_VERSION:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "unsupported adapter request schema_version %r; "
                        "this service reads version %d"
                        % (version, ADAPTER_SCHEMA_VERSION),
                        location="%s: schema_version" % request_path,
                        remedy="send schema_version %d"
                        % ADAPTER_SCHEMA_VERSION,
                    )
                ],
            ),
        )
    for key in ("input_ir", "manifest_path", "profile_id", "output_dir",
                "diagnostic_mode"):
        if not isinstance(request[key], str) or not request[key]:
            return _write_response(
                response_path,
                _response(
                    False,
                    {},
                    [
                        _request_failure(
                            "adapter request field %r must be a non-empty "
                            "string" % (key,),
                            location="%s: %s" % (request_path, key),
                            remedy="set %r to a non-empty string" % (key,),
                        )
                    ],
                ),
            )
    try:
        admitted_ids = _load_admission_ids()
    except (OSError, ValueError) as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter admission descriptor is unusable: %s"
                        % exc,
                        location=_admission_path(),
                        remedy="restore admission.json beside the "
                        "adapter service (reinstall the mojobpf "
                        "package for the packaged lane)",
                    )
                ],
            ),
        )
    if request["profile_id"] not in admitted_ids:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "unsupported target profile: %r"
                        % (request["profile_id"],),
                        location="%s: profile_id" % request_path,
                        remedy="use one of: %s"
                        % ", ".join(admitted_ids),
                    )
                ],
            ),
        )
    if request["diagnostic_mode"] not in SUPPORTED_DIAGNOSTIC_MODES:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "unsupported diagnostic_mode: %r"
                        % (request["diagnostic_mode"],),
                        location="%s: diagnostic_mode" % request_path,
                        remedy="use one of: %s"
                        % ", ".join(SUPPORTED_DIAGNOSTIC_MODES),
                    )
                ],
            ),
        )
    if not os.path.isfile(request["input_ir"]):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "input IR not found: %r" % (request["input_ir"],),
                        location="%s: input_ir" % request_path,
                        remedy="point input_ir at the frontend's LLVM IR "
                        "output",
                    )
                ],
            ),
        )
    if not os.path.isfile(request["manifest_path"]):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "manifest not found: %r"
                        % (request["manifest_path"],),
                        location="%s: manifest_path" % request_path,
                        remedy="point manifest_path at the project manifest",
                    )
                ],
            ),
        )
    try:
        os.makedirs(request["output_dir"], exist_ok=True)
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "cannot create output directory %r: %s"
                        % (request["output_dir"], exc),
                        location="%s: output_dir" % request_path,
                        remedy="use a writable output directory",
                    )
                ],
            ),
        )
    if not os.path.isdir(request["output_dir"]):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "output directory is not a directory: %r"
                        % (request["output_dir"],),
                        location="%s: output_dir" % request_path,
                        remedy="use a writable output directory",
                    )
                ],
            ),
        )
    try:
        with open(request["input_ir"], "r", encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "cannot read input IR: %s" % exc,
                        location=request["input_ir"],
                        remedy="check the input IR path and file permissions",
                    )
                ],
            ),
        )
    try:
        adapter = _load_adapter()
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _diagnostic(
                        "MBPF212",
                        STAGE_ADAPTER_TRANSFORM,
                        "cannot load the IR adapter: %s" % exc,
                        location="mojo_ir_adapter.py",
                        remedy="restore the adapter next to this service",
                    )
                ],
            ),
        )
    try:
        # One scan feeds mode, kind gate, and spec authoring
        # (validate is scan().mode; the error contract is
        # unchanged).
        program = adapter.audit.scan(text)
        mode = program.mode
        kinds = [
            name
            for flag, name in (
                (program.percpu, "percpu"),
                (program.hashkind, "hash"),
                (program.lrukind, "lru"),
            )
            if flag
        ]
        map_kind = kinds[0] if len(kinds) == 1 else (
            "array" if not kinds else "mixed"
        )
        route = select_route(
            mode, adapter.audit, map_kind=map_kind,
            core_profile=(
                request["profile_id"] == "linux-bpfel-v3-core"
            ),
        )
        verify_failed = _verify_ir(request["input_ir"])
        if verify_failed is not None:
            return _write_response(
                response_path,
                _response(False, {}, [verify_failed]),
            )
        if route == "parsed":
            spec, refusal = _author_spec(
                mode, program.entry, request["manifest_path"],
                request["profile_id"], entries=program.entries,
                map_kind=map_kind,
                ring_size=getattr(program, "ring_size", None),
            )
            if refusal is not None:
                return _write_response(
                    response_path,
                    _response(
                        False, {},
                        [refusal.to_diagnostic(
                            location=request["input_ir"])],
                    ),
                )
            lower, refusal = _resolve_lower()
            if refusal is not None:
                return _write_response(
                    response_path,
                    _response(
                        False, {},
                        [refusal.to_diagnostic(
                            location=request["input_ir"])],
                    ),
                )
            adapted_path, warnings, refusal = _run_parsed_lowering(
                lower, spec, request["input_ir"],
                request["output_dir"],
            )
            if refusal is not None:
                return _write_response(
                    response_path,
                    _response(
                        False, {},
                        [refusal.to_diagnostic(
                            location=request["input_ir"])],
                    ),
                )
            return _write_response(
                response_path,
                _response(
                    True,
                    {"adapted_ir": adapted_path, "route": route},
                    warnings,
                ),
            )
        adapted = adapter.adapt(text)
    except RouteRefused as exc:
        return _write_response(
            response_path,
            _response(
                False, {},
                [exc.to_diagnostic(location=request["input_ir"])],
            ),
        )
    except adapter.AdapterError as exc:
        # Structured audit rejections propagate unchanged: the exact
        # MBPF3xx code, audit stage, IR location and remedy survive
        # the service boundary verbatim.
        return _write_response(
            response_path,
            _response(False, {}, [exc.to_diagnostic()]),
        )
    except Exception as exc:
        # Anything else from the transform is an internal adapter
        # failure, never presented as unsupported user IR.
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _diagnostic(
                        "MBPF212",
                        STAGE_ADAPTER_TRANSFORM,
                        "adapter failed internally: %s"
                        % _bounded(str(exc)),
                        location=request["input_ir"],
                        remedy="report this adapter failure as a bug",
                    )
                ],
            ),
        )
    adapted_path = os.path.join(request["output_dir"], ADAPTED_FILENAME)
    try:
        with open(adapted_path, "w", encoding="utf-8") as handle:
            handle.write(adapted)
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _diagnostic(
                        "MBPF212",
                        STAGE_ADAPTER_TRANSFORM,
                        "cannot write adapted IR: %s" % exc,
                        location=adapted_path,
                        remedy="use a writable output directory",
                    )
                ],
            ),
        )
    return _write_response(
        response_path,
        _response(True, {"adapted_ir": adapted_path, "route": route}, []),
    )


def _write_response(response_path, document):
    """Write the response document; return 0/1, or 2 if unwritable."""
    try:
        with open(response_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        sys.stderr.write(
            "adapter service: cannot write response %r: %s\n"
            % (response_path, exc)
        )
        return 2
    return 0 if document["ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Serve one versioned JSON adapter request."
    )
    parser.add_argument("--request", required=True, help="request JSON file")
    parser.add_argument(
        "--response", required=True, help="response JSON file to write"
    )
    args = parser.parse_args(argv)
    return handle_request(args.request, args.response)


if __name__ == "__main__":
    sys.exit(main())
