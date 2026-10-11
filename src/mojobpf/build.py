# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unprivileged locked build orchestration for MojoBPF projects.

:func:`build_project` drives the validated three-step route for every
program in a manifest: the Mojo frontend (``mojo build --emit llvm``),
the versioned adapter service (``compiler/adapter_service.py`` fed one
JSON request per program), and the LLVM backend (``llc -mtriple=bpfel
-mcpu=v3 -filetype=obj``). Every subprocess runs from an argument
array (never a shell), with a timeout, bounded streaming capture, and
a per-build temporary work directory.

Before anything compiles, the build reconciles the manifest against
the supported export roots, entry/section pairs and map names
(``MBPF213``/``214``/``215``/``217``), validates the license
declaration pair (``MBPF701``/``703``/``704``), admits ``mojo`` and
``llc`` against the pinned lockfile (``MBPF102``/``103``/``104``)
through ``execution-contract-v1`` (resolved once, hashed,
pin-checked -- including the launcher ``exec`` target -- before
any probe runs), admits the adapter service (the packaged default
is pin-checked when the lock carries adapter pins; an explicit
service is recorded as an opt-in extension, never
default-qualified), and captures every build input through
``build-snapshot-v1``: the manifest, program sources, transitive
imports and (when needed) the whole SDK are read exactly once
each into a private capture root, the source grants are validated
over the staged bytes including imported helpers (``MBPF70x``),
and the toolchain distribution, lockfile, profile and environment
join the snapshot identity. Only the admitted binaries run,
through the admitted ``argv`` prefixes under the sanitized
environment, with every captured identity re-verified at spawn,
and only the staged paths are passed to the compiler. After the
backend step, map-mode objects pass a spill gate -- an empty
backend stack frame plus the mode's qualified add-immediate shape
(``MBPF107``) -- and every object passes inspection (structural,
unsupported-feature and declaration findings) plus the
emitted-versus-declared map reconciliation: map names and, for
map-mode objects, the entry count the program mode requires
(``MBPF216``) before anything is published.

Failure safety: objects are staged in the work directory and the
complete generation -- objects plus the ``<artifact>.evidence.json``
provenance sidecar, whose inputs are re-hashed from the snapshot's
staged bytes and verified against the setup seal -- is published
through one atomic transaction into an owned, identity-pinned
output directory (symlinks refused, concurrent publishers
serialized, swapped predecessors and directories detected, and
rollback failures recorded rather than swallowed; see
``mojobpf.evidence.publish_artifacts``). A failed build leaves the
output directory untouched and reports ``success=False`` with empty
artifacts, so a stale object can never be reported as a new
success. The private capture root is re-verified before compiling
and before publishing, and is removed on every exit path (kept
inside the work directory under ``save_temps``). On interruption
(``KeyboardInterrupt``) the running child is killed, the work
directory and capture root are removed, and the exception is
re-raised; interrupted builds are never reported at all.

The build path needs no privilege and runs no load, attach, run or
kernel operation: the only subprocesses are the frontend, the adapter
(a ``sys.executable`` file-to-file transform of the admitted service
script, with import-path variables stripped) and the backend
(including its MIR frame dump for the spill gate). ``bpftool`` is
never invoked here.

Request and result models are versioned and frozen:

* ``BuildRequest``: manifest path, output directory, adapter path,
  lockfile path (required: tools are admitted against it),
  optional ``search_paths`` (prepended to ``PATH`` for tool lookup),
  per-step ``timeout_s``, ``save_temps`` (keep the work directory and
  report it in ``work_dir``), and ``work_parent`` (parent directory
  for the per-build work directory; default is the system temp area).
* ``BuildResult``: ``success``, ``diagnostics``, ``artifacts``,
  ``provenance`` (``None`` when the failure precedes it),
  ``commands`` (one record per subprocess), and ``work_dir`` (kept
  only under ``save_temps``; ``None`` once removed).

Frontend rule: the staged SDK import path (the snapshot's private
copy of the packaged SDK, resolved through this package's own
resources, never the caller's working directory) is passed with
``-I`` when the manifest declares maps or when the program sources
(transitively, reusing snapshot import discovery) import SDK
modules. Builds with neither keep byte-identical behavior: no
``-I``, no SDK capture, unchanged flags and cache keys. Object
names are deterministic: one program builds ``<artifact>.bpf.o``;
several programs build ``<artifact>.<entry>.bpf.o`` each. The flat
output directory and the multiple-per-entry-object shape are the
documented equivalent of the original per-artifact directory and
one-manifest-one-object contract; see
``docs/artifact-format.md``.

New diagnostic codes (all ``error``):

* ``MBPF106``: a build step failed (missing SDK, tool crash, nonzero
  exit, timeout, error marker on stderr, output capture failure,
  publish failure). Frontend and backend failures name the tool's
  first error line as the location (the Mojo frontend's own
  ``file:line`` form for source errors), falling back to the
  expected output path when stderr carries no error line.
* ``MBPF212``: the adapter interface contract was violated
  (malformed adapter response, contradictory exit/status/
  diagnostics, unusable adapter output). Propagated adapter
  diagnostics keep their own codes (``MBPF212``/``MBPF3xx``) and
  stages (``adapter.request``/``adapter.transform``/
  ``adapter.audit``).
* ``MBPF102``/``MBPF103``/``MBPF104``: toolchain admission failed
  (pin mismatch, missing or broken tool, lockfile problem),
  reusing the toolchain codes and stages.
* ``MBPF107``: a built map-mode object leaves the qualified shape
  its spill-freedom proof covers (or its frame cannot be
  established), so the spill gate refuses to publish it.
* ``MBPF213``: a program entry is not a supported export root.
* ``MBPF214``: a map name is not a supported map declaration.
* ``MBPF215``: the manifest declares more maps than the route
  supports (a single state map, or the event pair of a state map
  plus its ring-buffer companion).
* ``MBPF216``: a built object's emitted maps or their entry
  counts disagree with the manifest's declared maps (two entries
  in one map are still one map; only the count is reconciled),
  or the object's CO-RE relocation records disagree with the
  manifest's CO-RE flag (requested relocations must be present
  and present relocations must be requested). For the event pair,
  the emitted array kind/count and the emitted ring-buffer size
  must each match the manifest. The core family additionally
  reconciles the emitted map value size against the declared
  value type and the object's BTF value size.
* ``MBPF217``: a program entry disagrees with its declared
  section/program-type pair (each supported root pins its pair).

New stages: ``build.setup``, ``build.inputs``, ``build.frontend``,
``build.adapter``, ``build.backend``, ``build.publish``. Input
capture failures (unresolved or unsupported imports, unreadable
inputs, manifest drift) report ``MBPF106`` at ``build.inputs``
before any tool runs. A failed adapter audit is followed by one
extra frontend re-emit with line tables
(``-g1``), recorded under ``build.diagnose``, whose only purpose
is mapping the audit's IR line to the offending source
``file:line`` plus its source excerpt; findings without a
mappable line fall back to the entry definition line, while
``MBPF301`` (an adapter-internal failure, never a program
finding) keeps its form. The reported path is always this
build's own source (the frontend replays cached line tables for
byte-identical sources, so a stale debuginfo path is remapped
only after its content verifies). The re-emit runs exclusively
on the failure path, never touches valid builds, and leaves the
original diagnostic untouched whenever the mapping cannot be
verified (re-emit failure, unaligned IR, missing debug location,
or an unreadable source line).

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, replace as _dataclass_replace

from . import __version__ as TOOL_VERSION
from . import native_adapter as native_module
from .capabilities import (
    SUPPORTED_PROFILES,
    ProfileError,
    lookup_profile,
)
from .diagnostics import (
    Diagnostic,
    SEVERITY_ERROR,
)
from .evidence import (
    EvidenceError,
    SealedInputs,
    dumps_evidence,
    evidence_from_build,
    publish_artifacts,
)
from .execution import (
    REASON_HASH_MISMATCH,
    REASON_MODULE_MISMATCH,
    REASON_NOT_FOUND,
    REASON_SPAWN_REFUSED,
    STATUS_FAILED,
    STATUS_OK,
    STATUS_SPAWN_FAILED,
    STATUS_TIMEOUT,
    AdmittedExecution,
    AdmissionError,
    CommandRecord,
    ModuleIdentity,
    admit_script_data,
    identify_file,
    popen_admitted,
    verify_spawn,
)
from .inputs import (
    BuildSnapshot,
    InputError,
    SdkInputs,
    SnapshotTool,
    ToolchainInputs,
    build_spawn_env,
    capture_build_inputs,
    capture_pinned_environment,
    canonical_manifest_bytes,
    check_spawn_env,
    discover_imports,
    module_resolves_to_sdk,
    parse_mojo_imports,
    stdlib_payload_identities,
    stdlib_payload_paths,
)
from .inspect import (
    InspectionError,
    object_has_btf_ext,
    object_map_names,
    object_map_specs,
    object_map_value_sizes,
    object_section_names,
    validate_declaration_pair,
    verify_object,
)
from .manifest import (
    ManifestError,
    parse_manifest,
)
from .models import (
    BUILD_SCHEMA_VERSION,
    DEFAULT_TIMEOUT_S,
    BuildArtifact,
    BuildProvenance,
    BuildRequest,
    BuildResult,
    is_int,
)
from .sdk import SDK_VERSION
from .toolchain import (
    ToolInfo,
    admit_tools,
    check_toolchain_distribution,
    load_toolchain_document,
)

# Version of the JSON documents exchanged with the adapter service.
# (BUILD_SCHEMA_VERSION lives in :mod:`mojobpf.models` and is
# re-exported here; see the import above.)
# Must equal ``ADAPTER_SCHEMA_VERSION`` there; the suites check this by
# loading both files.
ADAPTER_REQUEST_VERSION = 1

STAGE_BUILD_SETUP = "build.setup"
STAGE_BUILD_FRONTEND = "build.frontend"
STAGE_BUILD_ADAPTER = "build.adapter"
STAGE_BUILD_BACKEND = "build.backend"
STAGE_BUILD_PUBLISH = "build.publish"
STAGE_BUILD_DIAGNOSE = "build.diagnose"

# Subprocess status vocabulary (``STATUS_*``) and the per-step
# :class:`CommandRecord` live in :mod:`mojobpf.execution`
# (``execution-contract-v1``); the versioned build models live in
# :mod:`mojobpf.models`. Both are re-exported here (see the imports
# above) so existing ``mojobpf.build`` importers keep working.

# Kept tail of a step's stderr carried in its command record; the full
# log goes to the work directory (kept under ``save_temps``).
LOG_EXCERPT_LIMIT = 4000

# Per-stream subprocess capture cap. Pipe readers keep the head of
# each stream up to this many characters and count the rest as
# discarded, so a runaway tool cannot exhaust memory; the kept head
# plus a truncation note is what the logs and excerpts carry.
STREAM_CAPTURE_LIMIT = 1 << 20
_STREAM_CHUNK = 65536

# Error marker matched against the FULL drained stderr stream, not
# the retained head: a tool that prints this past the capture cap
# and exits zero still fails its step.
STDERR_ERROR_MARKER = "error:"

# Bounded grace for pipe readers to observe EOF after a step is
# killed (timeout or interrupt path). The live-step drain is bounded
# by the step deadline itself; this only covers kill recovery.
_DRAIN_GRACE_S = 10.0

REQUIRED_BUILD_TOOLS = ("mojo", "llc")

# The only manifest-declared export roots and map names this route
# can emit. Builds reconcile the manifest against these sets before
# compiling and reject anything else (MBPF213/214/215); wider
# vocabularies need a reviewed route, never silent renaming. These
# literals must equal the adapter's emitted entry symbols and map
# symbols; the suites cross-check this by loading both files. The
# route supports a single state map, or the event pair (a state
# map plus its ring-buffer companion); a second map of any other
# kind fails closed (MBPF215) before compiling.
SUPPORTED_ENTRY_ROOTS = ("xdp_entry", "trace_entry", "uprobe_entry")
SUPPORTED_MAP_NAMES = ("mojobpf_map0", "mojobpf_map1")

# The section/program-type pair each supported export root pins.
# The adapter emits the entry symbol's section from the audited IR,
# so a manifest pairing a known root with any other pair fails
# closed here (MBPF217) instead of building a mislabeled artifact.
# The pairs derive from the capability registry (one section per
# program type across the descriptor); only the root names stay
# pinned here, because they are emitter symbols, not descriptor
# data. A descriptor-only pair change needs no edit here.
def _section_for_program_type(program_type: str) -> str:
    """Return the single registry section for ``program_type``.

    Fails closed when the descriptor admits zero or several
    sections for the type: this route builds exactly one section
    per program type (one export root each), so a missing or
    ambiguous descriptor entry is a registry/route mismatch,
    never a guess.
    """
    sections = {
        pair[1]
        for profile in SUPPORTED_PROFILES.values()
        for pair in profile.allowed_pairs
        if pair[0] == program_type
    }
    if len(sections) != 1:
        raise ValueError(
            "capability registry admits %d sections for program "
            "type %r; this route supports exactly one"
            % (len(sections), program_type)
        )
    return next(iter(sections))


ENTRY_PROGRAM_SECTIONS = {
    "xdp_entry": ("xdp", _section_for_program_type("xdp")),
    "trace_entry": (
        "tracepoint", _section_for_program_type("tracepoint")
    ),
    "uprobe_entry": ("uprobe", _section_for_program_type("uprobe")),
}

# Transform names attested in build evidence, in pipeline order.
BUILD_TRANSFORMS = ("mojo-frontend", "ir-adapter", "llc-backend")

# Adapter implementation files sealed with the build: the service
# wrapper itself (always) plus these siblings when present next
# to it (the transform cannot run without its modules, and
# neither route admits a profile without the descriptor).
ADAPTER_SIBLING_FILES = (
    "mojo_ir_adapter.py",
    "audit.py",
    "admission.json",
)

# MIR frame-emptiness assertions for map-mode objects (same shape as
# the lowering proof): no fixed frame objects and no managed spill
# slots after prologue/epilogue lowering.
_MIR_FIXEDSTACK_EMPTY_RE = re.compile(r"^fixedStack:\s*\[\]", re.M)
_MIR_STACK_EMPTY_RE = re.compile(r"^stack:\s*\[\]", re.M)

# Lowered helper callee markers identifying map-mode adapted IR.
# Must equal the ``LOWERED_CALLEE`` values in compiler/audit.py; the
# pipeline suite cross-checks this by loading both files.
LOWERED_CALLEE_MARKERS = (
    "inttoptr (i64 1 to ptr)",
    "inttoptr (i64 2 to ptr)",
    "inttoptr (i64 3 to ptr)",
    "inttoptr (i64 14 to ptr)",
    "inttoptr (i64 5 to ptr)",
    "inttoptr (i64 8 to ptr)",
    "inttoptr (i64 130 to ptr)",
    "inttoptr (i64 131 to ptr)",
    "inttoptr (i64 132 to ptr)",
    "inttoptr (i64 133 to ptr)",
)

# Inline-assembly marker identifying per-CPU adapted IR: the kind
# tag shape in compiler/audit.py ties the loaded map address to
# its result through an empty template. Array programs carry no
# such line; per-CPU programs carry one per map-address load.
KINDTAG_MARKER = 'call i64 asm "", "=r,0"(i64 %'

# Inline-assembly marker identifying hash adapted IR: the hash
# tag shape in compiler/audit.py ties the loaded map address to
# its result through an empty template with the sideeffect
# marker. Only hash programs carry such a line (one per
# map-address load); the spelling is disjoint from the per-CPU
# marker above (no sideeffect keyword there), so neither marker
# matches the other's lines.
HASHTAG_MARKER = 'call i64 asm sideeffect "", "=r,0"(i64 %'

# Inline-assembly markers identifying event and reservation
# adapted IR: the ring-size tag shape ties the ring-buffer map
# address to its result through an empty template carrying the
# ring size (both families carry it), and the event slot
# prepares the 32-byte record buffer (only copy-output event
# programs carry it; reservation programs stamp the record
# into the kernel-provided reservation instead).
RBSIZE_MARKER = 'call i64 asm "", "=r,0,r"(i64 %'
EVENTSLOT_MARKER = '"r0 = r10\\0Ar0 += -64"'

# Address computation identifying uprobe adapted IR: the pinned
# x86-64 first-argument register word (``pt_regs`` word 14, rdi
# at byte 112) off the entry parameter. The adapter preserves
# body lines byte-identically outside the admitted callee edits,
# so the audited computation reaches classification verbatim;
# only uprobe programs carry this line, exactly once. Must equal
# the ``UPROBE_CTX_GEP_RE`` spelling in compiler/audit.py; the
# uprobe structure suite pins the adapted-IR side of that
# agreement.
UPROBE_CTXREAD_MARKER = (
    "getelementptr inbounds i64, ptr %0, i32 14"
)

# Qualified ring-buffer sizes in bytes. Must equal
# ``RINGBUF_SIZES`` in compiler/audit.py and the profile's
# allowed ring-buffer sizes; the build-command suite
# cross-checks the three spellings.
RINGBUF_SIZES = (4096, 131072)

# Map-type bounds the reconciliation accepts per manifest map type:
# 2 is the array map type, 6 the per-CPU array map type, 27 the
# ring-buffer map type, 1 the hash map type.
MAP_TYPE_IDS = {
    "array": 2,
    "percpu_array": 6,
    "ringbuf": 27,
    "hash": 1,
}
# Declared value-type vocabulary to BTF value sizes in bytes. Every
# profile-admitted keyed-map value type has an entry here; a
# vocabulary addition without one fails closed at reconciliation.
VALUE_TYPE_SIZES = {"u64": 8, "bytes4096": 4096}

# Proven 64-bit add-immediate multiset of the qualified map object,
# in sorted order: the two audited stack-slot offsets (key -4 twice,
# value -16) plus the round-trip increment. The lowering suite pins
# the same assertion on the canonical program; the spill gate below
# enforces it in the build path.
QUALIFIED_MAP_ADD_IMMS = (-16, -4, -4, 1)

# Proven 64-bit add-immediate multiset of the qualified combined
# object, in sorted order: the audited stack-slot offsets (key -4
# four times, value -16 twice) plus the entry-0 increment (+1) and
# the 15-byte packet length guard bound (+15). The combined
# structure suite pins the same assertion on the committed workload;
# the spill gate below enforces it in the build path.
QUALIFIED_COMBINED_ADD_IMMS = (-16, -16, -4, -4, -4, -4, 1, 15)

# Proven 64-bit add-immediate multisets of the qualified
# multi-pair map objects, in sorted order: N value slots (-16),
# 2N key slots (-4), and N round-trip increments (+1). The map
# structure suites pin the same assertions on the committed
# workloads; the spill gate below enforces them in the build path.
QUALIFIED_MAP2_ADD_IMMS = (-16, -16, -4, -4, -4, -4, 1, 1)
QUALIFIED_MAP3_ADD_IMMS = (
    -16, -16, -16, -4, -4, -4, -4, -4, -4, 1, 1, 1,
)
QUALIFIED_MAP4_ADD_IMMS = (
    -16, -16, -16, -16,
    -4, -4, -4, -4, -4, -4, -4, -4,
    1, 1, 1, 1,
)

# Proven 64-bit add-immediate multisets of the qualified delete
# probes, in sorted order: N key slots (-4); the status checks
# compile to moves and conditional exits with no adds.
QUALIFIED_DELETE1_ADD_IMMS = (-4,)
QUALIFIED_DELETE2_ADD_IMMS = (-4, -4)
QUALIFIED_DELETE3_ADD_IMMS = (-4, -4, -4)
QUALIFIED_DELETE4_ADD_IMMS = (-4, -4, -4, -4)

# Proven 64-bit add-immediate multiset of the qualified tracepoint
# counter, in sorted order: the filter key slot (-4), the two
# count key slots (-4 twice), the value slot (-16), and the count
# increment (+1). The TID masking compiles to a shift pair with no
# adds, and the filter comparison to a conditional exit. The
# tracepoint structure suite pins the same assertion on the
# committed counter; the spill gate below enforces it in the build
# path.
QUALIFIED_TRACEPOINT_ADD_IMMS = (-16, -4, -4, -4, 1)

# Proven 64-bit add-immediate multiset of the qualified event
# emitter, in sorted order: the two record buffer base views
# (-64 twice: the output data operand and the version field),
# the six record field views (-62, -60, -56, -52, -48, -40),
# the three pair value slots (-16 three times), the seven key
# slots (filter, sequence pair, success pair, failure pair: -4
# seven times), and the three pair increments (+1 three times).
# The TID masking compiles to a shift pair, the record word
# stores to plain stores, and the output status check to a
# conditional branch, all with no adds. The event structure
# suite pins the same assertion on the committed emitter; the
# spill gate below enforces it in the build path.
QUALIFIED_EVENT_ADD_IMMS = (
    -64, -64, -62, -60, -56, -52, -48, -40,
    -16, -16, -16,
    -4, -4, -4, -4, -4, -4, -4,
    1, 1, 1,
)

# Proven 64-bit add-immediate multiset of the qualified
# reservation emitter, in sorted order: the three pair value
# slots (-16 three times), the seven key slots (filter,
# sequence pair, released/success pair, failed pair: -4 seven
# times), and the three pair increments (+1 three times). There
# are no scratch-buffer offsets: the record lives in the
# kernel-provided reservation, not on the stack. The TID masking
# compiles to a shift pair, the reservation-relative word stores
# to plain stores, the null check and the terminus to a
# conditional branch and a void call, all with no adds. Both
# termini (submit and discard) and both ring sizes share this
# multiset; the reservation structure suite pins the same
# assertion on the committed emitters, and the spill gate below
# enforces it in the build path.
QUALIFIED_RESERVE_ADD_IMMS = (
    -16, -16, -16,
    -4, -4, -4, -4, -4, -4, -4,
    1, 1, 1,
)

# Proven 64-bit add-immediate multiset of the qualified core
# relocation probe, in sorted order: the single key-0 slot (-4).
# The lookup result check compiles to a conditional branch, the
# relocated load to a load with a loader-patched offset, the
# existence check to a loader-patched constant, and the packed
# return word to and/shift/or arithmetic, all with no adds. The
# core structure suite pins the same assertion on the committed
# probe; the spill gate below enforces it in the build path.
QUALIFIED_CORE_ADD_IMMS = (-4,)

# Proven 64-bit add-immediate multiset of the qualified uprobe
# register counter, in sorted order: the filter key slot (-4),
# the two count key slots (-4 twice), the value slot (-16), and
# the count increment (+1). The pinned context-word read
# compiles to one context-relative load with no adds, and the
# register comparison to a conditional exit. The uprobe
# structure suite pins the same assertion on the committed
# counter; the spill gate below enforces it in the build path.
QUALIFIED_UPROBE_ADD_IMMS = (-16, -4, -4, -4, 1)

# Qualified (family, entries) -> add-immediate multiset. The spill
# gate publishes only shapes listed here with kernel-observed
# behavior in both map kinds; anything else fails closed. The
# immediates are kind-blind (per-CPU kind tags emit no code), so
# array and per-CPU programs share each entry. The core entry
# covers the single-entry array-only relocation probe (one lookup,
# one relocated read, one existence check). There is no iteration
# family: the kernel offers no `map_get_next_key`-style helper and
# `for_each_map_elem` is outside the subset's scope.
QUALIFIED_SHAPE_IMMS = {
    ("map", 1): QUALIFIED_MAP_ADD_IMMS,
    ("map", 2): QUALIFIED_MAP2_ADD_IMMS,
    ("map", 3): QUALIFIED_MAP3_ADD_IMMS,
    ("map", 4): QUALIFIED_MAP4_ADD_IMMS,
    ("combined", 2): QUALIFIED_COMBINED_ADD_IMMS,
    ("delete", 1): QUALIFIED_DELETE1_ADD_IMMS,
    ("delete", 2): QUALIFIED_DELETE2_ADD_IMMS,
    ("delete", 3): QUALIFIED_DELETE3_ADD_IMMS,
    ("delete", 4): QUALIFIED_DELETE4_ADD_IMMS,
    ("tracepoint", 2): QUALIFIED_TRACEPOINT_ADD_IMMS,
    ("event", 4): QUALIFIED_EVENT_ADD_IMMS,
    ("reserve", 4): QUALIFIED_RESERVE_ADD_IMMS,
    ("core", 1): QUALIFIED_CORE_ADD_IMMS,
    ("uprobe", 2): QUALIFIED_UPROBE_ADD_IMMS,
}

_BPF_ADD64_IMM = 0x07
_BPF_LD_IMM64 = 0x18


# The versioned build models (BuildRequest, BuildArtifact,
# BuildProvenance, BuildResult, BUILD_SCHEMA_VERSION,
# DEFAULT_TIMEOUT_S) live in :mod:`mojobpf.models` and are
# re-exported here (see the import above) so existing
# ``mojobpf.build`` importers keep working.

def _fail_result(
    diagnostics: list[Diagnostic],
    commands: list[CommandRecord],
    provenance: BuildProvenance | None = None,
    work_dir: str | None = None,
) -> BuildResult:
    return BuildResult(
        schema_version=BUILD_SCHEMA_VERSION,
        success=False,
        diagnostics=tuple(diagnostics),
        artifacts=(),
        provenance=provenance,
        commands=tuple(commands),
        work_dir=work_dir,
    )


@dataclass(frozen=True)
class _SetupSeal:
    """Admitted tools and captured inputs for one build.

    Produced before the work directory exists: every input the
    pipeline will read is captured into ``snapshot``'s private
    root here, and only the admitted tool binaries run. The
    pipeline compiles from the staged paths and the evidence
    capture re-hashes the same staged bytes, rejecting any drift
    against this seal. ``tool_executions`` and
    ``adapter_execution`` are the ``execution-contract-v1``
    admissions every step spawns through; ``adapter_trust``
    records the adapter choice (see :class:`BuildProvenance`).
    ``source_files`` names the origin program paths (for
    provenance); the compiled paths are
    ``snapshot.program_paths()``. ``spawn_env`` pins the raw
    influential environment from the snapshot and
    ``spawn_unset`` pins the base names absent at capture:
    every pipeline step spawns under exactly that set, so the
    recorded environment IS the spawn environment even when
    the ambient environment moves after capture.
    """

    tool_paths: dict[str, str]
    tool_executions: dict[str, AdmittedExecution]
    adapter_execution: AdmittedExecution
    adapter_trust: str
    versions: dict[str, str]
    tool_shas: dict[str, str]
    profile_sha256: str
    manifest_sha: str
    source_files: tuple[str, ...]
    source_shas: tuple[str, ...]
    sdk_files: tuple[str, ...]
    sdk_needed: bool
    import_files: tuple[str, ...]
    adapter_files: tuple[str, ...]
    sdk_seal: tuple[tuple[str, str], ...]
    import_seal: tuple[tuple[str, str], ...]
    adapter_seal: tuple[tuple[str, str], ...]
    spawn_env: tuple[tuple[str, str], ...]
    spawn_unset: tuple[str, ...]
    snapshot: BuildSnapshot
    native_bundle: native_module.AdmittedNativeBundle | None = None
    native_inputs: tuple = ()


@dataclass(frozen=True)
class _NativeInputSeal:
    manifest_path: str
    manifest_sha256: str
    spec_bytes: bytes
    raw_path: str
    input_ir_sha256: str
    adapter_dir: str
    outputs_bytes: bytes | None = None


def materialize_native_manifest(captured_bytes: bytes, owned_path: str) -> str:
    """Write captured canonical bytes verbatim, never reopening the live TOML."""
    native_module._write_owned(owned_path, captured_bytes)
    digest = hashlib.sha256(captured_bytes).hexdigest()
    readback_native_manifest(captured_bytes, owned_path, digest)
    return digest


def readback_native_manifest(captured_bytes: bytes, owned_path: str, digest: str) -> None:
    raw = native_module._read(owned_path)
    if raw != captured_bytes or hashlib.sha256(raw).hexdigest() != digest:
        raise native_module.NativeAdapterError("captured native manifest bytes/hash changed", "MBPF106", "build.inputs")


def _readback_native_inputs(snapshot, item, bundle):
    snapshot.verify()
    bundle.verify()
    readback_native_manifest(snapshot.manifest_bytes, item.manifest_path, item.manifest_sha256)
    if native_module.derive_native_spec(snapshot.manifest_bytes, snapshot.profile_id) != item.spec_bytes:
        raise native_module.NativeAdapterError("native specification differs from captured declarations", "MBPF106", "build.inputs")
    if hashlib.sha256(native_module._read(item.raw_path, native_module.MAX_IR)).hexdigest() != item.input_ir_sha256:
        raise native_module.NativeAdapterError("native source IR changed after capture", "MBPF106", "build.inputs")
    result = native_module.read_native_outputs(item.adapter_dir, item.spec_bytes, item.raw_path)
    if item.outputs_bytes is not None and native_module.canonical_json(result) != item.outputs_bytes:
        raise native_module.NativeAdapterError("native output/report readback changed", "MBPF106", "build.inputs")
    return result


def _native_failure(exc):
    if isinstance(exc, InputError):
        return exc.diagnostic
    return Diagnostic(**exc.diagnostic())


def _step_failure(
    stage: str, explanation: str, location: str, remedy: str
) -> Diagnostic:
    return Diagnostic(
        code="MBPF106",
        stage=stage,
        severity=SEVERITY_ERROR,
        explanation=explanation,
        location=location,
        remedy=remedy,
    )


def _display_failure(
    failure: Diagnostic, snapshot: BuildSnapshot
) -> Diagnostic:
    """Rewrite staged paths in a step failure to origin paths.

    Step explanations quote the tool argv and error lines quote
    the staged paths the tools saw; users must see the project
    paths they own instead.
    """
    location = failure.location
    if location is not None:
        location = snapshot.display_text(location)
    return Diagnostic(
        code=failure.code,
        stage=failure.stage,
        severity=failure.severity,
        explanation=snapshot.display_text(failure.explanation),
        location=location,
        remedy=failure.remedy,
    )


def _display_record(
    record: CommandRecord, snapshot: BuildSnapshot
) -> CommandRecord:
    """Rewrite staged paths in a command record to origin paths.

    Step argv quotes the staged paths the tools saw and the log
    excerpt quotes staged error lines; the public result must
    name the project paths the caller owns instead, since the
    staged root is gone by the time the caller reads it.
    """
    return _dataclass_replace(
        record,
        argv=tuple(
            snapshot.display_path(token) for token in record.argv
        ),
        log_excerpt=snapshot.display_text(record.log_excerpt),
    )


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _excerpt(stderr: str) -> str:
    if len(stderr) > LOG_EXCERPT_LIMIT:
        return stderr[-LOG_EXCERPT_LIMIT:]
    return stderr


def _kill_step(proc: subprocess.Popen) -> None:
    """Kill a build step and any grandchildren it forked.

    Steps run with ``start_new_session=True``, so the child leads
    its own process group and signalling the group reaches forked
    descendants too. When the group is already gone -- the leader
    exited and was reaped between the timeout and the kill
    (``ProcessLookupError``), or the group signal is refused -- the
    leader-only ``kill()`` is the fallback. Already-dead processes
    are ignored, never an error.
    """
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass


def _pump_stream(stream, chunks: list[str], state: list,
                 marker: str | None = None) -> None:
    """Drain one text pipe into ``chunks`` up to the capture cap.

    ``state`` is ``[kept, discarded, error, saw_marker]``. The head
    of the stream is kept; anything past the cap is counted as
    discarded. When ``marker`` is given, every drained character is
    also scanned for it (case-insensitively, across chunk
    boundaries), so ``saw_marker`` reports the full stream
    independently of the retained head. Reader errors are recorded,
    never raised: callers still kill, join and classify the step
    deterministically.
    """
    lowered = marker.lower() if marker else None
    carry = ""
    try:
        while True:
            data = stream.read(_STREAM_CHUNK)
            if not data:
                return
            if lowered is not None:
                window = carry + data.lower()
                if lowered in window:
                    state[3] = True
                if len(lowered) > 1:
                    carry = window[-(len(lowered) - 1):]
            if state[0] < STREAM_CAPTURE_LIMIT:
                room = STREAM_CAPTURE_LIMIT - state[0]
                chunks.append(data[:room])
                state[0] += len(data[:room])
                if len(data) > room:
                    state[1] += len(data) - room
            else:
                state[1] += len(data)
    except Exception as exc:
        state[2] = exc
    finally:
        try:
            stream.close()
        except Exception:
            pass


def _join_pumps(threads: list[threading.Thread],
                timeout: float | None) -> None:
    """Join pipe readers under one shared deadline.

    The timeout bounds the whole join, not each thread: sequential
    joins must not multiply the budget past the step deadline.
    """
    if timeout is None:
        for thread in threads:
            thread.join()
        return
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))


def _pumps_alive(threads: list[threading.Thread]) -> bool:
    return any(thread.is_alive() for thread in threads)


def _captured_text(chunks: list[str], state: list, label: str) -> str:
    text = "".join(chunks)
    if state[1]:
        if text and not text.endswith("\n"):
            text += "\n"
        text += (
            "...[capture truncated %d %s bytes past the %d-byte "
            "head]...\n" % (state[1], label, STREAM_CAPTURE_LIMIT)
        )
    if state[2] is not None:
        if text and not text.endswith("\n"):
            text += "\n"
        text += "...[capture error: %s]...\n" % (state[2],)
    return text


def _run_step(
    argv: list[str],
    stage: str,
    timeout_s: int,
    log_path: str,
    cwd: str,
    marker: str | None = None,
    execution: AdmittedExecution | None = None,
    env_extra: dict[str, str] | None = None,
    env_unset: tuple[str, ...] | None = None,
    env_redirect: dict[str, str] | None = None,
) -> tuple[CommandRecord, str, str, bool]:
    """Run one build subprocess; never raises for step outcomes.

    Returns the command record, the captured stdout and stderr text
    (each bounded to the capture cap's head plus a truncation note),
    and whether ``marker`` was seen anywhere in the drained stderr
    stream (always False when no marker is given). One deadline
    bounds both process execution and pipe draining, under one
    cleanup handler: a child that exits while a descendant still
    holds its pipes cannot hang the step past ``timeout_s``, and an
    interruption during the drain kills the step the same way. A
    pipe reader error fails the step even when the tool exits zero
    (the only failed-with-zero-exit outcome; see
    :func:`_step_outcome`). ``KeyboardInterrupt`` kills the child
    and propagates (the caller owns cleanup). Timeouts and spawn
    failures become records.

    When ``execution`` is given, the step spawns through
    ``execution-contract-v1``: ``argv`` must start with the
    admitted prefix (compared by realpath), every captured
    identity is re-verified, and the child runs under the
    sanitized environment. ``execution=None`` preserves the
    historical direct-spawn unit seam (reached only by direct
    private callers); every product call site passes an admission.
    ``env_extra`` pins environment values over the ambient
    ones and ``env_unset`` lists the base names absent at
    capture: every product call site passes the snapshot's
    pinned compiler-material environment plus its unset list,
    so the recorded environment IS the spawn environment. The
    pinned path builds the child environment purely -- one
    ambient snapshot filtered into a new mapping passed as
    ``env=`` -- re-checks it against the pin (failing closed on
    divergence), and never touches the global ``os.environ``,
    so variables added after the snapshot (even inside
    verification) cannot reach the child and concurrent edits
    cannot be clobbered. ``env_redirect`` carries documented
    consumption overrides (such as the staged standard-library
    home) applied after the pin. Unpinned callers keep the
    historical inherit/admitted behavior.
    """
    start = time.monotonic()
    deadline = start + timeout_s
    spawn_kwargs: dict = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "errors": "replace",
        "start_new_session": True,
    }
    if execution is not None:
        prefix = execution.argv_prefix
        if len(argv) < len(prefix) or any(
            os.path.realpath(got) != os.path.realpath(want)
            for got, want in zip(argv, prefix)
        ):
            raise AdmissionError(
                "argv-mismatch",
                "step argv %r does not start with the admitted prefix %r"
                % (argv, list(prefix)),
            )
    try:
        if env_unset is not None:
            # Pinned path (every product call site): snapshot
            # the ambient environment once, verify the admission,
            # then filter the snapshot purely into the child
            # mapping. Verification-time additions land in the
            # global environment after the snapshot, so they are
            # absent from the child by construction; the
            # re-check below still proves the compiler-material
            # subset equals the pin plus redirect.
            ambient = dict(os.environ)
            if execution is not None:
                verify_spawn(execution)
                admission_unset = execution.env_unset
                admission_set = execution.env_set
            else:
                admission_unset = ()
                admission_set = ()
            pinned = env_extra or {}
            child_env = build_spawn_env(
                ambient=ambient,
                admission_unset=admission_unset,
                admission_set=admission_set,
                pinned=pinned,
                unset=env_unset,
                redirect=env_redirect,
            )
            divergence = check_spawn_env(
                child_env,
                pinned=pinned,
                unset=env_unset,
                redirect=env_redirect,
            )
            if divergence is not None:
                raise AdmissionError(
                    REASON_SPAWN_REFUSED,
                    "spawn refused: %s" % (divergence,),
                )
            proc = subprocess.Popen(
                argv, env=child_env, **spawn_kwargs
            )
        elif execution is not None:
            # Legacy admitted path without a snapshot pin (no
            # product caller): historical popen_admitted spawn.
            argv_suffix: list[str] = list(argv[len(prefix):])
            proc = popen_admitted(
                execution, argv_suffix, env_extra=env_extra,
                **spawn_kwargs
            )
        else:
            proc = subprocess.Popen(argv, **spawn_kwargs)
    except AdmissionError as exc:
        duration = time.monotonic() - start
        note = "spawn refused: %s" % (exc,)
        _write_log(log_path, argv, "", note)
        return (
            CommandRecord(
                argv=tuple(argv),
                stage=stage,
                status=STATUS_SPAWN_FAILED,
                exit_code=None,
                duration_s=duration,
                log_excerpt=_excerpt(note),
            ),
            "",
            note,
            False,
        )
    except OSError as exc:
        duration = time.monotonic() - start
        note = "spawn failed: %s" % exc
        _write_log(log_path, argv, "", note)
        return (
            CommandRecord(
                argv=tuple(argv),
                stage=stage,
                status=STATUS_SPAWN_FAILED,
                exit_code=None,
                duration_s=duration,
                log_excerpt=_excerpt(note),
            ),
            "",
            note,
            False,
        )
    out_chunks: list[str] = []
    err_chunks: list[str] = []
    out_state: list = [0, 0, None, False]
    err_state: list = [0, 0, None, False]
    pumps = [
        threading.Thread(
            target=_pump_stream,
            args=(proc.stdout, out_chunks, out_state, None),
            daemon=True,
        ),
        threading.Thread(
            target=_pump_stream,
            args=(proc.stderr, err_chunks, err_state, marker),
            daemon=True,
        ),
    ]
    for pump in pumps:
        pump.start()

    def _remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    try:
        proc.wait(timeout=_remaining())
        _join_pumps(pumps, _remaining())
    except subprocess.TimeoutExpired:
        _kill_step(proc)
        _join_pumps(pumps, _DRAIN_GRACE_S)
        duration = time.monotonic() - start
        stdout = _captured_text(out_chunks, out_state, "stdout")
        stderr = _captured_text(err_chunks, err_state, "stderr")
        note = "timed out after %ds\n%s" % (timeout_s, stderr or "")
        _write_log(log_path, argv, stdout or "", note)
        return (
            CommandRecord(
                argv=tuple(argv),
                stage=stage,
                status=STATUS_TIMEOUT,
                exit_code=None,
                duration_s=duration,
                log_excerpt=_excerpt(note),
            ),
            stdout or "",
            note,
            bool(err_state[3]),
        )
    except KeyboardInterrupt:
        _kill_step(proc)
        _join_pumps(pumps, _DRAIN_GRACE_S)
        raise
    if _pumps_alive(pumps):
        # The child exited but a descendant still holds its pipes:
        # kill the group (the pipes close with it) and report the
        # step as timed out rather than hanging past the deadline.
        _kill_step(proc)
        _join_pumps(pumps, _DRAIN_GRACE_S)
        duration = time.monotonic() - start
        stdout = _captured_text(out_chunks, out_state, "stdout")
        stderr = _captured_text(err_chunks, err_state, "stderr")
        note = "timed out after %ds draining output pipes\n%s" % (
            timeout_s, stderr or "",
        )
        _write_log(log_path, argv, stdout or "", note)
        return (
            CommandRecord(
                argv=tuple(argv),
                stage=stage,
                status=STATUS_TIMEOUT,
                exit_code=None,
                duration_s=duration,
                log_excerpt=_excerpt(note),
            ),
            stdout or "",
            note,
            bool(err_state[3]),
        )
    duration = time.monotonic() - start
    stdout = _captured_text(out_chunks, out_state, "stdout")
    stderr = _captured_text(err_chunks, err_state, "stderr")
    _write_log(log_path, argv, stdout, stderr)
    capture_error = (
        out_state[2] if out_state[2] is not None else err_state[2]
    )
    if capture_error is not None:
        status = STATUS_FAILED
    else:
        status = STATUS_OK if proc.returncode == 0 else STATUS_FAILED
    excerpt_source = stderr
    if capture_error is not None and "capture error" not in stderr:
        # A stdout-reader failure leaves stderr clean; surface it in
        # the excerpt anyway (the full note is in the step log).
        if excerpt_source and not excerpt_source.endswith("\n"):
            excerpt_source += "\n"
        excerpt_source += "...[capture error: %s]...\n" % (
            capture_error,
        )
    return (
        CommandRecord(
            argv=tuple(argv),
            stage=stage,
            status=status,
            exit_code=proc.returncode,
            duration_s=duration,
            log_excerpt=_excerpt(excerpt_source),
        ),
        stdout,
        stderr,
        bool(err_state[3]),
    )


def _write_log(path: str, argv: list[str], stdout: str, stderr: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("argv: %s\n" % json.dumps(argv))
            handle.write("--- stdout ---\n%s" % stdout)
            if stdout and not stdout.endswith("\n"):
                handle.write("\n")
            handle.write("--- stderr ---\n%s" % stderr)
            if stderr and not stderr.endswith("\n"):
                handle.write("\n")
    except OSError:
        pass


def _remove_tree(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def _sdk_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "resources", "sdk"
    )


def default_adapter_path() -> str:
    """Return the packaged adapter service script path.

    This resolves through this package's own resources, never the
    caller's working directory, so the installed CLI builds without
    repository-relative paths. An explicit ``adapter_path`` still
    selects any other service; the packaged copy is byte-identical
    to ``compiler/adapter_service.py`` (the wheel suite pins the
    sync), with its sibling modules packaged alongside it.
    """
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "resources",
        "adapter",
        "adapter_service.py",
    )


ADAPTER_TRUST_DEFAULT = "default"
ADAPTER_TRUST_DEFAULT_UNPINNED = "default-unpinned"
ADAPTER_TRUST_EXTENSION = "extension"


def admit_adapter(
    adapter_path: str,
    lockfile_path: str | None,
    diagnostics: list[Diagnostic],
    trust_root: str = "",
    native_bundle: native_module.AdmittedNativeBundle | None = None,
) -> tuple[AdmittedExecution | None, str]:
    """Admit the adapter service before any build step spawns.

    The packaged default service is compared against the lockfile's
    ``adapter`` pins (service bytes plus siblings) when the lock
    carries them, and a swapped default is refused with ``MBPF102``
    before anything executes. A lockfile carrying a
    ``distribution`` record has that closure binding enforced
    first. Under a lockfile without adapter
    pins the default still runs (test and legacy locks) but is
    recorded as ``"default-unpinned"``, never release-qualifying.
    An explicit non-default path is a documented opt-in extension:
    it is captured and recorded as ``"extension"`` but never
    receives default-qualified status. Returns the admission (None
    on failure) and the trust level.
    """
    is_default = os.path.abspath(adapter_path) == os.path.abspath(
        default_adapter_path()
    )
    document = load_toolchain_document(lockfile_path) if lockfile_path is not None else None
    if document is not None and document.get("schema_version") == 2:
        try:
            bundle = native_bundle or native_module.admit_native_bundle(document["native_adapter"], adapter_path)
            if is_default or bundle.pins_bytes != native_module.canonical_json(document["native_adapter"]):
                raise native_module.NativeAdapterError("native record requires explicit pinned adapter selection", "MBPF102", "build.setup")
            bundle.verify()
        except (native_module.NativeAdapterError, AdmissionError) as exc:
            diagnostics.append(_native_failure(exc) if isinstance(exc, native_module.NativeAdapterError) else
                Diagnostic(code="MBPF102", stage=STAGE_BUILD_SETUP, severity=SEVERITY_ERROR,
                           explanation=str(exc), remedy="restore the pinned native bundle"))
            return None, ADAPTER_TRUST_EXTENSION
        return bundle.adapter_execution, ADAPTER_TRUST_EXTENSION
    if lockfile_path is not None:
        dist_diag = check_toolchain_distribution(lockfile_path)
        if dist_diag is not None:
            diagnostics.append(dist_diag)
            return None, (
                ADAPTER_TRUST_DEFAULT
                if is_default
                else ADAPTER_TRUST_EXTENSION
            )
    service_pin: str | None = None
    sibling_pins: dict[str, str] | None = None
    if lockfile_path is not None:
        document = load_toolchain_document(lockfile_path)
        if document is not None:
            pins = document.get("adapter")
            if isinstance(pins, dict):
                candidate = pins.get("service_sha256")
                if isinstance(candidate, str):
                    service_pin = candidate
                siblings = pins.get("siblings")
                if isinstance(siblings, dict) and all(
                    isinstance(key, str) and isinstance(value, str)
                    for key, value in siblings.items()
                ):
                    sibling_pins = dict(siblings)
    enforce = is_default and (
        service_pin is not None or sibling_pins is not None
    )
    try:
        execution = admit_script_data(
            name="adapter",
            interpreter_path=sys.executable,
            script_path=adapter_path,
            script_sha256=service_pin if enforce else None,
            sibling_shas=sibling_pins if enforce else None,
            sibling_names=ADAPTER_SIBLING_FILES,
            trust_root=trust_root,
        )
    except AdmissionError as exc:
        if exc.reason == REASON_NOT_FOUND:
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_SETUP,
                    "adapter service not found: %r" % (adapter_path,),
                    adapter_path,
                    "point adapter_path at the adapter service script",
                )
            )
        elif exc.reason in (REASON_HASH_MISMATCH, REASON_MODULE_MISMATCH):
            diagnostics.append(
                Diagnostic(
                    code="MBPF102",
                    stage=STAGE_BUILD_SETUP,
                    severity=SEVERITY_ERROR,
                    explanation="packaged adapter does not match the "
                    "lockfile pin (%s)" % (exc.detail,),
                    location=adapter_path,
                    remedy="reinstall the mojobpf package or re-pin the "
                    "lockfile deliberately",
                )
            )
        else:
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_SETUP,
                    "adapter admission refused: %s" % (exc,),
                    adapter_path,
                    "check the adapter service script",
                )
            )
        return None, (
            ADAPTER_TRUST_DEFAULT
            if is_default
            else ADAPTER_TRUST_EXTENSION
        )
    if not is_default:
        trust = ADAPTER_TRUST_EXTENSION
    elif enforce and service_pin is not None:
        trust = ADAPTER_TRUST_DEFAULT
    else:
        trust = ADAPTER_TRUST_DEFAULT_UNPINNED
    return execution, trust


def _response_diagnostic(item: object) -> Diagnostic:
    if not isinstance(item, dict):
        raise ValueError("adapter diagnostic is not an object")
    return Diagnostic(
        code=item["code"],
        stage=item["stage"],
        severity=item.get("severity", SEVERITY_ERROR),
        explanation=item["explanation"],
        location=item.get("location"),
        remedy=item.get("remedy"),
    )


def _reconcile_manifest(manifest) -> Diagnostic | None:
    """Reconcile manifest declarations with the supported route.

    The adapter emits exactly the supported export roots and map
    names; anything else fails closed here (``MBPF213``/``214``)
    instead of building an artifact that disagrees with its
    manifest. More than two maps, or a two-map shape that is not
    the event pair of one state map plus its ring-buffer
    companion, is likewise unsupported (``MBPF215``). Each
    supported root pins its section/program-type pair, so a
    known root paired with any other pair fails closed here
    (``MBPF217``) instead of building a mislabeled artifact.
    """
    for index, program in enumerate(manifest.programs):
        if program.entry not in SUPPORTED_ENTRY_ROOTS:
            return Diagnostic(
                code="MBPF213",
                stage=STAGE_BUILD_SETUP,
                severity=SEVERITY_ERROR,
                explanation=(
                    "program entry %r is not a supported export root "
                    "(supported: %s)"
                    % (
                        program.entry,
                        ", ".join(SUPPORTED_ENTRY_ROOTS),
                    )
                ),
                location="%s: programs[%d].entry"
                % (manifest.manifest_path, index),
                remedy="declare entry %r; wider roots need a reviewed "
                "route" % (SUPPORTED_ENTRY_ROOTS[0],),
            )
        want_pair = ENTRY_PROGRAM_SECTIONS[program.entry]
        got_pair = (program.program_type, program.section)
        if got_pair != want_pair:
            return Diagnostic(
                code="MBPF217",
                stage=STAGE_BUILD_SETUP,
                severity=SEVERITY_ERROR,
                explanation=(
                    "program entry %r pins program_type %r with "
                    "section %r, but the manifest declares "
                    "program_type %r with section %r"
                    % (
                        program.entry,
                        want_pair[0],
                        want_pair[1],
                        got_pair[0],
                        got_pair[1],
                    )
                ),
                location="%s: programs[%d]" % (
                    manifest.manifest_path, index,
                ),
                remedy="declare program_type %r with section %r for "
                "entry %r" % (
                    want_pair[0], want_pair[1], program.entry,
                ),
            )
    if len(manifest.maps) > 2:
        return Diagnostic(
            code="MBPF215",
            stage=STAGE_BUILD_SETUP,
            severity=SEVERITY_ERROR,
            explanation=(
                "manifest declares %d maps; this route supports at "
                "most a state map plus its ring-buffer companion"
                % len(manifest.maps)
            ),
            location="%s: maps" % manifest.manifest_path,
            remedy="declare at most one map, or the event pair of a "
            "state map plus its ring-buffer companion; wider "
            "shapes need a reviewed route",
        )
    if len(manifest.maps) == 2 and (
        sum(entry.map_type == "ringbuf" for entry in manifest.maps)
        != 1
    ):
        return Diagnostic(
            code="MBPF215",
            stage=STAGE_BUILD_SETUP,
            severity=SEVERITY_ERROR,
            explanation=(
                "manifest declares 2 maps; the pair must be one "
                "state map plus its ring-buffer companion "
                "(map_type ringbuf)"
            ),
            location="%s: maps" % manifest.manifest_path,
            remedy="declare at most one map, or the event pair of a "
            "state map plus its ring-buffer companion; wider "
            "shapes need a reviewed route",
        )
    for index, entry in enumerate(manifest.maps):
        if entry.name not in SUPPORTED_MAP_NAMES:
            return Diagnostic(
                code="MBPF214",
                stage=STAGE_BUILD_SETUP,
                severity=SEVERITY_ERROR,
                explanation=(
                    "map name %r is not a supported map declaration "
                    "(supported: %s)"
                    % (
                        entry.name,
                        ", ".join(SUPPORTED_MAP_NAMES),
                    )
                ),
                location="%s: maps[%d].name"
                % (manifest.manifest_path, index),
                remedy="declare map %r; wider shapes need a reviewed "
                "route" % (SUPPORTED_MAP_NAMES[0],),
            )
    return None


def _imported_modules(source: str) -> list[str]:
    """Dotted module names imported by one Mojo source.

    Delegates to ``build-snapshot-v1``'s bounded import grammar;
    unsupported constructs raise :class:`mojobpf.inputs.InputError`
    instead of dropping out of the sealed set.
    """
    return list(parse_mojo_imports(source))


def _resolves_to_sdk(module: str, sdk_dir: str) -> bool:
    """Whether a dotted module is provided by the packaged SDK.

    Delegates to ``build-snapshot-v1``'s SDK membership check
    (module file or package directory at the full dotted path;
    a bare root directory never admits deeper names).
    """
    return module_resolves_to_sdk(module, sdk_dir)


def _discover_imports(source_files: tuple[str, ...], manifest_dir: str,
                      sdk_dir: str) -> tuple[str, ...]:
    """Find non-SDK Mojo modules imported by the program sources.

    Delegates to ``build-snapshot-v1`` discovery: the bounded
    import grammar resolved transitively to a fixpoint, with
    package directories sealing every ``.mojo`` file beneath
    them. Unresolved modules and unsupported constructs raise
    :class:`mojobpf.inputs.InputError` instead of dropping out
    of the sealed set.
    """
    return discover_imports(
        tuple(source_files), project_dir=manifest_dir, sdk_dir=sdk_dir
    )


def _setup_inputs(
    request: BuildRequest, manifest,
    diagnostics: list[Diagnostic],
) -> _SetupSeal | None:
    """Run every pre-compilation gate; capture inputs on success.

    Check order is fixed: manifest reconciliation (``MBPF213``/
    ``214``/``215``/``217``), target-profile resolution (``MBPF101``),
    declaration-pair validation (``MBPF701``/``703``/``704``),
    toolchain admission (``MBPF102``/``103``/``104``), adapter
    admission, then ``build-snapshot-v1`` capture (input grammar,
    resolution and read failures at ``MBPF106``/``build.inputs``;
    source-grant validation at ``MBPF702``/``703``/``707`` over
    the staged bytes, including imported helpers). On success
    every input file is staged into the snapshot's private root
    alongside the profile implementation digest. Returns ``None``
    after appending the first failure.
    """
    native_bundle = None
    document = load_toolchain_document(request.lockfile_path) if request.lockfile_path is not None else None
    if document is not None and document.get("schema_version") == 2:
        try:
            lock_identity = identify_file(request.lockfile_path)
            native_bundle = native_module.admit_native_bundle(document["native_adapter"], request.adapter_path)
            # Bind the exact admitted lock path/bytes into the existing spawn
            # seal. Its captured native pin record is never reread from ambient.
            adapter = native_module._harden(_dataclass_replace(native_bundle.adapter_execution,
                modules=native_bundle.adapter_execution.modules +
                        (ModuleIdentity("candidate-lock", lock_identity),)))
            native_bundle = _dataclass_replace(native_bundle, adapter_execution=adapter)
            native_bundle.verify()
            native_module.derive_native_spec(canonical_manifest_bytes(manifest), manifest.target.profile)
        except (native_module.NativeAdapterError, AdmissionError) as exc:
            diagnostics.append(_native_failure(exc) if isinstance(exc, native_module.NativeAdapterError) else
                Diagnostic(code="MBPF102", stage=STAGE_BUILD_SETUP, severity=SEVERITY_ERROR,
                    explanation=str(exc), remedy="restore the independently admitted native inputs"))
            return None
    mismatch = None if native_bundle is not None else _reconcile_manifest(manifest)
    if mismatch is not None:
        diagnostics.append(mismatch)
        return None
    try:
        lookup_profile(manifest.target.profile)
    except ProfileError as exc:
        diagnostics.append(exc.diagnostic)
        return None
    try:
        validate_declaration_pair(
            manifest.artifact.source_license,
            manifest.artifact.kernel_license,
        )
    except InspectionError as exc:
        diagnostics.append(exc.diagnostic)
        return None

    admitted: dict[str, ToolInfo]
    admitted, admission_diags = admit_tools(
        lockfile_path=request.lockfile_path,
        search_paths=request.search_paths,
        names=REQUIRED_BUILD_TOOLS,
        **({"native_bundle": native_bundle} if native_bundle is not None else {}),
    )
    if not admitted:
        diagnostics.extend(admission_diags)
        return None
    tool_executions: dict[str, AdmittedExecution] = {}
    for name in REQUIRED_BUILD_TOOLS:
        execution = admitted[name].execution
        if execution is None:
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_SETUP,
                    "tool admission for %r produced no execution record"
                    % (name,),
                    request.lockfile_path or "",
                    "reinstall the mojobpf package; this is a driver bug",
                )
            )
            return None
        tool_executions[name] = execution

    adapter_execution, adapter_trust = admit_adapter(
        request.adapter_path,
        request.lockfile_path,
        diagnostics,
        trust_root=(
            "lock:%s" % request.lockfile_path
            if request.lockfile_path is not None
            else ""
        ),
        native_bundle=native_bundle,
    )
    if adapter_execution is None:
        return None

    try:
        snapshot = _capture_snapshot(request, manifest, admitted)
    except InputError as exc:
        diagnostics.append(exc.diagnostic)
        return None
    except InspectionError as exc:
        diagnostics.append(exc.diagnostic)
        return None

    if native_bundle is not None:
        try:
            native_bundle.verify()
            native_module.derive_native_spec(snapshot.manifest_bytes, snapshot.profile_id)
        except native_module.NativeAdapterError as exc:
            snapshot.dispose()
            diagnostics.append(_native_failure(exc))
            return None

    adapter_files = [request.adapter_path]
    adapter_dir = os.path.dirname(request.adapter_path)
    for sibling in (("execution.py",) if native_bundle is not None else ADAPTER_SIBLING_FILES):
        candidate = os.path.join(adapter_dir, sibling)
        if os.path.isfile(candidate):
            adapter_files.append(candidate)

    try:
        adapter_seal = tuple(
            (os.path.realpath(path), _sha256_file(path))
            for path in adapter_files
        )
    except OSError as exc:
        snapshot.dispose()
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "cannot hash sealed build input: %s" % exc,
                request.manifest_path,
                "check the build inputs and file permissions",
            )
        )
        return None
    return _SetupSeal(
        tool_paths={
            name: tool_executions[name].argv_prefix[0]
            for name in REQUIRED_BUILD_TOOLS
        },
        tool_executions=tool_executions,
        adapter_execution=adapter_execution,
        adapter_trust=adapter_trust,
        versions={
            name: admitted[name].version for name in REQUIRED_BUILD_TOOLS
        },
        tool_shas={
            name: admitted[name].sha256 for name in REQUIRED_BUILD_TOOLS
        },
        profile_sha256=snapshot.profile_sha256,
        manifest_sha=snapshot.manifest_digest,
        source_files=snapshot.program_origins(),
        source_shas=tuple(
            item.sha256 for item in snapshot.programs
        ),
        sdk_files=tuple(item.staged for item in snapshot.sdk),
        sdk_needed=snapshot.sdk_needed,
        import_files=tuple(item.staged for item in snapshot.imports),
        adapter_files=tuple(adapter_files),
        sdk_seal=tuple(
            (os.path.realpath(item.staged), item.sha256)
            for item in snapshot.sdk
        ),
        import_seal=tuple(
            (os.path.realpath(item.staged), item.sha256)
            for item in snapshot.imports
        ),
        adapter_seal=adapter_seal,
        spawn_env=snapshot.spawn_environment,
        spawn_unset=snapshot.spawn_unset,
        snapshot=snapshot,
        native_bundle=native_bundle,
    )


def _frontend_env_redirect(
    snapshot: BuildSnapshot | None,
) -> dict[str, str] | None:
    """Return the frontend's staged-stdlib home override, if any.

    The Mojo frontend resolves ``modular.cfg`` through
    ``MODULAR_HOME`` and the compiled standard library through
    that file's ``import_path`` key, so pointing the frontend's
    ``MODULAR_HOME`` at the snapshot's staged payload makes it
    consume captured bytes instead of the live install: a
    transient substitution between the boundary checks then
    cannot reach compilation. Only the Mojo steps take this
    override (the backend and adapter never read the payload);
    ``None`` runs the step exactly as without staging. The
    override is capture-local like the staged source paths:
    evidence still records the pinned live value.
    """
    if snapshot is None:
        return None
    home = snapshot.stdlib_consumption_home
    if not home:
        return None
    return {"MODULAR_HOME": home}


def _capture_snapshot(
    request: BuildRequest, manifest,
    admitted: dict[str, ToolInfo],
) -> BuildSnapshot:
    """Capture the build inputs admitted tools will compile.

    Binds the admitted tool identities, the lockfile's
    distribution record and the lockfile bytes into the
    toolchain side of ``build-snapshot-v1``; failures propagate
    as :class:`mojobpf.inputs.InputError` (capture layer) or
    :class:`mojobpf.inspect.InspectionError` (license gate).
    Only the record's kind, platform and digest join the
    identity: the filename is a location (possibly absolute),
    not content, and the admission binding already verified
    the bytes it names. The installed standard-library
    payload the admitted toolchain resolves is hashed too,
    so a swapped ``std.mojoc``/``modular.cfg`` changes the
    identity even when the lockfile and binaries are
    identical. The influential environment is pinned once,
    before any toolchain byte is hashed, and that one pin
    object passes through payload resolution, capture,
    recording and spawn: capture performs no second ambient
    read, so a variable added after the pin reaches neither
    evidence nor the child.
    """
    pinned = capture_pinned_environment()
    pinned_spawn = dict(pinned.spawn)
    distribution: list[str] = []
    lockfile_sha: str | None = None
    if request.lockfile_path is not None:
        try:
            lockfile_sha = _sha256_file(request.lockfile_path)
        except OSError:
            lockfile_sha = None
        document = load_toolchain_document(request.lockfile_path)
        if document is not None:
            record = document.get("distribution")
            if isinstance(record, dict):
                distribution.append(
                    "%s %s %s"
                    % (
                        record.get("kind", "unknown-kind"),
                        record.get("platform", "unknown-platform"),
                        record.get("sha256", "unknown-sha256"),
                    )
                )
    mojo_execution = admitted["mojo"].execution
    mojo_binary = (
        mojo_execution.argv_prefix[0]
        if mojo_execution is not None
        else None
    )
    modular_home = pinned_spawn.get("MODULAR_HOME")
    payload = stdlib_payload_identities(
        mojo_binary=mojo_binary, modular_home=modular_home,
    )
    toolchain = ToolchainInputs(
        tools=tuple(
            SnapshotTool(
                name=name,
                version=admitted[name].version or "unknown-version",
                sha256=admitted[name].sha256 or "unknown-sha256",
            )
            for name in REQUIRED_BUILD_TOOLS
        ),
        distribution=tuple(distribution),
        lockfile_sha256=lockfile_sha,
        stdlib_payload=payload,
        stdlib_payload_paths=stdlib_payload_paths(
            mojo_binary=mojo_binary, modular_home=modular_home,
        ),
    )
    snapshot = capture_build_inputs(
        manifest,
        toolchain,
        SdkInputs(sdk_dir=_sdk_dir(), version=SDK_VERSION),
        pinned_environment=pinned,
        work_parent=request.work_parent,
    )
    return _dataclass_replace(
        snapshot, flags=_build_flags(snapshot.sdk_needed)
    )


def build_project(request: BuildRequest) -> BuildResult:
    """Build every program in a manifest into published objects.

    Returns a :class:`BuildResult`; only ``KeyboardInterrupt``
    propagates (after killing the running child and removing the work
    directory). A malformed request object raises ``ValueError``.
    """
    if not isinstance(request, BuildRequest):
        raise ValueError("build_project requires a BuildRequest")
    # Build steps run with the work directory as their working
    # directory, so every request path becomes absolute up front.
    request = BuildRequest(
        manifest_path=os.path.abspath(request.manifest_path),
        out_dir=os.path.abspath(request.out_dir),
        adapter_path=os.path.abspath(request.adapter_path),
        schema_version=request.schema_version,
        search_paths=tuple(
            os.path.abspath(entry) for entry in request.search_paths
        ),
        timeout_s=request.timeout_s,
        save_temps=request.save_temps,
        work_parent=(
            None if request.work_parent is None
            else os.path.abspath(request.work_parent)
        ),
        lockfile_path=(
            None if request.lockfile_path is None
            else os.path.abspath(request.lockfile_path)
        ),
    )
    diagnostics: list[Diagnostic] = []
    commands: list[CommandRecord] = []

    try:
        manifest = parse_manifest(request.manifest_path)
    except (ManifestError, ProfileError) as exc:
        diagnostics.append(exc.diagnostic)
        return _fail_result(diagnostics, commands)

    seal = _setup_inputs(request, manifest, diagnostics)
    if seal is None:
        return _fail_result(diagnostics, commands)

    try:
        workdir = tempfile.mkdtemp(
            prefix="mojobpf-build-", dir=request.work_parent
        )
    except (OSError, FileNotFoundError) as exc:
        seal.snapshot.dispose()
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "cannot create build work directory: %s" % exc,
                request.work_parent or tempfile.gettempdir(),
                "use a writable work_parent directory",
            )
        )
        return _fail_result(diagnostics, commands)
    try:
        return _build_inside(request, manifest, seal, workdir,
                             diagnostics, commands)
    except KeyboardInterrupt:
        _remove_tree(workdir)
        raise


def _build_flags(sdk_needed: bool) -> tuple[str, ...]:
    """Return the recorded build flag spellings (no paths).

    ``-I`` is recorded exactly when the frontend invocation carries
    it (maps declared or SDK modules imported); otherwise the flags
    are byte-identical to a no-SDK build.
    """
    flags = ["build", "--emit", "llvm"]
    if sdk_needed:
        flags.append("-I")
    flags += ["-mtriple=bpfel", "-mcpu=v3", "-filetype=obj"]
    return tuple(flags)


# An audit IR-line location, the primary audit location form the
# source mapping rewrites (findings without one fall back to the
# entry definition line; ``MBPF301`` keeps its form).
_AUDIT_LINE_RE = re.compile(r"^line (\d+)$")

# A ``!dbg`` attachment on a code line: ``, !dbg !23`` on
# instructions, `` !dbg !6`` on ``define`` headers.
_DBG_STRIP_RE = re.compile(r",? !dbg !\d+")
_DBG_ATTACH_RE = re.compile(r" !dbg !(\d+)")

# A metadata-only line (node definitions, module flags, named
# metadata): skipped positionally on both sides of the alignment.
_META_LINE_RE = re.compile(r"^!")

_DILOCATION_RE = re.compile(
    r"^!(\d+) = !DILocation\(line: (\d+), column: \d+, "
    r"scope: !(\d+)(?:, inlinedAt: !(\d+))?\)$"
)
_DIFILE_RE = re.compile(
    r'^!(\d+) = !DIFile\(filename: "(.*)", directory: ".*"\)$'
)
_DISUBPROGRAM_HEAD_RE = re.compile(
    r"^!(\d+) = (?:distinct )?!(?:DISubprogram)\((.*)\)$"
)
_DILEXICALBLOCK_HEAD_RE = re.compile(
    r"^!(\d+) = (?:distinct )?!(?:DILexicalBlock)\((.*)\)$"
)
_QUOTED_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_SCOPE_FILE_RE = re.compile(r"file: !(\d+)")
_SCOPE_LINE_RE = re.compile(r"(?:^|, )line: (\d+)")


def _parse_debug_nodes(
    lines: list[str],
) -> dict[int, tuple]:
    """Map metadata ids to file/location/scope nodes.

    Values are ``("file", filename)``, ``("loc", line, scope,
    inlined)`` with ``inlined`` possibly None, or ``("scope",
    file_id, line)`` for subprograms and lexical blocks. Unknown
    node shapes are skipped: resolution fails safe to None.
    """
    nodes: dict[int, tuple] = {}
    for raw in lines:
        line = raw.strip()
        match = _DILOCATION_RE.match(line)
        if match is not None:
            inlined = match.group(4)
            nodes[int(match.group(1))] = (
                "loc",
                int(match.group(2)),
                int(match.group(3)),
                int(inlined) if inlined is not None else None,
            )
            continue
        match = _DIFILE_RE.match(line)
        if match is not None:
            nodes[int(match.group(1))] = ("file", match.group(2))
            continue
        match = _DISUBPROGRAM_HEAD_RE.match(
            line
        ) or _DILEXICALBLOCK_HEAD_RE.match(line)
        if match is not None:
            body = _QUOTED_STRING_RE.sub('""', match.group(2))
            file_ref = _SCOPE_FILE_RE.search(body)
            line_ref = _SCOPE_LINE_RE.search(body)
            if file_ref is not None and line_ref is not None:
                nodes[int(match.group(1))] = (
                    "scope",
                    int(file_ref.group(1)),
                    int(line_ref.group(1)),
                )
    return nodes


def _debug_node_file(
    nodes: dict[int, tuple], node_id: int
) -> str | None:
    """Follow a scope chain to its DIFile filename, if known."""
    seen = set()
    while node_id not in seen:
        seen.add(node_id)
        node = nodes.get(node_id)
        if node is None:
            return None
        if node[0] == "file":
            return node[1]
        if node[0] == "scope":
            node_id = node[1]
        elif node[0] == "loc":
            node_id = node[2]
        else:
            return None
    return None


def _resolve_line_source(
    g1_lines: list[str], nodes: dict[int, tuple], lineno: int
) -> tuple[str, int] | None:
    """Map a 1-based IR line to (source file, source line).

    Follows ``inlinedAt`` to the outermost call site, so
    instructions from inlined SDK code point at the author's own
    line. ``define`` headers attach their subprogram directly and
    resolve to the definition line. Anything unrecognized yields
    None.
    """
    if lineno < 1 or lineno > len(g1_lines):
        return None
    match = _DBG_ATTACH_RE.search(g1_lines[lineno - 1])
    if match is None:
        return None
    node = nodes.get(int(match.group(1)))
    if node is None:
        return None
    if node[0] == "loc":
        seen = {int(match.group(1))}
        while node[3] is not None and node[3] not in seen:
            inner = nodes.get(node[3])
            if inner is None or inner[0] != "loc":
                break
            seen.add(node[3])
            node = inner
        filename = _debug_node_file(nodes, node[2])
        if filename is None:
            return None
        return (filename, node[1])
    if node[0] == "scope":
        filename = _debug_node_file(nodes, node[1])
        if filename is None:
            return None
        return (filename, node[2])
    return None


def _is_code_line(text: str) -> bool:
    """True for lines that carry instructions, not metadata."""
    stripped = text.strip()
    return bool(stripped) and _META_LINE_RE.match(stripped) is None


def _debug_aligns(
    raw_lines: list[str], g1_lines: list[str]
) -> bool:
    """Check the line-table re-emit against the audited IR.

    Every code line must equal the re-emitted line at the same
    number once ``!dbg`` attachments are stripped; blank and
    metadata lines may differ freely position for position (the
    metadata layout shifts under ``-g1``), and extra re-emitted
    lines must all be blank or metadata. Only then does an audit
    "line N" name the same instruction in both files, which is
    what makes the source mapping trustworthy.
    """
    for index, raw in enumerate(raw_lines):
        if index >= len(g1_lines):
            if _is_code_line(raw):
                return False
            continue
        other = _DBG_STRIP_RE.sub("", g1_lines[index])
        if _is_code_line(raw) or _is_code_line(other):
            if other != raw:
                return False
    for extra in g1_lines[len(raw_lines):]:
        if _is_code_line(extra):
            return False
    return True


def _read_source_excerpt(path: str, lineno: int) -> str | None:
    """Return source line ``lineno`` of ``path``, if readable."""
    if lineno < 1:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for number, text in enumerate(handle, 1):
                if number == lineno:
                    return text.rstrip("\r\n")
    except OSError:
        return None
    return None


def _same_file_bytes(first: str, second: str) -> bool:
    """True when both paths read byte-identical content."""
    try:
        with open(first, "rb") as handle:
            left = handle.read()
        with open(second, "rb") as handle:
            right = handle.read()
    except OSError:
        return False
    return left == right


def _apply_display_map(
    path: str, display_map: tuple[tuple[str, str], ...]
) -> str:
    """Rewrite a staged path to its origin through ``display_map``."""
    candidate = os.path.normpath(path)
    for staged, origin in display_map:
        if candidate == staged:
            return origin
        if candidate.startswith(staged + os.sep):
            return origin + candidate[len(staged):]
    return path


def _remap_source_location(
    path: str, lineno: int, *, source_abs: str, workdir: str, sdk_dir: str,
    display_map: tuple[tuple[str, str], ...] = (),
    sdk_display: str = "",
) -> str | None:
    """Build the reported ``file:line`` location, if verifiable.

    The frontend replays cached line tables for byte-identical
    sources, so the debuginfo path may name an earlier copy of
    this program rather than the file just compiled. The reported
    path is therefore this build's own ``source_abs`` whenever
    the resolved file matches it (the common case) or reads
    byte-identical (a stale replay of the same content). Any
    other absolute file is reported as resolved only under the
    SDK directory (SDK frames are this build's own toolchain
    inputs, staged or a stale replay of the origin SDK tree); a
    readable byte-different file elsewhere is a stale replay of
    another build and must not be named. Relative files resolve
    against the frontend working directory and must stay within
    it; they never resolve against the process working
    directory. ``display_map`` rewrites reported staged paths to
    their origin paths (the compiler reads the staged copies;
    users own the origins). Returns None when nothing verifiable
    can be reported and the original diagnostic must stand.
    """
    candidate = path
    from_workdir = False
    if not os.path.isabs(candidate):
        candidate = os.path.normpath(os.path.join(workdir, candidate))
        root = os.path.normpath(workdir)
        if candidate != root and not candidate.startswith(root + os.sep):
            return None
        from_workdir = True
    if os.path.normpath(candidate) == os.path.normpath(source_abs) or (
        _same_file_bytes(candidate, source_abs)
    ):
        excerpt = _read_source_excerpt(source_abs, lineno)
        if excerpt is None:
            return None
        reported = _apply_display_map(source_abs, display_map)
        return "%s:%d: %s" % (reported, lineno, excerpt)
    if not from_workdir:
        sdk_root = os.path.normpath(sdk_dir) if sdk_dir else None
        resolved = os.path.normpath(candidate)
        if sdk_root is not None and (
            resolved == sdk_root
            or resolved.startswith(sdk_root + os.sep)
        ):
            reported = _apply_display_map(candidate, display_map)
        elif sdk_display:
            origin_root = os.path.normpath(sdk_display)
            if resolved == origin_root or resolved.startswith(
                origin_root + os.sep
            ):
                reported = candidate
            else:
                return None
        else:
            return None
    else:
        reported = candidate
    excerpt = _read_source_excerpt(candidate, lineno)
    if excerpt is None:
        return None
    return "%s:%d: %s" % (reported, lineno, excerpt)


def _find_entry_define_line(
    lines: list[str], entry: str
) -> int | None:
    """Return the 1-based ``define`` line of ``entry``, if present."""
    pattern = re.compile(r"^define\s[^;]*@%s\s*\(" % re.escape(entry))
    for index, raw in enumerate(lines, 1):
        if pattern.match(raw.strip()):
            return index
    return None


def _enrich_audit_diagnostics(
    diagnostics: list[Diagnostic],
    *,
    raw_path: str,
    source_abs: str,
    tool_paths: dict[str, str],
    workdir: str,
    entry: str,
    sdk_needed: bool,
    sdk_dir: str,
    timeout_s: int,
    commands: list[CommandRecord],
    tool_executions: dict[str, AdmittedExecution] | None = None,
    _debug_lines: list[str] | None = None,
    display_map: tuple[tuple[str, str], ...] = (),
    sdk_display: str = "",
    spawn_env: dict[str, str] | None = None,
    spawn_unset: tuple[str, ...] | None = None,
    snapshot: BuildSnapshot | None = None,
) -> None:
    """Rewrite audit locations to source file:line excerpts.

    Runs only after the adapter already failed: re-emits this
    program's source with line tables, verifies the re-emit against
    the audited IR positionally, and rewrites each ``MBPF3xx``
    "line N" location to ``<file>:<line>: <excerpt>``. Findings
    without a mappable line (whole-program shape findings with no
    location, or lines the frontend preserves no location for,
    such as synthesized globals) fall back to the entry
    definition line when it resolves. ``MBPF301`` is never
    touched: it reports an adapter-internal failure, never a
    program finding, so a source line would misdirect. The re-emit
    command is recorded under ``build.diagnose``. The re-emit
    consumes up to a full ``timeout_s`` of its own: the frontend
    already succeeded, so this only extends failed builds, never
    successful ones. Every unverifiable step leaves the original
    diagnostic untouched. ``_debug_lines`` is a test seam
    supplying the re-emitted lines (bypassing the subprocess and
    its record) for the fail-safe controls. ``display_map``
    rewrites reported staged paths to origin paths; ``sdk_display``
    names the origin SDK tree for stale-replay SDK frames.
    """
    candidates = [
        position
        for position, diagnostic in enumerate(diagnostics)
        if diagnostic.code.startswith("MBPF3")
        and diagnostic.code != "MBPF301"
    ]
    if not candidates:
        return
    try:
        with open(raw_path, "r", encoding="utf-8") as handle:
            raw_lines = handle.read().splitlines()
    except OSError:
        return
    if _debug_lines is None:
        if tool_executions is None or "mojo" not in tool_executions:
            raise AssertionError(
                "diagnose re-emit requires the admitted mojo execution"
            )
        diag_path = os.path.join(workdir, "%s.diag.ll" % entry)
        argv = [tool_paths["mojo"], "build", "--emit", "llvm", "-g1"]
        if sdk_needed:
            argv += ["-I", sdk_dir]
        argv += ["-o", diag_path, source_abs]
        record, _, _, _ = _run_step(
            argv,
            STAGE_BUILD_DIAGNOSE,
            timeout_s,
            os.path.join(workdir, "%s.diagnose.log" % entry),
            workdir,
            execution=tool_executions["mojo"],
            env_extra=spawn_env,
            env_unset=spawn_unset,
            env_redirect=_frontend_env_redirect(snapshot),
        )
        commands.append(
            record if snapshot is None
            else _display_record(record, snapshot)
        )
        if record.status != STATUS_OK or record.exit_code != 0:
            return
        try:
            with open(diag_path, "r", encoding="utf-8") as handle:
                g1_lines = handle.read().splitlines()
        except OSError:
            return
    else:
        g1_lines = _debug_lines
    if not _debug_aligns(raw_lines, g1_lines):
        return
    nodes = _parse_debug_nodes(g1_lines)
    define_line = _find_entry_define_line(g1_lines, entry)
    for position in candidates:
        diagnostic = diagnostics[position]
        lineno: int | None = None
        if diagnostic.location is not None:
            match = _AUDIT_LINE_RE.match(diagnostic.location)
            if match is not None:
                lineno = int(match.group(1))
        resolved = None
        if lineno is not None:
            resolved = _resolve_line_source(g1_lines, nodes, lineno)
        if resolved is None and define_line is not None:
            resolved = _resolve_line_source(
                g1_lines, nodes, define_line
            )
        if resolved is None:
            continue
        location = _remap_source_location(
            resolved[0], resolved[1],
            source_abs=source_abs, workdir=workdir, sdk_dir=sdk_dir,
            display_map=display_map, sdk_display=sdk_display,
        )
        if location is None:
            continue
        diagnostics[position] = Diagnostic(
            code=diagnostic.code,
            stage=diagnostic.stage,
            severity=diagnostic.severity,
            explanation=diagnostic.explanation,
            location=location,
            remedy=diagnostic.remedy,
        )


def _build_inside(
    request: BuildRequest,
    manifest,
    seal: _SetupSeal,
    workdir: str,
    diagnostics: list[Diagnostic],
    commands: list[CommandRecord],
) -> BuildResult:
    """Run the pipeline stages, then retire the capture root.

    The snapshot is re-verified at the stage boundaries and its
    private root is removed on every exit path; under
    ``save_temps`` the root moves inside the kept work directory
    as ``inputs-snapshot`` for inspection instead.
    """
    try:
        return _build_stages(
            request, manifest, seal, workdir, diagnostics, commands
        )
    finally:
        snapshot = seal.snapshot
        if request.save_temps and os.path.isdir(workdir):
            target = os.path.join(workdir, "inputs-snapshot")
            try:
                os.rename(snapshot.root, target)
            except OSError:
                snapshot.dispose()
        else:
            snapshot.dispose()


def _build_stages(
    request: BuildRequest,
    manifest,
    seal: _SetupSeal,
    workdir: str,
    diagnostics: list[Diagnostic],
    commands: list[CommandRecord],
) -> BuildResult:
    try:
        os.makedirs(request.out_dir, exist_ok=True)
    except OSError as exc:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "cannot create output directory %r: %s"
                % (request.out_dir, exc),
                request.out_dir,
                "use a writable out_dir",
            )
        )
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, work_dir=kept)
    if not os.path.isdir(request.out_dir):
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "output directory is not a directory: %r"
                % (request.out_dir,),
                request.out_dir,
                "use a writable out_dir",
            )
        )
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, work_dir=kept)

    if not os.path.isfile(request.adapter_path):
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "adapter service not found: %r" % (request.adapter_path,),
                request.adapter_path,
                "point adapter_path at the adapter service script",
            )
        )
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, work_dir=kept)

    tool_paths = seal.tool_paths
    tool_executions = seal.tool_executions
    snapshot = seal.snapshot
    spawn_extra = dict(seal.spawn_env)
    spawn_unset = tuple(seal.spawn_unset)
    if seal.native_bundle is not None:
        for index, observation in enumerate(seal.native_bundle.closure.observer_records):
            _write_log(os.path.join(workdir, "native-runtime-%d.log" % index),
                observation["argv"], observation["stdout"], observation["stderr"])
            commands.append(CommandRecord(argv=tuple(observation["argv"]), stage="build.native-runtime",
                status=observation["status"], exit_code=observation["exit_code"],
                duration_s=observation["duration_s"], log_excerpt=_excerpt(observation["stderr"])))
    provenance = BuildProvenance(
        manifest_path=request.manifest_path,
        manifest_sha256=seal.manifest_sha,
        profile_id=manifest.target.profile,
        source_files=seal.source_files,
        source_sha256=seal.source_shas,
        adapter_path=request.adapter_path,
        adapter_sha256=dict(seal.adapter_seal)[
            os.path.realpath(request.adapter_path)
        ],
        mojo_version=seal.versions["mojo"],
        llc_version=seal.versions["llc"],
        mojo_sha256=seal.tool_shas["mojo"],
        llc_sha256=seal.tool_shas["llc"],
        tool_version=TOOL_VERSION,
        sdk_version=SDK_VERSION,
        adapter_trust=seal.adapter_trust,
    )

    staged: list[tuple[str, str]] = []
    multi = len(manifest.programs) > 1
    for program, source_abs in zip(
        manifest.programs, snapshot.program_paths()
    ):
        entry = program.entry
        raw_path = os.path.join(workdir, "%s.raw.ll" % entry)
        adapter_dir = os.path.join(workdir, "%s.adapter" % entry)
        staged_obj = os.path.join(workdir, "%s.bpf.o" % entry)
        if multi:
            final_name = "%s.%s.bpf.o" % (manifest.artifact.name, entry)
        else:
            final_name = "%s.bpf.o" % manifest.artifact.name

        try:
            snapshot.verify()
        except InputError as exc:
            diagnostics.append(exc.diagnostic)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        frontend_argv = [
            tool_paths["mojo"],
            "build",
            "--emit",
            "llvm",
        ]
        search_path = snapshot.frontend_search_path()
        if search_path is not None:
            frontend_argv += ["-I", search_path]
        frontend_argv += ["-o", raw_path, source_abs]
        record, _, stderr, saw_marker = _run_step(
            frontend_argv,
            STAGE_BUILD_FRONTEND,
            request.timeout_s,
            os.path.join(workdir, "%s.frontend.log" % entry),
            workdir,
            STDERR_ERROR_MARKER,
            execution=tool_executions["mojo"],
            env_extra=spawn_extra,
            env_unset=spawn_unset,
            env_redirect=_frontend_env_redirect(snapshot),
        )
        commands.append(_display_record(record, snapshot))
        failure = _step_outcome(
            record, raw_path, "frontend", STDERR_ERROR_MARKER, stderr,
            saw_marker,
        )
        if failure is not None:
            diagnostics.append(_display_failure(failure, snapshot))
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )

        native_input = None
        if seal.native_bundle is not None:
            try:
                native_root = os.path.join(workdir, "native-input")
                os.mkdir(native_root)
                native_manifest = os.path.join(native_root, "captured-manifest.json")
                native_input = _NativeInputSeal(manifest_path=native_manifest,
                    manifest_sha256=materialize_native_manifest(snapshot.manifest_bytes, native_manifest),
                    spec_bytes=native_module.derive_native_spec(snapshot.manifest_bytes, snapshot.profile_id),
                    raw_path=raw_path, input_ir_sha256=hashlib.sha256(native_module._read(raw_path, native_module.MAX_IR)).hexdigest(),
                    adapter_dir=adapter_dir)
                native_module._write_owned(os.path.join(native_root, "admitted-pins.json"), seal.native_bundle.pins_bytes)
                seal = _dataclass_replace(seal, native_inputs=(native_input,))
            except (OSError, InputError, native_module.NativeAdapterError) as exc:
                diagnostics.append(_native_failure(exc) if isinstance(exc, (InputError, native_module.NativeAdapterError)) else
                    _step_failure(STAGE_BUILD_ADAPTER, str(exc), workdir, "use writable fresh staging"))
                kept = _finish_workdir(request, workdir)
                return _fail_result(diagnostics, commands, provenance, work_dir=kept)

        adapted_path = _run_adapter(
            request, manifest, workdir, entry, raw_path, adapter_dir,
            diagnostics, commands,
            seal.adapter_execution,
            staged_manifest=(native_input.manifest_path if native_input is not None else snapshot.manifest_staged),
            spawn_env=spawn_extra,
            spawn_unset=spawn_unset,
            snapshot=snapshot,
            native_bundle=seal.native_bundle,
            native_input=native_input,
        )
        if adapted_path is None:
            if seal.native_bundle is None:
                _enrich_audit_diagnostics(
                    diagnostics,
                    raw_path=raw_path,
                    source_abs=source_abs,
                    tool_paths=tool_paths,
                    workdir=workdir,
                    entry=entry,
                    sdk_needed=seal.sdk_needed,
                    sdk_dir=search_path or "",
                    timeout_s=request.timeout_s,
                    commands=commands,
                    tool_executions=tool_executions,
                    display_map=snapshot.display_replacements(),
                    sdk_display=snapshot.sdk_dir,
                    spawn_env=spawn_extra,
                    spawn_unset=spawn_unset,
                    snapshot=snapshot,
                )
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )

        if native_input is not None:
            try:
                observed = _readback_native_inputs(snapshot, native_input, seal.native_bundle)
                native_input = _dataclass_replace(native_input, outputs_bytes=native_module.canonical_json(observed))
                seal = _dataclass_replace(seal, native_inputs=(native_input,))
                _readback_native_inputs(snapshot, native_input, seal.native_bundle)
                native_module._write_owned(os.path.join(native_root, "admitted-inputs.json"),
                    native_module.canonical_json({"route_id": native_module.ROUTE_ID, "runtime_qualified": False,
                        "native_pins_sha256": hashlib.sha256(seal.native_bundle.pins_bytes).hexdigest(),
                        "captured_manifest_json_sha256": native_input.manifest_sha256,
                        "runtime_closure_sha256": seal.native_bundle.closure.sha256,
                        "runtime_closure_content_sha256": seal.native_bundle.closure.content_sha256,
                        "observed": observed}))
            except (InputError, native_module.NativeAdapterError) as exc:
                diagnostics.append(_native_failure(exc))
            else:
                diagnostics.append(Diagnostic(code="MBPF107", stage=STAGE_BUILD_BACKEND, severity=SEVERITY_ERROR,
                    explanation="parsed frame/object verification and native evidence publication are unavailable",
                    remedy="use a driver with the complete parsed verification route"))
            kept = _finish_workdir(request, workdir)
            return _fail_result(diagnostics, commands, provenance, work_dir=kept)

        record, _, stderr, saw_marker = _run_step(
            [
                tool_paths["llc"],
                "-mtriple=bpfel",
                "-mcpu=v3",
                "-filetype=obj",
                adapted_path,
                "-o",
                staged_obj,
            ],
            STAGE_BUILD_BACKEND,
            request.timeout_s,
            os.path.join(workdir, "%s.backend.log" % entry),
            workdir,
            STDERR_ERROR_MARKER,
            execution=tool_executions["llc"],
            env_extra=spawn_extra,
            env_unset=spawn_unset,
        )
        commands.append(_display_record(record, snapshot))
        failure = _step_outcome(
            record, staged_obj, "backend", STDERR_ERROR_MARKER, stderr,
            saw_marker,
        )
        if failure is not None:
            diagnostics.append(_display_failure(failure, snapshot))
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        gate = _spill_gate_outcome(
            tool_executions["llc"], adapted_path, staged_obj,
            request.timeout_s, workdir, entry, commands,
            spawn_env=spawn_extra,
            spawn_unset=spawn_unset,
            snapshot=snapshot,
        )
        if gate is not None:
            diagnostics.append(gate)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        inspection = _verify_gate_outcome(
            manifest, program, staged_obj, adapted_path
        )
        if inspection:
            diagnostics.extend(inspection)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        staged.append((staged_obj, final_name))

    return _publish_generation(
        request, manifest, seal, workdir, staged, provenance,
        diagnostics, commands,
    )


def _publish_generation(
    request: BuildRequest,
    manifest,
    seal: _SetupSeal,
    workdir: str,
    staged: list[tuple[str, str]],
    provenance: BuildProvenance,
    diagnostics: list[Diagnostic],
    commands: list[CommandRecord],
) -> BuildResult:
    """Capture evidence and publish objects plus sidecar atomically.

    Publication moves bytes unchanged, so staged hashes describe the
    final artifacts; the snapshot is re-verified and the evidence
    inputs are re-hashed from the staged bytes and checked against
    the setup seal before anything is published. Objects and the
    provenance sidecar move through one transaction: any failure
    leaves the output directory without a new-or-partial result.
    """
    if seal.native_bundle is not None:
        try:
            for item in seal.native_inputs:
                _readback_native_inputs(seal.snapshot, item, seal.native_bundle)
        except (InputError, native_module.NativeAdapterError) as exc:
            diagnostics.append(_native_failure(exc))
        else:
            diagnostics.append(Diagnostic(code="MBPF107", stage=STAGE_BUILD_PUBLISH, severity=SEVERITY_ERROR,
                explanation="parsed frame/object verification and native evidence publication are unavailable",
                remedy="use a driver with the complete parsed verification route"))
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, provenance, work_dir=kept)
    try:
        seal.snapshot.verify()
    except InputError as exc:
        diagnostics.append(exc.diagnostic)
        kept = _finish_workdir(request, workdir)
        return _fail_result(
            diagnostics, commands, provenance, work_dir=kept
        )
    manifest_dir = os.path.dirname(os.path.abspath(request.manifest_path))
    provisional: list[BuildArtifact] = []
    entries: list[tuple[str, str, str]] = []
    for staged_obj, final_name in staged:
        try:
            size = os.path.getsize(staged_obj)
            sha = _sha256_file(staged_obj)
        except OSError as exc:
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_PUBLISH,
                    "cannot hash staged object %r: %s"
                    % (final_name, exc),
                    staged_obj,
                    "rebuild the project",
                )
            )
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        provisional.append(
            BuildArtifact(
                role="object",
                path=os.path.join(request.out_dir, final_name),
                sha256=sha,
                size=size,
            )
        )
        entries.append((final_name, staged_obj, "object"))
    try:
        evidence = evidence_from_build(
            BuildResult(
                schema_version=BUILD_SCHEMA_VERSION,
                success=True,
                diagnostics=(),
                artifacts=tuple(provisional),
                provenance=provenance,
                commands=tuple(commands),
                work_dir=None,
            ),
            manifest,
            project_dir=manifest_dir,
            out_dir=request.out_dir,
            transforms=BUILD_TRANSFORMS,
            sdk_files=seal.sdk_files,
            imported_sources=seal.import_files,
            adapter_files=seal.adapter_files,
            flags=seal.snapshot.flags,
            tool_version=TOOL_VERSION,
            sdk_version=SDK_VERSION,
            sealed=SealedInputs(
                manifest_sha256=seal.manifest_sha,
                source_sha256=seal.source_shas,
                sdk=seal.sdk_seal,
                imports=seal.import_seal,
                adapter=seal.adapter_seal,
                profile_sha256=seal.profile_sha256,
            ),
            snapshot=seal.snapshot,
        )
    except EvidenceError as exc:
        diagnostics.append(exc.diagnostic)
        kept = _finish_workdir(request, workdir)
        return _fail_result(
            diagnostics, commands, provenance, work_dir=kept
        )
    evidence_name = "%s.evidence.json" % manifest.artifact.name
    evidence_staged = os.path.join(workdir, evidence_name)
    try:
        with open(evidence_staged, "wb") as handle:
            handle.write(dumps_evidence(evidence))
    except OSError as exc:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_PUBLISH,
                "cannot stage build evidence %r: %s"
                % (evidence_name, exc),
                evidence_staged,
                "use a writable work_parent directory with free space",
            )
        )
        kept = _finish_workdir(request, workdir)
        return _fail_result(
            diagnostics, commands, provenance, work_dir=kept
        )
    entries.append((evidence_name, evidence_staged, "evidence"))
    try:
        published = publish_artifacts(entries, request.out_dir)
    except EvidenceError as exc:
        diagnostics.append(exc.diagnostic)
        kept = _finish_workdir(request, workdir)
        return _fail_result(
            diagnostics, commands, provenance, work_dir=kept
        )
    artifacts = [
        BuildArtifact(
            role=item.role,
            path=os.path.join(request.out_dir, item.name),
            sha256=item.sha256,
            size=item.size,
        )
        for item in published
    ]
    work_dir = _finish_workdir(request, workdir)
    return BuildResult(
        schema_version=BUILD_SCHEMA_VERSION,
        success=True,
        diagnostics=tuple(diagnostics),
        artifacts=tuple(artifacts),
        provenance=provenance,
        commands=tuple(commands),
        work_dir=work_dir,
    )


def _finish_workdir(request: BuildRequest, workdir: str) -> str | None:
    if request.save_temps:
        return workdir
    _remove_tree(workdir)
    return None


_ERROR_LOCATION_RE = re.compile(r":\d+(?::\d+)?: error:")


def _first_error_line(stderr: str) -> str | None:
    """First tool error line in retained stderr, if any.

    The Mojo frontend reports source errors as
    ``<file>.mojo:<line>:<col>: error: ...`` and the LLVM backend as
    ``error: ...`` (fatal backend errors as ``LLVM ERROR: ...``);
    the first such line is the actionable location. The match is
    anchored to those shapes: a bare ``error:`` substring inside
    warning or note text is not an error line. Returns None
    when stderr carries no error line (tool crash without
    diagnostics, marker past the capture cap), in which case the
    caller keeps the expected output path as the location.
    """
    for raw in stderr.splitlines():
        line = raw.strip()
        if not line:
            continue
        if (
            line.startswith("error:")
            or line.startswith("LLVM ERROR")
            or _ERROR_LOCATION_RE.search(line)
        ):
            return line
    return None


def _step_outcome(
    record: CommandRecord,
    expected_path: str,
    step: str,
    marker: str,
    stderr: str,
    saw_marker: bool,
) -> Diagnostic | None:
    """Classify a frontend/backend record; None means the step passed.

    ``saw_marker`` reports the error marker across the entire drained
    stderr stream (past the capture cap and across chunk boundaries),
    not just the retained head, so a late marker still fails loudly.
    A failed record with a zero exit means a pipe reader errored --
    the only outcome the runner marks that way -- and fails here too.
    """
    if record.status == STATUS_TIMEOUT:
        return _step_failure(
            record.stage,
            "%s step timed out after %.1fs: %s"
            % (step, record.duration_s, " ".join(record.argv)),
            expected_path,
            "retry with a larger timeout or fix the hanging tool",
        )
    if record.status == STATUS_SPAWN_FAILED:
        return _step_failure(
            record.stage,
            "%s step could not start %r: %s"
            % (
                step,
                record.argv[0] if record.argv else "",
                record.log_excerpt,
            ),
            expected_path,
            "check the installation of the build tool",
        )
    if record.status == STATUS_FAILED and record.exit_code == 0:
        return _step_failure(
            record.stage,
            "%s step failed to capture its output (a pipe reader "
            "errored), so the step result cannot be trusted: %s"
            % (step, " ".join(record.argv)),
            expected_path,
            "retry the build; the step log names the failing stream",
        )
    if record.exit_code != 0:
        return _step_failure(
            record.stage,
            "%s step exited %d: %s"
            % (step, record.exit_code, " ".join(record.argv)),
            _first_error_line(stderr) or expected_path,
            "fix the reported error; the log excerpt names it",
        )
    if saw_marker or marker.lower() in stderr.lower():
        return _step_failure(
            record.stage,
            "%s step reported errors: %s" % (step, " ".join(record.argv)),
            _first_error_line(stderr) or expected_path,
            "fix the reported error; the log excerpt names it",
        )
    if not os.path.isfile(expected_path):
        return _step_failure(
            record.stage,
            "%s step produced no output at %r" % (step, expected_path),
            expected_path,
            "check the installation of the build tool",
        )
    return None


_RBSIZE_LITERAL_RE = re.compile(
    r'call i64 asm "", "=r,0,r"\(i64\s+%\S+,\s+i64\s+(\d+)\)'
)


def _adapted_ring_size(adapted_text: str) -> int | None:
    """Ring-buffer size from the adapted size tag, if qualified.

    Returns the single ring-size literal when the adapted IR
    carries exactly one size tag with a qualified size, else
    None so the caller fails closed instead of reconciling an
    unknown size.
    """
    found = _RBSIZE_LITERAL_RE.findall(adapted_text)
    if len(found) != 1:
        return None
    try:
        size = int(found[0])
    except ValueError:
        return None
    if size not in RINGBUF_SIZES:
        return None
    return size


def _adapted_shape(adapted_text: str) -> tuple | None:
    """Classify adapted IR by its lowered helper-call counts.

    Returns ``(family, entries, percpu)`` with family one of
    ``"classifier"``, ``"map"``, ``"combined"``, ``"delete"``,
    ``"tracepoint"``, ``"event"``, ``"reserve"``, ``"core"``,
    or ``"uprobe"``;
    ``entries`` the dense key coverage (0 for the classifier);
    and ``percpu`` whether kind tags mark the program per-CPU.
    Hash tag lines pass through classification untouched (a hash
    program classifies exactly like its array twin); the caller
    resolves the hash kind from the hash marker separately. A
    two-pair program with three reinterpretations is the
    combined workload, with two the map-only pair shape; the
    tracepoint counter is two lookups, one update, and one
    PID/TID call with two reinterpretations and no kind tag; the
    event emitter is four lookups, three updates, two PID/TID
    calls, one clock call, one CPU call, and one output call
    with four reinterpretations, the ring-size tag, and the
    event slot, and no kind tag; the reservation emitter is
    four lookups, three updates, two PID/TID calls, one clock
    call, one CPU call, one reserve call, and one terminus call
    with five reinterpretations, the ring-size tag, no event
    slot, and no kind tag; the core probe is one lookup with
    one reinterpretation, the relocation expansion markers, and
    no kind tag; the uprobe counter is two lookups, one update,
    and no PID/TID call with two reinterpretations, the pinned
    context-word read, and no kind tag. Any other combination
    is unrecognized (None) and fails closed.
    """
    lookups = adapted_text.count(LOWERED_CALLEE_MARKERS[0])
    updates = adapted_text.count(LOWERED_CALLEE_MARKERS[1])
    deletes = adapted_text.count(LOWERED_CALLEE_MARKERS[2])
    pids = adapted_text.count(LOWERED_CALLEE_MARKERS[3])
    ktimes = adapted_text.count(LOWERED_CALLEE_MARKERS[4])
    cpus = adapted_text.count(LOWERED_CALLEE_MARKERS[5])
    outputs = adapted_text.count(LOWERED_CALLEE_MARKERS[6])
    reserves = adapted_text.count(LOWERED_CALLEE_MARKERS[7])
    submits = adapted_text.count(LOWERED_CALLEE_MARKERS[8])
    discards = adapted_text.count(LOWERED_CALLEE_MARKERS[9])
    percpu = KINDTAG_MARKER in adapted_text
    hashkind = HASHTAG_MARKER in adapted_text
    if (
        lookups == 0
        and updates == 0
        and deletes == 0
        and pids == 0
        and ktimes == 0
        and cpus == 0
        and outputs == 0
        and reserves == 0
        and submits == 0
        and discards == 0
    ):
        if percpu or hashkind:
            return None
        return ("classifier", 0, False)
    if pids:
        if (
            lookups == 4
            and updates == 3
            and pids == 2
            and ktimes == 1
            and cpus == 1
            and outputs == 1
            and not reserves
            and not submits
            and not discards
            and not deletes
            and not percpu
            and not hashkind
        ):
            reinterps = adapted_text.count(
                'call ptr asm "", "=r,0"'
            )
            if reinterps != 4:
                return None
            if RBSIZE_MARKER not in adapted_text:
                return None
            if EVENTSLOT_MARKER not in adapted_text:
                return None
            if _adapted_ring_size(adapted_text) is None:
                return None
            return ("event", 4, False)
        if (
            lookups == 4
            and updates == 3
            and pids == 2
            and ktimes == 1
            and cpus == 1
            and not outputs
            and reserves == 1
            and (submits, discards) in ((1, 0), (0, 1))
            and not deletes
            and not percpu
            and not hashkind
        ):
            reinterps = adapted_text.count(
                'call ptr asm "", "=r,0"'
            )
            if reinterps != 5:
                return None
            if RBSIZE_MARKER not in adapted_text:
                return None
            if EVENTSLOT_MARKER in adapted_text:
                return None
            if _adapted_ring_size(adapted_text) is None:
                return None
            return ("reserve", 4, False)
        if (
            pids != 1
            or deletes
            or lookups != 2
            or updates != 1
            or ktimes
            or cpus
            or outputs
            or reserves
            or submits
            or discards
        ):
            return None
        if percpu or hashkind:
            return None
        reinterps = adapted_text.count('call ptr asm "", "=r,0"')
        if reinterps != 2:
            return None
        return ("tracepoint", 2, False)
    if ktimes or cpus or outputs or reserves or submits or discards:
        return None
    if deletes and not (lookups or updates):
        return ("delete", deletes, percpu)
    if (
        lookups == 2
        and updates == 1
        and deletes == 0
        and not percpu
        and not hashkind
        and adapted_text.count(UPROBE_CTXREAD_MARKER) == 1
    ):
        reinterps = adapted_text.count('call ptr asm "", "=r,0"')
        if reinterps != 2:
            return None
        return ("uprobe", 2, False)
    if (
        lookups == 1
        and updates == 0
        and deletes == 0
        and not percpu
        and not hashkind
        and "llvm.bpf.passthrough" in adapted_text
        and "!llvm.preserve.access.index" in adapted_text
    ):
        reinterps = adapted_text.count('call ptr asm "", "=r,0"')
        if reinterps != 1:
            return None
        return ("core", 1, False)
    if deletes or lookups != updates or lookups < 1:
        return None
    if lookups == 2:
        reinterps = adapted_text.count('call ptr asm "", "=r,0"')
        if reinterps == 3:
            if hashkind:
                return None
            return ("combined", 2, percpu)
        if reinterps != 2:
            return None
    return ("map", lookups, percpu)


TRACEPOINT_GATE_SECTION = b"tracepoint/syscalls/sys_enter_getpid"
XDP_GATE_SECTION = b"xdp"
UPROBE_GATE_SECTION = b"uprobe"


def _section_add_immediates(
    image: bytes, section: bytes
) -> list[int] | None:
    """Sorted 64-bit add immediates of one section, if parseable.

    Returns None when the image is not a well-formed little-endian
    64-bit ELF object with the named section, so the caller fails
    closed instead of trusting an unknown object. Every offset is
    bounds-checked; malformed input yields None, never an error.
    """
    if len(image) < 64 or image[:4] != b"\x7fELF":
        return None
    if image[4] != 2 or image[5] != 1:
        return None
    try:
        header = struct.unpack_from("<QQIHHHHHH", image, 0x20)
    except struct.error:
        return None
    (_phoff, e_shoff, _flags, _ehsize, _phentsize, _phnum,
     e_shentsize, e_shnum, e_shstrndx) = header
    if e_shentsize < 64 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return None
    if e_shoff > len(image):
        return None
    try:
        str_fields = struct.unpack_from(
            "<IIQQQQ", image, e_shoff + e_shstrndx * e_shentsize
        )
    except struct.error:
        return None
    str_off, str_size = str_fields[4], str_fields[5]
    if str_off + str_size > len(image):
        return None
    code = None
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        if off + 64 > len(image):
            return None
        try:
            fields = struct.unpack_from("<IIQQQQ", image, off)
        except struct.error:
            return None
        name, _type, _flags, _addr, sec_off, size = fields
        if name >= str_size:
            return None
        end = image.find(b"\x00", str_off + name, str_off + str_size)
        if end < 0:
            return None
        if image[str_off + name:end] == section:
            if sec_off + size > len(image):
                return None
            code = image[sec_off:sec_off + size]
            break
    if code is None or len(code) % 8 != 0:
        return None
    imms = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        if opcode == _BPF_LD_IMM64:
            if offset + 16 > len(code):
                return None
            offset += 16
            continue
        if opcode == _BPF_ADD64_IMM:
            (imm,) = struct.unpack_from("<i", code, offset + 4)
            imms.append(imm)
        offset += 8
    return sorted(imms)


def _map_set_outcome(manifest, staged_obj: str,
                      adapted_path: str) -> list[Diagnostic]:
    """Reject an object whose maps disagree with the manifest.

    The route emits exactly the declared maps under their fixed
    names; an object carrying more, fewer, or differently-named maps
    than ``manifest.maps`` fails closed here (``MBPF216``) instead
    of publishing an artifact that disagrees with its manifest.
    Two map entries in one map are still one map: the entry count
    is reconciled separately below, never as a second map.
    """
    expected = sorted(entry.name for entry in manifest.maps)
    try:
        observed = list(object_map_names(staged_obj))
    except InspectionError as exc:
        return [exc.diagnostic]
    if observed != expected:
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built object %r carries maps %s but manifest.maps "
                    "declares %s"
                    % (
                        staged_obj,
                        observed or "none",
                        expected or "none",
                    )
                ),
                location=staged_obj,
                remedy="declare exactly the maps the program defines; "
                "wider shapes need a reviewed route",
            )
        ]
    return _map_entries_outcome(manifest, staged_obj, adapted_path)


def _event_map_outcome(manifest, staged_obj: str,
                       adapted_text: str,
                       family: str) -> list[Diagnostic]:
    """Reject an event-pair object whose pair, kinds, or sizes disagree.

    The event and reservation shapes emit the array state map
    ``mojobpf_map0`` (four entries) plus the ring-buffer companion
    ``mojobpf_map1`` sized by the audited size tag; the manifest
    must declare that pair (in either order) with those kinds and
    sizes, and the object's BTF map attributes must agree. Any
    other declaration or emission fails closed here (``MBPF216``).
    """
    want_size = _adapted_ring_size(adapted_text)
    if want_size is None:
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built %s object %r carries no qualified "
                    "ring-size tag, so its ring-buffer size cannot "
                    "be reconciled with manifest.maps"
                    % (family, staged_obj)
                ),
                location=staged_obj,
                remedy="build only the reviewed program shapes; "
                "wider shapes need a reviewed route",
            )
        ]
    declared = {entry.name: entry for entry in manifest.maps}
    state = declared.get("mojobpf_map0")
    ring = declared.get("mojobpf_map1")
    for member in (state, ring):
        if (
            member is not None
            and VALUE_TYPE_SIZES.get(member.value_type) == 4096
        ):
            return [
                Diagnostic(
                    code="MBPF216",
                    stage=STAGE_BUILD_BACKEND,
                    severity=SEVERITY_ERROR,
                    explanation=(
                        "manifest.maps declares value_type = %r "
                        "for %r but the %s program shape is not "
                        "the core shape; only core programs emit "
                        "a 4096-byte map value"
                        % (member.value_type, member.name, family)
                    ),
                    location=staged_obj,
                    remedy="declare the reviewed value type for "
                    "this program shape (u64 for the state map, "
                    "none for the ring-buffer companion); wider "
                    "shapes need a reviewed route",
                )
            ]
    if (
        state is None
        or ring is None
        or state.map_type != "array"
        or state.max_entries != 4
        or ring.map_type != "ringbuf"
        or ring.max_entries != want_size
    ):
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built %s object %r emits a 4-entry array "
                    "state map plus a %d-byte ring-buffer map, but "
                    "manifest.maps declares %s"
                    % (
                        family,
                        staged_obj,
                        want_size,
                        sorted(
                            (entry.name, entry.map_type,
                             entry.max_entries)
                            for entry in manifest.maps
                        ),
                    )
                ),
                location=staged_obj,
                remedy="declare mojobpf_map0 as a 4-entry array and "
                "mojobpf_map1 as a %d-byte ringbuf; wider shapes "
                "need a reviewed route" % (want_size,),
            )
        ]
    try:
        specs = dict(
            (name, (map_type, entries))
            for name, map_type, entries in object_map_specs(staged_obj)
        )
    except InspectionError as exc:
        return [exc.diagnostic]
    observed = (
        specs.get("mojobpf_map0"), specs.get("mojobpf_map1"),
    )
    if observed != ((2, 4), (MAP_TYPE_IDS["ringbuf"], want_size)):
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built object %r carries map attributes %s but "
                    "the %s program shape emits "
                    "((2, 4), (%d, %d))"
                    % (
                        staged_obj,
                        observed,
                        family,
                        MAP_TYPE_IDS["ringbuf"],
                        want_size,
                    )
                ),
                location=staged_obj,
                remedy="rebuild the object with the pinned toolchain",
            )
        ]
    return []


def _map_entries_outcome(manifest, staged_obj: str,
                         adapted_path: str) -> list[Diagnostic]:
    """Reject a map object whose kind, count, or value size disagrees.

    The adapter emits the map kind and entry count the audited
    program shape requires (the kind tag selects array, per-CPU
    array, or hash; dense key coverage selects the count; the
    event and reservation shapes additionally emit the
    ring-buffer size from the audited size tag); a manifest
    declaring any other kind or
    count fails closed here (``MBPF216``), as does an object whose
    BTF map attributes disagree with the emitted shape, instead of
    publishing an artifact that disagrees with its manifest. The
    core family additionally reconciles the emitted 4096-byte map
    value against the manifest's declared value type and the
    object's BTF value size; every other family keeps kind and
    entry count only, and refuses a 4096-byte value declaration
    outright (only the core shape emits one).
    """
    try:
        with open(adapted_path, "r", encoding="utf-8") as handle:
            adapted_text = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        return [
            _step_failure(
                STAGE_BUILD_BACKEND,
                "cannot read adapted IR for map reconciliation: %s"
                % exc,
                adapted_path,
                "check the adapter service output",
            )
        ]
    shape = _adapted_shape(adapted_text)
    if shape is not None and shape[0] == "classifier":
        return []
    if shape is None:
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built object %r has an unrecognized helper-call "
                    "shape, so its map kind and entry count cannot "
                    "be reconciled with manifest.maps" % (staged_obj,)
                ),
                location=staged_obj,
                remedy="build only the reviewed program shapes; "
                "wider shapes need a reviewed route",
            )
        ]
    family, want_entries, percpu = shape
    if family in ("event", "reserve"):
        return _event_map_outcome(
            manifest, staged_obj, adapted_text, family
        )
    hashkind = HASHTAG_MARKER in adapted_text
    if hashkind and percpu:
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built %s object %r carries both per-CPU and "
                    "hash kind tags, so its map kind cannot be "
                    "reconciled with manifest.maps"
                    % (family, staged_obj)
                ),
                location=staged_obj,
                remedy="build only the reviewed program shapes; "
                "wider shapes need a reviewed route",
            )
        ]
    if hashkind:
        want_kind = "hash"
    elif percpu:
        want_kind = "percpu_array"
    else:
        want_kind = "array"
    # The map names matched above and a non-event map-mode object
    # carries exactly one map, so the manifest declares exactly
    # one here.
    declared = manifest.maps[0]
    if (
        family != "core"
        and VALUE_TYPE_SIZES.get(declared.value_type) == 4096
    ):
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "manifest.maps declares value_type = %r but "
                    "the %s program shape is not the core shape; "
                    "only core programs emit a 4096-byte map value"
                    % (declared.value_type, family)
                ),
                location=staged_obj,
                remedy="declare value_type = 'u64' for this "
                "program shape, or build the core program shape "
                "under target.core = true",
            )
        ]
    if declared.map_type != want_kind:
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built %s object %r emits a %s map but "
                    "manifest.maps declares map_type = %r"
                    % (family, staged_obj, want_kind,
                       declared.map_type)
                ),
                location=staged_obj,
                remedy="declare map_type = %r for this program "
                "shape; wider shapes need a reviewed route"
                % (want_kind,),
            )
        ]
    if declared.max_entries != want_entries:
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built %s object %r emits a %d-entry map but "
                    "manifest.maps declares max_entries = %d"
                    % (family, staged_obj, want_entries,
                       declared.max_entries)
                ),
                location=staged_obj,
                remedy="declare max_entries = %d for this program "
                "shape; wider shapes need a reviewed route"
                % (want_entries,),
            )
        ]
    # Value-size reconciliation is core-family only; non-core
    # families keep their exact previous behavior (kind and entry
    # count, never value sizes).
    want_value = 4096
    if family == "core":
        declared_value = VALUE_TYPE_SIZES.get(declared.value_type)
        if declared_value is None:
            return [
                Diagnostic(
                    code="MBPF216",
                    stage=STAGE_BUILD_BACKEND,
                    severity=SEVERITY_ERROR,
                    explanation=(
                        "manifest.maps declares value_type = %r, "
                        "which has no reconciled BTF value size"
                        % (declared.value_type,)
                    ),
                    location=staged_obj,
                    remedy="declare a reviewed value type for this "
                    "program shape; wider shapes need a reviewed "
                    "route",
                )
            ]
        if declared_value != want_value:
            return [
                Diagnostic(
                    code="MBPF216",
                    stage=STAGE_BUILD_BACKEND,
                    severity=SEVERITY_ERROR,
                    explanation=(
                        "built %s object %r emits a %d-byte map "
                        "value but manifest.maps declares "
                        "value_type = %r (%d bytes)"
                        % (family, staged_obj, want_value,
                           declared.value_type, declared_value)
                    ),
                    location=staged_obj,
                    remedy="declare value_type = %r for this "
                    "program shape; wider shapes need a reviewed "
                    "route" % ("bytes4096",),
                )
            ]
    try:
        specs = dict(
            (name, (map_type, entries))
            for name, map_type, entries in object_map_specs(staged_obj)
        )
    except InspectionError as exc:
        return [exc.diagnostic]
    observed = specs.get(declared.name)
    if observed is None:
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built object %r carries no map BTF attributes "
                    "for %r" % (staged_obj, declared.name)
                ),
                location=staged_obj,
                remedy="rebuild the object with the pinned toolchain",
            )
        ]
    if observed != (MAP_TYPE_IDS[want_kind], want_entries):
        return [
            Diagnostic(
                code="MBPF216",
                stage=STAGE_BUILD_BACKEND,
                severity=SEVERITY_ERROR,
                explanation=(
                    "built object %r carries map attributes "
                    "(type %d, entries %d) but the %s program shape "
                    "emits (type %d, entries %d)"
                    % (
                        staged_obj,
                        observed[0],
                        observed[1],
                        family,
                        MAP_TYPE_IDS[want_kind],
                        want_entries,
                    )
                ),
                location=staged_obj,
                remedy="rebuild the object with the pinned toolchain",
            )
        ]
    if family == "core":
        try:
            sizes = object_map_value_sizes(staged_obj)
        except InspectionError as exc:
            return [exc.diagnostic]
        if sizes.get(declared.name) != want_value:
            return [
                Diagnostic(
                    code="MBPF216",
                    stage=STAGE_BUILD_BACKEND,
                    severity=SEVERITY_ERROR,
                    explanation=(
                        "built object %r carries a %r-byte map "
                        "value for %r but the %s program shape "
                        "emits %d bytes"
                        % (
                            staged_obj,
                            sizes.get(declared.name),
                            declared.name,
                            family,
                            want_value,
                        )
                    ),
                    location=staged_obj,
                    remedy="rebuild the object with the pinned "
                    "toolchain",
                )
            ]
    return []


def _verify_gate_outcome(manifest, program, staged_obj: str,
                         adapted_path: str) -> list[Diagnostic]:
    """Run the pre-publication inspection gate over one object.

    ``program`` is the manifest program entry this object was
    built for. Returns the report findings (structural,
    unsupported, license) when the object fails, the manifest
    disagreement (``MBPF216``) when the emitted program section
    is not the manifest program's declared section, when the
    emitted maps, their kinds, or their entry counts differ from
    ``manifest.maps`` (the core family additionally reconciles
    the emitted map value size), or when the emitted CO-RE
    relocation records disagree with the manifest's CO-RE flag,
    or an empty list when the object passes. An unreadable
    object fails with its own diagnostic.
    """
    try:
        report = verify_object(
            staged_obj,
            manifest.target.profile,
            manifest.artifact.source_license,
            manifest.artifact.kernel_license,
        )
    except InspectionError as exc:
        return [exc.diagnostic]
    if report.ok:
        flag_outcome = _core_flag_outcome(manifest, staged_obj)
        if flag_outcome:
            return flag_outcome
        section_outcome = _program_section_outcome(
            program, staged_obj
        )
        if section_outcome:
            return section_outcome
        return _map_set_outcome(manifest, staged_obj, adapted_path)
    return (
        list(report.structural)
        + list(report.unsupported)
        + list(report.license)
    )


def _program_section_outcome(program,
                             staged_obj: str) -> list[Diagnostic]:
    """Reject an object built for the wrong manifest program.

    The adapter emits the entry symbol's section from the
    audited source, so a source whose entry disagrees with the
    manifest program builds an object carrying another program
    section. The declared section must be present; anything else
    fails closed here (``MBPF216``) instead of publishing a
    mislabeled artifact that disagrees with its manifest.
    """
    try:
        sections = object_section_names(staged_obj)
    except InspectionError as exc:
        return [exc.diagnostic]
    if program.section in sections:
        return []
    return [
        Diagnostic(
            code="MBPF216",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built object %r carries program sections %s but "
                "manifest program entry %r declares section %r"
                % (
                    staged_obj,
                    sorted(set(sections)),
                    program.entry,
                    program.section,
                )
            ),
            location=staged_obj,
            remedy="build the source whose entry matches manifest "
            "program entry %r; wider shapes need a reviewed route"
            % (program.entry,),
        )
    ]


def _core_flag_outcome(manifest, staged_obj: str) -> list[Diagnostic]:
    """Reject relocation records the manifest does not match.

    Requested CO-RE relocations must be present and present
    relocations must be requested: only the core program shape
    emits ``.BTF.ext`` records, so a manifest asking for CO-RE
    without a core program, or a core program under a manifest
    that does not ask, fails closed here (``MBPF216``) instead of
    publishing an artifact that disagrees with its manifest.
    """
    try:
        carries = object_has_btf_ext(staged_obj)
    except InspectionError as exc:
        return [exc.diagnostic]
    if manifest.target.core == carries:
        return []
    if manifest.target.core:
        explanation = (
            "manifest requests CO-RE relocations but built object "
            "%r carries no .BTF.ext records" % (staged_obj,)
        )
        remedy = "build a core program shape under this manifest"
    else:
        explanation = (
            "built object %r carries CO-RE relocation records the "
            "manifest did not request" % (staged_obj,)
        )
        remedy = "set target.core = true under a CO-RE profile, or "
        "build a non-core program shape"
    return [
        Diagnostic(
            code="MBPF216",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location=staged_obj,
            remedy=remedy,
        )
    ]


def _spill_gate_outcome(
    llc_execution: AdmittedExecution,
    adapted_path: str,
    staged_obj: str,
    timeout_s: int,
    workdir: str,
    entry: str,
    commands: list[CommandRecord],
    spawn_env: dict[str, str] | None = None,
    spawn_unset: tuple[str, ...] | None = None,
    snapshot: BuildSnapshot | None = None,
) -> Diagnostic | None:
    """Enforce stack ownership on map-mode programs.

    Classifier programs carry no fixed stack slots, so only adapted
    IR with lowered helper calls is gated. Gated objects must pass
    both conjuncts, else they fail closed with MBPF107 and are
    never published:

    1. the backend allocates no stack frame for the adapted IR (the
       MIR frame is empty after prologue/epilogue lowering, so no
       compiler-placed slot can collide with the fixed key and value
       slots);
    2. the program section carries exactly the qualified
       add-immediate multiset for its (family, entries) shape (the
       audited stack-slot offsets plus the shape's proven
       arithmetic: the round-trip increments for map objects, the
       increment and guard bound for combined objects, slot
       traffic only for delete probes, the filter slots plus the
       count increment for the tracepoint counter, the filter
       slots plus the count increment for the uprobe register
       counter, the event
       buffer and pair slots plus the three pair increments for
       the event emitter, the pair slots plus the three pair
       increments without scratch-buffer offsets for the
       reservation emitter, the single key slot for the core probe).
    """
    try:
        with open(adapted_path, "r", encoding="utf-8") as handle:
            adapted_text = handle.read()
    except (OSError, UnicodeDecodeError):
        return _step_failure(
            STAGE_BUILD_BACKEND,
            "cannot read adapted IR for the spill gate: %r"
            % (adapted_path,),
            adapted_path,
            "check the adapter service output",
        )
    shape = _adapted_shape(adapted_text)
    if shape is not None and shape[0] == "classifier":
        return None
    if shape is None:
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built object %r has an unrecognized helper-call "
                "shape, so spill freedom cannot be established"
                % (staged_obj,)
            ),
            location=staged_obj,
            remedy=(
                "build only the reviewed program shapes; objects "
                "outside them are never published"
            ),
        )
    family, entries, _percpu = shape
    want_imms = QUALIFIED_SHAPE_IMMS.get((family, entries))
    if want_imms is None:
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built object %r has the %s shape over %d "
                "entries, which has no qualified add-immediate "
                "multiset, so spill freedom cannot be established"
                % (staged_obj, family, entries)
            ),
            location=staged_obj,
            remedy=(
                "build only the reviewed program shapes; objects "
                "outside them are never published"
            ),
        )
    want_imms = list(want_imms)
    mir_path = os.path.join(workdir, "%s.mir" % entry)
    record, _stdout, _stderr, _saw = _run_step(
        [
            llc_execution.argv_prefix[0],
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-stop-after=prologepilog",
            adapted_path,
            "-o",
            mir_path,
        ],
        STAGE_BUILD_BACKEND,
        timeout_s,
        os.path.join(workdir, "%s.mir.log" % entry),
        workdir,
        execution=llc_execution,
        env_extra=spawn_env,
        env_unset=spawn_unset,
    )
    commands.append(
        record if snapshot is None
        else _display_record(record, snapshot)
    )
    if record.status != STATUS_OK or not os.path.isfile(mir_path):
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "cannot establish spill freedom for %s object %r: "
                "the MIR frame dump failed (status %s)"
                % (family, staged_obj, record.status)
            ),
            location=staged_obj,
            remedy=(
                "rebuild with the pinned backend; objects whose "
                "frame cannot be established are never published"
            ),
        )
    try:
        with open(mir_path, "r", encoding="utf-8") as handle:
            mir_text = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "cannot establish spill freedom for %s object %r: "
                "cannot read the MIR frame dump: %s"
                % (family, staged_obj, exc)
            ),
            location=staged_obj,
            remedy=(
                "rebuild with the pinned backend; objects whose "
                "frame cannot be established are never published"
            ),
        )
    if not _MIR_FIXEDSTACK_EMPTY_RE.search(
        mir_text
    ) or not _MIR_STACK_EMPTY_RE.search(mir_text):
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built %s object leaves the qualified shape: the "
                "backend allocated a stack frame for %r, which may "
                "collide with the fixed key and value slots"
                % (family, staged_obj)
            ),
            location=staged_obj,
            remedy=(
                "keep the %s program within the qualified shape; "
                "only frameless %s objects are published"
                % (family, family)
            ),
        )
    try:
        with open(staged_obj, "rb") as handle:
            image = handle.read()
    except OSError as exc:
        return _step_failure(
            STAGE_BUILD_BACKEND,
            "cannot read built object for the spill gate: %s" % exc,
            staged_obj,
            "check the backend step output",
        )
    if family in ("tracepoint", "event", "reserve"):
        gate_section = TRACEPOINT_GATE_SECTION
    elif family == "uprobe":
        gate_section = UPROBE_GATE_SECTION
    else:
        gate_section = XDP_GATE_SECTION
    section_name = gate_section.decode("ascii")
    imms = _section_add_immediates(image, gate_section)
    if imms is None:
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built %s object is not a parseable ELF object "
                "with section %r: %r"
                % (family, section_name, staged_obj)
            ),
            location=staged_obj,
            remedy=(
                "rebuild with the pinned backend; unparseable "
                "objects are never published"
            ),
        )
    if imms != want_imms:
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built %s object leaves the qualified shape: %s "
                "add-immediate set %r, expected %r"
                % (family, section_name, imms, want_imms)
            ),
            location=staged_obj,
            remedy=(
                "keep the %s program within the qualified shape; "
                "only the proven object layout is published" % (family,)
            ),
        )
    return None


def _run_adapter(
    request: BuildRequest,
    manifest,
    workdir: str,
    entry: str,
    raw_path: str,
    adapter_dir: str,
    diagnostics: list[Diagnostic],
    commands: list[CommandRecord],
    adapter_execution: AdmittedExecution,
    staged_manifest: str | None = None,
    spawn_env: dict[str, str] | None = None,
    spawn_unset: tuple[str, ...] | None = None,
    snapshot: BuildSnapshot | None = None,
    native_bundle: native_module.AdmittedNativeBundle | None = None,
    native_input: _NativeInputSeal | None = None,
) -> str | None:
    """Run the adapter service; return the adapted IR path or None."""
    try:
        os.makedirs(adapter_dir, exist_ok=True)
    except OSError as exc:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_ADAPTER,
                "cannot create adapter directory: %s" % exc,
                adapter_dir,
                "use a writable work_parent directory",
            )
        )
        return None
    request_path = os.path.join(workdir, "%s.adapter-request.json" % entry)
    response_path = os.path.join(
        workdir, "%s.adapter-response.json" % entry
    )
    document = {
        "schema_version": ADAPTER_REQUEST_VERSION,
        "input_ir": raw_path,
        "manifest_path": (
            staged_manifest
            if staged_manifest is not None
            else request.manifest_path
        ),
        "profile_id": manifest.target.profile,
        "output_dir": adapter_dir,
        "diagnostic_mode": "text",
    }
    try:
        with open(request_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_ADAPTER,
                "cannot write adapter request: %s" % exc,
                request_path,
                "use a writable work_parent directory",
            )
        )
        return None
    env_redirect = None
    if native_bundle is not None:
        try:
            if snapshot is None or native_input is None:
                raise native_module.NativeAdapterError("native invocation has no captured input seal")
            snapshot.verify()
            native_bundle.verify()
            readback_native_manifest(snapshot.manifest_bytes, native_input.manifest_path, native_input.manifest_sha256)
            if hashlib.sha256(native_module._read(raw_path, native_module.MAX_IR)).hexdigest() != native_input.input_ir_sha256:
                raise native_module.NativeAdapterError("native IR changed before bridge", "MBPF106", "build.inputs")
            env_redirect = {native_module.ADMISSION_ENV: native_bundle.pins_bytes.decode("ascii")}
        except (InputError, native_module.NativeAdapterError) as exc:
            diagnostics.append(_native_failure(exc))
            return None
    record, stdout, stderr, _ = _run_step(
        [
            sys.executable,
            request.adapter_path,
            "--request",
            request_path,
            "--response",
            response_path,
        ],
        STAGE_BUILD_ADAPTER,
        request.timeout_s,
        os.path.join(workdir, "%s.adapter.log" % entry),
        workdir,
        execution=adapter_execution,
        env_extra=spawn_env,
        # The new carrier belongs only to a captured native selection. Clear
        # ambient values before the native-only derived overlay is applied.
        env_unset=(None if spawn_unset is None else
                   tuple(spawn_unset) + (native_module.ADMISSION_ENV,)),
        env_redirect=env_redirect,
    )
    commands.append(
        record if snapshot is None
        else _display_record(record, snapshot)
    )
    if native_bundle is not None:
        try:
            snapshot.verify()
            native_bundle.verify()
            readback_native_manifest(snapshot.manifest_bytes, native_input.manifest_path, native_input.manifest_sha256)
            if "...[capture truncated " in stdout + stderr:
                raise native_module.NativeAdapterError("native bridge output capture was truncated")
        except (InputError, native_module.NativeAdapterError) as exc:
            diagnostics.append(_native_failure(exc))
            return None
    if record.status == STATUS_TIMEOUT:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_ADAPTER,
                "adapter step timed out after %.1fs" % record.duration_s,
                response_path,
                "check the adapter service script",
            )
        )
        return None
    if record.status == STATUS_SPAWN_FAILED:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_ADAPTER,
                "adapter step could not start: %s" % record.log_excerpt,
                request.adapter_path,
                "check the Python interpreter and adapter script",
            )
        )
        return None
    if record.exit_code not in (0, 1):
        # Only exits 0 (success) and 1 (reported failure) carry a
        # trustworthy response; anything else (crash, signal, exit 2)
        # must not read a possibly stale response file.
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="adapter exited %s without a trustworthy "
                "response" % (record.exit_code,),
                location=response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    if record.status != STATUS_OK and record.exit_code == 0:
        # A pipe reader errored on a step the tool reports as
        # successful: the response file is not trusted. (Exit 1 is
        # already a failure verdict, handled through the response.)
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="adapter step failed to capture its output "
                "(a pipe reader errored), so the response file is not "
                "trusted",
                location=response_path,
                remedy="retry the build; the step log names the "
                "failing stream",
            )
        )
        return None
    try:
        if native_bundle is not None:
            response = native_module.strict_json(native_module._read(response_path))
        else:
            with open(response_path, "r", encoding="utf-8") as handle:
                response = json.load(handle)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="adapter produced no usable response "
                "(exit %s): %s" % (record.exit_code, exc),
                location=response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    return _interpret_response(
        response, response_path, diagnostics,
        exit_code=record.exit_code, adapter_dir=adapter_dir,
        native=native_bundle is not None,
    )


def _interpret_response(
    response: object, response_path: str,
    diagnostics: list[Diagnostic], *, exit_code: int | None,
    adapter_dir: str,
    native: bool = False,
) -> str | None:
    """Validate an adapter response; return the adapted IR path or None.

    The exit code, the ``ok`` flag and the diagnostics must agree
    (exit 0 with a clean success, exit 1 with a reported failure);
    any contradiction fails with ``MBPF212``. A successful output
    must name an existing file inside this invocation's adapter
    directory, so a stale or foreign path can never be trusted.
    """
    if native:
        try:
            native_module._object(response, {"schema_version", "ok", "outputs", "diagnostics"}, "native v1 response")
            native_module._diagnostics(response["diagnostics"])
            native_module._object(response["outputs"], {"adapted_ir"} if response["ok"] is True else set(), "native v1 outputs")
        except native_module.NativeAdapterError as exc:
            diagnostics.append(Diagnostic(code="MBPF212", stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR, explanation=str(exc), location=response_path,
                remedy="use the matching strict native service"))
            return None
    if not isinstance(response, dict):
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="malformed adapter response: not an object",
                location=response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    version = response.get("schema_version")
    if not is_int(version) or version != ADAPTER_REQUEST_VERSION:
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="malformed adapter response: unsupported "
                "schema_version %r" % (version,),
                location="%s: schema_version" % response_path,
                remedy="use the matching adapter service",
            )
        )
        return None
    ok = response.get("ok")
    if not isinstance(ok, bool):
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="malformed adapter response: ok is not "
                "a boolean",
                location="%s: ok" % response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    entries = response.get("diagnostics")
    if not isinstance(entries, list):
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="malformed adapter response: diagnostics is "
                "not a list",
                location="%s: diagnostics" % response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    propagated: list[Diagnostic] = []
    for item in entries:
        try:
            propagated.append(_response_diagnostic(item))
        except (ValueError, TypeError, KeyError):
            diagnostics.append(
                Diagnostic(
                    code="MBPF212",
                    stage=STAGE_BUILD_ADAPTER,
                    severity=SEVERITY_ERROR,
                    explanation="malformed adapter response: invalid "
                    "diagnostic entry",
                    location="%s: diagnostics" % response_path,
                    remedy="check the adapter service script",
                )
            )
            return None
    consistent = (exit_code == 0 and ok) or (
        exit_code == 1 and not ok
    )
    if not consistent:
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="contradictory adapter outcome: exit %s "
                "with ok=%s" % (exit_code, ok),
                location=response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    if not ok:
        if not propagated:
            diagnostics.append(
                Diagnostic(
                    code="MBPF212",
                    stage=STAGE_BUILD_ADAPTER,
                    severity=SEVERITY_ERROR,
                    explanation="adapter reported failure without "
                    "diagnostics",
                    location=response_path,
                    remedy="check the adapter service script",
                )
            )
        else:
            diagnostics.extend(propagated)
        return None
    errors = [
        item for item in propagated if item.severity == SEVERITY_ERROR
    ]
    if errors:
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="contradictory adapter outcome: ok=true "
                "with %d error diagnostic(s)" % len(errors),
                location="%s: diagnostics" % response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    outputs = response.get("outputs")
    if not isinstance(outputs, dict):
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="malformed adapter response: outputs is not "
                "an object",
                location="%s: outputs" % response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    adapted = outputs.get("adapted_ir")
    staged_root = os.path.realpath(adapter_dir)
    inside = (
        isinstance(adapted, str)
        and os.path.isfile(adapted)
        and (
            os.path.realpath(adapted) == staged_root
            or os.path.realpath(adapted).startswith(
                staged_root + os.sep
            )
        )
    )
    if not inside:
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="adapter reported success without a usable "
                "adapted_ir output inside this invocation's staging "
                "directory",
                location="%s: outputs.adapted_ir" % response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    diagnostics.extend(propagated)
    return adapted
