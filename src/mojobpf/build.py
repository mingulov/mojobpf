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
the supported export roots and map names (``MBPF213``/``214``/
``215``), validates the license declaration pair and the source
grants (``MBPF70x``), admits ``mojo`` and ``llc`` against the pinned
lockfile (``MBPF102``/``103``/``104``), and seals every input hash.
Only the admitted binaries run. After the backend step, map-mode
objects pass a spill gate -- an empty backend stack frame plus the
mode's qualified add-immediate shape (``MBPF107``) -- and every
object passes inspection (structural, unsupported-feature and
declaration findings) plus the emitted-versus-declared map
reconciliation: map names and, for map-mode objects, the entry
count the program mode requires (``MBPF216``) before anything is
published.

Failure safety: objects are staged in the work directory and the
complete generation -- objects plus the ``<artifact>.evidence.json``
provenance sidecar, whose inputs are verified against the setup
seal -- is published through one atomic transaction. A failed build
leaves the output directory untouched and reports ``success=False``
with empty artifacts, so a stale object can never be reported as a
new success. On interruption (``KeyboardInterrupt``) the running
child is killed, the work directory is removed, and the exception is
re-raised; interrupted builds are never reported at all.

The build path needs no privilege and runs no load, attach, run or
kernel operation: the only subprocesses are the frontend, the adapter
(a plain ``sys.executable`` file-to-file transform) and the backend
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

Frontend rule: the packaged SDK import path (resolved through this
package's own resources, never the caller's working directory) is
passed with ``-I`` when the manifest declares maps or when the
program sources (transitively, reusing import discovery) import SDK
modules. Builds with neither keep byte-identical behavior: no ``-I``,
no SDK capture, unchanged flags and cache keys. Object names are
deterministic: one program builds ``<artifact>.bpf.o``; several
programs build ``<artifact>.<entry>.bpf.o`` each.

New diagnostic codes (all ``error``):

* ``MBPF106``: a build step failed (missing SDK, tool crash, nonzero
  exit, timeout, error marker on stderr, output capture failure,
  publish failure).
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
  supports.
* ``MBPF216``: a built object's emitted maps, or their entry
  counts, disagree with the manifest's declared maps (two entries
  in one map are still one map; only the count is reconciled).

New stages: ``build.setup``, ``build.frontend``, ``build.adapter``,
``build.backend``, ``build.publish``.

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
from dataclasses import dataclass

from . import __version__ as TOOL_VERSION
from .diagnostics import (
    Diagnostic,
    SEVERITY_ERROR,
)
from .inspect import (
    InspectionError,
    object_map_names,
    object_map_specs,
    validate_declaration_pair,
    validate_source_grants,
    verify_object,
)
from .manifest import (
    ManifestError,
    ProfileError,
    _is_int,
    lookup_profile,
    parse_manifest,
    profile_digest,
)
from .sdk import SDK_VERSION
from .toolchain import ToolInfo, admit_tools

BUILD_SCHEMA_VERSION = 1

# Version of the JSON documents exchanged with the adapter service.
# Must equal ``ADAPTER_SCHEMA_VERSION`` there; the suites check this by
# loading both files.
ADAPTER_REQUEST_VERSION = 1

STAGE_BUILD_SETUP = "build.setup"
STAGE_BUILD_FRONTEND = "build.frontend"
STAGE_BUILD_ADAPTER = "build.adapter"
STAGE_BUILD_BACKEND = "build.backend"
STAGE_BUILD_PUBLISH = "build.publish"

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_TIMEOUT = "timeout"
STATUS_SPAWN_FAILED = "spawn_failed"

DEFAULT_TIMEOUT_S = 600

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
# literals must equal the adapter's emitted entry symbol and map
# symbol; the suites cross-check this by loading both files.
SUPPORTED_ENTRY_ROOTS = ("xdp_entry",)
SUPPORTED_MAP_NAMES = ("mojobpf_map0",)

# Transform names attested in build evidence, in pipeline order.
BUILD_TRANSFORMS = ("mojo-frontend", "ir-adapter", "llc-backend")

# Adapter implementation files sealed with the build: the service
# wrapper itself (always) plus these sibling modules when present
# next to it (the exact-match adapter cannot run without them).
ADAPTER_SIBLING_FILES = ("mojo_ir_adapter.py", "audit.py")

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
)

# Inline-assembly marker identifying per-CPU adapted IR: the kind
# tag shape in compiler/audit.py ties the loaded map address to
# its result through an empty template. Array programs carry no
# such line; per-CPU programs carry one per map-address load.
KINDTAG_MARKER = 'call i64 asm "", "=r,0"(i64 %'

# Map-type bounds the reconciliation accepts per manifest map type:
# 2 is the array map type, 6 the per-CPU array map type.
MAP_TYPE_IDS = {"array": 2, "percpu_array": 6}

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

# Qualified (family, entries) -> add-immediate multiset. The spill
# gate publishes only shapes listed here with kernel-observed
# behavior in both map kinds; anything else fails closed. The
# immediates are kind-blind (per-CPU kind tags emit no code), so
# array and per-CPU programs share each entry. There is no
# iteration family: the kernel offers no from-program
# map-iteration helper.
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
}

_BPF_ADD64_IMM = 0x07
_BPF_LD_IMM64 = 0x18


@dataclass(frozen=True)
class BuildRequest:
    """Inputs for :func:`build_project`.

    ``manifest_path`` points at the project manifest, ``out_dir`` is
    the directory receiving the built objects (created when missing),
    and ``adapter_path`` points at the adapter service script (an
    explicit path: the driver never guesses tool locations).
    ``lockfile_path`` points at the pinned toolchain lockfile;
    ``mojo`` and ``llc`` are admitted against it before anything
    compiles, and only the admitted binaries run (a missing lockfile
    fails the build with ``MBPF104``).
    ``search_paths`` are prepended to ``PATH`` when resolving ``mojo``
    and ``llc``. ``timeout_s`` bounds every build subprocess.
    ``save_temps`` keeps the per-build work directory for inspection.
    ``work_parent`` optionally parents the work directory. Relative
    paths resolve against the caller's working directory when the
    build starts; results always carry absolute paths.
    """

    manifest_path: str
    out_dir: str
    adapter_path: str
    schema_version: int = BUILD_SCHEMA_VERSION
    search_paths: tuple[str, ...] = ()
    timeout_s: int = DEFAULT_TIMEOUT_S
    save_temps: bool = False
    work_parent: str | None = None
    lockfile_path: str | None = None

    def __post_init__(self) -> None:
        if not _is_int(self.schema_version) or (
            self.schema_version != BUILD_SCHEMA_VERSION
        ):
            raise ValueError(
                "unsupported BuildRequest schema_version %r; "
                "this driver reads version %d"
                % (self.schema_version, BUILD_SCHEMA_VERSION)
            )
        if not _is_int(self.timeout_s) or self.timeout_s < 1:
            raise ValueError(
                "timeout_s must be a positive integer, got %r"
                % (self.timeout_s,)
            )
        object.__setattr__(self, "search_paths", tuple(self.search_paths))


@dataclass(frozen=True)
class CommandRecord:
    """One subprocess run inside a build.

    ``status`` is ``"ok"``, ``"failed"``, ``"timeout"`` or
    ``"spawn_failed"``. ``exit_code`` is ``None`` when the process
    never exited normally. ``duration_s`` measures the run.
    ``log_excerpt`` is the bounded tail of the step's stderr.
    """

    argv: tuple[str, ...]
    stage: str
    status: str
    exit_code: int | None
    duration_s: float
    log_excerpt: str


@dataclass(frozen=True)
class BuildArtifact:
    """One published build output.

    ``role`` names the artifact kind (``"object"`` for built
    objects, ``"evidence"`` for the provenance sidecar).
    ``path`` is the final published location, ``sha256`` its content
    hash, ``size`` its byte length.
    """

    role: str
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class BuildProvenance:
    """How a build was specified and with what tools.

    ``source_files`` and ``source_sha256`` run parallel in manifest
    program order. ``mojo_version``/``mojo_sha256`` and
    ``llc_version``/``llc_sha256`` identify the admitted tool
    binaries (version line plus binary hash from lockfile
    admission). ``tool_version``/``sdk_version`` stamp the
    mojobpf tool and Mojo SDK versions that ran the build.
    """

    manifest_path: str
    manifest_sha256: str
    profile_id: str
    source_files: tuple[str, ...]
    source_sha256: tuple[str, ...]
    adapter_path: str
    adapter_sha256: str
    mojo_version: str
    llc_version: str
    mojo_sha256: str
    llc_sha256: str
    tool_version: str
    sdk_version: str


@dataclass(frozen=True)
class BuildResult:
    """Versioned outcome of :func:`build_project`.

    ``success`` is true only when every program built and published.
    ``diagnostics`` holds every finding in deterministic order (empty
    on a clean success). ``artifacts`` holds the published objects (empty
    unless successful). ``provenance`` describes the attempted build,
    or ``None`` when the failure precedes it. ``commands`` holds one
    record per subprocess run. ``work_dir`` is the kept work directory
    under ``save_temps``, else ``None``.
    """

    schema_version: int
    success: bool
    diagnostics: tuple[Diagnostic, ...]
    artifacts: tuple[BuildArtifact, ...]
    provenance: BuildProvenance | None
    commands: tuple[CommandRecord, ...]
    work_dir: str | None = None


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
    """Admitted tools and sealed input hashes for one build.

    Produced before the work directory exists: every input the
    pipeline will read is hashed here, and only the admitted tool
    binaries run. The evidence capture re-reads the same files and
    rejects any hash drift against this seal.
    """

    tool_paths: dict[str, str]
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
    """
    start = time.monotonic()
    deadline = start + timeout_s
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,
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
    manifest. More than one map is likewise unsupported
    (``MBPF215``): the route emits at most the single declared map.
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
    if len(manifest.maps) > 1:
        return Diagnostic(
            code="MBPF215",
            stage=STAGE_BUILD_SETUP,
            severity=SEVERITY_ERROR,
            explanation=(
                "manifest declares %d maps; this route supports at "
                "most one" % len(manifest.maps)
            ),
            location="%s: maps" % manifest.manifest_path,
            remedy="declare at most one map; wider shapes need a "
            "reviewed route",
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


def _enumerate_sdk_files(sdk_dir: str) -> tuple[str, ...]:
    """List every regular file under the SDK directory, sorted."""
    found: list[str] = []
    for root, dirs, files in os.walk(sdk_dir):
        dirs.sort()
        for name in sorted(files):
            candidate = os.path.join(root, name)
            if os.path.isfile(candidate):
                found.append(candidate)
    return tuple(found)


_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_.]*)|import\s+([A-Za-z_]"
    r"[A-Za-z0-9_.]*))"
)


def _imported_modules(source: str) -> list[str]:
    """Dotted module names imported by one Mojo source.

    Best-effort single-line scan of ``from``/``import`` statements;
    comments are stripped before matching. Unreadable files yield no
    names.
    """
    try:
        with open(source, "r", encoding="utf-8",
                  errors="replace") as handle:
            text = handle.read()
    except OSError:
        return []
    names: list[str] = []
    for line in text.splitlines():
        match = _IMPORT_LINE_RE.match(line.split("#", 1)[0])
        if match:
            names.append(match.group(1) or match.group(2))
    return names


def _resolves_to_sdk(module: str, sdk_dir: str) -> bool:
    """Whether a dotted module is provided by the packaged SDK."""
    segments = module.split(".")
    return any(
        os.path.isfile(path)
        for path in (
            os.path.join(sdk_dir, *segments) + ".mojo",
            os.path.join(sdk_dir, segments[0]) + ".mojo",
        )
    )


def _discover_imports(source_files: tuple[str, ...], manifest_dir: str,
                      sdk_dir: str) -> tuple[str, ...]:
    """Find non-SDK Mojo modules imported by the program sources.

    Best-effort single-line scan of ``from``/``import`` statements;
    each dotted module resolves to the first existing ``.mojo`` file
    beside the importing source or under the manifest directory.
    Discovery follows imports transitively to a fixpoint (import
    cycles terminate: each file is scanned once), so the sealed set
    is the complete resolved dependency graph below the sources.
    Modules resolving into the SDK are already covered by the
    wholesale SDK capture and skipped; unresolvable names (standard
    library, builtins) are ignored. Every captured file is sealed
    and hashed into the evidence.
    """
    def _scan(source: str) -> list[str]:
        found: list[str] = []
        source_dir = os.path.dirname(source)
        for module in _imported_modules(source):
            segments = module.split(".")
            candidates = [
                os.path.join(source_dir, *segments) + ".mojo",
                os.path.join(manifest_dir, *segments) + ".mojo",
            ]
            if len(segments) > 1:
                candidates += [
                    os.path.join(source_dir, segments[0]) + ".mojo",
                    os.path.join(manifest_dir, segments[0]) + ".mojo",
                ]
            if _resolves_to_sdk(module, sdk_dir):
                continue
            for candidate in candidates:
                if os.path.isfile(candidate):
                    found.append(os.path.realpath(candidate))
                    break
        return found

    discovered: dict[str, None] = {}
    scanned: set[str] = set()
    queue = list(source_files)
    while queue:
        source = queue.pop(0)
        try:
            identity = os.path.realpath(source)
        except OSError:
            continue
        if identity in scanned:
            continue
        scanned.add(identity)
        for resolved in _scan(source):
            if resolved not in discovered and resolved not in scanned:
                discovered[resolved] = None
                queue.append(resolved)
    return tuple(sorted(discovered))


def _imports_sdk_modules(sources: tuple[str, ...], sdk_dir: str) -> bool:
    """Whether any source imports a module the packaged SDK provides.

    Reuses the import-discovery scan and SDK resolution; callers pass
    the program sources plus their discovered transitive imports so
    an SDK import through a local helper counts too.
    """
    return any(
        _resolves_to_sdk(module, sdk_dir)
        for source in sources
        for module in _imported_modules(source)
    )


def _setup_inputs(
    request: BuildRequest, manifest,
    diagnostics: list[Diagnostic],
) -> _SetupSeal | None:
    """Run every pre-compilation gate; seal inputs on success.

    Check order is fixed: manifest reconciliation (``MBPF213``/
    ``214``/``215``), target-profile resolution (``MBPF101``),
    declaration-pair validation (``MBPF701``/``703``/``704``),
    source-grant validation (``MBPF702``/``703``/``707``), then
    toolchain admission (``MBPF102``/``103``/``104``). On success
    every input file is hashed into the seal alongside the profile
    implementation digest. Returns ``None`` after appending the
    first failure.
    """
    mismatch = _reconcile_manifest(manifest)
    if mismatch is not None:
        diagnostics.append(mismatch)
        return None
    try:
        resolved_profile = lookup_profile(manifest.target.profile)
    except ProfileError as exc:
        diagnostics.append(exc.diagnostic)
        return None
    profile_sha = profile_digest(resolved_profile)
    try:
        validate_declaration_pair(
            manifest.artifact.source_license,
            manifest.artifact.kernel_license,
        )
    except InspectionError as exc:
        diagnostics.append(exc.diagnostic)
        return None

    manifest_dir = os.path.dirname(os.path.abspath(request.manifest_path))
    try:
        manifest_sha = _sha256_file(request.manifest_path)
    except OSError as exc:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "cannot hash manifest: %s" % exc,
                request.manifest_path,
                "check the manifest path and file permissions",
            )
        )
        return None
    source_files: list[str] = []
    source_shas: list[str] = []
    for program in manifest.programs:
        resolved = os.path.realpath(
            os.path.join(manifest_dir, program.source)
        )
        source_files.append(resolved)
        try:
            source_shas.append(_sha256_file(resolved))
        except OSError as exc:
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_SETUP,
                    "cannot hash program source %r: %s"
                    % (program.source, exc),
                    resolved,
                    "check the program source file",
                )
            )
            return None

    sdk_dir = _sdk_dir()
    # Import discovery runs before the SDK capture so the -I gate
    # can see transitive SDK imports; it is a pure function of the
    # source files and emits no diagnostics of its own.
    import_files = _discover_imports(
        tuple(source_files), manifest_dir, sdk_dir
    )
    sdk_needed = bool(manifest.maps) or _imports_sdk_modules(
        tuple(source_files) + import_files, sdk_dir
    )
    sdk_files: tuple[str, ...] = ()
    if sdk_needed:
        if not os.path.isdir(sdk_dir):
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_SETUP,
                    "SDK directory missing: %s" % sdk_dir,
                    sdk_dir,
                    "reinstall the mojobpf package; the SDK resolves "
                    "through package resources",
                )
            )
            return None
        try:
            sdk_files = _enumerate_sdk_files(sdk_dir)
        except OSError as exc:
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_SETUP,
                    "cannot enumerate SDK directory %s: %s"
                    % (sdk_dir, exc),
                    sdk_dir,
                    "reinstall the mojobpf package; the SDK resolves "
                    "through package resources",
                )
            )
            return None
    try:
        validate_source_grants(
            manifest.artifact.source_license,
            source_files,
            sdk_files,
            project_dir=manifest_dir,
        )
    except InspectionError as exc:
        diagnostics.append(exc.diagnostic)
        return None

    admitted: dict[str, ToolInfo]
    admitted, admission_diags = admit_tools(
        lockfile_path=request.lockfile_path,
        search_paths=request.search_paths,
        names=REQUIRED_BUILD_TOOLS,
    )
    if not admitted:
        diagnostics.extend(admission_diags)
        return None

    adapter_files = [request.adapter_path]
    adapter_dir = os.path.dirname(request.adapter_path)
    for sibling in ADAPTER_SIBLING_FILES:
        candidate = os.path.join(adapter_dir, sibling)
        if os.path.isfile(candidate):
            adapter_files.append(candidate)

    def _seal(paths: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
        entries = []
        for path in paths:
            entries.append(
                (os.path.realpath(path), _sha256_file(path))
            )
        return tuple(entries)

    try:
        sdk_seal = _seal(sdk_files)
        import_seal = _seal(import_files)
        adapter_seal = _seal(tuple(adapter_files))
    except OSError as exc:
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
            name: admitted[name].path for name in REQUIRED_BUILD_TOOLS
        },
        versions={
            name: admitted[name].version for name in REQUIRED_BUILD_TOOLS
        },
        tool_shas={
            name: admitted[name].sha256 for name in REQUIRED_BUILD_TOOLS
        },
        profile_sha256=profile_sha,
        manifest_sha=manifest_sha,
        source_files=tuple(source_files),
        source_shas=tuple(source_shas),
        sdk_files=sdk_files,
        sdk_needed=sdk_needed,
        import_files=import_files,
        adapter_files=tuple(adapter_files),
        sdk_seal=sdk_seal,
        import_seal=import_seal,
        adapter_seal=adapter_seal,
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


def _build_inside(
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
    sdk_dir = _sdk_dir()
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
    )

    staged: list[tuple[str, str]] = []
    multi = len(manifest.programs) > 1
    for program, source_abs in zip(manifest.programs, seal.source_files):
        entry = program.entry
        raw_path = os.path.join(workdir, "%s.raw.ll" % entry)
        adapter_dir = os.path.join(workdir, "%s.adapter" % entry)
        staged_obj = os.path.join(workdir, "%s.bpf.o" % entry)
        if multi:
            final_name = "%s.%s.bpf.o" % (manifest.artifact.name, entry)
        else:
            final_name = "%s.bpf.o" % manifest.artifact.name

        frontend_argv = [
            tool_paths["mojo"],
            "build",
            "--emit",
            "llvm",
        ]
        if seal.sdk_needed:
            frontend_argv += ["-I", sdk_dir]
        frontend_argv += ["-o", raw_path, source_abs]
        record, _, stderr, saw_marker = _run_step(
            frontend_argv,
            STAGE_BUILD_FRONTEND,
            request.timeout_s,
            os.path.join(workdir, "%s.frontend.log" % entry),
            workdir,
            STDERR_ERROR_MARKER,
        )
        commands.append(record)
        failure = _step_outcome(
            record, raw_path, "frontend", STDERR_ERROR_MARKER, stderr,
            saw_marker,
        )
        if failure is not None:
            diagnostics.append(failure)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )

        adapted_path = _run_adapter(
            request, manifest, workdir, entry, raw_path, adapter_dir,
            diagnostics, commands,
        )
        if adapted_path is None:
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )

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
        )
        commands.append(record)
        failure = _step_outcome(
            record, staged_obj, "backend", STDERR_ERROR_MARKER, stderr,
            saw_marker,
        )
        if failure is not None:
            diagnostics.append(failure)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        gate = _spill_gate_outcome(
            tool_paths["llc"], adapted_path, staged_obj,
            request.timeout_s, workdir, entry, commands,
        )
        if gate is not None:
            diagnostics.append(gate)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        inspection = _verify_gate_outcome(
            manifest, staged_obj, adapted_path
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
    final artifacts; the evidence inputs are verified against the
    setup seal before anything is published. Objects and the
    provenance sidecar move through one transaction: any failure
    leaves the output directory without a new-or-partial result.
    """
    # Imported here: evidence.py consumes BuildResult, so a
    # module-level import would cycle back into this module.
    from .evidence import (
        EvidenceError,
        SealedInputs,
        dumps_evidence,
        evidence_from_build,
        publish_artifacts,
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
            flags=_build_flags(seal.sdk_needed),
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
            expected_path,
            "fix the reported error; the log excerpt names it",
        )
    if saw_marker or marker.lower() in stderr.lower():
        return _step_failure(
            record.stage,
            "%s step reported errors: %s" % (step, " ".join(record.argv)),
            expected_path,
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


def _adapted_shape(adapted_text: str) -> tuple | None:
    """Classify adapted IR by its lowered helper-call counts.

    Returns ``(family, entries, percpu)`` with family one of
    ``"classifier"``, ``"map"``, ``"combined"``, or ``"delete"``;
    ``entries`` the dense key coverage (0 for the classifier); and
    ``percpu`` whether kind tags mark the program per-CPU. A
    two-pair program with three reinterpretations is the combined
    workload, with two the map-only pair shape; any other
    combination is unrecognized (None) and fails closed.
    """
    lookups = adapted_text.count(LOWERED_CALLEE_MARKERS[0])
    updates = adapted_text.count(LOWERED_CALLEE_MARKERS[1])
    deletes = adapted_text.count(LOWERED_CALLEE_MARKERS[2])
    percpu = KINDTAG_MARKER in adapted_text
    if lookups == 0 and updates == 0 and deletes == 0:
        if percpu:
            return None
        return ("classifier", 0, False)
    if deletes and not (lookups or updates):
        return ("delete", deletes, percpu)
    if deletes or lookups != updates or lookups < 1:
        return None
    if lookups == 2:
        reinterps = adapted_text.count('call ptr asm "", "=r,0"')
        if reinterps == 3:
            return ("combined", 2, percpu)
        if reinterps != 2:
            return None
    return ("map", lookups, percpu)


def _xdp_add_immediates(image: bytes) -> list[int] | None:
    """Sorted 64-bit add immediates of the xdp section, if parseable.

    Returns None when the image is not a well-formed little-endian
    64-bit ELF object with an xdp section, so the caller fails
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
        if image[str_off + name:end] == b"xdp":
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


def _map_entries_outcome(manifest, staged_obj: str,
                         adapted_path: str) -> list[Diagnostic]:
    """Reject a map object whose kind or count disagrees.

    The adapter emits the map kind and entry count the audited
    program shape requires (the kind tag selects array or per-CPU
    array; dense key coverage selects the count); a manifest
    declaring any other kind or count for the single map fails
    closed here (``MBPF216``), as does an object whose BTF map
    attributes disagree with the emitted shape, instead of
    publishing an artifact that disagrees with its manifest.
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
    want_kind = "percpu_array" if percpu else "array"
    # The map names matched above and a map-mode object carries
    # exactly one map, so the manifest declares exactly one here.
    declared = manifest.maps[0]
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
    return []


def _verify_gate_outcome(manifest, staged_obj: str,
                         adapted_path: str) -> list[Diagnostic]:
    """Run the pre-publication inspection gate over one object.

    Returns the report findings (structural, unsupported, license)
    when the object fails, the map disagreement (``MBPF216``) when
    the emitted maps, their kinds, or their entry counts differ
    from ``manifest.maps``, or an empty list when the object
    passes. An unreadable object fails with its own diagnostic.
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
        return _map_set_outcome(manifest, staged_obj, adapted_path)
    return (
        list(report.structural)
        + list(report.unsupported)
        + list(report.license)
    )


def _spill_gate_outcome(
    llc_path: str,
    adapted_path: str,
    staged_obj: str,
    timeout_s: int,
    workdir: str,
    entry: str,
    commands: list[CommandRecord],
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
    2. the xdp section carries exactly the qualified add-immediate
       multiset for its (family, entries) shape (the audited
       stack-slot offsets plus the shape's proven arithmetic: the
       round-trip increments for map objects, the increment and
       guard bound for combined objects, slot traffic only for
       delete probes).
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
            llc_path,
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
    )
    commands.append(record)
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
    imms = _xdp_add_immediates(image)
    if imms is None:
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built %s object is not a parseable ELF object "
                "with an xdp section: %r" % (family, staged_obj)
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
                "built %s object leaves the qualified shape: xdp "
                "add-immediate set %r, expected %r"
                % (family, imms, want_imms)
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
        "manifest_path": request.manifest_path,
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
    record, _, _, _ = _run_step(
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
    )
    commands.append(record)
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
        with open(response_path, "r", encoding="utf-8") as handle:
            response = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
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
    )


def _interpret_response(
    response: object, response_path: str,
    diagnostics: list[Diagnostic], *, exit_code: int | None,
    adapter_dir: str,
) -> str | None:
    """Validate an adapter response; return the adapted IR path or None.

    The exit code, the ``ok`` flag and the diagnostics must agree
    (exit 0 with a clean success, exit 1 with a reported failure);
    any contradiction fails with ``MBPF212``. A successful output
    must name an existing file inside this invocation's adapter
    directory, so a stale or foreign path can never be trusted.
    """
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
    if not _is_int(version) or version != ADAPTER_REQUEST_VERSION:
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
