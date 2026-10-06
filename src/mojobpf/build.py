# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unprivileged build orchestration for MojoBPF projects.

:func:`build_project` drives the validated three-step route for every
program in a manifest: the Mojo frontend (``mojo build --emit llvm``),
the versioned adapter service (``compiler/adapter_service.py`` fed one
JSON request per program), and the LLVM backend (``llc -mtriple=bpfel
-mcpu=v3 -filetype=obj``). Every subprocess runs from an argument
array (never a shell), with a timeout, bounded log excerpts, and a
per-build temporary work directory. After the backend step, map-mode
objects pass a spill gate: only the proven add-immediate shape is
published, so backend frame slots can never silently collide with
the fixed key/value stack slots.

Failure safety: objects are staged in the work directory and published
to the output directory only after every program built successfully.
A failed build leaves the output directory untouched and reports
``success=False`` with empty artifacts, so a stale object can never be
reported as a new success. On interruption (``KeyboardInterrupt``) the
running child is killed, the work directory is removed, and the
exception is re-raised; interrupted builds are never reported at all.

The build path needs no privilege and runs no load, attach, run or
kernel operation: the only subprocesses are the frontend, the adapter
(a plain ``sys.executable`` file-to-file transform) and the backend.
``bpftool`` is never invoked here.

Request and result models are versioned and frozen:

* ``BuildRequest``: manifest path, output directory, adapter path,
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
passed with ``-I`` exactly when the manifest declares maps, matching
the validated invocations. Object names are deterministic: one program
builds ``<artifact>.bpf.o``; several programs build
``<artifact>.<entry>.bpf.o`` each.

New diagnostic codes (all ``error``):

* ``MBPF106``: a build step failed (missing SDK, tool crash, nonzero
  exit, timeout, error marker on stderr, publish failure).
* ``MBPF212``: the adapter interface contract was violated (malformed
  adapter response, unusable adapter output). Propagated adapter
  diagnostics keep their own codes (``MBPF212``/``MBPF301``) and
  stages (``adapter.request``/``adapter.transform``).
* ``MBPF103``: a required build tool (``mojo``, ``llc``) is missing or
  broken, reusing the toolchain-discovery code and stage.
* ``MBPF107``: a built map-mode object leaves the qualified shape
  its spill-freedom proof covers (or cannot be parsed to check),
  so the spill gate refuses to publish it.

New stages: ``build.setup``, ``build.frontend``, ``build.adapter``,
``build.backend``, ``build.publish``.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

from .diagnostics import (
    STAGE_TOOLCHAIN_DISCOVERY,
    Diagnostic,
    SEVERITY_ERROR,
)
from .manifest import (
    ManifestError,
    ProfileError,
    _is_int,
    parse_manifest,
)

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
VERSION_TIMEOUT_S = 30

# Kept tail of a step's stderr carried in its command record; the full
# log goes to the work directory (kept under ``save_temps``).
LOG_EXCERPT_LIMIT = 4000

REQUIRED_BUILD_TOOLS = ("mojo", "llc")

# Lowered helper callee markers identifying map-mode adapted IR.
# Must equal the ``LOWERED_CALLEE`` values in compiler/audit.py; the
# pipeline suite cross-checks this by loading both files.
LOWERED_CALLEE_MARKERS = (
    "inttoptr (i64 1 to ptr)",
    "inttoptr (i64 2 to ptr)",
)

# Proven 64-bit add-immediate multiset of the qualified map object,
# in sorted order: the two audited stack-slot offsets (key -4 twice,
# value -16) plus the round-trip increment. The lowering suite pins
# the same assertion on the canonical program; the spill gate below
# enforces it in the build path.
QUALIFIED_MAP_ADD_IMMS = (-16, -4, -4, 1)

_BPF_ADD64_IMM = 0x07
_BPF_LD_IMM64 = 0x18


@dataclass(frozen=True)
class BuildRequest:
    """Inputs for :func:`build_project`.

    ``manifest_path`` points at the project manifest, ``out_dir`` is
    the directory receiving the built objects (created when missing),
    and ``adapter_path`` points at the adapter service script (an
    explicit path: the driver never guesses tool locations).
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

    ``role`` names the artifact kind (today always ``"object"``).
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
    program order. ``mojo_version`` and ``llc_version`` are the first
    lines of the tools' version probes.
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


def _search_path(search_paths: tuple[str, ...]) -> str:
    current = os.environ.get("PATH", "")
    extra = os.pathsep.join(search_paths)
    if extra and current:
        return extra + os.pathsep + current
    return extra or current


def _first_line(stdout: str, stderr: str) -> str | None:
    text = stdout if stdout.strip() else stderr
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


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


def _run_step(
    argv: list[str],
    stage: str,
    timeout_s: int,
    log_path: str,
    cwd: str,
) -> tuple[CommandRecord, str, str]:
    """Run one build subprocess; never raises for step outcomes.

    Returns the command record plus the full stdout and stderr text.
    ``KeyboardInterrupt`` kills the child and propagates (the caller
    owns cleanup). Timeouts and spawn failures become records.
    """
    start = time.monotonic()
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
        )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_step(proc)
        try:
            stdout, stderr = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.wait()
            stdout, stderr = "", ""
        duration = time.monotonic() - start
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
        )
    except KeyboardInterrupt:
        _kill_step(proc)
        try:
            proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.wait()
        raise
    duration = time.monotonic() - start
    stdout = stdout or ""
    stderr = stderr or ""
    _write_log(log_path, argv, stdout, stderr)
    status = STATUS_OK if proc.returncode == 0 else STATUS_FAILED
    return (
        CommandRecord(
            argv=tuple(argv),
            stage=stage,
            status=status,
            exit_code=proc.returncode,
            duration_s=duration,
            log_excerpt=_excerpt(stderr),
        ),
        stdout,
        stderr,
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
    )
    diagnostics: list[Diagnostic] = []
    commands: list[CommandRecord] = []

    try:
        manifest = parse_manifest(request.manifest_path)
    except (ManifestError, ProfileError) as exc:
        diagnostics.append(exc.diagnostic)
        return _fail_result(diagnostics, commands)

    search_path = _search_path(request.search_paths)
    tool_paths: dict[str, str] = {}
    for name in REQUIRED_BUILD_TOOLS:
        found = shutil.which(name, path=search_path)
        if found is None:
            diagnostics.append(
                Diagnostic(
                    code="MBPF103",
                    stage=STAGE_TOOLCHAIN_DISCOVERY,
                    severity=SEVERITY_ERROR,
                    explanation="required build tool not found on PATH: %s"
                    % name,
                    location="tool:%s" % name,
                    remedy="install %s or fix PATH; "
                    "no substitute tool is used" % name,
                )
            )
        else:
            tool_paths[name] = found
    if diagnostics:
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
        return _build_inside(request, manifest, tool_paths, workdir,
                             diagnostics, commands)
    except KeyboardInterrupt:
        _remove_tree(workdir)
        raise


def _build_inside(
    request: BuildRequest,
    manifest,
    tool_paths: dict[str, str],
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
    try:
        adapter_sha = _sha256_file(request.adapter_path)
    except OSError as exc:
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "cannot hash adapter service %r: %s"
                % (request.adapter_path, exc),
                request.adapter_path,
                "check the adapter service file",
            )
        )
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, work_dir=kept)

    sdk_dir = _sdk_dir()
    if manifest.maps and not os.path.isdir(sdk_dir):
        diagnostics.append(
            _step_failure(
                STAGE_BUILD_SETUP,
                "SDK directory missing: %s" % sdk_dir,
                sdk_dir,
                "reinstall the mojobpf package; the SDK resolves "
                "through package resources",
            )
        )
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, work_dir=kept)

    versions: dict[str, str] = {}
    for name in REQUIRED_BUILD_TOOLS:
        record, stdout, stderr = _run_step(
            [tool_paths[name], "--version"],
            STAGE_BUILD_SETUP,
            VERSION_TIMEOUT_S,
            os.path.join(workdir, "version-%s.log" % name),
            workdir,
        )
        commands.append(record)
        version = None
        if record.status == STATUS_OK:
            version = _first_line(stdout, stderr)
        if version is None:
            diagnostics.append(
                Diagnostic(
                    code="MBPF103",
                    stage=STAGE_TOOLCHAIN_DISCOVERY,
                    severity=SEVERITY_ERROR,
                    explanation="tool version probe failed for %s "
                    "(status %s)" % (name, record.status),
                    location="tool:%s" % name,
                    remedy="check the installation of %s" % name,
                )
            )
        else:
            versions[name] = version
    if diagnostics:
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, work_dir=kept)

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
        kept = _finish_workdir(request, workdir)
        return _fail_result(diagnostics, commands, work_dir=kept)
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
            kept = _finish_workdir(request, workdir)
            return _fail_result(diagnostics, commands, work_dir=kept)
    provenance = BuildProvenance(
        manifest_path=request.manifest_path,
        manifest_sha256=manifest_sha,
        profile_id=manifest.target.profile,
        source_files=tuple(source_files),
        source_sha256=tuple(source_shas),
        adapter_path=request.adapter_path,
        adapter_sha256=adapter_sha,
        mojo_version=versions["mojo"],
        llc_version=versions["llc"],
    )

    staged: list[tuple[str, str]] = []
    multi = len(manifest.programs) > 1
    for program, source_abs in zip(manifest.programs, source_files):
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
        if manifest.maps:
            frontend_argv += ["-I", sdk_dir]
        frontend_argv += ["-o", raw_path, source_abs]
        record, _, stderr = _run_step(
            frontend_argv,
            STAGE_BUILD_FRONTEND,
            request.timeout_s,
            os.path.join(workdir, "%s.frontend.log" % entry),
            workdir,
        )
        commands.append(record)
        failure = _step_outcome(
            record, raw_path, "frontend", "error:", stderr
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

        record, _, stderr = _run_step(
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
        )
        commands.append(record)
        failure = _step_outcome(
            record, staged_obj, "backend", "error:", stderr
        )
        if failure is not None:
            diagnostics.append(failure)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        gate = _spill_gate_outcome(adapted_path, staged_obj)
        if gate is not None:
            diagnostics.append(gate)
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        staged.append((staged_obj, final_name))

    artifacts: list[BuildArtifact] = []
    for staged_obj, final_name in staged:
        final_path = os.path.join(request.out_dir, final_name)
        try:
            _publish_file(staged_obj, final_path)
            size = os.path.getsize(final_path)
            sha = _sha256_file(final_path)
        except OSError as exc:
            diagnostics.append(
                _step_failure(
                    STAGE_BUILD_PUBLISH,
                    "cannot publish object %r: %s" % (final_name, exc),
                    final_path,
                    "use a writable out_dir with free space",
                )
            )
            kept = _finish_workdir(request, workdir)
            return _fail_result(
                diagnostics, commands, provenance, work_dir=kept
            )
        artifacts.append(
            BuildArtifact(
                role="object", path=final_path, sha256=sha, size=size
            )
        )

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


def _publish_file(staged_obj: str, final_path: str) -> None:
    """Publish one staged object atomically under its final name.

    The work directory may live on another filesystem than the output
    directory, so the bytes are first copied to a hidden temporary file
    inside the output directory and then renamed over the final name
    (the rename is atomic). The temporary file is removed again on any
    failure, including interruption.
    """
    out_dir = os.path.dirname(final_path) or "."
    fd, tmp_path = tempfile.mkstemp(
        dir=out_dir,
        prefix="." + os.path.basename(final_path) + ".",
        suffix=".tmp",
    )
    try:
        os.close(fd)
        shutil.copyfile(staged_obj, tmp_path)
        shutil.copymode(staged_obj, tmp_path)
        os.replace(tmp_path, final_path)
    except BaseException:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


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
) -> Diagnostic | None:
    """Classify a frontend/backend record; None means the step passed.

    The error marker is matched against the full stderr text, not the
    bounded excerpt, so a marker before a long tail still fails loudly.
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
    if record.exit_code != 0:
        return _step_failure(
            record.stage,
            "%s step exited %d: %s"
            % (step, record.exit_code, " ".join(record.argv)),
            expected_path,
            "fix the reported error; the log excerpt names it",
        )
    if marker.lower() in stderr.lower():
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


def _is_map_adapted(adapted_text: str) -> bool:
    """True when adapted IR carries both lowered helper calls."""
    return all(
        marker in adapted_text for marker in LOWERED_CALLEE_MARKERS
    )


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


def _spill_gate_outcome(
    adapted_path: str, staged_obj: str
) -> Diagnostic | None:
    """Enforce the proven object shape on map-mode programs.

    Classifier programs carry no fixed stack slots, so only adapted
    IR with both lowered helper calls is gated: its xdp section must
    carry exactly the qualified add-immediate multiset. Anything
    else fails closed with MBPF107, so an unproven object -- one
    whose backend frame slots might collide with the fixed key and
    value slots -- is never published.
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
    if not _is_map_adapted(adapted_text):
        return None
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
                "built map object is not a parseable ELF object "
                "with an xdp section: %r" % (staged_obj,)
            ),
            location=staged_obj,
            remedy=(
                "rebuild with the pinned backend; unparseable "
                "objects are never published"
            ),
        )
    if imms != list(QUALIFIED_MAP_ADD_IMMS):
        return Diagnostic(
            code="MBPF107",
            stage=STAGE_BUILD_BACKEND,
            severity=SEVERITY_ERROR,
            explanation=(
                "built map object leaves the qualified shape: xdp "
                "add-immediate set %r, expected %r"
                % (imms, list(QUALIFIED_MAP_ADD_IMMS))
            ),
            location=staged_obj,
            remedy=(
                "keep the map program within the qualified shape; "
                "only the proven object layout is published"
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
    record, _, _ = _run_step(
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
    return _interpret_response(response, response_path, diagnostics)


def _interpret_response(
    response: object, response_path: str, diagnostics: list[Diagnostic]
) -> str | None:
    """Validate an adapter response; return the adapted IR path or None."""
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
    if not isinstance(adapted, str) or not os.path.isfile(adapted):
        diagnostics.append(
            Diagnostic(
                code="MBPF212",
                stage=STAGE_BUILD_ADAPTER,
                severity=SEVERITY_ERROR,
                explanation="adapter reported success without a usable "
                "adapted_ir output",
                location="%s: outputs.adapted_ir" % response_path,
                remedy="check the adapter service script",
            )
        )
        return None
    diagnostics.extend(propagated)
    return adapted
