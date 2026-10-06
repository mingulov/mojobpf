# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Stable build provenance, cache keys and atomic publication.

:func:`evidence_from_build` derives stable :class:`Evidence` from a
finished build result: input hashes per cache class (program
sources, imported sources, SDK files, manifest, compiler identity,
flags), output hashes, applied transformations, license
declarations, normalized commands and environment entries. Stable
metadata excludes timestamps and absolute paths, so the same inputs
built in different directories serialize to identical bytes; exact
invocations, timings and log excerpts stay in the build result and
logs, never here.

:func:`cache_key` hashes the input classes into one versioned key.
Every input class participates, so changing any class invalidates
the key; reusing an object across SDK or compiler changes is a
cache miss, never a silent hit.

:func:`publish_artifacts` publishes one staged file set
all-or-nothing. Observable semantics, defined here and tested, not
merely asserted:

* success: every named file lands with its staged bytes; no
  temporary or backup file remains.
* failure: the output directory holds no new-or-partial result.
  Files already renamed by the failed call are removed, overwritten
  predecessors are restored byte-identically from backups, and
  temporary files are removed. Predecessor files from earlier
  successful publications are otherwise untouched -- and they are
  never reported as the new result, because a failed call raises
  instead of returning artifacts (nothing new is claimed).
* interruption propagates after the same rollback.
* names starting with ``.`` are never results: crash leftovers use
  that namespace and are safe to delete.

This covers error-path atomicity only; a crash between renames can
still leave backups behind, which is why the temporary namespace is
reserved and documented. Unrelated files in the output directory are
never touched.

Standard artifact layout: one program publishes
``<artifact>.bpf.o``; several programs publish
``<artifact>.<entry>.bpf.o`` each (:func:`layout_names`). Published
files are described by :class:`PublishedArtifact` records
(``role``/``name``/``sha256``/``size``).

New diagnostic codes: ``MBPF106`` is reused for publication
failures at stage ``evidence.publish`` (same failure as the build
driver's publish step, new stage); ``MBPF708`` names provenance
capture failures at stage ``evidence.capture``.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass

from .build import BuildResult
from .diagnostics import Diagnostic, MojobpfError, SEVERITY_ERROR
from .inspect import LICENSE_MAPPING_VERSION
from .manifest import ProjectManifest

EVIDENCE_SCHEMA_VERSION = 1
ARTIFACT_SCHEMA_VERSION = 1
CACHE_KEY_VERSION = 1

STAGE_EVIDENCE_CAPTURE = "evidence.capture"
STAGE_EVIDENCE_PUBLISH = "evidence.publish"

# Environment variables captured by default. Values holding path
# separators are recorded by hash (see _stable_env_value) so stable
# bytes never embed absolute paths.
DEFAULT_ENVIRONMENT_NAMES = ("PATH", "MODULAR_HOME")


class EvidenceError(MojobpfError):
    """Provenance capture or publication failed with a stable code."""


def _sdk_root() -> str:
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "resources", "sdk"
    )


@dataclass(frozen=True)
class HashedFile:
    """One input or output file: stable relative path plus hash."""

    path: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, str | int]:
        """Return a stable plain-data mapping of this file."""
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True)
class PublishedArtifact:
    """One published output file with its content hash."""

    schema_version: int
    role: str
    name: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, str | int]:
        """Return a stable plain-data mapping of this artifact."""
        return {
            "schema_version": self.schema_version,
            "role": self.role,
            "name": self.name,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class CacheInputs:
    """The six cache-key input classes.

    ``source`` holds program sources, ``imports`` non-SDK imported
    sources, ``sdk`` incorporated SDK files, ``manifest`` the project
    manifest, ``compiler`` toolchain identities (never paths), and
    ``flags`` the relevant build flag spellings.
    """

    source: tuple[HashedFile, ...]
    imports: tuple[HashedFile, ...]
    sdk: tuple[HashedFile, ...]
    manifest: HashedFile
    compiler: tuple[str, ...]
    flags: tuple[str, ...]

    def to_dict(self) -> dict:
        """Return a stable plain-data mapping of these inputs."""
        return {
            "source": [item.to_dict() for item in self.source],
            "imports": [item.to_dict() for item in self.imports],
            "sdk": [item.to_dict() for item in self.sdk],
            "manifest": self.manifest.to_dict(),
            "compiler": list(self.compiler),
            "flags": list(self.flags),
        }


@dataclass(frozen=True)
class EvidenceCommand:
    """One build command with paths normalized to stable placeholders.

    Absolute paths under the project or output directory become
    ``$SRC/``- and ``$OUT/``-relative; any other absolute path
    becomes ``$PATH/<basename>``. Durations and log excerpts are
    dropped as run-specific.
    """

    stage: str
    argv: tuple[str, ...]
    status: str
    exit_code: int | None

    def to_dict(self) -> dict:
        """Return a stable plain-data mapping of this command."""
        return {
            "stage": self.stage,
            "argv": list(self.argv),
            "status": self.status,
            "exit_code": self.exit_code,
        }


@dataclass(frozen=True)
class EnvironmentEntry:
    """One environment entry: verbatim value or ``sha256:<hex>``."""

    name: str
    value: str

    def to_dict(self) -> dict[str, str]:
        """Return a stable plain-data mapping of this entry."""
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True)
class Evidence:
    """Stable provenance for one finished build.

    ``success`` mirrors the build result; failed builds still record
    their inputs, tools and declarations, with empty ``outputs``.
    Diagnostics are intentionally absent: they are run-specific (and
    path-laden) and stay in the build result and logs.
    """

    schema_version: int
    artifact: str
    profile_id: str
    success: bool
    inputs: CacheInputs
    outputs: tuple[HashedFile, ...]
    transforms: tuple[str, ...]
    source_license: str
    kernel_license: str
    license_mapping_version: int
    commands: tuple[EvidenceCommand, ...]
    environment: tuple[EnvironmentEntry, ...]

    def to_dict(self) -> dict:
        """Return a stable plain-data mapping of this evidence."""
        return {
            "schema_version": self.schema_version,
            "artifact": self.artifact,
            "profile_id": self.profile_id,
            "success": self.success,
            "inputs": self.inputs.to_dict(),
            "outputs": [item.to_dict() for item in self.outputs],
            "transforms": list(self.transforms),
            "source_license": self.source_license,
            "kernel_license": self.kernel_license,
            "license_mapping_version": self.license_mapping_version,
            "commands": [item.to_dict() for item in self.commands],
            "environment": [item.to_dict() for item in self.environment],
        }


def dumps_evidence(evidence: Evidence) -> bytes:
    """Serialize evidence to canonical bytes (sorted keys, UTF-8).

    The encoding is fixed: ``json.dumps`` with sorted keys, compact
    separators and ASCII output, plus a trailing newline. No
    timestamp or absolute path may appear in the mapping.
    """
    if not isinstance(evidence, Evidence):
        raise TypeError("dumps_evidence requires Evidence")
    text = json.dumps(
        evidence.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return (text + "\n").encode("ascii")


def cache_key(inputs: CacheInputs) -> str:
    """Hash the cache-key input classes into one versioned key.

    The key is ``"v1:<sha256>"`` over the canonical input mapping;
    every input class participates, so any class change invalidates
    the key.
    """
    if not isinstance(inputs, CacheInputs):
        raise TypeError("cache_key requires CacheInputs")
    text = json.dumps(
        inputs.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = hashlib.sha256(text.encode("ascii")).hexdigest()
    return "v%d:%s" % (CACHE_KEY_VERSION, digest)


def artifact_filename(artifact_name: str, entry: str, multi: bool) -> str:
    """Return the published object name for one program entry."""
    if multi:
        return "%s.%s.bpf.o" % (artifact_name, entry)
    return "%s.bpf.o" % artifact_name


def layout_names(artifact_name: str, entries: list[str] | tuple[str, ...]
                 ) -> tuple[str, ...]:
    """Return the standard published object names in entry order."""
    multi = len(entries) > 1
    return tuple(
        artifact_filename(artifact_name, entry, multi) for entry in entries
    )


def _capture_fail(explanation: str, location: str | None,
                  remedy: str) -> EvidenceError:
    return EvidenceError(
        Diagnostic(
            code="MBPF708",
            stage=STAGE_EVIDENCE_CAPTURE,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location=location,
            remedy=remedy,
        )
    )


def _publish_fail(explanation: str, location: str | None,
                  remedy: str) -> EvidenceError:
    return EvidenceError(
        Diagnostic(
            code="MBPF106",
            stage=STAGE_EVIDENCE_PUBLISH,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location=location,
            remedy=remedy,
        )
    )


def _relative_under(path: str, root: str) -> str | None:
    try:
        relative = os.path.relpath(path, root)
    except ValueError:
        return None
    if not relative or relative == ".." or os.path.isabs(relative):
        return None
    if relative.startswith(".." + os.sep):
        return None
    return relative.replace(os.sep, "/")


def hash_file(path: str, root: str | None = None) -> HashedFile:
    """Hash one file, recording its path stably.

    Paths under ``root`` are recorded relative to it; other paths
    (and every path when ``root`` is None) are recorded by basename,
    so no absolute path enters stable metadata. Missing or
    unreadable files raise ``EvidenceError`` (``MBPF708``).
    """
    try:
        with open(path, "rb") as handle:
            content = handle.read()
    except OSError as exc:
        raise _capture_fail(
            "cannot read provenance input %r: %s" % (path, exc),
            path,
            "check the input path and permissions",
        ) from None
    stable = path
    if root is not None:
        stable = _relative_under(path, root) or os.path.basename(path)
    else:
        stable = os.path.basename(path)
    digest = hashlib.sha256(content).hexdigest()
    return HashedFile(path=stable, sha256=digest, size=len(content))


def _stable_token(token: str, project_dir: str, out_dir: str) -> str:
    if not os.path.isabs(token):
        return token
    under = _relative_under(token, out_dir)
    if under is not None:
        return "$OUT/" + under
    under = _relative_under(token, project_dir)
    if under is not None:
        return "$SRC/" + under
    return "$PATH/" + os.path.basename(token)


def _stable_env_value(value: str) -> str:
    if "/" in value or "\\" in value:
        return "sha256:" + hashlib.sha256(
            value.encode("utf-8", errors="replace")
        ).hexdigest()
    return value


def _compiler_identities(result: BuildResult, toolchain: object
                         ) -> tuple[str, ...]:
    if toolchain is None:
        provenance = result.provenance
        if provenance is None:
            return ()
        return (
            "mojo %s" % provenance.mojo_version,
            "llc %s" % provenance.llc_version,
        )
    tools = getattr(toolchain, "tools", ())
    identities: list[str] = []
    for tool in tools:
        name = getattr(tool, "name", "?")
        status = getattr(tool, "status", "?")
        if status != "present":
            identities.append("%s %s" % (name, status))
            continue
        version = getattr(tool, "version", None) or "unknown-version"
        digest = getattr(tool, "sha256", None) or "unknown-sha256"
        identities.append("%s %s %s" % (name, version, digest))
    return tuple(identities)


def evidence_from_build(
    result: BuildResult,
    manifest: ProjectManifest,
    *,
    project_dir: str,
    out_dir: str,
    transforms: list[str] | tuple[str, ...],
    sdk_files: list[str] | tuple[str, ...] = (),
    imported_sources: list[str] | tuple[str, ...] = (),
    flags: list[str] | tuple[str, ...] = (),
    toolchain: object = None,
    environment: dict[str, str] | None = None,
) -> Evidence:
    """Derive stable evidence from a finished build result.

    ``project_dir`` parents the manifest and program sources;
    ``out_dir`` holds the published objects. Both normalize paths
    out of the record. ``transforms`` names the applied
    transformations in order (attested by the caller, who ran the
    pipeline); ``flags`` carries the relevant build flag spellings
    verbatim, so callers must keep them free of absolute paths.
    ``toolchain`` is an optional toolchain report enriching compiler
    identities with binary hashes. ``environment`` adds to (or
    overrides) the default captured variables; path-valued entries
    are recorded by hash. Failed builds record inputs with empty
    outputs. ``manifest`` must carry an absolute ``manifest_path``
    (the build driver absolutizes request paths at entry); program
    sources resolve under ``project_dir`` per manifest semantics.
    Raises ``EvidenceError`` (``MBPF708``) when an input cannot be
    read.
    """
    if not isinstance(result, BuildResult):
        raise TypeError("evidence_from_build requires a BuildResult")
    if not isinstance(manifest, ProjectManifest):
        raise TypeError("evidence_from_build requires a ProjectManifest")
    if not os.path.isabs(manifest.manifest_path):
        raise _capture_fail(
            "manifest path %r is not absolute; callers must absolutize "
            "it (the build driver does at entry)"
            % (manifest.manifest_path,),
            manifest.manifest_path,
            "parse the manifest from an absolute path",
        )
    for label, value in (("project_dir", project_dir),
                         ("out_dir", out_dir)):
        if not isinstance(value, str) or not value:
            raise TypeError("%s must be a non-empty string" % label)
    transforms = tuple(transforms)
    if any(not isinstance(item, str) for item in transforms):
        raise TypeError("transforms must hold strings")
    flags = tuple(flags)
    if any(not isinstance(item, str) for item in flags):
        raise TypeError("flags must hold strings")

    hashed_manifest = hash_file(manifest.manifest_path, project_dir)
    sources: list[HashedFile] = []
    for program in manifest.programs:
        resolved = os.path.realpath(
            os.path.join(project_dir, program.source)
        )
        sources.append(hash_file(resolved, project_dir))
    sdk_root = _sdk_root()
    sdk: list[HashedFile] = []
    for path in sdk_files:
        under = _relative_under(path, sdk_root)
        if under is not None:
            content_digest = hash_file(path, sdk_root)
            sdk.append(
                HashedFile(
                    path="sdk/" + content_digest.path,
                    sha256=content_digest.sha256,
                    size=content_digest.size,
                )
            )
        else:
            sdk.append(hash_file(path))
    imports = [
        hash_file(path, project_dir) for path in imported_sources
    ]
    outputs: list[HashedFile] = []
    for artifact in result.artifacts:
        name = _relative_under(artifact.path, out_dir)
        if name is None or "/" in name:
            name = os.path.basename(artifact.path)
        outputs.append(
            HashedFile(
                path=name, sha256=artifact.sha256, size=artifact.size
            )
        )
    commands: list[EvidenceCommand] = []
    for record in result.commands:
        commands.append(
            EvidenceCommand(
                stage=record.stage,
                argv=tuple(
                    _stable_token(token, project_dir, out_dir)
                    for token in record.argv
                ),
                status=record.status,
                exit_code=record.exit_code,
            )
        )
    entries: dict[str, str] = {}
    for name in DEFAULT_ENVIRONMENT_NAMES:
        if name in os.environ:
            entries[name] = _stable_env_value(os.environ[name])
    if environment is not None:
        for name, value in environment.items():
            entries[str(name)] = _stable_env_value(str(value))
    return Evidence(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        artifact=manifest.artifact.name,
        profile_id=manifest.target.profile,
        success=result.success,
        inputs=CacheInputs(
            source=tuple(sources),
            imports=tuple(imports),
            sdk=tuple(sdk),
            manifest=hashed_manifest,
            compiler=_compiler_identities(result, toolchain),
            flags=flags,
        ),
        outputs=tuple(outputs),
        transforms=transforms,
        source_license=manifest.artifact.source_license,
        kernel_license=manifest.artifact.kernel_license,
        license_mapping_version=LICENSE_MAPPING_VERSION,
        commands=tuple(commands),
        environment=tuple(
            EnvironmentEntry(name, entries[name]) for name in sorted(entries)
        ),
    )


def _check_publish_name(name: object, staged: str) -> str:
    if not isinstance(name, str) or not name:
        raise _publish_fail(
            "cannot publish %r: names must be non-empty strings"
            % (staged,),
            staged,
            "publish under plain file names",
        )
    if (
        name != os.path.basename(name)
        or name in (".", "..")
        or "/" in name
        or "\\" in name
        or "\x00" in name
    ):
        raise _publish_fail(
            "cannot publish %r: names must not hold directories"
            % (name,),
            name,
            "publish under plain file names",
        )
    if name.startswith("."):
        raise _publish_fail(
            "cannot publish %r: leading-dot names are reserved for "
            "temporary files" % (name,),
            name,
            "publish under plain file names",
        )
    return name


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def publish_artifacts(
    staged: list[tuple[str, str]] | tuple[tuple[str, str], ...],
    out_dir: str,
) -> tuple[PublishedArtifact, ...]:
    """Publish one staged file set to ``out_dir`` all-or-nothing.

    ``staged`` holds ``(name, staged_path)`` pairs in publication
    order; ``name`` is a plain file name (no directories,
    no leading dot). Every input is validated before anything is
    written. Bytes move through temporary files inside ``out_dir``
    and are renamed into place one by one; predecessors are backed
    up first. On any failure -- including interruption -- renamed
    files are removed again, predecessors are restored
    byte-identically, and temporary files are removed, so the
    directory holds no new-or-partial result; the call then raises
    ``EvidenceError`` (``MBPF106``) instead of returning artifacts.
    Returns one :class:`PublishedArtifact` per file on success.
    """
    pairs = list(staged)
    if not pairs:
        raise _publish_fail(
            "cannot publish: no staged files",
            out_dir,
            "stage at least one file before publishing",
        )
    names: list[str] = []
    for item in pairs:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise _publish_fail(
                "cannot publish: staged entries must be (name, path) "
                "pairs",
                out_dir,
                "stage (name, path) pairs",
            )
        name, staged_path = item
        _check_publish_name(name, str(staged_path))
        names.append(name)
    if len(set(names)) != len(names):
        raise _publish_fail(
            "cannot publish: duplicate file names %r" % (names,),
            out_dir,
            "publish each name once",
        )
    for name, staged_path in pairs:
        if not isinstance(staged_path, str) or not os.path.isfile(
            staged_path
        ):
            raise _publish_fail(
                "cannot publish %r: staged file is missing" % (name,),
                str(staged_path),
                "restage the file before publishing",
            )
    if not isinstance(out_dir, str) or not out_dir:
        raise _publish_fail(
            "cannot publish: output directory must be a non-empty "
            "string",
            str(out_dir),
            "publish into a writable directory",
        )
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        raise _publish_fail(
            "cannot create output directory %r: %s" % (out_dir, exc),
            out_dir,
            "publish into a writable directory",
        ) from None
    if not os.path.isdir(out_dir):
        raise _publish_fail(
            "output location %r is not a directory" % (out_dir,),
            out_dir,
            "publish into a writable directory",
        )

    temps: list[str] = []
    try:
        for name, staged_path in pairs:
            fd, tmp_path = tempfile.mkstemp(
                dir=out_dir,
                prefix="." + name + ".",
                suffix=".tmp",
            )
            temps.append(tmp_path)
            try:
                os.close(fd)
                shutil.copyfile(staged_path, tmp_path)
                shutil.copymode(staged_path, tmp_path)
            except OSError as exc:
                raise _publish_fail(
                    "cannot stage %r for publication: %s" % (name, exc),
                    tmp_path,
                    "publish into a writable directory with free space",
                ) from None
        published: list[PublishedArtifact] = []
        renamed: list[tuple[str, str | None]] = []
        try:
            for (name, _staged_path), tmp_path in zip(pairs, list(temps)):
                final_path = os.path.join(out_dir, name)
                backup: str | None = None
                if os.path.lexists(final_path):
                    backup_fd, backup = tempfile.mkstemp(
                        dir=out_dir,
                        prefix="." + name + ".backup.",
                        suffix=".tmp",
                    )
                    os.close(backup_fd)
                    try:
                        if os.path.isdir(final_path) and not os.path.islink(
                            final_path
                        ):
                            raise IsADirectoryError(
                                "target is a directory: %r" % (final_path,)
                            )
                        shutil.copyfile(final_path, backup)
                        shutil.copymode(final_path, backup)
                    except OSError as exc:
                        _remove_quietly(backup)
                        raise _publish_fail(
                            "cannot publish %r: cannot back up %r: %s"
                            % (name, final_path, exc),
                            final_path,
                            "clear the blocking path or publish "
                            "elsewhere",
                        ) from None
                try:
                    os.replace(tmp_path, final_path)
                except OSError as exc:
                    if backup is not None:
                        _remove_quietly(backup)
                    raise _publish_fail(
                        "cannot publish %r: %s" % (name, exc),
                        final_path,
                        "publish into a writable directory with free "
                        "space",
                    ) from None
                renamed.append((final_path, backup))
                temps.remove(tmp_path)
                try:
                    size = os.path.getsize(final_path)
                    digest = hash_file(final_path).sha256
                except EvidenceError as exc:
                    raise _publish_fail(
                        "cannot hash published file %r: %s"
                        % (final_path, exc.diagnostic.explanation),
                        final_path,
                        "publish into a readable directory",
                    ) from None
                published.append(
                    PublishedArtifact(
                        schema_version=ARTIFACT_SCHEMA_VERSION,
                        role="object",
                        name=name,
                        sha256=digest,
                        size=size,
                    )
                )
        except BaseException:
            for final_path, backup in reversed(renamed):
                _remove_quietly(final_path)
                if backup is not None:
                    try:
                        os.replace(backup, final_path)
                    except OSError:
                        pass
            raise
        for _final_path, backup in renamed:
            if backup is not None:
                _remove_quietly(backup)
        return tuple(published)
    finally:
        for leftover in temps:
            _remove_quietly(leftover)
