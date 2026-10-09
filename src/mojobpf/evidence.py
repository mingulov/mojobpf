# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Stable build provenance, cache keys and atomic publication.

:func:`evidence_from_build` derives stable :class:`Evidence` from a
finished build result: input hashes per cache class (program
sources, imported sources, SDK files, manifest, compiler identity
including the stdlib/distribution and environment identities,
flags, target profile, adapter implementation, tool and SDK
versions), output hashes, applied transformations, license
declarations, version stamps, normalized commands and
environment entries. Stable metadata excludes timestamps and
absolute paths, so the same inputs built in different directories
serialize to identical bytes; exact invocations, timings and log
excerpts stay in the build result and logs, never here. The caller
passes the build's :class:`SealedInputs`, and every re-read hash
must match its seal or the capture is rejected, so evidence can
never attribute post-build bytes to the published objects. Builds
pass their :class:`mojobpf.inputs.BuildSnapshot`, whose staged
bytes are what the compiler consumed and what the capture
re-hashes; direct captures without a snapshot keep the legacy
origin-file behavior.

:func:`cache_key` hashes the input classes into one versioned key.
Every input class participates, so changing any class invalidates
the key; reusing an object across SDK or compiler changes is a
cache miss, never a silent hit.

:func:`publish_artifacts` publishes one staged file set
all-or-nothing into an owned, identity-pinned output directory.
Observable semantics, defined here and tested, not merely
asserted:

* success: every named file lands with its staged bytes; no
  temporary or backup file remains.
* failure: the output directory holds no new-or-partial result.
  Files already renamed by the failed call are removed, overwritten
  predecessors are restored byte-identically from backups, and
  temporary files are removed. Predecessor files from earlier
  successful publications are otherwise untouched -- and they are
  never reported as the new result, because a failed call raises
  instead of returning artifacts (nothing new is claimed). When a
  predecessor cannot be restored, the error reports the incomplete
  rollback and the retained recovery backups.
* interruption propagates after the same rollback, carrying a
  :class:`PublicationRecovery` account (see
  :func:`publication_recovery`): every journalled destination --
  including ones whose rename outcome is uncertain -- is
  recovered, and an incomplete rollback is reported through the
  account, never swallowed.
* the output directory must be a real directory owned by the
  current user (never a symlink); it is pinned by an open
  directory descriptor and held under an exclusive lock for the
  whole call, so concurrent publishers serialize into whole
  generations instead of interleaving. The pinned identity is
  re-verified before and after every mutation step: a swapped
  directory is detected, nothing new is reported, the original
  directory is rolled back through the pinned descriptor, and the
  swapped-in path is never mutated.
* predecessors are classified without following links, read back
  through ``O_NOFOLLOW`` opens, and re-verified immediately before
  the rename: symlink predecessors are rejected before any
  mutation, and a predecessor swapped between backup and replace
  aborts the call with its backup restored.
* names starting with ``.`` are never results: crash leftovers use
  that namespace and are safe to delete.

This covers error-path atomicity only; a crash between renames can
still leave backups behind, which is why the temporary namespace is
reserved and documented. Unrelated files in the output directory are
never touched.

Standard artifact layout: one program publishes
``<artifact>.bpf.o``; several programs publish
``<artifact>.<entry>.bpf.o`` each (:func:`layout_names`). A
successful build also publishes its provenance sidecar
``<artifact>.evidence.json`` in the same transaction. Published
files are described by :class:`PublishedArtifact` records
(``role``/``name``/``sha256``/``size``) with role ``"object"`` or
``"evidence"``. The flat layout and the multiple-per-entry-object
shape are the documented equivalent of the original
``build/<artifact>/`` per-program directory contract; see
``docs/artifact-format.md``.

:func:`qualify_artifacts` is the qualification aggregator: it
validates sidecar schema and hash consistency, compares every
recorded object hash against caller-supplied live bytes, and binds
the accepted generation to its input digest and to the caller's
run-plan digest in a :class:`QualificationReport`. The loader never
reads sidecars -- objects load standalone -- so qualification is
the layer that refuses detached or inconsistent provenance. Trust
limit, stated plainly: unsigned local provenance detects accident
and drift, not a coordinated malicious rewriting of objects plus
sidecars; see ``docs/artifact-format.md``. No signature service and
no mandatory custom loader are introduced here.

New diagnostic codes: ``MBPF106`` is reused for publication
failures at stage ``evidence.publish`` (same failure as the build
driver's publish step, new stage); ``MBPF708`` names provenance
capture failures at stage ``evidence.capture``; ``MBPF710`` names
sidecar qualification failures at stage ``evidence.verify``.

Standard library only.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX-only primitive
    fcntl = None  # type: ignore[assignment]

from . import __version__ as TOOL_VERSION
from .build import BuildResult
from .diagnostics import Diagnostic, MojobpfError, SEVERITY_ERROR
from .inputs import BuildSnapshot, stable_env_value
from .inspect import LICENSE_MAPPING_VERSION
from .manifest import (
    ProfileError,
    ProjectManifest,
    lookup_profile,
    profile_digest,
)
from .sdk import SDK_VERSION

EVIDENCE_SCHEMA_VERSION = 4
ARTIFACT_SCHEMA_VERSION = 2
#: Cache-key version. Bumped to 6 when the installed
#: standard-library payload bytes (``std.mojoc``,
#: ``modular.cfg``) joined the compiler class: v5 keys covered
#: only the lockfile's distribution *record*, so two installs
#: with identical lockfiles but different installed stdlib
#: bytes shared a v5 key and reusing a v5-keyed object across
#: a stdlib swap would be a silent hit. The ``v6:`` prefix
#: keeps old keys disjoint, so pre-fix cache entries never
#: validate post-fix builds.
CACHE_KEY_VERSION = 6

STAGE_EVIDENCE_CAPTURE = "evidence.capture"
STAGE_EVIDENCE_PUBLISH = "evidence.publish"
STAGE_EVIDENCE_VERIFY = "evidence.verify"

#: Version of the :class:`QualificationReport` record emitted by
#: :func:`qualify_artifacts`. Independent of
#: :data:`EVIDENCE_SCHEMA_VERSION`, which names the sidecar schema
#: the aggregator validates.
QUALIFICATION_SCHEMA_VERSION = 1

#: How long one publication waits for another publisher's
#: exclusive lock before failing loudly instead of hanging.
_PUBLISH_LOCK_TIMEOUT_S = 60.0
_PUBLISH_LOCK_POLL_S = 0.02

#: Stream unit for staged copies and published-byte hashing.
_COPY_CHUNK = 1024 * 1024

# Environment variables captured by default. Values holding path
# separators are recorded by hash (see
# ``mojobpf.inputs.stable_env_value``) so stable bytes never embed
# absolute paths.
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
    """The cache-key input classes.

    ``source`` holds program sources, ``imports`` non-SDK imported
    sources, ``sdk`` incorporated SDK files, ``manifest`` the project
    manifest, ``compiler`` the toolchain identities (never paths):
    one ``"<name> <version> <sha256>"`` per admitted tool, then
    the stdlib/distribution identities (``"stdlib ..."``) and the
    influential environment (``"env NAME=value"`` sorted by name,
    path-valued entries hashed), so a compiler, stdlib or
    environment change invalidates the key. ``flags`` holds the
    relevant build flag spellings, ``profile_id`` the target
    profile, ``profile_sha256`` the resolved profile
    implementation digest, ``adapter`` the transform
    implementation identities (``"<file> <sha256>"`` per adapter
    file, sorted), and ``tool_version``/``sdk_version`` the mojobpf
    tool and Mojo SDK versions, so a tool or SDK upgrade
    invalidates the key even when every file hash is unchanged.
    """

    source: tuple[HashedFile, ...]
    imports: tuple[HashedFile, ...]
    sdk: tuple[HashedFile, ...]
    manifest: HashedFile
    compiler: tuple[str, ...]
    flags: tuple[str, ...]
    profile_id: str
    profile_sha256: str
    adapter: tuple[str, ...]
    tool_version: str
    sdk_version: str

    def to_dict(self) -> dict:
        """Return a stable plain-data mapping of these inputs."""
        return {
            "source": [item.to_dict() for item in self.source],
            "imports": [item.to_dict() for item in self.imports],
            "sdk": [item.to_dict() for item in self.sdk],
            "manifest": self.manifest.to_dict(),
            "compiler": list(self.compiler),
            "flags": list(self.flags),
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "adapter": list(self.adapter),
            "tool_version": self.tool_version,
            "sdk_version": self.sdk_version,
        }


@dataclass(frozen=True)
class SealedInputs:
    """Input hashes recorded by the build when it read each input.

    The build seals every input class before running the pipeline;
    :func:`evidence_from_build` requires this seal, re-reads the
    files at capture time, and rejects the capture (``MBPF708``)
    when any re-read hash differs from its seal, so evidence can
    never attribute post-build bytes to the published objects.
    ``source_sha256`` runs in manifest program order; ``sdk``,
    ``imports`` and ``adapter`` hold ``(realpath, sha256)`` pairs
    keyed by resolved absolute path (the seal is never serialized,
    so absolute paths are fine here); ``profile_sha256`` is the
    resolved profile implementation digest.
    """

    manifest_sha256: str
    source_sha256: tuple[str, ...]
    sdk: tuple[tuple[str, str], ...]
    imports: tuple[tuple[str, str], ...]
    adapter: tuple[tuple[str, str], ...]
    profile_sha256: str


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
    ``tool_version``/``sdk_version`` stamp the mojobpf tool and Mojo
    SDK versions that ran the build. Diagnostics are intentionally
    absent: they are run-specific (and path-laden) and stay in the
    build result and logs.
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
    tool_version: str
    sdk_version: str
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
            "tool_version": self.tool_version,
            "sdk_version": self.sdk_version,
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

    The key is ``"v6:<sha256>"`` over the canonical input mapping;
    every input class participates, so any class change invalidates
    the key. Version 6 folds the installed standard-library
    payload bytes into the compiler class alongside the
    stdlib/distribution record and environment identities;
    older keys are not comparable.
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


def _verify_fail(explanation: str, location: str | None,
                 remedy: str) -> EvidenceError:
    return EvidenceError(
        Diagnostic(
            code="MBPF710",
            stage=STAGE_EVIDENCE_VERIFY,
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


def _stable_token(token: str, project_dir: str, out_dir: str,
                  snapshot: BuildSnapshot | None = None) -> str:
    if not os.path.isabs(token):
        return token
    under = _relative_under(token, out_dir)
    if under is not None:
        return "$OUT/" + under
    if snapshot is not None:
        under = _relative_under(token, snapshot.project_root)
        if under is not None:
            return "$SRC/" + under
        if snapshot.sdk_root is not None:
            relative = _relative_under(token, snapshot.sdk_root)
            if relative is not None:
                if relative == ".":
                    return "$SDK"
                return "$SDK/" + relative
    under = _relative_under(token, project_dir)
    if under is not None:
        return "$SRC/" + under
    if snapshot is not None and snapshot.sdk_dir:
        # Recorded argv names the origin SDK tree (staged paths
        # are mapped back before the result returns); it still
        # normalizes to $SDK. Project files keep priority above:
        # an SDK rooted inside the project must not shadow $SRC.
        relative = _relative_under(token, snapshot.sdk_dir)
        if relative is not None:
            if relative == ".":
                return "$SDK"
            return "$SDK/" + relative
    return "$PATH/" + os.path.basename(token)


#: Placeholder stdlib identity when no toolchain binding backs the
#: capture: explicit, never silently omitted.
STDLIB_UNBOUND = "stdlib distribution unbound no-toolchain-binding"


def _compiler_identities(
    result: BuildResult,
    toolchain: object,
    *,
    stdlib: tuple[str, ...] | None = None,
    environment: tuple[tuple[str, str], ...] = (),
) -> tuple[str, ...]:
    """Format the compiler cache-key class: tools, stdlib, environment."""
    if toolchain is None:
        provenance = result.provenance
        if provenance is None:
            tools: tuple[str, ...] = ()
        else:
            tools = (
                "mojo %s %s"
                % (provenance.mojo_version, provenance.mojo_sha256),
                "llc %s %s"
                % (provenance.llc_version, provenance.llc_sha256),
            )
    else:
        found = getattr(toolchain, "tools", ())
        formatted: list[str] = []
        for tool in found:
            name = getattr(tool, "name", "?")
            status = getattr(tool, "status", "?")
            if status != "present":
                formatted.append("%s %s" % (name, status))
                continue
            version = getattr(tool, "version", None) or "unknown-version"
            digest = getattr(tool, "sha256", None) or "unknown-sha256"
            formatted.append("%s %s %s" % (name, version, digest))
        tools = tuple(formatted)
    stdlib_entries = (
        tuple(stdlib) if stdlib is not None else (STDLIB_UNBOUND,)
    )
    env_entries = tuple(
        "env %s=%s" % (name, value) for name, value in environment
    )
    return tools + stdlib_entries + env_entries


def _check_seal(sealed: tuple[tuple[str, str], ...],
                paths: list[str] | tuple[str, ...],
                captured: list[HashedFile], label: str) -> None:
    """Reject a capture whose hashes differ from the build seal."""
    wanted = sorted(sealed)
    observed = sorted(
        (os.path.realpath(path), item.sha256)
        for path, item in zip(paths, captured)
    )
    if wanted != observed:
        raise _capture_fail(
            "%s inputs changed after sealing: sealed %d file(s), "
            "captured %d file(s); recapture rejected"
            % (label, len(wanted), len(observed)),
            None,
            "rebuild without modifying inputs while the build runs",
        )


def evidence_from_build(
    result: BuildResult,
    manifest: ProjectManifest,
    *,
    project_dir: str,
    out_dir: str,
    transforms: list[str] | tuple[str, ...],
    sdk_files: list[str] | tuple[str, ...] = (),
    imported_sources: list[str] | tuple[str, ...] = (),
    adapter_files: list[str] | tuple[str, ...] = (),
    flags: list[str] | tuple[str, ...] = (),
    toolchain: object = None,
    environment: dict[str, str] | None = None,
    tool_version: str = TOOL_VERSION,
    sdk_version: str = SDK_VERSION,
    sealed: SealedInputs,
    snapshot: BuildSnapshot | None = None,
    stdlib: tuple[str, ...] | list[str] | None = None,
) -> Evidence:
    """Derive stable evidence from a finished build result.

    ``project_dir`` parents the manifest and program sources;
    ``out_dir`` holds the published objects. Both normalize paths
    out of the record. ``transforms`` names the applied
    transformations in order (attested by the caller, who ran the
    pipeline); ``flags`` carries the relevant build flag spellings
    verbatim, so callers must keep them free of absolute paths.
    ``adapter_files`` holds the transform implementation files (the
    adapter service plus its sibling modules); their identities join
    the cache inputs. ``toolchain`` is an optional toolchain report
    enriching compiler identities with binary hashes. ``tool_version``
    and ``sdk_version`` stamp the record (and join the cache-key
    inputs); they default to the running tool's versions.
    ``environment`` adds to (or overrides) the default captured
    variables; path-valued entries are recorded by hash.
    ``stdlib`` carries the stdlib/distribution identity strings
    (``STDLIB_UNBOUND`` when no toolchain binding backs the
    capture). ``sealed`` is required: it carries the hashes the
    build recorded when it read each input, and every re-read hash
    must match its seal or the capture is rejected (``MBPF708``)
    -- there is no unsealed recapture, so evidence can never
    silently describe post-build bytes. Failed builds record
    inputs with empty outputs. ``manifest`` must carry an
    absolute ``manifest_path`` (the build driver absolutizes
    request paths at entry); program sources resolve under
    ``project_dir`` per manifest semantics, unless ``snapshot``
    is given: then the manifest, program sources, imports and
    SDK files are re-hashed from the snapshot's staged bytes
    (the bytes the compiler consumed), the recorded environment
    starts from the snapshot's sealed environment instead of
    the ambient one, ``stdlib``/``flags`` default from the
    snapshot, and staged command paths normalize to
    ``$SRC/``/``$SDK``-relative forms. Raises ``EvidenceError``
    (``MBPF708``) when an input cannot be read.
    """
    if not isinstance(result, BuildResult):
        raise TypeError("evidence_from_build requires a BuildResult")
    if not isinstance(manifest, ProjectManifest):
        raise TypeError("evidence_from_build requires a ProjectManifest")
    if not isinstance(sealed, SealedInputs):
        raise TypeError("evidence_from_build requires SealedInputs")
    if snapshot is not None and not isinstance(snapshot, BuildSnapshot):
        raise TypeError(
            "evidence_from_build snapshot must be a BuildSnapshot"
        )
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
    if snapshot is not None and not flags:
        flags = snapshot.flags

    if snapshot is not None:
        capture_root = snapshot.project_root
        sdk_root = snapshot.sdk_root or _sdk_root()
        manifest_file = snapshot.manifest_staged
        source_files = [
            item.staged for item in snapshot.programs
        ]
    else:
        capture_root = project_dir
        sdk_root = _sdk_root()
        manifest_file = manifest.manifest_path
        source_files = [
            os.path.realpath(os.path.join(project_dir, program.source))
            for program in manifest.programs
        ]
    hashed_manifest = hash_file(manifest_file, capture_root)
    sources: list[HashedFile] = []
    for path in source_files:
        sources.append(hash_file(path, capture_root))
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
        hash_file(path, capture_root) for path in imported_sources
    ]
    adapter = [hash_file(path) for path in adapter_files]
    if hashed_manifest.sha256 != sealed.manifest_sha256:
        raise _capture_fail(
            "manifest changed after sealing; recapture rejected",
            manifest.manifest_path,
            "rebuild without modifying inputs while the build runs",
        )
    if (
        tuple(item.sha256 for item in sources)
        != sealed.source_sha256
    ):
        raise _capture_fail(
            "program sources changed after sealing; "
            "recapture rejected",
            None,
            "rebuild without modifying inputs while the build runs",
        )
    _check_seal(sealed.sdk, sdk_files, sdk, "SDK")
    _check_seal(
        sealed.imports, imported_sources, imports,
        "imported-source",
    )
    _check_seal(sealed.adapter, adapter_files, adapter, "adapter")
    try:
        resolved_profile = lookup_profile(manifest.target.profile)
    except ProfileError as exc:
        raise _capture_fail(
            "target profile %r is not supported; recapture "
            "rejected" % (manifest.target.profile,),
            "%s: target.profile" % manifest.manifest_path,
            exc.diagnostic.remedy,
        ) from None
    if profile_digest(resolved_profile) != sealed.profile_sha256:
        raise _capture_fail(
            "target profile implementation changed after sealing; "
            "recapture rejected",
            "%s: target.profile" % manifest.manifest_path,
            "rebuild without modifying inputs while the build runs",
        )
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
                    _stable_token(
                        token, project_dir, out_dir, snapshot
                    )
                    for token in record.argv
                ),
                status=record.status,
                exit_code=record.exit_code,
            )
        )
    entries: dict[str, str] = {}
    if snapshot is not None:
        for name, value in snapshot.environment:
            entries[name] = value
    else:
        for name in DEFAULT_ENVIRONMENT_NAMES:
            if name in os.environ:
                entries[name] = stable_env_value(os.environ[name])
    if environment is not None:
        for name, value in environment.items():
            entries[str(name)] = stable_env_value(str(value))
    if stdlib is None and snapshot is not None:
        stdlib = snapshot.stdlib
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
            compiler=_compiler_identities(
                result,
                toolchain,
                stdlib=(
                    tuple(stdlib) if stdlib is not None else None
                ),
                environment=tuple(
                    (name, entries[name]) for name in sorted(entries)
                ),
            ),
            flags=flags,
            profile_id=manifest.target.profile,
            profile_sha256=sealed.profile_sha256,
            adapter=tuple(
                sorted(
                    "%s %s" % (item.path, item.sha256)
                    for item in adapter
                )
            ),
            tool_version=tool_version,
            sdk_version=sdk_version,
        ),
        outputs=tuple(outputs),
        transforms=transforms,
        source_license=manifest.artifact.source_license,
        kernel_license=manifest.artifact.kernel_license,
        license_mapping_version=LICENSE_MAPPING_VERSION,
        tool_version=tool_version,
        sdk_version=sdk_version,
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


def _remove_at_quietly(dir_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _lexists_at(dir_fd: int, name: str) -> bool:
    try:
        os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _remove_new_file_at(
    dir_fd: int,
    final_path: str,
    name: str,
    status: str,
    note: str,
    recovered: list[str],
    failures: list[str],
) -> None:
    """Remove one journalled new file; record an unlink failure.

    ``note`` locates the removal for the account (empty while
    the path still names the pin, " from the original directory"
    after a swap). A file already missing counts as removed; any
    other unlink error is recorded as a rollback failure, since
    a retained new file must never read as a clean rollback.
    """
    existed = _lexists_at(dir_fd, name)
    try:
        os.unlink(name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except OSError as exc:
        failures.append(
            "%r (%s rename; cannot remove new file%s: %s)"
            % (final_path, status, note, exc)
        )
        return
    if existed:
        recovered.append(
            "%r (%s rename; new file removed%s)"
            % (final_path, status, note)
        )
    else:
        recovered.append(
            "%r (%s rename; nothing published)"
            % (final_path, status)
        )


PUBLISH_ROLES = ("object", "evidence")


def _check_publish_role(role: object, name: str) -> str:
    if role not in PUBLISH_ROLES:
        raise _publish_fail(
            "cannot publish %r: role %r is not one of %s"
            % (name, role, ", ".join(PUBLISH_ROLES)),
            name,
            "publish under a known role",
        )
    return role  # type: ignore[return-value]


@dataclass(frozen=True)
class PublicationRecovery:
    """Rollback account for an interrupted publication.

    ``recovered`` names every journalled destination rolled back
    (predecessor restored, new file removed, or confirmed never
    published); ``failures`` names destinations left unrestored,
    each with its retained backup location. Attached to a
    propagating interruption (see :func:`publication_recovery`) so
    callers report cleanup from evidence instead of assuming it.
    """

    recovered: tuple[str, ...]
    failures: tuple[str, ...]

    @property
    def complete(self) -> bool:
        """True when every journalled destination was rolled back."""
        return not self.failures


#: Attribute carrying a :class:`PublicationRecovery` on a
#: propagating interruption raised from :func:`publish_artifacts`.
RECOVERY_ATTRIBUTE = "mojobpf_recovery"


def publication_recovery(exc: BaseException) -> PublicationRecovery | None:
    """Return the rollback account attached to ``exc``, if any."""
    found = getattr(exc, RECOVERY_ATTRIBUTE, None)
    if isinstance(found, PublicationRecovery):
        return found
    return None


def _require_publish_primitives(out_dir: str) -> None:
    """Fail closed when the platform lacks publication primitives.

    Owned-directory admission needs ``os.geteuid``,
    link-safe opens need ``os.O_NOFOLLOW``, directory pinning
    needs ``os.O_DIRECTORY``, and serialization needs
    ``fcntl.flock``. Silently publishing without any of them
    would re-open the swap window the hardening closes.
    """
    missing = []
    if fcntl is None:
        missing.append("fcntl.flock")
    if getattr(os, "geteuid", None) is None:
        missing.append("os.geteuid")
    if getattr(os, "O_NOFOLLOW", None) is None:
        missing.append("os.O_NOFOLLOW")
    if getattr(os, "O_DIRECTORY", None) is None:
        missing.append("os.O_DIRECTORY")
    if missing:
        raise _publish_fail(
            "cannot publish: this platform lacks %s; refusing "
            "an unlocked publication" % (", ".join(missing),),
            out_dir,
            "publish from a POSIX host",
        )


def _normalize_out_dir(out_dir: str) -> str:
    """Strip trailing slashes and dots from an output directory.

    ``lstat`` and ``O_NOFOLLOW`` opens resolve a trailing
    ``/`` or ``/.`` before inspecting the final component, so
    ``link/`` and ``link/.`` would admit a symlink ``link`` the
    plain spelling refuses. Normalization exposes the real
    final component to admission; interior components are left
    untouched. Never returns an empty string.
    """
    text = out_dir
    while True:
        stripped = text.rstrip("/")
        if not stripped:
            return "/" if text.startswith("/") else "."
        if stripped == ".":
            return "."
        if os.path.basename(stripped) != ".":
            return stripped
        text = os.path.dirname(stripped)


def _admit_out_dir(out_dir: str) -> tuple[int, tuple[int, int, int]]:
    """Admit, pin and lock the output directory.

    The directory must already exist or be creatable, must be a
    real directory (never a symlink), and must be owned by the
    current user. Returns the open directory descriptor and the
    pinned ``(st_dev, st_ino, st_uid)`` identity; the exclusive
    lock is held on return and the caller must release it with
    :func:`_release_out_dir`. Lock acquisition polls with a
    deadline so a stuck holder fails loudly instead of hanging
    the build.
    """
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        raise _publish_fail(
            "cannot create output directory %r: %s" % (out_dir, exc),
            out_dir,
            "publish into a writable directory",
        ) from None
    try:
        entry = os.lstat(out_dir)
    except OSError:
        raise _publish_fail(
            "output location %r is not a directory" % (out_dir,),
            out_dir,
            "publish into a writable directory",
        )
    if stat.S_ISLNK(entry.st_mode):
        raise _publish_fail(
            "output location %r is a symlink; refusing to publish "
            "through it" % (out_dir,),
            out_dir,
            "publish into a real directory",
        )
    if not stat.S_ISDIR(entry.st_mode):
        raise _publish_fail(
            "output location %r is not a directory" % (out_dir,),
            out_dir,
            "publish into a writable directory",
        )
    if entry.st_uid != os.geteuid():
        raise _publish_fail(
            "output directory %r is not owned by the current "
            "user; publication requires an owned directory"
            % (out_dir,),
            out_dir,
            "publish into a directory you own",
        )
    try:
        dir_fd = os.open(
            out_dir,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise _publish_fail(
            "cannot open output directory %r: %s" % (out_dir, exc),
            out_dir,
            "publish into a readable directory",
        ) from None
    locked = False
    try:
        pinned = os.fstat(dir_fd)
        if (pinned.st_dev, pinned.st_ino) != (
            entry.st_dev,
            entry.st_ino,
        ):
            raise _publish_fail(
                "output directory %r was swapped during "
                "publication setup; refusing to report success"
                % (out_dir,),
                out_dir,
                "republish into a stable directory",
            )
        identity = (pinned.st_dev, pinned.st_ino, pinned.st_uid)
        deadline = time.monotonic() + _PUBLISH_LOCK_TIMEOUT_S
        while True:
            try:
                fcntl.flock(dir_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise _publish_fail(
                        "cannot lock output directory %r within "
                        "%ds; another publication may still hold "
                        "it" % (out_dir, _PUBLISH_LOCK_TIMEOUT_S),
                        out_dir,
                        "wait for the other publisher, then "
                        "republish",
                    )
                time.sleep(_PUBLISH_LOCK_POLL_S)
                continue
            except OSError as exc:
                raise _publish_fail(
                    "cannot lock output directory %r: %s"
                    % (out_dir, exc),
                    out_dir,
                    "publish into a lockable filesystem",
                ) from None
            break
        locked = True
    finally:
        if not locked:
            _close_quietly(dir_fd)
    return dir_fd, identity


#: Run-ownership record inside a claimed output directory.
#: The leading dot keeps it out of the publishable namespace
#: (leading-dot names are never results), and the fixed name
#: never collides with the ``.<name>.<pid>.<n>.tmp`` temporary
#: pattern.
_RUN_OWNER_NAME = ".mojobpf-run-owner"


def _claim_or_check_run(
    dir_fd: int, out_dir: str, token: str | bytes | None
) -> None:
    """Claim the pinned directory for a run, or check its claim.

    ``token`` is the caller's run-ownership token (already
    validated; None means no token presented). The first token
    use creates the ownership record ``O_EXCL`` through the pin;
    later publishes must present the same token, and a token-less
    publish into a claimed directory is rejected -- the claim is
    not optional once set. Unclaimed directories still publish
    token-less and gain no record. The record is read ``O_NOFOLLOW``
    and must be a regular file: a planted symlink or directory
    fails closed instead of being followed or trusted.
    """
    want: bytes | None = None
    if token is not None:
        want = (
            token.encode("utf-8")
            if isinstance(token, str)
            else bytes(token)
        )
    for _attempt in range(2):
        try:
            fd = os.open(
                _RUN_OWNER_NAME,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=dir_fd,
            )
        except FileNotFoundError:
            if want is None:
                return
            try:
                claim_fd = os.open(
                    _RUN_OWNER_NAME,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=dir_fd,
                )
            except FileExistsError:
                # Lost a claim race against a non-publisher (the
                # lock serializes publishers): verify the winner
                # instead of overwriting it.
                continue
            except OSError as exc:
                raise _publish_fail(
                    "cannot publish: cannot claim output "
                    "directory %r for this run: %s"
                    % (out_dir, exc),
                    out_dir,
                    "publish into a writable directory",
                ) from None
            try:
                view = memoryview(want)
                while view:
                    view = view[os.write(claim_fd, view):]
                os.close(claim_fd)
            except OSError as exc:
                _close_quietly(claim_fd)
                _remove_at_quietly(dir_fd, _RUN_OWNER_NAME)
                raise _publish_fail(
                    "cannot publish: cannot claim output "
                    "directory %r for this run: %s"
                    % (out_dir, exc),
                    out_dir,
                    "publish into a writable directory with free "
                    "space",
                ) from None
            return
        except OSError as exc:
            raise _publish_fail(
                "cannot publish: run-ownership record in %r "
                "cannot be read safely: %s; refusing a spoofed "
                "claim" % (out_dir, exc),
                out_dir,
                "publish into a directory without a planted "
                "ownership record",
            ) from None
        try:
            current = os.fstat(fd)
            if not stat.S_ISREG(current.st_mode):
                raise _publish_fail(
                    "cannot publish: run-ownership record in %r "
                    "is not a regular file; refusing a spoofed "
                    "claim" % (out_dir,),
                    out_dir,
                    "publish into a directory without a planted "
                    "ownership record",
                )
            chunks = []
            while True:
                chunk = os.read(fd, _COPY_CHUNK)
                if not chunk:
                    break
                chunks.append(chunk)
            found = b"".join(chunks)
        finally:
            _close_quietly(fd)
        if want is None:
            raise _publish_fail(
                "cannot publish: output directory %r is claimed "
                "by another run; present its ownership token"
                % (out_dir,),
                out_dir,
                "publish into a directory your run owns",
            )
        if found != want:
            raise _publish_fail(
                "cannot publish: output directory %r is owned by "
                "another run; refusing a foreign token"
                % (out_dir,),
                out_dir,
                "publish into a directory your run owns",
            )
        return
    raise _publish_fail(
        "cannot publish: cannot claim output directory %r for "
        "this run: the ownership record changed underfoot"
        % (out_dir,),
        out_dir,
        "republish into a stable directory",
    )


def _release_out_dir(dir_fd: int) -> None:
    """Release the publication lock and the directory descriptor."""
    if fcntl is not None:
        try:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
        except OSError:
            pass
    _close_quietly(dir_fd)


def _directory_changed(
    out_dir: str, identity: tuple[int, int, int]
) -> str | None:
    """Report an output-directory swap, or None when pinned.

    Compares the live path against the admitted identity: a
    missing, unlinked, non-directory, re-owned or replaced
    directory all count as changed. Pure observation; callers
    decide between aborting and rolling back.
    """
    try:
        entry = os.lstat(out_dir)
    except OSError as exc:
        return "cannot stat output directory %r: %s" % (
            out_dir,
            exc,
        )
    if stat.S_ISLNK(entry.st_mode):
        return (
            "output directory %r was swapped during publication "
            "(now a symlink)" % (out_dir,)
        )
    if not stat.S_ISDIR(entry.st_mode):
        return "output location %r is no longer a directory" % (
            out_dir,
        )
    if (entry.st_dev, entry.st_ino, entry.st_uid) != identity:
        return (
            "output directory %r was swapped during publication "
            "(directory identity changed)" % (out_dir,)
        )
    return None


def _ensure_pinned(
    out_dir: str, identity: tuple[int, int, int]
) -> None:
    """Abort when the output directory no longer names the pin."""
    reason = _directory_changed(out_dir, identity)
    if reason is not None:
        raise _publish_fail(
            "%s; refusing to report success" % (reason,),
            out_dir,
            "republish into a stable directory",
        )


def _create_temp(
    dir_fd: int,
    out_dir: str,
    name: str,
    backup: bool,
    counter: list[int],
) -> tuple[int, str]:
    """Create an unreadable-by-others temporary inside the pin.

    Temporary names stay in the reserved leading-dot namespace;
    backups carry the ``.backup.`` infix the recovery account
    matches on. Creation is ``O_EXCL`` through the pinned
    descriptor, so a swapped path can neither redirect nor
    pre-create the temporary.
    """
    infix = ".backup." if backup else "."
    while True:
        counter[0] += 1
        if counter[0] > 1000:
            raise _publish_fail(
                "cannot mint a temporary name for %r" % (name,),
                out_dir,
                "clear stale temporary files, then republish",
            )
        tmp = ".%s%s%d.%d.tmp" % (
            name,
            infix,
            os.getpid(),
            counter[0],
        )
        try:
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
        except FileExistsError:
            continue
        except OSError as exc:
            raise _publish_fail(
                "cannot stage %r for publication: %s" % (name, exc),
                out_dir,
                "publish into a writable directory with free space",
            ) from None
        return fd, tmp


def _copy_fd_to_fd(src_fd: int, dst_fd: int) -> None:
    """Copy all bytes between descriptors, tolerating short writes."""
    while True:
        chunk = os.read(src_fd, _COPY_CHUNK)
        if not chunk:
            return
        view = memoryview(chunk)
        while view:
            view = view[os.write(dst_fd, view):]


def _classify_predecessor(
    dir_fd: int, name: str, final_path: str
) -> os.stat_result | None:
    """Classify the current occupant without following links.

    Returns None when nothing is published under ``name``;
    otherwise returns the ``lstat`` observation, after rejecting
    symlinks, directories and non-regular files. The rename and
    backup steps re-verify this observation before acting on it.
    """
    try:
        observed = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _publish_fail(
            "cannot publish %r: cannot inspect %r: %s"
            % (name, final_path, exc),
            final_path,
            "publish into a readable directory",
        ) from None
    mode = observed.st_mode
    if stat.S_ISLNK(mode):
        raise _publish_fail(
            "cannot publish %r: predecessor %r is a symlink; "
            "symlink predecessors are never replaced"
            % (name, final_path),
            final_path,
            "remove or replace the symlink, then republish",
        )
    if stat.S_ISDIR(mode):
        raise _publish_fail(
            "cannot publish %r: cannot back up %r: target is a "
            "directory" % (name, final_path),
            final_path,
            "clear the blocking path or publish elsewhere",
        )
    if not stat.S_ISREG(mode):
        raise _publish_fail(
            "cannot publish %r: cannot back up %r: not a regular "
            "file" % (name, final_path),
            final_path,
            "clear the blocking path or publish elsewhere",
        )
    return observed


def _back_up_predecessor(
    dir_fd: int,
    out_dir: str,
    name: str,
    final_path: str,
    observed: os.stat_result,
    counter: list[int],
) -> str:
    """Copy the classified predecessor to a backup temporary.

    The predecessor is opened ``O_NOFOLLOW`` through the pinned
    descriptor and its identity is compared against the backup
    observation, so a file-to-symlink swap between classification
    and the read aborts instead of backing up foreign bytes.
    Returns the backup temporary name.
    """
    backup_fd, backup = _create_temp(
        dir_fd, out_dir, name, True, counter
    )
    failed = True
    try:
        try:
            src_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=dir_fd,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise _publish_fail(
                    "cannot publish %r: predecessor %r is now a "
                    "symlink; symlink predecessors are never "
                    "replaced" % (name, final_path),
                    final_path,
                    "remove the swapped predecessor, then "
                    "republish",
                ) from None
            raise _publish_fail(
                "cannot publish %r: cannot back up %r: %s"
                % (name, final_path, exc),
                final_path,
                "clear the blocking path or publish elsewhere",
            ) from None
        try:
            current = os.fstat(src_fd)
            if (current.st_dev, current.st_ino) != (
                observed.st_dev,
                observed.st_ino,
            ) or not stat.S_ISREG(current.st_mode):
                raise _publish_fail(
                    "cannot publish %r: predecessor %r changed "
                    "during publication; refusing a swapped "
                    "predecessor" % (name, final_path),
                    final_path,
                    "republish into a stable directory",
                )
            _copy_fd_to_fd(src_fd, backup_fd)
            os.fchmod(backup_fd, stat.S_IMODE(current.st_mode))
        finally:
            _close_quietly(src_fd)
        try:
            os.close(backup_fd)
        except OSError as exc:
            raise _publish_fail(
                "cannot publish %r: cannot back up %r: %s"
                % (name, final_path, exc),
                final_path,
                "publish into a writable directory with free space",
            ) from None
        failed = False
        return backup
    finally:
        if failed:
            _close_quietly(backup_fd)
            _remove_at_quietly(dir_fd, backup)


def _recheck_predecessor(
    dir_fd: int,
    name: str,
    final_path: str,
    observed: os.stat_result | None,
) -> None:
    """Re-verify the predecessor immediately before the rename.

    ``observed`` is the backup-time classification; any change --
    appearance, disappearance, identity swap, or new symlink --
    aborts the call before the rename runs.
    """
    try:
        current = os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        current = None
    except OSError as exc:
        raise _publish_fail(
            "cannot publish %r: cannot re-inspect %r: %s"
            % (name, final_path, exc),
            final_path,
            "publish into a readable directory",
        ) from None
    if observed is None:
        if current is not None:
            raise _publish_fail(
                "cannot publish %r: %r changed during "
                "publication (a predecessor appeared where none "
                "was backed up); refusing a swapped predecessor"
                % (name, final_path),
                final_path,
                "republish into a stable directory",
            )
        return
    if (
        current is None
        or (current.st_dev, current.st_ino)
        != (observed.st_dev, observed.st_ino)
        or stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
    ):
        raise _publish_fail(
            "cannot publish %r: predecessor %r changed during "
            "publication; refusing a swapped predecessor"
            % (name, final_path),
            final_path,
            "republish into a stable directory",
        )


def _hash_published(
    dir_fd: int,
    name: str,
    final_path: str,
    expected: tuple[int, int],
) -> tuple[str, int]:
    """Hash the just-published file through the pinned descriptor.

    The read end re-verifies regularity without following links,
    and the opened file's identity must equal the staged
    temporary's pre-rename identity ``expected``: a result
    swapped in after the rename is refused instead of hashed,
    so the reported digest always describes the staged bytes
    inside the pinned directory.
    """
    try:
        observed = os.lstat(name, dir_fd=dir_fd)
    except OSError as exc:
        raise _publish_fail(
            "cannot hash published file %r: %s" % (final_path, exc),
            final_path,
            "publish into a readable directory",
        ) from None
    if not stat.S_ISREG(observed.st_mode):
        raise _publish_fail(
            "cannot publish: published file %r is not a regular "
            "file" % (final_path,),
            final_path,
            "republish into a stable directory",
        )
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd
        )
    except OSError as exc:
        raise _publish_fail(
            "cannot hash published file %r: %s" % (final_path, exc),
            final_path,
            "publish into a readable directory",
        ) from None
    try:
        # Compared on the open descriptor, not a re-stat of the
        # name, so no second lookup window remains.
        installed = os.fstat(fd)
        if (installed.st_dev, installed.st_ino) != expected:
            raise _publish_fail(
                "cannot publish %r: published file %r changed "
                "during publication; refusing a swapped result"
                % (name, final_path),
                final_path,
                "republish into a stable directory",
            )
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, _COPY_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    finally:
        _close_quietly(fd)
    return digest.hexdigest(), size


def _read_all_at(dir_fd: int, name: str) -> tuple[bytes, int]:
    """Read one pinned file without following links.

    Returns the content and the permission bits, for
    byte-identical predecessor restores.
    """
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        chunks = []
        while True:
            chunk = os.read(fd, _COPY_CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), mode
    finally:
        _close_quietly(fd)


def _write_all_at(
    dir_fd: int, name: str, content: bytes, mode: int
) -> None:
    """Replace one pinned file's bytes without following links."""
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        0o600,
        dir_fd=dir_fd,
    )
    try:
        view = memoryview(content)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, mode)
    finally:
        # A failed close surfaces (disk errors flush here); the
        # caller records it as a rollback failure.
        os.close(fd)


def _roll_back_publication(
    dir_fd: int,
    out_dir: str,
    identity: tuple[int, int, int],
    journal: list[list],
) -> tuple[list[str], list[str]]:
    """Roll back every journalled destination; report the account.

    Every mutation runs through the pinned descriptor, in both
    branches: the swapped-in path is never mutated, so a swap
    during rollback can neither divert nor break a restore.
    While the output path still names the pinned directory,
    rollback renames backups back over the finals. Once a swap is
    detected -- before rollback starts or between two entries --
    the remaining entries restore predecessors by byte-copy
    through the pin instead. A byte-copy restore reads its
    backup fully before touching the final, so a missing backup
    leaves the predecessor intact and the gap recorded. Returns
    ``(recovered, failures)`` message lists.
    """
    recovered: list[str] = []
    failures: list[str] = []
    swapped = _directory_changed(out_dir, identity) is not None
    for final_path, backup, replaced in reversed(journal):
        if not swapped and (
            _directory_changed(out_dir, identity) is not None
        ):
            swapped = True
        # Every journalled destination is recovered, including
        # ones with an uncertain rename outcome (see the journal
        # comment in publish_artifacts): without this, an
        # interruption between the rename and its confirmation
        # would keep the new file and drop the predecessor backup.
        _status = "confirmed" if replaced else "uncertain"
        name = os.path.basename(final_path)
        if not swapped:
            if backup is None:
                _remove_new_file_at(
                    dir_fd,
                    final_path,
                    name,
                    _status,
                    "",
                    recovered,
                    failures,
                )
                continue
            try:
                # Atomic and descriptor-relative: no pre-remove
                # window, no resolution through the path.
                os.replace(
                    os.path.basename(backup),
                    name,
                    src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd,
                )
            except OSError as exc:
                failures.append(
                    "%r (recovery backup retained at %r: %s)"
                    % (final_path, backup, exc)
                )
            else:
                recovered.append(
                    "%r (%s rename; predecessor restored)"
                    % (final_path, _status)
                )
            continue
        if backup is None:
            _remove_new_file_at(
                dir_fd,
                final_path,
                name,
                _status,
                " from the original directory",
                recovered,
                failures,
            )
            continue
        backup_name = os.path.basename(backup)
        try:
            content, mode = _read_all_at(dir_fd, backup_name)
        except OSError as exc:
            if not _lexists_at(dir_fd, backup_name):
                failures.append(
                    "%r (recovery backup missing from the "
                    "original directory: %r)"
                    % (final_path, backup)
                )
            else:
                failures.append(
                    "%r (cannot read recovery backup retained "
                    "in the original directory at %r: %s)"
                    % (final_path, backup, exc)
                )
            continue
        try:
            _write_all_at(dir_fd, name, content, mode)
        except OSError as exc:
            failures.append(
                "%r (cannot restore predecessor; recovery "
                "backup retained in the original directory at "
                "%r: %s)" % (final_path, backup, exc)
            )
            continue
        _remove_at_quietly(dir_fd, backup_name)
        recovered.append(
            "%r (%s rename; predecessor restored in the original "
            "directory)" % (final_path, _status)
        )
    return recovered, failures


def publish_artifacts(
    staged: list[tuple[str, ...]] | tuple[tuple[str, ...], ...],
    out_dir: str,
    *,
    ownership_token: str | bytes | None = None,
) -> tuple[PublishedArtifact, ...]:
    """Publish one staged file set to ``out_dir`` all-or-nothing.

    ``staged`` holds ``(name, staged_path)`` pairs in publication
    order, each optionally extended with a role
    (``(name, staged_path, role)`` with ``role`` ``"object"`` or
    ``"evidence"``; pairs default to ``"object"``); ``name`` is a
    plain file name (no directories, no leading dot). Every input is
    validated before anything is written. ``out_dir`` must be a
    real directory owned by the current user; it is pinned by an
    open descriptor and held under an exclusive lock for the whole
    call, so concurrent publishers serialize into whole
    generations. ``ownership_token`` optionally claims the
    directory for one run: the first token use records it, later
    publishes must present the same token, and another run's
    token (or none, once claimed) is rejected -- UID ownership
    alone cannot tell two same-user runs apart. Bytes move
    through temporary files inside the pinned directory and are
    renamed into place one by one;
    predecessors are classified without following links, backed up
    through ``O_NOFOLLOW`` opens, and re-verified immediately
    before the rename, and the recovery journal is written before
    each rename, so an interruption at any boundary rolls back to
    the pre-call state. Residual window: a symlink swapped in
    after that final recheck is removed by the rename, never
    followed -- POSIX rename replaces the entry, so outside
    targets cannot be affected -- and the installed file's
    identity is re-verified against the staged temporary before
    hashing, so the reported digest always describes the staged
    bytes. The pinned directory identity is
    re-verified around every step: a swapped directory aborts the
    call, the original directory is rolled back through the pinned
    descriptor, and the swapped-in path is never mutated. On any
    failure, renamed files are removed again, predecessors are
    restored byte-identically, and temporary files are removed, so
    the directory holds no new-or-partial result; the call then
    raises ``EvidenceError`` (``MBPF106``) instead of returning
    artifacts. When a predecessor cannot be restored, the error
    reports the incomplete rollback and the retained recovery
    backups. An interruption (``KeyboardInterrupt``,
    ``SystemExit``) runs the same rollback -- recovering every
    journalled destination, including ones whose rename outcome is
    uncertain -- and then propagates as itself, carrying a
    :class:`PublicationRecovery` account retrievable with
    :func:`publication_recovery`. Returns one
    :class:`PublishedArtifact` per file on success.
    """
    pairs = list(staged)
    if not pairs:
        raise _publish_fail(
            "cannot publish: no staged files",
            out_dir,
            "stage at least one file before publishing",
        )
    triples: list[tuple[str, str, str]] = []
    names: list[str] = []
    for item in pairs:
        if not isinstance(item, (list, tuple)) or len(item) not in (
            2, 3,
        ):
            raise _publish_fail(
                "cannot publish: staged entries must be "
                "(name, path[, role]) entries",
                out_dir,
                "stage (name, path[, role]) entries",
            )
        name, staged_path = item[0], item[1]
        _check_publish_name(name, str(staged_path))
        role = item[2] if len(item) == 3 else "object"
        triples.append(
            (name, staged_path, _check_publish_role(role, name))
        )
        names.append(name)
    if len(set(names)) != len(names):
        raise _publish_fail(
            "cannot publish: duplicate file names %r" % (names,),
            out_dir,
            "publish each name once",
        )
    for name, staged_path, _role in triples:
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
    # Normalize before admission so trailing-slash and
    # trailing-dot spellings of a symlink are refused exactly
    # like the plain spelling; every later step uses the
    # normalized path.
    out_dir = _normalize_out_dir(out_dir)
    if ownership_token is not None and (
        not isinstance(ownership_token, (str, bytes))
        or not ownership_token
    ):
        raise _publish_fail(
            "cannot publish: ownership token must be a "
            "non-empty string or bytes",
            out_dir,
            "present your run's ownership token",
        )
    _require_publish_primitives(out_dir)
    dir_fd, identity = _admit_out_dir(out_dir)
    counter = [0]
    try:
        _claim_or_check_run(dir_fd, out_dir, ownership_token)
        temps: list[str] = []
        try:
            for name, staged_path, _role in triples:
                tmp_fd, tmp_name = _create_temp(
                    dir_fd, out_dir, name, False, counter
                )
                temps.append(tmp_name)
                tmp_path = os.path.join(out_dir, tmp_name)
                staged_failed = True
                try:
                    with open(staged_path, "rb") as handle:
                        _copy_fd_to_fd(
                            handle.fileno(), tmp_fd
                        )
                        os.fchmod(
                            tmp_fd,
                            stat.S_IMODE(
                                os.fstat(handle.fileno()).st_mode
                            ),
                        )
                    try:
                        os.close(tmp_fd)
                    except OSError as exc:
                        raise _publish_fail(
                            "cannot stage %r for publication: %s"
                            % (name, exc),
                            tmp_path,
                            "publish into a writable directory "
                            "with free space",
                        ) from None
                    staged_failed = False
                except EvidenceError:
                    raise
                except OSError as exc:
                    raise _publish_fail(
                        "cannot stage %r for publication: %s"
                        % (name, exc),
                        tmp_path,
                        "publish into a writable directory with "
                        "free space",
                    ) from None
                finally:
                    if staged_failed:
                        _close_quietly(tmp_fd)
                        _remove_at_quietly(dir_fd, tmp_name)
        except BaseException:
            for leftover in temps:
                _remove_at_quietly(dir_fd, leftover)
            raise
        published: list[PublishedArtifact] = []
        # Recovery journal: [final path, backup path or None,
        # rename confirmed]. Entries are appended BEFORE the rename
        # they describe. An entry still pending at rollback time has
        # an UNCERTAIN rename outcome (the rename was attempted but
        # its confirmation never landed), so rollback recovers it
        # like a confirmed one: the final path is removed when
        # present and the predecessor restored from its backup.
        # Removing a still-original predecessor is safe -- the
        # backup holds the same bytes and is restored next.
        journal: list[list] = []
        try:
            for (name, _staged_path, role), tmp_name in zip(
                triples, list(temps)
            ):
                final_path = os.path.join(out_dir, name)
                _ensure_pinned(out_dir, identity)
                observed = _classify_predecessor(
                    dir_fd, name, final_path
                )
                backup: str | None = None
                if observed is not None:
                    backup = os.path.join(
                        out_dir,
                        _back_up_predecessor(
                            dir_fd,
                            out_dir,
                            name,
                            final_path,
                            observed,
                            counter,
                        ),
                    )
                journal.append([final_path, backup, False])
                _recheck_predecessor(
                    dir_fd, name, final_path, observed
                )
                try:
                    staged = os.lstat(tmp_name, dir_fd=dir_fd)
                except OSError as exc:
                    raise _publish_fail(
                        "cannot publish %r: staged temporary "
                        "vanished before the rename: %s"
                        % (name, exc),
                        final_path,
                        "republish into a stable directory",
                    ) from None
                expected = (staged.st_dev, staged.st_ino)
                try:
                    # Descriptor-relative: the rename lands inside
                    # the pinned directory even when the path has
                    # been swapped for a symlink; a post-check can
                    # only detect, never undo, a string-path write.
                    os.replace(
                        tmp_name,
                        name,
                        src_dir_fd=dir_fd,
                        dst_dir_fd=dir_fd,
                    )
                except OSError as exc:
                    journal.pop()
                    if backup is not None:
                        _remove_at_quietly(
                            dir_fd, os.path.basename(backup)
                        )
                    reason = _directory_changed(out_dir, identity)
                    if reason is not None:
                        raise _publish_fail(
                            "%s; the rename failed: %s"
                            % (reason, exc),
                            final_path,
                            "republish into a stable directory",
                        ) from None
                    raise _publish_fail(
                        "cannot publish %r: %s" % (name, exc),
                        final_path,
                        "publish into a writable directory with "
                        "free space",
                    ) from None
                journal[-1][2] = True
                _ensure_pinned(out_dir, identity)
                # The temporary is dropped from the cleanup list
                # only once the pin check proves the rename landed
                # inside the pinned directory; otherwise a swap
                # would orphan it there.
                temps.remove(tmp_name)
                digest, size = _hash_published(
                    dir_fd, name, final_path, expected
                )
                published.append(
                    PublishedArtifact(
                        schema_version=ARTIFACT_SCHEMA_VERSION,
                        role=role,
                        name=name,
                        sha256=digest,
                        size=size,
                    )
                )
            _ensure_pinned(out_dir, identity)
        except BaseException as original:
            for leftover in temps:
                _remove_at_quietly(dir_fd, leftover)
            recovered, failures = _roll_back_publication(
                dir_fd, out_dir, identity, journal
            )
            if isinstance(original, Exception):
                if failures:
                    raise _publish_fail(
                        "publication failed and rollback is "
                        "incomplete; predecessors not restored: %s"
                        % "; ".join(failures),
                        out_dir,
                        "restore the predecessors from the retained "
                        "recovery backups, then republish",
                    )
                raise
            # Interruptions (KeyboardInterrupt, SystemExit) keep
            # propagating as themselves, carrying the rollback
            # account: an incomplete rollback is reported through
            # it, never swallowed.
            setattr(
                original,
                RECOVERY_ATTRIBUTE,
                PublicationRecovery(
                    recovered=tuple(recovered),
                    failures=tuple(failures),
                ),
            )
            raise
        for _final_path, backup, _replaced in journal:
            if backup is not None:
                _remove_at_quietly(dir_fd, os.path.basename(backup))
        return tuple(published)
    finally:
        _release_out_dir(dir_fd)


#: Required top-level sidecar fields, mirroring
#: ``schemas/evidence.schema.json``. Unknown fields fail closed.
_VERIFY_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "artifact",
        "profile_id",
        "success",
        "inputs",
        "outputs",
        "transforms",
        "source_license",
        "kernel_license",
        "license_mapping_version",
        "tool_version",
        "sdk_version",
        "commands",
        "environment",
    }
)

#: Required input classes, mirroring the evidence schema.
_VERIFY_INPUT_KEYS = frozenset(
    {
        "source",
        "imports",
        "sdk",
        "manifest",
        "compiler",
        "flags",
        "profile_id",
        "profile_sha256",
        "adapter",
        "tool_version",
        "sdk_version",
    }
)

_VERIFY_HASHED_KEYS = frozenset({"path", "sha256", "size"})
_VERIFY_COMMAND_KEYS = frozenset(
    {"stage", "argv", "status", "exit_code"}
)
_VERIFY_ENV_KEYS = frozenset({"name", "value"})
_VERIFY_STATUSES = frozenset(
    {"ok", "failed", "timeout", "spawn_failed"}
)

_HEXDIGITS = frozenset("0123456789abcdef")
_ASCIIDIGITS = frozenset("0123456789")


def _is_sha256(value: object) -> bool:
    """True for a lowercase 64-hex digest string only."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEXDIGITS for char in value)
    )


def _is_exact_int(value: object) -> bool:
    """True for a genuine int (never a bool)."""
    return type(value) is int


def _is_sdk_version(value: object) -> bool:
    """True for an ASCII ``major.minor`` version string."""
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    return (
        len(parts) == 2
        and all(
            part and all(char in _ASCIIDIGITS for char in part)
            for part in parts
        )
    )


def _is_bound_object_name(artifact: str, name: object) -> bool:
    """True when ``name`` is a bound object of ``artifact``.

    Bound objects are exactly the publication layout:
    ``<artifact>.bpf.o`` for a single program, or
    ``<artifact>.<entry>.bpf.o`` with a non-empty entry for
    several. Sidecar-named entries never qualify: a sidecar hash
    cannot name its own final bytes, so ``outputs[]`` must hold
    bound objects only.
    """
    if not isinstance(name, str) or not name:
        return False
    if (
        name != os.path.basename(name)
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or name.startswith(".")
    ):
        return False
    if name == artifact + ".bpf.o":
        return True
    prefix = artifact + "."
    suffix = ".bpf.o"
    if not name.startswith(prefix) or not name.endswith(suffix):
        return False
    return len(name[len(prefix):-len(suffix)]) > 0


class _DuplicateKey(ValueError):
    """A JSON object repeated a key; fail-closed input."""


def _reject_dup_keys(pairs: list[tuple[str, object]]) -> dict:
    """Build a JSON object, rejecting duplicate keys at any level."""
    found: dict[str, object] = {}
    for key, value in pairs:
        if key in found:
            raise _DuplicateKey("duplicate key %r" % (key,))
        found[key] = value
    return found


@dataclass(frozen=True)
class QualifiedArtifact:
    """One sidecar-bound object accepted for qualification.

    ``object_sha256``/``object_size`` are the live-byte hashes the
    aggregator compared against the sidecar's record (equal by
    construction); ``sidecar_sha256`` hashes the sidecar bytes
    consumed; ``inputs_digest`` is the cache key over the sidecar's
    recorded inputs, binding the record to the exact input set.
    """

    artifact: str
    object_name: str
    object_sha256: str
    object_size: int
    sidecar_sha256: str
    inputs_digest: str

    def to_dict(self) -> dict[str, str | int]:
        """Return a stable plain-data mapping of this record."""
        return {
            "artifact": self.artifact,
            "object_name": self.object_name,
            "object_sha256": self.object_sha256,
            "object_size": self.object_size,
            "sidecar_sha256": self.sidecar_sha256,
            "inputs_digest": self.inputs_digest,
        }


@dataclass(frozen=True)
class QualificationReport:
    """One qualification aggregator verdict over bound sidecars.

    ``run_plan_digest`` is the caller-supplied run-plan binding
    (or None when the qualification runs outside a planned run);
    the aggregator validates its shape and records it, and never
    recomputes the plan. ``artifacts`` sorts by
    ``(artifact, object_name)`` so reports are deterministic.
    """

    schema_version: int
    run_plan_digest: str | None
    artifacts: tuple[QualifiedArtifact, ...]

    def to_dict(self) -> dict:
        """Return a stable plain-data mapping of this report."""
        return {
            "schema_version": self.schema_version,
            "run_plan_digest": self.run_plan_digest,
            "artifacts": [item.to_dict() for item in self.artifacts],
        }


def dumps_qualification(report: QualificationReport) -> bytes:
    """Serialize a report to canonical bytes (sorted keys, UTF-8).

    The encoding matches :func:`dumps_evidence`: ``json.dumps``
    with sorted keys, compact separators and ASCII output, plus a
    trailing newline.
    """
    if not isinstance(report, QualificationReport):
        raise TypeError(
            "dumps_qualification requires a QualificationReport"
        )
    text = json.dumps(
        report.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return (text + "\n").encode("ascii")


def _parse_sidecar(artifact: str, raw: bytes) -> dict:
    """Parse and shape-check one sidecar document.

    Rejects non-JSON bytes, duplicate keys, non-object
    documents, unknown or missing fields, foreign schema
    versions, failed builds, and key/artifact disagreement.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _verify_fail(
            "sidecar for %r is not valid JSON: not UTF-8"
            % (artifact,),
            artifact,
            "re-read the published sidecar bytes",
        )
    try:
        doc = json.loads(text, object_pairs_hook=_reject_dup_keys)
    except _DuplicateKey as exc:
        raise _verify_fail(
            "sidecar for %r is not valid JSON: %s" % (artifact, exc),
            artifact,
            "re-read the published sidecar bytes",
        )
    except ValueError:
        raise _verify_fail(
            "sidecar for %r is not valid JSON" % (artifact,),
            artifact,
            "re-read the published sidecar bytes",
        )
    if not isinstance(doc, dict):
        raise _verify_fail(
            "sidecar for %r is not a JSON object" % (artifact,),
            artifact,
            "re-read the published sidecar bytes",
        )
    unknown = sorted(set(doc) - _VERIFY_REQUIRED_KEYS)
    if unknown:
        raise _verify_fail(
            "sidecar for %r carries unknown fields: %s"
            % (artifact, ", ".join(unknown)),
            artifact,
            "qualify sidecars written by this tool version only",
        )
    missing = sorted(_VERIFY_REQUIRED_KEYS - set(doc))
    if missing:
        raise _verify_fail(
            "sidecar for %r is missing fields: %s"
            % (artifact, ", ".join(missing)),
            artifact,
            "re-read the published sidecar bytes",
        )
    if not _is_exact_int(doc["schema_version"]) or doc[
        "schema_version"
    ] != EVIDENCE_SCHEMA_VERSION:
        raise _verify_fail(
            "sidecar for %r has schema_version %r; this tool "
            "verifies schema %d only"
            % (
                artifact,
                doc["schema_version"],
                EVIDENCE_SCHEMA_VERSION,
            ),
            artifact,
            "qualify sidecars written by this tool version only",
        )
    if doc["success"] is not True:
        raise _verify_fail(
            "sidecar for %r records success %r; only successful "
            "builds qualify" % (artifact, doc["success"]),
            artifact,
            "qualify a successful build's sidecar",
        )
    if not isinstance(doc["artifact"], str) or not doc["artifact"]:
        raise _verify_fail(
            "sidecar for %r has no artifact name" % (artifact,),
            artifact,
            "re-read the published sidecar bytes",
        )
    if doc["artifact"] != artifact:
        raise _verify_fail(
            "sidecar key %r disagrees with its artifact %r"
            % (artifact, doc["artifact"]),
            artifact,
            "qualify each sidecar under its own artifact name",
        )
    return doc


def _check_verify_outputs(
    artifact: str, doc: dict
) -> list[tuple[str, str, int]]:
    """Validate ``outputs[]`` into bound ``(name, sha256, size)``."""
    outputs = doc["outputs"]
    if not isinstance(outputs, list) or not outputs:
        raise _verify_fail(
            "sidecar for %r has no outputs; only builds with "
            "published objects qualify" % (artifact,),
            artifact,
            "qualify a successful build's sidecar",
        )
    seen: set[str] = set()
    checked: list[tuple[str, str, int]] = []
    for index, entry in enumerate(outputs):
        where = "sidecar for %r outputs[%d]" % (artifact, index)
        if not isinstance(entry, dict) or (
            set(entry) != _VERIFY_HASHED_KEYS
        ):
            raise _verify_fail(
                "%s must hold exactly path/sha256/size" % (where,),
                where,
                "re-read the published sidecar bytes",
            )
        name = entry["path"]
        if not _is_bound_object_name(artifact, name):
            raise _verify_fail(
                "%s names %r, which is not a bound object of "
                "artifact %r" % (where, name, artifact),
                where,
                "qualify sidecars whose outputs are published "
                "objects of the same artifact",
            )
        if name in seen:
            raise _verify_fail(
                "%s repeats object %r" % (where, name),
                where,
                "re-read the published sidecar bytes",
            )
        want = entry["sha256"]
        if not _is_sha256(want):
            raise _verify_fail(
                "%s sha256 for %r is not a 64-hex digest"
                % (where, name),
                where,
                "re-read the published sidecar bytes",
            )
        size = entry["size"]
        if not _is_exact_int(size) or size < 0:
            raise _verify_fail(
                "%s size for %r is not a non-negative integer"
                % (where, name),
                where,
                "re-read the published sidecar bytes",
            )
        seen.add(name)
        checked.append((name, want, size))
    return checked


def _check_verify_hashed(
    entry: object, where: str
) -> HashedFile:
    """Validate one recorded file entry into a :class:`HashedFile`."""
    if not isinstance(entry, dict) or (
        set(entry) != _VERIFY_HASHED_KEYS
    ):
        raise _verify_fail(
            "%s must hold exactly path/sha256/size" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    path = entry["path"]
    digest = entry["sha256"]
    size = entry["size"]
    if not isinstance(path, str) or not path:
        raise _verify_fail(
            "%s path is not a non-empty string" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    if not _is_sha256(digest):
        raise _verify_fail(
            "%s sha256 is not a 64-hex digest" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    if not _is_exact_int(size) or size < 0:
        raise _verify_fail(
            "%s size is not a non-negative integer" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    return HashedFile(path=path, sha256=digest, size=size)


def _check_verify_str_list(value: object, where: str) -> tuple[str, ...]:
    """Validate one string-list input class."""
    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in value
    ):
        raise _verify_fail(
            "%s must be a list of strings" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    return tuple(value)


def _check_verify_inputs(artifact: str, doc: dict) -> CacheInputs:
    """Validate ``inputs`` into the bound :class:`CacheInputs`."""
    inputs = doc["inputs"]
    where = "sidecar for %r inputs" % (artifact,)
    if not isinstance(inputs, dict):
        raise _verify_fail(
            "%s is not an object" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    unknown = sorted(set(inputs) - _VERIFY_INPUT_KEYS)
    if unknown:
        raise _verify_fail(
            "%s carries unknown input classes: %s"
            % (where, ", ".join(unknown)),
            where,
            "qualify sidecars written by this tool version only",
        )
    missing = sorted(_VERIFY_INPUT_KEYS - set(inputs))
    if missing:
        raise _verify_fail(
            "%s is missing input classes: %s"
            % (where, ", ".join(missing)),
            where,
            "re-read the published sidecar bytes",
        )

    def hashed_list(key: str) -> tuple[HashedFile, ...]:
        value = inputs[key]
        if not isinstance(value, list):
            raise _verify_fail(
                "%s.%s is not a list" % (where, key),
                where,
                "re-read the published sidecar bytes",
            )
        return tuple(
            _check_verify_hashed(
                entry, "%s.%s[%d]" % (where, key, index)
            )
            for index, entry in enumerate(value)
        )

    profile_id = inputs["profile_id"]
    if not isinstance(profile_id, str) or not profile_id:
        raise _verify_fail(
            "%s.profile_id is not a non-empty string" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    profile_sha256 = inputs["profile_sha256"]
    if not _is_sha256(profile_sha256):
        raise _verify_fail(
            "%s.profile_sha256 is not a 64-hex digest" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    tool_version = inputs["tool_version"]
    if not isinstance(tool_version, str) or not tool_version:
        raise _verify_fail(
            "%s.tool_version is not a non-empty string" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    sdk_version = inputs["sdk_version"]
    if not _is_sdk_version(sdk_version):
        raise _verify_fail(
            "%s.sdk_version is not a major.minor version"
            % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    return CacheInputs(
        source=hashed_list("source"),
        imports=hashed_list("imports"),
        sdk=hashed_list("sdk"),
        manifest=_check_verify_hashed(
            inputs["manifest"], "%s.manifest" % (where,)
        ),
        compiler=_check_verify_str_list(
            inputs["compiler"], "%s.compiler" % (where,)
        ),
        flags=_check_verify_str_list(
            inputs["flags"], "%s.flags" % (where,)
        ),
        profile_id=profile_id,
        profile_sha256=profile_sha256,
        adapter=_check_verify_str_list(
            inputs["adapter"], "%s.adapter" % (where,)
        ),
        tool_version=tool_version,
        sdk_version=sdk_version,
    )


def _check_verify_rest(artifact: str, doc: dict) -> None:
    """Validate the remaining sidecar bodies (no binding)."""
    where = "sidecar for %r" % (artifact,)
    if not isinstance(doc["transforms"], list) or any(
        not isinstance(item, str) for item in doc["transforms"]
    ):
        raise _verify_fail(
            "%s transforms is not a list of strings" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    for key in (
        "profile_id",
        "source_license",
        "kernel_license",
        "tool_version",
    ):
        if not isinstance(doc[key], str) or not doc[key]:
            raise _verify_fail(
                "%s %s is not a non-empty string" % (where, key),
                where,
                "re-read the published sidecar bytes",
            )
    if not _is_sdk_version(doc["sdk_version"]):
        raise _verify_fail(
            "%s sdk_version is not a major.minor version" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    mapping_version = doc["license_mapping_version"]
    if not _is_exact_int(mapping_version) or mapping_version < 1:
        raise _verify_fail(
            "%s license_mapping_version is not a positive "
            "integer" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    commands = doc["commands"]
    if not isinstance(commands, list):
        raise _verify_fail(
            "%s commands is not a list" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    for index, record in enumerate(commands):
        entry_where = "%s commands[%d]" % (where, index)
        if not isinstance(record, dict) or (
            set(record) != _VERIFY_COMMAND_KEYS
        ):
            raise _verify_fail(
                "%s must hold exactly stage/argv/status/"
                "exit_code" % (entry_where,),
                entry_where,
                "re-read the published sidecar bytes",
            )
        if not isinstance(record["stage"], str) or (
            not record["stage"]
        ):
            raise _verify_fail(
                "%s stage is not a non-empty string"
                % (entry_where,),
                entry_where,
                "re-read the published sidecar bytes",
            )
        argv = record["argv"]
        if not isinstance(argv, list) or any(
            not isinstance(item, str) for item in argv
        ):
            raise _verify_fail(
                "%s argv is not a list of strings" % (entry_where,),
                entry_where,
                "re-read the published sidecar bytes",
            )
        status = record["status"]
        if not isinstance(status, str) or (
            status not in _VERIFY_STATUSES
        ):
            raise _verify_fail(
                "%s status %r is not one of %s"
                % (
                    entry_where,
                    status,
                    ", ".join(sorted(_VERIFY_STATUSES)),
                ),
                entry_where,
                "re-read the published sidecar bytes",
            )
        exit_code = record["exit_code"]
        if exit_code is not None and not _is_exact_int(exit_code):
            raise _verify_fail(
                "%s exit_code is not an integer or null"
                % (entry_where,),
                entry_where,
                "re-read the published sidecar bytes",
            )
    environment = doc["environment"]
    if not isinstance(environment, list):
        raise _verify_fail(
            "%s environment is not a list" % (where,),
            where,
            "re-read the published sidecar bytes",
        )
    for index, record in enumerate(environment):
        entry_where = "%s environment[%d]" % (where, index)
        if not isinstance(record, dict) or (
            set(record) != _VERIFY_ENV_KEYS
        ):
            raise _verify_fail(
                "%s must hold exactly name/value" % (entry_where,),
                entry_where,
                "re-read the published sidecar bytes",
            )
        if not isinstance(record["name"], str) or (
            not record["name"]
        ):
            raise _verify_fail(
                "%s name is not a non-empty string" % (entry_where,),
                entry_where,
                "re-read the published sidecar bytes",
            )
        if not isinstance(record["value"], str):
            raise _verify_fail(
                "%s value is not a string" % (entry_where,),
                entry_where,
                "re-read the published sidecar bytes",
            )


def _check_verify_consistency(
    artifact: str, doc: dict, cache_inputs: CacheInputs
) -> None:
    """Reject top-level values contradicting the recorded inputs.

    ``profile_id``, ``tool_version`` and ``sdk_version`` appear
    both at the top level and inside ``inputs``; a sidecar
    disagreeing with itself on any of them is inconsistent,
    however valid each half is in isolation.
    """
    where = "sidecar for %r" % (artifact,)
    for key in ("profile_id", "tool_version", "sdk_version"):
        recorded = getattr(cache_inputs, key)
        if doc[key] != recorded:
            raise _verify_fail(
                "%s is internally contradictory: top-level %s "
                "%r disagrees with inputs %s %r"
                % (where, key, doc[key], key, recorded),
                where,
                "re-read the published sidecar bytes",
            )


def qualify_artifacts(
    sidecars: Mapping[str, bytes],
    objects: Mapping[str, bytes],
    *,
    run_plan_digest: str | None = None,
    expected_inputs: CacheInputs | None = None,
    expected_run_plan: bytes | None = None,
) -> QualificationReport:
    """Qualify sidecars against live object bytes; bind the result.

    ``sidecars`` maps each artifact name to its published sidecar
    bytes and ``objects`` maps each published file name to its
    live bytes; both mappings are bytes-in, and anything else
    fails closed. Every sidecar must parse as duplicate-free
    JSON, carry exactly the version-4 evidence fields with no
    unknown entries, record a successful build, name the
    artifact it is qualified under, and agree with itself: the
    top-level ``profile_id``/``tool_version``/``sdk_version``
    must equal the corresponding recorded inputs. Every
    ``outputs[]`` entry must be a bound object of that artifact
    -- ``<artifact>.bpf.o`` or ``<artifact>.<entry>.bpf.o`` with
    a non-empty entry -- and the claimed object set must match
    the live-bytes mapping exactly: no missing bytes, no unbound
    bytes, and no object claimed by two sidecars. Each live
    object's SHA-256 and size are compared against its record.

    The returned :class:`QualificationReport` binds each accepted
    object to its sidecar bytes (``sidecar_sha256``), to the
    recorded input set (``inputs_digest``, the cache key over the
    sidecar's inputs), and -- when given -- to the caller's
    ``run_plan_digest`` (a 64-hex digest the aggregator records,
    never recomputes). Two optional expectations turn recording
    into comparison: ``expected_inputs`` (a :class:`CacheInputs`
    every sidecar's recorded inputs must match) and
    ``expected_run_plan`` (plan bytes whose SHA-256 must match
    ``run_plan_digest``, or becomes the recorded digest when
    none was supplied). Without expectations a shape-valid
    sidecar with different inputs qualifies under a different
    digest. Trust limit: this proves the sidecar is consistent
    with the bytes at hand; it does not authenticate either
    against coordinated rewriting (see
    ``docs/artifact-format.md``). Every rejection raises
    ``EvidenceError`` (``MBPF710``) at stage ``evidence.verify``.
    """
    if not isinstance(sidecars, Mapping):
        raise _verify_fail(
            "sidecars must be a mapping of artifact name to "
            "sidecar bytes",
            None,
            "qualify published sidecar bytes",
        )
    if not sidecars:
        raise _verify_fail(
            "no sidecars to qualify",
            None,
            "qualify at least one published sidecar",
        )
    for key in sidecars:
        if not isinstance(key, str) or not key:
            raise _verify_fail(
                "sidecar names must be non-empty strings",
                None,
                "qualify each sidecar under its artifact name",
            )
    for key, raw in sidecars.items():
        if not isinstance(raw, bytes):
            raise _verify_fail(
                "sidecar for %r must be bytes, got %s"
                % (key, type(raw).__name__),
                key,
                "qualify the published sidecar bytes",
            )
    if not isinstance(objects, Mapping):
        raise _verify_fail(
            "objects must be a mapping of file name to live bytes",
            None,
            "qualify against the published object bytes",
        )
    for key in objects:
        if not isinstance(key, str) or not key:
            raise _verify_fail(
                "object names must be non-empty strings",
                None,
                "qualify against the published object bytes",
            )
    for key, payload in objects.items():
        if not isinstance(payload, bytes):
            raise _verify_fail(
                "live bytes for %r must be bytes, got %s"
                % (key, type(payload).__name__),
                key,
                "qualify against the published object bytes",
            )
    if run_plan_digest is not None and not _is_sha256(
        run_plan_digest
    ):
        raise _verify_fail(
            "run_plan_digest must be a 64-hex digest or None",
            None,
            "bind the qualification to the run plan's digest",
        )
    if expected_inputs is not None and not isinstance(
        expected_inputs, CacheInputs
    ):
        raise _verify_fail(
            "expected_inputs must be CacheInputs or None, got %s"
            % type(expected_inputs).__name__,
            None,
            "compare against the planned CacheInputs",
        )
    if expected_run_plan is not None and not isinstance(
        expected_run_plan, bytes
    ):
        raise _verify_fail(
            "expected_run_plan must be bytes or None, got %s"
            % type(expected_run_plan).__name__,
            None,
            "compare against the planned run-plan bytes",
        )
    if expected_run_plan is not None:
        planned = hashlib.sha256(expected_run_plan).hexdigest()
        if run_plan_digest is None:
            run_plan_digest = planned
        elif run_plan_digest != planned:
            raise _verify_fail(
                "run plan content does not match run_plan_digest: "
                "content hashes to %s, digest supplied is %s"
                % (planned, run_plan_digest),
                None,
                "supply the run plan whose digest was recorded",
            )
    want_inputs_digest = (
        cache_key(expected_inputs)
        if expected_inputs is not None
        else None
    )
    claims: dict[str, str] = {}
    parsed: list[
        tuple[
            str, bytes, list[tuple[str, str, int]], CacheInputs
        ]
    ] = []
    for artifact in sorted(sidecars):
        raw = sidecars[artifact]
        doc = _parse_sidecar(artifact, raw)
        outputs = _check_verify_outputs(artifact, doc)
        cache_inputs = _check_verify_inputs(artifact, doc)
        _check_verify_rest(artifact, doc)
        _check_verify_consistency(artifact, doc, cache_inputs)
        for name, _want_hex, _want_size in outputs:
            if name in claims:
                raise _verify_fail(
                    "object %r is claimed by two sidecars (%r "
                    "and %r)" % (name, claims[name], artifact),
                    name,
                    "publish each object under one artifact",
                )
            claims[name] = artifact
        parsed.append((artifact, raw, outputs, cache_inputs))
    for name in sorted(claims):
        if name not in objects:
            raise _verify_fail(
                "object %r of artifact %r has no live bytes; "
                "unbound claims do not qualify"
                % (name, claims[name]),
                name,
                "qualify against the published object bytes",
            )
    for name in sorted(objects):
        if name not in claims:
            raise _verify_fail(
                "live bytes for %r are not bound by any sidecar"
                % (name,),
                name,
                "drop the unbound bytes or qualify their sidecar",
            )
    records: list[QualifiedArtifact] = []
    for artifact, raw, outputs, cache_inputs in parsed:
        sidecar_digest = hashlib.sha256(raw).hexdigest()
        inputs_digest = cache_key(cache_inputs)
        if want_inputs_digest is not None and (
            inputs_digest != want_inputs_digest
        ):
            raise _verify_fail(
                "sidecar for %r records inputs %s, expected %s"
                % (artifact, inputs_digest, want_inputs_digest),
                artifact,
                "rebuild from the expected inputs, or qualify "
                "without an expectation",
            )
        for name, want_hex, want_size in outputs:
            live = objects[name]
            live_hex = hashlib.sha256(live).hexdigest()
            if len(live) != want_size or live_hex != want_hex:
                raise _verify_fail(
                    "object %r bytes do not match sidecar %r: "
                    "recorded sha256 %s size %d, live sha256 %s "
                    "size %d"
                    % (
                        name,
                        artifact,
                        want_hex,
                        want_size,
                        live_hex,
                        len(live),
                    ),
                    name,
                    "republish the object and its sidecar together",
                )
            records.append(
                QualifiedArtifact(
                    artifact=artifact,
                    object_name=name,
                    object_sha256=want_hex,
                    object_size=want_size,
                    sidecar_sha256=sidecar_digest,
                    inputs_digest=inputs_digest,
                )
            )
    records.sort(key=lambda item: (item.artifact, item.object_name))
    return QualificationReport(
        schema_version=QUALIFICATION_SCHEMA_VERSION,
        run_plan_digest=run_plan_digest,
        artifacts=tuple(records),
    )
