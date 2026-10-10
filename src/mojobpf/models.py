# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Versioned serializable build models shared by driver and evidence.

This module is a leaf: it imports only :mod:`mojobpf.diagnostics`
(the stable diagnostic vocabulary) and :mod:`mojobpf.execution`
(the ``execution-contract-v1`` command records), and it is imported
by both :mod:`mojobpf.build` (the driver) and
:mod:`mojobpf.evidence` (provenance capture and publication). The
build result/request models used to live in the driver, which
forced a ``build`` <-> ``evidence`` import cycle contained by a
deferred import; moving the seam types here deletes that cycle,
so both consumers import this leaf at module level instead.

The module also owns :func:`is_int`, the canonical
genuine-integer predicate. It used to be the private
``manifest._is_int`` imported cross-module; the public spelling
here is the single home, and ``manifest`` keeps a compatibility
alias only.

Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass

from .diagnostics import Diagnostic
from .execution import CommandRecord

BUILD_SCHEMA_VERSION = 1

DEFAULT_TIMEOUT_S = 600


def is_int(value: object) -> bool:
    """Return True for genuine integers, excluding booleans.

    ``bool`` is an ``int`` subclass, but a schema version or a
    timeout of ``True`` is never meaningful input, so booleans
    fail closed here like any other non-integer.
    """
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class BuildRequest:
    """Inputs for :func:`mojobpf.build.build_project`.

    ``manifest_path`` points at the project manifest, ``out_dir`` is
    the directory receiving the built objects (created when missing),
    and ``adapter_path`` points at the adapter service script (an
    explicit path: the driver never guesses tool locations).
    ``lockfile_path`` points at the pinned toolchain lockfile;
    ``mojo`` and ``llc`` are admitted against it before anything
    compiles, and only the admitted binaries run (a missing lockfile
    fails the build with ``MBPF104``).
    ``search_paths`` are prepended to ``PATH`` when resolving ``mojo``
    and ``llc``. ``timeout_s`` bounds every build subprocess; it is a
    per-step budget, so after an adapter failure the diagnose
    re-emit may consume up to a further full budget mapping audit
    findings to source lines before the build result returns.
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
        if not is_int(self.schema_version) or (
            self.schema_version != BUILD_SCHEMA_VERSION
        ):
            raise ValueError(
                "unsupported BuildRequest schema_version %r; "
                "this driver reads version %d"
                % (self.schema_version, BUILD_SCHEMA_VERSION)
            )
        if not is_int(self.timeout_s) or self.timeout_s < 1:
            raise ValueError(
                "timeout_s must be a positive integer, got %r"
                % (self.timeout_s,)
            )
        object.__setattr__(self, "search_paths", tuple(self.search_paths))


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
    admission). ``adapter_trust`` records the adapter choice:
    ``"default"`` (the packaged service, pin-matched),
    ``"default-unpinned"`` (the packaged service under a lockfile
    without adapter pins -- not release-qualifying), or
    ``"extension"`` (an explicit opt-in service, never
    default-qualified). ``tool_version``/``sdk_version`` stamp the
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
    adapter_trust: str = "default"


@dataclass(frozen=True)
class BuildResult:
    """Versioned outcome of :func:`mojobpf.build.build_project`.

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
