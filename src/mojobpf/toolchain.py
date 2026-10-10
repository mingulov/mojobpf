# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Toolchain discovery and lockfile matching.

:func:`probe_toolchain` inspects the local machine for the required
build tools (``mojo``, ``llc``, ``bpftool`` and ``python3``), records
their versions and binary hashes, and optionally matches them against a
pinned lockfile. Discovery and validated support are separate states:
the report always describes what was found, while the ``supported``
verdict is true only when every required tool is present and matches
the lockfile (and the requested profile, if any, is registered).
:func:`admit_tools` reuses the same discovery and pin matching to
admit exactly the named build tools for one locked build.

Admission runs through ``execution-contract-v1``
(:mod:`mojobpf.execution`): every tool is resolved once, hashed, and
compared against its lockfile pin -- including the launcher ``exec``
target -- before any ``--version`` probe starts, and probes execute
the captured absolute path, never a re-resolved bare name. A
substituted tool is rejected with ``MBPF102`` without executing.

This module never installs, downloads or modifies anything, and it never
falls back silently: a missing tool stays missing, a tool whose version
probe fails stays broken, and an unreadable or version-unknown lockfile
fails loudly instead of being partially interpreted. Lockfile entries
for tools outside the required set are informational and are not
matched; that scoping is documented here rather than guessed per tool.

Standard library only.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .diagnostics import (
    STAGE_TOOLCHAIN_DISCOVERY,
    STAGE_TOOLCHAIN_MATCH,
    Diagnostic,
    SEVERITY_ERROR,
    SEVERITY_NOTE,
)
from .execution import (
    FORM_EXEC_LAUNCHER,
    FORM_UNKNOWN,
    REASON_LAUNCHER_UNKNOWN,
    REASON_NOT_FOUND,
    REASON_PROBE_FAILED,
    REASON_VERSION_MISMATCH,
    AdmittedExecution,
    AdmissionError,
    ExecutionPins,
    ExecutionRequest,
    admit_execution,
    capture_chain,
    first_output_line,
    follow_exec_target as _follow_exec_target,
    is_hex_digest,
    resolve_entry,
)
from .manifest import ProfileError, lookup_profile
from .models import is_int

TOOLCHAIN_SCHEMA_VERSION = 1
LOCKFILE_SCHEMA_VERSION = 1

REQUIRED_TOOLS = ("mojo", "llc", "bpftool", "python")

DISCOVERY_ARGV = {
    "mojo": ("mojo", "--version"),
    "llc": ("llc", "--version"),
    "bpftool": ("bpftool", "version"),
    "python": ("python3", "--version"),
}

DISCOVERY_TIMEOUT = 30

TOOL_PRESENT = "present"
TOOL_MISSING = "missing"
TOOL_BROKEN = "broken"

LOCKFILE_MATCHED = "matched"
LOCKFILE_MISMATCHED = "mismatched"
LOCKFILE_UNREADABLE = "unreadable"
LOCKFILE_UNSUPPORTED_VERSION = "unsupported_version"
LOCKFILE_NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class ToolchainConfig:
    """Inputs for :func:`probe_toolchain`.

    ``lockfile_path`` points at a pinned toolchain lockfile; when it is
    ``None`` the report carries discovery only and the lockfile state is
    ``"not_checked"``. ``profile_id`` optionally requests a
    target-profile membership check. ``search_paths`` are prepended to
    ``PATH`` during discovery (used by tests to plant fixture tools);
    the process environment is never modified.
    """

    schema_version: int = TOOLCHAIN_SCHEMA_VERSION
    lockfile_path: str | None = None
    profile_id: str | None = None
    search_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not is_int(self.schema_version) or (
            self.schema_version != TOOLCHAIN_SCHEMA_VERSION
        ):
            raise ValueError(
                "unsupported ToolchainConfig schema_version %r; "
                "this driver reads version %d"
                % (self.schema_version, TOOLCHAIN_SCHEMA_VERSION)
            )
        object.__setattr__(self, "search_paths", tuple(self.search_paths))


@dataclass(frozen=True)
class ToolInfo:
    """Discovery record for one required tool.

    ``status`` is ``"present"``, ``"missing"`` or ``"broken"``. Present
    tools carry the resolved ``path``, the first ``version`` line and
    the ``sha256`` of the resolved entry. When the entry is a launcher
    script whose ``exec`` chain resolves statically,
    ``exec_path``/``exec_sha256`` record the actually-executed image;
    both are None when the entry is itself the executed image or when
    the chain does not resolve (unreadable, ambiguous, dangling or
    over the depth bound). Lockfile pins match the entry ``sha256``
    and, for launchers, the ``exec_sha256``. A tool rejected against
    its pin before probing carries ``version=None``: the probe never
    ran, so there is no version to report. ``execution`` holds the
    ``execution-contract-v1`` admission when the tool was fully
    admitted (present and pin-matched), else None.
    """

    name: str
    status: str
    path: str | None = None
    version: str | None = None
    sha256: str | None = None
    exec_path: str | None = None
    exec_sha256: str | None = None
    execution: AdmittedExecution | None = None


@dataclass(frozen=True)
class ToolchainReport:
    """Versioned result of :func:`probe_toolchain`.

    ``tools`` holds discovery in ``REQUIRED_TOOLS`` order.
    ``lockfile_status`` is one of ``"matched"``, ``"mismatched"``,
    ``"unreadable"``, ``"unsupported_version"`` or ``"not_checked"``.
    ``profile_supported`` is true when a requested profile is
    registered. ``supported`` is the validated-support verdict: true
    only when the lockfile matched, every required tool is present, and
    a requested profile is registered. ``diagnostics`` holds every
    finding in deterministic order.
    """

    schema_version: int
    tools: tuple[ToolInfo, ...]
    lockfile_path: str | None
    lockfile_status: str
    profile_id: str | None
    profile_supported: bool
    supported: bool
    diagnostics: tuple[Diagnostic, ...]


def probe_toolchain(config: ToolchainConfig) -> ToolchainReport:
    """Discover tools and match them against the lockfile.

    Never raises for environment findings: missing or broken tools,
    lockfile problems and unknown profiles are reported as diagnostics
    with deterministic codes and reflected in ``supported``:

    * ``MBPF101``: unsupported target profile.
    * ``MBPF102``: tool does not match the lockfile pin.
    * ``MBPF103``: required tool missing or broken.
    * ``MBPF104``: lockfile unreadable or of unsupported version.
    * ``MBPF105``: validation skipped, no lockfile supplied (note).

    When a readable lockfile is supplied, each tool's static pin
    check (entry hash, launcher ``exec`` hash, launcher form) runs
    before its version probe, and a rejected tool is never
    executed. Without a lockfile the probe is purely observational.
    A supplied lockfile that cannot be loaded (missing file,
    invalid JSON, unsupported schema) fails closed: every tool is
    still resolved and hashed statically, but no version probe
    runs (``version`` stays ``None``), so invalid input never
    falls back to unpinned discovery. A lockfile carrying a
    ``distribution`` record also has that closure binding
    enforced: a missing file, a placeholder digest or a byte
    mismatch fails the match (``MBPF102``) -- and then no tool is
    probed at all, so a failed distribution binding allows zero
    probes.
    """
    if not isinstance(config, ToolchainConfig):
        raise ValueError("probe_toolchain requires a ToolchainConfig")
    discovery_diagnostics: list[Diagnostic] = []
    lock_diagnostics: list[Diagnostic] = []
    match_diagnostics: list[Diagnostic] = []
    lockfile_status = LOCKFILE_NOT_CHECKED
    tools_table: dict | None = None
    trust_root = ""
    if config.lockfile_path is None:
        lock_diagnostics.append(
            Diagnostic(
                code="MBPF105",
                stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_NOTE,
                explanation="no lockfile supplied; "
                "reporting discovery without validation",
                remedy="pass a lockfile_path to validate the toolchain",
            )
        )
    else:
        tools_table, lockfile_status, lock_diags = load_toolchain_lock(
            config.lockfile_path
        )
        lock_diagnostics.extend(lock_diags)
        if tools_table is not None:
            trust_root = "lock:%s" % (config.lockfile_path,)
    dist_ok = True
    if tools_table is not None and config.lockfile_path is not None:
        dist_diag = check_toolchain_distribution(config.lockfile_path)
        if dist_diag is not None:
            lock_diagnostics.append(dist_diag)
            dist_ok = False
    examined: list[ToolInfo] = []
    matched = tools_table is not None
    # A supplied-but-unloadable lockfile fails closed: the tools
    # are resolved and hashed statically below, but the
    # observational probe path is unreachable (see _examine_tool),
    # so invalid input never falls back to unpinned discovery.
    lock_invalid = (
        config.lockfile_path is not None and tools_table is None
    )
    for name in REQUIRED_TOOLS:
        entry = tools_table.get(name) if tools_table is not None else None
        tool, tool_matched = _examine_tool(
            name,
            config.search_paths,
            entry,
            tools_table is not None,
            config.lockfile_path,
            trust_root,
            discovery_diagnostics,
            match_diagnostics,
            probes_allowed=dist_ok,
            lock_invalid=lock_invalid,
        )
        examined.append(tool)
        matched = matched and tool_matched
    tools = tuple(examined)
    if tools_table is not None:
        lockfile_status = (
            LOCKFILE_MATCHED
            if (matched and dist_ok)
            else LOCKFILE_MISMATCHED
        )
    diagnostics = (
        discovery_diagnostics + lock_diagnostics + match_diagnostics
    )

    profile_supported = False
    if config.profile_id is not None:
        try:
            lookup_profile(config.profile_id)
        except ProfileError as exc:
            diagnostic = exc.diagnostic
            diagnostics.append(
                Diagnostic(
                    code=diagnostic.code,
                    stage=diagnostic.stage,
                    severity=diagnostic.severity,
                    explanation=diagnostic.explanation,
                    location="profile_id",
                    remedy=diagnostic.remedy,
                )
            )
        else:
            profile_supported = True

    supported = (
        lockfile_status == LOCKFILE_MATCHED
        and all(tool.status == TOOL_PRESENT for tool in tools)
        and (config.profile_id is None or profile_supported)
    )
    return ToolchainReport(
        schema_version=TOOLCHAIN_SCHEMA_VERSION,
        tools=tools,
        lockfile_path=config.lockfile_path,
        lockfile_status=lockfile_status,
        profile_id=config.profile_id,
        profile_supported=profile_supported,
        supported=supported,
        diagnostics=tuple(diagnostics),
    )


def _missing_tool(
    name: str, diagnostics: list[Diagnostic]
) -> ToolInfo:
    diagnostics.append(
        Diagnostic(
            code="MBPF103",
            stage=STAGE_TOOLCHAIN_DISCOVERY,
            severity=SEVERITY_ERROR,
            explanation="required tool not found on PATH: %s" % name,
            location="tool:%s" % name,
            remedy="install %s or fix PATH; "
            "no substitute tool is used" % DISCOVERY_ARGV[name][0],
        )
    )
    return ToolInfo(name=name, status=TOOL_MISSING)


def _broken_tool(
    name: str,
    path: str | None,
    explanation: str,
    diagnostics: list[Diagnostic],
) -> ToolInfo:
    diagnostics.append(
        Diagnostic(
            code="MBPF103",
            stage=STAGE_TOOLCHAIN_DISCOVERY,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location="tool:%s" % name,
            remedy="check the installation of %s" % name,
        )
    )
    return ToolInfo(name=name, status=TOOL_BROKEN, path=path)


def _observational_probe(
    name: str, entry_abspath: str, search_paths: tuple[str, ...]
) -> tuple[str | None, str | None]:
    """Probe an unadmitted entry observationally (no lockfile).

    Used only when no lockfile was supplied at all: discovery
    without a trust root reports what executes at the resolved
    absolute path. Returns ``(version, failure)`` with exactly one
    set. Callers with a lockfile never reach this: a loaded
    lockfile rejects before any probe, and a supplied-but-invalid
    lockfile fails closed without probing.
    """
    current = os.environ.get("PATH", "")
    extra = os.pathsep.join(search_paths)
    if extra and current:
        search_path = extra + os.pathsep + current
    else:
        search_path = extra or current
    child_env = dict(os.environ)
    child_env["PATH"] = search_path
    try:
        completed = subprocess.run(
            [entry_abspath, *DISCOVERY_ARGV[name][1:]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=DISCOVERY_TIMEOUT,
            env=child_env,
        )
    except UnicodeDecodeError as exc:
        return None, (
            "tool version probe printed undecodable output for %s: %s"
            % (name, exc)
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "tool version probe failed for %s: %s" % (name, exc)
    if completed.returncode != 0:
        return None, "tool version probe exited %d for %s" % (
            completed.returncode,
            name,
        )
    version = first_output_line(completed.stdout, completed.stderr)
    if version is None:
        return None, "tool version probe printed nothing for %s" % name
    return version, None


def _examine_tool(
    name: str,
    search_paths: tuple[str, ...],
    lock_entry,
    lock_loaded: bool,
    lockfile_path: str | None,
    trust_root: str,
    discovery_diagnostics: list[Diagnostic],
    match_diagnostics: list[Diagnostic],
    *,
    probes_allowed: bool,
    lock_invalid: bool = False,
) -> tuple[ToolInfo, bool]:
    """Resolve, capture and optionally admit one tool.

    Returns the :class:`ToolInfo` and whether it matched its pin
    (always False when no lockfile was loaded). Without a
    supplied lockfile the probe is purely observational; with
    one, the static pin check precedes the probe and a rejected
    tool never executes. When ``probes_allowed`` is false (the
    lockfile's distribution binding failed) or ``lock_invalid``
    is true (a lockfile was supplied but could not be loaded)
    the tool is resolved and captured statically but never
    probed, carrying ``version=None`` like any pre-probe
    rejection. The observational path is reachable only when no
    lockfile was supplied at all.
    """
    try:
        entry_path = resolve_entry(
            ExecutionRequest(
                name=name,
                argv0=DISCOVERY_ARGV[name][0],
                search_paths=tuple(search_paths),
            )
        )
    except AdmissionError:
        return _missing_tool(name, discovery_diagnostics), False
    try:
        captured = capture_chain(entry_path)
    except AdmissionError as exc:
        return (
            _broken_tool(
                name,
                entry_path,
                "cannot hash tool binary %s: %s" % (entry_path, exc.detail),
                discovery_diagnostics,
            ),
            False,
        )
    if captured.form == FORM_EXEC_LAUNCHER:
        entry_identity = captured.hops[0]
        exec_path: str | None = captured.image.realpath
        exec_digest: str | None = captured.image.sha256
    else:
        entry_identity = captured.image
        exec_path = None
        exec_digest = None
    observed = ToolInfo(
        name=name,
        status=TOOL_PRESENT,
        path=entry_path,
        version=None,
        sha256=entry_identity.sha256,
        exec_path=exec_path,
        exec_sha256=exec_digest,
    )
    if not lock_loaded:
        if lock_invalid:
            # A lockfile was supplied but could not be loaded
            # (already diagnosed as MBPF104 by the caller): the
            # tool keeps its static capture with version=None and
            # is never probed, so invalid input never falls back
            # to unpinned discovery.
            return observed, False
        return _examine_observational(
            name,
            search_paths,
            captured,
            observed,
            entry_path,
            discovery_diagnostics,
        )
    return _examine_against_pin(
        name,
        search_paths,
        captured,
        observed,
        entry_path,
        lock_entry,
        lockfile_path or "",
        trust_root,
        discovery_diagnostics,
        match_diagnostics,
        probes_allowed=probes_allowed,
    )


def _examine_observational(
    name: str,
    search_paths: tuple[str, ...],
    captured,
    observed: ToolInfo,
    entry_path: str,
    discovery_diagnostics: list[Diagnostic],
) -> tuple[ToolInfo, bool]:
    """Probe without pins; report whatever the entry does."""
    if captured.form == FORM_UNKNOWN:
        # No trust root constrains this probe, so observation
        # still runs the entry (as before); admission paths
        # reject unknown forms without executing.
        observed = ToolInfo(
            name=observed.name,
            status=observed.status,
            path=observed.path,
            version=None,
            sha256=observed.sha256,
            exec_path=None,
            exec_sha256=None,
        )
    version, failure = _observational_probe(name, entry_path, search_paths)
    if failure is not None:
        return (
            _broken_tool(name, entry_path, failure, discovery_diagnostics),
            False,
        )
    return (
        ToolInfo(
            name=observed.name,
            status=TOOL_PRESENT,
            path=observed.path,
            version=version,
            sha256=observed.sha256,
            exec_path=observed.exec_path,
            exec_sha256=observed.exec_sha256,
        ),
        False,
    )


def _pin_mismatch(
    name: str,
    lockfile_path: str,
    explanation: str,
    match_diagnostics: list[Diagnostic],
) -> None:
    match_diagnostics.append(
        Diagnostic(
            code="MBPF102",
            stage=STAGE_TOOLCHAIN_MATCH,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location="%s: tools.%s" % (lockfile_path, name),
            remedy="install the pinned %s or re-pin the lockfile "
            "deliberately" % name,
        )
    )


def _examine_against_pin(
    name: str,
    search_paths: tuple[str, ...],
    captured,
    observed: ToolInfo,
    entry_path: str,
    lock_entry,
    lockfile_path: str,
    trust_root: str,
    discovery_diagnostics: list[Diagnostic],
    match_diagnostics: list[Diagnostic],
    *,
    probes_allowed: bool,
) -> tuple[ToolInfo, bool]:
    """Admit against the lockfile pin; reject before probing."""
    if not probes_allowed:
        # The lockfile's distribution binding already failed
        # (diagnosed by the caller): the tool keeps its static
        # capture with version=None and is never probed, so a
        # failed distribution allows zero probes.
        return observed, False
    if not isinstance(lock_entry, dict):
        _pin_mismatch(
            name,
            lockfile_path,
            "tool %r has no pin in the lockfile" % name,
            match_diagnostics,
        )
        return observed, False
    pinned_version = lock_entry.get("version")
    pinned_sha = lock_entry.get("sha256")
    if not isinstance(pinned_version, str) or not isinstance(
        pinned_sha, str
    ):
        match_diagnostics.append(
            Diagnostic(
                code="MBPF104",
                stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR,
                explanation="lockfile pin for %r lacks a string "
                "version/sha256 pair" % name,
                location="%s: tools.%s" % (lockfile_path, name),
                remedy="restore a valid lockfile entry for %s" % name,
            )
        )
        return observed, False
    if captured.form == FORM_UNKNOWN:
        _pin_mismatch(
            name,
            lockfile_path,
            "tool %r is not a supported executable form (%s); "
            "unknown launchers are rejected, never guessed"
            % (name, captured.note),
            match_diagnostics,
        )
        return observed, False
    pins = _pins_from_entry(lock_entry)
    try:
        admitted = admit_execution(
            ExecutionRequest(
                name=name,
                argv0=entry_path,
                search_paths=tuple(search_paths),
                allow_path_lookup=False,
                version_argv=DISCOVERY_ARGV[name][1:],
                probe_version=True,
                trust_root=trust_root,
            ),
            pins,
            probe_timeout=DISCOVERY_TIMEOUT,
        )
    except AdmissionError as exc:
        if exc.reason in (REASON_NOT_FOUND, REASON_PROBE_FAILED):
            return (
                _broken_tool(
                    name,
                    entry_path,
                    "tool version probe failed for %s: %s"
                    % (name, exc.detail),
                    discovery_diagnostics,
                ),
                False,
            )
        if exc.reason == REASON_LAUNCHER_UNKNOWN:
            detail = "tool %r is not a supported executable form (%s)" % (
                name,
                exc.detail,
            )
        elif exc.reason == REASON_VERSION_MISMATCH:
            detail = (
                "tool %r does not match the lockfile pin "
                "(found version %r)" % (name, exc.observed)
            )
        else:
            detail = "tool %r does not match the lockfile pin (%s)" % (
                name,
                exc.detail,
            )
        _pin_mismatch(name, lockfile_path, detail, match_diagnostics)
        return observed, False
    except UnicodeDecodeError as exc:
        return (
            _broken_tool(
                name,
                entry_path,
                "tool version probe printed undecodable output for %s: %s"
                % (name, exc),
                discovery_diagnostics,
            ),
            False,
        )
    return (
        ToolInfo(
            name=name,
            status=TOOL_PRESENT,
            path=entry_path,
            version=admitted.version,
            sha256=observed.sha256,
            exec_path=observed.exec_path,
            exec_sha256=observed.exec_sha256,
            execution=admitted,
        ),
        True,
    )


def _pins_from_entry(lock_entry: dict) -> ExecutionPins:
    """Build admission pins from one lockfile tool entry."""
    return ExecutionPins(
        version=lock_entry.get("version"),
        entry_sha256=lock_entry.get("sha256"),
        exec_sha256=lock_entry.get("exec_sha256"),
        exec_pin_present="exec_sha256" in lock_entry,
        interpreter_sha256=lock_entry.get("interpreter_sha256"),
        interpreter_pin_present="interpreter_sha256" in lock_entry,
    )


def load_toolchain_lock(
    lockfile_path: str,
) -> tuple[dict | None, str, tuple[Diagnostic, ...]]:
    """Load a toolchain lockfile's tools table (no probing).

    Returns ``(tools_table_or_None, status, diagnostics)`` where
    ``status`` is ``LOCKFILE_MATCHED``-neutral: ``LOCKFILE_UNREADABLE``
    or ``LOCKFILE_UNSUPPORTED_VERSION`` on load failure, else
    ``LOCKFILE_MATCHED`` as a neutral "loaded" marker (callers
    compute the real match verdict per tool). Lockfile entries for
    tools outside the required set stay informational.
    """
    diagnostics: list[Diagnostic] = []
    try:
        raw = Path(lockfile_path).read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        diagnostics.append(
            Diagnostic(
                code="MBPF104",
                stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR,
                explanation="cannot read lockfile: %s" % exc,
                location=lockfile_path,
                remedy="check the lockfile path and file permissions",
            )
        )
        return None, LOCKFILE_UNREADABLE, tuple(diagnostics)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        diagnostics.append(
            Diagnostic(
                code="MBPF104",
                stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR,
                explanation="lockfile is not valid JSON: %s" % exc,
                location=lockfile_path,
                remedy="restore a valid lockfile",
            )
        )
        return None, LOCKFILE_UNREADABLE, tuple(diagnostics)
    version = data.get("schema_version") if isinstance(data, dict) else None
    if not is_int(version) or version != LOCKFILE_SCHEMA_VERSION:
        diagnostics.append(
            Diagnostic(
                code="MBPF104",
                stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR,
                explanation="unsupported lockfile schema_version; "
                "this driver reads version %d" % LOCKFILE_SCHEMA_VERSION,
                location=lockfile_path,
                remedy="use a lockfile with schema_version %d"
                % LOCKFILE_SCHEMA_VERSION,
            )
        )
        return None, LOCKFILE_UNSUPPORTED_VERSION, tuple(diagnostics)
    entries = data.get("tools")
    if not isinstance(entries, dict):
        diagnostics.append(
            Diagnostic(
                code="MBPF104",
                stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR,
                explanation="lockfile has no tools table",
                location=lockfile_path,
                remedy="restore a valid lockfile",
            )
        )
        return None, LOCKFILE_UNREADABLE, tuple(diagnostics)
    return entries, LOCKFILE_MATCHED, tuple(diagnostics)


def load_toolchain_document(lockfile_path: str) -> dict | None:
    """Return the parsed lockfile document, or None when unreadable.

    Used for the lock's non-tool trust records (such as the
    adapter pins); tool admission itself goes through
    :func:`load_toolchain_lock` plus per-tool examination.
    """
    try:
        raw = Path(lockfile_path).read_bytes().decode("utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not is_int(data.get("schema_version")) or (
        data.get("schema_version") != LOCKFILE_SCHEMA_VERSION
    ):
        return None
    return data


def _sha256_of_file(path: str) -> str:
    """Return the hex SHA-256 of a file's bytes (may raise OSError)."""
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_toolchain_distribution(
    lockfile_path: str,
) -> Diagnostic | None:
    """Enforce the lockfile's distribution closure binding (no spawn).

    The ``distribution`` record binds the native dynamic closure
    (loader, libc, linked libraries) and the toolchain install
    that per-file executable hashes cannot capture. A lockfile
    without the record (test/legacy locks) enforces nothing; a
    present record is verified, never trusted descriptively:
    ``file`` (resolved beside the lockfile unless absolute) must
    exist and its bytes must match ``sha256``. An all-zero
    placeholder digest is explicitly rejected and can never
    match. Returns None when the binding holds (or is absent),
    else the ``MBPF104`` diagnostic (malformed record) or
    ``MBPF102`` diagnostic (binding failure).
    """
    document = load_toolchain_document(lockfile_path)
    if document is None:
        return None
    record = document.get("distribution")
    if record is None:
        return None
    if not isinstance(record, dict):
        return Diagnostic(
            code="MBPF104",
            stage=STAGE_TOOLCHAIN_MATCH,
            severity=SEVERITY_ERROR,
            explanation="lockfile distribution record is not a mapping",
            location="%s: distribution" % (lockfile_path,),
            remedy="restore a valid lockfile distribution record",
        )
    filename = record.get("file")
    digest = record.get("sha256")
    if not isinstance(filename, str) or not filename:
        return Diagnostic(
            code="MBPF104",
            stage=STAGE_TOOLCHAIN_MATCH,
            severity=SEVERITY_ERROR,
            explanation="lockfile distribution record lacks a file string",
            location="%s: distribution" % (lockfile_path,),
            remedy="restore a valid lockfile distribution record",
        )
    if not is_hex_digest(
        digest.lower() if isinstance(digest, str) else digest
    ):
        return Diagnostic(
            code="MBPF104",
            stage=STAGE_TOOLCHAIN_MATCH,
            severity=SEVERITY_ERROR,
            explanation="lockfile distribution record carries a "
            "malformed sha256 digest",
            location="%s: distribution" % (lockfile_path,),
            remedy="restore a valid lockfile distribution record",
        )
    assert isinstance(digest, str)
    if digest.lower() == "0" * 64:
        return Diagnostic(
            code="MBPF102",
            stage=STAGE_TOOLCHAIN_MATCH,
            severity=SEVERITY_ERROR,
            explanation="lockfile distribution pins the all-zero "
            "placeholder digest",
            location="%s: distribution" % (lockfile_path,),
            remedy="re-pin the lockfile distribution deliberately",
        )
    candidate = (
        filename
        if os.path.isabs(filename)
        else os.path.join(
            os.path.dirname(os.path.abspath(lockfile_path)), filename
        )
    )
    try:
        observed = _sha256_of_file(candidate)
    except OSError:
        return Diagnostic(
            code="MBPF102",
            stage=STAGE_TOOLCHAIN_MATCH,
            severity=SEVERITY_ERROR,
            explanation="lockfile distribution file %r does not exist "
            "or is unreadable" % (filename,),
            location="%s: distribution" % (lockfile_path,),
            remedy="restore the pinned distribution or re-pin the "
            "lockfile deliberately",
        )
    if observed != digest.lower():
        return Diagnostic(
            code="MBPF102",
            stage=STAGE_TOOLCHAIN_MATCH,
            severity=SEVERITY_ERROR,
            explanation="lockfile distribution file %r hash %s does "
            "not match the pin" % (filename, observed),
            location="%s: distribution" % (lockfile_path,),
            remedy="restore the pinned distribution or re-pin the "
            "lockfile deliberately",
        )
    return None


def admit_tools(
    *,
    lockfile_path: str | None,
    search_paths: tuple[str, ...] = (),
    names: tuple[str, ...] = ("mojo", "llc"),
) -> tuple[dict[str, ToolInfo], tuple[Diagnostic, ...]]:
    """Admit named build tools against a lockfile for one build.

    Admits exactly ``names`` (default the build tools ``mojo`` and
    ``llc``) through ``execution-contract-v1``: each tool is
    resolved once, hashed, and compared against its lockfile pin
    (entry hash, launcher ``exec`` hash, then the version probe
    through the admitted chain). Admission is all-or-nothing: the
    returned mapping holds a present, pin-matched :class:`ToolInfo`
    -- each carrying its :class:`AdmittedExecution` -- per name on
    success and is empty otherwise. Diagnostics use the
    discovery/matching codes (``MBPF102`` pin mismatch,
    ``MBPF103`` missing or broken tool, ``MBPF104`` lockfile
    problem). When the lockfile carries a ``distribution``
    record its closure binding is enforced first: a failed
    binding refuses admission before any tool is examined.
    A missing lockfile is ``MBPF104``, never a silent
    unvalidated build: callers spawn through the admitted
    executions or fail, and no probe runs before the static pin
    check passes.
    """
    diagnostics: list[Diagnostic] = []
    for name in names:
        if name not in DISCOVERY_ARGV:
            raise ValueError("admit_tools cannot discover %r" % (name,))
    if lockfile_path is None:
        diagnostics.append(
            Diagnostic(
                code="MBPF104",
                stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR,
                explanation="no lockfile supplied; locked builds "
                "require lockfile validation",
                location=None,
                remedy="pass the pinned toolchains lockfile",
            )
        )
        return {}, tuple(diagnostics)
    tools_table, _status, lock_diags = load_toolchain_lock(lockfile_path)
    if tools_table is None:
        diagnostics.extend(lock_diags)
        return {}, tuple(diagnostics)
    dist_diag = check_toolchain_distribution(lockfile_path)
    if dist_diag is not None:
        diagnostics.append(dist_diag)
        return {}, tuple(diagnostics)
    trust_root = "lock:%s" % (lockfile_path,)
    by_name: dict[str, ToolInfo] = {}
    failed = False
    for name in names:
        discovery_diagnostics: list[Diagnostic] = []
        match_diagnostics: list[Diagnostic] = []
        tool, tool_matched = _examine_tool(
            name,
            tuple(search_paths),
            tools_table.get(name),
            True,
            lockfile_path,
            trust_root,
            discovery_diagnostics,
            match_diagnostics,
            # The distribution binding held (failure returned
            # above), so probes are allowed here.
            probes_allowed=True,
        )
        diagnostics.extend(discovery_diagnostics)
        diagnostics.extend(match_diagnostics)
        if not tool_matched or tool.status != TOOL_PRESENT:
            failed = True
        else:
            by_name[name] = tool
    if failed:
        return {}, tuple(diagnostics)
    return by_name, tuple(diagnostics)
