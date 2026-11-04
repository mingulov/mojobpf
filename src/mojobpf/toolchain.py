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
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, replace
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
    STATUS_OK,
    AdmittedExecution,
    AdmissionError,
    ExecutionPins,
    ExecutionRequest,
    admit_execution,
    capture_chain,
    filter_spawn_ambient,
    first_output_line,
    follow_exec_target as _follow_exec_target,
    is_hex_digest,
    resolve_entry,
    run_admitted,
)
from .manifest import ProfileError, lookup_profile
from .models import is_int

TOOLCHAIN_SCHEMA_VERSION = 1
LOCKFILE_SCHEMA_VERSION = 1
NATIVE_LOCKFILE_SCHEMA_VERSION = 2

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

# Qualified frontend LLVM dialect: the exact LLVM header lines the
# qualified mojo emits for the frozen frontend target, plus the flags
# reproducing them. The dialect canary compiles a fixed probe source
# with the admitted mojo and requires these lines byte-for-byte; a
# frontend whose LLVM drifted fails the probe with MBPF102 instead of
# compiling silently. This deliberately duplicates the adapter's
# HOST_* pins and the driver's FRONTEND_TARGET_FLAGS (toolchain.py
# cannot import either layer);
# test_producer_contract_matches_adapter_and_frontend fails closed on
# any drift between the three copies.
PRODUCER_CONTRACT = {
    "datalayout": (
        "target datalayout = "
        '"e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-'
        'i128:128-f80:128-n8:16:32:64-S128"'
    ),
    "triple": 'target triple = "x86_64-unknown-linux-gnu"',
    "attrs": (
        'attributes #0 = { "target-cpu"="znver4" '
        '"target-features"="+adx,+aes,+avx,+avx2,+avx512bf16,'
        "+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,"
        "+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,"
        "+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,"
        "+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,"
        "+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,"
        "+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,"
        "+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,"
        '+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }'
    ),
    "target_flags": (
        "--target-cpu",
        "znver4",
        "--target-features",
        "+adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,"
        "+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,"
        "+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,"
        "+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,"
        "+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,"
        "+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,"
        "+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,"
        "+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,"
        "+xsavec,+xsaveopt,+xsaves",
    ),
}

# Canary verdicts recorded on the mojo ToolInfo.
DIALECT_MATCH = "match"
DIALECT_SKIP = "skip"
DIALECT_MISMATCH = "mismatch"

CANARY_SOURCE_FILENAME = "dialect_probe.mojo"
CANARY_SOURCE = "def main():\n    pass\n"
CANARY_OUTPUT_FILENAME = "dialect_probe.ll"
CANARY_MAX_OUTPUT_BYTES = 262144
CANARY_EXCERPT_LIMIT = 300
# Short on purpose: an unresponsive frontend must not stall
# admission (the real build reports it loudly at its own phase),
# so a slow canary skips quickly and defers to the audit.
CANARY_TIMEOUT = 5
CANARY_HEADER_PREFIXES = (
    ("datalayout", "target datalayout = "),
    ("triple", "target triple = "),
    ("attrs", "attributes #0 = "),
)


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
    admitted (present and pin-matched), else None. ``dialect`` is
    the frontend-dialect canary verdict for mojo (``"match"``,
    ``"skip"`` or ``"mismatch"``), else None when the canary never
    ran there.
    """

    name: str
    status: str
    path: str | None = None
    version: str | None = None
    sha256: str | None = None
    exec_path: str | None = None
    exec_sha256: str | None = None
    execution: AdmittedExecution | None = None
    dialect: str | None = None


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


def _excerpt_canary_line(line: str) -> str:
    if len(line) > CANARY_EXCERPT_LIMIT:
        return line[:CANARY_EXCERPT_LIMIT] + "...[truncated]"
    return line


def check_frontend_dialect(
    mojo_execution: AdmittedExecution,
    mojo_version: str,
    llc_version: str,
    lockfile_path: str,
) -> tuple[str, Diagnostic | None]:
    """Compile the dialect probe; compare its headers to the contract.

    Runs the admitted mojo over a fixed SDK-free probe source with
    the qualified frontend flags and requires the emitted LLVM
    header lines to equal PRODUCER_CONTRACT byte-for-byte. Returns
    ``(DIALECT_MATCH, None)`` when they do and ``(DIALECT_MISMATCH,
    diagnostic)`` naming both tool versions when a present header
    differs. Anything inconclusive -- failed, timed-out or
    spawn-refused emit, missing or oversized output, undecodable
    bytes, no header lines at all -- returns ``(DIALECT_SKIP,
    None)``: the audit and the backend still gate the real build,
    so the canary abstains instead of failing closed spuriously.
    A present-but-differing header is firm drift evidence and
    never skips. Skipped work leaves no residue (private tmpdir,
    removed). The canary is best-effort end to end: any spawn or
    filesystem failure, including unexpected mock breakage around
    the pipe capture, skips instead of failing admission for a
    verdict it could not reach.
    """
    try:
        workdir = tempfile.mkdtemp(prefix="mojobpf-dialect-")
    except OSError:
        return (DIALECT_SKIP, None)
    try:
        src_path = os.path.join(workdir, CANARY_SOURCE_FILENAME)
        out_path = os.path.join(workdir, CANARY_OUTPUT_FILENAME)
        try:
            with open(src_path, "w", encoding="utf-8") as handle:
                handle.write(CANARY_SOURCE)
        except OSError:
            return (DIALECT_SKIP, None)
        try:
            record = run_admitted(
                mojo_execution,
                (
                    "build",
                    "--emit",
                    "llvm",
                    *PRODUCER_CONTRACT["target_flags"],
                    "-o",
                    out_path,
                    src_path,
                ),
                cwd=workdir,
                timeout=CANARY_TIMEOUT,
                stage=STAGE_TOOLCHAIN_MATCH,
            )
        except Exception:
            return (DIALECT_SKIP, None)
        if record.status != STATUS_OK or record.exit_code != 0:
            return (DIALECT_SKIP, None)
        try:
            if os.path.getsize(out_path) > CANARY_MAX_OUTPUT_BYTES:
                return (DIALECT_SKIP, None)
            with open(out_path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            return (DIALECT_SKIP, None)
        found: dict[str, str] = {}
        for line in text.splitlines():
            for key, prefix in CANARY_HEADER_PREFIXES:
                if key not in found and line.startswith(prefix):
                    found[key] = line
        if not found:
            return (DIALECT_SKIP, None)
        for key in ("datalayout", "triple", "attrs"):
            if key in found and found[key] != PRODUCER_CONTRACT[key]:
                return (
                    DIALECT_MISMATCH,
                    Diagnostic(
                        code="MBPF102",
                        stage=STAGE_TOOLCHAIN_MATCH,
                        severity=SEVERITY_ERROR,
                        explanation=(
                            "frontend LLVM dialect mismatch: mojo %r "
                            "emitted %s %r, qualified dialect requires "
                            "%r (backend llc %r consumes only the "
                            "qualified dialect)"
                            % (
                                mojo_version,
                                key,
                                _excerpt_canary_line(found[key]),
                                _excerpt_canary_line(
                                    PRODUCER_CONTRACT[key]
                                ),
                                llc_version,
                            )
                        ),
                        location=lockfile_path,
                        remedy="reinstall the qualified mojo build; "
                        "the admitted binary emits an LLVM dialect "
                        "outside the qualified contract",
                    ),
                )
        if len(found) != len(CANARY_HEADER_PREFIXES):
            return (DIALECT_SKIP, None)
        return (DIALECT_MATCH, None)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


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
        document = load_toolchain_document(config.lockfile_path)
        if document is not None and document.get("schema_version") == NATIVE_LOCKFILE_SCHEMA_VERSION:
            lock_diagnostics.append(Diagnostic(code="MBPF102", stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR, explanation="native candidate probing requires explicit admitted adapter selection",
                location=config.lockfile_path, remedy="use the explicitly selected pinned native build route"))
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
    if tools_table is not None and matched:
        mojo_index = next(
            (
                index
                for index, tool in enumerate(examined)
                if tool.name == "mojo"
            ),
            None,
        )
        llc_tool = next(
            (tool for tool in examined if tool.name == "llc"), None
        )
        mojo_tool = (
            examined[mojo_index] if mojo_index is not None else None
        )
        if (
            mojo_tool is not None
            and mojo_tool.execution is not None
            and mojo_tool.version is not None
            and llc_tool is not None
            and llc_tool.status == TOOL_PRESENT
            and llc_tool.version is not None
        ):
            verdict, canary = check_frontend_dialect(
                mojo_tool.execution,
                mojo_tool.version,
                llc_tool.version,
                config.lockfile_path,
            )
            examined[mojo_index] = replace(mojo_tool, dialect=verdict)
            if canary is not None:
                match_diagnostics.append(canary)
                matched = False
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
    child_env = filter_spawn_ambient(os.environ)
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
        data = _parse_lock_document(raw)
    except (ValueError, RecursionError) as exc:
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
    if not is_int(version) or version not in (LOCKFILE_SCHEMA_VERSION, NATIVE_LOCKFILE_SCHEMA_VERSION):
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


def _parse_lock_document(raw: str) -> dict:
    """Preserve schema1 semantics; schema2 is a closed candidate contract."""
    duplicates = []

    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                duplicates.append(name)
            result[name] = value
        return result

    data = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(data, dict):
        return data
    if is_int(data.get("schema_version")) and data["schema_version"] == NATIVE_LOCKFILE_SCHEMA_VERSION:
        from .native_adapter import strict_json, validate_candidate_record
        if duplicates:
            raise ValueError("duplicate candidate lock fields")
        data = strict_json(raw.encode("utf-8"))
        allowed = {"schema_version", "tools", "native_adapter", "adapter", "distribution",
                   "generated_by", "license", "status", "vm"}
        if set(data) - allowed or not {"schema_version", "tools", "native_adapter"} <= set(data):
            raise ValueError("missing/unknown candidate lock fields")
        validate_candidate_record(data["native_adapter"])
    return data


def load_toolchain_document(lockfile_path: str) -> dict | None:
    """Return the parsed lockfile document, or None when unreadable.

    Used for the lock's non-tool trust records (such as the
    adapter pins); tool admission itself goes through
    :func:`load_toolchain_lock` plus per-tool examination.
    """
    try:
        raw = Path(lockfile_path).read_bytes().decode("utf-8")
        data = _parse_lock_document(raw)
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not is_int(data.get("schema_version")) or (
        data.get("schema_version") not in (LOCKFILE_SCHEMA_VERSION, NATIVE_LOCKFILE_SCHEMA_VERSION)
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
    native_bundle=None,
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
    check passes. Once both build tools are admitted, the
    frontend-dialect canary compiles a fixed probe source with
    the admitted mojo and requires the qualified LLVM header
    lines; a differing header fails admission with ``MBPF102``
    (recorded on the mojo record as ``dialect="mismatch"``),
    while an inconclusive emit skips silently (``"skip"``).
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
    document = load_toolchain_document(lockfile_path)
    if document is not None and document.get("schema_version") == NATIVE_LOCKFILE_SCHEMA_VERSION:
        from .native_adapter import AdmittedNativeBundle, NativeAdapterError, canonical_json
        if not isinstance(native_bundle, AdmittedNativeBundle) or native_bundle.pins_bytes != canonical_json(document["native_adapter"]):
            diagnostics.append(Diagnostic(code="MBPF102", stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR, explanation="native candidates require explicit admitted adapter selection before tool probes",
                location=lockfile_path, remedy="select and admit the pinned native bundle explicitly"))
            return {}, tuple(diagnostics)
        try:
            native_bundle.verify()
        except NativeAdapterError as exc:
            diagnostics.append(Diagnostic(code="MBPF102", stage=STAGE_TOOLCHAIN_MATCH,
                severity=SEVERITY_ERROR, explanation=str(exc), location=lockfile_path,
                remedy="restore the independently admitted native runtime closure"))
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
    if not failed and "mojo" in by_name and "llc" in by_name:
        mojo_tool = by_name["mojo"]
        llc_tool = by_name["llc"]
        if (
            mojo_tool.execution is not None
            and mojo_tool.version is not None
            and llc_tool.version is not None
        ):
            verdict, canary = check_frontend_dialect(
                mojo_tool.execution,
                mojo_tool.version,
                llc_tool.version,
                lockfile_path,
            )
            by_name["mojo"] = replace(mojo_tool, dialect=verdict)
            if canary is not None:
                diagnostics.append(canary)
                failed = True
    if failed:
        return {}, tuple(diagnostics)
    return by_name, tuple(diagnostics)
