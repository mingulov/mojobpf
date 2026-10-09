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

This module never installs, downloads or modifies anything, and it never
falls back silently: a missing tool stays missing, a tool whose version
probe fails stays broken, and an unreadable or version-unknown lockfile
fails loudly instead of being partially interpreted. Lockfile entries
for tools outside the required set are informational and are not
matched; that scoping is documented here rather than guessed per tool.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
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
from .manifest import ProfileError, _is_int, lookup_profile

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
        if not _is_int(self.schema_version) or (
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
    over the depth bound). Lockfile pins match the entry ``sha256``.
    """

    name: str
    status: str
    path: str | None = None
    version: str | None = None
    sha256: str | None = None
    exec_path: str | None = None
    exec_sha256: str | None = None


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
    """
    if not isinstance(config, ToolchainConfig):
        raise ValueError("probe_toolchain requires a ToolchainConfig")
    diagnostics: list[Diagnostic] = []
    tools = tuple(
        _discover_tool(name, config.search_paths, diagnostics)
        for name in REQUIRED_TOOLS
    )
    by_name = {tool.name: tool for tool in tools}

    lockfile_status = LOCKFILE_NOT_CHECKED
    if config.lockfile_path is None:
        diagnostics.append(
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
        lockfile_status = _match_lockfile(
            config.lockfile_path, by_name, diagnostics
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


def _discover_tool(
    name: str, search_paths: tuple[str, ...], diagnostics: list[Diagnostic]
) -> ToolInfo:
    search_path = _search_path(search_paths)
    path = shutil.which(DISCOVERY_ARGV[name][0], path=search_path)
    if path is None:
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
    try:
        realpath = os.path.realpath(path)
        digest = _sha256_file(realpath)
    except OSError as exc:
        diagnostics.append(
            Diagnostic(
                code="MBPF103",
                stage=STAGE_TOOLCHAIN_DISCOVERY,
                severity=SEVERITY_ERROR,
                explanation="cannot hash tool binary %s: %s" % (path, exc),
                location="tool:%s" % name,
                remedy="check the installation of %s" % name,
            )
        )
        return ToolInfo(name=name, status=TOOL_BROKEN, path=path)
    child_env = dict(os.environ)
    child_env["PATH"] = search_path
    try:
        completed = subprocess.run(
            list(DISCOVERY_ARGV[name]),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=DISCOVERY_TIMEOUT,
            env=child_env,
        )
    except UnicodeDecodeError as exc:
        diagnostics.append(
            Diagnostic(
                code="MBPF103",
                stage=STAGE_TOOLCHAIN_DISCOVERY,
                severity=SEVERITY_ERROR,
                explanation="tool version probe printed undecodable "
                "output for %s: %s" % (name, exc),
                location="tool:%s" % name,
                remedy="check the installation of %s" % name,
            )
        )
        return ToolInfo(name=name, status=TOOL_BROKEN, path=path)
    except (OSError, subprocess.SubprocessError) as exc:
        diagnostics.append(
            Diagnostic(
                code="MBPF103",
                stage=STAGE_TOOLCHAIN_DISCOVERY,
                severity=SEVERITY_ERROR,
                explanation="tool version probe failed for %s: %s"
                % (name, exc),
                location="tool:%s" % name,
                remedy="check the installation of %s" % name,
            )
        )
        return ToolInfo(name=name, status=TOOL_BROKEN, path=path)
    if completed.returncode != 0:
        diagnostics.append(
            Diagnostic(
                code="MBPF103",
                stage=STAGE_TOOLCHAIN_DISCOVERY,
                severity=SEVERITY_ERROR,
                explanation="tool version probe exited %d for %s"
                % (completed.returncode, name),
                location="tool:%s" % name,
                remedy="check the installation of %s" % name,
            )
        )
        return ToolInfo(name=name, status=TOOL_BROKEN, path=path)
    version = _first_line(completed.stdout, completed.stderr)
    if version is None:
        diagnostics.append(
            Diagnostic(
                code="MBPF103",
                stage=STAGE_TOOLCHAIN_DISCOVERY,
                severity=SEVERITY_ERROR,
                explanation="tool version probe printed nothing for %s"
                % name,
                location="tool:%s" % name,
                remedy="check the installation of %s" % name,
            )
        )
        return ToolInfo(name=name, status=TOOL_BROKEN, path=path)
    exec_path = _follow_exec_target(realpath)
    exec_digest = None
    if exec_path is not None:
        try:
            exec_digest = _sha256_file(exec_path)
        except OSError:
            exec_path = None
    return ToolInfo(
        name=name,
        status=TOOL_PRESENT,
        path=path,
        version=version,
        sha256=digest,
        exec_path=exec_path,
        exec_sha256=exec_digest,
    )


_EXEC_CHAIN_LIMIT = 8
_EXEC_SCRIPT_LIMIT = 65536

_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_VAR_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)


def _follow_exec_target(entry: str) -> str | None:
    """Resolve a launcher entry to the image it execs, if any.

    Static and bounded: while the current file is a script, take its
    single ``exec`` target (``$NAME``/``${NAME}`` expanded from the
    script's own assignments only) and continue there. Returns the
    final image's realpath, or None when the entry is itself the
    executed image or the chain does not resolve.
    """
    try:
        seen = {os.path.realpath(entry)}
    except OSError:
        return None
    current = entry
    for _ in range(_EXEC_CHAIN_LIMIT):
        text = _read_script_text(current)
        if text is None:
            if current != entry and not _has_shebang(current):
                return current
            return None
        target = _exec_target(text)
        if target is None:
            # A script with no single exec line runs directly: it is
            # the chain terminus unless it is the entry itself.
            return current if current != entry else None
        if not os.path.isfile(target):
            return None
        try:
            resolved = os.path.realpath(target)
        except OSError:
            return None
        if resolved in seen:
            return None
        seen.add(resolved)
        current = resolved
    return None


def _has_shebang(path: str) -> bool:
    """True when the file starts with ``#!`` (or cannot be read)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return True


def _read_script_text(path: str) -> str | None:
    """Return the script text, or None when not a readable script."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(2)
            if head != b"#!":
                return None
            rest = handle.read(_EXEC_SCRIPT_LIMIT)
    except OSError:
        return None
    try:
        return (head + rest).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _exec_target(text: str) -> str | None:
    """Return the script's exec target, or None when not unique.

    Assignments after the exec line never execute (the image is
    already replaced), so only pre-exec assignments expand the
    target; exec lines are still all counted, so two execs stay
    ambiguous.
    """
    assigns: dict[str, str] = {}
    exec_lines: list[str] = []
    seen_exec = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGN_RE.match(stripped)
        if match is not None:
            if not seen_exec:
                assigns[match.group(1)] = _unquote(
                    match.group(2).strip()
                )
            continue
        if stripped == "exec" or stripped.startswith("exec "):
            exec_lines.append(stripped)
            seen_exec = True
    if len(exec_lines) != 1:
        return None
    try:
        tokens = shlex.split(exec_lines[0], posix=True)
    except ValueError:
        return None
    args = tokens[1:]
    while args and args[0] in ("-c", "-l"):
        args = args[1:]
    if len(args) >= 2 and args[0] == "-a":
        args = args[2:]
    if not args or args[0].startswith("-"):
        return None
    return _expand_vars(args[0], assigns)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _expand_vars(target: str, assigns: dict[str, str]) -> str | None:
    def _one(match: re.Match[str]) -> str:
        name = match.group(1) if match.group(1) is not None else match.group(2)
        if name not in assigns:
            raise KeyError(name)
        return assigns[name]

    try:
        expanded = _VAR_RE.sub(_one, target)
    except KeyError:
        return None
    if "$" in expanded:
        return None
    return expanded


def _search_path(search_paths: tuple[str, ...]) -> str:
    current = os.environ.get("PATH", "")
    extra = os.pathsep.join(search_paths)
    if extra and current:
        return extra + os.pathsep + current
    return extra or current


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_line(stdout: str, stderr: str) -> str | None:
    text = stdout if stdout.strip() else stderr
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _match_lockfile(
    lockfile_path: str,
    by_name: dict[str, ToolInfo],
    diagnostics: list[Diagnostic],
    names: tuple[str, ...] = REQUIRED_TOOLS,
) -> str:
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
        return LOCKFILE_UNREADABLE
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
        return LOCKFILE_UNREADABLE
    version = data.get("schema_version") if isinstance(data, dict) else None
    if not _is_int(version) or version != LOCKFILE_SCHEMA_VERSION:
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
        return LOCKFILE_UNSUPPORTED_VERSION
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
        return LOCKFILE_UNREADABLE
    mismatched = False
    for name in names:
        tool = by_name[name]
        entry = entries.get(name)
        if not isinstance(entry, dict):
            mismatched = True
            diagnostics.append(
                Diagnostic(
                    code="MBPF102",
                    stage=STAGE_TOOLCHAIN_MATCH,
                    severity=SEVERITY_ERROR,
                    explanation="tool %r has no pin in the lockfile" % name,
                    location="%s: tools.%s" % (lockfile_path, name),
                    remedy="pin %s in the lockfile or stop "
                    "requiring validation" % name,
                )
            )
            continue
        pinned_version = entry.get("version")
        pinned_sha = entry.get("sha256")
        if not isinstance(pinned_version, str) or not isinstance(
            pinned_sha, str
        ):
            mismatched = True
            diagnostics.append(
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
            continue
        if tool.status != TOOL_PRESENT:
            mismatched = True
            continue
        if tool.version != pinned_version or tool.sha256 != pinned_sha:
            mismatched = True
            diagnostics.append(
                Diagnostic(
                    code="MBPF102",
                    stage=STAGE_TOOLCHAIN_MATCH,
                    severity=SEVERITY_ERROR,
                    explanation="tool %r does not match the lockfile pin "
                    "(found version %r)" % (name, tool.version),
                    location="%s: tools.%s" % (lockfile_path, name),
                    remedy="install the pinned %s or re-pin the "
                    "lockfile deliberately" % name,
                )
            )
    return LOCKFILE_MISMATCHED if mismatched else LOCKFILE_MATCHED


def admit_tools(
    *,
    lockfile_path: str | None,
    search_paths: tuple[str, ...] = (),
    names: tuple[str, ...] = ("mojo", "llc"),
) -> tuple[dict[str, ToolInfo], tuple[Diagnostic, ...]]:
    """Admit named build tools against a lockfile for one build.

    Discovers exactly ``names`` (default the build tools ``mojo``
    and ``llc``) through the same version probes as
    :func:`probe_toolchain`, then matches their versions and binary
    hashes against ``lockfile_path``. Admission is all-or-nothing:
    the returned mapping holds a present, pin-matched
    :class:`ToolInfo` per name on success and is empty otherwise.
    Diagnostics use the discovery/matching codes (``MBPF102`` pin
    mismatch, ``MBPF103`` missing or broken tool, ``MBPF104``
    lockfile problem). A missing lockfile is ``MBPF104``, never a
    silent unvalidated build: callers execute the admitted paths or
    fail.
    """
    diagnostics: list[Diagnostic] = []
    for name in names:
        if name not in DISCOVERY_ARGV:
            raise ValueError("admit_tools cannot discover %r" % (name,))
    tools = tuple(
        _discover_tool(name, search_paths, diagnostics)
        for name in names
    )
    by_name = {tool.name: tool for tool in tools}
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
    status = _match_lockfile(
        lockfile_path, by_name, diagnostics, names
    )
    if status != LOCKFILE_MATCHED or not all(
        tool.status == TOOL_PRESENT for tool in tools
    ):
        return {}, tuple(diagnostics)
    return by_name, tuple(diagnostics)
