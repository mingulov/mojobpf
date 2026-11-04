# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""execution-contract-v1: admit the complete execution chain before probing it.

Every subprocess the driver runs -- compiler probes and builds, the
adapter service, the guest runner and its emulator -- flows through
one boundary: :func:`admit_execution` resolves, identifies and
pin-checks the whole chain before any process starts, and
:func:`run_admitted` / :func:`popen_admitted` are the sole spawn
paths. A substitution anywhere in the chain (unrelated same-version
binary, rewritten launcher target, repointed symlink, modified
package module, ambient ``PYTHONPATH`` shadow) is a typed
:class:`AdmissionError` raised before the substituted bytes execute.

Trust root: an approved lock document (or a built distribution the
lock binds). Admission compares observed bytes against that lock's
pins; it never re-resolves through ambient ``PATH`` or ambient
import paths, and every spawn carries the sanitized environment
captured at admission.

Supported executable forms (resolved explicitly; anything else is
``launcher-unknown`` and rejected, never shell-guessed):

* ``binary``: an ELF image, executed directly.
* ``exec-launcher``: a script with exactly one static ``exec`` line
  whose chain resolves within the depth bound, and whose only
  other content is blank lines, comments and literal assignments.
  The accepted grammar is exact (see
  :func:`_unsupported_shell_logic`): assignments are
  ``NAME=literal`` single shell words whose values carry no
  ``$``, backquote, backslash, tilde, brace or shell metachar
  (no expansion of any kind runs in an accepted position);
  the ``exec`` line is ``exec target [args]`` (no flags: shells
  disagree on flag spellings) where ``$`` appears only as
  ``$NAME``/``${NAME}`` in the target word (expanded from the
  script's own pre-exec assignments, resolving to an absolute
  path) and as the exact word ``"$@"`` in argument position;
  all other argument words are literal. Conditionals, command
  invocations and every other shell form are rejected, never
  guessed. The entry itself is executed (preserving ``argv[0]``
  semantics)
  after every hop's identity is captured, and the same identities
  are re-verified at spawn. Launchers must be pinned: admission
  without an ``exec`` pin, or with an unresolvable chain, is
  rejected.
* ``direct-script``: a ``#!`` script with no single ``exec`` line
  whose interpreter is an absolute path; executed through the
  kernel's shebang handling with the captured interpreter identity
  re-verified at spawn.
* ``console-script``: a ``direct-script`` whose interpreter is a
  Python binary. When the pins name package modules, each module is
  located through the *admitted* interpreter's module path dumped
  under ``-S`` (no ``site`` initialization: no ``.pth`` execution,
  no ``sitecustomize`` import) with virtual-environment roots
  recovered arithmetically, and hash-checked; spawns then run
  with exactly the admitted module path, so an ambient
  ``PYTHONPATH`` shadow can never be imported. Import selection
  binds to the verified roots before any probe executes: a
  declared root shadowing a verified module (or any ancestor
  package, or the standard library) is rejected without
  executing. Admitted module roots carrying
  ``sitecustomize.py``/``usercustomize.py`` are rejected: those
  files would execute at every spawn.
* ``script-data``: a script passed as data to an already-running
  interpreter (the adapter service). Never executed directly; the
  ``argv`` prefix is ``[interpreter, script]``.

Spawn-time re-verification compares each captured file's
``(st_dev, st_ino, size, mtime_ns)`` stat identity. This defeats
path substitution (symlink repoint, rename swap) between admission
and spawn. In-place rewriting of the admitted inode itself is
outside this boundary and stays bound to the trust root: the
approved lock/built distribution identity, not per-spawn re-hashing
(which would still race a concurrent writer). Likewise the native
dynamic closure (``libc``, loader, linked shared libraries) is
bound through the lock's ``distribution`` record, never claimed
from an executable hash alone.

Standard library only.
"""

from __future__ import annotations

import base64
import csv
import errno
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from time import monotonic as _monotonic

EXECUTION_CONTRACT_VERSION = "execution-contract-v1"


def resolve_under_root(path: str, root: str) -> str | None:
    """Return the realpath of ``path`` when under ``root``, else None.

    Both sides are resolved, so symlinks on either side cannot fool
    the comparison; lexical containment alone is never sufficient.
    Resolve-once-compare callers must still treat the window between
    this check and the subsequent open as untrusted input.
    """
    resolved = os.path.realpath(path)
    anchor = os.path.realpath(root)
    if os.path.commonpath([resolved, anchor]) != anchor:
        return None
    return resolved

# This module is mirrored standalone into native bundles (loaded via
# ``spec_from_file_location`` with no parent package), so it must stay
# free of ``mojobpf`` imports. The capped-read core therefore lives
# here, in stdlib only; :mod:`mojobpf.safeio` re-exports it for the
# other readers.
OBJECT_LIMIT = 16 * 1024 * 1024
MANIFEST_LIMIT = 1024 * 1024
LOCK_LIMIT = 1024 * 1024
MOJO_LIMIT = 8 * 1024 * 1024
IR_LIMIT = 32 * 1024 * 1024
JSON_LIMIT = 1024 * 1024
DIST_LIMIT = 1024 * 1024
SDK_CONFIG_LIMIT = 1024 * 1024
STDLIB_PAYLOAD_LIMIT = 32 * 1024 * 1024

_CAPPED_CHUNK = 64 * 1024


class FileTooLargeError(OSError):
    """A file exceeded its kind cap; the limit is named in the message."""


class NonRegularFileError(OSError):
    """A path swapped for a non-regular file (FIFO, socket, device, dir)."""


def _open_bound(path: str, kind: str) -> int:
    """Open ``path`` for a bounded read; never blocks on a FIFO.

    The descriptor is opened ``O_NONBLOCK`` so a FIFO swapped in for a
    regular file cannot hang the reader, then bound with ``fstat``: only
    regular files proceed (set back to blocking mode for the bounded
    read loop). Missing files raise :exc:`FileNotFoundError` exactly as
    :func:`open` would.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        os.close(fd)
        raise
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise NonRegularFileError(
            "refusing to read %s %r: not a regular file" % (kind, path)
        )
    os.set_blocking(fd, True)
    return fd


def _too_large(kind: str, path: str, limit: int) -> FileTooLargeError:
    return FileTooLargeError(
        "refusing to read %s %r: size exceeds the %d-byte cap"
        % (kind, path, limit)
    )


def read_capped(path: str, *, limit: int, kind: str) -> bytes:
    """Read a regular file of at most ``limit`` bytes.

    Files one byte over the cap are refused; the error names the limit.
    """
    fd = _open_bound(path, kind)
    chunks: list[bytes] = []
    seen = 0
    try:
        while True:
            chunk = os.read(fd, min(_CAPPED_CHUNK, limit + 1 - seen))
            if not chunk:
                break
            seen += len(chunk)
            if seen > limit:
                raise _too_large(kind, path, limit)
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def hash_file_capped(
    path: str, *, limit: int, kind: str, algorithm: str = "sha256"
):
    """Hash a regular file of at most ``limit`` bytes without loading it.

    Returns the in-progress hash object so callers choose ``digest`` or
    ``hexdigest``; memory stays bounded by the chunk size either way.
    """
    digest = hashlib.new(algorithm)
    fd = _open_bound(path, kind)
    seen = 0
    try:
        while True:
            chunk = os.read(fd, _CAPPED_CHUNK)
            if not chunk:
                break
            seen += len(chunk)
            if seen > limit:
                raise _too_large(kind, path, limit)
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_TIMEOUT = "timeout"
STATUS_SPAWN_FAILED = "spawn_failed"

FORM_BINARY = "binary"
FORM_EXEC_LAUNCHER = "exec-launcher"
FORM_DIRECT_SCRIPT = "direct-script"
FORM_CONSOLE_SCRIPT = "console-script"
FORM_SCRIPT_DATA = "script-data"
FORM_UNKNOWN = "unknown"

DEFAULT_FORMS = (
    FORM_BINARY,
    FORM_EXEC_LAUNCHER,
    FORM_DIRECT_SCRIPT,
    FORM_CONSOLE_SCRIPT,
)

REASON_NOT_FOUND = "not-found"
REASON_UNREADABLE = "unreadable"
REASON_HASH_MISMATCH = "hash-mismatch"
REASON_EXEC_UNPINNED = "exec-unpinned"
REASON_EXEC_MISMATCH = "exec-mismatch"
REASON_VERSION_MISMATCH = "version-mismatch"
REASON_PROBE_FAILED = "probe-failed"
REASON_LAUNCHER_UNKNOWN = "launcher-unknown"
REASON_LAUNCHER_UNRESOLVED = "launcher-unresolved"
REASON_UNSUPPORTED_FORM = "unsupported-form"
REASON_INTERPRETER_UNPINNED = "interpreter-unpinned"
REASON_INTERPRETER_MISMATCH = "interpreter-mismatch"
REASON_MODULE_NOT_FOUND = "module-not-found"
REASON_MODULE_MISMATCH = "module-mismatch"
REASON_SPAWN_REFUSED = "spawn-refused"
REASON_ARGV_MISMATCH = "argv-mismatch"

DEFAULT_PROBE_TIMEOUT = 60

# Ambient variables that never flow into an admitted spawn:
# import-path confusion (``PYTHONPATH`` is set only when the pins
# explicitly admit module roots, and then to exactly those roots),
# dynamic-loader injection (a preloaded library executes inside
# every child), and shell startup files (executed by script-form
# interpreters). See ``spawn_env`` for the kept-variable audit.
SPAWN_ENV_UNSET = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "BASH_ENV",
    "ENV",
)

# Interpreter hardening applied to every admitted spawn (inert for
# native binaries): no user site (kills ``usercustomize`` shadows),
# no bytecode writes into admitted roots, and no script-dir/cwd
# prepending (module lookup uses only absolute site entries plus
# explicitly admitted roots).
PYTHON_ENV_SET = (
    ("PYTHONNOUSERSITE", "1"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONSAFEPATH", "1"),
)

#: Ambient names that may reach an admitted spawn. Everything
#: else is dropped before the overlay applies (fail closed):
#: identity/locale/output names not listed here (``USER``,
#: ``TERM``, ``COLUMNS``) never pass from ambient, though
#: code-specified extras still bypass the allowlist. The
#: ``PYTHON*`` overlay names are members so the driver's own
#: hardening values pass the spawn checker; ambient copies are
#: overwritten by the overlay.
SPAWN_ENV_ALLOW = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "MODULAR_HOME",
        "LANG",
        "TZ",
        "PYTHONHASHSEED",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONSAFEPATH",
    }
)

#: Ambient name prefixes that may reach an admitted spawn (see
#: :data:`SPAWN_ENV_ALLOW`). ``MOJOBPF_`` carries the
#: lease/fixture/admission variables the lanes set explicitly.
SPAWN_ENV_ALLOW_PREFIXES = (
    "LC_",
    "MOJO_",
    "MODULAR_",
    "LLVM_",
    "MOJOBPF_",
)


def spawn_name_allowed(name: str) -> bool:
    """Return whether an ambient name may reach a spawn."""
    if name in SPAWN_ENV_ALLOW:
        return True
    return name.startswith(SPAWN_ENV_ALLOW_PREFIXES)


#: Caller keyword arguments admitted through to
#: :class:`subprocess.Popen` by :func:`popen_admitted`.
#: ``shell``, ``executable``, ``preexec_fn`` and ``pass_fds``
#: are refused; internal spawn kwargs (such as the held-fd
#: exec descriptors) are added inside :func:`popen_admitted`,
#: never via caller kwargs, so no carve-out is needed.
POPN_KWARGS_ALLOW = frozenset(
    {
        "stdout",
        "stderr",
        "stdin",
        "text",
        "errors",
        "start_new_session",
        "close_fds",
    }
)


def filter_spawn_ambient(
    ambient: Mapping[str, str],
) -> dict[str, str]:
    """Filter one ambient snapshot down to the spawn allowlist.

    Drops :data:`SPAWN_ENV_UNSET` first, then keeps only
    allowlisted names and prefixes. Overlays and explicit
    extras apply after, outside this function.
    """
    child: dict[str, str] = {}
    for name, value in ambient.items():
        if name in SPAWN_ENV_UNSET:
            continue
        if spawn_name_allowed(name):
            child[name] = value
    return child

# Bounded ``sys.path`` dump used to locate pinned modules without
# executing startup or third-party code. The probe always runs with
# ``-S`` (``site`` never initializes: no ``.pth`` execution, no
# ``sitecustomize``/``usercustomize`` import), so only ``sys``,
# ``json`` and a side-effect-free ``site.getsitepackages()`` call
# run. Virtual-environment roots (normally added by ``site``) are
# recovered deterministically by the driver from the interpreter's
# location plus the reported version, never by executing ``.pth``.
# The probe also reports the interpreter's own standard-library
# module names (``None`` when the interpreter predates the
# inventory): admission refuses declared roots carrying a
# top-level module that would shadow one, so a version probe can
# never import unadmitted bytes under a standard-library name.
_SYS_PATH_PROBE = (
    "import json,sys\n"
    "roots=[p for p in sys.path if isinstance(p,str)]\n"
    "site_roots=[]\n"
    "try:\n"
    " import site\n"
    " site_roots=list(site.getsitepackages() or [])\n"
    "except Exception:\n"
    " pass\n"
    "names=getattr(sys,'stdlib_module_names',None)\n"
    "print(json.dumps({'path':roots,'site':site_roots,"
    "'version_info':list(sys.version_info[:2]),"
    "'stdlib':(sorted(names) if names is not None else None)}))\n"
)


class AdmissionError(Exception):
    """Typed rejection from the execution boundary.

    ``reason`` is one of the ``REASON_*`` constants; ``detail``
    carries the human-readable evidence. ``observed`` carries the
    observed value when one exists (the reported version on a
    version mismatch). Raised before any process starts whenever
    admission fails, and at spawn when a captured identity
    drifted.
    """

    def __init__(
        self, reason: str, detail: str = "", observed=None
    ) -> None:
        super().__init__(
            "%s%s" % (reason, (": %s" % detail) if detail else "")
        )
        self.reason = reason
        self.detail = detail
        self.observed = observed


@dataclass(frozen=True)
class CommandRecord:
    """One subprocess run through the execution boundary.

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
class FileIdentity:
    """Bytes plus filesystem identity of one captured file.

    ``path`` is the path as resolved (possibly a symlink);
    ``realpath`` is the executed file. ``sha256`` hashes the
    resolved bytes. ``(dev, ino, size, mtime_ns)`` is the resolved
    stat identity re-checked at spawn; ``(link_dev, link_ino)``
    binds the symlink itself (``-1`` when ``path`` is not a link)
    so a repointed link is refused even though execution uses the
    captured ``realpath``.
    """

    path: str
    realpath: str
    sha256: str
    size: int
    dev: int
    ino: int
    mtime_ns: int
    link_dev: int = -1
    link_ino: int = -1


def _dup_above_stdio(fd: int) -> int:
    """Dup ``fd`` until the copy sits above the stdio numbers.

    Never leaks an intermediate on failure: every live dup is
    closed before the error propagates.
    """
    duped = os.dup(fd)
    try:
        while duped <= 2:
            spare = os.dup(duped)
            os.close(duped)
            duped = spare
    except OSError:
        try:
            os.close(duped)
        except OSError:
            pass
        raise
    return duped


def _check_open_image(fd: int, identity: FileIdentity) -> str | None:
    """Bind an open descriptor to its captured identity.

    Compares the live ``(st_dev, st_ino, size, mtime_ns)`` of the
    open description against admission. Returns the drift reason
    or ``None``. Path swaps after the open cannot affect the
    description; same-inode rewrites stay out of scope.
    """
    try:
        live = os.fstat(fd)
    except OSError as exc:
        return "fstat failed: %s" % (exc,)
    if (live.st_dev, live.st_ino) != (identity.dev, identity.ino):
        return "file replaced (dev/ino changed)"
    if live.st_size != identity.size or (
        live.st_mtime_ns != identity.mtime_ns
    ):
        return "file changed (size/mtime changed)"
    return None


@dataclass(frozen=True)
class ModuleIdentity:
    """One admitted Python module: dotted name plus file identity."""

    name: str
    identity: FileIdentity


@dataclass(frozen=True)
class ExecutionRequest:
    """What to admit.

    ``argv0`` is a bare command name (looked up through
    ``search_paths`` plus ``PATH``) or an explicit path (any value
    containing a path separator, or any value when
    ``allow_path_lookup`` is false). ``forms`` restricts the
    acceptable executable forms. ``probe_version`` runs the version
    probe through the admitted chain after every static check
    passes; ``version_argv`` is the probe suffix.
    """

    name: str
    argv0: str
    search_paths: tuple[str, ...] = ()
    allow_path_lookup: bool = True
    forms: tuple[str, ...] = DEFAULT_FORMS
    version_argv: tuple[str, ...] = ("--version",)
    probe_version: bool = False
    trust_root: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "search_paths", tuple(self.search_paths))
        object.__setattr__(self, "forms", tuple(self.forms))
        object.__setattr__(self, "version_argv", tuple(self.version_argv))


@dataclass(frozen=True)
class ExecutionPins:
    """Pin expectations from the trust root.

    ``None`` means "not pinned, record only" for ``version``,
    ``entry_sha256`` and ``interpreter_sha256``. The ``exec`` pin
    is tri-state -- absent (``exec_pin_present`` false), explicit
    ``None`` (the entry must be its own image), or a hash -- so a
    launcher can never slip through an unpinned lock entry, while
    directly executed entries need no ``exec`` pin. ``modules``
    maps dotted module names to expected hashes; ``python_path``
    is the explicitly admitted module search path (ambient
    ``PYTHONPATH`` never applies).
    """

    version: str | None = None
    entry_sha256: str | None = None
    exec_sha256: str | None = None
    exec_pin_present: bool = False
    interpreter_sha256: str | None = None
    interpreter_pin_present: bool = False
    modules: tuple[tuple[str, str], ...] = ()
    python_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "modules", tuple(self.modules))
        object.__setattr__(
            self, "python_path", tuple(self.python_path)
        )


@dataclass(frozen=True)
class AdmittedExecution:
    """The admitted chain plus its exact spawn parameters.

    Immutable: ``argv_prefix`` is the exact ``argv`` head every
    spawn uses, ``env_unset``/``env_set`` the sanitized environment
    overlay applied to the ambient environment, and ``digest`` the
    run-local identity of this admission (canonical JSON over the
    record; paths make it run-local, not portable).
    """

    contract: str
    name: str
    form: str
    trust_root: str
    entry: FileIdentity
    hops: tuple[FileIdentity, ...]
    image: FileIdentity
    interpreter: FileIdentity | None
    modules: tuple[ModuleIdentity, ...]
    version: str | None
    argv_prefix: tuple[str, ...]
    env_unset: tuple[str, ...]
    env_set: tuple[tuple[str, str], ...]
    digest: str = field(compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "hops", tuple(self.hops))
        object.__setattr__(self, "modules", tuple(self.modules))
        object.__setattr__(self, "argv_prefix", tuple(self.argv_prefix))
        object.__setattr__(self, "env_unset", tuple(self.env_unset))
        object.__setattr__(self, "env_set", tuple(self.env_set))


@dataclass(frozen=True)
class CapturedChain:
    """Static resolution of an entry: form, hops and final image.

    ``form`` is one of the ``FORM_*`` constants (``unknown`` when
    the entry is not a supported executable shape). ``hops`` holds
    every launcher hop's identity including the final image; for
    non-launcher forms it is empty and ``image`` is the entry
    itself. ``interpreter`` is the shebang interpreter path (or
    ``None`` for binaries). ``note`` explains ``unknown`` forms.
    """

    form: str
    hops: tuple[FileIdentity, ...]
    image: FileIdentity
    interpreter: str | None
    note: str = ""


def sha256_file(path: str) -> str:
    """Return the hex SHA-256 of a file's bytes."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def first_output_line(stdout: str, stderr: str) -> str | None:
    """Return the first non-blank output line (stdout preferred)."""
    text = stdout if stdout.strip() else stderr
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


_EXEC_CHAIN_LIMIT = 8
_EXEC_SCRIPT_LIMIT = 65536

_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_VAR_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)
def _logical_lines(text: str) -> list[str]:
    """Join physical lines the way shell token recognition does.

    A backslash-newline pair never ends a command: the pair is
    removed before parsing (even inside double quotes and even
    inside comments), so an ``exec`` split across physical
    lines still replaces the image. Only an odd run of
    trailing backslashes continues (``\\\\`` is a literal
    backslash and the newline still terminates). An
    unterminated quote likewise continues the command on the
    next line; a quote character inside a ``#`` comment is not
    a quote and never joins, and a ``#`` inside quotes is
    literal text, never a comment. Single quotes preserve
    backslash-newline in the shell, but joining anyway only
    ever adds doubt (a phantom exec shape still fails the
    grammar screen), never hides a real exec: any image
    replacement the shell performs survives the join.
    """
    joined: list[str] = []
    buf = ""
    for line in text.splitlines():
        buf += line
        trail = len(buf) - len(buf.rstrip("\\"))
        if trail % 2 == 1:
            buf = buf[:-1]
            continue
        joined.append(buf)
        buf = ""
    if buf:
        joined.append(buf)
    logical: list[str] = []
    buf = ""
    quote: str | None = None
    for line in joined:
        if buf:
            buf += "\n"
        start = len(buf)
        buf += line
        index = start
        comment = False
        escaped = False
        while index < len(buf):
            char = buf[index]
            if char == "\n":
                comment = False
                escaped = False
                index += 1
                continue
            if comment:
                index += 1
                continue
            if escaped:
                escaped = False
                index += 1
                continue
            if quote == "'":
                if char == "'":
                    quote = None
                index += 1
                continue
            if char == "\\":
                escaped = True
                index += 1
                continue
            if char == "'":
                if quote is None:
                    quote = "'"
                elif quote == "'":
                    quote = None
                index += 1
                continue
            if char == '"':
                if quote is None:
                    quote = '"'
                elif quote == '"':
                    quote = None
                index += 1
                continue
            if (
                quote is None
                and char == "#"
                and (index == 0 or buf[index - 1] in " \t;&|(\n")
            ):
                comment = True
                index += 1
                continue
            index += 1
        if quote is not None:
            continue
        logical.append(buf)
        buf = ""
    if buf:
        logical.append(buf)
    return logical


def _strip_shape_comment(line: str) -> str:
    """Cut a ``#`` comment before exec-shape detection.

    Quote- and backslash-aware: ``#`` starts a comment only
    outside quotes, at the start or after a word break or a
    command separator. A ``#`` inside a word (``a#b``) or
    inside quotes is literal and stays.
    """
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'":
            if quote is None:
                quote = "'"
            elif quote == "'":
                quote = None
            continue
        if char == '"':
            if quote is None:
                quote = '"'
            elif quote == '"':
                quote = None
            continue
        if char == "#" and quote is None and (
            index == 0 or line[index - 1] in " \t;&|(\n"
        ):
            return line[:index]
    return line


def _split_segments(line: str) -> list[str] | None:
    """Split a logical line into command segments, or None.

    Boundaries are the unquoted, unescaped command separators
    (``;``, ``&``, ``|``, ``(``, ``)``), so ``&&``, ``||``,
    ``;;``, pipelines, subshells and case/function parens all
    split. A ``&`` that belongs to a redirection operator
    (``>&``, ``<&``, ``&>``, ``&>>``) never splits: leading
    descriptor duplications stay with their command. Quotes,
    backslash escapes, backquote spans and ``$(...)`` spans
    (paren-counted, nestable) are kept whole and never
    split. None means the line is unparseable here
    (unbalanced quoting or spans), which the caller treats as
    doubt, never as evidence of absence.
    """
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    escaped = False
    backquote = False
    depth = 0
    index = 0
    end = len(line)
    while index < end:
        char = line[index]
        if escaped:
            buf.append(char)
            escaped = False
            index += 1
            continue
        if quote == "'":
            buf.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\":
            buf.append(char)
            escaped = True
            index += 1
            continue
        if quote == '"':
            # Inside double quotes every character but the
            # closing quote is literal: separators and spans
            # below never fire here.
            buf.append(char)
            if char == '"':
                quote = None
            index += 1
            continue
        if char == "'":
            buf.append(char)
            if quote is None:
                quote = "'"
            elif quote == "'":
                quote = None
            index += 1
            continue
        if char == '"':
            buf.append(char)
            if quote is None:
                quote = '"'
            elif quote == '"':
                quote = None
            index += 1
            continue
        if backquote:
            buf.append(char)
            if char == "`":
                backquote = False
            index += 1
            continue
        if char == "`":
            buf.append(char)
            backquote = True
            index += 1
            continue
        if char == "$" and line[index + 1 : index + 2] == "(":
            buf.append("$(")
            depth += 1
            index += 2
            continue
        if char == "(":
            if depth:
                buf.append(char)
                depth += 1
            else:
                segments.append("".join(buf))
                buf = []
            index += 1
            continue
        if char == ")":
            if depth:
                buf.append(char)
                depth -= 1
            else:
                segments.append("".join(buf))
                buf = []
            index += 1
            continue
        if char == "&" and (
            (buf and buf[-1] in "<>")
            or line[index + 1 : index + 2] == ">"
        ):
            # A redirection operator, not a separator: the
            # ``&`` of ``>&``, ``<&``, ``&>`` and ``&>>``
            # either follows ``<``/``>`` or opens ``&>``,
            # while ``&&``, background ``&`` and ``|&``
            # still split below.
            buf.append(char)
            index += 1
            continue
        if char in ";|&":
            segments.append("".join(buf))
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    if quote is not None or escaped or backquote or depth:
        return None
    segments.append("".join(buf))
    return segments


def _split_words(segment: str) -> list[str] | None:
    """Split a segment into words, or None on doubt.

    Whitespace splits only outside quotes, backslash escapes,
    backquote spans and ``$(...)`` spans. Unbalanced quoting
    or spans return None: the shell would continue or fail
    the command, so the shape is doubted, never guessed.
    """
    words: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    escaped = False
    backquote = False
    depth = 0
    index = 0
    end = len(segment)
    started = False
    while index < end:
        char = segment[index]
        if escaped:
            buf.append(char)
            escaped = False
            started = True
            index += 1
            continue
        if quote == "'":
            buf.append(char)
            if char == "'":
                quote = None
            started = True
            index += 1
            continue
        if char == "\\":
            buf.append(char)
            escaped = True
            started = True
            index += 1
            continue
        if quote == '"':
            # Inside double quotes every character but the
            # closing quote is literal: whitespace below
            # never splits here.
            buf.append(char)
            if char == '"':
                quote = None
            started = True
            index += 1
            continue
        if char == "'":
            buf.append(char)
            if quote is None:
                quote = "'"
            elif quote == "'":
                quote = None
            started = True
            index += 1
            continue
        if char == '"':
            buf.append(char)
            if quote is None:
                quote = '"'
            elif quote == '"':
                quote = None
            started = True
            index += 1
            continue
        if backquote:
            buf.append(char)
            if char == "`":
                backquote = False
            started = True
            index += 1
            continue
        if char == "`":
            buf.append(char)
            backquote = True
            started = True
            index += 1
            continue
        if char == "$" and segment[index + 1 : index + 2] == "(":
            buf.append("$(")
            depth += 1
            started = True
            index += 2
            continue
        if depth and char in "()":
            buf.append(char)
            depth += 1 if char == "(" else -1
            started = True
            index += 1
            continue
        if char in " \t\n":
            if started:
                words.append("".join(buf))
                buf = []
                started = False
            index += 1
            continue
        buf.append(char)
        started = True
        index += 1
    if quote is not None or escaped or backquote or depth:
        return None
    if started:
        words.append("".join(buf))
    return words


def _resolve_word(word: str) -> str | None:
    """Remove quoting and escapes, or None when unresolvable.

    ``$`` and backquote open expansions the static pass cannot
    represent, so such words are doubted (None) rather than
    guessed; the caller treats doubt as an exec shape. Quote
    removal and backslash unescaping otherwise match the
    shell, so ``"ex"ec`` and ``\\exec`` resolve to ``exec``.
    """
    if "$" in word or "`" in word:
        return None
    out: list[str] = []
    quote: str | None = None
    escaped = False
    for char in word:
        if escaped:
            out.append(char)
            escaped = False
            continue
        if quote == "'":
            if char == "'":
                quote = None
            else:
                out.append(char)
            continue
        if char == "\\":
            escaped = True
            continue
        if char in ("'", '"'):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            else:
                out.append(char)
            continue
        out.append(char)
    if quote is not None or escaped:
        return None
    return "".join(out)


_SKIP_KEYWORDS = frozenset(
    [
        "!",
        "{",
        "}",
        "coproc",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "if",
        "in",
        "select",
        "then",
        "until",
        "while",
    ]
)

_REDIRECT_OP_RE = re.compile(
    r"(\d*)(<<-|<<<|<<|<>|>&|<&|&>>|&>|>>|>\||>|<)"
)

_EVAL_DEPTH_LIMIT = 4

_WRAPPER_CHAIN_LIMIT = 8


def _has_command_substitution(segment: str) -> bool:
    """True when the segment embeds a command substitution.

    ``$(...)`` and backquotes execute when the segment runs,
    even tucked inside an argument, a redirect target or an
    assignment value, so their presence is doubted, never
    cleared: the static pass cannot prove what they run.
    Single quotes and backslash escapes never open one, and
    neither does ``$((...))`` arithmetic on its own (the
    scan still enters it, so a nested substitution still
    counts). A single quote inside double quotes is literal
    text (POSIX) and never opens single-quote state, so
    ``"'$(...)"`` still counts; backquotes count even
    inside double quotes, where they still execute.
    """
    quote: str | None = None
    escaped = False
    index = 0
    end = len(segment)
    while index < end:
        char = segment[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if char == "'":
            if quote is None:
                quote = "'"
            index += 1
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
            index += 1
            continue
        if char == "`":
            return True
        if (
            char == "$"
            and segment[index + 1 : index + 2] == "("
            and segment[index + 2 : index + 3] != "("
        ):
            return True
        index += 1
    return False


def _skip_redirect_target(word: str, pos: int) -> int:
    """Advance POS past one redirection target span.

    Quote- and backslash-aware: the target ends before the
    next unquoted ``<``, ``>`` or ``&`` (which opens the
    next glued redirection) or at the end of the word. A
    single quote inside double quotes is literal text
    (POSIX) and never opens single-quote state.
    """
    quote: str | None = None
    escaped = False
    end = len(word)
    while pos < end:
        char = word[pos]
        if escaped:
            escaped = False
            pos += 1
            continue
        if quote == "'":
            if char == "'":
                quote = None
            pos += 1
            continue
        if char == "\\":
            escaped = True
            pos += 1
            continue
        if char == "'":
            if quote is None:
                quote = "'"
            pos += 1
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
            pos += 1
            continue
        if quote is None and char in "<>&":
            break
        pos += 1
    return pos


def _redirect_needs_word(word: str) -> bool | None:
    """Classify WORD as pure redirections, or None.

    Redirections glue (``2>/dev/null>`` is two of them), so
    the word parses as a run of ``[fd]operator[target]``
    pieces. Returns whether a trailing bare operator takes
    the next word as its target, or None when the word is
    not pure redirections.
    """
    pos = 0
    end = len(word)
    if end == 0:
        return None
    while pos < end:
        match = _REDIRECT_OP_RE.match(word, pos)
        if match is None:
            return None
        start = match.end()
        pos = _skip_redirect_target(word, start)
        if pos >= end:
            return pos == start
    return False


def _redirect_skip_words(words: list[str], index: int) -> int:
    """Words consumed when words[index] is pure redirections.

    Returns 1 when the run is self-contained, 2 when a
    trailing bare operator takes the next word as its
    target, and 0 when the word is not pure redirections.
    A quoted or escaped spelling falls back to its resolved
    form, matching the historical single-match behavior.
    """
    for candidate in (words[index], _resolve_word(words[index])):
        if candidate is None:
            continue
        needs_word = _redirect_needs_word(candidate)
        if needs_word is None:
            continue
        return 2 if needs_word else 1
    return 0


def _command_base(word: str) -> str | None:
    """Resolve a command word, or None when unresolvable.

    A redirection operator glued to the command word
    (``exec>file``) does not hide it: the word is cut there
    before comparing.
    """
    command = _resolve_word(word)
    if command is None:
        return None
    cut = len(command)
    for mark in ("<", ">"):
        at = command.find(mark)
        if at != -1 and at < cut:
            cut = at
    return command[:cut]


def _eval_args_exec_shape(arg_words: list[str], depth: int) -> bool:
    """True when resolved eval arguments could invoke ``exec``.

    The shell joins eval's arguments with spaces and parses
    the result as a full script, so the joined body
    re-enters the grammar line by line: multi-line bodies
    and every separator (``;``, ``&&``, ``||``, ``|``,
    newlines) all re-analyze, bounded by the eval depth
    limit. Unresolvable arguments are doubted, never
    cleared, and an empty body runs nothing.
    """
    if depth >= _EVAL_DEPTH_LIMIT:
        return True
    resolved_args: list[str] = []
    for word in arg_words:
        arg = _resolve_word(word)
        if arg is None:
            return True
        resolved_args.append(arg)
    return any(
        _line_has_exec_shape(line, depth + 1)
        for line in _logical_lines(" ".join(resolved_args))
    )


def _wrapper_exec_shape(
    words: list[str], index: int, total: int, depth: int = 0
) -> bool:
    """True when a wrapper segment could invoke ``exec``.

    ``command``/``builtin``/``time`` defer to their target
    word: single-dash options and one ``--``
    end-of-options skipped, then the redirections the shell
    applies around the target, then the target itself with
    glued redirection operators cut away. ``time``
    additionally skips assignment prefixes -- it times a
    whole pipeline, so ``time FOO=1 exec ...`` still
    replaces the image -- while ``command``/``builtin``
    take plain operands (an assignment there names the
    command and never executes). A deferred-to ``eval``
    keeps its eval-ness: its resolved arguments re-analyze
    as a full script, so wrapper chains (flags, ``--``,
    redirections, nesting) never clear a pending eval.
    Wrappers nest (``command command exec ...``); chains
    past the bound and unresolvable words are doubted,
    never cleared. A ``--foo`` word is the target itself,
    never an option, and an exhausted target runs nothing.
    """
    pos = index
    kind = _command_base(words[index])
    for _ in range(_WRAPPER_CHAIN_LIMIT):
        rest = pos + 1
        while rest < total:
            flag = _resolve_word(words[rest])
            if flag is None:
                return True
            if flag == "--":
                rest += 1
                break
            if (
                len(flag) > 1
                and flag.startswith("-")
                and not flag.startswith("--")
            ):
                rest += 1
                continue
            break
        while rest < total:
            word = words[rest]
            if kind == "time" and (
                _ASSIGN_RE.match(word) is not None
            ):
                rest += 1
                continue
            skip = _redirect_skip_words(words, rest)
            if skip:
                rest += skip
                continue
            break
        if rest >= total:
            return False
        target = _command_base(words[rest])
        if target is None:
            return True
        if target == "exec":
            return True
        if target == "eval":
            return _eval_args_exec_shape(words[rest + 1 :], depth)
        if target not in ("command", "builtin", "time"):
            return False
        pos = rest
        kind = target
    return True


def _segment_exec_shape(segment: str, depth: int = 0) -> bool:
    """True when a command segment could invoke ``exec``.

    An embedded command substitution is doubted first: it
    executes wherever it sits, so no segment carrying one
    is ever cleared. Leading shell keywords are skipped
    (``if``/``then``/loops/``!``/braces; ``for``/``select``/
    ``function`` consume their name too; ``case`` skips
    through ``in`` since its subject is matched data, never
    executed). Assignment prefixes are recognized before
    the command word, so plain assignments keep their
    historical classification instead of tripping the
    expansion doubt. Redirections (every operator spelling,
    glued runs and spaced file words, quoted or plain) are
    skipped the way the shell skips them before the command
    word. The command word then resolves quoting and
    escapes: ``exec`` (however quoted or escaped) is an exec
    invocation, while ``$``/backquote expansions that could
    expand to ``exec`` are doubted, never defaulted to
    direct. ``command``/``builtin``/``time`` defer to their
    target (see :func:`_wrapper_exec_shape`), and ``eval``
    re-analyzes its resolved arguments as a full script
    (bounded; see :func:`_eval_args_exec_shape`), so the
    literal form re-enters the grammar instead of hiding
    behind its quoting; anything unparseable is doubted.
    """
    if _has_command_substitution(segment):
        return True
    words = _split_words(segment)
    if words is None:
        return True
    index = 0
    total = len(words)
    while index < total:
        if _ASSIGN_RE.match(words[index]) is not None:
            index += 1
            continue
        resolved = _resolve_word(words[index])
        if resolved is None:
            return True
        if resolved in ("for", "select", "function"):
            index += 2
            continue
        if resolved == "case":
            index += 1
            while index < total and (
                _resolve_word(words[index]) != "in"
            ):
                index += 1
            index += 1
            continue
        if resolved in _SKIP_KEYWORDS:
            index += 1
            continue
        break
    while index < total:
        word = words[index]
        if _ASSIGN_RE.match(word) is not None:
            index += 1
            continue
        skip = _redirect_skip_words(words, index)
        if skip:
            index += skip
            continue
        break
    if index >= total:
        return False
    command = _command_base(words[index])
    if command is None:
        return True
    if command == "exec":
        return True
    if command in ("command", "builtin", "time"):
        return _wrapper_exec_shape(words, index, total, depth)
    if command == "eval":
        return _eval_args_exec_shape(words[index + 1 :], depth)
    return False


def _line_has_exec_shape(stripped: str, depth: int = 0) -> bool:
    """True when a stripped logical line could invoke ``exec``.

    Blank lines and full-line comments cannot. Anything else
    is comment-stripped, split into command segments and
    checked segment by segment; unparseable lines are
    doubted, never treated as direct.
    """
    if not stripped or stripped.startswith("#"):
        return False
    code = _strip_shape_comment(stripped).strip()
    if not code:
        return False
    segments = _split_segments(code)
    if segments is None:
        return True
    return any(
        _segment_exec_shape(segment, depth) for segment in segments
    )


_SHELL_INTERPRETER_NAMES = frozenset(
    [
        "ash",
        "bash",
        "busybox",
        "dash",
        "ksh",
        "mksh",
        "pdksh",
        "posh",
        "sh",
        "yash",
        "zsh",
    ]
)


def _is_shell_interpreter(interpreter: str | None) -> bool:
    """True when exec lines follow shell tokenization rules.

    Only a recognized shell interpreter selects its image
    through shell syntax (busybox runs scripts through its
    shell applet). An absent or unparseable shebang (None)
    counts as a shell: the kernel falls back to running
    such entries as shell scripts, so doubting their shapes
    is the fail-closed choice. Every other interpreter
    keeps the historical space/tab ``exec`` spelling check,
    so shell tokenization never misreads python, perl and
    friends.
    """
    if interpreter is None:
        return True
    return os.path.basename(interpreter) in _SHELL_INTERPRETER_NAMES


def _text_interpreter(text: str) -> str | None:
    """Return the shebang interpreter named by script text."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("#!"):
        return None
    words = lines[0][2:].strip().split()
    if not words:
        return None
    return words[0]


def _is_exec_line(stripped: str, shell: bool = True) -> bool:
    """True when a stripped line could invoke ``exec``.

    Shell-faithful detection, not a prefix spelling check:
    the line is comment-stripped, split at command
    separators, and each segment skips keywords, assignment
    prefixes and redirections before its command word
    resolves quoting, escapes and expansions. ``exec``
    behind separators (``:;exec``), redirections
    (``exec</dev/null``), quoting (``"exec"``), escapes
    (``\\exec``) or continuations is still an exec
    invocation; command words carrying expansions
    (``$X``, ``exec${IFS}...``) could expand to ``exec`` and
    are doubted, never defaulted to direct. Callers pass
    logical lines from :func:`_logical_lines` and refuse
    shaped lines through the exact launcher grammar.
    Non-shell scripts (``shell`` False) keep the
    historical space/tab ``exec`` spelling check instead.
    """
    if not shell:
        return stripped == "exec" or (
            stripped.startswith("exec")
            and stripped[4:5] in (" ", "\t")
        )
    return _line_has_exec_shape(stripped)


def _strip_shell_comment(line: str) -> str:
    """Cut a ``#`` comment that starts outside any shell word."""
    for index, char in enumerate(line):
        if char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _split_assignment(line: str) -> tuple[str, str] | None:
    """Split a bare ``NAME=value`` line, else None.

    A line is a bare assignment only when it holds exactly one
    shell word: ``VAR=ok /path/cmd`` (one prefix or several,
    ``A=1 B=2 cmd``) is an env-prefix COMMAND whose executable
    the shell runs, never an assignment, so it returns None and
    the caller rejects the launcher instead of capturing the
    wrong program. A trailing ``#`` comment does not make a
    second word. Unparseable quoting returns None (the shell
    would fail the script, so admission refuses it too).
    """
    match = _ASSIGN_RE.match(line)
    if match is None:
        return None
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        return None
    if len(tokens) == 1:
        return (match.group(1), match.group(2))
    stripped = _strip_shell_comment(line)
    if stripped == line:
        return None
    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        return None
    if len(tokens) != 1:
        return None
    return (match.group(1), match.group(2))


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


def _has_shebang(path: str) -> bool:
    """True when the file starts with ``#!`` (or cannot be read)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return True


def _is_elf(path: str) -> bool:
    """True when the file starts with the ELF magic."""
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"\x7fELF"
    except OSError:
        return False


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


def _exec_target(text: str, shell: bool = True) -> str | None:
    """Return the script's exec target, or None when not unique.

    Assignments after the exec line never execute (the image is
    already replaced), so only pre-exec assignments expand the
    target; exec lines are still all counted, so two execs stay
    ambiguous. Env-prefix commands (``VAR=ok /path/cmd``) are
    commands, never assignments, and contribute no expansions.
    Shell lines are logical (continuations and quotes joined
    as the shell joins them), and an exec-shaped line outside
    the exact launcher grammar is unresolvable on its own.
    Non-shell scripts keep the historical physical-line
    resolution exactly, flags included.
    """
    assigns: dict[str, str] = {}
    exec_lines: list[str] = []
    seen_exec = False
    lines = _logical_lines(text) if shell else text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        split = _split_assignment(stripped)
        if split is not None:
            if not seen_exec:
                assigns[split[0]] = _unquote(split[1].strip())
            continue
        if _is_exec_line(stripped, shell):
            if shell and not _exec_line_supported(stripped):
                # An exec-shaped line outside the exact
                # grammar selects its image through
                # semantics the resolver does not model
                # (separators, redirections, flags, quoted
                # flags, prefixes, unquoted expansions):
                # unresolvable, never guessed.
                return None
            exec_lines.append(stripped)
            seen_exec = True
    if len(exec_lines) != 1:
        return None
    try:
        tokens = shlex.split(exec_lines[0], posix=True)
    except ValueError:
        return None
    args = tokens[1:]
    if not shell:
        # Historical non-shell resolution, preserved
        # exactly: flags skipped, never screened.
        while args and args[0] in ("-c", "-l"):
            args = args[1:]
        if len(args) >= 2 and args[0] == "-a":
            args = args[2:]
    # Shell flags are rejected by the grammar screen above,
    # never skipped: shells disagree on them, so no flag
    # spelling is modeled. The guards below stay as
    # fail-closed redundancy, not as a fallback path.
    if not args or args[0].startswith("-"):
        return None
    if _ASSIGN_RE.match(args[0]) is not None:
        # ``exec VAR=... cmd`` runs the image under unmodeled
        # environment influence (and ``exec VAR=...`` alone
        # never replaces the image at all), so the target is
        # unresolvable, never the prefix word.
        return None
    expanded = _expand_vars(args[0], assigns)
    if expanded is None:
        return None
    # An unquoted expansion undergoes word splitting and pathname
    # expansion at runtime, so a static literal carrying whitespace
    # or glob characters may name a different file than the shell
    # executes; such targets are unresolvable, never guessed.
    if any(char in expanded for char in " \t\n*?["):
        return None
    return expanded


def follow_exec_target(entry: str) -> str | None:
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
        shell = _is_shell_interpreter(_text_interpreter(text))
        target = _exec_target(text, shell)
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


def parse_shebang(path: str) -> str | None:
    """Return the shebang interpreter path, or None when absent.

    Returns the interpreter's path exactly as written (leading
    blanks skipped, like the kernel). An empty interpreter or an
    unreadable file yields None.
    """
    try:
        with open(path, "rb") as handle:
            first = handle.readline(512)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    try:
        line = first[2:].decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        return None
    if not line:
        return None
    return line.split()[0]


def is_python_interpreter(interpreter: str) -> bool:
    """True when the interpreter path names a Python binary."""
    base = os.path.basename(interpreter)
    return base == "python" or base.startswith("python")


def identify_file(path: str) -> FileIdentity:
    """Capture a file's bytes and filesystem identity.

    Follows symlinks for the bytes and stat identity, and records
    the link's own ``(st_dev, st_ino)`` when ``path`` itself is a
    symlink. Raises :class:`AdmissionError` (``not-found`` /
    ``unreadable``) instead of ``OSError``.
    """
    try:
        link_stat = os.lstat(path)
    except OSError as exc:
        raise AdmissionError(
            REASON_NOT_FOUND, "cannot stat %r: %s" % (path, exc)
        )
    link_dev, link_ino = -1, -1
    if stat.S_ISLNK(link_stat.st_mode):
        link_dev, link_ino = link_stat.st_dev, link_stat.st_ino
    try:
        realpath = os.path.realpath(path)
        file_stat = os.stat(path)
    except OSError as exc:
        raise AdmissionError(
            REASON_UNREADABLE, "cannot stat %r: %s" % (path, exc)
        )
    if not stat.S_ISREG(file_stat.st_mode):
        raise AdmissionError(
            REASON_UNREADABLE, "not a regular file: %r" % (path,)
        )
    try:
        digest = sha256_file(realpath)
    except OSError as exc:
        raise AdmissionError(
            REASON_UNREADABLE, "cannot hash %r: %s" % (path, exc)
        )
    return FileIdentity(
        path=path,
        realpath=realpath,
        sha256=digest,
        size=file_stat.st_size,
        dev=file_stat.st_dev,
        ino=file_stat.st_ino,
        mtime_ns=file_stat.st_mtime_ns,
        link_dev=link_dev,
        link_ino=link_ino,
    )


def capture_chain(entry_abspath: str) -> CapturedChain:
    """Classify an entry and capture its launcher chain (no spawn).

    Returns the executable form, every hop identity for
    ``exec-launcher`` entries, the final image and the shebang
    interpreter path (if any). ``unknown`` forms carry the reason
    in ``note``; callers must reject them, never guess.
    """
    entry = identify_file(entry_abspath)
    if _is_elf(entry.realpath):
        return CapturedChain(
            form=FORM_BINARY, hops=(), image=entry, interpreter=None
        )
    interpreter = parse_shebang(entry.realpath)
    if interpreter is None:
        return CapturedChain(
            form=FORM_UNKNOWN,
            hops=(),
            image=entry,
            interpreter=None,
            note="not an ELF image and carries no shebang",
        )
    if os.path.basename(interpreter) == "env" or not os.path.isabs(
        interpreter
    ):
        return CapturedChain(
            form=FORM_UNKNOWN,
            hops=(),
            image=entry,
            interpreter=interpreter,
            note="shebang interpreter %r resolves through PATH; "
            "PATH-resolved interpreters are never guessed"
            % (interpreter,),
        )
    text = _read_script_text(entry.realpath)
    if text is None:
        return CapturedChain(
            form=FORM_UNKNOWN,
            hops=(),
            image=entry,
            interpreter=interpreter,
            note="shebang script is unreadable",
        )
    shell = _is_shell_interpreter(interpreter)
    target = _exec_target(text, shell)
    exec_lines = _count_exec_lines(text, shell)
    unsupported = _unsupported_shell_logic(text, shell)
    if unsupported is not None:
        return CapturedChain(
            form=FORM_UNKNOWN,
            hops=(),
            image=entry,
            interpreter=interpreter,
            note="unsupported shell logic in launcher entry: %r"
            % (unsupported[:80],),
        )
    if target is None and exec_lines == 0:
        form = (
            FORM_CONSOLE_SCRIPT
            if is_python_interpreter(interpreter)
            else FORM_DIRECT_SCRIPT
        )
        return CapturedChain(
            form=form, hops=(), image=entry, interpreter=interpreter
        )
    if target is None:
        # One unresolvable exec line (unknown variable, bad flags)
        # or several (ambiguous): the continuation depends on the
        # ambient environment or a guess, so the entry is an
        # unresolvable launcher, never a directly run script.
        return CapturedChain(
            form=FORM_UNKNOWN,
            hops=(),
            image=entry,
            interpreter=interpreter,
            note=(
                "ambiguous exec lines in launcher entry"
                if exec_lines > 1
                else "unresolvable exec target in launcher entry"
            ),
        )
    if not os.path.isabs(target):
        # A relative target resolves against the runtime working
        # directory (or PATH for a bare name), so the image the
        # shell selects depends on where the spawn runs rather
        # than on the captured chain: rejected, never resolved
        # against the admission-time directory.
        return CapturedChain(
            form=FORM_UNKNOWN,
            hops=(),
            image=entry,
            interpreter=interpreter,
            note="relative exec target %r in launcher entry" % (target,),
        )
    return _capture_launcher(entry, interpreter)


def _count_exec_lines(text: str, shell: bool = True) -> int:
    count = 0
    lines = _logical_lines(text) if shell else text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _is_exec_line(stripped, shell):
            count += 1
    return count


# Exact launcher grammar (see _unsupported_shell_logic). An
# exec line carries no shell metacharacters at all: pipelines,
# backgrounding, sequencing, redirections, subshells, command
# substitution, globbing, tilde expansion, history, comments and
# quoting escapes are all rejected, never guessed. ``$`` and
# braces are validated structurally per word (see
# _exec_line_supported): the only ``$`` forms are ``$NAME`` and
# ``${NAME}`` in the target word plus the exact argument word
# ``"$@"``.
_EXEC_LINE_FORBIDDEN = (
    "`",
    ";",
    "|",
    "&",
    "<",
    ">",
    "(",
    ")",
    "\\",
    "#",
    "!",
    "~",
    "*",
    "?",
    "[",
    "]",
)

# Assignment values are literal: no ``$`` (any parameter,
# command, arithmetic or positional expansion), no backquote, no
# backslash, no tilde, no braces and no shell metacharacters.
# Quoting survives only as shell quoting that still leaves one
# word (``LABEL="a b"``); glob characters are literal here
# because the shell performs no pathname expansion on an
# assignment's right-hand side.
_ASSIGNMENT_VALUE_FORBIDDEN = (
    "$",
    "`",
    "\\",
    "~",
    "{",
    "}",
    ";",
    "|",
    "&",
    "<",
    ">",
    "(",
    ")",
)


def _unsupported_shell_logic(
    text: str, shell: bool = True
) -> str | None:
    """Return the first unsupported launcher line, or None.

    Scripts without an exec line run directly under their pinned
    interpreter and may carry arbitrary logic. Launcher-shaped
    scripts (at least one exec line) must match the exact
    grammar -- blank lines, comments, literal single-word
    assignments and one supported exec line -- and nothing else:

    * a physical line ending in a backslash joins the next line
      in the shell but parses separately here, so it is
      rejected wherever it appears;
    * an assignment is ``NAME=literal`` holding exactly one
      shell word (a trailing ``#`` comment does not make a
      second one); ``VAR=ok /path/cmd`` is an env-prefix
      COMMAND naming its executable, never an assignment;
    * an exec line is ``exec target [args]`` with no flags, no
      ``VAR=...`` prefix, a target word whose only ``$`` forms
      are ``$NAME`` and ``${NAME}`` (expanded from the script's
      own pre-exec assignments, resolving to an absolute path),
      and argument words that are either literal or exactly
      ``"$@"``. Flags are rejected, never skipped: shells
      disagree on them -- dash runs ``exec "-c" ...`` as a
      command while bash reads a flag, and dash has no ``-a``
      at all -- so no flag spelling is modeled.

    Anything else -- conditionals, loops, command invocations,
    ``export``/``set``, function definitions, pipelines,
    arithmetic/command/process expansion in any accepted
    position, and every other ``$`` form -- selects the executed
    program through semantics this resolver does not model, so
    the script is rejected instead of guessed. The rejected
    line is returned verbatim, so the diagnostic captures the
    uncaptured executable.
    """
    meaningful: list[str] = []
    for line in text.splitlines():
        if line.endswith("\\"):
            # A trailing backslash joins the next physical line
            # in the shell (even inside a comment), while this
            # parser reads lines separately: the joined meaning
            # is never guessed.
            return line.strip()
    lines = _logical_lines(text) if shell else text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        meaningful.append(stripped)
    if not any(_is_exec_line(line, shell) for line in meaningful):
        return None
    for line in meaningful:
        if _is_exec_line(line, shell):
            if not _exec_line_supported(line):
                return line
            continue
        split = _split_assignment(line)
        if split is None:
            return line
        if not _assignment_value_supported(split[1]):
            return line
    return None


def _assignment_value_supported(value: str) -> bool:
    """True when an assignment value is a pure literal.

    No ``$`` (parameter, command, arithmetic, positional or
    special-parameter expansion of any spelling), no backquote,
    no backslash, no tilde, no braces and no shell
    metacharacters: the shell stores the value exactly as
    written (modulo the single-word quoting the assignment
    check already validated).
    """
    return not any(char in value for char in _ASSIGNMENT_VALUE_FORBIDDEN)


def _exec_word_is_literal(word: str) -> bool:
    """True when an exec-line word carries no expansion syntax.

    ``-a`` names and plain argument words are literal: no ``$``
    and no braces (brace expansion would split one word into
    several). Quoting is fine -- the line tokenizer already
    validated its balance -- and every other metacharacter was
    rejected by the exec-line scan.
    """
    return "$" not in word and "{" not in word and "}" not in word


def _target_word_supported(word: str) -> bool:
    """True when an exec target word uses only documented refs.

    ``$`` may only open ``$NAME`` or ``${NAME}`` (plain names
    from the script's own assignments); every other ``$`` form
    -- ``$(...)``, ``$((...))``, ``$[...]``, ``$1``, ``$@``,
    ``$?``, ``$$``, ``${NAME-op}`` and friends -- is rejected,
    as is a ``$`` inside single quotes (literal there, but the
    expansion pass cannot represent it) or a stray brace. An
    unbraced ``$NAME`` ends where the shell ends it: a quote
    right after the name (``$P"x"``) would let the shell read
    ``P`` while the expansion pass reads through the removed
    quotes and resolves ``Px``, so a following quote is
    allowed only when it closes the currently open double
    quote (``"$P"``) and is itself followed by a name
    boundary (end of word, another ``$`` ref, or a character
    outside names and quotes -- braces still fail on the next
    pass). Braced refs always agree with the expansion pass
    and need no boundary check.
    """
    index = 0
    end = len(word)
    quote: str | None = None
    while index < end:
        char = word[index]
        if quote == "'":
            if char == "'":
                quote = None
            elif char == "$":
                return False
            index += 1
            continue
        if char == "'":
            # Literal inside double quotes (POSIX): only an
            # unquoted single quote opens single-quote state.
            if quote is None:
                quote = "'"
            index += 1
            continue
        if char == '"':
            quote = None if quote == '"' else '"'
            index += 1
            continue
        if char == "$":
            match = _VAR_RE.match(word, index)
            if match is None:
                return False
            if match.group(1) is None:
                follow_at = match.end()
                if (
                    quote == '"'
                    and word[follow_at : follow_at + 1] == '"'
                ):
                    follow_at += 1
                follow = word[follow_at : follow_at + 1]
                if follow in ("'", '"'):
                    return False
                if (
                    follow != ""
                    and follow != "$"
                    and (follow.isalnum() or follow == "_")
                ):
                    return False
            index = match.end()
            continue
        if char == "{" or char == "}":
            return False
        index += 1
    return True


def _exec_line_supported(line: str) -> bool:
    """True when an exec line matches the exact launcher grammar.

    ``exec target [args]``: the line carries no shell
    metacharacters (scanned raw, before tokenizing), the first
    word is the target (no flags: a leading ``-`` word or any
    quoting of ``-c``/``-l``/``-a`` is rejected, since shells
    disagree on flag spellings), the target is not a
    ``VAR=...`` env prefix and uses only documented ``$`` refs
    (see :func:`_target_word_supported`), and every argument is
    either a literal word or exactly ``"$@"`` (verbatim
    passthrough of the admitted argument suffix).
    """
    if any(char in line for char in _EXEC_LINE_FORBIDDEN):
        return False
    try:
        # Quotes preserved: `"$@"` (passthrough) must stay
        # distinguishable from `'$@'` (a literal dollar word,
        # rejected) and `$@` (word splitting, rejected).
        tokens = shlex.split(line, posix=False)
    except ValueError:
        return False
    if not tokens:
        return False
    if _resolve_word(tokens[0]) != "exec":
        # Exec-shaped lines whose first word is not the exec
        # builtin itself (an env prefix, a ``command``/``eval``
        # wrapper, an expansion) select their image through
        # unmodeled semantics: unsupported, never guessed. A
        # quoted spelling of the builtin itself (``"exec"``)
        # still resolves and proceeds to the target checks.
        return False
    args = tokens[1:]
    if not args or args[0].startswith("-"):
        return False
    if args[0].replace("'", "").replace('"', "") in ("-c", "-l", "-a"):
        # A quoted flag spelling: bash reads ``exec "-c" ...``
        # as a flag while dash runs ``-c`` as a command, so
        # the target the shell selects depends on the
        # interpreter and is never guessed.
        return False
    if _ASSIGN_RE.match(args[0]) is not None:
        # ``exec VAR=... cmd`` runs the image under unmodeled
        # environment influence (and ``exec VAR=...`` alone
        # never replaces the image at all), so the target is
        # unsupported, never the prefix word.
        return False
    if not _target_word_supported(args[0]):
        return False
    for word in args[1:]:
        if word == '"$@"':
            continue
        if not _exec_word_is_literal(word):
            return False
    return True


def _capture_launcher(
    entry: FileIdentity, interpreter: str
) -> CapturedChain:
    """Capture a single-exec launcher's hop chain (no spawn)."""
    hops: list[FileIdentity] = [entry]
    seen = {entry.realpath}
    current = entry.realpath
    for _ in range(_EXEC_CHAIN_LIMIT):
        text = _read_script_text(current)
        if text is None:
            if _has_shebang(current) and not _is_elf(current):
                return CapturedChain(
                    form=FORM_UNKNOWN,
                    hops=tuple(hops),
                    image=hops[-1],
                    interpreter=interpreter,
                    note="launcher hop %r is not analyzable" % (current,),
                )
            if hops and hops[-1].realpath == current:
                image = hops[-1]
            else:
                try:
                    image = identify_file(current)
                except AdmissionError as exc:
                    return CapturedChain(
                        form=FORM_UNKNOWN,
                        hops=tuple(hops),
                        image=hops[-1],
                        interpreter=interpreter,
                        note="launcher target unreadable: %s" % exc.detail,
                    )
                hops.append(image)
            return CapturedChain(
                form=FORM_EXEC_LAUNCHER,
                hops=tuple(hops),
                image=image,
                interpreter=interpreter,
            )
        shell = _is_shell_interpreter(_text_interpreter(text))
        unsupported = _unsupported_shell_logic(text, shell)
        if unsupported is not None:
            return CapturedChain(
                form=FORM_UNKNOWN,
                hops=tuple(hops),
                image=hops[-1],
                interpreter=interpreter,
                note="unsupported shell logic in launcher hop %r: %r"
                % (current, unsupported[:80]),
            )
        target = _exec_target(text, shell)
        if target is None:
            if _count_exec_lines(text, shell) != 0:
                # An unresolvable or ambiguous continuation:
                # ambient-dependent, never a terminus.
                return CapturedChain(
                    form=FORM_UNKNOWN,
                    hops=tuple(hops),
                    image=hops[-1],
                    interpreter=interpreter,
                    note="unresolvable exec lines in launcher hop %r"
                    % (current,),
                )
            # A chained script with no exec line runs directly:
            # the chain terminus.
            if hops and hops[-1].realpath == current:
                image = hops[-1]
            else:
                try:
                    image = identify_file(current)
                except AdmissionError as exc:
                    return CapturedChain(
                        form=FORM_UNKNOWN,
                        hops=tuple(hops),
                        image=hops[-1],
                        interpreter=interpreter,
                        note="launcher target unreadable: %s" % exc.detail,
                    )
                hops.append(image)
            return CapturedChain(
                form=FORM_EXEC_LAUNCHER,
                hops=tuple(hops),
                image=image,
                interpreter=interpreter,
            )
        if not os.path.isabs(target):
            return CapturedChain(
                form=FORM_UNKNOWN,
                hops=tuple(hops),
                image=hops[-1],
                interpreter=interpreter,
                note="relative exec target %r in launcher hop %r"
                % (target, current),
            )
        if not os.path.isfile(target):
            return CapturedChain(
                form=FORM_UNKNOWN,
                hops=tuple(hops),
                image=hops[-1],
                interpreter=interpreter,
                note="dangling exec target %r" % (target,),
            )
        try:
            resolved = os.path.realpath(target)
        except OSError:
            return CapturedChain(
                form=FORM_UNKNOWN,
                hops=tuple(hops),
                image=hops[-1],
                interpreter=interpreter,
                note="unresolvable exec target %r" % (target,),
            )
        if resolved in seen:
            return CapturedChain(
                form=FORM_UNKNOWN,
                hops=tuple(hops),
                image=hops[-1],
                interpreter=interpreter,
                note="cyclic exec chain at %r" % (resolved,),
            )
        seen.add(resolved)
        try:
            # The hop is identified through the pathname the
            # parent launcher names (possibly a symlink), not
            # through its staging resolution: bytes and stat
            # identity still follow links, but the recorded
            # path keeps the executed resolution so the
            # spawn-time recheck refuses a retargeted link.
            hop = identify_file(target)
        except AdmissionError as exc:
            return CapturedChain(
                form=FORM_UNKNOWN,
                hops=tuple(hops),
                image=hops[-1],
                interpreter=interpreter,
                note="launcher hop unreadable: %s" % exc.detail,
            )
        hops.append(hop)
        current = resolved
    return CapturedChain(
        form=FORM_UNKNOWN,
        hops=tuple(hops),
        image=hops[-1],
        interpreter=interpreter,
        note="exec chain exceeds the depth bound",
    )


def resolve_entry(request: ExecutionRequest) -> str:
    """Resolve the request to one absolute entry path (no spawn).

    Explicit paths (containing a separator, or any value when
    ``allow_path_lookup`` is false) must exist; bare names resolve
    through ``search_paths`` plus ``PATH`` exactly once. Raises
    :class:`AdmissionError` (``not-found``) when nothing resolves.
    The returned path is captured and never re-resolved.
    """
    if not isinstance(request, ExecutionRequest):
        raise ValueError("resolve_entry requires an ExecutionRequest")
    explicit = (
        os.path.sep in request.argv0
        or not request.allow_path_lookup
    )
    if explicit:
        candidate = request.argv0
        if not os.path.isfile(candidate):
            raise AdmissionError(
                REASON_NOT_FOUND,
                "explicit entry is not a file: %r" % (candidate,),
            )
        return os.path.abspath(candidate)
    search_path = _search_path(request.search_paths)
    found = shutil.which(request.argv0, path=search_path)
    if found is None:
        raise AdmissionError(
            REASON_NOT_FOUND,
            "command not found on the search path: %r" % (request.argv0,),
        )
    return os.path.abspath(found)


def _search_path(search_paths: tuple[str, ...]) -> str:
    current = os.environ.get("PATH", "")
    extra = os.pathsep.join(search_paths)
    if extra and current:
        return extra + os.pathsep + current
    return extra or current


def _interpreter_identity(path: str) -> FileIdentity | None:
    """Capture the interpreter identity, or None when unreadable."""
    try:
        return identify_file(path)
    except AdmissionError:
        return None


def _venv_site_candidates(
    interpreter: FileIdentity, version_info: tuple[int, int]
) -> list[str]:
    """Recover virtual-environment site roots without running ``site``.

    With ``-S`` the interpreter reports no ``site``-added roots, so
    an environment whose ``bin/python`` is selected through a
    symlink (``uv tool``, ``virtualenv``) would lose its own
    site-packages. The roots are recovered arithmetically instead:
    for the interpreter's captured path and realpath alike, when
    the parent directory is named ``bin`` the sibling
    ``lib{,64}/pythonX.Y/{site,dist}-packages`` directories are
    candidates. Only existing directories are returned. These
    roots only locate pinned-by-hash modules, so extra candidates
    can never cause an unpinned import.
    """
    major, minor = version_info
    tag = "python%d.%d" % (major, minor)
    candidates: list[str] = []
    seen: set[str] = set()
    for base in (interpreter.path, interpreter.realpath):
        bindir = os.path.dirname(base)
        if os.path.basename(bindir) != "bin":
            continue
        env_root = os.path.dirname(bindir)
        for lib in ("lib", "lib64"):
            for spelling in ("site-packages", "dist-packages"):
                candidate = os.path.join(env_root, lib, tag, spelling)
                if candidate not in seen and os.path.isdir(candidate):
                    seen.add(candidate)
                    candidates.append(candidate)
    return candidates


def _dump_interpreter_sys_path(
    interpreter: FileIdentity,
    python_path: tuple[str, ...],
    timeout: int,
) -> tuple[list[str], tuple[str, ...] | None]:
    """Ask an admitted interpreter for its module path (no startup).

    Runs under ``-S`` with the sanitized environment and WITHOUT
    any ``PYTHONPATH``, so ``site`` never initializes (no
    ``.pth`` file executes and no ``sitecustomize``/
    ``usercustomize`` imports, from the declared roots or
    anywhere else) and the probe's own ``json``/``sys``/``site``
    imports resolve to the interpreter's real standard library,
    never to a declared-but-still-unverified search root: a
    ``json.py`` planted on a declared root cannot execute here.
    Only ``sys``/``json`` plus a side-effect-free
    ``site.getsitepackages()`` call run. The explicitly
    admitted ``PYTHONPATH`` roots are merged ahead of the
    reported path below (absolute existing directories only),
    reproducing runtime resolution order without ever exposing
    the probe process to them. Virtual-environment roots are
    recovered deterministically from the interpreter's location
    (see ``_venv_site_candidates``) and ordered after the
    reported path but before the ``getsitepackages()`` entries.
    Only absolute existing directories are returned (relative
    ``sys.path`` entries such as the ``-c`` working directory
    never locate pins). The interpreter is invoked through its
    captured path (not the realpath) so virtual-environment
    context resolves exactly as it does for the admitted entry;
    the captured identity is re-checked immediately first.
    Returns ``(roots, stdlib_names)``: the resolution order plus
    the interpreter's own standard-library module names, or
    ``None`` for the names when the interpreter predates the
    inventory (callers with declared roots fail closed then,
    since a shadow cannot be ruled out).
    """
    drift = _check_identity_live(interpreter)
    if drift is not None:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter %r drifted before its module-path probe: %s"
            % (interpreter.path, drift),
        )
    env = filter_spawn_ambient(os.environ)
    for name, value in PYTHON_ENV_SET:
        env[name] = value
    # Deliberately no PYTHONPATH here: the declared roots are
    # still unverified at this point, and PYTHONPATH precedes
    # the standard library on sys.path, so reinstating it would
    # let a planted stdlib-named module (json.py) execute inside
    # the probe. The declared roots are merged into the
    # returned order below instead (same set, same order, zero
    # probe exposure).
    try:
        completed = subprocess.run(
            [interpreter.path, "-S", "-c", _SYS_PATH_PROBE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter module-path probe failed: %s" % (exc,),
        )
    if completed.returncode != 0:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter module-path probe exited %d"
            % (completed.returncode,),
        )
    try:
        document = json.loads(completed.stdout)
    except ValueError as exc:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter module-path probe was unparseable: %s" % (exc,),
        )
    if not isinstance(document, dict):
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter module-path probe was unparseable",
        )
    entries = document.get("path")
    site_entries = document.get("site")
    reported = document.get("version_info")
    stdlib_reported = document.get("stdlib")
    if (
        not isinstance(entries, list)
        or not isinstance(site_entries, list)
        or not (
            isinstance(reported, list)
            and len(reported) == 2
            and all(
                isinstance(part, int) and 0 <= part < 100
                for part in reported
            )
        )
        or not (
            stdlib_reported is None
            or (
                isinstance(stdlib_reported, list)
                and all(
                    isinstance(name, str) for name in stdlib_reported
                )
            )
        )
    ):
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter module-path probe was unparseable",
        )
    stdlib_names = (
        tuple(sorted(set(stdlib_reported)))
        if stdlib_reported is not None
        else None
    )
    roots = [
        entry
        for entry in entries
        if isinstance(entry, str)
        and os.path.isabs(entry)
        and os.path.isdir(entry)
    ]
    recovered = _venv_site_candidates(
        interpreter, (reported[0], reported[1])
    )
    # Declared roots first (runtime order), merged here rather
    # than through the probe's PYTHONPATH: the probe never saw
    # them, so nothing unverified was imported to report them.
    ordered = [
        entry
        for entry in python_path
        if os.path.isabs(entry) and os.path.isdir(entry)
    ]
    ordered.extend(entry for entry in roots if entry not in ordered)
    ordered.extend(entry for entry in recovered if entry not in ordered)
    ordered.extend(
        entry
        for entry in site_entries
        if isinstance(entry, str)
        and os.path.isabs(entry)
        and os.path.isdir(entry)
        and entry not in ordered
    )
    return ordered, stdlib_names


def _locate_module_file(
    dotted: str, search_roots: list[str]
) -> str | None:
    """Locate a module file under absolute search roots (no import).

    ``a.b`` resolves to the first ``a/b.py`` or ``a/b/__init__.py``
    under the roots in order; a top-level ``a`` also accepts
    ``a/__init__.py`` (regular packages only, never namespace
    portions or zip imports).
    """
    parts = dotted.split(".")
    if not parts or not all(
        part.isidentifier() for part in parts
    ):
        return None
    for root in search_roots:
        module_path = os.path.join(root, *parts) + ".py"
        if os.path.isfile(module_path):
            return module_path
        package_init = os.path.join(root, *parts, "__init__.py")
        if os.path.isfile(package_init):
            return package_init
    return None


def _module_prefix_paths(parts: list[str]) -> list[str]:
    """Relative import paths shadowed at or above a module.

    For ``a.b.c`` the interpreter selects ``a``, then ``a.b``
    under the selected ``a``, then ``a.b.c`` under the selected
    ``a.b`` -- so a shadow of any ancestor package hijacks the
    whole subtree even when the leaf file itself is verified.
    Returns the relative paths (``a``, ``a/b``, ``a/b/c``) whose
    ``.py`` or ``__init__.py`` presence on an earlier root wins
    import selection away from the verified file.
    """
    return [
        os.path.join(*parts[: end]) for end in range(1, len(parts) + 1)
    ]


def _earlier_root_shadow(
    prefix_rel: str, earlier_roots: list[str]
) -> str | None:
    """Return the first earlier root shadowing a module path.

    Any winning sibling spelling shadows: ``stem.py``,
    ``stem/__init__.py``, sourceless ``stem.pyc`` or a
    platform-tagged ``stem.*.so``/``stem.pyd`` (the first
    path entry carrying any match wins import selection, so a
    same-name module beats a package and an extension beats
    source across roots). A bare directory without
    ``__init__.py`` is only a namespace portion and does not
    shadow a verified regular module or package, so only
    files count. Returns the shadowing root, or None.
    """
    for root in earlier_roots:
        base = os.path.join(root, prefix_rel)
        if (
            os.path.isfile(base + ".py")
            or os.path.isfile(base + ".pyc")
            or os.path.isfile(
                os.path.join(base, "__init__.py")
            )
        ):
            return root
        parent = os.path.dirname(base)
        leaf = os.path.basename(base)
        try:
            entries = os.listdir(parent)
        except OSError:
            continue
        for entry in entries:
            if (
                entry.startswith(leaf + ".")
                and entry.lower().endswith((".so", ".pyd"))
                and os.path.isfile(os.path.join(parent, entry))
            ):
                return root
    return None


def _reject_earlier_module_shadow(
    entry_path: str,
    dotted: str,
    found: str,
    roots: list[str],
) -> None:
    """Reject when an earlier root shadows a verified module.

    ``found`` is the first-hit file whose bytes were verified;
    import selection still escapes the pin when an earlier root
    in resolution order carries the module path itself (both
    spellings) or any ancestor package in either spelling,
    because the interpreter resolves each level's first hit.
    Raises :class:`AdmissionError` (``module-mismatch``) naming
    the shadow, before any probe executes.
    """
    parts = dotted.split(".")
    index = None
    for position, root in enumerate(roots):
        if found == os.path.join(
            root, *parts
        ) + ".py" or found == os.path.join(
            root, *parts, "__init__.py"
        ):
            index = position
            break
    if index is None:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "%r module %r resolved outside the admitted "
            "interpreter path" % (entry_path, dotted),
        )
    try:
        verified_root = os.path.realpath(roots[index])
    except OSError:
        verified_root = roots[index]
    earlier: list[str] = []
    for root in roots[:index]:
        try:
            current = os.path.realpath(root)
        except OSError:
            current = root
        # A symlinked alias of the verified root holds the
        # verified files themselves, not a shadow.
        if current != verified_root:
            earlier.append(root)
    for prefix_rel in _module_prefix_paths(parts):
        shadow = _earlier_root_shadow(prefix_rel, earlier)
        if shadow is not None:
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "%r module %r is shadowed by %r on earlier "
                "admitted root %r; the verified bytes would not "
                "be the imported bytes"
                % (entry_path, dotted, prefix_rel, shadow),
            )


def _reject_stdlib_shadow(
    entry_path: str,
    declared_roots: tuple[str, ...],
    stdlib_names: tuple[str, ...] | None,
) -> None:
    """Reject declared roots shadowing the admitted stdlib.

    Declared ``PYTHONPATH`` roots precede the standard library
    in resolution order, so a top-level ``X.py`` or
    ``X/__init__.py`` there wins every ``import X`` -- including
    inside the version probe -- over verified bytes. Raises
    :class:`AdmissionError` (``module-mismatch``) when any
    declared root carries a top-level module colliding with the
    admitted interpreter's own standard-library names, and when
    those names are unavailable (a shadow cannot be ruled out),
    before any probe executes. Only existing absolute roots can
    shadow, matching the merge filter.
    """
    existing = [
        root
        for root in declared_roots
        if os.path.isabs(root) and os.path.isdir(root)
    ]
    if not existing:
        return
    if stdlib_names is None:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "%r admits module roots but the interpreter "
            "predates the standard-library inventory; a "
            "standard-library shadow cannot be ruled out"
            % (entry_path,),
        )
    wanted = {name.split(".")[0] for name in stdlib_names}
    for root in existing:
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for name in entries:
            full = os.path.join(root, name)
            if name.endswith(".py"):
                top, hit = name[:-3], os.path.isfile(full)
            elif name.endswith(".pyc"):
                # A sourceless top-level ``X.pyc`` is imported
                # as ``X`` (legacy layout, no __pycache__).
                top, hit = name[:-4], os.path.isfile(full)
            elif name.lower().endswith((".so", ".pyd")):
                top = name.split(".", 1)[0]
                hit = os.path.isfile(full)
            else:
                top = name
                hit = os.path.isfile(
                    os.path.join(full, "__init__.py")
                )
            if top not in wanted or not hit:
                continue
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "%r admitted module root %r carries %r, "
                "which shadows the admitted interpreter's "
                "standard library at every spawn"
                % (entry_path, root, top),
            )


def admit_execution(
    request: ExecutionRequest,
    pins: ExecutionPins,
    *,
    probe_timeout: int = DEFAULT_PROBE_TIMEOUT,
) -> AdmittedExecution:
    """Admit the request's complete chain against the pins.

    Resolves once, captures entry/hop/image/interpreter/module
    identities, enforces every present pin, and only then -- when
    ``request.probe_version`` is set -- runs the version probe
    through the admitted chain via the same verify-then-spawn
    path as :func:`run_admitted`. Any rejection raises
    :class:`AdmissionError` before any process starts, except a
    failing version probe itself (``probe-failed``), which by
    definition runs the already-admitted chain once, and drift
    between the static checks and the probe (``spawn-refused``).
    """
    if not isinstance(request, ExecutionRequest):
        raise ValueError("admit_execution requires an ExecutionRequest")
    if not isinstance(pins, ExecutionPins):
        raise ValueError("admit_execution requires ExecutionPins")
    if not request.forms:
        raise ValueError("admit_execution requires at least one form")
    entry_path = resolve_entry(request)
    captured = capture_chain(entry_path)
    if captured.form == FORM_UNKNOWN:
        raise AdmissionError(
            REASON_LAUNCHER_UNKNOWN,
            "%r: %s" % (entry_path, captured.note),
        )
    if captured.form not in request.forms:
        raise AdmissionError(
            REASON_UNSUPPORTED_FORM,
            "%r resolves as %s, want one of %s"
            % (entry_path, captured.form, ", ".join(request.forms)),
        )
    if captured.form == FORM_EXEC_LAUNCHER:
        entry_identity = captured.hops[0]
    else:
        entry_identity = captured.image
    if (
        pins.entry_sha256 is not None
        and entry_identity.sha256 != pins.entry_sha256
    ):
        raise AdmissionError(
            REASON_HASH_MISMATCH,
            "%r entry hash %s does not match the pin"
            % (entry_path, entry_identity.sha256),
        )
    if captured.form == FORM_EXEC_LAUNCHER:
        if not pins.exec_pin_present:
            raise AdmissionError(
                REASON_EXEC_UNPINNED,
                "%r is a launcher but the lock carries no exec pin"
                % (entry_path,),
            )
        if captured.image.sha256 != pins.exec_sha256:
            raise AdmissionError(
                REASON_EXEC_MISMATCH,
                "%r exec image hash %s does not match the pin"
                % (entry_path, captured.image.sha256),
            )
    elif pins.exec_pin_present and pins.exec_sha256 is not None:
        raise AdmissionError(
            REASON_EXEC_MISMATCH,
            "%r is %s (no exec chain) but the lock pins exec %s"
            % (entry_path, captured.form, pins.exec_sha256),
        )
    interpreter_identity: FileIdentity | None = None
    if captured.interpreter is not None:
        interpreter_identity = _interpreter_identity(captured.interpreter)
        if pins.interpreter_pin_present and (
            interpreter_identity is None
            or interpreter_identity.sha256 != pins.interpreter_sha256
        ):
            raise AdmissionError(
                REASON_INTERPRETER_MISMATCH,
                "%r interpreter %r does not match the pin"
                % (entry_path, captured.interpreter),
            )
    modules: list[ModuleIdentity] = []
    if pins.modules:
        if captured.form != FORM_CONSOLE_SCRIPT:
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "%r pins %d modules but is %s, not a console script"
                % (entry_path, len(pins.modules), captured.form),
            )
        if (
            interpreter_identity is None
            or not pins.interpreter_pin_present
        ):
            raise AdmissionError(
                REASON_INTERPRETER_UNPINNED,
                "%r pins modules but no interpreter is pinned"
                % (entry_path,),
            )
        for root in pins.python_path:
            for startup in ("sitecustomize.py", "usercustomize.py"):
                if os.path.isfile(os.path.join(root, startup)):
                    raise AdmissionError(
                        REASON_MODULE_MISMATCH,
                        "%r admitted module root %r carries %s, "
                        "which the interpreter would execute at "
                        "every spawn; admitted roots must not "
                        "carry startup files"
                        % (entry_path, root, startup),
                    )
        roots, stdlib_names = _dump_interpreter_sys_path(
            interpreter_identity, pins.python_path, probe_timeout
        )
        # Import selection binds to the verified roots before
        # any probe executes: an earlier root shadowing a
        # verified module (or any ancestor package, or the
        # standard library itself) would be the imported bytes,
        # so the shadow rejects here, without a marker.
        _reject_stdlib_shadow(
            entry_path, pins.python_path, stdlib_names
        )
        for dotted, expected in pins.modules:
            found = _locate_module_file(dotted, roots)
            if found is None:
                raise AdmissionError(
                    REASON_MODULE_NOT_FOUND,
                    "%r module %r not found under the admitted "
                    "interpreter path" % (entry_path, dotted),
                )
            try:
                observed = sha256_file(found)
            except OSError as exc:
                raise AdmissionError(
                    REASON_MODULE_MISMATCH,
                    "%r module %r unreadable: %s"
                    % (entry_path, dotted, exc),
                )
            if observed != expected:
                raise AdmissionError(
                    REASON_MODULE_MISMATCH,
                    "%r module %r hash %s does not match the pin"
                    % (entry_path, dotted, observed),
                )
            _reject_earlier_module_shadow(
                entry_path, dotted, found, roots
            )
            modules.append(
                ModuleIdentity(
                    name=dotted, identity=identify_file(found)
                )
            )
    env_unset = SPAWN_ENV_UNSET
    env_set = list(PYTHON_ENV_SET)
    if pins.python_path:
        env_set.append(
            ("PYTHONPATH", os.pathsep.join(pins.python_path))
        )
    env_set_tuple = tuple(sorted(env_set))
    # The spawn uses the entry path exactly as resolved (never a
    # re-resolved bare name, never a re-computed realpath): the
    # recorded argv matches the executed argv, and the spawn-time
    # stat re-verification refuses any drift (repoint, swap)
    # between admission and spawn.
    argv_prefix = (entry_identity.path,)
    record = AdmittedExecution(
        contract=EXECUTION_CONTRACT_VERSION,
        name=request.name,
        form=captured.form,
        trust_root=request.trust_root,
        entry=captured.hops[0] if captured.hops else captured.image,
        hops=captured.hops,
        image=captured.image,
        interpreter=interpreter_identity,
        modules=tuple(modules),
        version=None,
        argv_prefix=argv_prefix,
        env_unset=env_unset,
        env_set=env_set_tuple,
        digest="",
    )
    provisional = AdmittedExecution(
        contract=record.contract,
        name=record.name,
        form=record.form,
        trust_root=record.trust_root,
        entry=record.entry,
        hops=record.hops,
        image=record.image,
        interpreter=record.interpreter,
        modules=record.modules,
        version=record.version,
        argv_prefix=record.argv_prefix,
        env_unset=record.env_unset,
        env_set=record.env_set,
        digest=_admission_digest(record),
    )
    version: str | None = None
    if request.probe_version:
        version = _run_version_probe(
            request, provisional, probe_timeout
        )
        if pins.version is not None and version != pins.version:
            raise AdmissionError(
                REASON_VERSION_MISMATCH,
                "%r version %r does not match the pin %r"
                % (entry_path, version, pins.version),
                observed=version,
            )
    final = AdmittedExecution(
        contract=record.contract,
        name=record.name,
        form=record.form,
        trust_root=record.trust_root,
        entry=record.entry,
        hops=record.hops,
        image=record.image,
        interpreter=record.interpreter,
        modules=record.modules,
        version=version,
        argv_prefix=record.argv_prefix,
        env_unset=record.env_unset,
        env_set=record.env_set,
        digest="",
    )
    return AdmittedExecution(
        contract=final.contract,
        name=final.name,
        form=final.form,
        trust_root=final.trust_root,
        entry=final.entry,
        hops=final.hops,
        image=final.image,
        interpreter=final.interpreter,
        modules=final.modules,
        version=final.version,
        argv_prefix=final.argv_prefix,
        env_unset=final.env_unset,
        env_set=final.env_set,
        digest=_admission_digest(final),
    )


def _run_version_probe(
    request: ExecutionRequest,
    provisional: AdmittedExecution,
    timeout: int,
) -> str | None:
    """Run the version probe through the verified spawn path.

    Only called after every static pin check passed. Spawns
    through :func:`popen_admitted` -- the same verify-then-spawn
    path as :func:`run_admitted` -- so a chain that drifted
    between the static checks and the probe (symlink repoint,
    rename swap) is refused instead of executed. Drift surfaces
    as ``spawn-refused`` from the re-verification, unwrapped.
    Raises :class:`AdmissionError` (``probe-failed``) when the
    admitted chain cannot report a version; ``UnicodeDecodeError``
    propagates so callers can report undecodable output distinctly.
    """
    try:
        proc = popen_admitted(
            provisional,
            tuple(request.version_argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except AdmissionError:
        raise
    except OSError as exc:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "version probe failed for %r: %s" % (request.name, exc),
        )
    capture = _CappedCapture(proc, SPOOL_LIMIT_PER_STREAM)
    if not capture.join(timeout):
        kill_child_group(proc)
        capture.join()
        try:
            capture.output()
        except UnicodeDecodeError:
            pass
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "version probe timed out after %ds for %r"
            % (timeout, request.name),
        )
    out = capture.output()
    if proc.returncode != 0:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "version probe exited %d for %r"
            % (proc.returncode, request.name),
        )
    version = first_output_line(out.stdout, out.stderr)
    if version is None:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "version probe printed nothing for %r" % (request.name,),
        )
    return version


def _identity_json(identity: FileIdentity) -> dict:
    return {
        "path": identity.path,
        "realpath": identity.realpath,
        "sha256": identity.sha256,
        "size": identity.size,
        "dev": identity.dev,
        "ino": identity.ino,
        "mtime_ns": identity.mtime_ns,
        "link_dev": identity.link_dev,
        "link_ino": identity.link_ino,
    }


def _admission_digest(record: AdmittedExecution) -> str:
    """Compute the run-local identity of an admission record."""
    document = {
        "contract": record.contract,
        "name": record.name,
        "form": record.form,
        "trust_root": record.trust_root,
        "entry": _identity_json(record.entry),
        "hops": [_identity_json(hop) for hop in record.hops],
        "image": _identity_json(record.image),
        "interpreter": (
            _identity_json(record.interpreter)
            if record.interpreter is not None
            else None
        ),
        "modules": [
            {"name": item.name, "file": _identity_json(item.identity)}
            for item in record.modules
        ],
        "version": record.version,
        "argv_prefix": list(record.argv_prefix),
        "env_unset": list(record.env_unset),
        "env_set": [list(pair) for pair in record.env_set],
    }
    canonical = json.dumps(
        document, indent=None, separators=(",", ":"), sort_keys=True
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def summarize(execution: AdmittedExecution) -> dict:
    """Return the JSON-safe attestation summary of an admission."""
    return {
        "contract": execution.contract,
        "name": execution.name,
        "form": execution.form,
        "trust_root": execution.trust_root,
        "entry": _identity_json(execution.entry),
        "hops": [_identity_json(hop) for hop in execution.hops],
        "image": _identity_json(execution.image),
        "interpreter": (
            _identity_json(execution.interpreter)
            if execution.interpreter is not None
            else None
        ),
        "modules": [
            {"name": item.name, "file": _identity_json(item.identity)}
            for item in execution.modules
        ],
        "version": execution.version,
        "argv_prefix": list(execution.argv_prefix),
        "env_unset": list(execution.env_unset),
        "env_set": [list(pair) for pair in execution.env_set],
        "digest": execution.digest,
    }


def _check_identity_live(identity: FileIdentity) -> str | None:
    """Re-check one captured file; return the drift reason or None.

    Compares the live ``(st_dev, st_ino, size, mtime_ns)`` stat
    identity (plus the symlink's own identity when the captured
    path was a link) against admission. Bytes are not re-hashed:
    this defeats path substitution, not in-place inode rewriting
    (bound to the trust root instead).
    """
    try:
        link_stat = os.lstat(identity.path)
    except OSError as exc:
        return "vanished: %s" % (exc,)
    if identity.link_dev != -1:
        if not stat.S_ISLNK(link_stat.st_mode):
            return "no longer a symlink"
        if (link_stat.st_dev, link_stat.st_ino) != (
            identity.link_dev,
            identity.link_ino,
        ):
            return "symlink replaced"
    try:
        live = os.stat(identity.path)
    except OSError as exc:
        return "target vanished: %s" % (exc,)
    if (live.st_dev, live.st_ino) != (identity.dev, identity.ino):
        return "file replaced (dev/ino changed)"
    if live.st_size != identity.size or (
        live.st_mtime_ns != identity.mtime_ns
    ):
        return "file changed (size/mtime changed)"
    try:
        if os.path.realpath(identity.path) != identity.realpath:
            return "realpath changed"
    except OSError as exc:
        return "realpath unreadable: %s" % (exc,)
    return None


def verify_spawn(execution: AdmittedExecution) -> None:
    """Re-verify every captured identity immediately before spawn.

    Raises :class:`AdmissionError` (``spawn-refused``) when any
    file drifted since admission. Called by both spawn paths; there
    is no way to spawn an :class:`AdmittedExecution` without it.
    """
    if not isinstance(execution, AdmittedExecution):
        raise ValueError("verify_spawn requires an AdmittedExecution")
    watched: list[tuple[str, FileIdentity]] = [
        ("entry", execution.entry),
    ]
    for index, hop in enumerate(execution.hops):
        if hop.realpath != execution.entry.realpath:
            watched.append(("hop-%d" % index, hop))
    if execution.image.realpath != execution.entry.realpath and all(
        hop.realpath != execution.image.realpath
        for hop in execution.hops
    ):
        watched.append(("image", execution.image))
    if execution.interpreter is not None:
        watched.append(("interpreter", execution.interpreter))
    for module in execution.modules:
        watched.append(("module-%s" % module.name, module.identity))
    for label, identity in watched:
        drift = _check_identity_live(identity)
        if drift is not None:
            raise AdmissionError(
                REASON_SPAWN_REFUSED,
                "%s %r drifted since admission: %s"
                % (label, identity.path, drift),
            )


def spawn_env(
    execution: AdmittedExecution,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the spawn environment: allowlisted ambient plus overlay.

    Sanitization order: the admission unset list first, then the
    ambient filtered to :data:`SPAWN_ENV_ALLOW` plus
    :data:`SPAWN_ENV_ALLOW_PREFIXES` (fail closed: ``USER``,
    ``TERM``, ``COLUMNS`` and per-language interpreter options
    such as ``PERL5OPT`` never pass from ambient), then the
    admission overlay, then ``extra``. Explicit extras are
    code-specified and bypass the allowlist.
    """
    if not isinstance(execution, AdmittedExecution):
        raise ValueError("spawn_env requires an AdmittedExecution")
    env = dict(os.environ)
    for name in execution.env_unset:
        env.pop(name, None)
    env = {
        name: value
        for name, value in env.items()
        if spawn_name_allowed(name)
    }
    for name, value in execution.env_set:
        env[name] = value
    if extra:
        env.update(extra)
    return env


def popen_admitted(
    execution: AdmittedExecution,
    argv_suffix: tuple[str, ...] | list[str],
    *,
    cwd: str | None = None,
    env_extra: dict[str, str] | None = None,
    **popen_kwargs,
):
    """Spawn through an admission: verify, then :class:`Popen`.

    Re-verifies every captured identity, applies the sanitized
    environment, and spawns ``argv_prefix + argv_suffix``. Extra
    keyword arguments pass through to :class:`subprocess.Popen`
    only when allowlisted (see :data:`POPN_KWARGS_ALLOW`);
    anything else raises :class:`TypeError` before any spawn.

    The exec image runs through an open descriptor, never a
    re-resolved path: after verification the image is opened
    ``O_RDONLY|O_CLOEXEC``, bound to its captured identity with
    :func:`_check_open_image` (drift refuses the spawn), and
    executed as ``/dev/fd/N`` with the descriptor inherited.
    ``argv[0]`` keeps the admitted path. The descriptor kwargs
    stay internal; callers cannot pass them. The parent closes
    its copy once :class:`Popen` returns, so spawns hold no
    descriptors. Chain scripts passed as arguments (script-data
    form) stay path-based; verification re-stats them
    immediately pre-spawn.
    """
    for name in popen_kwargs:
        if name not in POPN_KWARGS_ALLOW:
            raise TypeError(
                "popen_admitted forbids keyword argument %r" % (name,)
            )
    verify_spawn(execution)
    if execution.form == FORM_SCRIPT_DATA:
        if execution.interpreter is None:
            raise AdmissionError(
                REASON_SPAWN_REFUSED,
                "spawn refused: script-data admission lacks an interpreter",
            )
        image = execution.interpreter
    else:
        image = execution.entry
    if not execution.argv_prefix or (
        image.path != execution.argv_prefix[0]
    ):
        raise AdmissionError(
            REASON_SPAWN_REFUSED,
            "spawn refused: exec image is not the argv head",
        )
    argv = tuple(execution.argv_prefix) + tuple(argv_suffix)
    env = spawn_env(execution, env_extra)
    try:
        image_fd = os.open(image.realpath, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as exc:
        raise AdmissionError(
            REASON_SPAWN_REFUSED,
            "spawn refused: exec image unreadable: %s" % (exc,),
        )
    try:
        drift = _check_open_image(image_fd, image)
        if drift is not None:
            raise AdmissionError(
                REASON_SPAWN_REFUSED,
                "spawn refused: exec image drifted: %s" % (drift,),
            )
        try:
            spawn_fd = image_fd
            if spawn_fd <= 2:
                spawn_fd = _dup_above_stdio(image_fd)
                try:
                    os.close(image_fd)
                except OSError:
                    pass
        except OSError as exc:
            raise AdmissionError(
                REASON_SPAWN_REFUSED,
                "spawn refused: no usable image descriptor: %s" % (exc,),
            )
        image_fd = -1
        try:
            return subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=env,
                executable="/dev/fd/%d" % spawn_fd,
                pass_fds=(spawn_fd,),
                **popen_kwargs,
            )
        finally:
            try:
                os.close(spawn_fd)
            except OSError:
                pass
    finally:
        if image_fd >= 0:
            try:
                os.close(image_fd)
            except OSError:
                pass


#: Per-stream head retained from a spawned child's output.
SPOOL_LIMIT_PER_STREAM = 1 << 20

#: Read unit for spool pumps.
_SPOOL_CHUNK = 65536


@dataclass(frozen=True)
class CapturedOutput:
    """Bounded drain of a child's pipes.

    ``stdout``/``stderr`` hold the retained head per stream (with
    a truncation note appended when capped); ``truncated`` reports
    whether either stream exceeded the cap; ``marker_found``
    reports whether ``scan_marker`` appeared anywhere in the full
    streams, independently of the retained heads.
    """

    stdout: str
    stderr: str
    truncated: bool
    marker_found: bool


def _spool_note(discarded: int, label: str, limit: int) -> str:
    return (
        "...[capture truncated %d %s bytes past the %d-byte "
        "head]...\n" % (discarded, label, limit)
    )


def _cap_spooled_text(
    text: str, limit: int, label: str
) -> tuple[str, bool]:
    """Cap one collected stream to its head plus a note."""
    if len(text) <= limit:
        return text, False
    head = text[:limit]
    if head and not head.endswith("\n"):
        head += "\n"
    return head + _spool_note(len(text) - limit, label, limit), True


def cap_captured_text(
    stdout: str | None,
    stderr: str | None,
    limit_per_stream: int,
    *,
    scan_marker: str | None = None,
) -> CapturedOutput:
    """Cap already-collected streams (``communicate`` results).

    The marker scan sees the full collected text; only the
    stored heads are capped. Used where the drain itself must
    stay on ``communicate`` (a poll loop that resumes it).
    """
    stdout = stdout or ""
    stderr = stderr or ""
    capped_out, drop_out = _cap_spooled_text(
        stdout, limit_per_stream, "stdout"
    )
    capped_err, drop_err = _cap_spooled_text(
        stderr, limit_per_stream, "stderr"
    )
    found = bool(scan_marker) and (
        scan_marker in stdout or scan_marker in stderr
    )
    return CapturedOutput(
        stdout=capped_out,
        stderr=capped_err,
        truncated=drop_out or drop_err,
        marker_found=found,
    )


class _CappedCapture:
    """Threaded streaming drain of a live child, race-free.

    Reader threads start at construction, so pipes drain from
    spawn (no pipe-buffer deadlock) and the marker scan sees
    every byte while only the head is retained. :meth:`join`
    waits under a shared deadline; callers kill, then rejoin
    the SAME object (never a fresh one), so no byte is lost or
    double-read across a timeout. :meth:`output` raises the
    first recorded stream error (``UnicodeDecodeError``
    propagates like ``communicate``) and must be called after a
    successful join.
    """

    def __init__(
        self,
        proc,
        limit_per_stream: int,
        *,
        scan_marker: str | None = None,
    ) -> None:
        self._proc = proc
        self._limit = limit_per_stream
        self._marker = scan_marker or None
        self._chunks: dict[str, list[str]] = {
            "stdout": [],
            "stderr": [],
        }
        self._kept = {"stdout": 0, "stderr": 0}
        self._discarded = {"stdout": 0, "stderr": 0}
        self._errors: dict[str, BaseException | None] = {
            "stdout": None,
            "stderr": None,
        }
        self._found = {"stdout": False, "stderr": False}
        self._threads: list[threading.Thread] = []
        for label in ("stdout", "stderr"):
            stream = getattr(proc, label, None)
            if stream is None:
                continue
            thread = threading.Thread(
                target=self._pump,
                args=(stream, label),
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def _pump(self, stream, label: str) -> None:
        marker = self._marker
        carry = ""
        try:
            while True:
                data = stream.read(_SPOOL_CHUNK)
                if not data:
                    return
                if marker is not None:
                    window = carry + data
                    if marker in window:
                        self._found[label] = True
                    if len(marker) > 1:
                        carry = window[-(len(marker) - 1):]
                kept = self._kept[label]
                if kept < self._limit:
                    room = self._limit - kept
                    self._chunks[label].append(data[:room])
                    self._kept[label] = kept + len(data[:room])
                    if len(data) > room:
                        self._discarded[label] += (
                            len(data) - room
                        )
                else:
                    self._discarded[label] += len(data)
        except BaseException as exc:
            self._errors[label] = exc
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def join(self, timeout: float | None = None) -> bool:
        """Join readers and reap the child under one deadline.

        Returns False on expiry (threads keep draining; kill,
        then rejoin). True means joined and reaped. The deadline
        runs on the import-bound monotonic clock (like
        ``subprocess`` internals), never the patchable
        ``time.monotonic`` attribute. A non-positive timeout
        polls once without waiting.
        """
        if timeout is None:
            for thread in self._threads:
                thread.join()
            self._proc.wait()
            return True
        deadline = _monotonic() + timeout
        for thread in self._threads:
            remaining = deadline - _monotonic()
            thread.join(max(0.0, remaining))
            if thread.is_alive():
                return False
        remaining = deadline - _monotonic()
        try:
            self._proc.wait(timeout=max(0.0, remaining))
        except subprocess.TimeoutExpired:
            return False
        return True

    def output(self) -> CapturedOutput:
        """Collect the bounded result; raises stream errors."""
        error = self._errors["stdout"] or self._errors["stderr"]
        if error is not None:
            raise error
        heads: dict[str, str] = {}
        truncated = False
        for label in ("stdout", "stderr"):
            head = "".join(self._chunks[label])
            discarded = self._discarded[label]
            if discarded:
                truncated = True
                if head and not head.endswith("\n"):
                    head += "\n"
                head += _spool_note(
                    discarded, label, self._limit
                )
            heads[label] = head
        return CapturedOutput(
            stdout=heads["stdout"],
            stderr=heads["stderr"],
            truncated=truncated,
            marker_found=self._found["stdout"]
            or self._found["stderr"],
        )


def capture_capped(
    proc,
    limit_per_stream: int,
    *,
    scan_marker: str | None = None,
    timeout: float | None = None,
) -> CapturedOutput:
    """Drain one child with per-stream caps (one shot).

    Like ``communicate`` with ``timeout`` (raising
    :class:`subprocess.TimeoutExpired` on expiry), but the
    retained heads stay bounded while the marker scan sees the
    full streams. Callers that kill on timeout must rejoin the
    same capture object instead of calling this twice.
    """
    capture = _CappedCapture(
        proc, limit_per_stream, scan_marker=scan_marker
    )
    if not capture.join(timeout):
        raise subprocess.TimeoutExpired(
            getattr(proc, "args", None), timeout
        )
    return capture.output()


def child_pins_group(pid: int, pgid: int) -> bool:
    """True when our unreaped ``pid`` is a member of ``pgid``.

    One ``/proc`` read checks membership (the ``pgrp`` field)
    plus ownership (``ppid`` is us): zombies pin (still ours,
    and the group survives while any member does), while reaped
    or foreign pids fail (no entry, or another owner). Callers
    must pass a pid they spawned; a bare pgid proves nothing
    (pid 1 sits in group 1 and is never our child).
    """
    try:
        with open(
            "/proc/%d/stat" % pid, "r", encoding="utf-8"
        ) as handle:
            data = handle.read(4096)
    except OSError:
        return False
    try:
        fields = data[data.rindex(")") + 2:].split()
        pgrp = int(fields[2])
        ppid = int(fields[1])
    except (ValueError, IndexError):
        return False
    return pgrp == pgid and ppid == os.getpid()


def signal_child_pidfd(proc, sig=signal.SIGKILL) -> bool:
    """Signal a direct child through a pidfd, never a numeric pid.

    Opens the pidfd only while our own reaping accounts show the
    child unreaped (``returncode is None``; a zombie is still
    ours, so the open cannot grab a stranger), signals, and
    closes immediately: nothing is retained, so there is no
    close discipline and no leak surface. The open-to-signal
    window is airtight in single-threaded reaping flow (only we
    reap our children, and we do not reap between the two
    calls). Already-reaped children are a silent no-op, as are
    vanished ones; a kernel without pidfds (``ENOSYS``) falls
    back to the numeric send (Linux-first, documented). Returns
    True when the pidfd path signalled.
    """
    if proc.returncode is not None:
        return False
    pidfd_open = getattr(os, "pidfd_open", None)
    send_signal = getattr(signal, "pidfd_send_signal", None)
    if pidfd_open is None or send_signal is None:
        try:
            proc.send_signal(sig)
        except OSError:
            pass
        return False
    try:
        fd = pidfd_open(proc.pid, 0)
    except OSError as exc:
        if exc.errno == errno.ENOSYS:
            try:
                proc.send_signal(sig)
            except OSError:
                pass
        return False
    try:
        try:
            send_signal(fd, sig, None, 0)
        except OSError:
            pass
        return True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _group_has_live_members(pgid: int) -> bool:
    """True when ``pgid`` has a live (non-zombie) member process."""
    try:
        entries = os.listdir("/proc")
    except OSError:
        return False
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(
                "/proc/%s/stat" % name, "r", encoding="utf-8"
            ) as handle:
                data = handle.read(4096)
        except OSError:
            continue
        try:
            rest = data[data.rindex(")") + 2:].split()
            state = rest[0]
            member_pgid = int(rest[2])
        except (ValueError, IndexError):
            continue
        if member_pgid == pgid and state not in ("Z", "X"):
            return True
    return False


def kill_child_group(proc) -> None:
    """Kill a direct child and its group, precisely first.

    Signals the direct child through its pidfd, then sweeps the
    child's own group while the child still pins it (an unreaped
    leader, live or zombie) or while the group stays occupied
    after our reap (an occupied pgid cannot be reused, so live
    members are our orphans). A reused pgid after our orphans
    died stays a documented fork-bomb residual. Already-dead
    processes are ignored, never an error. Never reaps: callers
    reap through their normal wait paths.
    """
    signal_child_pidfd(proc)
    if child_pins_group(proc.pid, proc.pid) or _group_has_live_members(
        proc.pid
    ):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass


def run_admitted(
    execution: AdmittedExecution,
    argv_suffix: tuple[str, ...] | list[str] = (),
    cwd: str | None = None,
    timeout: int = DEFAULT_PROBE_TIMEOUT,
    *,
    stage: str = "exec",
) -> CommandRecord:
    """Run an admitted chain to completion; return its record.

    Never raises for step outcomes: timeouts and spawn failures
    become records. ``UnicodeDecodeError`` propagates (strict
    decoding) so callers can report undecodable output distinctly.
    """
    start = time.monotonic()
    argv = tuple(execution.argv_prefix) + tuple(argv_suffix)
    try:
        proc = popen_admitted(
            execution,
            tuple(argv_suffix),
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except AdmissionError as exc:
        duration = time.monotonic() - start
        note = "spawn refused: %s" % (exc,)
        return CommandRecord(
            argv=argv,
            stage=stage,
            status=STATUS_SPAWN_FAILED,
            exit_code=None,
            duration_s=duration,
            log_excerpt=note[-4000:],
        )
    except OSError as exc:
        duration = time.monotonic() - start
        note = "spawn failed: %s" % (exc,)
        return CommandRecord(
            argv=argv,
            stage=stage,
            status=STATUS_SPAWN_FAILED,
            exit_code=None,
            duration_s=duration,
            log_excerpt=note[-4000:],
        )
    capture = _CappedCapture(proc, SPOOL_LIMIT_PER_STREAM)
    if not capture.join(timeout):
        kill_child_group(proc)
        capture.join()
        out = capture.output()
        duration = time.monotonic() - start
        note = "timed out after %ds\n%s" % (timeout, out.stderr or "")
        return CommandRecord(
            argv=argv,
            stage=stage,
            status=STATUS_TIMEOUT,
            exit_code=None,
            duration_s=duration,
            log_excerpt=note[-4000:],
        )
    out = capture.output()
    duration = time.monotonic() - start
    status = STATUS_OK if proc.returncode == 0 else STATUS_FAILED
    return CommandRecord(
        argv=argv,
        stage=stage,
        status=status,
        exit_code=proc.returncode,
        duration_s=duration,
        log_excerpt=(out.stderr or "")[-4000:],
    )


def admit_script_data(
    *,
    name: str,
    interpreter_path: str,
    script_path: str,
    script_sha256: str | None,
    sibling_shas: dict[str, str] | None = None,
    sibling_names: tuple[str, ...] = (),
    trust_root: str = "",
) -> AdmittedExecution:
    """Admit a script executed as data by an already-running interpreter.

    Used for the adapter service: ``interpreter_path`` (the
    driver's own interpreter) is recorded, never pinned -- it is
    already executing this process -- while ``script_path`` bytes
    are enforced against ``script_sha256`` when given, and each
    sibling in ``sibling_names`` (resolved beside the script) is
    captured and enforced against ``sibling_shas`` when given. The
    ``argv`` prefix is ``[interpreter, script]`` (the interpreter
    through its captured path, preserving virtual-environment
    context); the environment overlay is the standard sanitized
    one. Raises :class:`AdmissionError` before anything spawns.
    """
    try:
        interpreter = identify_file(interpreter_path)
    except AdmissionError as exc:
        raise AdmissionError(
            exc.reason, "interpreter: %s" % (exc.detail,)
        )
    try:
        script = identify_file(os.path.abspath(script_path))
    except AdmissionError as exc:
        if exc.reason == REASON_NOT_FOUND:
            raise AdmissionError(
                REASON_NOT_FOUND,
                "script not found: %r" % (script_path,),
            )
        raise AdmissionError(exc.reason, exc.detail)
    if script_sha256 is not None and script.sha256 != script_sha256:
        raise AdmissionError(
            REASON_HASH_MISMATCH,
            "%r script hash %s does not match the pin"
            % (script_path, script.sha256),
        )
    modules: list[ModuleIdentity] = []
    script_dir = os.path.dirname(script.realpath)
    for sibling in sibling_names:
        candidate = os.path.join(script_dir, sibling)
        if not os.path.isfile(candidate):
            if sibling_shas is not None and sibling in sibling_shas:
                raise AdmissionError(
                    REASON_MODULE_NOT_FOUND,
                    "%r pinned sibling %r is missing beside the "
                    "service; a pinned closure with a missing "
                    "member never admits" % (script_path, sibling),
                )
            continue
        identity = identify_file(candidate)
        if (
            sibling_shas is not None
            and sibling in sibling_shas
            and identity.sha256 != sibling_shas[sibling]
        ):
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "%r sibling %r hash %s does not match the pin"
                % (script_path, sibling, identity.sha256),
            )
        modules.append(
            ModuleIdentity(name=sibling, identity=identity)
        )
    record = AdmittedExecution(
        contract=EXECUTION_CONTRACT_VERSION,
        name=name,
        form=FORM_SCRIPT_DATA,
        trust_root=trust_root,
        entry=script,
        hops=(),
        image=script,
        interpreter=interpreter,
        modules=tuple(modules),
        version=None,
        argv_prefix=(interpreter.path, script.path),
        env_unset=SPAWN_ENV_UNSET,
        env_set=tuple(sorted(PYTHON_ENV_SET)),
        digest="",
    )
    return AdmittedExecution(
        contract=record.contract,
        name=record.name,
        form=record.form,
        trust_root=record.trust_root,
        entry=record.entry,
        hops=record.hops,
        image=record.image,
        interpreter=record.interpreter,
        modules=record.modules,
        version=record.version,
        argv_prefix=record.argv_prefix,
        env_unset=record.env_unset,
        env_set=record.env_set,
        digest=_admission_digest(record),
    )


def _console_shared_pins(
    runner: dict, package_key: str
) -> tuple[str | None, bool, tuple[tuple[str, str], ...], tuple[str, ...]]:
    """Extract the interpreter/module/path pins shared by one entry.

    Both guest-runner console scripts (``vng`` and ``virtme-run``)
    share the lock's interpreter pin and admitted module path;
    each names its own package-module table through
    ``package_key``. Returns ``(interpreter_sha,
    interpreter_pinned, modules, python_path)``. Raises
    ``ValueError`` when the record is malformed.
    """
    interpreter = runner.get("interpreter")
    interpreter_sha: str | None = None
    interpreter_pinned = False
    if isinstance(interpreter, dict):
        candidate = interpreter.get("sha256")
        if isinstance(candidate, str):
            interpreter_sha = candidate
            interpreter_pinned = True
    package = runner.get(package_key)
    modules: list[tuple[str, str]] = []
    if isinstance(package, dict):
        table = package.get("modules")
        if isinstance(table, dict):
            for dotted, digest in sorted(table.items()):
                if isinstance(dotted, str) and isinstance(digest, str):
                    modules.append((dotted, digest))
    python_path = runner.get("python_path", ())
    if not isinstance(python_path, (tuple, list)) or not all(
        isinstance(entry, str) for entry in python_path
    ):
        raise ValueError("runner python_path must be a list of strings")
    return (
        interpreter_sha,
        interpreter_pinned,
        tuple(modules),
        tuple(python_path),
    )


def runner_pins(runner: dict) -> ExecutionPins:
    """Build console-script pins from a kernels-lock runner record.

    Reads the entry/exec version pins, the console-script
    interpreter pin, the package module pins and the explicitly
    admitted module path. Raises ``ValueError`` when the record
    is malformed (callers map it to their typed error).
    """
    if not isinstance(runner, dict):
        raise ValueError("runner record must be a mapping")
    interpreter_sha, interpreter_pinned, modules, python_path = (
        _console_shared_pins(runner, "package")
    )
    return ExecutionPins(
        version=runner.get("version"),
        entry_sha256=runner.get("sha256"),
        exec_sha256=runner.get("exec_sha256"),
        exec_pin_present="exec_sha256" in runner,
        interpreter_sha256=interpreter_sha,
        interpreter_pin_present=interpreter_pinned,
        modules=modules,
        python_path=python_path,
    )


VIRTME_RUN_NAME = "virtme-run"


def virtme_run_pins(runner: dict) -> tuple[str, ExecutionPins]:
    """Return the ``virtme-run`` launcher name plus its pins.

    ``vng`` invokes this exact bare name through a shell, so the
    name is fixed by the runner implementation, not the lock. The
    entry hash pin is mandatory, the implementation modules are
    mandatory and non-empty (an unpinned ``virtme.*`` table binds
    nothing), and both entries share the lock's interpreter pin
    and admitted module path. The version is record-only: the
    ``--help`` probe line varies with output width, so identity
    rests on the entry/interpreter/module hashes. Raises
    ``ValueError`` when the record is malformed or unpinned.
    """
    if not isinstance(runner, dict):
        raise ValueError("runner record must be a mapping")
    digest = runner.get("virtme_run_sha256")
    if not isinstance(digest, str):
        raise ValueError(
            "runner lacks virtme_run_sha256; re-pin the lock before "
            "qualifying guests"
        )
    interpreter_sha, interpreter_pinned, modules, python_path = (
        _console_shared_pins(runner, "virtme_package")
    )
    if not modules:
        raise ValueError(
            "runner lacks virtme_package modules; re-pin the lock "
            "before qualifying guests"
        )
    return VIRTME_RUN_NAME, ExecutionPins(
        version=None,
        entry_sha256=digest,
        exec_sha256=runner.get("virtme_run_exec_sha256"),
        exec_pin_present="virtme_run_exec_sha256" in runner,
        interpreter_sha256=interpreter_sha,
        interpreter_pin_present=interpreter_pinned,
        modules=modules,
        python_path=python_path,
    )


def qemu_pins(runner: dict) -> tuple[str, ExecutionPins]:
    """Return the runner's emulator binary name plus its pins.

    The emulator hash pin is mandatory: a lock without
    ``qemu_sha256`` cannot qualify guests. Raises ``ValueError``
    when the record is malformed or the emulator is unpinned.
    """
    if not isinstance(runner, dict):
        raise ValueError("runner record must be a mapping")
    binary = runner.get("qemu_binary") or "qemu-system-x86_64"
    digest = runner.get("qemu_sha256")
    if not isinstance(digest, str):
        raise ValueError(
            "runner lacks qemu_sha256; re-pin the lock before "
            "qualifying guests"
        )
    return binary, ExecutionPins(
        version=runner.get("qemu"),
        entry_sha256=digest,
        exec_sha256=runner.get("qemu_exec_sha256"),
        exec_pin_present="qemu_exec_sha256" in runner,
    )


def is_hex_digest(value: object) -> bool:
    """True when the value is a 64-character lowercase hex digest."""
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _module_search_root(dotted: str, realpath: str) -> str | None:
    """Recover the site root holding one admitted module (no spawn).

    Strips the module's own filename plus its package directories
    from the captured realpath. Returns None when the name and
    path do not fit the regular ``a/b.py`` / ``a/b/__init__.py``
    layout.
    """
    parts = dotted.split(".")
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    rel = os.path.join(*parts)
    if realpath.endswith(rel + ".py"):
        stripped = realpath[: -len(rel + ".py")]
    elif realpath.endswith(os.path.join(rel, "__init__.py")):
        stripped = realpath[: -len(os.path.join(rel, "__init__.py"))]
    else:
        return None
    return stripped.rstrip(os.path.sep) or os.path.sep


def _distribution_search_roots(
    execution: AdmittedExecution,
) -> list[str]:
    """Roots that may hold the admission's distribution metadata.

    The admitted ``PYTHONPATH`` roots plus the site roots derived
    from every admitted module's captured path. First-party
    modules and third-party distribution metadata ship in the
    same site root in every supported layout; a metadata file
    outside these roots fails closed (``module-not-found``),
    never resolves elsewhere.
    """
    roots: list[str] = []
    seen: set[str] = set()

    def _add(candidate: str | None) -> None:
        if (
            candidate
            and candidate not in seen
            and os.path.isabs(candidate)
            and os.path.isdir(candidate)
        ):
            seen.add(candidate)
            roots.append(candidate)

    for name, value in execution.env_set:
        if name == "PYTHONPATH":
            for entry in value.split(os.pathsep):
                _add(entry)
    for module in execution.modules:
        _add(
            _module_search_root(
                module.name, module.identity.realpath
            )
        )
    return roots


def _dist_info_candidates(name: str, version: str) -> list[str]:
    """Candidate ``.dist-info`` directory names for a dependency."""
    spellings = [
        name,
        re.sub(r"[-_.]+", "-", name).lower(),
        re.sub(r"[-_.]+", "_", name),
    ]
    candidates = []
    for spelling in spellings:
        dirname = "%s-%s.dist-info" % (spelling, version)
        if dirname not in candidates:
            candidates.append(dirname)
    return candidates


def _metadata_field(content: str, field: str) -> str | None:
    """Return one METADATA header value, or None when absent."""
    prefix = field.lower() + ":"
    for line in content.splitlines():
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return None


def _normalize_dist_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def verify_runner_distribution(
    distribution: dict | None,
    execution: AdmittedExecution,
    qemu_version: str | None,
) -> None:
    """Enforce the kernels lock's distribution bindings (no spawn).

    A missing record (legacy/test locks) enforces nothing; a
    present record is verified, never trusted descriptively. Every
    third-party runner dependency must resolve to a same-version
    ``.dist-info`` whose ``METADATA`` bytes match the pin (and
    whose ``Name``/``Version`` headers agree) and whose full
    installed content matches the ``RECORD`` chain (see
    :func:`verify_runner_dependencies`); an emulator version
    claim must equal the admitted emulator version.
    Raises ``ValueError`` when the record is malformed (callers
    map it to their typed lock error) and :class:`AdmissionError`
    (``module-not-found`` / ``module-mismatch`` /
    ``version-mismatch``) when a well-formed binding fails --
    including an all-zero placeholder digest, which is explicitly
    rejected and can never match.
    """
    if distribution is None:
        return
    if not isinstance(distribution, dict):
        raise ValueError("distribution record must be a mapping")
    verify_runner_dependencies(distribution, execution)
    verify_emulator_claim(distribution, qemu_version)


def verify_runner_dependencies(
    distribution: dict | None, execution: AdmittedExecution
) -> None:
    """Enforce the dependency content bindings (no spawn).

    A missing record (legacy/test locks) or a record without a
    ``runner`` table enforces nothing. Every
    declared dependency must resolve to a same-version
    ``.dist-info`` under the admission's search roots whose
    ``METADATA`` bytes match ``metadata_sha256`` (with agreeing
    ``Name``/``Version`` headers) and whose ``RECORD`` bytes
    match ``record_sha256``; every file the pinned ``RECORD``
    lists inside the distribution root is then re-hashed. The
    lock pin binds the manifest, the manifest binds each file,
    so substituted dependency content -- the files the runner
    actually imports -- is refused even when ``METADATA`` is
    untouched. Finally each ``RECORD``-listed import path must
    have no shadow on an earlier declared root (either sibling
    spelling, at the leaf or any ancestor package): metadata
    lookup alone does not bind import selection, so a shadow
    dependency there is refused before any probe executes.
    ``RECORD`` entries installed outside the distribution root
    (entry-point scripts under ``bin/``) are outside this
    binding. Raises ``ValueError`` when the record is malformed
    and :class:`AdmissionError` when a well-formed binding
    fails.
    """
    if distribution is None:
        return
    if not isinstance(distribution, dict):
        raise ValueError("distribution record must be a mapping")
    if "runner" not in distribution:
        return
    _verify_runner_dependencies(
        distribution["runner"], execution
    )


def verify_emulator_claim(
    distribution: dict | None, qemu_version: str | None
) -> None:
    """Enforce the emulator version claim (no spawn).

    A missing record (legacy/test locks) or a record without
    an ``emulator`` table enforces nothing; a table without a
    ``qemu_version`` claim enforces nothing. Raises
    ``ValueError`` when the record is malformed and
    :class:`AdmissionError` (``version-mismatch``) when the
    claim disagrees with the given emulator version -- the
    lock's pinned version for the pre-probe static half, the
    observed version for the post-probe half.
    """
    if distribution is None:
        return
    if not isinstance(distribution, dict):
        raise ValueError("distribution record must be a mapping")
    if "emulator" not in distribution:
        return
    _verify_emulator_distribution(
        distribution["emulator"], qemu_version
    )


def _verify_runner_dependencies(
    runner_dist: object, execution: AdmittedExecution
) -> None:
    if not isinstance(runner_dist, dict):
        raise ValueError("distribution runner record must be a mapping")
    dependencies = runner_dist.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("distribution dependencies must be a list")
    if not dependencies:
        return
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError(
                "distribution dependency must be a mapping"
            )
        name = dependency.get("name")
        version = dependency.get("version")
        digest = dependency.get("metadata_sha256")
        record_digest = dependency.get("record_sha256")
        if not isinstance(name, str) or not name:
            raise ValueError(
                "distribution dependency lacks a name string"
            )
        if not isinstance(version, str) or not version:
            raise ValueError(
                "distribution dependency %r lacks a version string"
                % (name,)
            )
        if not is_hex_digest(
            digest.lower() if isinstance(digest, str) else digest
        ):
            raise ValueError(
                "distribution dependency %r carries a malformed "
                "metadata digest" % (name,)
            )
        assert isinstance(digest, str)
        if digest.lower() == "0" * 64:
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r pins the all-zero "
                "placeholder digest" % (name,),
            )
        if not is_hex_digest(
            record_digest.lower()
            if isinstance(record_digest, str)
            else record_digest
        ):
            raise ValueError(
                "distribution dependency %r carries a malformed "
                "record digest" % (name,)
            )
        assert isinstance(record_digest, str)
        if record_digest.lower() == "0" * 64:
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r pins the all-zero "
                "placeholder record digest" % (name,),
            )
        _verify_one_dependency(
            name, version, digest.lower(), record_digest.lower(),
            _distribution_search_roots(execution),
            _declared_roots(execution),
        )


def _declared_roots(execution: AdmittedExecution) -> list[str]:
    """Admitted ``PYTHONPATH`` roots in resolution order (no spawn).

    Declared roots head runtime resolution order ahead of the
    standard library and every site directory, so a shadow of a
    verified dependency there wins import selection. Only
    absolute existing directories can shadow.
    """
    declared: list[str] = []
    seen: set[str] = set()
    for env_name, value in execution.env_set:
        if env_name != "PYTHONPATH":
            continue
        for entry in value.split(os.pathsep):
            if (
                entry
                and entry not in seen
                and os.path.isabs(entry)
                and os.path.isdir(entry)
            ):
                seen.add(entry)
                declared.append(entry)
    return declared


def _earlier_declared_roots(
    declared: list[str], dist_root: str
) -> list[str]:
    """Declared roots preceding a verified distribution (no spawn).

    Only the roots ahead of the verified ``.dist-info`` in
    resolution order can shadow its files; declared roots head
    that order, so when the distribution lives outside them
    every declared root precedes it. Compared by realpath, so a
    symlinked alias of the verified root itself marks the
    verified position instead of shadowing it.
    """
    try:
        verified = os.path.realpath(dist_root)
    except OSError:
        verified = dist_root
    earlier: list[str] = []
    for entry in declared:
        try:
            current = os.path.realpath(entry)
        except OSError:
            current = entry
        if current == verified:
            break
        earlier.append(entry)
    return earlier


def _verify_one_dependency(
    name: str, version: str, digest: str, record_digest: str,
    roots: list[str], declared: list[str],
) -> None:
    dist_info: str | None = None
    dist_root = ""
    for root in roots:
        for dirname in _dist_info_candidates(name, version):
            candidate = os.path.join(root, dirname)
            if os.path.isfile(os.path.join(candidate, "METADATA")):
                dist_info = candidate
                dist_root = root
                break
        if dist_info is not None:
            break
    if dist_info is None:
        raise AdmissionError(
            REASON_MODULE_NOT_FOUND,
            "distribution dependency %r %s has no .dist-info under "
            "the admitted roots" % (name, version),
        )
    metadata_path = os.path.join(dist_info, "METADATA")
    try:
        content = read_capped(
            metadata_path, limit=DIST_LIMIT, kind="METADATA"
        )
    except OSError as exc:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "distribution dependency %r metadata unreadable: %s"
            % (name, exc),
        )
    observed = hashlib.sha256(content).hexdigest()
    if observed != digest:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "distribution dependency %r metadata hash %s does not "
            "match the pin" % (name, observed),
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "distribution dependency %r metadata is not UTF-8: %s"
            % (name, exc),
        )
    observed_name = _metadata_field(text, "Name")
    observed_version = _metadata_field(text, "Version")
    if (
        observed_name is None
        or _normalize_dist_name(observed_name)
        != _normalize_dist_name(name)
        or observed_version != version
    ):
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "distribution dependency %r metadata names %r %r"
            % (name, observed_name, observed_version),
        )
    record_text = _verify_dependency_record(
        name, version, record_digest, dist_info, dist_root
    )
    _reject_dependency_shadow(
        name, record_text, dist_root,
        _earlier_declared_roots(declared, dist_root),
    )


def _verify_dependency_record(
    name: str, version: str, digest: str, dist_info: str, root: str
) -> str:
    """Enforce one dependency's installed-content binding (no spawn).

    The lock pin binds the ``RECORD`` manifest's bytes; the
    manifest binds every installed file's hash, so each listed
    file inside the distribution root is re-hashed. ``METADATA``
    alone cannot bind the files the runner actually imports, so
    the ``RECORD`` chain is mandatory, never optional. Entries
    installed outside the distribution root (entry-point
    scripts) are outside this binding; anything else that
    cannot be verified -- a missing manifest, an empty or
    foreign hash, a missing file -- fails closed. Returns the
    decoded ``RECORD`` text for the import-selection check.
    """
    record_path = os.path.join(dist_info, "RECORD")
    if not os.path.isfile(record_path):
        raise AdmissionError(
            REASON_MODULE_NOT_FOUND,
            "distribution dependency %r %s has no RECORD under "
            "the admitted roots" % (name, version),
        )
    try:
        content = read_capped(
            record_path, limit=DIST_LIMIT, kind="RECORD"
        )
    except OSError as exc:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "distribution dependency %r record unreadable: %s"
            % (name, exc),
        )
    observed = hashlib.sha256(content).hexdigest()
    if observed != digest:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "distribution dependency %r record hash %s does not "
            "match the pin" % (name, observed),
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdmissionError(
            REASON_MODULE_MISMATCH,
            "distribution dependency %r record is not UTF-8: %s"
            % (name, exc),
        )
    record_norm = os.path.normpath(record_path)
    root_prefix = os.path.normpath(root).rstrip(os.path.sep) + os.path.sep
    for row in csv.reader(text.splitlines()):
        if not row or not row[0] or not row[0].strip():
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r record carries an "
                "empty entry" % (name,),
            )
        rel = row[0]
        if rel.startswith("/"):
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r record carries an "
                "absolute entry %r" % (name, rel),
            )
        candidate = os.path.normpath(os.path.join(root, rel))
        if candidate != record_norm and not candidate.startswith(
            root_prefix
        ):
            # Installed outside the distribution root (an
            # entry-point script under bin/): outside this
            # binding, pinned separately when admitted.
            continue
        if candidate == record_norm:
            if len(row) > 1 and row[1].strip():
                raise AdmissionError(
                    REASON_MODULE_MISMATCH,
                    "distribution dependency %r record hashes "
                    "itself" % (name,),
                )
            continue
        field = row[1] if len(row) > 1 else ""
        if not field.strip():
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r record entry %r "
                "carries no verifiable hash" % (name, rel),
            )
        if not field.startswith("sha256="):
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r record entry %r "
                "carries a foreign hash" % (name, rel),
            )
        try:
            stream = hash_file_capped(
                candidate, limit=DIST_LIMIT, kind="distribution file"
            )
        except FileNotFoundError:
            raise AdmissionError(
                REASON_MODULE_NOT_FOUND,
                "distribution dependency %r record entry %r is "
                "missing" % (name, rel),
            )
        except OSError as exc:
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r record entry %r "
                "unreadable: %s" % (name, rel, exc),
            )
        observed_hash = (
            base64.urlsafe_b64encode(stream.digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        if not hmac.compare_digest(observed_hash, field[7:]):
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r record entry %r hash "
                "does not match the manifest" % (name, rel),
            )
    return text


def _record_import_stems(record_text: str) -> list[str]:
    """Import-path stems from a verified ``RECORD`` (no spawn).

    Only entries the interpreter can import matter: ``.py``
    sources (stemmed), sourceless ``.pyc`` outside any
    ``__pycache__`` (stemmed the same way), and extension
    modules (kept whole: the platform tag is part of the
    winning filename). Distribution metadata, ``__pycache__``
    bytecode, data files and out-of-root entries never win
    import selection and are skipped.
    """
    stems: list[str] = []
    for row in csv.reader(record_text.splitlines()):
        if not row or not row[0]:
            continue
        rel = row[0]
        if rel.startswith("/") or rel.startswith(".."):
            continue
        segments = rel.split("/")
        if not segments or segments[0].endswith(".dist-info"):
            continue
        if "__pycache__" in segments:
            continue
        lowered = rel.lower()
        if lowered.endswith(".py"):
            stems.append(rel[:-3])
        elif lowered.endswith(".pyc"):
            stems.append(rel[:-4])
        elif lowered.endswith((".so", ".pyd")):
            stems.append(rel)
    return stems


def _reject_dependency_shadow(
    name: str,
    record_text: str,
    dist_root: str,
    earlier_roots: list[str],
) -> None:
    """Bind a verified dependency's actual import selection.

    Metadata lookup alone does not bind which bytes the
    interpreter imports: an earlier declared root carrying the
    same module path (or any ancestor package) wins import
    selection over the verified distribution root. Every
    ``RECORD``-listed import path -- including each ancestor
    package, whose shadow hijacks the whole subtree -- must
    have no ``.py``/``__init__.py`` sibling on any earlier
    declared root. A top-level stem colliding with the
    standard library is likewise rejected: on a declared root
    it would shadow the real library, and on a later site root
    the real library shadows the verified file instead, so in
    neither case do verified bytes run. (The admitted
    interpreter's own inventory cannot reach this layer, so
    the driver's inventory approximates it; same-host flows
    admit the same interpreter either way.) Raises
    :class:`AdmissionError` (``module-mismatch``) naming the
    shadow, before any probe executes.
    """
    stdlib_names = set(
        getattr(sys, "stdlib_module_names", ()) or ()
    )
    for stem in _record_import_stems(record_text):
        top = stem.split("/", 1)[0]
        if top in stdlib_names:
            raise AdmissionError(
                REASON_MODULE_MISMATCH,
                "distribution dependency %r provides %r, "
                "which collides with the standard library; "
                "the verified bytes would not be the imported "
                "bytes" % (name, top),
            )
        if stem.lower().endswith((".so", ".pyd")):
            prefixes = _extension_prefix_paths(stem)
        else:
            prefixes = _module_prefix_paths(stem.split("/"))
        winners = [
            (prefix, _earlier_root_shadow(prefix, earlier_roots))
            for prefix in prefixes
        ]
        if stem.lower().endswith((".so", ".pyd")):
            # The platform-tagged filename wins as a whole.
            winners.append(
                (
                    stem,
                    next(
                        (
                            root
                            for root in earlier_roots
                            if os.path.isfile(
                                os.path.join(root, stem)
                            )
                        ),
                        None,
                    ),
                )
            )
        for prefix_rel, shadow in winners:
            if shadow is not None:
                raise AdmissionError(
                    REASON_MODULE_MISMATCH,
                    "distribution dependency %r file %r is "
                    "shadowed by %r on earlier admitted root "
                    "%r; the verified bytes would not be the "
                    "imported bytes"
                    % (name, stem, prefix_rel, shadow),
                )


def _extension_prefix_paths(stem: str) -> list[str]:
    """Shadow-sensitive plain prefixes for an extension module.

    A same-stem ``.py``/package on an earlier root wins when
    that root carries no matching extension, and an ancestor
    package shadow hijacks the subtree either way; the
    platform-tagged filename itself is compared exactly by the
    caller.
    """
    head, _, base = stem.rpartition("/")
    first = base.split(".", 1)[0]
    plain = (head + "/" + first) if head else first
    return _module_prefix_paths(plain.split("/"))


def _verify_emulator_distribution(
    emulator_dist: object, qemu_version: str | None
) -> None:
    if not isinstance(emulator_dist, dict):
        raise ValueError("distribution emulator record must be a mapping")
    claimed = emulator_dist.get("qemu_version")
    if claimed is None:
        return
    if not isinstance(claimed, str) or not claimed:
        raise ValueError(
            "distribution emulator qemu_version must be a string"
        )
    if qemu_version != claimed:
        raise AdmissionError(
            REASON_VERSION_MISMATCH,
            "distribution emulator claims %r but the emulator "
            "version is %r" % (claimed, qemu_version),
            observed=qemu_version,
        )


def build_path_farm(
    entries: dict[str, str], parent: str | None = None
) -> str:
    """Create a directory forcing name-to-target resolution.

    Each ``name`` becomes a symlink to its admitted target's
    ``realpath``. Prepending the farm to ``PATH`` makes a child
    (such as the guest runner resolving its emulator) use exactly
    the admitted binaries however it resolves them. Names must be
    bare basenames; targets must exist. The caller owns cleanup.
    """
    if not entries:
        raise ValueError("build_path_farm requires at least one entry")
    for link_name, target in entries.items():
        if (
            not link_name
            or os.path.sep in link_name
            or link_name in (".", "..")
        ):
            raise ValueError(
                "farm entry name must be a bare basename: %r"
                % (link_name,)
            )
        if not os.path.exists(target):
            raise ValueError(
                "farm target does not exist: %r" % (target,)
            )
    farm = tempfile.mkdtemp(prefix="mojobpf-farm-", dir=parent)
    try:
        for link_name, target in entries.items():
            os.symlink(
                os.path.realpath(target),
                os.path.join(farm, link_name),
            )
    except OSError:
        shutil.rmtree(farm, ignore_errors=True)
        raise
    return farm


def farm_path_prefix(farm_dir: str) -> str:
    """Return the ``PATH`` value forcing farm-first resolution."""
    return farm_dir + os.pathsep + os.environ.get("PATH", "")
