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
  other content is blank lines, comments and plain assignments;
  conditionals, command invocations and other shell logic are
  rejected, never guessed. The entry itself is executed
  (preserving ``argv[0]`` semantics) after every hop's identity is
  captured, and the same identities are re-verified at spawn.
  Launchers must be pinned: admission without an ``exec`` pin, or
  with an unresolvable chain, is rejected.
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
  ``PYTHONPATH`` shadow can never be imported. Admitted module
  roots carrying ``sitecustomize.py``/``usercustomize.py`` are
  rejected: those files would execute at every spawn.
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

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

EXECUTION_CONTRACT_VERSION = "execution-contract-v1"

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

# Bounded ``sys.path`` dump used to locate pinned modules without
# executing startup or third-party code. The probe always runs with
# ``-S`` (``site`` never initializes: no ``.pth`` execution, no
# ``sitecustomize``/``usercustomize`` import), so only ``sys``,
# ``json`` and a side-effect-free ``site.getsitepackages()`` call
# run. Virtual-environment roots (normally added by ``site``) are
# recovered deterministically by the driver from the interpreter's
# location plus the reported version, never by executing ``.pth``.
_SYS_PATH_PROBE = (
    "import json,sys\n"
    "roots=[p for p in sys.path if isinstance(p,str)]\n"
    "site_roots=[]\n"
    "try:\n"
    " import site\n"
    " site_roots=list(site.getsitepackages() or [])\n"
    "except Exception:\n"
    " pass\n"
    "print(json.dumps({'path':roots,'site':site_roots,"
    "'version_info':list(sys.version_info[:2])}))\n"
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
    target = _exec_target(text)
    exec_lines = _count_exec_lines(text)
    unsupported = _unsupported_shell_logic(text)
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
    return _capture_launcher(entry, interpreter)


def _count_exec_lines(text: str) -> int:
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "exec" or stripped.startswith("exec "):
            count += 1
    return count


# Characters that start a new shell construct inside a launcher
# line: pipelines, backgrounding, sequencing, redirections,
# subshells and command substitution. A launcher line carrying any
# of these selects its meaning through unmodeled shell semantics
# and is unsupported, never guessed.
_LAUNCHER_METACHARS = ("$(", "`", ";", "|", "&", "<", ">", "(", ")")


def _unsupported_shell_logic(text: str) -> str | None:
    """Return the first unsupported launcher line, or None.

    Scripts without an exec line run directly under their pinned
    interpreter and may carry arbitrary logic. Launcher-shaped
    scripts (at least one exec line) must be exactly blank lines,
    comments, plain assignments and exec lines with no shell
    metacharacters: anything else -- conditionals, loops, command
    invocations, ``export``/``set``, function definitions,
    pipelines -- selects the executed image through semantics
    this resolver does not model, so the script is rejected
    instead of guessed.
    """
    meaningful: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        meaningful.append(stripped)
    if not any(
        line == "exec" or line.startswith("exec ")
        for line in meaningful
    ):
        return None
    for line in meaningful:
        if line == "exec" or line.startswith("exec "):
            if any(char in line for char in _LAUNCHER_METACHARS):
                return line
            continue
        match = _ASSIGN_RE.match(line)
        if match is None:
            return line
        if any(char in match.group(2) for char in _LAUNCHER_METACHARS):
            return line
    return None


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
        unsupported = _unsupported_shell_logic(text)
        if unsupported is not None:
            return CapturedChain(
                form=FORM_UNKNOWN,
                hops=tuple(hops),
                image=hops[-1],
                interpreter=interpreter,
                note="unsupported shell logic in launcher hop %r: %r"
                % (current, unsupported[:80]),
            )
        target = _exec_target(text)
        if target is None:
            if _count_exec_lines(text) != 0:
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
            hop = identify_file(resolved)
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
) -> list[str]:
    """Ask an admitted interpreter for its module path (no startup).

    Runs under ``-S`` with the sanitized environment, so ``site``
    never initializes: no ``.pth`` file executes and no
    ``sitecustomize``/``usercustomize`` imports, from the admitted
    roots or anywhere else. Only ``sys``/``json`` plus a
    side-effect-free ``site.getsitepackages()`` call run, and
    explicitly admitted ``PYTHONPATH`` roots are still honored.
    Virtual-environment roots are recovered deterministically from
    the interpreter's location (see ``_venv_site_candidates``) and
    ordered after the reported path (admitted ``PYTHONPATH`` roots
    first) but before the ``getsitepackages()`` entries, mirroring
    runtime resolution order. Only absolute existing directories
    are returned (relative ``sys.path`` entries such as the ``-c``
    working directory never locate pins). The interpreter is
    invoked through its captured path (not the realpath) so
    virtual-environment context resolves exactly as it does for
    the admitted entry; the captured identity is re-checked
    immediately first.
    """
    drift = _check_identity_live(interpreter)
    if drift is not None:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter %r drifted before its module-path probe: %s"
            % (interpreter.path, drift),
        )
    env = dict(os.environ)
    for name in SPAWN_ENV_UNSET:
        env.pop(name, None)
    for name, value in PYTHON_ENV_SET:
        env[name] = value
    if python_path:
        env["PYTHONPATH"] = os.pathsep.join(python_path)
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
    ):
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "interpreter module-path probe was unparseable",
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
    ordered = list(roots)
    ordered.extend(entry for entry in recovered if entry not in roots)
    ordered.extend(
        entry
        for entry in site_entries
        if isinstance(entry, str)
        and os.path.isabs(entry)
        and os.path.isdir(entry)
        and entry not in ordered
    )
    return ordered


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
        roots = _dump_interpreter_sys_path(
            interpreter_identity, pins.python_path, probe_timeout
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
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.communicate()
        except UnicodeDecodeError:
            pass
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "version probe timed out after %ds for %r"
            % (timeout, request.name),
        )
    if proc.returncode != 0:
        raise AdmissionError(
            REASON_PROBE_FAILED,
            "version probe exited %d for %r"
            % (proc.returncode, request.name),
        )
    version = first_output_line(stdout, stderr)
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
    """Build the spawn environment: ambient plus the overlay.

    Stripped (see ``SPAWN_ENV_UNSET``): Python import-path and
    startup variables, the dynamic-loader injection variables
    (``LD_PRELOAD``, ``LD_LIBRARY_PATH``, ``LD_AUDIT``) and the
    shell startup-file variables (``BASH_ENV``, ``ENV``). Kept by
    design: ``PATH`` (required so nested farm-first resolution
    keeps working; callers prepend the admitted farm),
    identity/locale variables (``HOME``, ``USER``, ``LANG``,
    ``LC_*``, ``TZ``: no code execution, only identity and
    formatting), and output-shaping variables (``TERM``,
    ``COLUMNS``). Per-language option variables for interpreters
    this boundary never admits (``PERL5OPT``, ``RUBYOPT``,
    ``NODE_OPTIONS``) are out of scope; a future interpreter
    family must audit its own.
    """
    if not isinstance(execution, AdmittedExecution):
        raise ValueError("spawn_env requires an AdmittedExecution")
    env = dict(os.environ)
    for name in execution.env_unset:
        env.pop(name, None)
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
    keyword arguments pass through to :class:`subprocess.Popen`.
    """
    verify_spawn(execution)
    argv = tuple(execution.argv_prefix) + tuple(argv_suffix)
    env = spawn_env(execution, env_extra)
    return subprocess.Popen(
        list(argv), cwd=cwd, env=env, **popen_kwargs
    )


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
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            try:
                proc.kill()
            except OSError:
                pass
        stdout, stderr = proc.communicate()
        duration = time.monotonic() - start
        note = "timed out after %ds\n%s" % (timeout, stderr or "")
        return CommandRecord(
            argv=argv,
            stage=stage,
            status=STATUS_TIMEOUT,
            exit_code=None,
            duration_s=duration,
            log_excerpt=note[-4000:],
        )
    duration = time.monotonic() - start
    status = STATUS_OK if proc.returncode == 0 else STATUS_FAILED
    return CommandRecord(
        argv=argv,
        stage=stage,
        status=status,
        exit_code=proc.returncode,
        duration_s=duration,
        log_excerpt=(stderr or "")[-4000:],
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
    whose ``Name``/``Version`` headers agree), and an emulator
    version claim must equal the admitted emulator version.
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
    if "runner" in distribution:
        _verify_runner_dependencies(
            distribution["runner"], execution
        )
    if "emulator" in distribution:
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
        _verify_one_dependency(
            name, version, digest.lower(),
            _distribution_search_roots(execution),
        )


def _verify_one_dependency(
    name: str, version: str, digest: str, roots: list[str]
) -> None:
    metadata_path: str | None = None
    for root in roots:
        for dirname in _dist_info_candidates(name, version):
            candidate = os.path.join(root, dirname, "METADATA")
            if os.path.isfile(candidate):
                metadata_path = candidate
                break
        if metadata_path is not None:
            break
    if metadata_path is None:
        raise AdmissionError(
            REASON_MODULE_NOT_FOUND,
            "distribution dependency %r %s has no .dist-info under "
            "the admitted roots" % (name, version),
        )
    try:
        with open(metadata_path, "rb") as handle:
            content = handle.read()
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
            "distribution emulator claims %r but the admitted "
            "emulator reported %r" % (claimed, qemu_version),
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
