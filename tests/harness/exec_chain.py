# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Shared launcher ``exec``-chain resolution for the consumer suites.

Every consumer suite probes its PATH-resolved toolchain and records
each entry's hash. When an entry is a launcher script (as the
independent consumer toolchain's ``mojo`` is), the entry hash alone
identifies the launcher, not the compiler that actually runs. This
module resolves the chain statically: :func:`follow_exec_target`
returns the realpath of the image a launcher hands off to, or None
when the entry is itself the executed image or the chain does not
resolve. Suites record both hashes and cross-check the executed
image against the installed tool's own report.

Standard library only.
"""

import os
import re
import shlex

CHAIN_LIMIT = 8
SCRIPT_LIMIT = 65536

_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_VAR_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)


def follow_exec_target(entry):
    """Resolve a launcher entry to the image it execs, if any.

    Static and bounded: while the current file is a script, take its
    single ``exec`` target (``$NAME``/``${NAME}`` expanded from the
    script's own assignments only) and continue there. Returns the
    final image's realpath, or None when the entry is itself the
    executed image or the chain does not resolve (unreadable,
    ambiguous, dangling, cyclic or over the depth bound).
    """
    try:
        seen = {os.path.realpath(entry)}
    except OSError:
        return None
    current = entry
    for _ in range(CHAIN_LIMIT):
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


def _has_shebang(path):
    """True when the file starts with ``#!`` (or cannot be read)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return True


def _read_script_text(path):
    """Return the script text, or None when not a readable script."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(2)
            if head != b"#!":
                return None
            rest = handle.read(SCRIPT_LIMIT)
    except OSError:
        return None
    try:
        return (head + rest).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _exec_target(text):
    """Return the script's exec target, or None when not unique.

    Assignments after the exec line never execute (the image is
    already replaced), so only pre-exec assignments expand the
    target; exec lines are still all counted, so two execs stay
    ambiguous.
    """
    assigns = {}
    exec_lines = []
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


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _expand_vars(target, assigns):
    def _one(match):
        name = (
            match.group(1)
            if match.group(1) is not None
            else match.group(2)
        )
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
