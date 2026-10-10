# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Minimal BPF load / test-run / unload harness (bpftool-driven).

Contract revision 2. Revision 1 established the flags, JSON keys, and
exit numbers below (all unchanged); revision 2 corrects two
classifications: explicit verifier evidence at load now reports
``verifier``/4 even when permission substrings appear alongside it, and
a version-probe failure reports the coherent environment triple
(stage ``setup``, classification ``environment``, exit 3).

Admission addendum (same result contract): the pin path is always
contained to an owned root (``--owned-root``, default
``/sys/fs/bpf``), always bound to the run's ownership token
(``--ownership-token``, mandatory), so the default root spans
only the owned run root, and the bpftool binary is always
admitted against its pins before it executes: ``--bpftool-sha256``
and ``--bpftool-version`` are mandatory together (the version
accompanies the byte identity; version-only pinning admits
nothing), with ``--bpftool-exec-sha256`` required exactly when
the entry is a launcher. There is no unadmitted execution path:
a missing pin or token is refused with the ``setup``/6 triple
before any execution, as are pin and admission violations.

  python3 tests/harness/bpf_test_run.py --object OBJ --expect-action N \
      [--data-in FILE] [--repeat 1] [--pin-path PATH] [--bpftool BIN] \
      [--owned-root DIR] [--ownership-token TOKEN] \
      [--bpftool-sha256 SHA] [--bpftool-exec-sha256 SHA] \
      [--bpftool-version VER] [--output FILE] [--timeout SECS]

Behavior: record the object hash, load exactly one program with
``bpftool prog load``, execute one kernel test-run
(``bpftool prog run ... repeat N``), require the return value to equal
``--expect-action`` exactly, then unpin (unload). Cleanup is attempted even
when the run step fails.

Failure layers stay distinct (exit code in parentheses):

  * ``setup`` (6): missing input file, missing bpftool binary, pin
    path outside the owned root, or bpftool/pin admission refusal.
  * ``environment`` (3): tooling/permission failure, e.g. load denied with
    "Operation not permitted" when run without the required capabilities
    and without verifier evidence.
  * ``verifier`` (4): the kernel verifier rejected the program. Explicit
    verifier evidence takes precedence over permission substrings: a
    verifier denial that surfaces as EACCES is still a verifier failure.
  * ``loader`` (5): libbpf/bpftool could not load the object for another
    reason (bad ELF, stale pin path, ...).
  * ``runtime`` (1): the test-run executed but the return value differs from
    the expectation, or the run itself errored.

Exit 0 means the observed return value matched the expectation. Exit 2 is
reserved for CLI usage errors. A JSON result is always written (to stdout,
or to ``--output``); a one-line human summary goes to stderr.

Privileged load/test-run must happen inside the approved disposable VM; this
script performs no privilege escalation itself.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

CONTRACT_VERSION = 2

EXIT_PASS = 0
EXIT_RUNTIME = 1
# EXIT 2 is reserved for CLI usage errors (argparse).
EXIT_ENVIRONMENT = 3
EXIT_VERIFIER = 4
EXIT_LOADER = 5
EXIT_SETUP = 6

DEFAULT_PIN_PATH = "/sys/fs/bpf/mojobpf_control"
DEFAULT_OWNED_ROOT = "/sys/fs/bpf"
DEFAULT_REPEAT = 1
DEFAULT_TIMEOUT = 120
CHAIN_LIMIT = 8
SCRIPT_LIMIT = 65536
# Placeholder input when the caller passes no packet: a minimum-size
# Ethernet frame of zero bytes. Packet-sensitive tests must pass --data-in.
DEFAULT_FRAME_SIZE = 60

_PERMISSION_PATTERNS = (
    "operation not permitted",
    "permission denied",
    "eacces",
    "eperm",
    "unprivileged",
    "cap_sys_admin",
    "cap_bpf",
)

_VERIFIER_PATTERNS = (
    "verifier",
    "rejected",
    "invalid opcode",
    "invalid access",
    "invalid mem access",
    "prog load log",  # libbpf framing around the kernel verifier log
    "not ok",
    "processed 0 insns",  # libbpf verifier-log trailer; no bare "processed"
    "r0 !read_ok",
    "r0 invalid",
    "unknown func",
    "invalid func",
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_VAR_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)


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


def _has_shebang(path):
    """True when the file starts with ``#!`` (or cannot be read)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return True


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


def _logical_lines(text):
    """Join physical lines the way shell token recognition does.

    Staged copy of the shared execution contract's join: a
    backslash-newline pair never ends a command (only an odd
    run of trailing backslashes continues), and an
    unterminated quote continues on the next line, while a
    quote character inside a ``#`` comment never joins,
    and a ``#`` inside quotes is literal text, never a
    comment. Joining can only add doubt, never hide a
    real exec.
    """
    joined = []
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
    logical = []
    buf = ""
    quote = None
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


def _strip_shape_comment(line):
    """Cut a ``#`` comment before exec-shape detection.

    Staged copy of the shared execution contract's cutter:
    quote- and backslash-aware, ``#`` starts a comment only
    outside quotes, at the start or after a word break or a
    command separator.
    """
    quote = None
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


def _split_segments(line):
    """Split a logical line into command segments, or None.

    Staged copy of the shared execution contract's
    splitter: unquoted, unescaped ``;``, ``&``, ``|``,
    ``(``, ``)`` split, except a ``&`` that belongs to a
    redirection operator (``>&``, ``<&``, ``&>``,
    ``&>>``), which stays with its command; quotes,
    backslash escapes, backquote spans and ``$(...)``
    spans are kept whole. None means unparseable, which
    the caller doubts, never excuses.
    """
    segments = []
    buf = []
    quote = None
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
        if char == "$" and line[index + 1:index + 2] == "(":
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
            or line[index + 1:index + 2] == ">"
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


def _split_words(segment):
    """Split a segment into words, or None on doubt.

    Staged copy of the shared execution contract's
    splitter: whitespace splits only outside quotes,
    backslash escapes, backquote spans and ``$(...)``
    spans. Unbalanced quoting or spans return None.
    """
    words = []
    buf = []
    quote = None
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
        if char == "$" and segment[index + 1:index + 2] == "(":
            buf.append("$(")
            depth += 1
            started = True
            index += 2
            continue
        if depth and char in "()":
            buf.append(char)
            if char == "(":
                depth += 1
            else:
                depth -= 1
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


def _resolve_word(word):
    """Remove quoting and escapes, or None when unresolvable.

    Staged copy of the shared execution contract's
    resolver: ``$`` and backquote open unrepresentable
    expansions (doubted, never guessed); quote removal and
    backslash unescaping otherwise match the shell.
    """
    if "$" in word or "`" in word:
        return None
    out = []
    quote = None
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


def _has_command_substitution(segment):
    """True when the segment embeds a command substitution.

    Staged copy of the shared execution contract's scan:
    ``$(...)`` and backquotes execute wherever they sit,
    so their presence is doubted, never cleared. Single
    quotes and backslash escapes never open one, and
    neither does ``$((...))`` arithmetic on its own (the
    scan still enters it, so a nested substitution still
    counts). A single quote inside double quotes is
    literal text (POSIX) and never opens single-quote
    state, so ``"'$(...)"`` still counts; backquotes
    count even inside double quotes, where they execute.
    """
    quote = None
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
            and segment[index + 1:index + 2] == "("
            and segment[index + 2:index + 3] != "("
        ):
            return True
        index += 1
    return False


def _skip_redirect_target(word, pos):
    """Advance POS past one redirection target span.

    Staged copy of the shared execution contract's
    scanner: quote- and backslash-aware, the target ends
    before the next unquoted ``<``, ``>`` or ``&`` (which
    opens the next glued redirection) or at the end of
    the word. A single quote inside double quotes is
    literal text (POSIX) and never opens single-quote
    state.
    """
    quote = None
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


def _redirect_needs_word(word):
    """Classify WORD as pure redirections, or None.

    Staged copy of the shared execution contract's
    parser: the word is a run of ``[fd]operator[target]``
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


def _redirect_skip_words(words, index):
    """Words consumed when words[index] is pure redirections.

    Staged copy of the shared execution contract's skip:
    1 when the run is self-contained, 2 when a trailing
    bare operator takes the next word as its target, and 0
    when the word is not pure redirections. A quoted or
    escaped spelling falls back to its resolved form.
    """
    for candidate in (words[index], _resolve_word(words[index])):
        if candidate is None:
            continue
        needs_word = _redirect_needs_word(candidate)
        if needs_word is None:
            continue
        return 2 if needs_word else 1
    return 0


def _command_base(word):
    """Resolve a command word, or None when unresolvable.

    Staged copy of the shared execution contract's
    resolver: a redirection operator glued to the command
    word (``exec>file``) is cut away before comparing.
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


def _eval_args_exec_shape(arg_words, depth):
    """True when resolved eval arguments could invoke ``exec``.

    Staged copy of the shared execution contract's
    check: the shell joins eval's arguments with spaces
    and parses the result as a full script, so the joined
    body re-enters the grammar line by line (multi-line
    bodies, every separator), bounded by the eval depth
    limit. Unresolvable arguments are doubted, and an
    empty body runs nothing.
    """
    if depth >= _EVAL_DEPTH_LIMIT:
        return True
    resolved_args = []
    for word in arg_words:
        arg = _resolve_word(word)
        if arg is None:
            return True
        resolved_args.append(arg)
    return any(
        _line_has_exec_shape(line, depth + 1)
        for line in _logical_lines(" ".join(resolved_args))
    )


def _wrapper_exec_shape(words, index, total, depth=0):
    """True when a wrapper segment could invoke ``exec``.

    Staged copy of the shared execution contract's
    wrapper check: ``command``/``builtin``/``time`` defer
    to their target word, skipping single-dash options,
    one ``--`` end-of-options and the redirections the
    shell applies around the target. ``time`` additionally
    skips assignment prefixes (it times a whole
    pipeline), while ``command``/``builtin`` take plain
    operands. A deferred-to ``eval`` keeps its eval-ness:
    its resolved arguments re-analyze as a full script,
    so wrapper chains never clear a pending eval.
    Wrappers nest; chains past the bound and
    unresolvable words are doubted. A ``--foo`` word is
    the target itself, and an exhausted target runs
    nothing.
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
            return _eval_args_exec_shape(words[rest + 1:], depth)
        if target not in ("command", "builtin", "time"):
            return False
        pos = rest
        kind = target
    return True


def _segment_exec_shape(segment, depth=0):
    """True when a command segment could invoke ``exec``.

    Staged copy of the shared execution contract's shape
    check: an embedded command substitution is doubted
    first; leading keywords skipped (``for``/``select``/
    ``function`` consume their name, ``case`` skips through
    ``in``); assignment prefixes recognized before the
    command word, so plain assignments keep their
    historical classification; every redirection spelling
    skipped, glued runs included. The command word
    resolves quoting and escapes: ``exec`` is an
    invocation, ``$``/backquote expansions are doubted,
    wrappers defer to their target, and ``eval``
    re-analyzes its resolved arguments as a full script
    (bounded); anything unparseable is doubted.
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
        return _eval_args_exec_shape(words[index + 1:], depth)
    return False


def _line_has_exec_shape(stripped, depth=0):
    """True when a stripped logical line could invoke ``exec``.

    Staged copy of the shared execution contract's check:
    blank lines and full-line comments cannot; anything
    else is comment-stripped, split into segments and
    checked segment by segment, with unparseable lines
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


def _is_shell_interpreter(interpreter):
    """True when exec lines follow shell tokenization rules.

    Staged copy of the shared execution contract's check:
    only a recognized shell interpreter selects its image
    through shell syntax; an absent or unparseable shebang
    (None) counts as a shell (the kernel falls back to
    running such entries as shell scripts), while every
    other interpreter keeps the historical space/tab
    ``exec`` spelling check.
    """
    if interpreter is None:
        return True
    return (
        os.path.basename(interpreter) in _SHELL_INTERPRETER_NAMES
    )


def _text_interpreter(text):
    """Return the shebang interpreter named by script text."""
    lines = text.splitlines()
    if not lines or not lines[0].startswith("#!"):
        return None
    words = lines[0][2:].strip().split()
    if not words:
        return None
    return words[0]


def _is_exec_line(stripped, shell=True):
    """True when a stripped line could invoke ``exec``.

    Staged copy of the shared execution contract's
    shell-faithful detection: separators, redirections,
    quoting, escapes, expansions and continuations are
    tokenized like the shell tokenizes them before
    deciding. Callers pass logical lines from
    :func:`_logical_lines`; shaped lines outside the exact
    launcher grammar refuse through :func:`_exec_target`.
    Non-shell scripts (``shell`` False) keep the
    historical space/tab ``exec`` spelling check instead.
    """
    if not shell:
        return stripped == "exec" or (
            stripped.startswith("exec")
            and stripped[4:5] in (" ", "\t")
        )
    return _line_has_exec_shape(stripped)


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


def _exec_word_is_literal(word):
    """True when an exec-line word carries no expansion syntax.

    Staged copy of the shared execution contract's check:
    no ``$`` and no braces.
    """
    return "$" not in word and "{" not in word and "}" not in word


def _target_word_supported(word):
    """True when an exec target word uses only documented refs.

    Staged copy of the shared execution contract's check:
    ``$`` may only open ``$NAME`` or ``${NAME}``; every
    other ``$`` form, a ``$`` inside single quotes and stray
    braces are rejected, and an unbraced ``$NAME`` followed
    by a quote is allowed only across its closing double
    quote onto a name boundary.
    """
    index = 0
    end = len(word)
    quote = None
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
                    and word[follow_at:follow_at + 1] == '"'
                ):
                    follow_at += 1
                follow = word[follow_at:follow_at + 1]
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


def _exec_line_supported(line):
    """True when an exec line matches the exact launcher grammar.

    Staged copy of the shared execution contract's screen:
    no shell metacharacters, the first word resolves to the
    ``exec`` builtin itself, the target is not a flag, a
    quoted flag or a ``VAR=...`` prefix and uses only
    documented ``$`` refs, and every argument is literal or
    exactly ``"$@"``.
    """
    if any(char in line for char in _EXEC_LINE_FORBIDDEN):
        return False
    try:
        tokens = shlex.split(line, posix=False)
    except ValueError:
        return False
    if not tokens:
        return False
    if _resolve_word(tokens[0]) != "exec":
        return False
    args = tokens[1:]
    if not args or args[0].startswith("-"):
        return False
    if args[0].replace("'", "").replace('"', "") in (
        "-c", "-l", "-a"
    ):
        return False
    if _ASSIGN_RE.match(args[0]) is not None:
        return False
    if not _target_word_supported(args[0]):
        return False
    for word in args[1:]:
        if word == '"$@"':
            continue
        if not _exec_word_is_literal(word):
            return False
    return True


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


def _assignment_value_supported(value):
    """True when an assignment value is a pure literal.

    Staged copy of the shared execution contract's
    check: no ``$``, no backquote, no backslash, no
    tilde, no braces and no shell metacharacters.
    """
    return not any(
        char in value for char in _ASSIGNMENT_VALUE_FORBIDDEN
    )


def _strip_shell_comment(line):
    """Cut a ``#`` comment that starts outside any shell word.

    Staged copy of the shared execution contract's
    cutter, used by the assignment fallback below only.
    """
    for index, char in enumerate(line):
        if char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _split_assignment(line):
    """Split a bare ``NAME=value`` line, else None.

    Staged copy of the shared execution contract's
    splitter: a bare assignment holds exactly one shell
    word (``VAR=ok /path/cmd`` is an env-prefix COMMAND,
    never an assignment); a trailing ``#`` comment does
    not make a second word.
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


def _unsupported_shell_logic(text, shell=True):
    """Return the first unsupported launcher line, or None.

    Staged copy of the shared execution contract's
    grammar screen: scripts without an exec line run
    directly under their pinned interpreter and may carry
    arbitrary logic, while launcher-shaped scripts (at
    least one exec line) must match the exact grammar --
    blank lines, comments, literal single-word
    assignments and one supported exec line -- and nothing
    else. A physical line ending in a backslash refuses
    wherever it appears, exactly as in the shared
    capture.
    """
    meaningful = []
    for line in text.splitlines():
        if line.endswith("\\"):
            # A trailing backslash continues the command in
            # the shell, but shells recognize comments
            # before joining: a comment continuation still
            # executes the next line, which the join below
            # would hide inside one comment. Continuations
            # are never guessed; they refuse here, exactly
            # as in the shared capture.
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


def _exec_target(text, shell=True):
    """Return the script's exec target, or None when not unique.

    Staged copy of the shared execution contract's
    resolution: shell lines are logical, exec-shaped lines
    screened against the exact launcher grammar (an
    ungrammatical shape is unresolvable on its own), bare
    assignments single-word with literal values (anything
    else is unresolvable on its own), only pre-exec
    assignments expanding the target. Shell flags are
    rejected by the screen, never skipped; the guards
    below stay as fail-closed redundancy. Non-shell scripts
    keep the historical physical-line resolution exactly,
    flags included.
    """
    assigns = {}
    exec_lines = []
    seen_exec = False
    lines = _logical_lines(text) if shell else text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _is_exec_line(stripped, shell):
            if shell and not _exec_line_supported(stripped):
                return None
            exec_lines.append(stripped)
            seen_exec = True
            continue
        split = _split_assignment(stripped)
        if split is not None:
            if not _assignment_value_supported(split[1]):
                # An assignment carrying expansions or
                # metacharacters selects the executed program
                # through unmodeled semantics: unresolvable,
                # never guessed.
                return None
            if not seen_exec:
                assigns[split[0]] = _unquote(split[1].strip())
            continue
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
    if not args or args[0].startswith("-"):
        return None
    if _ASSIGN_RE.match(args[0]) is not None:
        return None
    expanded = _expand_vars(args[0], assigns)
    if expanded is None:
        return None
    # An unquoted expansion undergoes word splitting and
    # pathname expansion at runtime, so a static literal
    # carrying whitespace or glob characters may name a
    # different file than the shell executes: unresolvable,
    # never guessed.
    if any(char in expanded for char in " \t\n*?["):
        return None
    return expanded


def _count_exec_lines(text, shell=True):
    """Count the script's ``exec`` lines (comments aside)."""
    count = 0
    lines = _logical_lines(text) if shell else text.splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _is_exec_line(stripped, shell):
            count += 1
    return count


def classify_exec_chain(entry):
    """Classify a launcher entry without executing it.

    Static and bounded: while the current file is a script, take its
    single ``exec`` target (``$NAME``/``${NAME}`` expanded from the
    script's own assignments only) and continue there. Returns
    ``(kind, target, note)`` where ``kind`` is ``"direct"`` (the
    entry is itself the executed image), ``"launcher"`` (``target``
    is the final image's realpath), or ``"unknown"`` (the chain
    does not resolve: unreadable, ambiguous, dangling, cyclic,
    relative, unsupported shell logic, or over the depth bound --
    ``note`` says why). Launcher-shaped scripts face the exact
    launcher grammar at every hop, exactly as in the shared
    capture. Unknown chains must be rejected, never treated as
    direct.
    """
    try:
        seen = {os.path.realpath(entry)}
    except OSError:
        return ("unknown", None, "entry is not resolvable")
    current = entry
    for _ in range(CHAIN_LIMIT):
        text = _read_script_text(current)
        if text is None:
            if current != entry and not _has_shebang(current):
                return ("launcher", current, "")
            if current == entry:
                return ("direct", None, "")
            return (
                "unknown",
                None,
                "launcher hop %r is not analyzable" % (current,),
            )
        shell = _is_shell_interpreter(_text_interpreter(text))
        unsupported = _unsupported_shell_logic(text, shell)
        if unsupported is not None:
            return (
                "unknown",
                None,
                "unsupported shell logic in launcher script %r: %r"
                % (current, unsupported[:80]),
            )
        target = _exec_target(text, shell)
        if target is None:
            if _count_exec_lines(text, shell) == 0:
                # A script with no exec line runs directly: it is
                # the chain terminus unless it is the entry itself.
                if current != entry:
                    return ("launcher", current, "")
                return ("direct", None, "")
            if _count_exec_lines(text, shell) > 1:
                return (
                    "unknown",
                    None,
                    "ambiguous exec lines in launcher entry",
                )
            return (
                "unknown",
                None,
                "unresolvable exec target in launcher entry",
            )
        if not os.path.isabs(target):
            return (
                "unknown",
                None,
                "relative exec target %r resolves against the "
                "runtime directory" % (target,),
            )
        if not os.path.isfile(target):
            return (
                "unknown",
                None,
                "dangling exec target %r" % (target,),
            )
        try:
            resolved = os.path.realpath(target)
        except OSError:
            return (
                "unknown",
                None,
                "exec target %r is not resolvable" % (target,),
            )
        if resolved in seen:
            return (
                "unknown",
                None,
                "cyclic exec chain at %r" % (resolved,),
            )
        seen.add(resolved)
        current = resolved
    return (
        "unknown",
        None,
        "exec chain exceeds the depth bound",
    )


def follow_exec_target(entry):
    """Resolve a launcher entry to the image it execs, if any.

    Static and bounded: while the current file is a script, take its
    single ``exec`` target (``$NAME``/``${NAME}`` expanded from the
    script's own assignments only) and continue there. Returns the
    final image's realpath, or None when the entry is itself the
    executed image or the chain does not resolve (unreadable,
    ambiguous, dangling, cyclic or over the depth bound).

    This is the staged copy of the shared ``exec_chain`` follower:
    the guest stage carries only this file, so the logic is mirrored
    here and pinned to parity by
    ``tests/unit/test_portability_locks.py``. Admission uses
    :func:`classify_exec_chain` instead, which distinguishes an
    unresolvable chain from a directly executed entry.
    """
    kind, target, _note = classify_exec_chain(entry)
    if kind == "launcher":
        return target
    return None


def validate_owned_pin(pin_path, owned_root, token):
    """Check the pin path against the run's owned root.

    Returns None when the pin is inside the owned root (and, when a
    token is given, inside the token directory), else a refusal note.
    Malformed inputs are refused, never normalized into shape.
    Containment is checked lexically first, then resolved: both
    paths are resolved through existing symlinks and compared
    again, so an escape through an ancestor symlink is refused.
    """
    if not owned_root or not os.path.isabs(owned_root):
        return "owned root %r is not absolute" % (owned_root,)
    if os.path.normpath(owned_root) != owned_root:
        return "owned root %r is malformed" % (owned_root,)
    if not pin_path or not os.path.isabs(pin_path):
        return "pin path %r is not absolute" % (pin_path,)
    if os.path.normpath(pin_path) != pin_path:
        return "pin path %r is malformed" % (pin_path,)
    if pin_path == owned_root:
        return "pin path %r is the owned root itself" % (pin_path,)
    try:
        common = os.path.commonpath([owned_root, pin_path])
    except ValueError:
        return "pin path %r is outside the owned root" % (pin_path,)
    if common != owned_root:
        return "pin path %r is outside the owned root" % (pin_path,)
    resolved_root = os.path.realpath(owned_root)
    resolved_pin = os.path.realpath(pin_path)
    if resolved_pin == resolved_root:
        return "pin path %r resolves to the owned root itself" % (
            pin_path,
        )
    try:
        resolved_common = os.path.commonpath(
            [resolved_root, resolved_pin]
        )
    except ValueError:
        return "pin path %r resolves outside the owned root" % (
            pin_path,
        )
    if resolved_common != resolved_root:
        return "pin path %r resolves outside the owned root" % (
            pin_path,
        )
    if token is not None:
        if (
            not token
            or token in (".", "..")
            or os.sep in token
            or (os.altsep is not None and os.altsep in token)
            or os.path.normpath(token) != token
        ):
            return "ownership token %r is malformed" % (token,)
        token_dir = os.path.join(owned_root, token)
        if pin_path != token_dir and os.path.commonpath(
            [token_dir, pin_path]
        ) != token_dir:
            return "pin path %r carries another run's ownership token" % (
                pin_path,
            )
        resolved_token_dir = os.path.realpath(token_dir)
        try:
            token_common = os.path.commonpath(
                [resolved_root, resolved_token_dir]
            )
        except ValueError:
            token_common = None
        if token_common != resolved_root:
            return "ownership token %r resolves outside the owned root" % (
                token,
            )
        if resolved_pin != resolved_token_dir and os.path.commonpath(
            [resolved_token_dir, resolved_pin]
        ) != resolved_token_dir:
            return (
                "pin path %r resolves outside the owned run's "
                "directory" % (pin_path,)
            )
    return None


def admit_bpftool(path, expected_sha256, expected_exec_sha256):
    """Admit the bpftool entry against its pins before execution.

    Returns ``(realpath, entry_sha256, exec_path, exec_sha256, note)``
    with ``note`` None on admission, else the refusal note. No
    process starts on any path through this function.
    """
    try:
        realpath = os.path.realpath(path)
        entry_sha256 = sha256_file(realpath)
    except OSError as exc:
        return (
            None,
            None,
            None,
            None,
            "cannot hash bpftool binary %s: %s" % (path, exc),
        )
    if entry_sha256 != expected_sha256:
        return (
            realpath,
            entry_sha256,
            None,
            None,
            "bpftool admission refused: entry hash %s does not match "
            "the pinned hash" % entry_sha256,
        )
    chain_kind, exec_path, chain_note = classify_exec_chain(realpath)
    if chain_kind == "unknown":
        return (
            realpath,
            entry_sha256,
            None,
            None,
            "bpftool admission refused: unresolvable launcher "
            "chain (%s)" % chain_note,
        )
    exec_sha256 = None
    if exec_path is not None:
        try:
            exec_sha256 = sha256_file(exec_path)
        except OSError as exc:
            return (
                realpath,
                entry_sha256,
                exec_path,
                None,
                "cannot hash bpftool exec image %s: %s" % (exec_path, exc),
            )
    if exec_path is not None and expected_exec_sha256 is None:
        return (
            realpath,
            entry_sha256,
            exec_path,
            exec_sha256,
            "bpftool admission refused: launcher exec chain is not "
            "pinned",
        )
    if exec_path is None and expected_exec_sha256 is not None:
        return (
            realpath,
            entry_sha256,
            None,
            None,
            "bpftool admission refused: exec chain pinned but the "
            "entry is its own image",
        )
    if exec_sha256 != expected_exec_sha256:
        return (
            realpath,
            entry_sha256,
            exec_path,
            exec_sha256,
            "bpftool admission refused: exec image hash %s does not "
            "match the pinned hash" % exec_sha256,
        )
    return (realpath, entry_sha256, exec_path, exec_sha256, None)


def run_command(argv, timeout):
    """Run argv, capturing text output. Never raises on nonzero exit."""
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "argv": list(argv),
            "exit_code": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", "replace"),
            "stderr": completed.stderr.decode("utf-8", "replace"),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": list(argv),
            "exit_code": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "timeout": True,
        }


def classify_load_failure(record):
    blob = (record.get("stdout", "") + "\n" + record.get("stderr", "")).lower()
    if record.get("timeout"):
        return "environment"
    if any(pattern in blob for pattern in _VERIFIER_PATTERNS):
        return "verifier"
    if any(pattern in blob for pattern in _PERMISSION_PATTERNS):
        return "environment"
    return "loader"


def parse_return_value(text):
    match = re.search(r"return value:\s*(\d+)", text, re.IGNORECASE)
    if match is None:
        return None
    return int(match.group(1))


def build_parser():
    parser = argparse.ArgumentParser(
        description="Load one BPF program, run one kernel test-run, unload."
    )
    parser.add_argument("--object", required=True, help="BPF ELF object to load")
    parser.add_argument(
        "--expect-action",
        required=True,
        type=int,
        help="Required exact test-run return value",
    )
    parser.add_argument(
        "--data-in",
        default=None,
        help="Packet bytes for the test-run (default: 60 zero bytes)",
    )
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT)
    parser.add_argument("--pin-path", default=DEFAULT_PIN_PATH)
    parser.add_argument("--owned-root", default=DEFAULT_OWNED_ROOT)
    parser.add_argument("--ownership-token", default=None)
    parser.add_argument("--bpftool", default="bpftool")
    parser.add_argument("--bpftool-sha256", default=None)
    parser.add_argument("--bpftool-exec-sha256", default=None)
    parser.add_argument("--bpftool-version", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    return parser


def emit(result, output_path):
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not __debug__:
        sys.stderr.write(
            "REFUSED: must not run under python -O (checks stripped)\n"
        )
        return 2
    commands = []
    result = {
        "tool": "bpf_test_run",
        "contract_version": CONTRACT_VERSION,
        "status": "fail",
        "stage": "setup",
        "classification": "setup",
        "expected_action": args.expect_action,
        "actual_action": None,
        "repeat": args.repeat,
        "pin_path": args.pin_path,
        "object": {"path": args.object, "sha256": None},
        "data_in": {"path": args.data_in, "sha256": None, "size": None},
        "bpftool": {"path": None, "version": None},
        "runtime": {"uid": os.geteuid(), "kernel_release": platform.release()},
        "commands": commands,
        "cleanup_ok": None,
        "note": None,
    }

    def fail(stage, classification, exit_code, note=None):
        result["stage"] = stage
        result["classification"] = classification
        result["note"] = note
        emit(result, args.output)
        sys.stderr.write(
            "FAIL stage=%s classification=%s expected=%s actual=%s\n"
            % (stage, classification, args.expect_action, result["actual_action"])
        )
        return exit_code

    pin_note = validate_owned_pin(
        args.pin_path, args.owned_root, args.ownership_token
    )
    if pin_note is not None:
        return fail("setup", "setup", EXIT_SETUP, pin_note)
    if args.bpftool_sha256 is None:
        return fail(
            "setup",
            "setup",
            EXIT_SETUP,
            "bpftool admission refused: --bpftool-sha256 is "
            "mandatory (no unadmitted execution path)",
        )
    if args.bpftool_version is None:
        return fail(
            "setup",
            "setup",
            EXIT_SETUP,
            "bpftool admission refused: --bpftool-version is "
            "mandatory alongside the entry pin",
        )
    if args.ownership_token is None:
        return fail(
            "setup",
            "setup",
            EXIT_SETUP,
            "run ownership refused: --ownership-token is mandatory "
            "(pins are contained to the owned run root)",
        )
    result["admission"] = {
        "bpftool_admitted": None,
        "owned_root": args.owned_root,
        "ownership_token": args.ownership_token,
    }

    if not os.path.isfile(args.object):
        return fail("setup", "setup", EXIT_SETUP, "object file not found")
    result["object"]["sha256"] = sha256_file(args.object)

    data_path = args.data_in
    generated_data = None
    try:
        if data_path is None:
            with tempfile.NamedTemporaryFile(
                prefix="bpf_test_run_", suffix=".bin", delete=False
            ) as handle:
                # The allocated name registers for cleanup before
                # the first write: a write failure must still
                # unlink the owned packet.
                generated_data = handle.name
                handle.write(b"\x00" * DEFAULT_FRAME_SIZE)
            data_path = generated_data
            result["data_in"]["path"] = (
                "generated:%d-zero-bytes" % DEFAULT_FRAME_SIZE
            )
        if not os.path.isfile(data_path):
            return fail(
                "setup", "setup", EXIT_SETUP, "data-in file not found"
            )
        result["data_in"]["sha256"] = sha256_file(data_path)
        result["data_in"]["size"] = os.path.getsize(data_path)

        bpftool_path = shutil.which(args.bpftool)
        if bpftool_path is None:
            return fail(
                "setup", "setup", EXIT_SETUP, "bpftool binary not found"
            )
        result["bpftool"]["path"] = bpftool_path
        (
            admitted_realpath,
            entry_sha256,
            exec_path,
            exec_sha256,
            admission_note,
        ) = admit_bpftool(
            bpftool_path,
            args.bpftool_sha256,
            args.bpftool_exec_sha256,
        )
        result["bpftool"]["entry_sha256"] = entry_sha256
        result["bpftool"]["exec_path"] = exec_path
        result["bpftool"]["exec_sha256"] = exec_sha256
        if admission_note is not None:
            result["admission"]["bpftool_admitted"] = False
            return fail(
                "setup", "setup", EXIT_SETUP, admission_note
            )
        result["admission"]["bpftool_admitted"] = True
        bpftool_argv0 = admitted_realpath
        result["bpftool"]["path"] = admitted_realpath
        version_record = run_command(
            [bpftool_argv0, "version"], args.timeout
        )
        commands.append(version_record)
        if version_record["exit_code"] == 0:
            first_line = version_record["stdout"].splitlines()
            result["bpftool"]["version"] = (
                first_line[0] if first_line else ""
            )
        else:
            return fail(
                "setup",
                "environment",
                EXIT_ENVIRONMENT,
                "bpftool version failed",
            )
        if result["bpftool"]["version"] != args.bpftool_version:
            return fail(
                "setup",
                "setup",
                EXIT_SETUP,
                "bpftool version %r does not match the pinned "
                "version %r"
                % (result["bpftool"]["version"], args.bpftool_version),
            )

        pin_note = validate_owned_pin(
            args.pin_path, args.owned_root, args.ownership_token
        )
        if pin_note is not None:
            return fail("setup", "setup", EXIT_SETUP, pin_note)
        load_record = run_command(
            [bpftool_argv0, "prog", "load", args.object, args.pin_path],
            args.timeout,
        )
        commands.append(load_record)
        if load_record["exit_code"] != 0:
            classification = classify_load_failure(load_record)
            exit_code = {
                "environment": EXIT_ENVIRONMENT,
                "verifier": EXIT_VERIFIER,
            }.get(classification, EXIT_LOADER)
            return fail("load", classification, exit_code)

        outcome = None
        unload_note = None
        try:
            run_record = run_command(
                [
                    bpftool_argv0,
                    "prog",
                    "run",
                    "pinned",
                    args.pin_path,
                    "data_in",
                    data_path,
                    "repeat",
                    str(args.repeat),
                ],
                args.timeout,
            )
            commands.append(run_record)
            if run_record["exit_code"] != 0:
                blob = (
                    run_record["stdout"] + "\n" + run_record["stderr"]
                ).lower()
                if run_record["timeout"] or any(
                    pattern in blob for pattern in _PERMISSION_PATTERNS
                ):
                    outcome = (
                        "run", "environment", EXIT_ENVIRONMENT, None
                    )
                else:
                    outcome = (
                        "run",
                        "runtime",
                        EXIT_RUNTIME,
                        "test-run command failed",
                    )
            else:
                actual = parse_return_value(
                    run_record["stdout"] + run_record["stderr"]
                )
                result["actual_action"] = actual
                if actual is None:
                    outcome = (
                        "run",
                        "runtime",
                        EXIT_RUNTIME,
                        "could not parse return value",
                    )
                elif actual != args.expect_action:
                    outcome = (
                        "run",
                        "runtime",
                        EXIT_RUNTIME,
                        "return value mismatch",
                    )
        finally:
            unload_pin_note = validate_owned_pin(
                args.pin_path, args.owned_root, args.ownership_token
            )
            if unload_pin_note is not None:
                unload_note = unload_pin_note
                result["cleanup_ok"] = False
            else:
                unload_record = run_command(
                    ["rm", "-f", args.pin_path], args.timeout
                )
                commands.append(unload_record)
                result["cleanup_ok"] = (
                    unload_record["exit_code"] == 0
                    and not os.path.exists(args.pin_path)
                )

        if outcome is not None:
            return fail(*outcome)

        if not result["cleanup_ok"]:
            return fail(
                "unload",
                "environment",
                EXIT_ENVIRONMENT,
                unload_note or "pin path remains",
            )
        result["status"] = "pass"
        result["stage"] = "run"
        result["classification"] = None
        emit(result, args.output)
        sys.stderr.write(
            "PASS action=%s expected=%s\n"
            % (result["actual_action"], args.expect_action)
        )
        return EXIT_PASS
    finally:
        if generated_data is not None:
            try:
                os.unlink(generated_data)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
