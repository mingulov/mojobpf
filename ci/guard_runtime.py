# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Exec-allowlist guard runtime: identity, refusal, and propagation.

The guard interposes on process creation (subprocess, os.exec,
os.system, os.posix_spawn, and an audit-hook second opinion) and
admits or refuses each spawn by argv-level rules only:

- a FORBIDDEN tool name refuses even when absent;
- an owned fixture (under the fixture root, owned uid, regular
  file, #! line) runs, with shell fixtures screened for static
  forbidden tokens;
- a host tool name resolves through the spawn environment and its
  file digest must match the install-time digest recorded from the
  trusted directories;
- shells run only admitted programs (exact data, vetted templates,
  or statically checkable single commands and pipelines);
- loader and delegation variables (LD_PRELOAD, BASH_ENV, ENV, ...)
  refuse when a spawn adds or changes them; the install
  environment's own values pass;
- everything else refuses with a journal entry and PermissionError.

There is deliberately no shell-semantics engine: no expansion,
substitution, eval, arithmetic, or multicall modeling. Anything the
argv-level rules cannot admit fails closed. File digests are read
fresh on every decision; verdicts memoize on file identity
(dev/ino/size/mtime/ctime) plus PATH, cwd, and strictness, so a
changed file always re-decides.

Trust flows downhill: an explicit install samples the trusted
directories, the install PATH, and the scratch roots from the
caller's environment (CI trust: the lane's own invocation).
Propagated installs (the python prelude) inherit the parent's
install PATH, scratch roots, and runtime digest through the
rewritten argv, never from the child's environment; the prelude
verifies the published runtime copy before loading it, and
journals install failures before exiting 99.

Same-uid tampering with the journal marker, the published
runtime, or the guard's in-memory state by deliberately hostile
test code is outside the enforcement boundary: it needs explicit
circumvention code in the committed test, visible to review. The
guard's guarantee is that no accidental unadmitted execution
passes silently: every refusal raises PermissionError and
journals {event, argv, reason}.
"""
import hashlib
import json  # noqa: F401  (eager tripwire: a raising stdlib shadow breaks installation loudly, never silently)
import os
import re
import shutil
import stat
import subprocess
import sys

HOST_TOOLS = (
    'bash', 'sh', 'dash', 'env', 'true', 'false', 'sleep', 'timeout',
    'git', 'sha256sum', 'cat', 'head', 'tail', 'stat', 'readlink',
    'realpath', 'mkdir', 'mktemp', 'rm', 'cp', 'mv', 'touch', 'chmod',
    'grep', 'tr', 'cut', 'uname', 'pwd', 'printf', 'echo',
    'gzip', 'bwrap', 'ls', 'find', 'sort', 'wc', 'id', 'awk',
)
# sed and tar are deliberately absent: sed's e-flag and tar's
# --to-command execute shell, which no argv-level rule can bound,
# and no lane needs them. awk stays with a program-word rule (its
# command pipes refuse); find stays listed but refuses (its -exec
# primaries execute).

FORBIDDEN = re.compile(
    r'(?:[A-Za-z0-9_]+-)?(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+)(?:-\d+)?'
    r'|llvm-[A-Za-z0-9+.-]*|llc(?:-\d+)?|opt(?:-\d+)?'
    r'|mojo|mojobpf-lower|mojobpf-frame(?:-audit)?|mojobpf-audit-driver'
    r'|cmake|ninja|make|rustc|cargo|vng|virtme(?:-run)?|qemu[^/]*|bpftool|docker|sudo'
)

TRUSTED_DIRS = ('/usr/bin', '/bin')
SHELL_NAMES = ('sh', 'bash', 'dash')
PYTHON_RE = re.compile(r'python[\d.]*')
MAX_SEEN = 4096

_MARKER = None
_ROOT = None
_ALLOWED = {}
_PYTHON_DIGESTS = set()
_ACTIVE = False
_SEEN = {}
_ORIGINALS = {}
_SCRATCH = frozenset()
_INSTALL_ENV = {}
_RUNTIME_DIGEST = None


def active():
    return _ACTIVE


def _env_path(env):
    """Read PATH from a spawn environment, tolerating bytes keys.

    Native lookup sees the encoded entries in order and takes
    the first PATH, so duplicate string/bytes keys resolve by
    dict order, not by kind; the guard reads them the same way.
    """
    if env is None:
        return None
    try:
        items = env.items()
    except AttributeError:
        return None
    for key, value in items:
        try:
            name = os.fsdecode(key)
        except Exception:
            continue
        if name != 'PATH' or value is None:
            continue
        try:
            return os.fsdecode(value)
        except Exception:
            continue
    return None


def file_digest(path):
    """Fresh SHA-256 of path; no memo, so no stale reads."""
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _emit_json(value):
    """Serialize the journal line without the json module (shadow-safe)."""
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(_emit_json(item) for item in value) + ']'
    if isinstance(value, dict):
        return '{' + ','.join(
            _emit_json(key) + ':' + _emit_json(val) for key, val in value.items()
        ) + '}'
    text = str(value)
    out = ['"']
    for char in text:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == '\\':
            out.append('\\\\')
        elif char == '\n':
            out.append('\\n')
        elif char == '\r':
            out.append('\\r')
        elif char == '\t':
            out.append('\\t')
        elif code < 0x20:
            out.append('\\u%04x' % code)
        elif 0xD800 <= code <= 0xDFFF:
            # Lone surrogates (bytes argv via surrogateescape)
            # cannot encode as UTF-8; escape them so a refusal
            # always journals instead of raising UnicodeEncodeError.
            out.append('\\u%04x' % code)
        else:
            out.append(char)
    out.append('"')
    return ''.join(out)


def _journal(event, argv, reason, detail=None):
    """Append one journal line; journal failure never blocks refusal."""
    record = {'event': event, 'argv': [os.fsdecode(a) for a in argv], 'reason': reason}
    if detail is not None:
        record['detail'] = detail
    line = _emit_json(record) + '\n'
    try:
        with open(_MARKER, 'a', encoding='utf-8') as handle:
            handle.write(line)
    except OSError:
        pass
    return line


def refuse(argv, reason, detail=None):
    _journal('forbidden-execution', argv, reason, detail)
    raise PermissionError('guard refused %r: %s' % (os.fsdecode(argv[0]), reason))


def _resolve(name, path_value, cwd):
    """Resolve a command word the way execvp would (never shutil.which)."""
    if '/' in name:
        candidate = name if os.path.isabs(name) else os.path.join(cwd, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
        if os.path.exists(candidate):
            return os.path.realpath(candidate)
        return None
    if path_value is None:
        path_value = os.defpath
    for directory in path_value.split(os.pathsep):
        if not directory:
            # POSIX execvp treats an empty entry as the current
            # directory; skipping it would pass spawns through
            # unchecked that the kernel then resolves via cwd.
            directory = cwd
        elif not os.path.isabs(directory):
            directory = os.path.join(cwd, directory)
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    return None


def _sample_trusted(path_value=None):
    """Record install-time digests.

    Host tools resolve from the trusted directories only; the
    install PATH is never consulted for them, so install-time
    shadowing cannot admit a spoofed tool. Pythons additionally
    resolve from the install PATH: the install environment is CI
    trust (the lane's own invocation, reviewed like the workflow),
    while per-spawn PATH stays untrusted and re-verified. Any
    python still starts guarded through the argv-embedded prelude,
    so a surprising interpreter cannot escape supervision.
    Propagated installs pass the parent's install PATH
    explicitly; sampling a child's own environment would trust
    test-mutated PATH entries.
    """
    allowed = {}
    wanted = frozenset(HOST_TOOLS)
    for directory in TRUSTED_DIRS:
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            if name not in wanted and not PYTHON_RE.fullmatch(name):
                continue
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            try:
                digest = file_digest(path)
            except OSError:
                continue
            allowed.setdefault(name, set()).add(digest)
    if path_value is None:
        path_value = os.environ.get('PATH', os.defpath)
    for name in ('python', 'python3'):
        for directory in path_value.split(os.pathsep):
            if not directory:
                continue
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            try:
                allowed.setdefault(name, set()).add(file_digest(path))
            except OSError:
                continue
    try:
        own = file_digest(sys.executable)
    except OSError:
        own = None
    if own is not None:
        resolved = os.path.realpath(sys.executable)
        allowed.setdefault(os.path.basename(resolved), set()).add(own)
        allowed.setdefault('python', set()).add(own)
        allowed.setdefault('python3', set()).add(own)
    for name, digests in list(allowed.items()):
        if PYTHON_RE.fullmatch(name):
            _PYTHON_DIGESTS.update(digests)
    _PYTHON_DIGESTS.update(allowed.get('python', set()))
    _PYTHON_DIGESTS.update(allowed.get('python3', set()))
    return allowed


def _shebang(path):
    try:
        with open(path, 'rb') as handle:
            first = handle.readline(256)
    except OSError:
        return None
    if not first.startswith(b'#!'):
        return None
    try:
        text = first[2:].decode('utf-8').strip()
    except UnicodeDecodeError:
        return None
    if not text or '\x00' in text:
        return None
    return text.split()


def _snapshot_scratch():
    """Install-time scratch roots; never re-read per spawn.

    tempfile honors the calling process's TMPDIR, so reading it
    at check time would let a test widen ownership to an
    attacker directory by setting TMPDIR. The snapshot is taken
    from the trusted install environment and inherited by
    propagated installs.
    """
    import tempfile
    roots = set()
    for candidate in (tempfile.gettempdir(), '/tmp', '/var/tmp', '/dev/shm'):
        try:
            roots.add(os.path.realpath(candidate))
        except OSError:
            continue
    return frozenset(roots)


def _snapshot_install_env():
    """Denied names the install environment already carries.

    Inherited-unchanged values pass the spawn screen; the
    lane's own invocation is CI trust, like the install PATH.
    """
    snapshot = {}
    for key, value in os.environ.items():
        try:
            name = os.fsdecode(key)
            text = os.fsdecode(value)
        except Exception:
            continue
        if _denied_env_name(name):
            snapshot[name] = text
    return snapshot


def _owned_fixture(path):
    try:
        stat_result = os.stat(path)
    except OSError:
        return False
    if not stat.S_ISREG(stat_result.st_mode):
        return False
    if stat_result.st_uid != os.geteuid():
        return False
    if path.startswith(_ROOT + os.sep):
        return True
    # Private scratch outside the fixture root (mkdtemp/pytest tmp)
    # is test-owned too, but only under a real scratch root: an
    # euid-private home directory must not swallow the world.
    # Admit on reaching a private (0700-style) euid-owned
    # directory; a shared or foreign-owned ancestor refuses.
    if not any(path.startswith(root + os.sep) or path == root for root in _SCRATCH):
        return False
    euid = os.geteuid()
    node = os.path.dirname(path)
    for _ in range(64):
        if node.startswith(_ROOT + os.sep) or node == _ROOT:
            return True
        try:
            ancestor = os.stat(node)
        except OSError:
            return False
        if ancestor.st_uid != euid:
            return False
        if (ancestor.st_mode & 0o77) == 0:
            return True
        parent = os.path.dirname(node)
        if parent == node:
            return False
        node = parent
    return False


# Fixture-head vocabulary: inert host tools by name, plus mount
# (the guest-mount fragment names it; direct mount spawns never
# admit). Shells, launchers, delegators, find, and awk never
# admit as fixture heads: the fixture's runtime PATH is
# test-controlled, so names alone cannot bound them.
_SCREEN_TOOLS = frozenset([
    'true', 'false', 'sleep', 'sha256sum', 'cat', 'head', 'tail',
    'stat', 'readlink', 'realpath', 'mkdir', 'mktemp', 'rm', 'cp',
    'mv', 'touch', 'chmod', 'grep', 'tr', 'cut', 'uname', 'pwd',
    'printf', 'echo', 'gzip', 'ls', 'sort', 'wc', 'id', 'mount',
])
_SCREEN_BUILTINS = frozenset([
    'test', '[', ':', 'exit', 'return', 'shift', 'set', 'unset',
    'readonly', 'export', 'local',
])
# case/select refuse wholesale (absent here): their pattern
# words would need pattern-aware splitting, and no fixture
# uses them. `for` is absent too: its header skips whole (see
# below), not word by word. while/until/if conditions gate as
# commands.
_SCREEN_KEYWORDS = frozenset([
    'if', 'then', 'else', 'elif', 'fi', 'while', 'until',
    'do', 'done', 'esac', 'in', 'function',
    ']', '}',
])
_SCREEN_ASSIGN_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=')
_SCREEN_COMMAND_CAP = 4096
_SCREEN_SUBST_DEPTH = 8


def _screen_shell_fixture(argv, path):
    """Admit an owned shell fixture by vocabulary, or refuse.

    Two phases over the static bytes: first every executable
    construct gates ($() inners recurse with a depth cap;
    backticks, arithmetic, brace expansion, heredocs, process
    substitution, subshells, ANSI quotes, and [[ ]] refuse);
    then every command head must be a listed tool or builtin
    (assignments denied-checked, dynamic and path heads
    refused). Quoted spans are data for structure but visible
    for heads: 'cc', "cc", and \\cc all refuse. Fixture heads
    admit by name only (their runtime PATH is test-controlled,
    stub-shadowed by design), while direct spawns verify by
    digest; review of the committed fixture is the control the
    screen backs, not replaces.
    """
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(1048576 + 1)
    except OSError:
        refuse(argv, 'owned-fixture-unreadable', path)
    if len(raw) > 1048576:
        # The screen must see every executed byte; a fixture
        # larger than the read cap refuses instead of running
        # partly unexamined.
        refuse(argv, 'owned-fixture-too-large', path)
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        refuse(argv, 'owned-fixture-not-text', path)
    _screen_text(argv, text, 0)


def _screen_text(argv, text, depth):
    """Gate one shell text: strip comments, split, gate commands."""
    if depth > _SCREEN_SUBST_DEPTH:
        refuse(argv, 'owned-fixture-nesting-too-deep')
    stripped = []
    quote = None
    index = 0
    count = len(text)
    while index < count:
        char = text[index]
        if quote == "'":
            stripped.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if char == '\\' and text[index + 1:index + 2] == '\n':
            # Spliced outside single quotes (the shell's own
            # rule); inside them the backslash is literal.
            index += 2
            continue
        if char == '\\' and quote is None:
            stripped.append(text[index:index + 2])
            index += 2
            continue
        if char == '\\' and quote == '"':
            # An escaped quote must not toggle quote state,
            # or bytes after it screen under the wrong quoting.
            stripped.append(text[index:index + 2])
            index += 2
            continue
        if char == "'" and quote is None:
            quote = "'"
            stripped.append(char)
            index += 1
            continue
        if char == '"' and quote != "'":
            quote = None if quote == '"' else '"'
            stripped.append(char)
            index += 1
            continue
        if char == '#' and quote is None:
            while index < count and text[index] != '\n':
                index += 1
            continue
        stripped.append(char)
        index += 1
    commands = []
    current = []
    quote = None
    index = 0
    joined = ''.join(stripped)
    count = len(joined)
    while index < count:
        char = joined[index]
        if quote is not None:
            current.append(char)
            if char == '\\' and quote == '"':
                current.append(joined[index + 1:index + 2])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char == '\\':
            current.append(joined[index:index + 2])
            index += 2
            continue
        if char in ('"', "'"):
            quote = char
            current.append(char)
            index += 1
            continue
        if char in (';', '&', '|', '\n'):
            commands.append(''.join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    commands.append(''.join(current))
    if len(commands) > _SCREEN_COMMAND_CAP:
        refuse(argv, 'owned-fixture-too-many-commands')
    for command in commands:
        _screen_command(argv, command, depth)


def _screen_command(argv, command, depth):
    """Gate executable constructs, then the command head."""
    _screen_substitutions(argv, command, depth)
    words = []
    current = []
    quote = None
    index = 0
    count = len(command)
    while index < count:
        char = command[index]
        if quote is not None:
            if char == quote:
                quote = None
            else:
                current.append(char)
            index += 1
            continue
        if char == '\\' and index + 1 < count:
            current.append(command[index + 1])
            index += 2
            continue
        if char in ('"', "'"):
            quote = char
            index += 1
            continue
        if char in (' ', '\t', '\r', '\v', '\f'):
            if current:
                words.append(''.join(current))
                current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if current:
        words.append(''.join(current))
    at = 0
    total = len(words)
    while at < total and words[at] in ('!', '{', '}', ']'):
        at += 1
    while at < total and words[at] in _SCREEN_KEYWORDS:
        at += 1
    while at < total and _SCREEN_ASSIGN_RE.match(words[at]):
        name = words[at].partition('=')[0]
        if _denied_env_name(name):
            refuse(argv, 'owned-fixture-environment', name)
        at += 1
        while at < total and words[at] in _SCREEN_KEYWORDS:
            at += 1
    if at < total and words[at] == 'for':
        # A for header (variable, in, targets) is structure,
        # never a command; the body gates as its own commands.
        # ($() inside still gated: substitutions screen first.)
        return
    if at >= total:
        return
    head = words[at]
    if head[:1] == '$':
        refuse(argv, 'owned-fixture-dynamic-head', head)
    if head[:1] == '~':
        refuse(argv, 'owned-fixture-tilde-head', head)
    if '/' in head:
        refuse(argv, 'owned-fixture-path-head', head)
    if head[:1] in ('>', '<') or head.startswith('&>') or head.startswith('<<<'):
        refuse(argv, 'owned-fixture-leading-redirect', head)
    if head[0].isdigit() and ('>' in head or '<' in head):
        refuse(argv, 'owned-fixture-leading-redirect', head)
    if head in ('export', 'readonly', 'local'):
        for word in words[at + 1:]:
            if _SCREEN_ASSIGN_RE.match(word):
                name = word.partition('=')[0]
                if _denied_env_name(name):
                    refuse(argv, 'owned-fixture-environment', name)
        return
    if head not in _SCREEN_TOOLS and head not in _SCREEN_BUILTINS:
        refuse(argv, 'owned-fixture-command-head', head)


def _screen_substitutions(argv, command, depth):
    """Gate $() inners; refuse every other executable construct."""
    quote = None
    index = 0
    count = len(command)
    while index < count:
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            index += 1
            continue
        if char == '\\':
            index += 2
            continue
        if char == '"' and quote != "'":
            quote = None if quote == '"' else '"'
            index += 1
            continue
        if char == "'" and quote is None:
            quote = "'"
            index += 1
            continue
        if char == '`' and quote != "'":
            refuse(argv, 'owned-fixture-backtick')
        if char == '$' and quote != "'" and command[index + 1:index + 2] == '(':
            if command[index + 2:index + 3] == '(':
                refuse(argv, 'owned-fixture-arith', '$((...)')
            inner, end = _screen_paren(argv, command, index + 2)
            _screen_text(argv, inner, depth + 1)
            index = end
            continue
        if char == '$' and quote != "'" and command[index + 1:index + 2] == '{':
            refuse(argv, 'owned-fixture-brace-expansion', '${...}')
        if char == '$' and quote is None and command[index + 1:index + 2] == "'":
            refuse(argv, 'owned-fixture-ansi-quote', "$'...'")
        if char == '<' and quote is None and command[index + 1:index + 2] == '<':
            if command[index + 2:index + 3] != '<':
                refuse(argv, 'owned-fixture-heredoc', '<<')
            index += 3
            continue
        if char in ('<', '>') and quote is None:
            if command[index + 1:index + 2] == '(':
                refuse(argv, 'owned-fixture-procsub', command[index:index + 2])
        if char == '[' and quote is None and command[index + 1:index + 2] == '[':
            refuse(argv, 'owned-fixture-test-expr', '[[')
        if char == '(' and quote is None:
            refuse(argv, 'owned-fixture-subshell', '(...)')
        if char == '{' and quote is None:
            follower = command[index + 1:index + 2]
            if follower not in (' ', '\t', ';', '}'):
                refuse(argv, 'owned-fixture-brace-expansion', '{...}')
        index += 1


def _screen_paren(argv, command, start):
    """Match a $() inner; return (inner, index-after-close)."""
    inner = []
    quote = None
    depth = 1
    index = start
    count = len(command)
    while index < count:
        char = command[index]
        if quote is not None:
            inner.append(char)
            if char == '\\' and quote == '"':
                inner.append(command[index + 1:index + 2])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char == '\\':
            inner.append(command[index:index + 2])
            index += 2
            continue
        if char in ('"', "'"):
            quote = char
            inner.append(char)
            index += 1
            continue
        if char == '(':
            depth += 1
        if char == ')':
            depth -= 1
            if depth == 0:
                return ''.join(inner), index + 1
        inner.append(char)
        index += 1
    refuse(argv, 'owned-fixture-unbalanced-substitution')


def _fixture_prefix(bang, env, cwd, argv):
    """Classify a #! interpreter, returning (kind, argv-prefix).

    The interpreter must be a single digest-verified path: any
    shebang arguments refuse (no lane fixture uses them), names
    alone never classify (a spoofed name must not select the
    rules), and env(1) interposers refuse (launchers never
    admit). Python fixtures rewrite to the interpreter plus an
    injected runner; shell fixtures screen instead.
    """
    if len(bang) > 1:
        refuse(argv, 'unadmitted-shebang-arguments', ' '.join(bang[1:]))
    interp = bang[0]
    if not os.path.isabs(interp):
        # The kernel resolves a relative interposer against the
        # spawn cwd (no PATH search); digest the same bytes.
        interp = os.path.join(cwd, interp)
    try:
        digest = file_digest(interp)
    except OSError:
        refuse(argv, 'uninspectable-interpreter', interp)
    if digest in _PYTHON_DIGESTS:
        return 'python', [interp]
    key = os.path.basename(interp)
    if key in SHELL_NAMES and digest in _ALLOWED.get(key, set()):
        return 'shell', None
    refuse(argv, 'unsupported-fixture-interpreter', interp)


def _inject_script(argv, words, resolved, prefix):
    """Rewrite an owned python fixture spawn to start guarded."""
    runner = (
        _prelude()
        + 'import runpy as _gr, sys as _gs;'
        + '_gs.argv=%r;_gr.run_path(%r, run_name="__main__")'
        % (list(words), resolved)
    )
    return prefix + ['-c', runner]


def _screen_spawn_env(argv, env):
    """Refuse loader/delegation variables a spawn adds or changes.

    Names the install environment already carried with the same
    value pass (the lane's own invocation is CI trust);
    removals pass (safe direction); additions and changes
    refuse. PYTHONPATH passes: lane workers need it, the
    prelude resolves its runtime by absolute path, and a
    hostile sitecustomize it could name is deliberate committed
    code, visible to review.
    """
    try:
        items = env.items()
    except AttributeError:
        return
    for key, value in items:
        try:
            name = os.fsdecode(key)
        except Exception:
            continue
        if name == 'PYTHONPATH' or not _denied_env_name(name):
            continue
        if value is None:
            continue
        try:
            text = os.fsdecode(value)
        except Exception:
            refuse(argv, 'unadmitted-shell-environment', name)
        if _INSTALL_ENV.get(name) != text:
            refuse(argv, 'unadmitted-shell-environment', name)


def check(argv, env=None, cwd=None, executable=None):
    """Admit a spawn, returning the argv to execute, or refuse.

    Identity comes from the executed path (the `executable`
    override when given), never from argv[0] alone. Direct
    spawns admit by digest union (the explicit path is
    journaled); shells, pythons, and awk dispatch by digest to
    their kind's rules, and launchers refuse wholesale.
    Anything the guard cannot inspect refuses: an unresolvable
    slash path, an unstatable target, a non-regular target, or
    unreadable bytes. Only a slashless name the kernel itself
    must fail (ENOENT) passes through.
    """
    words = [os.fsdecode(word) for word in argv]
    identity = os.fsdecode(executable) if executable is not None else words[0]
    if cwd is None:
        cwd = os.getcwd()
    else:
        cwd = os.fsdecode(cwd)
    if env is None:
        env = os.environ
    _screen_spawn_env(argv, env)
    path_value = _env_path(env)
    base = os.path.basename(identity)
    resolved = _resolve(identity, path_value, cwd)
    if resolved is None:
        if FORBIDDEN.fullmatch(base):
            refuse(argv, 'forbidden-name')
        if '/' in identity:
            refuse(argv, 'unresolvable-path', identity)
        return argv
    try:
        st = os.stat(resolved)
    except OSError:
        if FORBIDDEN.fullmatch(base):
            refuse(argv, 'forbidden-name')
        refuse(argv, 'uninspectable-target', resolved)
    if not stat.S_ISREG(st.st_mode):
        # Non-regular targets refuse explicitly: memfds execute
        # despite failing ordinary inspection, so passing them
        # through would admit unadmitted bytes. (This also keeps
        # FIFOs and devices out of the digest reader, which
        # would block on them.)
        refuse(argv, 'uninspectable-target', resolved)
    # A `sh script` verdict also depends on the script bytes
    # (a descendant of the spawn): stat the operand so a
    # changed script re-decides instead of hitting the shell's
    # own memo entry. Other spawns carry a None leg; a leg that
    # can only force re-decision is fail-closed by construction.
    script_stat = None
    if len(words) == 2 and not words[1].startswith('-'):
        candidate = words[1] if os.path.isabs(words[1]) else os.path.join(cwd, words[1])
        try:
            script_st = os.stat(candidate)
            script_stat = (script_st.st_dev, script_st.st_ino, script_st.st_size,
                           script_st.st_mtime_ns, script_st.st_ctime_ns)
        except OSError:
            script_stat = None
    # Repeat-spawn memo, keyed by file identity: same bytes give
    # the same verdict, so only a changed file re-decides. The
    # ctime leg catches same-size/same-mtime rewrites. The PATH
    # and cwd legs matter because name resolution (and hence
    # the verdict) depends on them. The spawn environment
    # screens before the memo on every call, so it needs no leg;
    # screened fixtures re-screen whenever their bytes change,
    # because their stat identity is the memo's first leg.
    memo = (resolved, tuple(words), st.st_dev, st.st_ino, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, path_value, cwd, script_stat)
    if memo in _SEEN:
        return list(_SEEN[memo])
    bang = _shebang(resolved)
    if bang is not None:
        if not _owned_fixture(resolved):
            refuse(argv, 'unowned-script')
        # Owned fixtures are admitted by ownership, independent of
        # the name they carry (even a forbidden tool's name).
        kind, prefix = _fixture_prefix(bang, env, cwd, argv)
        if kind == 'python':
            return _remember(memo, _inject_script(argv, words, resolved, prefix))
        if kind == 'shell':
            _screen_shell_fixture(argv, resolved)
            return _remember(memo, argv)
        refuse(argv, 'unsupported-fixture-interpreter')
    if FORBIDDEN.fullmatch(base):
        refuse(argv, 'forbidden-name')
    try:
        digest = file_digest(resolved)
    except OSError:
        refuse(argv, 'uninspectable-target', resolved)
    # Direct spawns admit by digest union: the invoker names an
    # explicit path, visible in argv and the journal, so a
    # renamed copy of an admitted binary stays admitted.
    for digests in _ALLOWED.values():
        if digest in digests:
            break
    else:
        refuse(argv, 'unadmitted-identity')
    gated = _gate_shell(argv, words, cwd, digest)
    verdict = _remember(memo, gated)
    if list(gated) != words:
        # Memoize the rewritten argv to itself: the audit hook
        # re-checks the executed argv in this same process. Only
        # the exact admitted bytes hit; anything altered
        # re-decides (and a fresh rewrite at hook time refuses,
        # since the hook cannot apply it).
        rewritten = (resolved, tuple(gated), st.st_dev, st.st_ino,
                     st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                     path_value, cwd, script_stat)
        _remember(rewritten, gated)
    return verdict


def _digest_is(name, digest):
    return digest in _ALLOWED.get(name, set())


def _gate_shell(argv, words, cwd, digest):
    """Dispatch union-admitted binaries by digest.

    Content decides the kind, never spelling, so a renamed copy
    keeps its kind's rules (inject, peel, refuse). An inert tool
    sampled under its own name admits directly (correct on
    multicall boxes, where one digest serves several names; a
    trojan spelling of launcher bytes still refuses, because
    those bytes were never sampled under that name). Launchers
    (env/timeout/bwrap), delegators (git), and -exec carriers
    (find) refuse wholesale: no argv-level peel can bound what
    they run, and nothing in the guarded lane spawns them.
    """
    name = os.path.basename(words[0])
    special = (
        name in SHELL_NAMES or PYTHON_RE.fullmatch(name) is not None
        or name in ('env', 'timeout', 'bwrap', 'git', 'awk', 'find')
    )
    if not special and digest in _ALLOWED.get(name, set()):
        return argv
    if digest in _PYTHON_DIGESTS:
        return _inject_python(argv, list(words))
    if _is_shell_digest(digest):
        return _admit_script_only(argv, list(words), cwd)
    for candidate in ('env', 'timeout', 'bwrap', 'git', 'find'):
        if _digest_is(candidate, digest):
            refuse(argv, 'unadmitted-launcher', candidate)
    if _digest_is('awk', digest):
        return _awk_words(argv, list(words))
    return argv


def _admit_script_only(argv, words, cwd):
    """Admit `sh script` only; every flag and -c/-s refuses.

    The script must be an owned fixture; its bytes screen as
    shell vocabulary. Slashless names resolve against the
    spawn cwd only (no PATH fallback); that refusal is
    fail-closed, so whenever the guard admits, the screened
    bytes are the bytes the shell runs.
    """
    if len(words) != 2:
        refuse(argv, 'unadmitted-shell-form', 'want-sh-script')
    script = words[1]
    if script.startswith('-'):
        refuse(argv, 'unadmitted-shell-form', script)
    target = script if os.path.isabs(script) else os.path.join(cwd, script)
    if not os.path.isfile(target):
        refuse(argv, 'unadmitted-shell-script', script)
    real = os.path.realpath(target)
    if not _owned_fixture(real):
        refuse(argv, 'unowned-script', script)
    _screen_shell_fixture(argv, real)
    return words


def _is_shell_digest(digest):
    for shell in SHELL_NAMES:
        if digest in _ALLOWED.get(shell, set()):
            return True
    return False


# No exact-admitted -c programs: inherited values re-expand inside
# admitted arithmetic (finding 10), so exact text cannot prove a
# program's tool set. Shells run owned scripts only (screened).

# Assignment names refused when a spawn adds or changes them:
# loader and tool-delegation variables turn vetted tools into
# launchers. BASH_ENV/ENV are sourced by non-interactive shells
# before the gated program runs; GCONV_PATH loads attacker iconv
# modules into any dynamic child; __PYVENV_LAUNCHER__ can redirect
# the interpreter itself; PYTHONHOME/PYTHONUSERBASE redirect the
# child's standard library and site packages (unhooking the
# child's own guard). ENV/BASH_ENV refuse even for non-shell
# children: the peel cannot know the child kind without
# resolving it, and no lane test assigns them. Other PYTHON*
# names (bytecode, locale, debug, safety flags) cannot smuggle
# execution into an admitted spawn -- native binaries ignore
# them, python children run test-owned payloads under hooks --
# so no PYTHON prefix ships: it refused legitimate lane
# environments (PYTHONDONTWRITEBYTECODE, PYTHONNOUSERSITE).
# Perl/Ruby/Node names are likewise unprefixed: those
# interpreters never admit, so their variables are moot.
_DENIED_ENV_EXACT = frozenset([
    'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG',
    'GLIBC_TUNABLES', 'GCONV_PATH', 'PAGER', 'EDITOR', 'VISUAL', 'BROWSER',
    'GIT_PAGER', 'GIT_EDITOR', 'BASH_ENV', 'ENV', '__PYVENV_LAUNCHER__',
    'PYTHONHOME', 'PYTHONUSERBASE',
])
# BASH_FUNC_* carries exported functions: bash imports them
# before running a screened script, overriding verified
# builtins (finding 11).
_DENIED_ENV_PREFIX = ('DYLD_', 'GIT_EXTERNAL', 'BASH_FUNC_')


def _denied_env_name(name):
    if name in _DENIED_ENV_EXACT:
        return True
    return name.startswith(_DENIED_ENV_PREFIX)



_AWK_SYSTEM_RE = re.compile(r'\bsystem\b\s*\(')


def _awk_words(argv, words):
    """Admit awk with vetted flags; refuse command execution.

    Only -F and -v take operands (--source, -f, and every other
    flag refuse: no lane filter uses them). The program word
    strips double-quoted strings and /.../ literals, then any
    remaining '|' (pipe, coprocess, or getline pipe) or
    'system(' refuses. A '|' is never valid awk outside those
    literals except as a pipe, so stripping cannot hide one;
    backslash-newline splices normalize first so a split
    'system' cannot hide either. '#' refuses anywhere outside
    strings and literals (no lane filter comments): a comment
    slash would otherwise pair across lines and hide a pipe.
    """
    index = 1
    count = len(words)
    program = None
    while index < count:
        word = words[index]
        if word in ('-F', '-v'):
            index += 2
            continue
        if word.startswith('-'):
            refuse(argv, 'unsupported-awk-option', word)
        program = word
        break
    if program is None:
        refuse(argv, 'unadmitted-awk-program', 'missing-program')
    text = program.replace('\\\n', '')
    code = []
    index = 0
    count = len(text)
    while index < count:
        char = text[index]
        if char == '"':
            index += 1
            while index < count and text[index] != '"':
                if text[index] == '\\':
                    index += 1
                index += 1
            index += 1
            continue
        if char == '/':
            end = index + 1
            while end < count and text[end] != '/':
                if text[end] == '\\':
                    end += 1
                end += 1
            if end < count:
                index = end + 1
                continue
        if char == '#':
            refuse(argv, 'unadmitted-awk-program', 'comment')
        code.append(char)
        index += 1
    bare = ''.join(code)
    if '|' in bare or _AWK_SYSTEM_RE.search(bare):
        refuse(argv, 'unadmitted-awk-program', 'command-pipe')
    return words


_PRELUDE_MARKER = '# mojobpf-guard-prelude v3\n'

_PRELUDE_TEMPLATE = (
    '# mojobpf-guard-prelude v3\n'
    '_gr, _gm, _gp = %r, %r, %r\n'
    '_gx = %r\n'
    'def _gf():\n'
    '    import hashlib as _gh, importlib.util as _gu, sys as _gs\n'
    '    _gfd = open(_gr, "rb")\n'
    '    _gd = _gh.sha256(_gfd.read()).hexdigest()\n'
    '    _gfd.close()\n'
    '    if _gd != _gx[1]:\n'
    '        raise ValueError("guard runtime digest mismatch")\n'
    '    _gspec = _gu.spec_from_file_location("guard_runtime_child", _gr)\n'
    '    _gmod = _gu.module_from_spec(_gspec)\n'
    '    _gs.modules["guard_runtime_child"] = _gmod\n'
    '    _gspec.loader.exec_module(_gmod)\n'
    '    _gmod.install_guard(_gm, _gp, _gx)\n'
    'try:\n'
    '    _gf()\n'
    'except BaseException:\n'
    '    try:\n'
    '        _gj = open(_gm, "a", encoding="utf-8")\n'
    '        _gj.write(\'{"event":"guard-install-failure","argv":[],"reason":"child-install-failure"}\\n\')\n'
    '        _gj.close()\n'
    '    except OSError:\n'
    '        pass\n'
    '    raise SystemExit(99)\n'
    'del _gr, _gm, _gp, _gx, _gf\n'
)

# Flags the prelude scanner skips while looking for -c/-m/script.
_PYTHON_BOOL_SINGLE = frozenset('BbdiIEOPqRsStuvV')
_PYTHON_BOOL_LONG = frozenset([
    '--help', '--version', '-?', '--isolated', '--dev', '--disable-gil',
])


def _prelude():
    """Build the child prelude from install-time snapshots only.

    The prelude runs at check time, when the spawning test may
    have mutated its environment; baking the live environment
    would hand trust decisions to the test. Everything baked
    here was fixed at install, including the trust map itself:
    children reuse the parent's sampled digests verbatim, never
    re-resolving the install PATH against their own cwd or
    picking up files planted after sampling.
    """
    runtime = os.path.join(os.path.dirname(os.path.abspath(_MARKER)), 'guard-runtime.py')
    allowed = tuple(sorted(
        (name, tuple(sorted(digests))) for name, digests in _ALLOWED.items()
    ))
    inherit = (
        sorted(_SCRATCH),
        _RUNTIME_DIGEST,
        allowed,
        tuple(sorted(_PYTHON_DIGESTS)),
        tuple(sorted(_INSTALL_ENV.items())),
    )
    return _PRELUDE_TEMPLATE % (runtime, _MARKER, _ROOT, inherit)


def _inject_python(argv, words):
    """Rewrite a python spawn to install the guard first.

    Returns the argv to execute. Covers -c, -m, script-path, and
    stdin forms; anything else refuses (fail closed).
    """
    # A carried prelude verifies whole, never by marker line: the
    # marker alone admits a hostile payload that merely quotes it.
    carried = _prelude()
    if len(words) >= 3 and words[1] == '-c' and words[2].startswith(carried):
        return argv
    index = 1
    count = len(words)
    while index < count:
        word = words[index]
        if word in ('-W', '-X', '--check-hash-based-pycs'):
            index += 2
            continue
        if word.startswith(('-W', '-X', '--check-hash-based-pycs=')):
            index += 1
            continue
        if word in _PYTHON_BOOL_LONG:
            index += 1
            continue
        if word == '-c' and index + 1 < count:
            if words[index + 1].startswith(carried):
                return argv
            words[index + 1] = carried + words[index + 1]
            return words
        if word == '-m' and index + 1 < count:
            module = words[index + 1]
            runner = (
                carried
                + 'import runpy as _gr, sys as _gs;'
                + '_gs.argv=%r;_gr.run_module(%r, run_name="__main__")'
                % ([module] + words[index + 2:], module)
            )
            return words[:index] + ['-c', runner] + words[index + 2:]
        if word == '-':
            runner = (
                carried + 'import sys as _gs;'
                + '_gs.argv=%r;exec(_gs.stdin.read())' % (['-'] + words[index + 1:])
            )
            return words[:index] + ['-c', runner]
        if word == '--':
            index += 1
            break
        if word.startswith('-') and len(word) > 1:
            dashed = word[1:]
            if dashed and all(char in _PYTHON_BOOL_SINGLE for char in dashed):
                index += 1
                continue
            refuse(argv, 'unsupported-python-option', word)
        break
    if index < count and not words[index].startswith('-'):
        script = words[index]
        runner = (
            carried
            + 'import runpy as _gr, sys as _gs;'
            + '_gs.argv=%r;_gr.run_path(%r, run_name="__main__")'
            % (words[index:], script)
        )
        return words[:index] + ['-c', runner]
    if index >= count:
        runner = carried + 'import sys as _gs;exec(_gs.stdin.read())'
        return words + ['-c', runner]
    refuse(argv, 'unsupported-python-form')


def _remember(memo, result):
    if len(_SEEN) >= MAX_SEEN:
        _SEEN.clear()
    _SEEN[memo] = list(result)
    return result


def _guarded_init(self, args, **kwargs):
    executable = kwargs.get('executable')
    env = kwargs.get('env')
    cwd = kwargs.get('cwd')
    if kwargs.get('shell'):
        # Mirror CPython's shell join ([sh, -c] + args, with the
        # executable override replacing sh) so the checked argv is
        # the executed argv; shell=False below stops CPython from
        # joining a second time. A sequence with shell=True joins
        # the same way: checking it as a direct spawn would pass
        # through a command the shell then parses.
        if isinstance(args, (str, bytes, bytearray)):
            seq = ['/bin/sh', '-c', os.fsdecode(args)]
        else:
            seq = ['/bin/sh', '-c'] + [os.fsdecode(word) for word in args]
        if executable is not None:
            seq = [os.fsdecode(executable)] + seq[1:]
        kwargs['shell'] = False
    elif isinstance(args, (str, bytes, bytearray, os.PathLike)):
        seq = [os.fsdecode(args)]
    else:
        seq = [os.fsdecode(word) for word in args]
    if kwargs.get('preexec_fn') is not None:
        # The callback runs after both checks but before exec,
        # so it could replace the verified bytes unchecked. No
        # lane spawn uses one.
        refuse(seq, 'unadmitted-preexec-fn')
    checked = check(seq, env=env, cwd=cwd, executable=executable)
    if executable is not None and checked[0] != seq[0]:
        # A rewrite changed the executed program (fixture
        # interposer): the override must track the rewrite, or
        # the kernel runs the original bytes. In-place
        # injections (python prelude) keep the override.
        kwargs['executable'] = checked[0]
    return _ORIGINALS['popen'](self, checked, **kwargs)


def _guarded_system(command):
    # system() always refuses: it runs sh -c, and shells run
    # owned scripts only. Return-value mapping matches
    # system(): exit N -> N << 8, signal S -> S. (Unlike
    # system(), SIGINT/SIGQUIT stay unignored in the waiter; no
    # lane test depends on that.)
    seq = check(['/bin/sh', '-c', os.fsdecode(command)])
    proc = subprocess.Popen.__new__(subprocess.Popen)
    _ORIGINALS['popen'](proc, seq)
    status = proc.wait()
    return status << 8 if status >= 0 else -status


def _guarded_exec(kind):
    def _run(path, *args, **kwargs):
        if kind in ('execv', 'execve', 'execvp', 'posix_spawn', 'posix_spawnp'):
            seq = [os.fsdecode(word) for word in args[0]]
            if kind in ('execve', 'posix_spawn', 'posix_spawnp'):
                env = args[1]
            else:
                env = None
        elif kind == 'execvpe':
            seq = [os.fsdecode(word) for word in args[0]]
            env = args[1]
        elif kind == 'execle':
            seq = [os.fsdecode(word) for word in args[:-1]]
            env = args[-1]
        else:
            seq = [os.fsdecode(word) for word in args]
            env = None
        target = os.fsdecode(path)
        head = seq[0] if seq else None
        seq = check(seq, env=env, executable=target)
        if seq and seq[0] != head:
            # Like the Popen wrapper: a rewrite changed the
            # executed program, so the path tracks it.
            path = seq[0]
        func = _ORIGINALS[kind]
        if kind == 'execve':
            return func(path, seq, env if env is not None else os.environ)
        if kind in ('posix_spawn', 'posix_spawnp'):
            return func(path, seq, env if env is not None else os.environ, **kwargs)
        if kind in ('execv', 'execvp'):
            return func(path, seq)
        if kind == 'execvpe':
            return func(path, seq, env)
        if kind == 'execle':
            return func(path, *seq, env)
        return func(path, *seq)
    return _run


def _audit_hook(event, args):
    # Second opinion: re-verify identity after the wrapper allowed
    # the spawn, closing the check-to-exec window. Allowed spawns
    # re-verify silently; only a changed file can refuse here, and
    # that refusal is the first journal entry for the attempt.
    if event != 'subprocess.Popen' or not _ACTIVE:
        return
    try:
        executable, argv, cwd, env = args[0], args[1], args[2], args[3]
    except (IndexError, TypeError):
        return
    if executable is None or not argv:
        return
    try:
        seq = [os.fsdecode(word) for word in argv]
        target = os.fsdecode(executable)
    except Exception:
        return
    checked = check(seq, env=env, cwd=cwd, executable=target)
    if list(checked) != list(seq):
        # The hook cannot apply a rewrite: the wrapper already
        # ran (or was bypassed). A fresh rewrite here means the
        # executed argv is not the admitted argv, so it refuses.
        refuse(seq, 'unapplied-rewrite')


def _publish(workdir):
    """Publish the runtime copy the prelude loads; return its path."""
    runtime_dest = os.path.join(workdir, 'guard-runtime.py')
    source = os.path.realpath(__file__)
    tmp_runtime = runtime_dest + '.tmp-%d' % os.getpid()
    shutil.copyfile(source, tmp_runtime)
    os.replace(tmp_runtime, runtime_dest)
    return runtime_dest


def install_guard(marker, fixture_root, _inherit=None):
    """Install the spawn interposition for this process and children.

    An explicit call samples trust from the caller's
    environment (CI trust: the lane's own invocation) and
    publishes the runtime copy. A propagated call (_inherit
    from the prelude) reuses the parent's trust map, python
    digests, scratch roots, install environment, and runtime
    digest verbatim instead of sampling the child's possibly
    hostile environment; the prelude verified the runtime copy
    before loading it, and the shared workdir needs no
    re-publication. A reinstall with different parameters
    resets every verdict and trust cache.
    """
    global _MARKER, _ROOT, _ALLOWED, _ACTIVE, _SCRATCH, _INSTALL_ENV, _RUNTIME_DIGEST
    marker = os.fsdecode(marker)
    fixture_root = os.path.realpath(os.fsdecode(fixture_root))
    params = getattr(sys, '_mojobpf_guard_params', None)
    if params == (marker, fixture_root) and _ACTIVE and _inherit is None:
        return
    _MARKER = marker
    _ROOT = fixture_root
    _SEEN.clear()
    _PYTHON_DIGESTS.clear()
    workdir = os.path.dirname(os.path.abspath(marker))
    os.makedirs(workdir, exist_ok=True)
    if _inherit is None:
        install_path = os.environ.get('PATH', os.defpath)
        _SCRATCH = _snapshot_scratch()
        _ALLOWED = _sample_trusted(install_path)
        _RUNTIME_DIGEST = file_digest(_publish(workdir))
        _INSTALL_ENV = _snapshot_install_env()
    else:
        roots, _RUNTIME_DIGEST, allowed, pythons, install_env = _inherit
        _SCRATCH = frozenset(roots)
        _ALLOWED = {name: set(digests) for name, digests in allowed}
        _PYTHON_DIGESTS.update(pythons)
        _INSTALL_ENV = dict(install_env)
    if not _ORIGINALS:
        _ORIGINALS['popen'] = subprocess.Popen.__init__
        _ORIGINALS['system'] = os.system
        for kind in ('execv', 'execve', 'execl', 'execle', 'execlp',
                     'execvp', 'execvpe', 'posix_spawn', 'posix_spawnp'):
            if hasattr(os, kind):
                _ORIGINALS[kind] = getattr(os, kind)
        subprocess.Popen.__init__ = _guarded_init
        os.system = _guarded_system
        for kind in list(_ORIGINALS):
            if kind in ('popen', 'system'):
                continue
            setattr(os, kind, _guarded_exec(kind))
        try:
            sys.addaudithook(_audit_hook)
        except Exception:
            _journal('guard-degraded', [sys.executable], 'audit-hook-unavailable')
    sys._mojobpf_guard_params = (marker, fixture_root)
    _ACTIVE = True
