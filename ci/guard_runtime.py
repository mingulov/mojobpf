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
_INSTALL_PATH = None
_SCRATCH = frozenset()
_INSTALL_ENV = {}
_RUNTIME_DIGEST = None


def active():
    return _ACTIVE


def _env_path(env):
    """Read PATH from a spawn environment, tolerating bytes keys."""
    if env is None:
        return None
    if not hasattr(env, 'get'):
        return None
    for key in ('PATH', b'PATH'):
        try:
            value = env.get(key)
        except (TypeError, KeyError):
            continue
        if value is not None:
            return os.fsdecode(value)
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


def _is_python(path, name):
    if PYTHON_RE.fullmatch(name or ''):
        return True
    try:
        return file_digest(path) in _PYTHON_DIGESTS
    except OSError:
        return False


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


def _screen_shell_fixture(path):
    """Static forbidden-token screen for owned shell fixtures.

    Refuses when the bytes name a forbidden tool as an absolute
    path or as a command-position word, and when they name a python
    interpreter for execution outside the self-exec-$0 polyglot
    shape. Comments and single-quoted spans are data. This is a
    lexical screen, not an analysis: dynamically constructed tool
    names are invisible to it (documented residual).
    """
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(1048576 + 1)
    except OSError:
        refuse([path], 'owned-fixture-unreadable')
    if len(raw) > 1048576:
        # The screen must see every executed byte; a fixture
        # larger than the read cap refuses instead of running
        # partly unexamined.
        refuse([path], 'owned-fixture-too-large')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        refuse([path], 'owned-fixture-not-text')
    names = (
        'gcc|g\\+\\+|clang|clang\\+\\+|cc|c\\+\\+|llvm-[A-Za-z0-9+.-]*'
        '|llc|opt|mojo|mojobpf-lower|mojobpf-frame(?:-audit)?'
        '|mojobpf-audit-driver|cmake|ninja|make|rustc|cargo|vng'
        '|virtme(?:-run)?|qemu[^\\s]*|bpftool|docker|sudo'
    )
    for line in text.splitlines():
        masked = []
        in_single = False
        index = 0
        while index < len(line):
            char = line[index]
            if in_single:
                masked.append(' ')
                if char == "'":
                    in_single = False
                index += 1
                continue
            if char == "'":
                masked.append(' ')
                in_single = True
                index += 1
                continue
            if char == '#':
                break
            masked.append(char)
            index += 1
        code = ''.join(masked)
        hit = re.search(r'(?:^|[\s\'"=;|&(`])/[^\s\'"]*(?:%s)\b' % names, code)
        if hit:
            refuse([path], 'owned-fixture-forbidden-token', hit.group(0).strip())
        hit = re.search(
            r'(?:^|[;&|(`]|\bif\b|\bthen\b|\belse\b|\belif\b|\bwhile\b'
            r'|\buntil\b|\bdo\b|\bfor\b|\bcase\b)\s*(?:%s)(?=[\s;&|)\s]|$)'
            % names,
            code,
        )
        if hit:
            refuse([path], 'owned-fixture-forbidden-token', hit.group(0).strip())
    hit = re.search(r"""['"]?(?:/[^'":\s]*/)?python[\d.]*(?:['"]|\s|$)""", text)
    if hit:
        if not re.search(r"""exec['" ]+[^'"\n]*python[\d.]*[^'"\n]*"\$0\"""", text):
            refuse([path], 'owned-fixture-python-execute', hit.group(0).strip())


def _fixture_prefix(bang, env, cwd, argv):
    """Classify a #! interpreter, returning (kind, argv-prefix).

    The prefix rewrites an owned python fixture spawn so the
    interpreter starts guarded; shell fixtures screen instead.
    """
    head = os.path.basename(bang[0])
    if _is_python(bang[0], head) or PYTHON_RE.fullmatch(head):
        return 'python', list(bang)
    if head in SHELL_NAMES:
        return 'shell', None
    if head == 'env' and len(bang) > 1:
        if any(word == '-S' or word.startswith('-S') for word in bang[1:]):
            _journal('forbidden-execution', ['unsupported-env-option'],
                     'unsupported-env-option', {'argv': bang})
            raise PermissionError('guard refused env -S shebang: unsupported-env-option')
        for word in bang[1:]:
            if '=' in word and not word.startswith('-'):
                key = word.partition('=')[0]
                if key and _denied_env_name(key):
                    refuse(argv, 'unadmitted-shell-environment', key)
        at = None
        for index, word in enumerate(bang[1:], start=1):
            if not word.startswith('-') and '=' not in word:
                at = index
                break
        if at is None:
            return None, None
        interp = bang[at]
        resolved_interp = _resolve(interp, _env_path(env), cwd)
        if resolved_interp is None:
            refuse(argv, 'unadmitted-fixture-interpreter', interp)
        tail = os.path.basename(interp)
        if tail in SHELL_NAMES or _is_shell_path(resolved_interp):
            return 'shell', None
        if PYTHON_RE.fullmatch(tail) or _is_python(resolved_interp, tail):
            return 'python', ['env'] + bang[1:at] + [resolved_interp]
    return None, None


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


def check(argv, env=None, cwd=None, executable=None, _strict=False, _depth=0):
    """Admit a spawn, returning the argv to execute, or refuse.

    Identity comes from the executed path (the `executable`
    override when given), never from argv[0] alone. Direct spawns
    admit by digest union (the explicit path is journaled);
    shell-program heads resolve implicitly and check strictly
    per name (_strict).
    """
    if _depth > _MAX_NESTING:
        refuse(argv, 'unadmitted-shell-program', 'nesting-too-deep')
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
        return argv
    try:
        st = os.stat(resolved)
    except OSError:
        if FORBIDDEN.fullmatch(base):
            refuse(argv, 'forbidden-name')
        return argv
    if not stat.S_ISREG(st.st_mode):
        # Non-regular targets cannot execute; the kernel reports
        # the ordinary error. (This also keeps FIFOs and devices
        # out of the digest reader, which would block on them.)
        return argv
    # Repeat-spawn memo, keyed by file identity: same bytes give
    # the same verdict, so only a changed file re-decides. The
    # ctime leg catches same-size/same-mtime rewrites. The PATH
    # and cwd legs matter because head resolution (and hence the
    # verdict) depends on them.
    memo = (resolved, tuple(words), st.st_dev, st.st_ino, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, path_value, cwd, _strict)
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
            _screen_shell_fixture(resolved)
            return _remember(memo, argv)
        refuse(argv, 'unsupported-fixture-interpreter')
    if FORBIDDEN.fullmatch(base):
        refuse(argv, 'forbidden-name')
    try:
        digest = file_digest(resolved)
    except OSError:
        return argv
    if _strict:
        # Shell-program heads: the name must be listed and the
        # file must be that name's install-time binary. Shadows
        # (same name, other bytes) and renamed tools (other name)
        # both refuse here.
        key = os.path.basename(identity)
        if key not in _ALLOWED or digest not in _ALLOWED[key]:
            refuse(argv, 'unadmitted-shell-head')
    else:
        # Direct spawns admit by digest union: the invoker names
        # an explicit path, visible in argv and the journal, so a
        # renamed copy of an admitted binary stays admitted.
        for digests in _ALLOWED.values():
            if digest in digests:
                break
        else:
            refuse(argv, 'unadmitted-identity')
    gated = _gate_shell(argv, words, resolved, env, cwd, digest, _strict, _depth)
    verdict = _remember(memo, gated)
    if list(gated) != words:
        # Memoize the rewritten argv to itself: the audit hook
        # re-checks the executed argv in this same process, and a
        # rewritten shell program (multi-line after injection)
        # would otherwise refuse as a fresh compound. Only the
        # exact admitted bytes hit; anything altered re-decides.
        rewritten = (resolved, tuple(gated), st.st_dev, st.st_ino,
                     st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                     path_value, cwd, _strict)
        _remember(rewritten, gated)
    return verdict


def _digest_is(name, digest):
    return digest in _ALLOWED.get(name, set())


def _gate_shell(argv, words, resolved, env, cwd, digest, strict, _depth=0):
    """Dispatch admitted binaries by name or digest.

    Dispatch keys on the digest as well as the spelling so a
    renamed copy keeps its kind's rules (peel, inject, gate).
    Peels recurse with a strictly increasing depth so wrapper
    chains terminate in a journaled refusal, never a bare
    RecursionError.
    """
    # Kind resolution: name and content agreeing wins (correct
    # on multicall boxes where one digest serves several names);
    # otherwise content wins over spelling, so a renamed copy
    # keeps the rules of what it is.
    name = os.path.basename(words[0])
    kind = None
    if (PYTHON_RE.fullmatch(name) or name in SHELL_NAMES
            or name in ('env', 'timeout', 'bwrap', 'git', 'awk', 'find')):
        if name in SHELL_NAMES and _is_shell_digest(digest):
            kind = 'shell'
        elif PYTHON_RE.fullmatch(name) and digest in _PYTHON_DIGESTS:
            kind = 'python'
        elif name in ('env', 'timeout', 'bwrap', 'git', 'awk', 'find') and _digest_is(name, digest):
            kind = name
    if kind is None:
        if digest in _PYTHON_DIGESTS:
            kind = 'python'
        elif _is_shell_digest(digest):
            kind = 'shell'
        else:
            for candidate in ('env', 'timeout', 'bwrap', 'git', 'awk', 'find'):
                if _digest_is(candidate, digest):
                    kind = candidate
                    break
    if kind == 'python':
        return _inject_python(argv, list(words))
    if kind == 'env':
        assignments, unsets, ignore, chdir, child, at = _split_env(argv, words)
        if not child:
            return argv
        merged = {} if ignore else dict(env)
        for var in unsets:
            merged.pop(var, None)
        merged.update(assignments)
        target_cwd = chdir if chdir is not None else cwd
        verdict = check(child, env=merged, cwd=target_cwd, _strict=strict, _depth=_depth + 1)
        if list(verdict) != list(child):
            return words[:at] + list(verdict)
        return argv
    if kind == 'timeout':
        child = _split_timeout(argv, words)
        if not child:
            return argv
        at = len(words) - len(child)
        verdict = check(child, env=env, cwd=cwd, _strict=strict, _depth=_depth + 1)
        if list(verdict) != list(child):
            return words[:at] + list(verdict)
        return argv
    if kind == 'bwrap':
        child = _split_bwrap(argv, words)
        if not child:
            return argv
        at = len(words) - len(child)
        verdict = check(child, env=env, cwd=cwd, _strict=strict, _depth=_depth + 1)
        if list(verdict) != list(child):
            return words[:at] + list(verdict)
        return argv
    if kind == 'shell':
        return _admit_shell_words(argv, list(words), env, cwd, 0)
    if kind == 'git':
        return _git_words(argv, list(words))
    if kind == 'awk':
        return _awk_words(argv, list(words))
    if kind == 'find':
        refuse(argv, 'unadmitted-find')
    return argv


def _is_shell_digest(digest):
    for shell in SHELL_NAMES:
        if digest in _ALLOWED.get(shell, set()):
            return True
    return False


def _is_shell_path(resolved):
    try:
        return _is_shell_digest(file_digest(resolved))
    except OSError:
        return False


# Exact-admitted -c programs: program text -> tool heads the gate
# re-verifies at every use (name-keyed digests over the spawn
# environment, so a shadowed head refuses). Every entry below was
# read in full at admission; inner interpreters run vetted fixed
# payloads only.
_ADMITTED_PROGRAMS = {
    'out=$(printf "%s" $(printf nested-ok))\nprintf "%s" "$out"': ('printf',),
    'd=$(timeout 60 mktemp -d)\nrm -r "$d"\nprintf "%s" ok': ('timeout', 'mktemp', 'rm', 'printf'),
    'o=$(printf "%s" "$(printf deep)")\nprintf "%s" "$o"': ('printf',),
    'printf "%s" $((1 + 2 * 3))': ('printf',),
    'n=1\nprintf "%s" $((n + ${STEP:-5}))': ('printf',),
    'printf "%s" $(((_cb_dead * 1000 - 1) / 1000))': ('printf',),
    '((x = 6 * 7))\nprintf "%s" "$x"': ('printf',),
    's=0\nfor ((i = 0; i < 3; i++)); do s=$((s + i)); done\nprintf "%s" "$s"': ('printf',),
    '((x = 1 << 4))\nprintf "%s" "$x"': ('printf',),
    'cat <<\'EOF\'\nliteral `x` $(y) "q" \'s\'\nEOF': ('cat',),
    'cat <<\'E\' | tr a b\na\nE': ('cat', 'tr'),
    'out=$(cat <<\'EOF\'\ndata $(x) `y`\nEOF\n)\nprintf "%s" "$out"': ('cat', 'printf'),
    'cat <<-\'E\'\n\tindented\nE': ('cat',),
    'v=$(timeout 60 python3 -c \'print(40 + 2)\')\nprintf "%s" "$v"': ('timeout', 'python3', 'printf'),
    'printf \'a\\n\' | python3 -c \'import sys; print("b")\'': ('printf', 'python3'),
    'printf \'a\\n\' | TAG=x python3 -c \'print("t")\'': ('printf', 'python3'),
    'printf "%s" "bpftool v0.0-fixture"': ('printf',),
    'echo hello; exit 3': ('echo',),
}

# Vetted program templates: (prefix, suffix, heads). The hole
# between prefix and suffix must be exactly one bare-safe token or
# one single-quoted span (both inert by construction); the fixed
# text was read in full at admission.
_PROGRAM_TEMPLATES = (
    ('STAGE=',
     '\nMAP_TYPE=array\nline=$(grep -F "map_type $MAP_TYPE is" "$STAGE/feature.txt" | head -1 || true)\nprintf "%s" "$line"',
     ('grep', 'head', 'printf')),
    ('STAGE=',
     '\nPROG_TYPE=xdp\nline=$(grep -F "program_type $PROG_TYPE is" "$STAGE/feature.txt" | head -1 || true)\nprintf "%s" "$line"',
     ('grep', 'head', 'printf')),
)

_HOLE_BARE = re.compile(r"[^'\s;|&<>()$`\\\"#\n!{}*?\[\]~]+")
# shlex.quote spells an embedded quote as '"'"' (close, double-quoted
# quote, open), so the quoted hole admits those groups explicitly.
_HOLE_QUOTED = re.compile(r"'(?:[^']|'\"'\"')*'")

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
_DENIED_ENV_PREFIX = ('DYLD_', 'GIT_EXTERNAL')


def _denied_env_name(name):
    if name in _DENIED_ENV_EXACT:
        return True
    return name.startswith(_DENIED_ENV_PREFIX)


_SHELL_BOOL_SINGLE = frozenset('abdefhklmnpqrtuvxBCEHPT')
_SHELL_BOOL_LONG = frozenset([
    '--login', '--norc', '--noprofile', '--posix', '--verbose',
    '--version', '--help',
])
_MAX_NESTING = 8


def _verify_heads(argv, heads, env, cwd):
    """Re-verify admitted-program tool heads against the spawn environment."""
    path_value = _env_path(env)
    for head in heads:
        resolved = _resolve(head, path_value, cwd)
        if resolved is None:
            refuse(argv, 'unadmitted-shell-head', head)
        if _owned_fixture(resolved):
            refuse(argv, 'unadmitted-shell-head', head)
        try:
            digest = file_digest(resolved)
        except OSError:
            refuse(argv, 'unadmitted-shell-head', head)
        key = os.path.basename(head)
        if key not in _ALLOWED or digest not in _ALLOWED[key]:
            refuse(argv, 'unadmitted-shell-head', head)


def _match_template(prog):
    for prefix, suffix, heads in _PROGRAM_TEMPLATES:
        if not prog.startswith(prefix) or not prog.endswith(suffix):
            continue
        hole = prog[len(prefix):len(prog) - len(suffix)]
        if _HOLE_QUOTED.fullmatch(hole) or _HOLE_BARE.fullmatch(hole):
            return heads
    return None


def _split_stages(argv, body):
    """Quote-aware pipeline split; refuses compounds and redirects."""
    stages = []
    current = []
    quote = None
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == '\\' and quote != "'":
            escaped = True
            current.append(char)
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in ('"', "'"):
            quote = char
            current.append(char)
            continue
        if char == '|':
            stages.append(''.join(current))
            current = []
            continue
        if char in (';', '&', '(', ')', '<', '>'):
            refuse(argv, 'unadmitted-shell-program', char)
        current.append(char)
    if escaped or quote is not None:
        refuse(argv, 'unadmitted-shell-program', 'unterminated-quote')
    stages.append(''.join(current))
    return stages


_ASSIGN_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=.*')


def _strip_exec(argv, words):
    """Strip one leading exec prefix (exec [-a name] [-c] [-l])."""
    if not words or words[0] != 'exec':
        return words
    rest = words[1:]
    while rest and rest[0] in ('-c', '-l'):
        rest = rest[1:]
    if rest and rest[0] == '-a':
        if len(rest) < 2:
            refuse(argv, 'unadmitted-shell-program', 'exec-without-name')
        rest = rest[2:]
    while rest and rest[0] in ('-c', '-l'):
        rest = rest[1:]
    if not rest:
        refuse(argv, 'unadmitted-shell-program', 'bare-exec')
    return rest


def _admit_stage(argv, words, env, cwd, pipeline, depth):
    """Admit one pipeline stage; return the (possibly rewritten) words."""
    if depth > _MAX_NESTING:
        refuse(argv, 'unadmitted-shell-program', 'nesting-too-deep')
    original = list(words)
    words = _strip_exec(argv, list(words))
    assigns = {}
    while words and _ASSIGN_RE.fullmatch(words[0]):
        key, _, value = words[0].partition('=')
        if _denied_env_name(key):
            refuse(argv, 'unadmitted-shell-environment', key)
        assigns[key] = value
        words = words[1:]
    if not words:
        # Assignments alone execute nothing; keep them verbatim so
        # the shell's own semantics (exit status, scope) survive.
        return original
    path_value = assigns.get('PATH')
    if path_value is None:
        path_value = _env_path(env)
    head = words[0]
    resolved = _resolve(head, path_value, cwd)
    if resolved is None:
        refuse(argv, 'unadmitted-shell-head', head)
    if _owned_fixture(resolved):
        refuse(argv, 'unadmitted-shell-head', head)
    try:
        digest = file_digest(resolved)
    except OSError:
        refuse(argv, 'unadmitted-shell-head', head)
    key = os.path.basename(head)
    if key not in _ALLOWED or digest not in _ALLOWED[key]:
        refuse(argv, 'unadmitted-shell-head', head)
    if _is_shell_digest(digest):
        return _admit_shell_words(argv, words, env, cwd, depth + 1)
    if digest in _PYTHON_DIGESTS:
        if pipeline:
            refuse(argv, 'unsupported-python-shell-launcher', head)
        return _inject_python(argv, words)
    if _digest_is('env', digest):
        sub_assigns, sub_unsets, ignore, chdir, child, at = _split_env(argv, words)
        if not child:
            return words
        merged = dict(assigns)
        if not ignore:
            for var, value in (env.items() if hasattr(env, 'items') else os.environ.items()):
                merged.setdefault(os.fsdecode(var), os.fsdecode(value))
        for var in sub_unsets:
            merged.pop(var, None)
        merged.update(sub_assigns)
        target_cwd = chdir if chdir is not None else cwd
        return words[:at] + _admit_stage(argv, child, merged, target_cwd, pipeline, depth + 1)
    if _digest_is('timeout', digest):
        child = _split_timeout(argv, words)
        if not child:
            return words
        at = len(words) - len(child)
        return words[:at] + _admit_stage(argv, child, env, cwd, pipeline, depth + 1)
    if _digest_is('bwrap', digest):
        child = _split_bwrap(argv, words)
        if not child:
            return words
        at = len(words) - len(child)
        return words[:at] + _admit_stage(argv, child, env, cwd, pipeline, depth + 1)
    if _digest_is('git', digest):
        return _git_words(argv, words)
    if _digest_is('awk', digest):
        return _awk_words(argv, words)
    if _digest_is('find', digest):
        refuse(argv, 'unadmitted-find')
    return words


def _names_python_launcher(prog):
    """Whether a compound program plausibly launches python.

    A bare interpreter path may be an alias (no 'python' text),
    so a -c word in a compound counts too: both shapes need the
    launcher-specific refusal.
    """
    if re.search(r'\bpython[\d.]*\b', prog):
        return True
    return re.search(r'(?:^|\s)-c(?:\s|$)', prog) is not None


def _gate_program(argv, prog, pos, env, cwd, depth):
    """Admit a -c program; return the program to run (maybe rewritten)."""
    if depth > _MAX_NESTING:
        refuse(argv, 'unadmitted-shell-program', 'nesting-too-deep')
    if prog in _ADMITTED_PROGRAMS:
        _verify_heads(argv, _ADMITTED_PROGRAMS[prog], env, cwd)
        return prog
    heads = _match_template(prog)
    if heads is not None:
        _verify_heads(argv, heads, env, cwd)
        return prog
    if '\n' in prog or '\r' in prog:
        if _names_python_launcher(prog):
            refuse(argv, 'unsupported-python-shell-launcher')
        refuse(argv, 'unadmitted-shell-program')
    if any(sep in prog for sep in (';', '&&', '||')) and _names_python_launcher(prog):
        refuse(argv, 'unsupported-python-shell-launcher')

    def _substitute(match):
        index = int(match.group(1))
        return pos[index] if index < len(pos) else ''

    body = re.sub(r'\$([0-9])', _substitute, prog)
    if '$' in body or '`' in body:
        refuse(argv, 'unadmitted-shell-program')
    stages = _split_stages(argv, body)
    pipeline = len(stages) > 1
    rewritten = []
    changed = False
    for stage in stages:
        try:
            import shlex
            stage_words = shlex.split(stage, posix=True)
        except ValueError:
            refuse(argv, 'unadmitted-shell-program', 'unbalanced-quotes')
        if not stage_words:
            refuse(argv, 'unadmitted-shell-program', 'empty-stage')
        admitted = _admit_stage(argv, stage_words, env, cwd, pipeline, depth)
        if admitted != stage_words:
            changed = True
        rewritten.append(admitted)
    if not changed:
        return prog
    import shlex
    return ' | '.join(shlex.join(stage) for stage in rewritten)


def _admit_shell_words(argv, words, env, cwd, depth):
    """Admit a shell invocation; return the argv to execute."""
    if depth > _MAX_NESTING:
        refuse(argv, 'unadmitted-shell-program', 'nesting-too-deep')
    index = 1
    count = len(words)
    while index < count:
        word = words[index]
        if word in ('-o', '-O'):
            index += 2
            continue
        if word in _SHELL_BOOL_LONG:
            index += 1
            continue
        if word == '-c' and index + 1 < count:
            pos = [words[0]] + words[index + 2:]
            prog = _gate_program(argv, words[index + 1], pos, env, cwd, depth + 1)
            if prog != words[index + 1]:
                words = words[:index + 1] + [prog] + words[index + 2:]
            return words
        if word == '-c':
            refuse(argv, 'unadmitted-shell-program', 'dash-c-without-program')
        if word.startswith('-') and word not in ('-', '--') and not word.startswith('--'):
            bundle = word[1:]
            if 's' in bundle and 'c' not in bundle:
                # -s reads the program from stdin, which no
                # argv-level rule can see; -c combinations gate
                # the -c program instead (-s is inert with -c).
                refuse(argv, 'unadmitted-shell-program', 'stdin-program')
            if bundle.endswith('c') and all(char in _SHELL_BOOL_SINGLE for char in bundle[:-1]):
                if index + 1 >= count:
                    refuse(argv, 'unadmitted-shell-program', 'dash-c-without-program')
                pos = [words[0]] + words[index + 2:]
                prog = _gate_program(argv, words[index + 1], pos, env, cwd, depth + 1)
                words = words[:index] + ['-c', prog] + words[index + 2:]
                return words
            if bundle and all(char in _SHELL_BOOL_SINGLE for char in bundle):
                index += 1
                continue
            refuse(argv, 'unsupported-shell-option', word)
        if word == '--':
            index += 1
            break
        break
    if index >= count:
        refuse(argv, 'unsupported-shell-stdin')
    script = words[index]
    if script.startswith('-'):
        refuse(argv, 'unsupported-shell-option', script)
    # The script resolves against the spawn cwd only. Bash would
    # fall back to a PATH search for a slashless name, but that
    # refusal is fail-closed: whenever the guard admits, the
    # screened bytes are the bytes the shell runs (cwd wins).
    target = script if os.path.isabs(script) else os.path.join(cwd, script)
    if not os.path.isfile(target):
        refuse(argv, 'unadmitted-shell-script', script)
    if not _owned_fixture(os.path.realpath(target)):
        refuse(argv, 'unowned-script', script)
    _screen_shell_fixture(os.path.realpath(target))
    return words


_GIT_SUBCOMMANDS = frozenset(['show', 'rev-parse', 'init', 'add', 'ls-files', '--version', '--help'])
_GIT_CONFIG_RE = re.compile(r'(?:core|pager|diff|merge|credential|advice|color)\.[A-Za-z0-9_.]+')


def _git_words(argv, words):
    """Admit vetted git subcommands; refuse delegation knobs."""
    index = 1
    count = len(words)
    while index < count and words[index] in ('--no-pager',):
        index += 1
    while index < count and words[index] == '-C':
        index += 2
    if index >= count or words[index] not in _GIT_SUBCOMMANDS:
        refuse(argv, 'unadmitted-git-subcommand', words[index] if index < count else '')
    for word in words[1:]:
        if word == '-c':
            refuse(argv, 'unadmitted-git-option', word)
        if word.startswith('--ext-diff') or word.startswith('--external'):
            refuse(argv, 'unadmitted-git-option', word)
        if _GIT_CONFIG_RE.fullmatch(word) or (
                '=' in word and _GIT_CONFIG_RE.fullmatch(word.partition('=')[0])):
            refuse(argv, 'unadmitted-git-option', word)
    return words


_AWK_PROGRAM_RE = re.compile(r'\bsystem\b\s*\(|\|&|\|\s*getline|\|\s*["\']')


def _awk_words(argv, words):
    """Admit awk with vetted flags; refuse command-pipe constructs.

    Backslash-newline splices normalize before matching, so a
    split 'system' cannot hide. Pipes to computed targets
    ('print | variable', 'print | (expr)') stay invisible: a bare
    '|' also spells regex alternation, so no word rule can catch
    them without a real lexer (out of scope by design). The
    lane's embedded filters print to stdout only; a computed
    pipe in a future filter needs its own admission.
    """
    index = 1
    count = len(words)
    program = None
    while index < count:
        word = words[index]
        if word in ('-F', '-v'):
            index += 2
            continue
        if word.startswith('--source='):
            program = word.partition('=')[2]
            index += 1
            continue
        if word.startswith('-'):
            refuse(argv, 'unsupported-awk-option', word)
        program = word
        break
    if program is None:
        refuse(argv, 'unadmitted-awk-program', 'missing-program')
    if _AWK_PROGRAM_RE.search(program.replace('\\\n', '')):
        refuse(argv, 'unadmitted-awk-program', 'command-pipe')
    return words


_PRELUDE_MARKER = '# mojobpf-guard-prelude v2\n'

_PRELUDE_TEMPLATE = (
    '# mojobpf-guard-prelude v2\n'
    'import hashlib as _gh, importlib.util as _gu, os as _go, sys as _gs\n'
    '_gr, _gm, _gp = %r, %r, %r\n'
    '_gx = %r\n'
    'def _gf():\n'
    '    _gfd = open(_gr, "rb")\n'
    '    _gd = _gh.sha256(_gfd.read()).hexdigest()\n'
    '    _gfd.close()\n'
    '    if _gd != _gx[2]:\n'
    '        raise ValueError("guard runtime digest mismatch")\n'
    '    _gspec = _gu.spec_from_file_location("guard_runtime_child", _gr)\n'
    '    _gmod = _gu.module_from_spec(_gspec)\n'
    '    _gs.modules["guard_runtime_child"] = _gmod\n'
    '    _gspec.loader.exec_module(_gmod)\n'
    '    _gmod.install_guard(_gm, _gp, _gx)\n'
    'try:\n'
    '    _gf()\n'
    'except SystemExit:\n'
    '    raise\n'
    'except BaseException:\n'
    '    try:\n'
    '        _gj = open(_gm, "a", encoding="utf-8")\n'
    '        _gj.write(\'{"event":"guard-install-failure","argv":[],"reason":"child-install-failure"}\\n\')\n'
    '        _gj.close()\n'
    '    except OSError:\n'
    '        pass\n'
    '    _go._exit(99)\n'
    'del _gh, _gu, _go, _gs, _gr, _gm, _gp, _gx, _gf\n'
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
    here (marker, root, install PATH, scratch roots, runtime
    digest) was fixed at install.
    """
    runtime = os.path.join(os.path.dirname(os.path.abspath(_MARKER)), 'guard-runtime.py')
    inherit = (_INSTALL_PATH, sorted(_SCRATCH), _RUNTIME_DIGEST)
    return _PRELUDE_TEMPLATE % (runtime, _MARKER, _ROOT, inherit)


def _inject_python(argv, words):
    """Rewrite a python spawn to install the guard first.

    Returns the argv to execute. Covers -c, -m, script-path, and
    stdin forms; anything else refuses (fail closed).
    """
    if len(words) >= 3 and words[1] == '-c' and words[2].startswith(_PRELUDE_MARKER):
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
            if words[index + 1].startswith(_PRELUDE_MARKER):
                return argv
            words[index + 1] = _prelude() + words[index + 1]
            return words
        if word == '-m' and index + 1 < count:
            module = words[index + 1]
            runner = (
                _prelude()
                + 'import runpy as _gr, sys as _gs;'
                + '_gs.argv=%r;_gr.run_module(%r, run_name="__main__")'
                % ([module] + words[index + 2:], module)
            )
            return words[:index] + ['-c', runner] + words[index + 2:]
        if word == '-':
            runner = (
                _prelude() + 'import sys as _gs;'
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
            _prelude()
            + 'import runpy as _gr, sys as _gs;'
            + '_gs.argv=%r;_gr.run_path(%r, run_name="__main__")'
            % (words[index:], script)
        )
        return words[:index] + ['-c', runner]
    if index >= count:
        runner = _prelude() + 'import sys as _gs;exec(_gs.stdin.read())'
        return words + ['-c', runner]
    refuse(argv, 'unsupported-python-form')


def _unsupported_env_option(argv, words):
    _journal('forbidden-execution', ['unsupported-env-option'],
             'unsupported-env-option', {'argv': words})
    raise PermissionError('guard refused env option: unsupported-env-option')


def _split_env(argv, words):
    """Peel env(1) flags/assignments.

    Returns (assignments, unsets, ignore, chdir, child_argv,
    child_index). Refuses -S (whose operand re-parses) and unknown
    options.
    """
    assignments = {}
    unsets = []
    ignore = False
    chdir = None
    index = 1
    count = len(words)
    while index < count:
        word = words[index]
        if word in ('-i', '--ignore-environment'):
            ignore = True
            index += 1
            continue
        if word in ('-u', '--unset') and index + 1 < count:
            unsets.append(words[index + 1])
            index += 2
            continue
        if word.startswith('--unset='):
            unsets.append(word.partition('=')[2])
            index += 1
            continue
        if word in ('-0', '--null'):
            index += 1
            continue
        if word in ('-C', '--chdir') and index + 1 < count:
            chdir = words[index + 1]
            index += 2
            continue
        if word.startswith('--chdir='):
            chdir = word.partition('=')[2]
            index += 1
            continue
        if word == '-S' or word.startswith('-S') or word.startswith('--split-string'):
            _unsupported_env_option(argv, words)
        if word == '--':
            index += 1
            break
        if '=' in word and not word.startswith('-'):
            key, _, value = word.partition('=')
            if key and all(char.isalnum() or char == '_' for char in key):
                if _denied_env_name(key):
                    refuse(argv, 'unadmitted-shell-environment', key)
                assignments[key] = value
                index += 1
                continue
        if word.startswith('-'):
            _unsupported_env_option(argv, words)
        break
    return assignments, unsets, ignore, chdir, words[index:], index


def _split_timeout(argv, words):
    """Peel timeout(1) flags/duration; return the child argv."""
    index = 1
    count = len(words)
    while index < count:
        word = words[index]
        if word in ('-k', '--kill-after', '-s', '--signal', '--foreground',
                    '--preserve-status'):
            if word in ('-k', '--kill-after', '-s', '--signal'):
                index += 2
            else:
                index += 1
            continue
        if word.startswith('--kill-after=') or word.startswith('--signal='):
            index += 1
            continue
        if word == '--':
            index += 1
            break
        if word.startswith('-'):
            refuse(argv, 'unsupported-timeout-option', word)
        index += 1
        break
    return words[index:]


def _overlap_refuses(argv, dest):
    if not os.path.isabs(dest):
        # bwrap requires absolute destinations; anything else is
        # unmodelable, so it refuses like an unknown option.
        refuse(argv, 'unsupported-bwrap-option', dest)
    target = os.path.realpath(dest)
    workdir = os.path.dirname(os.path.realpath(_MARKER))
    if target == '/' or target == workdir or workdir.startswith(target + '/'):
        refuse(argv, 'bwrap-guard-journal-overlap', dest)


def _split_bwrap(argv, words):
    """Peel bwrap(1) to the child argv; refuse journal-overlapping binds.

    Only the bind family, --dev, --die-with-parent, --new-session,
    and the -- terminator are modeled; anything else refuses.
    """
    index = 1
    count = len(words)
    # The bind family takes (source, dest): the DESTINATION is
    # the overlap-checked operand. Peeling --bind as one operand
    # would check the source and mis-parse the destination as the
    # child argv.
    one_arg_binds = frozenset(['--tmpfs', '--dir', '--dev'])
    two_arg_binds = frozenset([
        '--bind', '--ro-bind', '--dev-bind',
        '--symlink', '--file', '--bind-data',
    ])
    while index < count:
        word = words[index]
        if word == '--':
            return words[index + 1:]
        if word in one_arg_binds and index + 1 < count:
            _overlap_refuses(argv, words[index + 1])
            index += 2
            continue
        if word in two_arg_binds and index + 2 < count:
            _overlap_refuses(argv, words[index + 2])
            index += 3
            continue
        if word in ('--die-with-parent', '--new-session'):
            index += 1
            continue
        if word.startswith('-'):
            refuse(argv, 'unsupported-bwrap-option', word)
        return words[index:]
    return []


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
    seq = check(seq, env=env, cwd=cwd, executable=executable)
    return _ORIGINALS['popen'](self, seq, **kwargs)


def _guarded_system(command):
    # The checked argv executes, not the raw command: rewrites
    # (python injection for shell python-launchers) must survive.
    # Return-value mapping matches system(): exit N -> N << 8,
    # signal S -> S. (Unlike system(), SIGINT/SIGQUIT stay
    # unignored in the waiter; no lane test depends on that.)
    seq = check(['/bin/sh', '-c', os.fsdecode(command)])
    proc = subprocess.Popen.__new__(subprocess.Popen)
    _ORIGINALS['popen'](proc, seq)
    status = proc.wait()
    return status << 8 if status >= 0 else -status


def _guarded_exec(kind):
    def _run(path, *args, **kwargs):
        if kind in ('execv', 'execve', 'posix_spawn', 'posix_spawnp'):
            seq = [os.fsdecode(word) for word in args[0]]
            env = args[1] if kind in ('execve', 'posix_spawn') else None
        elif kind in ('execle', 'execvpe'):
            seq = [os.fsdecode(word) for word in args[:-1]]
            env = args[-1]
        else:
            seq = [os.fsdecode(word) for word in args]
            env = None
        target = os.fsdecode(path)
        seq = check(seq, env=env, executable=target)
        func = _ORIGINALS[kind]
        if kind == 'execve':
            return func(path, seq, env if env is not None else os.environ)
        if kind == 'posix_spawn':
            return func(path, seq, env if env is not None else os.environ, **kwargs)
        if kind in ('posix_spawnp',):
            return func(path, seq, env if env is not None else os.environ, **kwargs)
        if kind in ('execv', 'execvp', 'execvpe'):
            if kind == 'execvpe':
                return func(path, seq, env)
            return func(path, seq)
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
    check(seq, env=env, cwd=cwd, executable=target)


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
    from the prelude) reuses the parent's install PATH,
    scratch roots, and runtime digest instead of sampling the
    child's possibly hostile environment; the prelude verified
    the runtime copy before loading it, and the shared workdir
    needs no re-publication. A reinstall with different
    parameters resets every verdict and trust cache.
    """
    global _MARKER, _ROOT, _ALLOWED, _ACTIVE, _INSTALL_PATH, _SCRATCH, _INSTALL_ENV, _RUNTIME_DIGEST
    marker = os.fsdecode(marker)
    fixture_root = os.path.realpath(os.fsdecode(fixture_root))
    params = getattr(sys, '_mojobpf_guard_params', None)
    if params == (marker, fixture_root) and _ACTIVE and _inherit is None:
        return
    _MARKER = marker
    _ROOT = fixture_root
    _SEEN.clear()
    _PYTHON_DIGESTS.clear()
    _INSTALL_ENV = _snapshot_install_env()
    workdir = os.path.dirname(os.path.abspath(marker))
    os.makedirs(workdir, exist_ok=True)
    if _inherit is None:
        _INSTALL_PATH = os.environ.get('PATH', os.defpath)
        _SCRATCH = _snapshot_scratch()
        _ALLOWED = _sample_trusted(_INSTALL_PATH)
        _RUNTIME_DIGEST = file_digest(_publish(workdir))
    else:
        _INSTALL_PATH, roots, _RUNTIME_DIGEST = _inherit
        _SCRATCH = frozenset(roots)
        _ALLOWED = _sample_trusted(_INSTALL_PATH)
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
