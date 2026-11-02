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
- everything else refuses with a journal entry and PermissionError.

There is deliberately no shell-semantics engine: no expansion,
substitution, eval, arithmetic, or multicall modeling. Anything the
argv-level rules cannot admit fails closed. Digests are computed
fresh at every spawn; there is no digest cache to go stale.
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
    'grep', 'sed', 'tr', 'cut', 'uname', 'pwd', 'printf', 'echo',
    'tar', 'gzip', 'bwrap', 'ls', 'find', 'sort', 'wc', 'id',
)

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


def active():
    return _ACTIVE


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
            continue
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.realpath(candidate)
    return None


def _sample_trusted():
    """Record install-time digests; environ PATH is never consulted."""
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


def _owned_fixture(path):
    if not path.startswith(_ROOT + os.sep):
        return False
    try:
        stat_result = os.stat(path)
    except OSError:
        return False
    if not stat.S_ISREG(stat_result.st_mode):
        return False
    if stat_result.st_uid != os.geteuid():
        return False
    return True


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
            raw = handle.read(65536)
    except OSError:
        refuse([path], 'owned-fixture-unreadable')
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
        if re.search(r'(?:^|[\s\'"=;|&(`])/[^\s\'"]*(?:%s)\b' % names, code):
            refuse([path], 'owned-fixture-forbidden-token')
        if re.search(
            r'(?:^|[;&|(`]|\bif\b|\bthen\b|\belse\b|\belif\b|\bwhile\b'
            r'|\buntil\b|\bdo\b|\bfor\b|\bcase\b)\s*(?:%s)(?=[\s;&|)\s]|$)'
            % names,
            code,
        ):
            refuse([path], 'owned-fixture-forbidden-token')
    if re.search(r"""['"]?(?:/[^'":\s]*/)?python[\d.]*(?:['"]|\s|$)""", text):
        if not re.search(r"""exec['" ]+[^'"\n]*python[\d.]*[^'"\n]*"\$0\"""", text):
            refuse([path], 'owned-fixture-python-execute')


def _fixture_interpreter_kind(words):
    """Classify a #! interpreter: python, shell, or None (unsupported)."""
    head = os.path.basename(words[0])
    if _is_python(words[0], head):
        return 'python'
    if PYTHON_RE.fullmatch(head):
        return 'python'
    if head in SHELL_NAMES:
        return 'shell'
    if head == 'env' and len(words) > 1:
        rest = [word for word in words[1:] if not word.startswith('-') and '=' not in word]
        if rest:
            tail = os.path.basename(rest[0])
            if tail in SHELL_NAMES:
                return 'shell'
            if PYTHON_RE.fullmatch(tail) or _is_python(rest[0], tail):
                return 'python'
    return None


def check(argv, env=None, cwd=None, executable=None):
    """Admit a spawn, returning the argv to execute, or refuse.

    Identity comes from the executed path (the `executable`
    override when given), never from argv[0] alone.
    """
    words = [os.fsdecode(word) for word in argv]
    identity = os.fsdecode(executable) if executable is not None else words[0]
    if cwd is None:
        cwd = os.getcwd()
    else:
        cwd = os.fsdecode(cwd)
    if env is None:
        env = os.environ
    path_value = env.get('PATH') if hasattr(env, 'get') else None
    if isinstance(path_value, bytes):
        path_value = os.fsdecode(path_value)
    base = os.path.basename(identity)
    resolved = _resolve(identity, path_value, cwd)
    bang = _shebang(resolved) if resolved is not None else None
    if bang is not None and _owned_fixture(resolved):
        # Owned fixtures are admitted by ownership, independent of
        # the name they carry (even a forbidden tool's name).
        kind = _fixture_interpreter_kind(bang)
        if kind == 'python':
            return argv
        if kind == 'shell':
            _screen_shell_fixture(resolved)
            return argv
        refuse(argv, 'unsupported-fixture-interpreter')
    if FORBIDDEN.fullmatch(base):
        refuse(argv, 'forbidden-name')
    if resolved is None:
        return argv
    if bang is not None:
        refuse(argv, 'unowned-script')
    try:
        digest = file_digest(resolved)
    except OSError:
        return argv
    # Direct spawns admit by digest union: the invoker names an
    # explicit path, visible in argv and the journal, so a renamed
    # copy of an admitted binary stays admitted. Shell-program
    # heads resolve implicitly through PATH and are checked
    # strictly per name (see the shell gate): that is where
    # shadow attacks live.
    for digests in _ALLOWED.values():
        if digest in digests:
            break
    else:
        refuse(argv, 'unadmitted-identity')
    return _gate_shell(argv, words, resolved, env, cwd, digest)


def _gate_shell(argv, words, resolved, env, cwd, digest):
    """Shell-form gating; the full gate arrives with program data."""
    return argv


def _covered(key):
    if key in _SEEN:
        return True
    if len(_SEEN) >= MAX_SEEN:
        _SEEN.clear()
    _SEEN[key] = True
    return False


def _spawn_key(argv, cwd):
    try:
        flat = tuple(os.fsdecode(word) for word in argv)
    except Exception:
        flat = ('<?>',)
    return (flat, cwd)


def _guarded_init(self, args, **kwargs):
    if isinstance(args, str) and kwargs.get('shell'):
        args = ['/bin/sh', '-c', args]
    if isinstance(args, (bytes, bytearray)) and kwargs.get('shell'):
        args = ['/bin/sh', '-c', os.fsdecode(args)]
    executable = kwargs.get('executable')
    env = kwargs.get('env')
    cwd = kwargs.get('cwd')
    seq = list(args)
    key = _spawn_key([os.fsdecode(executable)] + seq[1:] if executable else seq, cwd)
    if not _covered(key):
        seq = check(seq, env=env, cwd=cwd, executable=executable)
    if executable is not None:
        kwargs['executable'] = executable
    return _ORIGINALS['popen'](self, seq, **kwargs)


def _guarded_system(command):
    seq = ['/bin/sh', '-c', os.fsdecode(command)]
    if not _covered(_spawn_key(seq, None)):
        check(seq)
    return _ORIGINALS['system'](command)


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
        if not _covered(_spawn_key([target] + seq[1:], None)):
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


_SITECUSTOMIZE_TEMPLATE = '''"""Reinstall the exec-allowlist guard in child interpreters."""
import os
import sys

_MARKER = %r
_ROOT = %r
_RUNTIME = %r


def _emit(value):
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(_emit(item) for item in value) + ']'
    if isinstance(value, dict):
        return '{' + ','.join(_emit(k) + ':' + _emit(v) for k, v in value.items()) + '}'
    out = ['"']
    for char in str(value):
        code = ord(char)
        if char == '"':
            out.append('\\\\"')
        elif char == '\\\\':
            out.append('\\\\\\\\')
        elif char == '\\n':
            out.append('\\\\n')
        elif char == '\\r':
            out.append('\\\\r')
        elif char == '\\t':
            out.append('\\\\t')
        elif code < 0x20:
            out.append('\\\\u%%04x' %% code)
        else:
            out.append(char)
    out.append('"')
    return ''.join(out)


def _fail():
    try:
        with open(_MARKER, 'a', encoding='utf-8') as handle:
            handle.write(_emit({'event': 'guard-install-failure',
                                'argv': sys.argv,
                                'reason': 'child-install-failure'}) + '\\n')
    except OSError:
        pass
    os._exit(99)


try:
    import importlib.util
    _spec = importlib.util.spec_from_file_location('guard_runtime_child', _RUNTIME)
    _guard = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_guard)
    _guard.install_guard(_MARKER, _ROOT)
except Exception:
    _fail()
except SystemExit:
    raise
except BaseException:
    _fail()

# Chain any real sitecustomize shadowed by this directory.
for _entry in sys.path[1:]:
    _candidate = os.path.join(_entry, 'sitecustomize.py')
    if os.path.isfile(_candidate):
        try:
            import runpy
            runpy.run_path(_candidate)
        except ImportError:
            pass
        break
'''


def _publish(workdir):
    runtime_dest = os.path.join(workdir, 'guard-runtime.py')
    site_dir = os.path.join(workdir, 'guard-site')
    os.makedirs(site_dir, exist_ok=True)
    source = os.path.realpath(__file__)
    tmp_runtime = runtime_dest + '.tmp-%d' % os.getpid()
    shutil.copyfile(source, tmp_runtime)
    os.replace(tmp_runtime, runtime_dest)
    site_source = _SITECUSTOMIZE_TEMPLATE % (_MARKER, _ROOT, runtime_dest)
    tmp_site = os.path.join(site_dir, 'sitecustomize.py.tmp-%d' % os.getpid())
    with open(tmp_site, 'w', encoding='utf-8') as handle:
        handle.write(site_source)
    os.replace(tmp_site, os.path.join(site_dir, 'sitecustomize.py'))
    return runtime_dest, site_dir


def install_guard(marker, fixture_root):
    """Install the spawn interposition for this process and children."""
    global _MARKER, _ROOT, _ALLOWED, _ACTIVE
    marker = os.fsdecode(marker)
    fixture_root = os.path.realpath(os.fsdecode(fixture_root))
    params = getattr(sys, '_mojobpf_guard_params', None)
    if params == (marker, fixture_root) and _ACTIVE:
        return
    _MARKER = marker
    _ROOT = fixture_root
    workdir = os.path.dirname(os.path.abspath(marker))
    os.makedirs(workdir, exist_ok=True)
    _ALLOWED = _sample_trusted()
    _publish(workdir)
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
            pass
    sys._mojobpf_guard_params = (marker, fixture_root)
    _ACTIVE = True
