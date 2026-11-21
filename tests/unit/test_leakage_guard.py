# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Leakage guard: shipped files carry no internal IDs or private paths.

The shipped set is derived, never guessed: the union of the sdist
member pin (``tests/packaging/sdist-members.json``) and the wheel
payload pin (``PINNED_PAYLOAD``/``PINNED_SCHEMA_DATA`` in
``tests/packaging/test_wheel_contents.py``, mapped back to tree
paths), intersected with tracked files read from the git index
directly (no subprocess: the lane guard refuses delegating
launchers, and this module spawns nothing).
Untracked pinned drops are allowlisted by
``PINNED_GENERATED_DROPPED``; anything else fails. Every
text-decodable member is grepped for internal work-package IDs
(``WP-*``), stage IDs (``M-*``), finding IDs (``F-*``), and private
workspace paths. A hit fails with a ``file:line`` listing; scrub the
hit by rewording (zero behavior change), never by narrowing the set.

Standard library only. Runnable directly
(``python3 tests/unit/test_leakage_guard.py``) or under pytest.
"""

import ast
import hashlib
import json
import os
import re
import struct
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SDIST_PIN = os.path.join(
    REPO_ROOT, "tests", "packaging", "sdist-members.json"
)
WHEEL_CONTRACT = os.path.join(
    REPO_ROOT, "tests", "packaging", "test_wheel_contents.py"
)

# (label, pattern). Labels stay symbolic so this file names no
# internal ID literally.
PATTERNS = (
    ("work-package ID", re.compile(r"WP-\d")),
    ("stage ID", re.compile(r"\bM-[A-Z]{2,}[A-Z0-9-]*")),
    ("finding ID", re.compile(r"\bF-\d{3}\b")),
    (
        "private workspace path",
        re.compile(r"mojobpf-ws|/home/user\b|\.worktrees/"),
    ),
)

# Pinned build-generated sdist members that are untracked by
# design: anything else dropping out of the shipped set fails
# for review instead of going silently unscanned.
PINNED_GENERATED_DROPPED = (
    "PKG-INFO",
    "setup.cfg",
    "src/mojobpf.egg-info/PKG-INFO",
    "src/mojobpf.egg-info/SOURCES.txt",
    "src/mojobpf.egg-info/dependency_links.txt",
    "src/mojobpf.egg-info/entry_points.txt",
    "src/mojobpf.egg-info/top_level.txt",
)


# Files the guard must cover for the verdict to mean anything: if a
# manifest stops listing one of these, the guard fails closed instead
# of silently narrowing.
REQUIRED_SHIPPED = (
    "src/mojobpf/cli.py",
    "compiler/audit.py",
    "src/mojobpf/resources/adapter/audit.py",
    "MANIFEST.in",
)


_PIN_NAMES = ("PINNED_PAYLOAD", "PINNED_SCHEMA_DATA")

# ``type X = ...`` exists only on 3.12+; None below, where the
# statement is a syntax error and there is nothing to refuse.
_TYPE_ALIAS = getattr(ast, "TypeAlias", None)


def _read_wheel_pins(path):
    """Read the wheel contract pins from ``path``.

    Exactly one plain module-level assignment per pin:
    nested assignments never override it, duplicates fail
    instead of silently winning, non-literal values fail
    as AssertionError, and any other rebinding form
    (annotated, augmented, def/class, import including
    star, loop/with/except targets, walrus, match
    captures, ``del``, ``type`` aliases) anywhere outside
    nested local scopes fails loudly instead of diverging
    from the runtime value. A ``global`` pin declaration
    inside a nested scope fails too. Unreadable files
    (missing, undecodable, unparsable) fail as
    AssertionError, never as a bare traceback.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), path)
    except (OSError, SyntaxError, ValueError) as exc:
        raise AssertionError(
            "wheel contract unreadable: %s (%s)" % (path, exc)
        )
    pinset = set(_PIN_NAMES)
    pins = {}
    accepted = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id in pinset
            ):
                if target.id in pins:
                    raise AssertionError(
                        "duplicate wheel pin %r in %s"
                        % (target.id, path)
                    )
                try:
                    pins[target.id] = ast.literal_eval(
                        node.value
                    )
                except (ValueError, TypeError, SyntaxError):
                    raise AssertionError(
                        "non-literal wheel pin %r in %s"
                        % (target.id, path)
                    )
                accepted.add(id(target))
    comp_targets = set()
    for sub in ast.walk(tree):
        if isinstance(sub, ast.comprehension):
            for inner in ast.walk(sub.target):
                comp_targets.add(id(inner))

    def _refuse(what, name):
        raise AssertionError(
            "wheel pin %r %s in %s" % (name, what, path)
        )

    def _refuse_targets(targets):
        for target in targets:
            for found in ast.walk(target):
                if (
                    isinstance(found, ast.Name)
                    and found.id in pinset
                    and id(found) not in accepted
                ):
                    _refuse("reassigned", found.id)

    def _scan(root):
        stack = [root]
        while stack:
            sub = stack.pop()
            if id(sub) in comp_targets:
                continue
            if isinstance(
                sub,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Lambda,
                ),
            ):
                for inner in ast.walk(sub):
                    if (
                        isinstance(inner, ast.Global)
                        and set(inner.names) & pinset
                    ):
                        _refuse(
                            "rebound via global",
                            sorted(
                                set(inner.names) & pinset
                            )[0],
                        )
                if isinstance(
                    sub,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.ClassDef,
                    ),
                ):
                    if sub.name in pinset:
                        _refuse("redefined", sub.name)
                    parts = list(sub.decorator_list)
                    if not isinstance(sub, ast.ClassDef):
                        parts.extend(sub.args.defaults)
                        parts.extend(
                            default
                            for default in sub.args.kw_defaults
                            if default is not None
                        )
                    else:
                        parts.extend(sub.bases)
                        parts.extend(
                            keyword.value
                            for keyword in sub.keywords
                        )
                else:
                    parts = list(sub.args.defaults)
                    parts.extend(
                        default
                        for default in sub.args.kw_defaults
                        if default is not None
                    )
                stack.extend(parts)
                continue
            if isinstance(sub, ast.Assign):
                _refuse_targets(sub.targets)
            elif isinstance(sub, ast.AnnAssign):
                if sub.value is not None:
                    _refuse_targets([sub.target])
            elif isinstance(sub, ast.AugAssign):
                _refuse_targets([sub.target])
            elif isinstance(sub, ast.NamedExpr):
                _refuse_targets([sub.target])
            elif isinstance(sub, (ast.For, ast.AsyncFor)):
                _refuse_targets([sub.target])
            elif isinstance(sub, ast.With):
                _refuse_targets(
                    [
                        item.optional_vars
                        for item in sub.items
                        if item.optional_vars is not None
                    ]
                )
            elif isinstance(sub, ast.ExceptHandler):
                if sub.name in pinset:
                    _refuse("rebound", sub.name)
            elif isinstance(sub, ast.Delete):
                _refuse_targets(sub.targets)
            elif isinstance(sub, (ast.Import, ast.ImportFrom)):
                for entry in sub.names:
                    if entry.name == "*":
                        # A star import may rebind any pin at
                        # runtime (whatever the module
                        # exports), so any star import fails.
                        raise AssertionError(
                            "star import in %s" % path
                        )
                    bound = entry.asname or entry.name.split(
                        ".", 1
                    )[0]
                    if bound in pinset:
                        _refuse("rebound", bound)
            elif _TYPE_ALIAS is not None and isinstance(
                sub, _TYPE_ALIAS
            ):
                if (
                    isinstance(sub.name, ast.Name)
                    and sub.name.id in pinset
                ):
                    _refuse("redefined", sub.name.id)
            elif isinstance(
                sub, (ast.MatchAs, ast.MatchStar)
            ):
                if sub.name in pinset:
                    _refuse("rebound", sub.name)
            elif isinstance(sub, ast.MatchMapping):
                if sub.rest in pinset:
                    _refuse("rebound", sub.rest)
            stack.extend(ast.iter_child_nodes(sub))

    for node in tree.body:
        _scan(node)
    if set(pins) != pinset:
        raise AssertionError(
            "wheel contract pins unreadable in %s" % path
        )
    return pins


def _validate_schema_source(source):
    """Validate a pinned schema source path.

    The source joins under ``schemas/`` on this Linux
    host, so only ``..`` segments (plus absolute, empty,
    NUL-bearing, non-string, and non-json spellings) can
    escape; bare ``..foo``/``.`` names are harmless and
    stay allowed.
    """
    if (
        not isinstance(source, str)
        or not source
        or "\x00" in source
        or source.startswith("/")
        or ".." in source.split("/")
        or not source.endswith(".json")
    ):
        raise AssertionError(
            "unexpected wheel schema source: %r" % (source,)
        )


def _wheel_tree_paths():
    """Map the wheel payload pin back to tree-relative paths.

    Pins are literals, not necessarily strings: mistyped
    pins fail as AssertionError here, never as a
    TypeError/AttributeError traceback downstream.
    """
    pins = _read_wheel_pins(WHEEL_CONTRACT)
    paths = set()
    payload = pins["PINNED_PAYLOAD"]
    if not isinstance(payload, (tuple, list)):
        raise AssertionError(
            "unexpected wheel payload pin: %r" % (payload,)
        )
    for name in payload:
        if not isinstance(name, str):
            raise AssertionError(
                "unexpected wheel payload entry: %r" % (name,)
            )
        if not name.startswith("mojobpf/"):
            raise AssertionError("unexpected wheel payload entry: %r" % name)
        paths.add("src/" + name)
    schemas = pins["PINNED_SCHEMA_DATA"]
    if not isinstance(schemas, (tuple, list)):
        raise AssertionError(
            "unexpected wheel schema pin: %r" % (schemas,)
        )
    for entry in schemas:
        if (
            not isinstance(entry, (tuple, list))
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
        ):
            raise AssertionError(
                "unexpected wheel schema entry: %r" % (entry,)
            )
        source, shipped = entry
        _validate_schema_source(source)
        if (
            "/" in shipped
            or not shipped.endswith(".json")
        ):
            raise AssertionError(
                "unexpected wheel schema entry: %r" % (entry,)
            )
        paths.add("schemas/" + source)
    return paths


def shipped_tracked_files():
    """Return the sorted shipped set: manifests union, tracked only."""
    try:
        with open(SDIST_PIN, encoding="utf-8") as handle:
            members = json.load(handle)
    except (OSError, ValueError) as exc:
        raise AssertionError(
            "sdist member pin unreadable: %s (%s)"
            % (SDIST_PIN, exc)
        )
    if not isinstance(members, list) or not members:
        raise AssertionError("sdist member pin is empty: %s" % SDIST_PIN)
    tracked = _tracked_files_from_index(REPO_ROOT)
    pinned = set(members) | _wheel_tree_paths()
    dropped = pinned - tracked
    if dropped != set(PINNED_GENERATED_DROPPED):
        raise AssertionError(
            "unpinned shipped-set drop: %s"
            % sorted(dropped ^ set(PINNED_GENERATED_DROPPED))
        )
    shipped = pinned & tracked
    if not shipped:
        raise AssertionError("shipped tracked set is empty")
    return sorted(shipped)


def scan_shipped():
    """Grep the shipped set; return (hits, scanned, skipped)."""
    hits = []
    scanned = 0
    skipped = 0
    for name in shipped_tracked_files():
        path = os.path.join(REPO_ROOT, name)
        try:
            with open(path, "rb") as handle:
                body = handle.read()
        except (OSError, ValueError) as exc:
            raise AssertionError("shipped member unreadable: %s (%s)" % (name, exc))
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        scanned += 1
        for number, line in enumerate(text.splitlines(), 1):
            for label, pattern in PATTERNS:
                if pattern.search(line):
                    hits.append((name, number, label, line.strip()))
                    break
    return hits, scanned, skipped


def _encode_git_index(entries, version=2, extensions=()):
    # Minimal valid v2 index bytes for reader tests: fixed stat
    # fields, exact path records, real trailing checksum.
    parts = [b"DIRC", struct.pack(">II", version, len(entries))]
    for path in entries:
        parts.append(
            struct.pack(
                ">IIIIIIIIII20sH", 0, 0, 0, 0, 0, 0, 0o100644,
                0, 0, 0, b"\x00" * 20, len(path) & 0xFFF,
            )
        )
        parts.append(path + b"\x00")
        pad = (8 - ((62 + len(path) + 1) % 8)) % 8
        parts.append(b"\x00" * pad)
    for sig, payload in extensions:
        parts.append(sig + struct.pack(">I", len(payload)) + payload)
    body = b"".join(parts)
    return body + hashlib.sha1(body).digest()  # git index uses SHA-1


def _expect_index_failure(raw, fragment):
    with tempfile.TemporaryDirectory(
        prefix="leakage-index-"
    ) as parent:
        path = os.path.join(parent, "index")
        with open(path, "wb") as handle:
            handle.write(raw)
        try:
            _read_git_index_file(path)
        except AssertionError as exc:
            assert fragment in str(exc), exc
        else:
            raise AssertionError(
                "corrupt index accepted: %s" % fragment
            )


def test_git_index_reader_returns_live_tracked_set():
    tracked = _tracked_files_from_index(REPO_ROOT)
    assert isinstance(tracked, set), type(tracked)
    assert tracked, "tracked set is empty"
    for name in ("README.md", "pyproject.toml", "tests/unit/test_leakage_guard.py"):
        assert name in tracked, name
    missing = [
        name for name in tracked
        if not os.path.isfile(os.path.join(REPO_ROOT, name))
    ]
    assert not missing, missing[:5]


def test_git_index_reader_parses_minimal_index():
    with tempfile.TemporaryDirectory(
        prefix="leakage-index-"
    ) as parent:
        path = os.path.join(parent, "index")
        with open(path, "wb") as handle:
            handle.write(
                _encode_git_index([b"a.py", b"sub/b.md"])
            )
        assert _read_git_index_file(path) == {
            "a.py", "sub/b.md",
        }


def test_git_index_reader_rejects_bad_magic():
    raw = _encode_git_index([b"a.py"])
    _expect_index_failure(b"XXXX" + raw[4:], "bad magic")


def test_git_index_reader_rejects_truncation():
    raw = _encode_git_index([b"a.py", b"b.py"])
    _expect_index_failure(raw[:20], "truncated index")
    inflated = (
        raw[:8] + struct.pack(">I", 9) + raw[12:-20]
    )
    inflated += hashlib.sha1(inflated).digest()
    _expect_index_failure(inflated, "truncated entry")


def test_git_index_reader_rejects_bad_version():
    raw = _encode_git_index([b"a.py"], version=3)
    _expect_index_failure(raw, "version 3")


def test_git_index_reader_rejects_bad_checksum():
    raw = bytearray(_encode_git_index([b"a.py"]))
    raw[-1] ^= 0xFF
    _expect_index_failure(bytes(raw), "checksum")


def test_git_index_reader_rejects_split_link():
    raw = _encode_git_index(
        [], extensions=[(b"link", b"\x00" * 20)]
    )
    _expect_index_failure(raw, "split")


def test_git_index_reader_rejects_unknown_required_extension():
    # Git refuses an index carrying an unknown extension
    # whose signature does not start with A-Z ("index uses
    # abcd extension, which we do not understand", exit 128
    # on git 2.56.0); the gate must refuse it too instead
    # of certifying paths from metadata git will not
    # interpret. Verified against real git on crafted,
    # checksummed v2 indexes.
    raw = _encode_git_index(
        [b"a.py"], extensions=[(b"abcd", b"")]
    )
    _expect_index_failure(raw, "required extension")


def test_git_index_reader_skips_unknown_optional_extension():
    # The matching git-compatible pin: an unknown extension with
    # an A-Z signature is ignored by git ("ignoring ABCD
    # extension", exit 0), so the reader skips it and still
    # returns the entry paths.
    with tempfile.TemporaryDirectory(
        prefix="leakage-index-"
    ) as parent:
        path = os.path.join(parent, "index")
        with open(path, "wb") as handle:
            handle.write(
                _encode_git_index(
                    [b"a.py"], extensions=[(b"ABCD", b"")]
                )
            )
        assert _read_git_index_file(path) == {"a.py"}


def test_git_index_reader_rejects_missing_file():
    with tempfile.TemporaryDirectory(
        prefix="leakage-index-"
    ) as parent:
        try:
            _read_git_index_file(os.path.join(parent, "absent"))
        except AssertionError as exc:
            assert "cannot derive tracked files" in str(exc), exc
        else:
            raise AssertionError("missing index accepted")


def test_git_index_reader_rejects_non_utf8_path():
    raw = _encode_git_index([b"\xff\xfe.py"])
    _expect_index_failure(raw, "utf-8")


def test_git_index_reader_resolves_pointer_file():
    with tempfile.TemporaryDirectory(
        prefix="leakage-gitdir-"
    ) as parent:
        target = os.path.join(parent, "real-git")
        os.makedirs(target)
        with open(os.path.join(target, "index"), "wb") as handle:
            handle.write(_encode_git_index([b"a.py"]))
        pointer = os.path.join(parent, "linked")
        with open(pointer, "w", encoding="utf-8") as handle:
            handle.write("gitdir: %s\n" % target)
        assert _resolve_git_dir(pointer) == target
        nested = os.path.join(parent, "sub", "linked")
        os.makedirs(os.path.dirname(nested))
        with open(nested, "w", encoding="utf-8") as handle:
            handle.write("gitdir: ../real-git\n")
        assert _resolve_git_dir(nested) == target


def _resolve_git_dir(git_path):
    # .git is a directory in plain checkouts and a pointer file
    # (`gitdir: <path>`) in linked worktrees. Either form resolves
    # to the directory holding the index; anything else fails.
    # The layout comes from git itself, never repo content.
    if os.path.isdir(git_path):
        return os.path.normpath(git_path)
    try:
        with open(git_path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise AssertionError(
            "cannot derive tracked files (unreadable git metadata: %s)"
            % exc
        )
    if not text.startswith("gitdir: "):
        raise AssertionError(
            "cannot derive tracked files (not a git directory: %s)"
            % git_path
        )
    target = text[len("gitdir: "):].splitlines()[0].strip()
    if not target:
        raise AssertionError(
            "cannot derive tracked files (empty git pointer: %s)"
            % git_path
        )
    if not os.path.isabs(target):
        target = os.path.join(
            os.path.dirname(os.path.abspath(git_path)), target
        )
    target = os.path.normpath(target)
    if not os.path.isdir(target):
        raise AssertionError(
            "cannot derive tracked files (dangling git pointer: %s)"
            % git_path
        )
    return target


def _read_git_index_file(index_path):
    # Tracked paths from a v2 git index, without spawning git
    # (the lane guard refuses delegating launchers). Only the
    # plain v2 layout is accepted: any other version, a bad
    # checksum, truncated records, a split-index link, or an
    # unknown required (non-A-Z) extension fails closed,
    # exactly like an unreadable file. Unknown A-Z extensions
    # are optional: git ignores them, so the reader skips them.
    try:
        with open(index_path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise AssertionError(
            "cannot derive tracked files (unreadable index: %s)" % exc
        )
    if len(raw) < 12 or raw[:4] != b"DIRC":
        raise AssertionError(
            "cannot derive tracked files (bad magic in %s)"
            % index_path
        )
    version, count = struct.unpack(">II", raw[4:12])
    if version != 2:
        raise AssertionError(
            "cannot derive tracked files (unsupported index "
            "version %d in %s)" % (version, index_path)
        )
    if len(raw) < 32:
        raise AssertionError(
            "cannot derive tracked files (truncated index %s)"
            % index_path
        )
    body, want = raw[:-20], raw[-20:]
    if hashlib.sha1(body).digest() != want:  # SHA-1 per index format
        raise AssertionError(
            "cannot derive tracked files (checksum mismatch in %s)"
            % index_path
        )
    pos = 12
    paths = set()
    for _ in range(count):
        start = pos
        if start + 62 > len(body):
            raise AssertionError(
                "cannot derive tracked files (truncated entry in %s)"
                % index_path
            )
        flags = struct.unpack(">H", body[start + 60:start + 62])[0]
        pos = start + 62
        try:
            end = body.index(b"\x00", pos)
        except ValueError:
            raise AssertionError(
                "cannot derive tracked files (unterminated path in %s)"
                % index_path
            )
        path = body[pos:end]
        if flags & 0xFFF != 0xFFF and flags & 0xFFF != len(path):
            raise AssertionError(
                "cannot derive tracked files (path length mismatch in %s)"
                % index_path
            )
        try:
            paths.add(path.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise AssertionError(
                "cannot derive tracked files (non utf-8 path in %s: %s)"
                % (index_path, exc)
            )
        total = 62 + len(path) + 1
        pos = start + total + (8 - total % 8) % 8
        if pos > len(body):
            raise AssertionError(
                "cannot derive tracked files (truncated entry in %s)"
                % index_path
            )
    while pos < len(body):
        if pos + 8 > len(body):
            raise AssertionError(
                "cannot derive tracked files (truncated extension in %s)"
                % index_path
            )
        sig = body[pos:pos + 4]
        (size,) = struct.unpack(">I", body[pos + 4:pos + 8])
        if sig == b"link":
            raise AssertionError(
                "cannot derive tracked files (split-index link in %s)"
                % index_path
            )
        if not b"A"[0] <= sig[0] <= b"Z"[0]:
            # A non-A-Z signature is a required extension: git
            # refuses an index carrying one it does not know, so
            # the gate refuses too instead of certifying paths
            # from metadata git will not interpret. A-Z
            # signatures are optional (git ignores unknowns).
            raise AssertionError(
                "cannot derive tracked files (unrecognized "
                "required extension %r in %s)"
                % (sig, index_path)
            )
        pos += 8 + size
        if pos > len(body):
            raise AssertionError(
                "cannot derive tracked files (truncated extension in %s)"
                % index_path
            )
    if pos != len(body):
        raise AssertionError(
            "cannot derive tracked files (trailing bytes in %s)"
            % index_path
        )
    return paths


def _tracked_files_from_index(repo_root):
    return _read_git_index_file(
        os.path.join(_resolve_git_dir(os.path.join(repo_root, ".git")), "index")
    )


def test_shipped_set_covers_scrubbed_files():
    shipped = set(shipped_tracked_files())
    missing = [name for name in REQUIRED_SHIPPED if name not in shipped]
    assert not missing, "guard lost coverage of: %s" % (", ".join(missing),)
    print("PASS shipped set covers %d files" % len(shipped))


def test_unexpected_untracked_drop_fails_closed():
    # A pinned file that is not git-tracked must be a pinned
    # build-generated drop; anything else fails here instead
    # of going silently unscanned.
    with tempfile.TemporaryDirectory(
        prefix="leakage-drop-"
    ) as parent:
        members_path = os.path.join(parent, "sdist-members.json")
        with open(members_path, "w", encoding="utf-8") as handle:
            json.dump(
                ["setup.cfg", "zz-unexpected-drop.txt"], handle
            )
        old = globals()["SDIST_PIN"]
        globals()["SDIST_PIN"] = members_path
        try:
            try:
                shipped_tracked_files()
            except AssertionError as exc:
                # Both directions: the extra drop and a
                # missing pinned drop are named, so an
                # extra-only (missing-blind) check fails here.
                assert "zz-unexpected-drop.txt" in str(exc), exc
                assert "PKG-INFO" in str(exc), exc
            else:
                raise AssertionError(
                    "unexpected drop went unscanned"
                )
        finally:
            globals()["SDIST_PIN"] = old


def test_wheel_pin_reader_ignores_nested_and_refuses_duplicates():
    # A nested pin assignment must not override the
    # module-level pin, and a duplicate module-level
    # assignment must fail instead of silently winning.
    probe = (
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "PINNED_SCHEMA_DATA = "
        "((\"s.schema.json\", \"s.schema.json\"),)\n"
        "def factory():\n"
        "    PINNED_PAYLOAD = (\"evil\",)\n"
    )
    with tempfile.TemporaryDirectory(
        prefix="leakage-pin-"
    ) as parent:
        path = os.path.join(parent, "probe_contract.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(probe)
        assert _read_wheel_pins(path) == {
            "PINNED_PAYLOAD": ("mojobpf/a.py",),
            "PINNED_SCHEMA_DATA": (
                ("s.schema.json", "s.schema.json"),
            ),
        }
        dup_path = os.path.join(parent, "dup_contract.py")
        with open(dup_path, "w", encoding="utf-8") as handle:
            handle.write(
                probe + "PINNED_PAYLOAD = (\"mojobpf/b.py\",)\n"
            )
        try:
            _read_wheel_pins(dup_path)
        except AssertionError:
            pass
        else:
            raise AssertionError("duplicate pin accepted")


def test_wheel_pin_reader_refuses_rebinding_forms():
    # Only a single plain module-level assignment per pin
    # is accepted: any other rebinding form (annotated,
    # augmented, def/class, import including star, del,
    # match captures, global declarations, conditional
    # assigns, loop/with/except targets, walrus including
    # default/decorator positions, and ``type`` aliases)
    # fails loudly instead of silently diverging from the
    # runtime value.
    rebinding = (
        "PINNED_PAYLOAD: tuple = (\"mojobpf/a.py\",)\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "PINNED_PAYLOAD += (\"mojobpf/b.py\",)\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "def PINNED_PAYLOAD():\n"
        "    pass\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "class PINNED_PAYLOAD:\n"
        "    pass\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "import os as PINNED_PAYLOAD\n",
        "from os import path as PINNED_PAYLOAD\n"
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "for PINNED_PAYLOAD in []:\n"
        "    pass\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "with open(\"x\") as PINNED_PAYLOAD:\n"
        "    pass\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "try:\n"
        "    pass\n"
        "except ValueError as PINNED_PAYLOAD:\n"
        "    pass\n",
        "y = (PINNED_PAYLOAD := (\"mojobpf/evil.py\",))\n"
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "from os import *\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "del PINNED_PAYLOAD\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "match command:\n"
        "    case PINNED_PAYLOAD:\n"
        "        pass\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "def factory():\n"
        "    global PINNED_PAYLOAD\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "if cond:\n"
        "    PINNED_PAYLOAD = (\"mojobpf/evil.py\",)\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "def factory(x=(PINNED_PAYLOAD := (\"mojobpf/evil.py\",))):\n"
        "    pass\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "@dec(PINNED_PAYLOAD := (\"mojobpf/evil.py\",))\n"
        "def factory():\n"
        "    pass\n",
    )
    if _TYPE_ALIAS is not None:
        # Below 3.12 the statement is a syntax error, so
        # only pin the refusal where it parses.
        rebinding += (
            "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
            "type PINNED_PAYLOAD = tuple\n",
        )
    schema = (
        "PINNED_SCHEMA_DATA = "
        "((\"s.schema.json\", \"s.schema.json\"),)\n"
    )
    with tempfile.TemporaryDirectory(
        prefix="leakage-rebind-"
    ) as parent:
        for index, body in enumerate(rebinding):
            path = os.path.join(
                parent, "rebind_%d.py" % index
            )
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body + schema)
            try:
                _read_wheel_pins(path)
            except AssertionError:
                pass
            else:
                raise AssertionError(
                    "rebinding form accepted: %r" % (body,)
                )


def test_wheel_pin_reader_ignores_comprehension_targets():
    # A comprehension loop variable never rebinds the
    # module global (its scope is the comprehension), so a
    # pin-named loop target is accepted -- and a runtime
    # exec proves the pin value survives it.
    probe = (
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "PINNED_SCHEMA_DATA = "
        "((\"s.schema.json\", \"s.schema.json\"),)\n"
        "seen = [PINNED_PAYLOAD for PINNED_PAYLOAD in [1]]\n"
    )
    with tempfile.TemporaryDirectory(
        prefix="leakage-comp-"
    ) as parent:
        path = os.path.join(parent, "comp_contract.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(probe)
        assert _read_wheel_pins(path) == {
            "PINNED_PAYLOAD": ("mojobpf/a.py",),
            "PINNED_SCHEMA_DATA": (
                ("s.schema.json", "s.schema.json"),
            ),
        }
        namespace = {}
        exec(probe, namespace)
        assert namespace["PINNED_PAYLOAD"] == (
            "mojobpf/a.py",
        ), namespace


def test_wheel_pin_reader_multi_target_and_non_literal():
    # A shared multi-target assignment binds every pin
    # name; a non-literal value fails as AssertionError
    # (never a bare literal_eval error).
    with tempfile.TemporaryDirectory(
        prefix="leakage-pinform-"
    ) as parent:
        multi = os.path.join(parent, "multi_contract.py")
        with open(multi, "w", encoding="utf-8") as handle:
            handle.write(
                "PINNED_PAYLOAD = PINNED_SCHEMA_DATA = "
                "(\"shared\",)\n"
            )
        assert _read_wheel_pins(multi) == {
            "PINNED_PAYLOAD": ("shared",),
            "PINNED_SCHEMA_DATA": ("shared",),
        }
        dynamic = os.path.join(parent, "dyn_contract.py")
        with open(dynamic, "w", encoding="utf-8") as handle:
            handle.write(
                "PINNED_PAYLOAD = list((\"mojobpf/a.py\",))\n"
                "PINNED_SCHEMA_DATA = "
                "((\"s.schema.json\", \"s.schema.json\"),)\n"
            )
        try:
            _read_wheel_pins(dynamic)
        except AssertionError:
            pass
        else:
            raise AssertionError("non-literal pin accepted")


def test_wheel_tree_paths_rejects_non_string_pins():
    # Pin values are literals, not necessarily strings: an
    # int payload, a tuple-of-int payload, or a non-list
    # schema pin must fail as AssertionError here, never
    # as a TypeError/AttributeError traceback downstream.
    bodies = (
        "PINNED_PAYLOAD = 3\n"
        "PINNED_SCHEMA_DATA = "
        "((\"s.schema.json\", \"s.schema.json\"),)\n",
        "PINNED_PAYLOAD = (3,)\n"
        "PINNED_SCHEMA_DATA = "
        "((\"s.schema.json\", \"s.schema.json\"),)\n",
        "PINNED_PAYLOAD = (\"mojobpf/a.py\",)\n"
        "PINNED_SCHEMA_DATA = 3\n",
    )
    with tempfile.TemporaryDirectory(
        prefix="leakage-pintype-"
    ) as parent:
        old = globals()["WHEEL_CONTRACT"]
        try:
            for index, body in enumerate(bodies):
                path = os.path.join(
                    parent, "pins_%d.py" % index
                )
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(body)
                globals()["WHEEL_CONTRACT"] = path
                try:
                    _wheel_tree_paths()
                except AssertionError:
                    pass
                else:
                    raise AssertionError(
                        "non-string pins accepted: %r" % (body,)
                    )
        finally:
            globals()["WHEEL_CONTRACT"] = old


def test_wheel_pin_reader_unreadable_fails_closed():
    # A missing contract or an unparsable one fails as
    # AssertionError, never as a bare OSError/SyntaxError
    # traceback.
    with tempfile.TemporaryDirectory(
        prefix="leakage-unread-"
    ) as parent:
        missing = os.path.join(parent, "absent.py")
        try:
            _read_wheel_pins(missing)
        except AssertionError as exc:
            assert "absent.py" in str(exc), exc
        else:
            raise AssertionError("missing contract accepted")
        broken = os.path.join(parent, "broken.py")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write("def broken(:\n")
        try:
            _read_wheel_pins(broken)
        except AssertionError as exc:
            assert "broken.py" in str(exc), exc
        else:
            raise AssertionError("unparsable contract accepted")


def test_shipped_tracked_files_unreadable_manifest_fails_closed():
    # A missing or corrupt sdist manifest fails as
    # AssertionError, never as a bare OSError/ValueError
    # traceback.
    with tempfile.TemporaryDirectory(
        prefix="leakage-manifest-"
    ) as parent:
        old = globals()["SDIST_PIN"]
        try:
            globals()["SDIST_PIN"] = os.path.join(
                parent, "absent.json"
            )
            try:
                shipped_tracked_files()
            except AssertionError:
                pass
            else:
                raise AssertionError(
                    "missing manifest accepted"
                )
            corrupt = os.path.join(parent, "corrupt.json")
            with open(corrupt, "w", encoding="utf-8") as handle:
                handle.write("{oops\n")
            globals()["SDIST_PIN"] = corrupt
            try:
                shipped_tracked_files()
            except AssertionError:
                pass
            else:
                raise AssertionError(
                    "corrupt manifest accepted"
                )
        finally:
            globals()["SDIST_PIN"] = old


def test_schema_source_validation_rejects_escapes():
    # Pinned schema sources must stay inside schemas/:
    # only ".." path segments escape, so only they (plus
    # absolute/empty/NUL/non-string/non-json spellings)
    # fail. Harmless doppelgangers ("..foo", ".") stay
    # allowed.
    for good in (
        "a.schema.json",
        "sub/dir/b.schema.json",
        "..foo.json",
        "a/./b.schema.json",
    ):
        _validate_schema_source(good)
    for bad in (
        "../x.json",
        "a/../../x.json",
        "/abs.json",
        "",
        "x.txt",
        "a\x00.json",
        None,
        3,
    ):
        try:
            _validate_schema_source(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError(
                "bad schema source accepted: %r" % (bad,)
            )


def test_scan_shipped_nul_member_fails_closed():
    # A NUL member path raises ValueError from open (not
    # OSError): the scan must account it as FAIL, never as
    # a traceback.
    old = globals()["shipped_tracked_files"]
    globals()["shipped_tracked_files"] = lambda: ["a\x00.json"]
    try:
        try:
            scan_shipped()
        except AssertionError as exc:
            assert "a\x00.json" in str(exc), exc
        else:
            raise AssertionError("NUL member not failed closed")
    finally:
        globals()["shipped_tracked_files"] = old


def test_tracked_sources_carry_spdx_headers():
    # licensing.md: every first-party source file carries an SPDX
    # header. Sweep all tracked .py/.mojo/.md (shipped and tests
    # alike); the marker must sit in the first five lines, so a
    # fixture string deep in a test body cannot satisfy the file.
    # Same set `git ls-files *.py *.mojo *.md` would list
    # (slash-free patterns match basenames at any depth):
    # tracked paths with those suffixes, without spawning git.
    names = sorted(
        name
        for name in _tracked_files_from_index(REPO_ROOT)
        if name.endswith((".py", ".mojo", ".md"))
    )
    assert names, "tracked source set is empty"
    misses = []
    for name in names:
        path = os.path.join(REPO_ROOT, name)
        with open(path, encoding="utf-8") as handle:
            head = "".join(
                line for _, line in zip(range(5), handle)
            )
        if "SPDX-License-Identifier" not in head:
            misses.append(name)
    assert not misses, "missing SPDX header: %s" % ", ".join(misses)
    print("PASS SPDX headers in %d tracked sources" % len(names))


def test_patterns_match_known_samples():
    # Positive control: every pattern matches its sample
    # form, so the clean-tree test cannot pass vacuously
    # if a regex breaks. Samples live in this unshipped
    # test file, never in the scanned set.
    samples = {
        "work-package ID": "see WP-1 for context",
        "stage ID": "stage M-AB done",
        "finding ID": "finding F-001 closed",
        "private workspace path": "checked out under mojobpf-ws",
    }
    assert sorted(label for label, _ in PATTERNS) == sorted(
        samples
    )
    for label, pattern in PATTERNS:
        assert pattern.search(samples[label]), label


def test_no_internal_ids_or_private_paths_in_shipped_files():
    hits, scanned, skipped = scan_shipped()
    assert scanned > 200, "guard scanned too few files: %d" % scanned
    if hits:
        lines = ["%s:%d [%s]: %s" % (name, number, label, text[:120])
                 for name, number, label, text in hits]
        raise AssertionError(
            "%d leakage hit(s) in %d shipped file(s) "
            "(scanned %d, skipped %d binary):\n%s"
            % (len(hits), len({name for name, _, _, _ in hits}),
               scanned, skipped, "\n".join(lines))
        )
    print("PASS no leakage in %d shipped files (skipped %d binary)"
          % (scanned, skipped))


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    checks = sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    )
    for name, func in checks:
        try:
            func()
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
    if failures:
        return 1
    print("leakage guard: %d checks pass" % len(checks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
