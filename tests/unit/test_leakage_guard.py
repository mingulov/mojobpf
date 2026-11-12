# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Leakage guard: shipped files carry no internal IDs or private paths.

The shipped set is derived, never guessed: the union of the sdist
member pin (``tests/packaging/sdist-members.json``) and the wheel
payload pin (``PINNED_PAYLOAD``/``PINNED_SCHEMA_DATA`` in
``tests/packaging/test_wheel_contents.py``, mapped back to tree
paths), intersected with ``git ls-files`` tracked files.
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
import json
import os
import re
import subprocess
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


def _read_wheel_pins(path):
    """Read the wheel contract pins from ``path``.

    Exactly one plain module-level assignment per pin:
    nested assignments never override it, duplicates fail
    instead of silently winning, non-literal values fail
    as AssertionError, and any other rebinding form
    (annotated, augmented, def/class, import, loop/with/
    except targets, walrus, match captures, ``del``)
    anywhere outside nested local scopes fails loudly
    instead of diverging from the runtime value. A
    ``global`` pin declaration inside a nested scope
    fails too.
    """
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)
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
                    bound = entry.asname or entry.name.split(
                        ".", 1
                    )[0]
                    if bound in pinset:
                        _refuse("rebound", bound)
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
    non-string, and non-json spellings) can escape; bare
    ``..foo``/``.`` names are harmless and stay allowed.
    """
    if (
        not isinstance(source, str)
        or not source
        or source.startswith("/")
        or ".." in source.split("/")
        or not source.endswith(".json")
    ):
        raise AssertionError(
            "unexpected wheel schema source: %r" % (source,)
        )


def _wheel_tree_paths():
    """Map the wheel payload pin back to tree-relative paths."""
    pins = _read_wheel_pins(WHEEL_CONTRACT)
    paths = set()
    for name in pins["PINNED_PAYLOAD"]:
        if not name.startswith("mojobpf/"):
            raise AssertionError("unexpected wheel payload entry: %r" % name)
        paths.add("src/" + name)
    for entry in pins["PINNED_SCHEMA_DATA"]:
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
    with open(SDIST_PIN, encoding="utf-8") as handle:
        members = json.load(handle)
    if not isinstance(members, list) or not members:
        raise AssertionError("sdist member pin is empty: %s" % SDIST_PIN)
    try:
        raw = subprocess.check_output(
            ["git", "ls-files"], cwd=REPO_ROOT, timeout=120
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AssertionError(
            "cannot derive tracked files (git ls-files failed): %s" % exc
        )
    tracked = set(raw.decode("utf-8").split())
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
        except OSError as exc:
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
    # augmented, def/class, import, loop/with/except
    # targets, walrus) fails loudly instead of silently
    # diverging from the runtime value.
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


def test_schema_source_validation_rejects_escapes():
    # Pinned schema sources must stay inside schemas/:
    # only ".." path segments escape, so only they (plus
    # absolute/empty/non-string/non-json spellings) fail.
    # Harmless doppelgangers ("..foo", ".") stay allowed.
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


def test_tracked_sources_carry_spdx_headers():
    # licensing.md: every first-party source file carries an SPDX
    # header. Sweep all tracked .py/.mojo/.md (shipped and tests
    # alike); the marker must sit in the first five lines, so a
    # fixture string deep in a test body cannot satisfy the file.
    try:
        raw = subprocess.check_output(
            ["git", "ls-files", "*.py", "*.mojo", "*.md"],
            cwd=REPO_ROOT, timeout=120,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AssertionError(
            "cannot derive tracked files (git ls-files failed): %s" % exc
        )
    names = sorted(raw.decode("utf-8").split())
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
