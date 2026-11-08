# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Leakage guard: shipped files carry no internal IDs or private paths.

The shipped set is derived, never guessed: the union of the sdist
member pin (``tests/packaging/sdist-members.json``) and the wheel
payload pin (``PINNED_PAYLOAD``/``PINNED_SCHEMA_DATA`` in
``tests/packaging/test_wheel_contents.py``, mapped back to tree
paths), intersected with ``git ls-files`` tracked files. Every
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

# Files the guard must cover for the verdict to mean anything: if a
# manifest stops listing one of these, the guard fails closed instead
# of silently narrowing.
REQUIRED_SHIPPED = (
    "src/mojobpf/cli.py",
    "compiler/audit.py",
    "src/mojobpf/resources/adapter/audit.py",
    "MANIFEST.in",
)


def _wheel_tree_paths():
    """Map the wheel payload pin back to tree-relative paths."""
    with open(WHEEL_CONTRACT, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), WHEEL_CONTRACT)
    pins = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id in ("PINNED_PAYLOAD", "PINNED_SCHEMA_DATA")
            ):
                pins[target.id] = ast.literal_eval(node.value)
    if set(pins) != {"PINNED_PAYLOAD", "PINNED_SCHEMA_DATA"}:
        raise AssertionError(
            "wheel contract pins unreadable in %s" % WHEEL_CONTRACT
        )
    paths = set()
    for name in pins["PINNED_PAYLOAD"]:
        if not name.startswith("mojobpf/"):
            raise AssertionError("unexpected wheel payload entry: %r" % name)
        paths.add("src/" + name)
    for name in pins["PINNED_SCHEMA_DATA"]:
        if "/" in name or not name.endswith(".json"):
            raise AssertionError("unexpected wheel schema entry: %r" % name)
        paths.add("schemas/" + name)
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
    shipped = (set(members) | _wheel_tree_paths()) & tracked
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
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
    if failures:
        return 1
    print("leakage guard: 2 checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
