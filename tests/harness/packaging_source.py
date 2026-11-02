# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Small owned-source fixtures for offline packaging tests.

An explicit local .git identity selects real Git membership. Exports and
archives without one use only their own files, even beneath another repository.
Development residue is never a source input; no Git metadata is copied.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess


_RESIDUE = frozenset({
    ".git", ".pixi", ".venv", ".worktrees", "build", "dist", "out",
    "artifacts", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".cache", ".coverage", "htmlcov", "coverage.xml",
})


def _excluded(name, *, directory=False):
    parts = PurePosixPath(name).parts
    directories = parts if directory else parts[:-1]
    if any(part in _RESIDUE or part.endswith(".egg-info") for part in directories):
        return True
    if directory or not parts:
        return False
    # A public executable such as tools/build is an input. Only explicit
    # file residue rules apply to the final regular basename.
    final = parts[-1]
    return (final in {".git", ".coverage", "coverage.xml"}
            or final.endswith((".pyc", ".pyo", ".egg-info"))
            or final.startswith(".coverage."))


def _regular_source(source, name):
    relative = PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or any(
            part in {".", ".."} for part in relative.parts) or "\\" in name:
        raise ValueError("unsafe source member: " + repr(name))
    current = source
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as exc:
            raise ValueError("missing source member: " + name) from exc
        if stat.S_ISLNK(mode):
            raise ValueError("source symlink is not a regular input: " + name)
        expected = stat.S_ISREG if index == len(relative.parts) - 1 else stat.S_ISDIR
        if not expected(mode):
            raise ValueError("nonregular source member: " + name)
    if not current.resolve().is_relative_to(source):
        raise ValueError("source member resolves outside source: " + name)
    return current


def _git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True,
                            timeout=120)
    if result.returncode:
        raise ValueError("Git fixture operation failed: " + result.stderr.decode(errors="replace"))
    return result.stdout


def _git_owner(source):
    owner = Path(os.fsdecode(_git(source, "rev-parse", "--show-toplevel")).strip()).resolve()
    if owner != source:
        raise ValueError("Git owner is not the source root: " + str(owner))
    return str(owner)


def source_members(source: Path) -> tuple[str, tuple[str, ...]]:
    source = Path(source)
    if source.is_symlink() or not source.is_dir():
        raise ValueError("source root must be a real directory")
    source = source.resolve()
    if os.path.lexists(source / ".git"):
        _git_owner(source)
        names = {os.fsdecode(name) for name in _git(
            source, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0") if name}
        kind = "git"
    else:
        names = set()
        # os.walk does not follow symlinks. Non-residue symlinks and special
        # inputs fail before a destination can be created.
        for base, directories, files in os.walk(source, followlinks=False):
            kept = []
            for name in sorted(directories):
                path = Path(base) / name
                relative = path.relative_to(source).as_posix()
                if _excluded(relative, directory=True):
                    continue
                if path.is_symlink():
                    raise ValueError("source symlink is not a regular input: " + relative)
                kept.append(name)
            directories[:] = kept
            names.update((Path(base) / name).relative_to(source).as_posix() for name in files)
        kind = "filesystem"
    selected = tuple(sorted(name for name in names if not _excluded(name)))
    for name in selected:
        _regular_source(source, name)
    return kind, selected


def _file_identity(path):
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode):
        raise ValueError("not a regular source file: " + str(path))
    body = path.read_bytes()
    return {"sha256": hashlib.sha256(body).hexdigest(), "size": len(body),
            "mode": stat.S_IMODE(mode)}


def copy_source_tree(source: Path, destination: Path) -> dict:
    source = Path(source)
    destination = Path(destination)
    original = source.resolve()
    target = destination.resolve()
    if target.is_relative_to(original) or original.is_relative_to(target):
        raise ValueError("source and destination overlap")
    if os.path.lexists(destination):
        raise FileExistsError("source destination must be new: " + str(destination))
    kind, members = source_members(source)
    # Validate every member and capture its identity before any write.
    identities = {name: _file_identity(_regular_source(original, name)) for name in members}
    owner = _git_owner(original) if kind == "git" else None
    destination.mkdir(parents=True, exist_ok=False)
    for name in members:
        src = _regular_source(original, name)
        dest = destination / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest, follow_symlinks=False)
        dest.chmod(identities[name]["mode"])
        if _file_identity(dest) != identities[name]:
            raise ValueError("source changed while copying: " + name)
    return {"source_root": str(original), "destination": str(target),
            "origin_kind": kind, "git_top_level": owner, "files": identities}


def initialize_fixture_git(root: Path) -> dict:
    root = Path(root).resolve()
    if os.path.lexists(root / ".git"):
        raise FileExistsError("fixture Git identity already exists")
    kind, members = source_members(root)
    assert kind == "filesystem"
    before = {name: _file_identity(root / name) for name in members}
    _git(root, "init", "--quiet")
    _git(root, "add", "--all")
    owner = _git_owner(root)
    indexed = tuple(sorted(os.fsdecode(name) for name in _git(
        root, "ls-files", "--cached", "-z").split(b"\0") if name))
    if indexed != members:
        raise ValueError("fixture Git index differs from copied source membership")
    if any(_file_identity(root / name) != pin for name, pin in before.items()):
        raise ValueError("fixture Git initialization changed source files")
    return {"git_top_level": owner, "indexed_members": list(indexed), "files": before}


def snapshot_source(root: Path) -> dict:
    """Inventory all entries, including ignored material and a missing root."""
    root = Path(root)
    if not os.path.lexists(root):
        return {"exists": False, "entries": {}}
    entries = {}

    def visit(path, relative):
        info = path.lstat()
        row = {"mode": stat.S_IMODE(info.st_mode)}
        if stat.S_ISLNK(info.st_mode):
            row.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            row["kind"] = "directory"
        elif stat.S_ISREG(info.st_mode):
            row.update(kind="file", **_file_identity(path))
        else:
            row.update(kind="special", type=stat.S_IFMT(info.st_mode))
        entries[relative] = row
        if row["kind"] == "directory":
            for child in sorted(path.iterdir()):
                visit(child, child.relative_to(root).as_posix())

    visit(root, ".")
    return {"exists": True, "entries": entries}
