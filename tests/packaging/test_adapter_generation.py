# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Adapter generation equivalence: wheel/sdist/standalone agree.

``compiler/`` is the authoritative adapter source; the packaged
``mojobpf/resources/adapter/`` copies are generated from it. This
suite proves every install lane ships the same generated
implementation:

* the tree's packaged copies equal the ``compiler/`` sources
  (the generation step's input/output identity, via the shared
  mirror table);
* a wheel install, an sdist install, and a standalone source-tree
  install (``pip install`` from each artifact, all offline with
  ``--no-deps --no-build-isolation``) each carry adapter scripts
  byte-identical to the ``compiler/`` sources.

The sdist lane additionally unpacks the archive and checks the
adapter sources travel inside it, so the equivalence holds for
the published artifact itself, not just its install result.

Requires ``pip`` with ``setuptools``/``wheel`` for the running
interpreter. A missing builder is an environment failure, never a
pass. Build residue (``build/``, ``dist/``, ``*.egg-info``) the
lanes create under the checkout is removed afterwards.

Runnable directly (``python3
tests/packaging/test_adapter_generation.py``) or under any
``test_``-style runner. Standard library only.
"""

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import mirror_sync  # noqa: E402

_FIXTURE = {}


class EnvironmentFailure(Exception):
    """The builder needed by this test is missing or broken."""


def _run(argv, cwd, timeout=600):
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except OSError as exc:
        raise EnvironmentFailure(
            "cannot run %s: %s" % (argv[:2], exc)
        ) from None


def _clean_build_residue(preexisting):
    for path in (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "dist"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    ):
        if path not in preexisting and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)


def _build_wheel(parent):
    proc = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "-w",
            parent,
        ],
        REPO_ROOT,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "pip wheel failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    wheels = sorted(
        entry
        for entry in os.listdir(parent)
        if entry.endswith(".whl")
    )
    if len(wheels) != 1:
        raise EnvironmentFailure(
            "expected exactly one wheel, found: %s" % wheels
        )
    return os.path.join(parent, wheels[0])


def _build_sdist(parent):
    # No network, no isolation: invoke the configured build
    # backend's sdist hook in-process through a subprocess pinned
    # to the checkout (pip has no sdist verb of its own).
    script = (
        "import os, sys;"
        "sys.path.insert(0, os.getcwd());"
        "from setuptools import build_meta;"
        "print(build_meta.build_sdist(%r))" % parent
    )
    proc = _run([sys.executable, "-c", script], REPO_ROOT)
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "sdist build failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    archives = sorted(
        entry
        for entry in os.listdir(parent)
        if entry.endswith(".tar.gz")
    )
    if len(archives) != 1:
        raise EnvironmentFailure(
            "expected exactly one sdist, found: %s" % archives
        )
    return os.path.join(parent, archives[0])


def _install(source, target):
    proc = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            source,
            "--no-deps",
            "--no-build-isolation",
            "--no-index",
            "--target",
            target,
        ],
        REPO_ROOT,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "pip install %s failed (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )


def _installed_adapter_bytes(target):
    found = {}
    for shipped, _source in mirror_sync.SYNCED_FILES:
        path = os.path.join(target, *shipped.split("/"))
        if not os.path.isfile(path):
            raise AssertionError(
                "installed adapter script missing: %s" % shipped
            )
        with open(path, "rb") as handle:
            found[shipped] = handle.read()
    return found


def fixture():
    """Build all three lanes once per process; return their bytes."""
    if "lanes" in _FIXTURE:
        return _FIXTURE["lanes"]
    parent = tempfile.mkdtemp(prefix="mojobpf-adapter-gen-")
    _FIXTURE["dir"] = parent
    scratch = (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "dist"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    )
    preexisting = {path for path in scratch if os.path.exists(path)}
    try:
        wheel_dir = os.path.join(parent, "wheelhouse")
        sdist_dir = os.path.join(parent, "dist")
        os.makedirs(wheel_dir)
        os.makedirs(sdist_dir)
        wheel = _build_wheel(wheel_dir)
        sdist = _build_sdist(sdist_dir)
        lanes = {}
        for label, source in (
            ("wheel", wheel),
            ("sdist", sdist),
            ("standalone", "."),
        ):
            target = os.path.join(parent, "install-%s" % label)
            os.makedirs(target)
            _install(source, target)
            lanes[label] = _installed_adapter_bytes(target)
        lanes["sdist_archive"] = sdist
        _FIXTURE["lanes"] = lanes
        return lanes
    finally:
        _clean_build_residue(preexisting)


def _compiler_bytes():
    found = {}
    for shipped, source in mirror_sync.SYNCED_FILES:
        with open(os.path.join(REPO_ROOT, source), "rb") as handle:
            found[shipped] = handle.read()
    return found


def test_tree_copies_match_authoritative_source():
    try:
        checked = mirror_sync.check_tree_mirrors(REPO_ROOT)
    except mirror_sync.MirrorDriftError as exc:
        raise AssertionError(str(exc))
    assert checked == 3, checked


def test_wheel_matches_authoritative_source():
    lanes = fixture()
    want = _compiler_bytes()
    for shipped, body in want.items():
        assert lanes["wheel"][shipped] == body, shipped


def test_sdist_matches_authoritative_source():
    lanes = fixture()
    want = _compiler_bytes()
    for shipped, body in want.items():
        assert lanes["sdist"][shipped] == body, shipped


def test_standalone_matches_authoritative_source():
    lanes = fixture()
    want = _compiler_bytes()
    for shipped, body in want.items():
        assert lanes["standalone"][shipped] == body, shipped


def test_sdist_archive_carries_adapter_sources():
    lanes = fixture()
    with tarfile.open(lanes["sdist_archive"], "r:gz") as archive:
        members = {
            member.name: member for member in archive.getmembers()
        }
    want = _compiler_bytes()
    for shipped, body in want.items():
        tree_rel = os.path.join(
            "src", "mojobpf", shipped[len("mojobpf/"):]
        )
        matches = sorted(
            name
            for name in members
            if name.replace(os.sep, "/").endswith(
                tree_rel.replace(os.sep, "/")
            )
        )
        assert len(matches) == 1, (shipped, matches)
        with tarfile.open(lanes["sdist_archive"], "r:gz") as archive:
            assert archive.extractfile(matches[0]).read() == body, (
                shipped
            )


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    try:
        for name in names:
            try:
                globals()[name]()
            except EnvironmentFailure as exc:
                print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
                return 2
            except AssertionError as exc:
                print("FAIL %s: %s" % (name, exc))
                failures += 1
            else:
                print("PASS %s" % name)
    finally:
        parent = _FIXTURE.pop("dir", None)
        _FIXTURE.pop("lanes", None)
        if parent is not None:
            shutil.rmtree(parent, ignore_errors=True)
    if failures:
        return 1
    print("adapter generation: wheel/sdist/standalone equivalence passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
