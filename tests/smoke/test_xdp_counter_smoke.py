# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Tester smoke: one real example build plus inspect (F-26).

The ``smoke`` lane (``ci/test_lanes.py --lane smoke``) runs this
module plus a bounded reuse of SDK-surface, safeio and helper unit
modules: the fastest path that still proves the toolchain works end
to end (target under five minutes). This module builds the
``xdp_counter`` example through the real ``mojobpf build`` CLI with
the packaged default adapter and the repository lockfile, then
inspects the built object through ``mojobpf inspect``.

Requires the working Mojo compiler, LLVM ``llc`` and ``bpftool``
on PATH, a ``mojobpf-lower`` binary (``MOJOBPF_LOWER`` or PATH),
and the repository lockfile. Anything missing is an environment
failure, never a pass.

Runnable directly (``python3 tests/smoke/test_xdp_counter_smoke.py``)
or under any ``test_``-style runner.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import tomllib

import pytest

REPO_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."
)
SRC_DIR = os.path.join(REPO_ROOT, "src")
EXAMPLE_DIR = os.path.join(REPO_ROOT, "examples", "xdp_counter")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")


class EnvironmentFailure(Exception):
    """The real toolchain (or a repo input) is unavailable."""


def check_tools():
    for tool in ("mojo", "llc", "bpftool"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    lower = os.environ.get("MOJOBPF_LOWER") or shutil.which(
        "mojobpf-lower"
    )
    if not lower or not os.path.isfile(lower):
        raise EnvironmentFailure(
            "a mojobpf-lower binary is required "
            "(MOJOBPF_LOWER or PATH)"
        )
    if not os.path.isfile(LOCKFILE):
        raise EnvironmentFailure("missing repo file: %s" % LOCKFILE)


def _run_cli(argv, cwd, timeout):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get(
        "PYTHONPATH", ""
    )
    return subprocess.run(
        [sys.executable, "-m", "mojobpf.cli"] + argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def _build(parent):
    manifest_path = os.path.join(EXAMPLE_DIR, "mojobpf.toml")
    if not os.path.isfile(manifest_path):
        raise AssertionError("xdp_counter carries no manifest")
    with open(manifest_path, "rb") as handle:
        artifact = tomllib.load(handle)["artifact"]["name"]
    out_dir = os.path.join(parent, "out-xdp-counter")
    proc = _run_cli(
        [
            "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--lockfile", LOCKFILE,
        ],
        REPO_ROOT,
        900,
    )
    assert proc.returncode == 0, (
        "smoke cli build exited %d:\n%s\n%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
    object_path = os.path.join(out_dir, "%s.bpf.o" % artifact)
    assert os.path.isfile(object_path), out_dir
    assert os.path.getsize(object_path) > 0, object_path
    return object_path


@pytest.fixture(scope="module")
def built_object():
    # One shared build for the module: the smoke contract is one
    # build plus inspect, and the scratch directory is removed
    # afterwards instead of accumulating under /tmp.
    check_tools()
    with tempfile.TemporaryDirectory(prefix="smoke-") as parent:
        yield _build(parent)


def test_smoke_builds_xdp_counter(built_object):
    assert os.path.isfile(built_object), built_object
    print("PASS xdp_counter -> %s" % built_object)


def test_smoke_inspects_built_object(built_object):
    proc = _run_cli(
        [
            "inspect",
            "--object", built_object,
            "--profile", "linux-bpfel-v3",
        ],
        REPO_ROOT,
        300,
    )
    assert proc.returncode == 0, (
        "smoke inspect exited %d:\n%s\n%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
    assert ": ok" in proc.stdout, proc.stdout


def main():
    names = sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )
    failures = 0
    check_tools()
    with tempfile.TemporaryDirectory(prefix="smoke-") as parent:
        object_path = _build(parent)
        for name in names:
            try:
                globals()[name](object_path)
            except Exception:
                failures += 1
                print("FAIL %s" % name)
                import traceback

                traceback.print_exc()
            else:
                print("ok %s" % name)
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
