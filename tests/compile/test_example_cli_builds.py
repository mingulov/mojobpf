# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Every committed example builds through the real ``mojobpf build`` CLI.

Runs the exact user path (default packaged adapter, repository
lockfile, real Mojo/llc toolchain) over all ten example manifests
and asserts each build exits 0 with its object on disk. Fixture
builds of a subset live in the unit lane; this suite is the
real-toolchain proof.

Requires the working Mojo compiler and LLVM ``llc`` on PATH (for
example the project pixi environment plus system LLVM). A missing
tool is reported as an environment failure, never a pass.

Runnable directly (``python3 tests/compile/test_example_cli_builds.py``)
or under any ``test_``-style runner. Standard library only.
"""

import hashlib
import os
import subprocess
import sys
import tempfile
import tomllib

REPO_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."
)
SRC_DIR = os.path.join(REPO_ROOT, "src")
EXAMPLES_DIR = os.path.join(REPO_ROOT, "examples")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")

PINNED_EXAMPLES = (
    "hash_counter",
    "packet_classifier",
    "packet_counter",
    "ringbuf_reserve",
    "subprog_call",
    "tracepoint_counter",
    "tracepoint_events",
    "uprobe_counter",
    "xdp_counter",
    "xdp_pass",
)


class EnvironmentFailure(Exception):
    """The real toolchain (or a repo input) is unavailable."""


def check_tools():
    import shutil

    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    if not os.path.isfile(LOCKFILE):
        raise EnvironmentFailure("missing repo file: %s" % LOCKFILE)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_example(name, parent):
    manifest_path = os.path.join(EXAMPLES_DIR, name, "mojobpf.toml")
    if not os.path.isfile(manifest_path):
        raise AssertionError("example %r carries no manifest" % name)
    with open(manifest_path, "rb") as handle:
        artifact = tomllib.load(handle)["artifact"]["name"]
    out_dir = os.path.join(parent, "out-%s" % name)
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [
            sys.executable, "-m", "mojobpf.cli", "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--lockfile", LOCKFILE,
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=900,
    )
    assert proc.returncode == 0, (
        "example %r cli build exited %d:\n%s\n%s"
        % (name, proc.returncode, proc.stdout, proc.stderr)
    )
    object_path = os.path.join(out_dir, "%s.bpf.o" % artifact)
    assert os.path.isfile(object_path), (name, out_dir)
    return object_path, sha256_file(object_path)


def test_all_examples_build_via_cli():
    check_tools()
    found = sorted(
        entry
        for entry in os.listdir(EXAMPLES_DIR)
        if os.path.isdir(os.path.join(EXAMPLES_DIR, entry))
    )
    assert found == sorted(PINNED_EXAMPLES), found
    parent = tempfile.mkdtemp(prefix="example-cli-builds-")
    for name in PINNED_EXAMPLES:
        object_path, digest = build_example(name, parent)
        print("PASS %s -> %s %s" % (name, object_path, digest[:16]))


def main():
    names = sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )
    failures = 0
    for name in names:
        try:
            globals()[name]()
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
