# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Frontend-dialect canary against the real qualified toolchain.

Admits the real mojo and llc from PATH into a fresh measured lock,
then proves the dialect canary reads MATCH (not skip): the qualified
frontend's probe output reproduces the producer contract
byte-for-byte. A fixture-shaped emit would read "skip", so asserting
"match" proves the comparison really ran against live output.

Runnable directly (``python3
tests/compile/test_frontend_dialect.py``) or under any ``test_``-style
runner. Standard library only.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.toolchain import admit_tools  # noqa: E402


class EnvironmentFailure(Exception):
    """The lane lacks a required tool; fail loudly, never skip."""


def check_tools():
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def _digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _version(argv):
    proc = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure("version probe failed: %r" % (argv,))
    for line in proc.stdout.splitlines():
        if line.strip():
            return line.strip()
    raise EnvironmentFailure("empty version output: %r" % (argv,))


def test_canary_matches_real_qualified_frontend():
    check_tools()
    parent = tempfile.mkdtemp(prefix="dialect-real-")
    bindir = os.path.join(parent, "bin")
    os.makedirs(bindir)
    links = {}
    for name in ("mojo", "llc"):
        target = os.path.realpath(shutil.which(name))
        link = os.path.join(bindir, name)
        os.symlink(target, link)
        links[name] = link
    tools = {}
    for name, link in links.items():
        tools[name] = {
            "binary": link,
            "sha256": _digest(link),
            "version": _version([link, "--version"]),
        }
    lockfile = os.path.join(parent, "toolchains.lock.json")
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "tools": tools}, handle)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile,
        search_paths=(bindir,),
        names=("mojo", "llc"),
    )
    assert diagnostics == (), diagnostics
    assert sorted(admitted) == ["llc", "mojo"], admitted
    assert admitted["mojo"].dialect == "match", admitted["mojo"]
    print("PASS real frontend reproduces the qualified dialect")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
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
    if failures:
        return 1
    print("frontend dialect: live canary matches the contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
