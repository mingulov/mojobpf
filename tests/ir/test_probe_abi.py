# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Check the Mojo probe IR for a clean ABI and no runtime calls.

Builds ``tests/compile/probe.mojo`` with ``mojo build --emit llvm`` and
walks the IR reachable from each exported function, asserting that the
bodies contain no call or invoke instructions (hence no runtime, allocator,
error, unwinding, or initialization helpers), that the module declares no
external functions, and that the context-pointer export keeps exactly one
pointer parameter with an integer return.

Requires a working Mojo compiler on PATH (for example the project pixi
environment). A missing compiler or a failing build is reported as an
environment failure with a nonzero exit status, never as a pass.

Runnable directly (``python3 tests/ir/test_probe_abi.py``) or under any
``test_``-style runner. Standard library only.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE_SOURCE = os.path.join(HERE, "..", "compile", "probe.mojo")

EXPECTED_EXPORTS = {
    "probe_add": ("i32", ["i32", "i32"]),
    "probe_ctx": ("i32", ["ptr"]),
}

DEFINE_RE = re.compile(r"^define\s+.*?\s+@([A-Za-z0-9_.]+)\s*\(.*\)\s*(?:#\d+\s*)?\{")
DECLARE_RE = re.compile(r"^declare\s+.*?\s+@([A-Za-z0-9_.]+)\s*\(.*\)")
CALL_RE = re.compile(r"(?:^|\s)(?:call|invoke)\b")


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def emit_probe_ir():
    """Compile probe.mojo to LLVM IR text."""
    mojo = shutil.which("mojo")
    if mojo is None:
        raise EnvironmentFailure("mojo compiler not found on PATH")
    if not os.path.isfile(PROBE_SOURCE):
        raise EnvironmentFailure("probe source missing: %s" % PROBE_SOURCE)
    workdir = tempfile.mkdtemp(prefix="probe-abi-")
    ir_path = os.path.join(workdir, "probe.ll")
    proc = subprocess.run(
        ["mojo", "build", "--emit", "llvm", "-o", ir_path, PROBE_SOURCE],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0 or not os.path.isfile(ir_path):
        raise EnvironmentFailure(
            "mojo build --emit llvm failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(ir_path, "r", encoding="utf-8") as handle:
        return handle.read()


def split_bodies(ir_text):
    """Map defined function name -> list of body lines (without define line)."""
    bodies = {}
    current = None
    for line in ir_text.splitlines():
        stripped = line.strip()
        match = DEFINE_RE.match(stripped)
        if match:
            current = match.group(1)
            assert current not in bodies, "duplicate definition of %s" % current
            bodies[current] = []
            continue
        if stripped == "}" and current is not None:
            current = None
            continue
        if current is not None:
            bodies[current].append(stripped)
    return bodies


def test_no_runtime_calls_in_exports():
    ir_text = emit_probe_ir()
    bodies = split_bodies(ir_text)
    for name in EXPECTED_EXPORTS:
        assert name in bodies, "expected export @%s not defined" % name
        calls = [line for line in bodies[name] if CALL_RE.search(line)]
        assert not calls, (
            "@%s body contains %d call/invoke instruction(s): %s"
            % (name, len(calls), calls[:3])
        )


def test_no_external_declares():
    ir_text = emit_probe_ir()
    declares = [
        DECLARE_RE.match(line.strip()).group(1)
        for line in ir_text.splitlines()
        if DECLARE_RE.match(line.strip())
    ]
    assert not declares, "module declares external functions: %s" % declares


def test_no_unwind_or_runtime_metadata():
    ir_text = emit_probe_ir()
    bodies = split_bodies(ir_text)
    for name in EXPECTED_EXPORTS:
        assert name in bodies, "expected export @%s not defined" % name
        for marker in ("landingpad", "resume ", "personality", "nounwind "):
            hits = [line for line in bodies[name] if marker in line]
            assert not hits, "@%s body references %r: %s" % (name, marker, hits[:2])


def test_context_pointer_shape():
    ir_text = emit_probe_ir()
    bodies = split_bodies(ir_text)
    assert "probe_ctx" in bodies, "expected export @probe_ctx not defined"
    header = None
    for line in ir_text.splitlines():
        if line.strip().startswith("define ") and "@probe_ctx(" in line:
            header = line.strip()
            break
    assert header is not None, "define line for @probe_ctx not found"
    assert re.search(r"define\s+(?:\S+\s+)*?i32\s+@probe_ctx\(ptr\b", header), (
        "unexpected @probe_ctx signature: %s" % header
    )
    assert header.count(",") == 0, (
        "@probe_ctx takes extra parameters: %s" % header
    )


def main():
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
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
    print("probe ABI: no calls, no declares, clean context-pointer export")
    return 0


if __name__ == "__main__":
    sys.exit(main())
