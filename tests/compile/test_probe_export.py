# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Compile the Mojo probe and check its exported signatures.

Builds the sibling ``probe.mojo`` with ``mojo build --emit llvm`` and asserts
that each exported function keeps a clean C-level ABI: the declared return
type and parameters only, with no hidden error, ownership, runtime, or
initialization arguments and no ``main`` entrypoint.

Requires a working Mojo compiler on PATH (for example the project pixi
environment). A missing compiler or a failing build is reported as an
environment failure with a nonzero exit status, never as a pass.

Runnable directly (``python3 tests/compile/test_probe_export.py``) or under
any ``test_``-style runner. Standard library only.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

PROBE_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe.mojo")

# name -> (return type, [parameter types]) using LLVM IR base type names.
EXPECTED_EXPORTS = {
    "probe_add": ("i32", ["i32", "i32"]),
    "probe_ctx": ("i32", ["ptr"]),
}

DEFINE_RE = re.compile(
    r"^define\s+(?:\S+\s+)*?(\S+)\s+@([A-Za-z0-9_.]+)\s*\(([^)]*)\)"
)


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def emit_probe_ir():
    """Compile probe.mojo to LLVM IR text; return (ir_text, workdir)."""
    mojo = shutil.which("mojo")
    if mojo is None:
        raise EnvironmentFailure("mojo compiler not found on PATH")
    if not os.path.isfile(PROBE_SOURCE):
        raise EnvironmentFailure("probe source missing: %s" % PROBE_SOURCE)
    workdir = tempfile.mkdtemp(prefix="probe-export-")
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
    if "error:" in proc.stderr:
        raise EnvironmentFailure(
            "mojo build reported errors:\n%s" % proc.stderr
        )
    with open(ir_path, "r", encoding="utf-8") as handle:
        return handle.read(), workdir


def parse_defines(ir_text):
    """Map defined function name -> (return type, [param base types])."""
    defines = {}
    for line in ir_text.splitlines():
        match = DEFINE_RE.match(line.strip())
        if not match:
            continue
        ret_type, name, params = match.groups()
        param_types = []
        params = params.strip()
        if params and params != "void":
            for param in params.split(","):
                tokens = param.strip().split()
                assert tokens, "empty parameter in define of %s" % name
                param_types.append(tokens[0])
        assert name not in defines, "duplicate definition of %s" % name
        defines[name] = (ret_type, param_types)
    return defines


def test_export_signatures():
    ir_text, _ = emit_probe_ir()
    defines = parse_defines(ir_text)
    for name, (ret_type, param_types) in EXPECTED_EXPORTS.items():
        assert name in defines, "expected export @%s not defined" % name
        actual_ret, actual_params = defines[name]
        assert actual_ret == ret_type, (
            "@%s returns %s, expected %s" % (name, actual_ret, ret_type)
        )
        assert actual_params == param_types, (
            "@%s takes (%s), expected (%s)"
            % (name, ", ".join(actual_params), ", ".join(param_types))
        )
    assert "main" not in defines, "probe must not define main"


def test_no_extra_defines():
    ir_text, _ = emit_probe_ir()
    defines = parse_defines(ir_text)
    extra = sorted(set(defines) - set(EXPECTED_EXPORTS))
    assert not extra, "unexpected extra definitions: %s" % ", ".join(extra)


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
    print("probe exports: %s" % ", ".join(sorted(EXPECTED_EXPORTS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
