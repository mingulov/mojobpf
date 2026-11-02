# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Subset-kernel build pins the frontend target (B1 evidence).

Every other guest suite builds Mojo with
``mojobpf.build.FRONTEND_TARGET_FLAGS``; the subset-kernel
builder omitted them, so a bare ``mojo build`` emitted
host-native attributes the adapter rejects (``MBPF301``)
on any non-znver4 host. Requires the pinned toolchain.
"""

import importlib.util
import os
import shutil
import sys
import tempfile

import pytest

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


def _load_subset_module():
    sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "harness"))
    try:
        path = os.path.join(
            REPO_ROOT, "tests", "verifier", "test_subset_kernel.py"
        )
        spec = importlib.util.spec_from_file_location(
            "subset_kernel_build", path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(os.path.join(REPO_ROOT, "tests", "harness"))


def test_subset_build_pins_frontend_target():
    mojo = shutil.which("mojo")
    llc = shutil.which("llc")
    if mojo is None or llc is None:
        pytest.skip("pinned Mojo/LLVM toolchain not on PATH")
    subset = _load_subset_module()
    workdir = tempfile.mkdtemp(prefix="subset-build-")
    try:
        source = os.path.join(
            REPO_ROOT, "tests", "compile", "subset",
            "subset_loop_sum.mojo",
        )
        object_path = subset.build_object(source, workdir, "loop")
        assert os.path.isfile(object_path), object_path
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    test_subset_build_pins_frontend_target()
    print("subset-build OK")
