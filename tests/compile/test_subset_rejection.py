# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Subset rejection: every prohibited behavior fails with its code.

Drives ``compiler/audit.py`` over the ``tests/compile/unsupported/``
fixtures (one per prohibited reachable behavior) and asserts each
rejection carries its exact MBPF3xx code at stage ``adapter.audit``.
The one-lane positive fixture must validate. Genuine-frontend checks
(the two canonical programs validate; the same map source at -O0 is
rejected; a Mojo program keeping a value live across a helper call is
rejected) need the Mojo compiler and report a missing compiler as an
environment failure, never a pass.

Runnable directly (``python3 tests/compile/test_subset_rejection.py``)
or under any ``test_``-style runner. Standard library only.
"""

import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))

import audit

FIXTURE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "unsupported"
)
CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
MAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile",
                          "map_roundtrip.mojo")
COUNTER_CONTENT_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "counter_content_attempt.mojo"
)
COUNTER_LENGTH_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "counter_length_attempt.mojo"
)
COUNTER_BYTESUM_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "counter_bytesum_attempt.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources",
                           "sdk")

STAGE = "adapter.audit"

# Fixture file -> expected (code, stage). Every MBPF3xx check owns at
# least one fixture here; the audit unit tests add edge cases.
EXPECTED = {
    "allocator_call.ll": ("MBPF303", STAGE),
    "runtime_init_call.ll": ("MBPF303", STAGE),
    "hidden_entry_arg.ll": ("MBPF302", STAGE),
    "unsupported_call.ll": ("MBPF303", STAGE),
    "float_op.ll": ("MBPF305", STAGE),
    "vector_op.ll": ("MBPF305", STAGE),
    "dynamic_alloca.ll": ("MBPF310", STAGE),
    "static_alloca.ll": ("MBPF310", STAGE),
    "recursion.ll": ("MBPF312", STAGE),
    "indirect_call.ll": ("MBPF306", STAGE),
    "indirectbr.ll": ("MBPF306", STAGE),
    "blockaddress.ll": ("MBPF306", STAGE),
    "legacy_helper_asm.ll": ("MBPF306", STAGE),
    "unknown_helper_id.ll": ("MBPF306", STAGE),
    "unwind_invoke.ll": ("MBPF304", STAGE),
    "tls_global.ll": ("MBPF304", STAGE),
    "poison_operand.ll": ("MBPF311", STAGE),
    "ptrtoint_op.ll": ("MBPF311", STAGE),
    "module_asm.ll": ("MBPF309", STAGE),
    "intrinsic_call.ll": ("MBPF304", STAGE),
    "live_across_call.ll": ("MBPF308", STAGE),
    "missing_map_provenance.ll": ("MBPF307", STAGE),
    "nonzero_flags.ll": ("MBPF314", STAGE),
    "pseudo_decl_attrs.ll": ("MBPF313", STAGE),
    "pseudo_call_attrs.ll": ("MBPF313", STAGE),
    "undefined_ssa_use.ll": ("MBPF315", STAGE),
    "ptr_store_map_mem.ll": ("MBPF316", STAGE),
    "ptr_store_update_buf.ll": ("MBPF316", STAGE),
}

POSITIVE = ("onelane_vector_ok.ll",)

# A Mojo program that keeps its first key slot live across the lookup
# call (the update reuses the first key while preparing a second
# slot, so shapes and counts stay valid). Genuine frontend output for
# this source must trip exactly the liveness check.
PRESSURE_SOURCE = """\
from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import MapHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key, slot, Int64(0))
    return Int32(2)
"""


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def read_fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.isfile(path):
        raise AssertionError("missing fixture: %s" % path)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def assert_rejected(text, code, stage):
    try:
        audit.validate(text)
    except audit.AuditError as exc:
        assert exc.code == code, (
            "expected code %s, got %s (%s)" % (code, exc.code, exc)
        )
        assert exc.stage == stage, (
            "expected stage %s, got %s" % (stage, exc.stage)
        )
        return exc
    raise AssertionError(
        "audit accepted input it must reject with %s" % code
    )


def test_fixture_rejections():
    for name in sorted(EXPECTED):
        code, stage = EXPECTED[name]
        exc = assert_rejected(read_fixture(name), code, stage)
        print("PASS %s -> %s/%s" % (name, exc.code, exc.stage))


def test_onelane_positive_validates():
    for name in POSITIVE:
        mode = audit.validate(read_fixture(name))
        assert mode == "classifier", (
            "%s validated as %s, expected classifier" % (name, mode)
        )
        print("PASS %s validates (%s)" % (name, mode))


def mojo_emit(source, extra_args=()):
    if shutil.which("mojo") is None:
        raise EnvironmentFailure("mojo compiler not found on PATH")
    workdir = tempfile.mkdtemp(prefix="subset-reject-")
    out_path = os.path.join(workdir, "out.ll")
    argv = (
        ["mojo", "build", "--emit", "llvm"]
        + list(extra_args)
        + ["-I", SDK_INCLUDE, "-o", out_path, source]
    )
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0 or not os.path.isfile(out_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    with open(out_path, "r", encoding="utf-8") as handle:
        return handle.read()


def test_canonical_programs_validate():
    raw = mojo_emit(CLASSIFIER_SOURCE)
    assert audit.validate(raw) == "classifier"
    print("PASS canonical classifier validates")
    raw = mojo_emit(MAP_SOURCE)
    assert audit.validate(raw) == "map"
    print("PASS canonical map program validates")


def test_unoptimized_output_rejected():
    raw = mojo_emit(MAP_SOURCE, extra_args=("-O0",))
    exc = assert_rejected(raw, "MBPF310", STAGE)
    print("PASS -O0 map output rejected (%s)" % exc.code)


def test_genuine_liveness_violation_rejected():
    workdir = tempfile.mkdtemp(prefix="subset-pressure-")
    source = os.path.join(workdir, "pressure.mojo")
    with open(source, "w", encoding="utf-8") as handle:
        handle.write(PRESSURE_SOURCE)
    raw = mojo_emit(source)
    exc = assert_rejected(raw, "MBPF308", STAGE)
    print("PASS genuine live-across program rejected (%s)" % exc.code)


def test_genuine_content_combination_refused():
    raw = mojo_emit(COUNTER_CONTENT_ATTEMPT)
    exc = assert_rejected(raw, "MBPF307", STAGE)
    print("PASS genuine content-combination program rejected (%s)" % exc.code)


def test_genuine_length_combination_refused():
    raw = mojo_emit(COUNTER_LENGTH_ATTEMPT)
    exc = assert_rejected(raw, "MBPF308", STAGE)
    print("PASS genuine length-combination program rejected (%s)" % exc.code)


def test_genuine_bytesum_combination_refused():
    raw = mojo_emit(COUNTER_BYTESUM_ATTEMPT)
    exc = assert_rejected(raw, "MBPF308", STAGE)
    print("PASS genuine bytesum program rejected (%s)" % exc.code)


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
    print(
        "subset rejection: %d fixtures rejected with exact codes, "
        "%d positive fixture validates" % (len(EXPECTED), len(POSITIVE))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
