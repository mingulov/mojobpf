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
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import audit
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

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
EVENT_SIZE_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "event_size_attempt.mojo"
)
RESERVE_SUBMIT_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_submit.mojo"
)
RESERVE_DISCARD_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_discard.mojo"
)
RESERVE_SIZE_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_size_attempt.mojo"
)
SUBPROG_SOURCE = os.path.join(
    REPO_ROOT, "examples", "subprog_call", "decision.mojo"
)
SUBPROG_ENTRY_FIRST_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_entry_first.mojo"
)
SUBPROG_RECURSION_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_recursion_attempt.mojo"
)
SUBPROG_MULTI_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_multi_attempt.mojo"
)
SUBPROG_ARITY_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_arity_attempt.mojo"
)
SUBPROG_NARROW_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_narrow_attempt.mojo"
)
SUBPROG_TRACE_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_trace_attempt.mojo"
)
SUBPROG_MAP_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_map_attempt.mojo"
)
UPROBE_SOURCE = os.path.join(
    REPO_ROOT, "examples", "uprobe_counter", "counter.mojo"
)
UPROBE_MUTANT_SOURCE = os.path.join(
    REPO_ROOT,
    "examples",
    "uprobe_counter",
    "counter_inverted_mutated.mojo",
)
UPROBE_REG_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "uprobe_reg_attempt.mojo"
)
UPROBE_TWO_READS_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "uprobe_two_reads_attempt.mojo"
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
    "pid_in_xdp.ll": ("MBPF307", STAGE),
    "pid_missing_decl.ll": ("MBPF313", STAGE),
    "tracepoint_ctx_read.ll": ("MBPF317", STAGE),
    "tracepoint_entry_mismatch.ll": ("MBPF302", STAGE),
    "tracepoint_xdp_body.ll": ("MBPF302", STAGE),
    "tracepoint_key_order.ll": ("MBPF307", STAGE),
    "tracepoint_kindtag.ll": ("MBPF307", STAGE),
    "event_output_nonzero_flags.ll": ("MBPF314", STAGE),
    "event_output_bad_size.ll": ("MBPF314", STAGE),
    "event_output_data_not_eventslot.ll": ("MBPF314", STAGE),
    "event_output_map_not_rbsize.ll": ("MBPF307", STAGE),
    "event_rbsize_bad_size.ll": ("MBPF307", STAGE),
    "event_rbsize_map_not_rbmapaddr.ll": ("MBPF307", STAGE),
    "event_slot_bad_offset.ll": ("MBPF307", STAGE),
    "event_ktime_with_operands.ll": ("MBPF314", STAGE),
    "event_cpu_with_operands.ll": ("MBPF314", STAGE),
    "event_xdp_entry.ll": ("MBPF302", STAGE),
    "event_ctx_use.ll": ("MBPF317", STAGE),
    "event_kindtag.ll": ("MBPF307", STAGE),
    "event_key_order.ll": ("MBPF307", STAGE),
    "event_output_size_from_ssa.ll": ("MBPF314", STAGE),
    "hash_tag_bad_operand.ll": ("MBPF307", STAGE),
    "hash_kindtag_mixed.ll": ("MBPF307", STAGE),
    "tracepoint_hashtag.ll": ("MBPF307", STAGE),
    "event_hashtag.ll": ("MBPF307", STAGE),
    "reserve_bad_size.ll": ("MBPF314", STAGE),
    "reserve_nonzero_flags.ll": ("MBPF314", STAGE),
    "reserve_bad_arity.ll": ("MBPF314", STAGE),
    "reserve_map_not_rbsize.ll": ("MBPF307", STAGE),
    "reserve_bad_ring_size.ll": ("MBPF307", STAGE),
    "reserve_stores_bad_width.ll": ("MBPF307", STAGE),
    "reserve_key_order.ll": ("MBPF307", STAGE),
    "reserve_xdp_entry.ll": ("MBPF302", STAGE),
    "reserve_ctx_use.ll": ("MBPF317", STAGE),
    "submit_nonzero_flags.ll": ("MBPF314", STAGE),
    "submit_data_not_reserve.ll": ("MBPF314", STAGE),
    "discard_nonzero_flags.ll": ("MBPF314", STAGE),
    "double_submit.ll": ("MBPF307", STAGE),
    "submit_discard_mixed.ll": ("MBPF307", STAGE),
    "use_after_discard.ll": ("MBPF314", STAGE),
    "load_after_submit.ll": ("MBPF314", STAGE),
    "subprog_recursion.ll": ("MBPF312", STAGE),
    "subprog_indirect.ll": ("MBPF306", STAGE),
    "subprog_callee_calls_entry.ll": ("MBPF312", STAGE),
    "subprog_multi_callee.ll": ("MBPF302", STAGE),
    "subprog_call_bad_arity.ll": ("MBPF314", STAGE),
    "subprog_call_ptr_arg.ll": ("MBPF314", STAGE),
    "subprog_call_notail.ll": ("MBPF306", STAGE),
    "subprog_call_unknown.ll": ("MBPF303", STAGE),
    "subprog_define_arity.ll": ("MBPF302", STAGE),
    "subprog_define_narrow.ll": ("MBPF302", STAGE),
    "subprog_define_uncalled.ll": ("MBPF307", STAGE),
    "subprog_trace_entry.ll": ("MBPF302", STAGE),
    "subprog_attrs_missing_noinline.ll": ("MBPF302", STAGE),
    "subprog_attrs_entry_noinline.ll": ("MBPF302", STAGE),
    "subprog_callee_store.ll": ("MBPF316", STAGE),
    "subprog_callee_load.ll": ("MBPF303", STAGE),
    "subprog_callee_load_null.ll": ("MBPF303", STAGE),
    "subprog_callee_helper.ll": ("MBPF303", STAGE),
    "subprog_attr_index_order.ll": ("MBPF302", STAGE),
    "subprog_attrs_extra.ll": ("MBPF309", STAGE),
    "subprog_map_shape.ll": ("MBPF307", STAGE),
    "uprobe_reg_unpinned.ll": ("MBPF317", STAGE),
    "uprobe_reg_multi.ll": ("MBPF317", STAGE),
    "uprobe_reg_missing.ll": ("MBPF317", STAGE),
    "uprobe_entry_mismatch.ll": ("MBPF302", STAGE),
    "uprobe_xdp_body.ll": ("MBPF302", STAGE),
    "uprobe_key_order.ll": ("MBPF307", STAGE),
    "uprobe_callee.ll": ("MBPF302", STAGE),
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
        ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS]
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


def test_genuine_output_size_refused():
    raw = mojo_emit(EVENT_SIZE_ATTEMPT)
    exc = assert_rejected(raw, "MBPF314", STAGE)
    print("PASS genuine wrong-size output rejected (%s)" % exc.code)


def test_genuine_reserve_programs_validate():
    raw = mojo_emit(RESERVE_SUBMIT_SOURCE)
    assert audit.validate(raw) == "reserve"
    print("PASS genuine reserve submitter validates")
    raw = mojo_emit(RESERVE_DISCARD_SOURCE)
    assert audit.validate(raw) == "reserve"
    print("PASS genuine reserve discarder validates")


def test_genuine_reserve_size_refused():
    raw = mojo_emit(RESERVE_SIZE_ATTEMPT)
    exc = assert_rejected(raw, "MBPF314", STAGE)
    print("PASS genuine wrong-size reserve rejected (%s)" % exc.code)


def test_genuine_subprog_programs_validate():
    raw = mojo_emit(SUBPROG_SOURCE)
    assert audit.validate(raw) == "subprog"
    print("PASS genuine subprogram decision validates")
    raw = mojo_emit(SUBPROG_ENTRY_FIRST_SOURCE)
    assert audit.validate(raw) == "subprog"
    print("PASS genuine entry-first subprogram validates")


def test_genuine_subprog_recursion_refused():
    raw = mojo_emit(SUBPROG_RECURSION_ATTEMPT)
    exc = assert_rejected(raw, "MBPF312", STAGE)
    print("PASS genuine recursive subprogram rejected (%s)" % exc.code)


def test_genuine_subprog_multi_refused():
    raw = mojo_emit(SUBPROG_MULTI_ATTEMPT)
    exc = assert_rejected(raw, "MBPF302", STAGE)
    print("PASS genuine two-callee program rejected (%s)" % exc.code)


def test_genuine_subprog_arity_refused():
    raw = mojo_emit(SUBPROG_ARITY_ATTEMPT)
    exc = assert_rejected(raw, "MBPF302", STAGE)
    print("PASS genuine two-argument callee rejected (%s)" % exc.code)


def test_genuine_subprog_narrow_refused():
    raw = mojo_emit(SUBPROG_NARROW_ATTEMPT)
    exc = assert_rejected(raw, "MBPF302", STAGE)
    print("PASS genuine 32-bit callee rejected (%s)" % exc.code)


def test_genuine_subprog_trace_refused():
    raw = mojo_emit(SUBPROG_TRACE_ATTEMPT)
    exc = assert_rejected(raw, "MBPF302", STAGE)
    print("PASS genuine trace-entry call rejected (%s)" % exc.code)


def test_genuine_subprog_map_refused():
    raw = mojo_emit(SUBPROG_MAP_ATTEMPT)
    exc = assert_rejected(raw, "MBPF313", STAGE)
    print("PASS genuine map-plus-call program rejected (%s)" % exc.code)


def test_genuine_uprobe_programs_validate():
    raw = mojo_emit(UPROBE_SOURCE)
    assert audit.validate(raw) == "uprobe"
    print("PASS genuine uprobe counter validates")
    raw = mojo_emit(UPROBE_MUTANT_SOURCE)
    assert audit.validate(raw) == "uprobe"
    print("PASS genuine inverted uprobe mutant validates")


def test_genuine_uprobe_reg_refused():
    raw = mojo_emit(UPROBE_REG_ATTEMPT)
    exc = assert_rejected(raw, "MBPF317", STAGE)
    print("PASS genuine non-pinned register read rejected (%s)" % exc.code)


def test_genuine_uprobe_two_reads_refused():
    raw = mojo_emit(UPROBE_TWO_READS_ATTEMPT)
    exc = assert_rejected(raw, "MBPF317", STAGE)
    print("PASS genuine two-word context read rejected (%s)" % exc.code)


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
