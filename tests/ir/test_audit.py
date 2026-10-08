# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the IR audit (``compiler/audit.py``).

Exercises the audit's exact codes, stages, locations, and edge cases
with inline IR modules: liveness crossings and non-crossings, operand
provenance, one-lane vector allowance, malformed reserved calls and
declarations, count vectors, first-failure ordering, pointer-store
dataflow (tainted and typed-pointer stores rejected; loaded and
predicate-derived stores allowed), and the post-lowering checks. The
``tests/compile/unsupported/`` fixtures cover one behavior per file;
these tests cover the boundaries between checks. Toolchain-independent:
no Mojo compiler or LLVM tools needed. Standard library only.

Runnable directly (``python3 tests/ir/test_audit.py``) or under any
``test_``-style runner.
"""

import os
import sys

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))

import audit

HEADER = """\
source_filename = "fixture.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
"""
FOOTER = """\
}
attributes #0 = { "target-cpu"="v3" }
"""

KEYSLOT = (
    '  %s = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)'
)
KEYSLOT1 = (
    '  %s = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)'
)
MAPADDR = (
    '  %s = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()'
)
VALSLOT = (
    '  %s = call ptr asm sideeffect "r0 = r10\\0Ar0 += -16", "={r0}"()'
)
EMPTY = '  %s = call ptr asm "", "=r,0"(i64 %s)'
LOOKUP = "  %s = call i64 @__mojobpf_lookup_v1(i64 %s, ptr %s)"
UPDATE = (
    "  %s = call i64 @__mojobpf_update_v1(i64 %s, ptr %s, ptr %s, i64 0)"
)
DELETE = "  %s = call i64 @__mojobpf_delete_elem_v1(i64 %s, ptr %s)"
# A from-program iteration-step call spelled with the long
# reserved-style name. The kernel offers no such helper, so this
# template builds refusal probes only: no audit shape matches it.
NEXTKEY = (
    "  %s = call i64 @__mojobpf_get_next_key_v1(i64 %s, ptr %s, ptr %s)"
)
NEXTKEY_DECL = (
    "declare i64 @__mojobpf_get_next_key_v1(i64, ptr, ptr) #0"
)
KEYSLOTN = (
    '  %s = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 %s)'
)
# The key-slot address recomputation without a store. No helper
# writes to a key slot, so no audit shape admits this template:
# it builds refusal probes only.
KEYADDR = (
    '  %s = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4",'
    ' "={r0}"()'
)
KINDTAG = '  %s = call i64 asm "", "=r,0"(i64 %s)'

CLASSIFIER_IR = (
    HEADER
    + "entry:\n"
    + "  %1 = load i64, ptr %0, align 8\n"
    + (EMPTY % ("%2", "%1"))
    + "\n  ret i32 2\n"
    + FOOTER
)

MAP_BODY = "\n".join(
    [
        KEYSLOT % "%2",
        MAPADDR % "%3",
        LOOKUP % ("%4", "%3", "%2"),
        "  %5 = icmp eq i64 %4, 0",
        "  br i1 %5, label %6, label %7",
        "6:",
        "  br label %15",
        "7:",
        VALSLOT % "%8",
        EMPTY % ("%9", "%4"),
        "  %10 = load i64, ptr %9, align 8",
        "  %11 = add i64 %10, 1",
        "  store i64 %11, ptr %8, align 8",
        KEYSLOT % "%12",
        MAPADDR % "%13",
        UPDATE % ("%14", "%13", "%12", "%8"),
        "  br label %15",
        "15:",
        "  ret i32 2",
    ]
)

MAP_IR = (
    HEADER
    + MAP_BODY
    + "\n"
    + FOOTER.replace(
        "}\n",
        "}\n"
        + audit.LOOKUP_DECL_LINE
        + "\n"
        + audit.UPDATE_DECL_LINE
        + "\n",
        1,
    )
)

# The combined packet workload: one packet reinterpretation plus two
# map read-modify-write pairs (entries 0 and 1) sharing one
# lookup/update declaration pair. Values %1 (length-like) and %4
# (action-like) are defined before the first helper call and used
# after later ones, which only the combined liveness exemption
# admits; nothing lookup-derived crosses a call.
COMBINED_BODY = "\n".join(
    [
        "  %1 = load i64, ptr %0, align 8",
        EMPTY % ("%2", "%1"),
        "  %3 = load i8, ptr %2, align 1",
        "  %4 = zext i8 %3 to i64",
        KEYSLOT % "%5",
        MAPADDR % "%6",
        LOOKUP % ("%7", "%6", "%5"),
        "  %8 = icmp eq i64 %7, 0",
        "  br i1 %8, label %miss0, label %hit0",
        "miss0:",
        "  br label %rmw1",
        "hit0:",
        VALSLOT % "%9",
        EMPTY % ("%10", "%7"),
        "  %11 = load i64, ptr %10, align 8",
        "  %12 = add i64 %11, 1",
        "  store i64 %12, ptr %9, align 8",
        KEYSLOT % "%13",
        MAPADDR % "%14",
        UPDATE % ("%15", "%14", "%13", "%9"),
        "  br label %rmw1",
        "rmw1:",
        KEYSLOT1 % "%16",
        MAPADDR % "%17",
        LOOKUP % ("%18", "%17", "%16"),
        "  %19 = icmp eq i64 %18, 0",
        "  br i1 %19, label %done, label %hit1",
        "hit1:",
        VALSLOT % "%20",
        EMPTY % ("%21", "%18"),
        "  %22 = load i64, ptr %21, align 8",
        "  %23 = add i64 %22, %1",
        "  store i64 %23, ptr %20, align 8",
        KEYSLOT1 % "%24",
        MAPADDR % "%25",
        UPDATE % ("%26", "%25", "%24", "%20"),
        "  br label %done",
        "done:",
        "  %27 = add i64 %4, 0",
        "  %28 = trunc i64 %27 to i32",
        "  ret i32 %28",
    ]
)

COMBINED_IR = (
    HEADER
    + COMBINED_BODY
    + "\n"
    + FOOTER.replace(
        "}\n",
        "}\n"
        + audit.LOOKUP_DECL_LINE
        + "\n"
        + audit.UPDATE_DECL_LINE
        + "\n",
        1,
    )
)

RET_ANCHOR = "  ret i32 2\n"


def with_body_line(ir_text, extra):
    assert ir_text.count(RET_ANCHOR) == 1
    return ir_text.replace(
        RET_ANCHOR, "  " + extra + "\n" + RET_ANCHOR, 1
    )


def assert_rejected(ir_text, code, stage="adapter.audit"):
    try:
        audit.validate(ir_text)
    except audit.AuditError as exc:
        assert exc.code == code, (
            "expected %s, got %s (%s)" % (code, exc.code, exc)
        )
        assert exc.stage == stage, (
            "expected stage %s, got %s" % (stage, exc.stage)
        )
        return exc
    raise AssertionError(
        "audit accepted input it must reject with %s" % code
    )


def test_modes():
    assert audit.validate(CLASSIFIER_IR) == "classifier"
    assert audit.validate(MAP_IR) == "map"
    assert audit.validate(COMBINED_IR) == "combined"


def test_combined_count_vector_exact():
    assert audit.COMBINED_COUNTS == {
        "empty": 3,
        "mapaddr": 4,
        "keyslot": 2,
        "keyslot1": 2,
        "keyslotN": 0,
        "kindtag": 0,
        "valslot": 2,
        "rbmapaddr": 0,
        "rbsize": 0,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 2,
        "update": 2,
        "delete": 0,
        "pid": 0,
        "ktime": 0,
        "cpu": 0,
        "output": 0,
        "coreread": 0,
        "coreexists": 0,
    }
    assert audit.TRACEPOINT_COUNTS == {
        "empty": 2,
        "mapaddr": 3,
        "keyslot": 1,
        "keyslot1": 2,
        "keyslotN": 0,
        "kindtag": 0,
        "valslot": 1,
        "rbmapaddr": 0,
        "rbsize": 0,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 2,
        "update": 1,
        "delete": 0,
        "pid": 1,
        "ktime": 0,
        "cpu": 0,
        "output": 0,
        "coreread": 0,
        "coreexists": 0,
    }
    assert audit.EVENT_COUNTS == {
        "empty": 4,
        "mapaddr": 7,
        "keyslot": 1,
        "keyslot1": 2,
        "keyslotN": 4,
        "kindtag": 0,
        "valslot": 3,
        "rbmapaddr": 1,
        "rbsize": 1,
        "eventslot": 2,
        "eventslotN": 6,
        "lookup": 4,
        "update": 3,
        "delete": 0,
        "pid": 2,
        "ktime": 1,
        "cpu": 1,
        "output": 1,
        "coreread": 0,
        "coreexists": 0,
    }
    assert audit.MAP_COUNTS["keyslot1"] == 0
    assert audit.CLASSIFIER_COUNTS["keyslot1"] == 0
    for counts in (
        audit.CLASSIFIER_COUNTS,
        audit.MAP_COUNTS,
        audit.COMBINED_COUNTS,
        audit.TRACEPOINT_COUNTS,
    ):
        assert counts["keyslotN"] == 0
        assert counts["kindtag"] == 0
        assert counts["delete"] == 0
        assert counts["rbmapaddr"] == 0
        assert counts["rbsize"] == 0
        assert counts["eventslot"] == 0
        assert counts["eventslotN"] == 0
        assert counts["ktime"] == 0
        assert counts["cpu"] == 0
        assert counts["output"] == 0
        assert "keyaddr" not in counts
        assert "nextkey" not in counts
    for counts in (
        audit.CLASSIFIER_COUNTS,
        audit.MAP_COUNTS,
        audit.COMBINED_COUNTS,
    ):
        assert counts["pid"] == 0
    assert audit.TRACEPOINT_COUNTS["pid"] == 1


def test_combined_cross_call_values_allowed():
    # %1 is defined before the first helper call and used in the
    # second pair; %4 is defined before the calls and used at the
    # return. Both crossings validate only through the combined
    # liveness exemption (re-enabling the check for this mode must
    # fail this test with MBPF308).
    assert audit.validate(COMBINED_IR) == "combined"


def test_combined_duplicate_decl_rejected():
    bad = COMBINED_IR.replace(
        audit.LOOKUP_DECL_LINE + "\n",
        audit.LOOKUP_DECL_LINE + "\n" + audit.LOOKUP_DECL_LINE + "\n",
        1,
    )
    assert bad != COMBINED_IR
    exc = assert_rejected(bad, "MBPF313")
    assert "shares one lookup" in exc.explanation, exc.explanation


def test_combined_missing_decl_rejected():
    bad = COMBINED_IR.replace(audit.UPDATE_DECL_LINE + "\n", "", 1)
    assert bad != COMBINED_IR
    assert_rejected(bad, "MBPF313")


def test_combined_pair_key_disagreement_rejected():
    # Swap the slot shapes between the first update's key (%13)
    # and the second lookup's key (%16): counts stay combined, but
    # neither pair agrees on its key anymore.
    bad = COMBINED_IR.replace(KEYSLOT % "%13", KEYSLOT1 % "%13", 1)
    bad = bad.replace(KEYSLOT1 % "%16", KEYSLOT % "%16", 1)
    assert bad != COMBINED_IR
    exc = assert_rejected(bad, "MBPF307")
    assert "must reference one map entry" in exc.explanation, (
        exc.explanation
    )


def test_combined_swapped_entry_order_validates():
    # Entry order is free: the key-1 pair first, then the key-0
    # pair, still validates because each pair agrees internally.
    bad = COMBINED_IR.replace(KEYSLOT % "%5", KEYSLOT1 % "%5", 1)
    bad = bad.replace(KEYSLOT % "%13", KEYSLOT1 % "%13", 1)
    bad = bad.replace(KEYSLOT1 % "%16", KEYSLOT % "%16", 1)
    bad = bad.replace(KEYSLOT1 % "%24", KEYSLOT % "%24", 1)
    assert bad != COMBINED_IR
    assert audit.validate(bad) == "combined"


def test_key1_outside_combined_rejected():
    # A lone key-1 slot spells a qualified shape but the program
    # matches no count family: the count rule, not the spelling,
    # refuses it, naming the dense key coverage the program breaks
    # (a single pair covers exactly key 0).
    bad = MAP_IR.replace(KEYSLOT % "%2", KEYSLOT1 % "%2", 1)
    assert bad != MAP_IR
    exc = assert_rejected(bad, "MBPF307")
    assert "one map count family over dense keys" in exc.explanation, (
        exc.explanation
    )


def test_combined_lookup_derived_store_rejected():
    # MBPF316 fires in combined mode too: the second lookup result
    # stored into its update buffer is a kernel address either way.
    anchor = UPDATE % ("%26", "%25", "%24", "%20")
    assert COMBINED_IR.count(anchor) == 1
    bad = COMBINED_IR.replace(
        anchor, "  store i64 %18, ptr %20, align 8\n" + anchor, 1
    )
    exc = assert_rejected(bad, "MBPF316")
    assert "update value buffer" in exc.explanation, exc.explanation


def test_liveness_call_result_use_is_not_a_crossing():
    # The lookup result %4 is defined BY the lookup call and used
    # after it; the valid map program proves this validates.
    audit.validate(MAP_IR)


def test_liveness_entry_param_used_after_call():
    bad = with_body_line(MAP_IR, "%99 = load i8, ptr %0, align 1")
    exc = assert_rejected(bad, "MBPF308")
    assert "%0" in str(exc), "rejection must name the value: %s" % exc


def test_liveness_value_used_only_before_call():
    good = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        "  %20 = add i64 1, 2\n"
        "  %21 = add i64 %20, %20\n" + LOOKUP % ("%4", "%3", "%2"),
        1,
    )
    assert good != MAP_IR
    audit.validate(good)


def test_liveness_update_result_unused_is_fine():
    audit.validate(MAP_IR)


def test_liveness_key_reused_across_lookup():
    bad = MAP_IR.replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%13", "%2", "%8"),
        1,
    )
    assert bad != MAP_IR
    exc = assert_rejected(bad, "MBPF308")
    assert "%2" in str(exc), "rejection must name the value: %s" % exc


def test_reject_redefined_ssa():
    bad = with_body_line(MAP_IR, "%5 = add i64 1, 2")
    assert_rejected(bad, "MBPF303")


def test_reject_quoted_ssa_name():
    bad = with_body_line(MAP_IR, '%"x" = add i64 1, 2')
    assert_rejected(bad, "MBPF303")


def test_reject_undefined_ssa_use():
    bad = with_body_line(CLASSIFIER_IR, "%a = add i64 %99, 1")
    exc = assert_rejected(bad, "MBPF315")
    assert "%99" in str(exc), "rejection must name the value: %s" % exc


def test_undefined_roots_phi_block_refs_allowed():
    # Phi successor operands name blocks without the ``label``
    # keyword; the label definitions satisfy them.
    good = (
        HEADER
        + "entry:\n"
        + "  %1 = load i64, ptr %0, align 8\n"
        + (EMPTY % ("%2", "%1"))
        + "\n  br label %4\n"
        + "4:\n"
        + "  %3 = phi i64 [ %1, %entry ], [ %1, %4 ]\n"
        + "  ret i32 2\n"
        + FOOTER
    )
    assert audit.validate(good) == "classifier"


def test_undefined_roots_first_use_wins():
    bad = with_body_line(CLASSIFIER_IR, "%a = add i64 %77, 1")
    bad = with_body_line(bad, "%b = add i64 %88, 2")
    exc = assert_rejected(bad, "MBPF315")
    assert "%77" in str(exc), "rejection must name %77: %s" % exc
    assert exc.location == "line 8", exc.location


def test_undefined_helper_operand_reports_operands_first():
    # Operand provenance runs before the roots check, so an
    # undefined helper operand keeps its narrower code.
    bad = MAP_IR.replace(
        "@__mojobpf_lookup_v1(i64 %3,",
        "@__mojobpf_lookup_v1(i64 %77,",
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF307")


def test_onelane_integer_vectors_allowed():
    good = with_body_line(
        CLASSIFIER_IR,
        "%v = insertelement <1 x i64> zeroinitializer, i64 1, i32 0",
    )
    good = with_body_line(
        good, "%a = add <1 x i64> zeroinitializer, %v"
    )
    audit.validate(good)
    good32 = with_body_line(
        CLASSIFIER_IR, "%a = add <1 x i32> zeroinitializer, zeroinitializer"
    )
    audit.validate(good32)


def test_reject_multilane_vector():
    bad = with_body_line(
        CLASSIFIER_IR, "%a = add <2 x i64> zeroinitializer, zeroinitializer"
    )
    assert_rejected(bad, "MBPF305")


def test_reject_scalable_vector():
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = add <vscale x 1 x i64> zeroinitializer, zeroinitializer",
    )
    assert_rejected(bad, "MBPF305")


def test_reject_onelane_float_vector():
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = fadd <1 x float> zeroinitializer, zeroinitializer",
    )
    assert_rejected(bad, "MBPF305")


def test_reject_onelane_pointer_vector():
    bad = with_body_line(
        CLASSIFIER_IR, "%a = add <1 x ptr> zeroinitializer, zeroinitializer"
    )
    assert_rejected(bad, "MBPF305")


def test_reject_float_conversions():
    assert_rejected(
        with_body_line(CLASSIFIER_IR, "%a = fpext float 1.0 to double"),
        "MBPF305",
    )
    assert_rejected(
        with_body_line(CLASSIFIER_IR, "%a = sitofp i64 1 to double"),
        "MBPF305",
    )


def test_reject_shufflevector():
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = shufflevector <1 x i64> zeroinitializer, "
        "<1 x i64> undef, <1 x i32> zeroinitializer",
    )
    assert_rejected(bad, "MBPF305")


def test_reject_undef_and_addrspace():
    assert_rejected(
        with_body_line(CLASSIFIER_IR, "%a = add i64 1, undef"), "MBPF311"
    )
    assert_rejected(
        with_body_line(
            CLASSIFIER_IR, "%a = load i64, ptr addrspace(1) %0, align 8"
        ),
        "MBPF311",
    )


def test_reject_indirectbr_and_blockaddress():
    assert_rejected(
        with_body_line(
            CLASSIFIER_IR,
            "indirectbr ptr %1, [label %taken, label %fallthrough]",
        ),
        "MBPF306",
    )
    assert_rejected(
        with_body_line(
            CLASSIFIER_IR,
            "store ptr blockaddress (@xdp_entry, %entry), ptr %0",
        ),
        "MBPF306",
    )


def test_reject_raw_inttoptr():
    bad = with_body_line(
        CLASSIFIER_IR, "%a = call i64 inttoptr (i64 1 to ptr)(i64 0)"
    )
    assert_rejected(bad, "MBPF311")


def test_reject_reserved_definition():
    bad = MAP_IR + (
        "define i64 @__mojobpf_lookup_v1(i64 %0, ptr %1) #0 {\n"
        "  ret i64 0\n"
        "}\n"
    )
    assert_rejected(bad, "MBPF313")


def test_reject_reserved_alias():
    bad = (
        "@al = alias i64 (i64, ptr), ptr @__mojobpf_lookup_v1\n"
        + MAP_IR
    )
    assert_rejected(bad, "MBPF313")


def test_reject_reserved_address_taking():
    bad = with_body_line(
        MAP_IR, "store ptr @__mojobpf_lookup_v1, ptr %8, align 8"
    )
    assert_rejected(bad, "MBPF313")


def test_reject_pseudo_call_without_result():
    bad = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        "call i64 @__mojobpf_lookup_v1(i64 %3, ptr %2)",
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_pseudo_call_with_bundle():
    bad = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        LOOKUP % ("%4", "%3", "%2") + ' [ "tag"(i32 1) ]',
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_pseudo_tail_call():
    bad = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        "tail " + LOOKUP % ("%4", "%3", "%2"),
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_pseudo_wrong_result_type():
    bad = MAP_IR.replace(
        "call i64 @__mojobpf_lookup_v1",
        "call i32 @__mojobpf_lookup_v1",
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_pseudo_wrong_arity():
    bad = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        "  %4 = call i64 @__mojobpf_lookup_v1(i64 %3)",
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF314")


def test_reject_decl_without_call():
    bad = CLASSIFIER_IR.replace(
        "}\n", "}\n" + audit.LOOKUP_DECL_LINE + "\n", 1
    )
    assert bad != CLASSIFIER_IR
    assert_rejected(bad, "MBPF313")


def test_reject_duplicate_decl():
    bad = MAP_IR.replace(
        audit.LOOKUP_DECL_LINE + "\n",
        audit.LOOKUP_DECL_LINE + "\n" + audit.LOOKUP_DECL_LINE + "\n",
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_double_lookup():
    bad = MAP_IR.replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        LOOKUP % ("%14", "%13", "%12"),
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_lookup_without_update():
    bad = MAP_IR.replace(
        UPDATE % ("%14", "%13", "%12", "%8") + "\n", "", 1
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_missing_update_decl():
    bad = MAP_IR.replace(audit.UPDATE_DECL_LINE + "\n", "", 1)
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF313")


def test_reject_extra_empty_in_classifier():
    bad = with_body_line(
        CLASSIFIER_IR, EMPTY.strip() % ("claim", "%1")
    )
    assert_rejected(bad, "MBPF303")


def test_reject_key_from_value_slot():
    bad = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        LOOKUP % ("%4", "%3", "%8"),
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF314")


def test_reject_value_from_key_slot():
    bad = MAP_IR.replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%13", "%12", "%12"),
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF314")


def test_reject_map_from_plain_value():
    bad = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        LOOKUP % ("%4", "%11", "%2"),
        1,
    )
    assert bad != MAP_IR
    # %11 is defined after the lookup line, so this also crosses the
    # call; the operand check runs first and names the provenance.
    assert_rejected(bad, "MBPF307")


def test_reject_entry_varargs():
    bad = CLASSIFIER_IR.replace(
        "@xdp_entry(ptr noundef %0)", "@xdp_entry(ptr noundef %0, ...)", 1
    )
    assert bad != CLASSIFIER_IR
    assert_rejected(bad, "MBPF302")


def test_reject_entry_wrong_return():
    bad = CLASSIFIER_IR.replace(
        "define dso_local i32 @xdp_entry",
        "define dso_local i64 @xdp_entry",
        1,
    )
    assert bad != CLASSIFIER_IR
    assert_rejected(bad, "MBPF302")


def test_diagnostic_shape():
    exc = assert_rejected(
        with_body_line(CLASSIFIER_IR, "%a = fadd float 1.0, 2.0"),
        "MBPF305",
    )
    assert "[MBPF305]" in str(exc)
    assert exc.location is not None and exc.location.startswith("line ")
    assert exc.remedy
    fields = exc.to_diagnostic()
    assert sorted(fields) == [
        "code",
        "explanation",
        "location",
        "remedy",
        "severity",
        "stage",
    ], sorted(fields)
    assert fields["code"] == "MBPF305"
    assert fields["stage"] == "adapter.audit"


def test_first_failure_wins_in_line_order():
    bad = with_body_line(CLASSIFIER_IR, "%a = fadd float 1.0, 2.0")
    bad = with_body_line(bad, "%b = alloca i32, align 4")
    exc = assert_rejected(bad, "MBPF305")
    assert exc.location == "line 8", exc.location


def test_inline_check_beats_later_counts():
    # A malformed helper call must report its own shape violation,
    # not the count mismatch it also implies.
    bad = MAP_IR.replace(
        LOOKUP % ("%4", "%3", "%2"),
        "  %4 = call i64 @__mojobpf_lookup_v1(i64 %3)",
        1,
    )
    assert bad != MAP_IR
    assert_rejected(bad, "MBPF314")


def test_liveness_reports_call_location():
    bad = MAP_IR.replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%13", "%2", "%8"),
        1,
    )
    assert bad != MAP_IR
    exc = assert_rejected(bad, "MBPF308")
    assert exc.location == "line 7", exc.location
    assert "line 5" in str(exc) and "line 20" in str(exc), str(exc)


def test_post_rejects_remaining_pseudo_call():
    try:
        audit.audit_post(
            "  %4 = call i64 @__mojobpf_lookup_v1(i64 %3, ptr %2)\n",
            "map",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError("post audit accepted a pseudo-call")


def test_post_rejects_unknown_lowered_id():
    # Helper ID 3 is the qualified delete lowering now, so the
    # unknown-ID check moved to ID 7 (still outside 1 to 3).
    try:
        audit.audit_post(
            "  %4 = call i64 inttoptr (i64 7 to ptr)(i64 %3, ptr %2)\n",
            "map",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF306", exc.code
    else:
        raise AssertionError("post audit accepted helper ID 7")


def test_post_rejects_missing_lowered_call():
    try:
        audit.audit_post("  ret i32 2\n", "map")
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError("post audit accepted zero lowered calls")


def test_post_combined_wants_two_pairs():
    one_pair = (
        "  %4 = call i64 inttoptr (i64 1 to ptr)(i64 %3, ptr %2)\n"
        "  %5 = call i64 inttoptr (i64 2 to ptr)"
        "(i64 %3, ptr %2, ptr %8, i64 0)\n"
    )
    try:
        audit.audit_post(one_pair, "combined")
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError(
            "post audit accepted one lowered pair as combined"
        )
    try:
        audit.audit_post(one_pair, "map")
    except audit.AuditError:
        raise AssertionError("post audit rejected one pair as map")
    audit.audit_post(one_pair + one_pair, "combined")


def test_post_rejects_helper_asm():
    try:
        audit.audit_post(
            '  %4 = call i64 asm sideeffect "call 1", "={r0}"()\n',
            "map",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF306", exc.code
    else:
        raise AssertionError("post audit accepted helper assembly")


def test_graph_preserved_accepts_callee_edit():
    raw = ["%a = call i64 @__mojobpf_lookup_v1(i64 %m, ptr %k)"]
    adapted = ["%a = call i64 inttoptr (i64 1 to ptr)(i64 %m, ptr %k)"]
    audit.check_graph_preserved(raw, adapted, {raw[0]: adapted[0]})


def test_graph_preserved_rejects_drift():
    try:
        audit.check_graph_preserved(
            ["  %a = add i64 1, 2"], ["  %a = add i64 1, 3"], {}
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF301", exc.code
    else:
        raise AssertionError("graph check accepted drifted lines")


def test_graph_preserved_rejects_length_change():
    try:
        audit.check_graph_preserved(["  ret i32 2"], [], {})
    except audit.AuditError as exc:
        assert exc.code == "MBPF301", exc.code
    else:
        raise AssertionError("graph check accepted a length change")


UPDATE_LINE = UPDATE % ("%14", "%13", "%12", "%8")


def with_orphan_block(ir_text, *block_lines):
    """Insert an unreachable block with the lines before the update.

    Block 18 has no predecessors, so the snippet cannot execute its
    store even if lowered by hand; the audit rejects the shape
    wherever it appears. Placement before the update keeps the
    liveness check quiet, so only the dataflow verdict can fire.
    """
    assert ir_text.count(UPDATE_LINE) == 1
    block = "  br label %19\n18:\n"
    for item in block_lines:
        block += "  " + item + "\n"
    block += "  br label %15\n19:"
    return ir_text.replace(UPDATE_LINE, block + "\n" + UPDATE_LINE, 1)


def test_ptrstore_lookup_result_into_map_memory():
    bad = with_orphan_block(MAP_IR, "store i64 %4, ptr %9, align 8")
    exc = assert_rejected(bad, "MBPF316")
    assert "%4" in exc.explanation, exc.explanation
    assert "map memory" in exc.explanation, exc.explanation


def test_ptrstore_lookup_result_into_update_buffer():
    bad = with_orphan_block(MAP_IR, "store i64 %4, ptr %8, align 8")
    exc = assert_rejected(bad, "MBPF316")
    assert "update value buffer" in exc.explanation, exc.explanation


def test_ptrstore_typed_pointer_store():
    # %8 is the untainted value slot: storing its address isolates
    # the pointer-typed rule from lookup taint.
    bad = with_orphan_block(MAP_IR, "store ptr %8, ptr %9, align 8")
    exc = assert_rejected(bad, "MBPF316")
    assert "pointer-typed" in exc.explanation, exc.explanation


def test_ptrstore_laundered_arithmetic_rejected():
    bad = with_orphan_block(
        MAP_IR,
        "%50 = add i64 %4, 0",
        "store i64 %50, ptr %8, align 8",
    )
    exc = assert_rejected(bad, "MBPF316")
    assert "%50" in exc.explanation, exc.explanation


def test_ptrstore_laundered_casts_rejected():
    bad = with_orphan_block(
        MAP_IR,
        "%50 = trunc i64 %4 to i32",
        "%51 = zext i32 %50 to i64",
        "store i64 %51, ptr %8, align 8",
    )
    exc = assert_rejected(bad, "MBPF316")


def test_ptrstore_loaded_value_store_allowed():
    # Loads break taint: stored map content is data, and the round
    # trip stores load-derived sums.
    good = with_orphan_block(
        MAP_IR,
        "%50 = load i64, ptr %9, align 8",
        "store i64 %50, ptr %8, align 8",
    )
    assert audit.validate(good) == "map"


def test_ptrstore_predicate_store_allowed():
    # %5 compares the lookup result against null; its widened
    # predicate is a 0/1 scalar, not an address.
    good = with_orphan_block(
        MAP_IR,
        "%50 = zext i1 %5 to i64",
        "store i64 %50, ptr %8, align 8",
    )
    assert audit.validate(good) == "map"


def _family_module(body_lines, *decls):
    body = "\n".join(body_lines)
    suffix = "".join(line + "\n" for line in decls)
    return (
        HEADER
        + body
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def _delete_step(first, key, slot):
    # One checked deletion: key slot, map load, delete call, and
    # an immediate status check, using SSA names first..first+4.
    # The miss path returns from the out-of-line drop block the
    # module builder appends after the final return.
    res = "%%%d" % (first + 3)
    return [
        slot % ("%%%d" % first),
        MAPADDR % ("%%%d" % (first + 1)),
        DELETE % (res, "%%%d" % (first + 1), "%%%d" % first),
        "  %%%d = icmp eq i64 %s, -22" % (first + 4, res),
        "  br i1 %%%d, label %%ok%d, label %%drop%d"
        % (first + 4, first, first),
        "ok%d:" % first,
    ]


def _delete_ir(keys):
    lines = []
    first = 2
    starts = []
    for key, slot in keys:
        starts.append(first)
        lines.extend(_delete_step(first, key, slot))
        first += 6
    lines.append("  ret i32 2")
    for start in starts:
        lines.append("drop%d:" % start)
        lines.append("  ret i32 1")
    return _family_module(lines, audit.DELETE_DECL_LINE)


def _nextkey_ir():
    # One from-program iteration-step attempt: input and output key
    # slots, a map load, and the long-spelled step call. The kernel
    # offers no such helper, so the audit refuses the program.
    lines = [
        KEYSLOT % "%2",
        KEYSLOT % "%3",
        MAPADDR % "%4",
        NEXTKEY % ("%5", "%4", "%2", "%3"),
        "  ret i32 2",
    ]
    return _family_module(lines, NEXTKEY_DECL)


def test_delete_family_validates():
    program = audit.scan(
        _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)])
    )
    assert program.mode == "map"
    assert program.family == "delete"
    assert program.entries == 2
    assert program.percpu is False


def test_from_bpf_nextkey_refused():
    # The long-spelled iteration call matches no audit shape: the
    # kernel offers no from-program map-iteration helper, so the
    # name is unreserved and the direct call is refused.
    exc = assert_rejected(_nextkey_ir(), "MBPF303")
    assert "__mojobpf_get_next_key_v1" in exc.explanation


def test_keyslotN_dense_keys_validate():
    # Three deletions over keys 0, 1, and 2 with key 2 spelled
    # through the keyslotN shape: dense coverage validates.
    slot2 = KEYSLOTN % ("%s", "2")
    lines = []
    lines.extend(_delete_step(2, 0, KEYSLOT))
    lines.extend(_delete_step(8, 1, KEYSLOT1))
    lines.extend(_delete_step(14, 2, slot2))
    lines.append("  ret i32 2")
    for start in (2, 8, 14):
        lines.append("drop%d:" % start)
        lines.append("  ret i32 1")
    program = audit.scan(
        _family_module(lines, audit.DELETE_DECL_LINE)
    )
    assert program.mode == "map"
    assert program.family == "delete"
    assert program.entries == 3


def test_keyslotN_sparse_rejected():
    # A lone key-2 deletion is not dense coverage of a one-entry
    # map (key 0 is missing), so no family admits the program.
    bad = _delete_ir([(0, KEYSLOT)]).replace("(i32 0)", "(i32 2)")
    assert "(i32 2)" in bad
    exc = assert_rejected(bad, "MBPF307")
    assert "dense keys" in exc.explanation, exc.explanation


def test_sparse_keys_rejected():
    # Rewriting one slot of a single pair to key 2 breaks dense
    # coverage, so no map count family admits the program.
    bad = MAP_IR.replace(KEYSLOT % "%12", KEYSLOTN % ("%12", "2"), 1)
    assert bad != MAP_IR
    exc = assert_rejected(bad, "MBPF307")
    assert "dense keys" in exc.explanation, exc.explanation


def test_crossed_pair_keys_rejected():
    # Two pairs whose lookup/update keys cross (the first lookup
    # reads key 0 while its paired update writes key 1) match the
    # pair counts but fail the per-pair agreement check.
    pair0 = [
        KEYSLOT % "%2",
        MAPADDR % "%3",
        LOOKUP % ("%4", "%3", "%2"),
        VALSLOT % "%8",
        EMPTY % ("%9", "%4"),
        "  %10 = load i64, ptr %9, align 8",
        "  %11 = add i64 %10, 1",
        "  store i64 %11, ptr %8, align 8",
        KEYSLOT1 % "%12",
        MAPADDR % "%13",
        UPDATE % ("%14", "%13", "%12", "%8"),
    ]
    pair1 = [
        KEYSLOT1 % "%22",
        MAPADDR % "%23",
        LOOKUP % ("%24", "%23", "%22"),
        VALSLOT % "%28",
        EMPTY % ("%29", "%24"),
        "  %30 = load i64, ptr %29, align 8",
        "  %31 = add i64 %30, 1",
        "  store i64 %31, ptr %28, align 8",
        KEYSLOT % "%32",
        MAPADDR % "%33",
        UPDATE % ("%34", "%33", "%32", "%28"),
    ]
    bad = _family_module(
        pair0 + pair1 + ["  ret i32 2"],
        audit.LOOKUP_DECL_LINE,
        audit.UPDATE_DECL_LINE,
    )
    exc = assert_rejected(bad, "MBPF307")
    assert "must reference one map entry" in exc.explanation


def test_delete_short_name_rejected():
    bad = _delete_ir([(0, KEYSLOT)]).replace(
        audit.DELETE_NAME, "__mojobpf_delete_v1"
    )
    assert "__mojobpf_delete_v1" in bad
    assert_rejected(bad, "MBPF303")


def test_nextkey_short_name_rejected():
    bad = _delete_ir([(0, KEYSLOT)]).replace(
        audit.DELETE_NAME, "__mojobpf_nextkey_v1"
    )
    assert "__mojobpf_nextkey_v1" in bad
    assert_rejected(bad, "MBPF303")


def test_delete_bad_arity_rejected():
    bad = _delete_ir([(0, KEYSLOT)]).replace(
        "(i64 %3, ptr %2)", "(i64 %3, ptr %2, i64 0)"
    )
    assert_rejected(bad, "MBPF314")


def test_nextkey_bad_arity_rejected():
    # Arity cannot rescue the spelling: a two-operand
    # iteration-style call is still an unreserved direct call.
    good = _nextkey_ir()
    bad = good.replace(
        "(i64 %4, ptr %2, ptr %3)", "(i64 %4, ptr %2)"
    )
    assert bad != good
    assert_rejected(bad, "MBPF303")


def test_keyaddr_shape_refused():
    # The store-less slot address matches no audit shape: no
    # helper writes to a key slot, so nothing can read one back.
    lines = [
        KEYSLOT % "%2",
        KEYADDR % "%3",
        "  %4 = load i32, ptr %3, align 4",
        "  ret i32 2",
    ]
    exc = assert_rejected(_family_module(lines), "MBPF303")
    assert "assembly shapes" in exc.explanation, exc.explanation


def test_kindtag_pair_validates_percpu():
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (KINDTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (KINDTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    program = audit.scan(tagged)
    assert program.mode == "map"
    assert program.family == "map"
    assert program.entries == 1
    assert program.percpu is True


def test_mixed_kindtags_rejected():
    # One kind tag for two map-address loads matches neither
    # array (zero tags) nor per-CPU (one tag per load).
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (KINDTAG % ("%30", "%3")),
        1,
    )
    assert_rejected(tagged, "MBPF307")


def test_kindtag_bad_operand_rejected():
    # A kind tag tied to anything but a map-address load carries
    # no map provenance.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (KINDTAG % ("%30", "%2")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (KINDTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_percpu_bare_mapaddr_operand_rejected():
    # The tag counts fit per-CPU but one call takes the bare
    # map-address load: per-CPU calls take tags only.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (KINDTAG % ("%30", "%3")),
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (KINDTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_combined_percpu_validates():
    program = audit.scan(_tagged_combined())
    assert program.mode == "combined"
    assert program.family == "combined"
    assert program.entries == 2
    assert program.percpu is True


def _tagged_combined():
    lines = COMBINED_IR.splitlines()
    out = []
    tag = 100
    loads = []
    for line in lines:
        out.append(line)
        stripped = line.strip()
        if stripped.startswith("%") and "mojobpf_map0 ll" in stripped:
            name = stripped[1:].split()[0]
            loads.append(name)
            out.append(KINDTAG % ("%%%d" % tag, "%" + name))
            tag += 1
    text = "\n".join(out)
    for name, num in zip(loads, range(100, 100 + len(loads))):
        text = text.replace(
            "(i64 %%%s," % name, "(i64 %%%d," % num
        )
    return text


TRACEPOINT_HEADER = """\
source_filename = "fixture.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @trace_entry(ptr noundef %0) #0 {
"""
PID = "  %s = call i64 @__mojobpf_get_pid_tgid_v1()"


def _tracepoint_body():
    return [
        KEYSLOT % "%2",
        MAPADDR % "%3",
        LOOKUP % ("%4", "%3", "%2"),
        "  %5 = icmp eq i64 %4, 0",
        "  br i1 %5, label %6, label %7",
        "6:",
        "  br label %31",
        "7:",
        EMPTY % ("%8", "%4"),
        "  %9 = load i64, ptr %8, align 8",
        PID % "%10",
        "  %11 = and i64 %10, 4294967295",
        "  %12 = icmp eq i64 %9, %11",
        "  %13 = xor i1 %12, true",
        "  br i1 %13, label %14, label %15",
        "14:",
        "  br label %30",
        "15:",
        KEYSLOT1 % "%16",
        MAPADDR % "%17",
        LOOKUP % ("%18", "%17", "%16"),
        "  %19 = icmp eq i64 %18, 0",
        "  br i1 %19, label %20, label %21",
        "20:",
        "  br label %29",
        "21:",
        VALSLOT % "%22",
        EMPTY % ("%23", "%18"),
        "  %24 = load i64, ptr %23, align 8",
        "  %25 = add i64 %24, 1",
        "  store i64 %25, ptr %22, align 8",
        KEYSLOT1 % "%26",
        MAPADDR % "%27",
        UPDATE % ("%28", "%27", "%26", "%22"),
        "  br label %29",
        "29:",
        "  br label %30",
        "30:",
        "  br label %31",
        "31:",
        "  ret i32 0",
    ]


def _tracepoint_module(extra=(), decls=None):
    lines = _tracepoint_body() + list(extra)
    if decls is None:
        decls = (
            audit.LOOKUP_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.UPDATE_DECL_LINE,
        )
    suffix = "".join(line + "\n" for line in decls)
    return (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def test_tracepoint_family_validates():
    # The filter value and the PID/TID result necessarily meet at
    # their comparison after their producing calls; the exemption
    # is structural, and this positive pins it.
    program = audit.scan(_tracepoint_module())
    assert program.mode == "tracepoint"
    assert program.family == "tracepoint"
    assert program.entries == 2
    assert program.entry == "trace_entry"
    assert program.percpu is False
    assert program.counts == audit.TRACEPOINT_COUNTS
    assert audit.validate(_tracepoint_module()) == "tracepoint"


def test_tracepoint_cross_call_result_allowed():
    # A PID/TID-derived value used after the count update still
    # validates: tracepoint mode is exempt from the liveness rule.
    good = _tracepoint_module(
        ["  %50 = add i64 %11, %25", "  br label %31"]
    )
    assert audit.validate(good) == "tracepoint"


def test_tracepoint_pid_operand_rejected():
    bad = _tracepoint_module().replace(
        PID % "%10",
        "  %10 = call i64 @__mojobpf_get_pid_tgid_v1(i64 %9)",
    )
    exc = assert_rejected(bad, "MBPF314")
    assert "no operands" in exc.explanation


def test_tracepoint_pid_decl_drift_rejected():
    bad = _tracepoint_module(
        decls=(
            audit.LOOKUP_DECL_LINE,
            "declare i64 @__mojobpf_get_pid_tgid_v1(i64) #0",
            audit.UPDATE_DECL_LINE,
        )
    )
    assert_rejected(bad, "MBPF313")


def test_traceentry_self_call_rejected():
    bad = _tracepoint_module(
        ["  %99 = call i32 @trace_entry(ptr %0)"]
    )
    assert_rejected(bad, "MBPF312")


def test_post_tracepoint_family():
    audit.audit_post(
        "  %4 = call i64 inttoptr (i64 1 to ptr)(i64 %3, ptr %2)\n"
        "  %10 = call i64 inttoptr (i64 14 to ptr)()\n"
        "  %18 = call i64 inttoptr (i64 1 to ptr)(i64 %17, ptr %16)\n"
        "  %28 = call i64 inttoptr (i64 2 to ptr)"
        "(i64 %27, ptr %26, ptr %22, i64 0)\n",
        "tracepoint",
    )
    try:
        audit.audit_post(
            "  %10 = call i64 inttoptr (i64 15 to ptr)()\n",
            "tracepoint",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF306", exc.code
    else:
        raise AssertionError("post audit accepted helper 15")
    try:
        audit.audit_post(
            "  %4 = call i64 inttoptr (i64 1 to ptr)(i64 %3, ptr %2)\n"
            "  %10 = call i64 inttoptr (i64 14 to ptr)()\n",
            "map",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError("post audit accepted pid calls in map mode")


RBMAPADDR = (
    '  %s = call i64 asm sideeffect "r0 = mojobpf_map1 ll",'
    ' "={r0},~{memory}"()'
)
RBSIZE = '  %s = call i64 asm "", "=r,0,r"(i64 %s, i64 %s)'
EVENTSLOT = (
    '  %s = call ptr asm sideeffect "r0 = r10\\0Ar0 += -64",'
    ' "={r0},~{memory}"()'
)
EVENTSLOTN = (
    '  %s = call ptr asm sideeffect "r0 = r10\\0Ar0 += -%s",'
    ' "={r0},~{memory}"()'
)
KTIME = "  %s = call i64 @__mojobpf_ktime_get_ns_v1()"
CPU = "  %s = call i64 @__mojobpf_get_smp_processor_id_v1()"
OUTPUT = (
    "  %s = call i64 @__mojobpf_ringbuf_output_v1"
    "(i64 %s, ptr %s, i64 32, i64 0)"
)


def _event_body():
    return [
        KEYSLOT % "%2",
        MAPADDR % "%3",
        LOOKUP % ("%4", "%3", "%2"),
        "  %5 = icmp eq i64 %4, 0",
        "  br i1 %5, label %6, label %7",
        "6:",
        "  br label %99",
        "7:",
        EMPTY % ("%8", "%4"),
        "  %9 = load i64, ptr %8, align 8",
        PID % "%10",
        "  %11 = and i64 %10, 4294967295",
        "  %12 = icmp eq i64 %9, %11",
        "  %13 = xor i1 %12, true",
        "  br i1 %13, label %14, label %15",
        "14:",
        "  br label %99",
        "15:",
        KEYSLOT1 % "%16",
        MAPADDR % "%17",
        LOOKUP % ("%18", "%17", "%16"),
        "  %19 = icmp eq i64 %18, 0",
        "  br i1 %19, label %20, label %21",
        "20:",
        "  br label %99",
        "21:",
        VALSLOT % "%22",
        EMPTY % ("%23", "%18"),
        "  %24 = load i64, ptr %23, align 8",
        "  %25 = add i64 %24, 1",
        "  store i64 %25, ptr %22, align 8",
        KEYSLOT1 % "%26",
        MAPADDR % "%27",
        UPDATE % ("%28", "%27", "%26", "%22"),
        CPU % "%29",
        "  %30 = and i64 %29, 4294967295",
        KTIME % "%31",
        PID % "%32",
        "  %33 = and i64 %32, 4294967295",
        EVENTSLOT % "%34",
        EVENTSLOT % "%35",
        EVENTSLOTN % ("%36", "62"),
        EVENTSLOTN % ("%37", "60"),
        EVENTSLOTN % ("%38", "56"),
        EVENTSLOTN % ("%39", "52"),
        EVENTSLOTN % ("%40", "48"),
        EVENTSLOTN % ("%41", "40"),
        "  store i16 1, ptr %35, align 2",
        "  store i16 32, ptr %36, align 2",
        "  %42 = trunc i64 %32 to i32",
        "  store i32 %42, ptr %37, align 4",
        "  %43 = trunc i64 %33 to i32",
        "  store i32 %43, ptr %38, align 4",
        "  %44 = trunc i64 %30 to i32",
        "  store i32 %44, ptr %39, align 4",
        "  store i64 %24, ptr %40, align 8",
        "  store i64 %31, ptr %41, align 8",
        RBMAPADDR % "%45",
        RBSIZE % ("%46", "%45", "131072"),
        OUTPUT % ("%47", "%46", "%34"),
        "  %48 = icmp eq i64 %47, 0",
        "  br i1 %48, label %49, label %60",
        "49:",
        KEYSLOTN % ("%50", "2"),
        MAPADDR % "%51",
        LOOKUP % ("%52", "%51", "%50"),
        "  %53 = icmp eq i64 %52, 0",
        "  br i1 %53, label %54, label %55",
        "54:",
        "  br label %99",
        "55:",
        VALSLOT % "%56",
        EMPTY % ("%57", "%52"),
        "  %58 = load i64, ptr %57, align 8",
        "  %59 = add i64 %58, 1",
        "  store i64 %59, ptr %56, align 8",
        KEYSLOTN % ("%58a", "2"),
        MAPADDR % "%58b",
        UPDATE % ("%58c", "%58b", "%58a", "%56"),
        "  br label %99",
        "60:",
        KEYSLOTN % ("%60a", "3"),
        MAPADDR % "%61",
        LOOKUP % ("%62", "%61", "%60a"),
        "  %63 = icmp eq i64 %62, 0",
        "  br i1 %63, label %64, label %65",
        "64:",
        "  br label %99",
        "65:",
        VALSLOT % "%66",
        EMPTY % ("%67", "%62"),
        "  %68 = load i64, ptr %67, align 8",
        "  %69 = add i64 %68, 1",
        "  store i64 %69, ptr %66, align 8",
        KEYSLOTN % ("%70", "3"),
        MAPADDR % "%71",
        UPDATE % ("%72", "%71", "%70", "%66"),
        "  br label %99",
        "99:",
        "  ret i32 0",
    ]


def _event_module(extra=(), decls=None):
    lines = _event_body() + list(extra)
    if decls is None:
        decls = (
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
            audit.OUTPUT_DECL_LINE,
        )
    suffix = "".join(line + "\n" for line in decls)
    return (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def test_event_module_passes_audit_and_validate():
    text = _event_module()
    program = audit.scan(text)
    assert program.mode == "event"
    assert program.family == "event"
    assert program.entries == 4
    assert program.ring_size == 131072
    assert audit.validate(text) == "event"


def test_event_count_vector_still_exact():
    counts = audit.scan(_event_module()).counts
    assert counts == audit.EVENT_COUNTS, (
        "event fixture drifted: %r vs %r" % (counts, audit.EVENT_COUNTS)
    )


def _event_text(lines):
    return (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace(
            "}\n",
            "}\n"
            + audit.LOOKUP_DECL_LINE
            + "\n"
            + audit.UPDATE_DECL_LINE
            + "\n"
            + audit.PID_DECL_LINE
            + "\n"
            + audit.KTIME_DECL_LINE
            + "\n"
            + audit.CPU_DECL_LINE
            + "\n"
            + audit.OUTPUT_DECL_LINE
            + "\n",
            1,
        )
    )


def test_event_single_eventslot_refused():
    # One base view instead of two drifts the count vector, so no
    # count family matches.
    lines = _event_body()
    base = lines.index(EVENTSLOT % "%35")
    lines = (
        lines[:base]
        + [
            "  store i16 1, ptr %34, align 2",
            "  store i16 32, ptr %36, align 2",
        ]
        + [line for line in lines[base + 1:] if "%35" not in line]
    )
    assert_rejected(_event_text(lines), "MBPF307")


def test_event_missing_ktime_cpu_refused():
    lines = [
        line
        for line in _event_body()
        if "%29" not in line
        and "%31" not in line
        and "store i32 %44" not in line
        and "store i64 %31" not in line
    ]
    text = (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace(
            "}\n",
            "}\n"
            + audit.LOOKUP_DECL_LINE
            + "\n"
            + audit.UPDATE_DECL_LINE
            + "\n"
            + audit.PID_DECL_LINE
            + "\n"
            + audit.OUTPUT_DECL_LINE
            + "\n",
            1,
        )
    )
    assert_rejected(text, "MBPF307")


def test_event_third_pid_refused():
    lines = _event_body()
    slot = lines.index(CPU % "%29")
    lines = (
        lines[:slot]
        + [PID % "%29x", "  %29y = and i64 %29x, 7"]
        + lines[slot:]
    )
    assert_rejected(_event_text(lines), "MBPF307")


def test_event_second_output_refused():
    lines = _event_body()
    out = lines.index(OUTPUT % ("%47", "%46", "%34"))
    lines = lines[:out] + [OUTPUT % ("%47x", "%46", "%34")] + lines[out:]
    assert_rejected(_event_text(lines), "MBPF307")


def test_event_failed_branch_updates_refused():
    # Any map write spliced into the failure arm drifts the count
    # vector, so the failure pair stays exactly one pair.
    lines = _event_body()
    out = lines.index(OUTPUT % ("%47", "%46", "%34"))
    branch = next(
        index
        for index in range(out, len(lines))
        if lines[index].startswith("  br i1 %48")
    )
    lines = (
        lines[: branch + 1]
        + ["60x:"]
        + [
            KEYSLOTN % ("%80", "3"),
            MAPADDR % "%81",
            UPDATE % ("%82", "%81", "%80", "%22"),
        ]
        + lines[branch + 1:]
    )
    assert_rejected(_event_text(lines), "MBPF307")


def test_event_key_order_refused():
    # Swapping the success and failure pair keys keeps every count
    # but breaks the filter-0/pairs-1-2-3 order.
    lines = _event_body()
    swapped = []
    for line in lines:
        if line == KEYSLOTN % ("%50", "2"):
            swapped.append(KEYSLOTN % ("%50", "3"))
        elif line == KEYSLOTN % ("%58a", "2"):
            swapped.append(KEYSLOTN % ("%58a", "3"))
        elif line == KEYSLOTN % ("%60a", "3"):
            swapped.append(KEYSLOTN % ("%60a", "2"))
        elif line == KEYSLOTN % ("%70", "3"):
            swapped.append(KEYSLOTN % ("%70", "2"))
        else:
            swapped.append(line)
    assert_rejected(_event_text(swapped), "MBPF307")


def test_event_field_offset_refused():
    # One field view at the wrong offset keeps every count but
    # breaks the exact record layout.
    lines = _event_body()
    swapped = [
        EVENTSLOTN % ("%38", "57") if line == EVENTSLOTN % ("%38", "56")
        else line
        for line in lines
    ]
    assert_rejected(_event_text(swapped), "MBPF307")


def test_event_output_flags_bit_refused():
    lines = _event_body()
    out = lines.index(OUTPUT % ("%47", "%46", "%34"))
    thru = OUTPUT.partition("i64 0)")[0]
    flagged = (thru + "i64 1)") % ("%47", "%46", "%34")
    lines = lines[:out] + [flagged] + lines[out + 1:]
    assert_rejected(_event_text(lines), "MBPF314")


def test_event_ringbuf_kindtag_refused():
    lines = _event_body()
    rbslot = lines.index(RBMAPADDR % "%45")
    lines = (
        lines[:rbslot]
        + [
            RBMAPADDR % "%45",
            KINDTAG % ("%45k", "%45"),
            "  %45u = add i64 %45k, 0",
        ]
        + lines[rbslot + 1:]
    )
    assert_rejected(_event_text(lines), "MBPF307")


def test_event_missing_output_decl_refused():
    text = _event_module(
        decls=(
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
        )
    )
    assert_rejected(text, "MBPF313")


def test_event_duplicate_ktime_decl_refused():
    text = _event_module(
        decls=(
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
            audit.OUTPUT_DECL_LINE,
        )
    )
    assert_rejected(text, "MBPF313")


def test_post_delete_family():
    audit.audit_post(
        "  %4 = call i64 inttoptr (i64 3 to ptr)(i64 %3, ptr %2)\n",
        "map",
    )
    try:
        audit.audit_post(
            "  %5 = call i64 inttoptr (i64 4 to ptr)"
            "(i64 %4, ptr %2, ptr %3)\n",
            "map",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF306", exc.code
    else:
        raise AssertionError("post audit accepted helper 4")
    try:
        audit.audit_post(
            "  %4 = call i64 inttoptr (i64 1 to ptr)(i64 %3, ptr %2)\n"
            "  %5 = call i64 inttoptr (i64 3 to ptr)(i64 %3, ptr %2)\n",
            "map",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError("post audit accepted mixed families")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    for name in names:
        try:
            globals()[name]()
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("audit units: %d checks passed" % len(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
