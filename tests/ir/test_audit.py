# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the IR audit (``compiler/audit.py``).

Exercises the audit's exact codes, stages, locations, and edge cases
with inline IR modules: liveness crossings and non-crossings, operand
provenance, one-lane vector allowance, malformed reserved calls and
declarations, count vectors, first-failure ordering, key freshness
(stale, re-prepared, cross-edge, execution-reordered, and
store-clobbered key lifetimes rejected in every mode; fresh
preparation still validates), pointer-store
dataflow (tainted and typed-pointer stores rejected; loaded and
predicate-derived stores allowed), and the post-lowering checks. The
``tests/compile/unsupported/`` fixtures cover one behavior per file;
these tests cover the boundaries between checks. Toolchain-independent:
no Mojo compiler or LLVM tools needed. Standard library only.

Runnable directly (``python3 tests/ir/test_audit.py``) or under any
``test_``-style runner.
"""

import os
import re
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
# reserved-style name. The kernel offers no `map_get_next_key`-style
# helper and `for_each_map_elem` is outside the subset's scope, so
# this template builds refusal probes only: no audit shape matches it.
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
HASHTAG = '  %s = call i64 asm sideeffect "", "=r,0"(i64 %s)'
LRUTAG = '  %s = call i64 asm sideeffect "", "=r,0,~{memory}"(i64 %s)'
PCPUTAG = '  %s = call i64 asm "", "=r,0,~{memory}"(i64 %s)'
SKBLOAD = (
    "  %s = call i64 @__mojobpf_skb_load_bytes_v1"
    "(ptr %s, i32 %s, ptr %s, i32 %s)"
)
SKBSTORE = (
    "  %s = call i64 @__mojobpf_skb_store_bytes_v1"
    "(ptr %s, i32 %s, ptr %s, i32 %s, i64 0)"
)

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
        "entry:",
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
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
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
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 0,
        "skbstore": 0,
    }
    assert audit.TRACEPOINT_COUNTS == {
        "empty": 2,
        "mapaddr": 3,
        "keyslot": 1,
        "keyslot1": 2,
        "keyslotN": 0,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
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
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 0,
        "skbstore": 0,
    }
    assert audit.EVENT_COUNTS == {
        "empty": 4,
        "mapaddr": 7,
        "keyslot": 1,
        "keyslot1": 2,
        "keyslotN": 4,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
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
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 0,
        "skbstore": 0,
    }
    assert audit.RESERVE_SUBMIT_COUNTS == {
        "empty": 5,
        "mapaddr": 7,
        "keyslot": 1,
        "keyslot1": 2,
        "keyslotN": 4,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
        "valslot": 3,
        "rbmapaddr": 1,
        "rbsize": 1,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 4,
        "update": 3,
        "delete": 0,
        "pid": 2,
        "ktime": 1,
        "cpu": 1,
        "output": 0,
        "reserve": 1,
        "submit": 1,
        "discard": 0,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 0,
        "skbstore": 0,
    }
    assert audit.RESERVE_DISCARD_COUNTS == {
        "empty": 5,
        "mapaddr": 7,
        "keyslot": 1,
        "keyslot1": 2,
        "keyslotN": 4,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
        "valslot": 3,
        "rbmapaddr": 1,
        "rbsize": 1,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 4,
        "update": 3,
        "delete": 0,
        "pid": 2,
        "ktime": 1,
        "cpu": 1,
        "output": 0,
        "reserve": 1,
        "submit": 0,
        "discard": 1,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 0,
        "skbstore": 0,
    }
    assert audit.MAP_COUNTS["keyslot1"] == 0
    assert audit.CLASSIFIER_COUNTS["keyslot1"] == 0
    assert audit.CORE_COUNTS["hashtag"] == 0
    for counts in (
        audit.CLASSIFIER_COUNTS,
        audit.MAP_COUNTS,
        audit.COMBINED_COUNTS,
        audit.TRACEPOINT_COUNTS,
    ):
        assert counts["keyslotN"] == 0
        assert counts["kindtag"] == 0
        assert counts["hashtag"] == 0
        assert counts["delete"] == 0
        assert counts["rbmapaddr"] == 0
        assert counts["rbsize"] == 0
        assert counts["eventslot"] == 0
        assert counts["eventslotN"] == 0
        assert counts["ktime"] == 0
        assert counts["cpu"] == 0
        assert counts["output"] == 0
        assert counts["reserve"] == 0
        assert counts["submit"] == 0
        assert counts["discard"] == 0
        assert counts["skbload"] == 0
        assert counts["skbstore"] == 0
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


def test_reject_spaced_vector_spellings():
    # The vector check sees every spelling, including spaces
    # inside the brackets: a spaced multi-lane or scalable
    # vector refuses exactly like its canonical form.
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = add < 2 x i64 > zeroinitializer, zeroinitializer",
    )
    assert_rejected(bad, "MBPF305")
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = add < vscale x 1 x i64 > zeroinitializer, "
        "zeroinitializer",
    )
    assert_rejected(bad, "MBPF305")
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = fadd < 1 x float > zeroinitializer, zeroinitializer",
    )
    assert_rejected(bad, "MBPF305")


def test_spaced_onelane_vector_allowed():
    # The spaced spelling of the one admitted vector shape
    # still validates (control for the spaced refusals above).
    good = with_body_line(
        CLASSIFIER_IR,
        "%a = add < 1 x i32 > zeroinitializer, zeroinitializer",
    )
    audit.validate(good)


def test_split_store_type_keeps_aggregates():
    # The store splitter scans vector, struct and array stored
    # types to the balanced closer; an aggregate store never
    # splits mid-type (previously `{...}` split after the first
    # whitespace run, garbling type and value).
    assert audit._split_store_type(
        "{i32, i32} {i32 1, i32 2}, ptr %p"
    ) == ("{i32, i32}", "{i32 1, i32 2}, ptr %p")
    assert audit._split_store_type(
        "[4 x i32] [i32 1, i32 2, i32 3, i32 4], ptr %p"
    ) == ("[4 x i32]", "[i32 1, i32 2, i32 3, i32 4], ptr %p")
    assert audit._split_store_type(
        "{<2 x i32>} {<2 x i32> zeroinitializer}, ptr %p"
    ) == (
        "{<2 x i32>}",
        "{<2 x i32> zeroinitializer}, ptr %p",
    )
    assert audit._split_store_type(
        "<1 x i64> zeroinitializer, ptr %p"
    ) == ("<1 x i64>", "zeroinitializer, ptr %p")
    assert audit._split_store_type("i64 42, ptr %p") == (
        "i64",
        "42, ptr %p",
    )
    assert audit._split_store_type("{i32, i32") == (None, None)
    assert audit._split_store_type("i64") == (None, None)


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


def test_allowlist_rejects_freeze():
    # freeze masks poison/undef flow; no frozen shape emits it.
    bad = with_body_line(CLASSIFIER_IR, "%a = freeze i64 %1")
    exc = assert_rejected(bad, "MBPF321")
    assert "freeze" in exc.explanation, exc.explanation


def test_allowlist_rejects_switch():
    # Self-edge to entry keeps the probe to one line; the
    # opcode allowlist fires before any CFG reasoning.
    bad = with_body_line(
        CLASSIFIER_IR, "switch i64 %1, label %entry [ i64 1, label %entry ]"
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "switch" in exc.explanation, exc.explanation


def test_allowlist_rejects_sext():
    # Only zext/trunc appear in the genuine union; sext is
    # unobserved, so it fails closed. (indirectbr stays
    # MBPF306-denied via the blockaddress fixture, and any
    # addrspacecast spelling trips the denylist's addrspace
    # word first -- neither is duplicated here.)
    bad = with_body_line(CLASSIFIER_IR, "%a = sext i32 1 to i64")
    exc = assert_rejected(bad, "MBPF321")
    assert "sext" in exc.explanation, exc.explanation


def test_allowlist_rejects_extractvalue():
    bad = with_body_line(
        CLASSIFIER_IR, "%a = extractvalue { i64, i64 } zeroinitializer, 0"
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "extractvalue" in exc.explanation, exc.explanation


def test_allowlist_rejects_insertvalue():
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = insertvalue { i64, i64 } zeroinitializer, i64 %1, 0",
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "insertvalue" in exc.explanation, exc.explanation


def test_allowlist_rejects_bitcast():
    # Pointer/integer erasure adjacent: ptrtoint/inttoptr are
    # already forbidden; bitcast is not in the genuine union.
    bad = with_body_line(CLASSIFIER_IR, "%a = bitcast i64 %1 to ptr")
    exc = assert_rejected(bad, "MBPF321")
    assert "bitcast" in exc.explanation, exc.explanation


def test_allowlist_rejects_unknown_opcode():
    # Default-deny: an opcode the audit never heard of fails
    # closed rather than passing unexamined.
    bad = with_body_line(CLASSIFIER_IR, "%a = frobnicate i64 %1")
    exc = assert_rejected(bad, "MBPF321")
    assert "frobnicate" in exc.explanation, exc.explanation


def test_allowlist_rejects_unreachable():
    bad = with_body_line(CLASSIFIER_IR, "unreachable")
    exc = assert_rejected(bad, "MBPF321")
    assert "unreachable" in exc.explanation, exc.explanation


def test_allowlist_rejects_trailing_switch():
    # R1 finding 1: LLVM accepts several instructions on one
    # physical line; the audit must classify every one. An
    # allowed head followed by a switch smuggled the switch's
    # conditional behavior through audit, adapter, opt-verify,
    # and llc into BPF.
    bad = with_body_line(
        CLASSIFIER_IR,
        "%3 = add i64 %1, 0 switch i64 %1, label %pass "
        "[ i64 0, label %drop ]",
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "switch" in exc.explanation, exc.explanation


def test_allowlist_rejects_trailing_unreachable():
    bad = with_body_line(
        CLASSIFIER_IR, "%a = add i64 %1, 0 unreachable"
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "unreachable" in exc.explanation, exc.explanation


def test_allowlist_rejects_second_ssa_definition():
    # Both opcodes are allowed; the multiplicity is the
    # violation: the second instruction escapes counts, CFG,
    # and lowering, which all model one instruction per line.
    bad = with_body_line(
        CLASSIFIER_IR, "%a = add i64 %1, 0 %b = mul i64 %a, 2"
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "mul" in exc.explanation, exc.explanation


def test_allowlist_rejects_trailing_freeze_definition():
    bad = with_body_line(
        CLASSIFIER_IR, "%a = add i64 %1, 0 %b = freeze i64 %a"
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "freeze" in exc.explanation, exc.explanation


def test_allowlist_rejects_trailing_ret_after_store():
    # Bare first opcodes smuggle too: the store is allowed,
    # the trailing ret is a second unmodeled instruction.
    bad = with_body_line(
        CLASSIFIER_IR, "store i64 %1, ptr %0, align 8 ret i32 2"
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "ret" in exc.explanation, exc.explanation


def test_allowlist_rejects_constant_expression_operand():
    # Folded inline operands (constant expressions) are
    # unmodeled: counts, CFG, and lowering see plain values
    # only. No genuine shape emits them.
    bad = with_body_line(
        CLASSIFIER_IR,
        "%a = load i64, ptr getelementptr (i64, ptr null, i32 1)",
    )
    exc = assert_rejected(bad, "MBPF321")
    assert "constant expression" in exc.explanation, exc.explanation
    assert "getelementptr" in exc.explanation, exc.explanation


def test_rejects_atomic_load_orderings():
    # R1 finding 3: atomic loads sailed through both layers
    # and opt-verify, then died in llc (unsupported seq_cst
    # lowering). Orderings stay rejected pending qualification.
    for ordering in ("seq_cst", "acquire", "monotonic", "unordered"):
        bad = with_body_line(
            CLASSIFIER_IR,
            "%%a = load atomic i64, ptr %%0 %s, align 8" % ordering,
        )
        exc = assert_rejected(bad, "MBPF322")
        assert "atomic" in exc.explanation, (ordering, exc.explanation)
    scoped = with_body_line(
        CLASSIFIER_IR,
        '%a = load atomic i64, ptr %0 seq_cst, align 8, '
        '!tbaa !0, syncscope("singlethread")',
    )
    exc = assert_rejected(scoped, "MBPF322")
    assert "atomic" in exc.explanation, exc.explanation


def test_rejects_atomic_store_orderings():
    for ordering in ("release", "seq_cst"):
        bad = with_body_line(
            CLASSIFIER_IR,
            "store atomic i64 1, ptr %%0 %s, align 8" % ordering,
        )
        exc = assert_rejected(bad, "MBPF322")
        assert "atomic" in exc.explanation, (ordering, exc.explanation)


def test_rejects_volatile_memory_access():
    # Same class as atomics: unmodeled memory semantics that
    # the line model (counts, CFG, lowering) does not capture.
    bad = with_body_line(
        CLASSIFIER_IR, "%a = load volatile i64, ptr %0, align 8"
    )
    exc = assert_rejected(bad, "MBPF322")
    assert "volatile" in exc.explanation, exc.explanation
    bad = with_body_line(
        CLASSIFIER_IR, "store volatile i64 %1, ptr %0, align 8"
    )
    exc = assert_rejected(bad, "MBPF322")
    assert "volatile" in exc.explanation, exc.explanation


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


def with_orphan_block(ir_text, *block_lines, orphan="18", cont="19"):
    """Insert an unreachable block with the lines before the update.

    The orphan block has no predecessors, so the snippet cannot
    execute its store even if lowered by hand; the audit rejects
    the shape wherever it appears. Placement before the update
    keeps the liveness check quiet, so only the dataflow verdict
    can fire. The block labels default to the historic 18/19 and
    accept named overrides where a mutant must keep valid LLVM
    numbering (numeric labels consume numbering slots).
    """
    assert ir_text.count(UPDATE_LINE) == 1
    block = "  br label %" + cont + "\n" + orphan + ":\n"
    for item in block_lines:
        block += "  " + item + "\n"
    block += "  br label %15\n" + cont + ":"
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
    # offers no `map_get_next_key`-style helper and `for_each_map_elem`
    # is outside the subset's scope, so the audit refuses the program.
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


def test_pairs_reject_stray_core_calls():
    # The pairs rule matches on body counts, so a stray CO-RE
    # relocation call must fail the match explicitly: a
    # read-modify-write pair plus an existence check refuses at
    # the declaration/call agreement check (previously the pair
    # rule matched and the mixed shape validated as mode=map).
    bad = with_body_line(
        MAP_IR,
        "%99 = call i32 @__mojobpf_core_exists_task_scx_v1()",
    )
    exc = assert_rejected(bad, "MBPF313")
    assert "coreexists calls 1 declaration 0" in str(exc), exc


def test_deletes_reject_stray_core_calls():
    # The deletes rule likewise refuses a stray CO-RE call
    # explicitly instead of matching the mixed shape.
    bad = with_body_line(
        _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)]),
        "%99 = call i32 @__mojobpf_core_exists_task_scx_v1()",
    )
    exc = assert_rejected(bad, "MBPF313")
    assert "coreexists calls 1 declaration 0" in str(exc), exc


def test_from_bpf_nextkey_refused():
    # The long-spelled iteration call matches no audit shape: the
    # kernel offers no `map_get_next_key`-style helper and
    # `for_each_map_elem` is outside the subset's scope, so the
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


def test_hashtag_pair_validates_hash():
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (HASHTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (HASHTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    program = audit.scan(tagged)
    assert program.mode == "map"
    assert program.family == "map"
    assert program.entries == 1
    assert program.percpu is False
    assert program.hashkind is True


def test_mixed_hashtags_rejected():
    # One hash tag for two map-address loads matches neither
    # array (zero tags) nor hash (one tag per load).
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (HASHTAG % ("%30", "%3")),
        1,
    )
    assert_rejected(tagged, "MBPF307")


def test_lrutag_pair_validates_lru():
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (LRUTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (LRUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    program = audit.scan(tagged)
    assert program.mode == "map"
    assert program.family == "map"
    assert program.entries == 1
    assert program.percpu is False
    assert program.hashkind is False
    assert program.lrukind is True


def test_mixed_lrutags_rejected():
    # One LRU tag for two map-address loads matches neither
    # array (zero tags) nor LRU (one tag per load).
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (LRUTAG % ("%30", "%3")),
        1,
    )
    assert_rejected(tagged, "MBPF307")


def test_mixed_kind_and_lru_tags_rejected():
    # One per-CPU tag and one LRU tag: one program defines one
    # map of one kind, so the two tag kinds never mix.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (KINDTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (LRUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_pcpuhashtag_pair_validates_percpuhash():
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (PCPUTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (PCPUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    program = audit.scan(tagged)
    assert program.mode == "map"
    assert program.family == "map"
    assert program.entries == 1
    assert program.percpu is False
    assert program.hashkind is False
    assert program.lrukind is False
    assert program.pcpuhashkind is True


def test_mixed_pcpuhashtags_rejected():
    # One per-CPU-hash tag for two map-address loads matches neither
    # array (zero tags) nor per-CPU-hash (one tag per load).
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (PCPUTAG % ("%30", "%3")),
        1,
    )
    assert_rejected(tagged, "MBPF307")


def test_mixed_kind_and_percpuhash_tags_rejected():
    # One per-CPU tag and one per-CPU-hash tag: one program defines
    # one map of one kind, so the two tag kinds never mix.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (KINDTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (PCPUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_mixed_hash_and_percpuhash_tags_rejected():
    # One hash tag and one per-CPU-hash tag: one program defines
    # one map of one kind, so the two tag kinds never mix.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (HASHTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (PCPUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_mixed_lru_and_percpuhash_tags_rejected():
    # One LRU tag and one per-CPU-hash tag: one program defines
    # one map of one kind, so the two tag kinds never mix.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (LRUTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (PCPUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_pcpuhashtag_bad_operand_rejected():
    # A per-CPU-hash tag tied to anything but a map-address load
    # carries no map provenance.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (PCPUTAG % ("%30", "%2")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (PCPUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_percpuhash_bare_mapaddr_operand_rejected():
    # The tag counts fit per-CPU-hash but one call takes the bare
    # map-address load: per-CPU-hash calls take tags only.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (PCPUTAG % ("%30", "%3")),
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (PCPUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_mixed_hash_and_lru_tags_rejected():
    # One hash tag and one LRU tag: one program defines one
    # map of one kind, so the two tag kinds never mix.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (HASHTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (LRUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_lrutag_bad_operand_rejected():
    # An LRU tag tied to anything but a map-address load carries
    # no map provenance.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (LRUTAG % ("%30", "%2")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (LRUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_lru_bare_mapaddr_operand_rejected():
    # The tag counts fit LRU but one call takes the bare
    # map-address load: LRU calls take tags only.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (LRUTAG % ("%30", "%3")),
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (LRUTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_mixed_kind_and_hash_tags_rejected():
    # One per-CPU tag and one hash tag: one program defines one
    # map of one kind, so the two tag kinds never mix.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (KINDTAG % ("%30", "%3")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (HASHTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_hashtag_bad_operand_rejected():
    # A hash tag tied to anything but a map-address load carries
    # no map provenance.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (HASHTAG % ("%30", "%2")),
    ).replace(
        LOOKUP % ("%4", "%3", "%2"), LOOKUP % ("%4", "%30", "%2")
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (HASHTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_hash_bare_mapaddr_operand_rejected():
    # The tag counts fit hash but one call takes the bare
    # map-address load: hash calls take tags only.
    tagged = MAP_IR.replace(
        MAPADDR % "%3",
        (MAPADDR % "%3") + "\n" + (HASHTAG % ("%30", "%3")),
    )
    tagged = tagged.replace(
        MAPADDR % "%13",
        (MAPADDR % "%13") + "\n" + (HASHTAG % ("%31", "%13")),
    ).replace(
        UPDATE % ("%14", "%13", "%12", "%8"),
        UPDATE % ("%14", "%31", "%12", "%8"),
    )
    assert_rejected(tagged, "MBPF307")


def test_hash_delete_family_validates():
    lines = []
    tag = 100
    for line in _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)]).splitlines():
        lines.append(line)
        stripped = line.strip()
        if stripped.startswith("%") and "mojobpf_map0 ll" in stripped:
            name = stripped[1:].split()[0]
            tag_name = "%%%d" % tag
            tag += 1
            lines.append(HASHTAG % (tag_name, "%" + name))
    text = "\n".join(lines)
    # Re-point each delete call at its tag (SSA names %3 and %9
    # are the two map-address loads in _delete_ir order).
    text = text.replace(
        DELETE % ("%5", "%3", "%2"), DELETE % ("%5", "%100", "%2")
    )
    text = text.replace(
        DELETE % ("%11", "%9", "%8"),
        DELETE % ("%11", "%101", "%8"),
    )
    program = audit.scan(text)
    assert program.mode == "map"
    assert program.family == "delete"
    assert program.entries == 2
    assert program.percpu is False
    assert program.hashkind is True


def test_combined_hashtag_rejected():
    # The combined workload is array or per-CPU only: a hash tag
    # matches no combined count vector.
    tagged = COMBINED_IR.replace(
        MAPADDR % "%6",
        (MAPADDR % "%6") + "\n" + (HASHTAG % ("%130", "%6")),
        1,
    )
    assert_rejected(tagged, "MBPF307")


def test_lru_delete_family_validates():
    lines = []
    tag = 100
    for line in _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)]).splitlines():
        lines.append(line)
        stripped = line.strip()
        if stripped.startswith("%") and "mojobpf_map0 ll" in stripped:
            name = stripped[1:].split()[0]
            tag_name = "%%%d" % tag
            tag += 1
            lines.append(LRUTAG % (tag_name, "%" + name))
    text = "\n".join(lines)
    # Re-point each delete call at its tag (SSA names %3 and %9
    # are the two map-address loads in _delete_ir order).
    text = text.replace(
        DELETE % ("%5", "%3", "%2"), DELETE % ("%5", "%100", "%2")
    )
    text = text.replace(
        DELETE % ("%11", "%9", "%8"),
        DELETE % ("%11", "%101", "%8"),
    )
    program = audit.scan(text)
    assert program.mode == "map"
    assert program.family == "delete"
    assert program.entries == 2
    assert program.percpu is False
    assert program.hashkind is False
    assert program.lrukind is True


def test_combined_lrutag_rejected():
    # The combined workload is array or per-CPU only: an LRU tag
    # matches no combined count vector.
    tagged = COMBINED_IR.replace(
        MAPADDR % "%6",
        (MAPADDR % "%6") + "\n" + (LRUTAG % ("%130", "%6")),
        1,
    )
    assert_rejected(tagged, "MBPF307")


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


UPROBE_HEADER = """\
source_filename = "fixture.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @uprobe_entry(ptr noundef %0) #0 {
"""
UPROBE_CTX_GEP = (
    "  %s = getelementptr inbounds i64, ptr %%0, i32 14"
)
UPROBE_CTX_LOAD = "  %s = load i64, ptr %s, align 8"


def _uprobe_body():
    return [
        UPROBE_CTX_GEP % "%2",
        UPROBE_CTX_LOAD % ("%3", "%2"),
        KEYSLOT % "%4",
        MAPADDR % "%5",
        LOOKUP % ("%6", "%5", "%4"),
        "  %7 = icmp eq i64 %6, 0",
        "  br i1 %7, label %8, label %9",
        "8:",
        "  br label %31",
        "9:",
        EMPTY % ("%10", "%6"),
        "  %11 = load i64, ptr %10, align 8",
        "  %12 = icmp eq i64 %11, %3",
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


def _uprobe_module(extra=(), decls=None):
    lines = _uprobe_body() + list(extra)
    if decls is None:
        decls = (
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
        )
    suffix = "".join(line + "\n" for line in decls)
    return (
        UPROBE_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def test_uprobe_family_validates():
    # The filter value and the extracted register value
    # necessarily meet at their comparison after their producing
    # calls; the exemption is structural, and this positive pins
    # it together with the pinned context-word read.
    program = audit.scan(_uprobe_module())
    assert program.mode == "uprobe"
    assert program.family == "uprobe"
    assert program.entries == 2
    assert program.entry == "uprobe_entry"
    assert program.percpu is False
    assert program.counts == audit.UPROBE_COUNTS
    assert audit.validate(_uprobe_module()) == "uprobe"


def test_uprobe_cross_call_result_allowed():
    # A register-derived value used after the count update still
    # validates: uprobe mode is exempt from the liveness rule.
    good = _uprobe_module(
        ["  %50 = add i64 %3, %25", "  br label %31"]
    )
    assert audit.validate(good) == "uprobe"


def test_uprobe_reg_width_rejected():
    bad = _uprobe_module().replace(
        "getelementptr inbounds i64, ptr %0, i32 14",
        "getelementptr inbounds i32, ptr %0, i32 14",
    )
    exc = assert_rejected(bad, "MBPF317")
    assert "word 14" in exc.explanation


def test_uprobe_reg_noinbounds_rejected():
    bad = _uprobe_module().replace(
        "getelementptr inbounds i64, ptr %0, i32 14",
        "getelementptr i64, ptr %0, i32 14",
    )
    assert_rejected(bad, "MBPF317")


def test_uprobe_reg_second_load_rejected():
    bad = _uprobe_module().replace(
        "  %3 = load i64, ptr %2, align 8\n",
        "  %3 = load i64, ptr %2, align 8\n"
        "  %50 = load i64, ptr %2, align 8\n",
    )
    exc = assert_rejected(bad, "MBPF317")
    assert "exactly once" in exc.explanation


def test_uprobe_reg_store_rejected():
    bad = _uprobe_module().replace(
        "  %3 = load i64, ptr %2, align 8\n",
        "  store i64 7, ptr %2, align 8\n",
    )
    assert_rejected(bad, "MBPF317")


def test_uprobe_reg_extra_param_use_rejected():
    bad = _uprobe_module().replace(
        "  %3 = load i64, ptr %2, align 8\n",
        "  %3 = load i64, ptr %2, align 8\n"
        "  %50 = load i64, ptr %0, align 8\n",
    )
    exc = assert_rejected(bad, "MBPF317")
    assert "also used" in exc.explanation


def test_uprobe_trace_entry_rejected():
    bad = _uprobe_module().replace(
        "@uprobe_entry", "@trace_entry", 1
    )
    assert_rejected(bad, "MBPF302")


def test_uprobe_entry_tracepoint_body_rejected():
    bad = _tracepoint_module().replace(
        "@trace_entry", "@uprobe_entry", 1
    )
    assert_rejected(bad, "MBPF302")


def test_post_uprobe_family():
    audit.audit_post(
        "  %6 = call i64 inttoptr (i64 1 to ptr)(i64 %5, ptr %4)\n"
        "  %18 = call i64 inttoptr (i64 1 to ptr)(i64 %17, ptr %16)\n"
        "  %28 = call i64 inttoptr (i64 2 to ptr)"
        "(i64 %27, ptr %26, ptr %22, i64 0)\n",
        "uprobe",
    )
    try:
        audit.audit_post(
            "  %10 = call i64 inttoptr (i64 14 to ptr)()\n"
            "  %6 = call i64 inttoptr (i64 1 to ptr)(i64 %5, ptr %4)\n"
            "  %18 = call i64 inttoptr (i64 1 to ptr)(i64 %17, ptr %16)\n"
            "  %28 = call i64 inttoptr (i64 2 to ptr)"
            "(i64 %27, ptr %26, ptr %22, i64 0)\n",
            "uprobe",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError("post audit accepted pid calls in uprobe mode")


def _socket_classifier_ir():
    return CLASSIFIER_IR.replace("@xdp_entry", "@socket_entry", 1)


def _tc_classifier_ir():
    return CLASSIFIER_IR.replace("@xdp_entry", "@tc_entry", 1)


def test_socket_classifier_validates():
    try:
        mode = audit.validate(_socket_classifier_ir())
    except audit.AuditError as exc:
        raise AssertionError(
            "socket classifier refused: %s" % exc
        )
    assert mode == "classifier", mode
    program = audit.scan(_socket_classifier_ir())
    assert program.mode == "classifier"
    assert program.family == "classifier"
    assert program.entry == "socket_entry"
    assert program.counts == audit.CLASSIFIER_COUNTS


def test_tc_classifier_validates():
    try:
        mode = audit.validate(_tc_classifier_ir())
    except audit.AuditError as exc:
        raise AssertionError(
            "tc classifier refused: %s" % exc
        )
    assert mode == "classifier", mode
    program = audit.scan(_tc_classifier_ir())
    assert program.mode == "classifier"
    assert program.family == "classifier"
    assert program.entry == "tc_entry"
    assert program.counts == audit.CLASSIFIER_COUNTS


SOCKET_HEADER = HEADER.replace("@xdp_entry", "@socket_entry", 1)
TC_HEADER = HEADER.replace("@xdp_entry", "@tc_entry", 1)


def _skb_load_ir(entry="socket_entry"):
    header = SOCKET_HEADER if entry == "socket_entry" else TC_HEADER
    body = "\n".join(
        [
            "entry:",
            KEYSLOT % "%2",
            SKBLOAD % ("%3", "%0", "14", "%2", "1"),
            "  ret i32 0",
        ]
    )
    return (
        header
        + body
        + "\n"
        + FOOTER.replace(
            "}\n",
            "}\n" + audit.SKBLOAD_DECL_LINE + "\n",
            1,
        )
    )


def _skb_store_ir(entry="tc_entry"):
    header = TC_HEADER if entry == "tc_entry" else SOCKET_HEADER
    body = "\n".join(
        [
            "entry:",
            KEYSLOTN % ("%2", "2"),
            SKBSTORE % ("%3", "%0", "13", "%2", "1"),
            "  ret i32 0",
        ]
    )
    return (
        header
        + body
        + "\n"
        + FOOTER.replace(
            "}\n",
            "}\n" + audit.SKBSTORE_DECL_LINE + "\n",
            1,
        )
    )


def test_skb_decl_lines_pinned():
    assert audit.SKBLOAD_DECL_LINE == (
        "declare i64 @__mojobpf_skb_load_bytes_v1(ptr, i32, ptr, i32) #0"
    )
    assert audit.SKBSTORE_DECL_LINE == (
        "declare i64 @__mojobpf_skb_store_bytes_v1"
        "(ptr, i32, ptr, i32, i64) #0"
    )
    assert audit.SKBLOAD_NAME == "__mojobpf_skb_load_bytes_v1"
    assert audit.SKBSTORE_NAME == "__mojobpf_skb_store_bytes_v1"
    assert audit.SKBLOAD_NAME in audit.RESERVED_NAMES
    assert audit.SKBSTORE_NAME in audit.RESERVED_NAMES


def test_skb_lowered_callees_pinned():
    assert audit.LOWERED_CALLEE["skbload"] == (
        "inttoptr (i64 26 to ptr)"
    )
    assert audit.LOWERED_CALLEE["skbstore"] == (
        "inttoptr (i64 9 to ptr)"
    )


def test_skb_call_shapes_match():
    load = (
        "%3 = call i64 @__mojobpf_skb_load_bytes_v1"
        "(ptr %0, i32 14, ptr %2, i32 1)"
    )
    match = audit.SKBLOAD_CALL_RE.match(load)
    assert match is not None
    assert match.group(2) == "0"
    assert match.group(4) == "2"
    ssa = (
        "%3 = call i64 @__mojobpf_skb_load_bytes_v1"
        "(ptr %0, i32 %off, ptr %2, i32 %len)"
    )
    assert audit.SKBLOAD_CALL_RE.match(ssa) is not None
    store = (
        "%3 = call i64 @__mojobpf_skb_store_bytes_v1"
        "(ptr %0, i32 13, ptr %2, i32 1, i64 0)"
    )
    match = audit.SKBSTORE_CALL_RE.match(store)
    assert match is not None
    assert match.group(2) == "0"
    assert match.group(4) == "2"


def test_skb_call_shapes_reject():
    bad_loads = [
        "%3 = call i64 @__mojobpf_skb_load_bytes_v1"
        "(ptr %0, i64 14, ptr %2, i32 1)",
        "%3 = call i64 @__mojobpf_skb_load_bytes_v1"
        "(ptr %0, i32 14, ptr %2, i64 1)",
        "%3 = call i32 @__mojobpf_skb_load_bytes_v1"
        "(ptr %0, i32 14, ptr %2, i32 1)",
        "call i64 @__mojobpf_skb_load_bytes_v1"
        "(ptr %0, i32 14, ptr %2, i32 1)",
    ]
    for bad in bad_loads:
        assert audit.SKBLOAD_CALL_RE.match(bad) is None, bad
    bad_stores = [
        "%3 = call i64 @__mojobpf_skb_store_bytes_v1"
        "(ptr %0, i32 13, ptr %2, i32 1, i64 1)",
        "%3 = call i64 @__mojobpf_skb_store_bytes_v1"
        "(ptr %0, i32 13, ptr %2, i32 1, i32 0)",
        "%3 = call i64 @__mojobpf_skb_store_bytes_v1"
        "(ptr %0, i32 13, ptr %2, i32 1)",
    ]
    for bad in bad_stores:
        assert audit.SKBSTORE_CALL_RE.match(bad) is None, bad


def test_skb_count_vectors_exact():
    assert audit.SKB_LOAD_COUNTS == {
        "empty": 0,
        "mapaddr": 0,
        "keyslot": 1,
        "keyslot1": 0,
        "keyslotN": 0,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
        "valslot": 0,
        "rbmapaddr": 0,
        "rbsize": 0,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 0,
        "update": 0,
        "delete": 0,
        "pid": 0,
        "ktime": 0,
        "cpu": 0,
        "output": 0,
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 1,
        "skbstore": 0,
    }
    assert audit.SKB_STORE_COUNTS == {
        "empty": 0,
        "mapaddr": 0,
        "keyslot": 0,
        "keyslot1": 0,
        "keyslotN": 1,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
        "valslot": 0,
        "rbmapaddr": 0,
        "rbsize": 0,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 0,
        "update": 0,
        "delete": 0,
        "pid": 0,
        "ktime": 0,
        "cpu": 0,
        "output": 0,
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 0,
        "skbstore": 1,
    }


def test_skb_socket_load_validates():
    mode = audit.validate(_skb_load_ir())
    assert mode == "skb", mode
    program = audit.scan(_skb_load_ir())
    assert program.mode == "skb"
    assert program.family == "skb"
    assert program.entry == "socket_entry"
    assert program.counts == audit.SKB_LOAD_COUNTS


def test_skb_tc_store_validates():
    mode = audit.validate(_skb_store_ir())
    assert mode == "skb", mode
    program = audit.scan(_skb_store_ir())
    assert program.mode == "skb"
    assert program.family == "skb"
    assert program.entry == "tc_entry"
    assert program.counts == audit.SKB_STORE_COUNTS


def test_skb_shapes_admit_either_net_entry():
    assert audit.validate(_skb_load_ir(entry="tc_entry")) == "skb"
    assert audit.validate(_skb_load_ir(entry="socket_entry")) == "skb"
    assert audit.validate(_skb_store_ir(entry="tc_entry")) == "skb"


def test_skb_store_under_socket_rejected():
    bad = _skb_store_ir(entry="socket_entry")
    exc = assert_rejected(bad, "MBPF302")
    assert "socket_entry" in exc.explanation, exc.explanation
    assert "store" in exc.explanation, exc.explanation


def test_skb_body_under_xdp_rejected():
    bad = _skb_load_ir().replace("@socket_entry", "@xdp_entry", 1)
    exc = assert_rejected(bad, "MBPF302")
    assert "does not admit the skb shape" in exc.explanation


def test_skb_load_missing_decl_rejected():
    bad = _skb_load_ir().replace(audit.SKBLOAD_DECL_LINE + "\n", "", 1)
    assert bad != _skb_load_ir()
    exc = assert_rejected(bad, "MBPF313")
    assert "skbload calls" in exc.explanation, exc.explanation


def _skb_load_ir_with_call(call):
    body = "\n".join(
        [
            "entry:",
            KEYSLOT % "%2",
            call,
            "  ret i32 0",
        ]
    )
    return (
        SOCKET_HEADER
        + body
        + "\n"
        + FOOTER.replace(
            "}\n",
            "}\n" + audit.SKBLOAD_DECL_LINE + "\n",
            1,
        )
    )


def test_skb_buffer_requires_key_slot():
    # The `to` operand takes the entry context instead of the key
    # slot: counts still match the load vector, so only the
    # provenance rule refuses it.
    bad = _skb_load_ir_with_call(
        SKBLOAD % ("%3", "%0", "14", "%0", "1")
    )
    exc = assert_rejected(bad, "MBPF314")
    assert "to operand" in exc.explanation, exc.explanation


def test_skb_context_requires_non_call_value():
    # The skb operand takes the key-slot result: a stack slot is
    # not the entry context.
    bad = _skb_load_ir_with_call(
        SKBLOAD % ("%3", "%2", "14", "%2", "1")
    )
    exc = assert_rejected(bad, "MBPF314")
    assert "skb operand" in exc.explanation, exc.explanation



def _skb_loadmap_ir(entry="tc_entry"):
    header = TC_HEADER if entry == "tc_entry" else SOCKET_HEADER
    body = "\n".join(
        [
            "entry:",
            KEYSLOT % "%2",
            SKBLOAD % ("%3", "%0", "14", "%2", "1"),
            VALSLOT % "%4",
            KEYSLOT1 % "%5",
            MAPADDR % "%6",
            UPDATE % ("%7", "%6", "%5", "%4"),
            "  ret i32 0",
        ]
    )
    decls = (
        audit.SKBLOAD_DECL_LINE + "\n" + audit.UPDATE_DECL_LINE + "\n"
    )
    return (
        header + body + "\n"
        + FOOTER.replace("}\n", "}\n" + decls, 1)
    )


def test_skb_loadmap_vector_exact():
    assert audit.SKB_LOADMAP_COUNTS == {
        "empty": 0,
        "mapaddr": 1,
        "keyslot": 1,
        "keyslot1": 1,
        "keyslotN": 0,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
        "valslot": 1,
        "rbmapaddr": 0,
        "rbsize": 0,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 0,
        "update": 1,
        "delete": 0,
        "pid": 0,
        "ktime": 0,
        "cpu": 0,
        "output": 0,
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "coreread": 0,
        "coreexists": 0,
        "skbload": 1,
        "skbstore": 0,
    }


def test_skb_loadmap_validates():
    mode = audit.validate(_skb_loadmap_ir())
    assert mode == "skb", mode
    program = audit.scan(_skb_loadmap_ir())
    assert program.mode == "skb"
    assert program.family == "skb"
    assert program.entry == "tc_entry"
    assert program.entries == 2
    assert program.counts == audit.SKB_LOADMAP_COUNTS


def test_post_skb_loadmap_wants_update_plus_load():
    both = (
        "  %3 = call i64 inttoptr (i64 26 to ptr)"
        "(ptr %0, i32 14, ptr %2, i32 1)\n"
        "  %7 = call i64 inttoptr (i64 2 to ptr)"
        "(i64 %6, ptr %5, ptr %4, i64 0)\n"
    )
    audit.audit_post(both, "skb")
    update_only = (
        "  %7 = call i64 inttoptr (i64 2 to ptr)"
        "(i64 %6, ptr %5, ptr %4, i64 0)\n"
    )
    try:
        audit.audit_post(update_only, "skb")
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError(
            "post audit accepted an update without its load"
        )
    store_pair = (
        "  %3 = call i64 inttoptr (i64 9 to ptr)"
        "(ptr %0, i32 13, ptr %2, i32 1, i64 0)\n"
        "  %7 = call i64 inttoptr (i64 2 to ptr)"
        "(i64 %6, ptr %5, ptr %4, i64 0)\n"
    )
    try:
        audit.audit_post(store_pair, "skb")
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError(
            "post audit accepted a store/update mix"
        )

def test_socket_tracepoint_body_rejected():
    bad = _tracepoint_module().replace(
        "@trace_entry", "@socket_entry", 1
    )
    exc = assert_rejected(bad, "MBPF302")
    assert "must export trace_entry" in exc.explanation


def test_tc_tracepoint_body_rejected():
    bad = _tracepoint_module().replace(
        "@trace_entry", "@tc_entry", 1
    )
    exc = assert_rejected(bad, "MBPF302")
    assert "must export trace_entry" in exc.explanation


def test_socket_uprobe_body_rejected():
    bad = _uprobe_module().replace(
        "@uprobe_entry", "@socket_entry", 1
    )
    exc = assert_rejected(bad, "MBPF302")
    assert "must export uprobe_entry" in exc.explanation


def test_tc_uprobe_body_rejected():
    bad = _uprobe_module().replace(
        "@uprobe_entry", "@tc_entry", 1
    )
    exc = assert_rejected(bad, "MBPF302")
    assert "must export uprobe_entry" in exc.explanation


def test_socket_map_body_rejected():
    # The net slice proves only the mapless classifier shape
    # in-kernel: a map body under a socket entry stays refused
    # until a reviewed route carries its own proof.
    bad = MAP_IR.replace("@xdp_entry", "@socket_entry", 1)
    exc = assert_rejected(bad, "MBPF302")
    assert "exports the socket classifier" in exc.explanation


def test_tc_map_body_rejected():
    bad = MAP_IR.replace("@xdp_entry", "@tc_entry", 1)
    exc = assert_rejected(bad, "MBPF302")
    assert "exports the tc classifier" in exc.explanation


def test_socket_subprog_body_rejected():
    # The subprogram shape stays pinned to XDP: a static call
    # under a socket entry is refused, not silently retargeted.
    bad = _subprog_module(entry="socket_entry")
    exc = assert_rejected(bad, "MBPF302")
    assert "exports the socket classifier" in exc.explanation
    assert "subprog" in exc.explanation


def test_renamed_socket_entry_rejected():
    # Near-miss spellings stay refused once the entries exist:
    # the admission regex must not admit socket_entry2.
    bad = _socket_classifier_ir().replace(
        "@socket_entry", "@socket_entry2", 1
    )
    assert_rejected(bad, "MBPF302")


def test_truncated_tc_define_rejected():
    bad = _tc_classifier_ir().replace(
        "define dso_local i32 @tc_entry(ptr noundef %0) #0 {",
        "define dso_local i32 @tc_entry(ptr noundef %0) #0",
        1,
    )
    assert_rejected(bad, "MBPF302")


def test_extra_define_with_socket_entry_rejected():
    bad = _socket_classifier_ir() + (
        "define i32 @evil() { ret i32 0 }\n"
    )
    exc = assert_rejected(bad, "MBPF302")
    # The socket entry itself is admitted: the refusal names the
    # second definition, not the entrypoint header.
    assert "@evil" in exc.explanation
    assert "@socket_entry(ptr...)" in exc.explanation


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
        KEYSLOTN % ("%k58a", "2"),
        MAPADDR % "%k58b",
        UPDATE % ("%k58c", "%k58b", "%k58a", "%56"),
        "  br label %99",
        "60:",
        KEYSLOTN % ("%k60a", "3"),
        MAPADDR % "%61",
        LOOKUP % ("%62", "%61", "%k60a"),
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
        elif line == KEYSLOTN % ("%k58a", "2"):
            swapped.append(KEYSLOTN % ("%k58a", "3"))
        elif line == KEYSLOTN % ("%k60a", "3"):
            swapped.append(KEYSLOTN % ("%k60a", "2"))
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


RESERVE = (
    "  %s = call i64 @__mojobpf_ringbuf_reserve_v1"
    "(i64 %s, i64 32, i64 0)"
)
SUBMIT = (
    "  %s = call i64 @__mojobpf_ringbuf_submit_v1(ptr %s, i64 0)"
)
DISCARD = (
    "  %s = call i64 @__mojobpf_ringbuf_discard_v1(ptr %s, i64 0)"
)
RESGEP = "  %s = getelementptr inbounds i8, ptr %s, i32 %s"


def _reserve_body(terminus="submit"):
    if terminus == "submit":
        term = SUBMIT % ("%52", "%45")
    else:
        term = DISCARD % ("%52", "%45")
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
        "  br i1 %12, label %14, label %13",
        "13:",
        "  br label %99",
        "14:",
        KEYSLOT1 % "%15",
        MAPADDR % "%16",
        LOOKUP % ("%17", "%16", "%15"),
        "  %18 = icmp eq i64 %17, 0",
        "  br i1 %18, label %19, label %20",
        "19:",
        "  br label %99",
        "20:",
        EMPTY % ("%21", "%17"),
        "  %22 = load i64, ptr %21, align 8",
        VALSLOT % "%23",
        "  %24 = add i64 %22, 1",
        "  store i64 %24, ptr %23, align 8",
        KEYSLOT1 % "%25",
        MAPADDR % "%26",
        UPDATE % ("%27", "%26", "%25", "%23"),
        KTIME % "%28",
        CPU % "%29",
        PID % "%30",
        RBMAPADDR % "%31",
        RBSIZE % ("%32", "%31", "131072"),
        RESERVE % ("%33", "%32"),
        "  %34 = icmp eq i64 %33, 0",
        "  br i1 %34, label %rnull, label %35",
        "35:",
        EMPTY % ("%45", "%33"),
        "  store i16 1, ptr %45, align 2",
        RESGEP % ("%46", "%45", "2"),
        "  store i16 32, ptr %46, align 2",
        RESGEP % ("%47", "%45", "4"),
        "  store i32 7, ptr %47, align 4",
        RESGEP % ("%48", "%45", "8"),
        "  store i32 8, ptr %48, align 4",
        RESGEP % ("%49", "%45", "12"),
        "  store i32 9, ptr %49, align 4",
        RESGEP % ("%50", "%45", "16"),
        "  store i64 10, ptr %50, align 8",
        RESGEP % ("%51", "%45", "24"),
        "  store i64 11, ptr %51, align 8",
        term,
        KEYSLOTN % ("%53", "2"),
        MAPADDR % "%54",
        LOOKUP % ("%55", "%54", "%53"),
        "  %56 = icmp eq i64 %55, 0",
        "  br i1 %56, label %99, label %57",
        "57:",
        EMPTY % ("%58", "%55"),
        "  %59 = load i64, ptr %58, align 8",
        VALSLOT % "%60",
        "  %61 = add i64 %59, 1",
        "  store i64 %61, ptr %60, align 8",
        KEYSLOTN % ("%62", "2"),
        MAPADDR % "%63",
        UPDATE % ("%64", "%63", "%62", "%60"),
        "  br label %99",
        "rnull:",
        KEYSLOTN % ("%65", "3"),
        MAPADDR % "%66",
        LOOKUP % ("%67", "%66", "%65"),
        "  %68 = icmp eq i64 %67, 0",
        "  br i1 %68, label %99, label %69",
        "69:",
        EMPTY % ("%70", "%67"),
        "  %71 = load i64, ptr %70, align 8",
        VALSLOT % "%72",
        "  %73 = add i64 %71, 1",
        "  store i64 %73, ptr %72, align 8",
        KEYSLOTN % ("%74", "3"),
        MAPADDR % "%75",
        UPDATE % ("%76", "%75", "%74", "%72"),
        "  br label %99",
        "99:",
        "  ret i32 0",
    ]


def _reserve_module(terminus="submit", decls=None):
    lines = _reserve_body(terminus)
    if decls is None:
        decls = (
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
            audit.RESERVE_DECL_LINE,
            audit.SUBMIT_DECL_LINE
            if terminus == "submit"
            else audit.DISCARD_DECL_LINE,
        )
    suffix = "".join(line + "\n" for line in decls)
    return (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def _reserve_counts(terminus="submit"):
    counts = dict(audit.RESERVE_SUBMIT_COUNTS)
    if terminus == "discard":
        counts["submit"] = 0
        counts["discard"] = 1
    return counts


def test_reserve_modules_pass_audit_and_validate():
    for terminus in ("submit", "discard"):
        program = audit.scan(_reserve_module(terminus))
        assert program.mode == "reserve", terminus
        assert program.family == "reserve", terminus
        assert program.entries == 4, terminus
        assert program.ring_size == 131072, terminus
        assert program.counts == _reserve_counts(terminus), terminus
        assert audit.validate(_reserve_module(terminus)) == "reserve"


def test_reserve_terminus_mix_refused():
    # One submit plus one discard matches neither reservation
    # vector: a reservation admits exactly one terminus.
    lines = _reserve_body()
    term = next(
        index for index, line in enumerate(lines)
        if "@__mojobpf_ringbuf_submit_v1" in line
    )
    lines = (
        lines[: term + 1]
        + [DISCARD % ("%152", "%45")]
        + lines[term + 1:]
    )
    suffix = "".join(
        line + "\n"
        for line in (
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
            audit.RESERVE_DECL_LINE,
            audit.SUBMIT_DECL_LINE,
            audit.DISCARD_DECL_LINE,
        )
    )
    text = (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )
    assert_rejected(text, "MBPF307")


def test_reserve_second_reserve_refused():
    # A second reservation for one program matches neither
    # reservation vector: a program holds at most one live
    # reservation.
    lines = _reserve_body()
    reserve = next(
        index for index, line in enumerate(lines)
        if "@__mojobpf_ringbuf_reserve_v1" in line
    )
    lines = (
        lines[: reserve + 1]
        + [RESERVE % ("%133", "%32")]
        + lines[reserve + 1:]
    )
    assert_rejected(_reserve_module_wrapped(lines), "MBPF307")


def _reserve_module_wrapped(lines, terminus="submit"):
    if terminus == "submit":
        term_decl = audit.SUBMIT_DECL_LINE
    else:
        term_decl = audit.DISCARD_DECL_LINE
    suffix = "".join(
        line + "\n"
        for line in (
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
            audit.RESERVE_DECL_LINE,
            term_decl,
        )
    )
    return (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def test_reserve_store_after_terminus_refused():
    # A reservation store textually after the terminus is a use
    # after release, even though the counts still match.
    lines = _reserve_body()
    term = next(
        index for index, line in enumerate(lines)
        if "@__mojobpf_ringbuf_submit_v1" in line
    )
    lines = (
        lines[: term + 1]
        + ["  store i16 1, ptr %45, align 2"]
        + lines[term + 1:]
    )
    assert_rejected(_reserve_module_wrapped(lines), "MBPF314")


def test_reserve_terminus_wrong_pointer_refused():
    # The terminus must take the record reinterpretation of the
    # reservation result, not a map value pointer.
    lines = [
        SUBMIT % ("%52", "%8") if "@__mojobpf_ringbuf_submit_v1" in line
        else line
        for line in _reserve_body()
    ]
    assert_rejected(_reserve_module_wrapped(lines), "MBPF314")


def test_reserve_result_store_refused():
    # The nullable reservation address is tainted like a lookup
    # result: storing it into map memory is refused.
    lines = _reserve_body()
    slot = next(
        index for index, line in enumerate(lines)
        if line == "  store i64 %24, ptr %23, align 8"
    )
    lines = (
        lines[:slot]
        + ["  store i64 %33, ptr %23, align 8"]
        + lines[slot + 1:]
    )
    assert_rejected(_reserve_module_wrapped(lines), "MBPF316")


def test_reserve_terminus_result_store_refused():
    # The terminus result is tainted for both termini: storing
    # the submit/discard return into map memory is refused.
    for terminus, name in (
        ("submit", "@__mojobpf_ringbuf_submit_v1"),
        ("discard", "@__mojobpf_ringbuf_discard_v1"),
    ):
        lines = _reserve_body(terminus=terminus)
        term = next(
            index for index, line in enumerate(lines)
            if name in line
        )
        lines = (
            lines[: term + 1]
            + ["  store i64 %52, ptr %23, align 8"]
            + lines[term + 1:]
        )
        assert_rejected(
            _reserve_module_wrapped(lines, terminus=terminus), "MBPF316"
        )


def test_reserve_gep_after_terminus_refused():
    # Computing a reservation address after the terminus is a
    # use after release, even with no store behind it.
    lines = _reserve_body()
    term = next(
        index for index, line in enumerate(lines)
        if "@__mojobpf_ringbuf_submit_v1" in line
    )
    lines = (
        lines[: term + 1]
        + [RESGEP % ("%153", "%45", "2")]
        + lines[term + 1:]
    )
    assert_rejected(_reserve_module_wrapped(lines), "MBPF314")


def test_reserve_load_after_terminus_refused():
    # A reservation load textually after the terminus is a use
    # after release, even though the counts still match.
    lines = _reserve_body()
    term = next(
        index for index, line in enumerate(lines)
        if "@__mojobpf_ringbuf_submit_v1" in line
    )
    lines = (
        lines[: term + 1]
        + ["  %153 = load i16, ptr %45, align 2"]
        + lines[term + 1:]
    )
    assert_rejected(_reserve_module_wrapped(lines), "MBPF314")


def test_reserve_gep_load_after_terminus_refused():
    # A load through a tracked reservation address after the
    # terminus is a use after release, even though the address
    # itself was computed before the release.
    lines = _reserve_body()
    term = next(
        index for index, line in enumerate(lines)
        if "@__mojobpf_ringbuf_submit_v1" in line
    )
    lines = (
        lines[: term + 1]
        + ["  %153 = load i16, ptr %46, align 2"]
        + lines[term + 1:]
    )
    assert_rejected(_reserve_module_wrapped(lines), "MBPF314")


def test_reserve_load_after_discard_refused():
    # The load rule is terminus-agnostic: a reservation load
    # after the discard terminus is refused the same way.
    lines = _reserve_body(terminus="discard")
    term = next(
        index for index, line in enumerate(lines)
        if "@__mojobpf_ringbuf_discard_v1" in line
    )
    lines = (
        lines[: term + 1]
        + ["  %153 = load i16, ptr %45, align 2"]
        + lines[term + 1:]
    )
    suffix = "".join(
        line + "\n"
        for line in (
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
            audit.RESERVE_DECL_LINE,
            audit.DISCARD_DECL_LINE,
        )
    )
    text = (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )
    assert_rejected(text, "MBPF314")


def test_reserve_missing_submit_decl_refused():
    text = _reserve_module(
        decls=(
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.KTIME_DECL_LINE,
            audit.CPU_DECL_LINE,
            audit.RESERVE_DECL_LINE,
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


SUBPROG_MODULE_HEADER = """\
source_filename = "subprog.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
"""

SUBPROG_ATTRS = (
    'attributes #0 = { noinline "target-cpu"="v3" }\n'
    'attributes #1 = { "target-cpu"="v3" }\n'
)

SUBPROG_ATTRS_AFTER = (
    'attributes #0 = { "target-cpu"="v3" }\n'
    'attributes #1 = { noinline "target-cpu"="v3" }\n'
)

SUBPROG_CALLEE_BODY = (
    "  %2 = and i64 %0, 1\n"
    "  %3 = icmp eq i64 %2, 1\n"
    "  %4 = select i1 %3, i64 1, i64 2\n"
    "  ret i64 %4\n"
)

SUBPROG_ENTRY_BODY = (
    "  %1 = load i64, ptr %0, align 8\n"
    + (EMPTY % ("%2", "%1"))
    + "\n"
    "  %3 = tail call i64 @decide(i64 %1)\n"
    "  %5 = trunc i64 %3 to i32\n"
    "  ret i32 %5\n"
)


def _subprog_module(order="before", callee_body=None, entry_body=None,
                    callee_name="decide", entry="xdp_entry",
                    attrs=None):
    """Build inline subprogram IR in either definition order.

    The default bodies reuse SSA names across the two functions
    (``%2`` is defined in both), so the positive also proves the
    per-function SSA scoping.
    """
    if callee_body is None:
        callee_body = SUBPROG_CALLEE_BODY
    if entry_body is None:
        entry_body = SUBPROG_ENTRY_BODY
    if attrs is None:
        if order == "before":
            attrs = SUBPROG_ATTRS
        else:
            attrs = SUBPROG_ATTRS_AFTER
    if order == "before":
        first = (
            "define dso_local i64 @%s(i64 noundef %%0) #0 {\n"
            % callee_name
        ) + callee_body + "}\n"
        second = (
            "define dso_local i32 @%s(ptr noundef %%0) #1 {\n" % entry
        ) + entry_body + "}\n"
    else:
        first = (
            "define dso_local i32 @%s(ptr noundef %%0) #0 {\n" % entry
        ) + entry_body + "}\n"
        second = (
            "define dso_local i64 @%s(i64 noundef %%0) #1 {\n"
            % callee_name
        ) + callee_body + "}\n"
    return SUBPROG_MODULE_HEADER + "\n" + first + "\n" + second + "\n" + attrs


def test_subprog_both_orders_validate():
    for order, sets in (
        ("before", {0: True, 1: False}),
        ("after", {0: False, 1: True}),
    ):
        program = audit.scan(_subprog_module(order))
        assert program.mode == "subprog", order
        assert program.family == "subprog", order
        assert program.callee == "decide", order
        assert program.callee_order == order, order
        assert len(program.subprog_calls) == 1, order
        assert program.counts == audit.CLASSIFIER_COUNTS, order
        assert program.attr_sets == sets, order
        assert audit.validate(_subprog_module(order)) == "subprog"


def test_subprog_two_sites_validate():
    # The audit admits one or more call sites: a second tail
    # call to the same callee validates in both orders.
    entry_body = (
        "  %1 = load i64, ptr %0, align 8\n"
        + (EMPTY % ("%2", "%1"))
        + "\n"
        "  %3 = tail call i64 @decide(i64 %1)\n"
        "  %second = tail call i64 @decide(i64 %1)\n"
        "  %5 = trunc i64 %3 to i32\n"
        "  ret i32 %5\n"
    )
    for order in ("before", "after"):
        text = _subprog_module(order, entry_body=entry_body)
        program = audit.scan(text)
        assert program.mode == "subprog", order
        assert program.callee == "decide", order
        assert len(program.subprog_calls) == 2, order
        assert audit.validate(text) == "subprog"


def test_subprog_branchy_callee_validates():
    body = (
        "  %2 = icmp sgt i64 %0, 100\n"
        "  br i1 %2, label %big, label %small\n"
        "big:\n"
        "  %3 = sub i64 %0, 100\n"
        "  br label %done\n"
        "small:\n"
        "  %4 = add i64 %0, 100\n"
        "  br label %done\n"
        "done:\n"
        "  %5 = phi i64 [ %3, %big ], [ %4, %small ]\n"
        "  ret i64 %5\n"
    )
    for order in ("before", "after"):
        assert audit.validate(
            _subprog_module(order, callee_body=body)
        ) == "subprog", order


def test_subprog_literal_operands_validate():
    for operand in ("21", "-5", "0"):
        body = SUBPROG_ENTRY_BODY.replace(
            "tail call i64 @decide(i64 %1)",
            "tail call i64 @decide(i64 %s)" % operand,
        )
        assert audit.validate(_subprog_module(entry_body=body)) == (
            "subprog"
        ), operand


def test_subprog_cross_scope_use_refused():
    callee_body = (
        "  %2 = add i64 %1, 1\n"
        "  ret i64 %2\n"
    )
    assert_rejected(
        _subprog_module(callee_body=callee_body), "MBPF315"
    )
    entry_body = SUBPROG_ENTRY_BODY.replace(
        "  %3 = tail call i64 @decide(i64 %1)\n",
        "  %3 = tail call i64 @decide(i64 %4)\n",
    )
    assert_rejected(_subprog_module(entry_body=entry_body), "MBPF315")


def test_subprog_reserved_name_never_callee():
    text = _subprog_module(callee_name="__mojobpf_lookup_v1")
    assert_rejected(text, "MBPF313")


def test_subprog_entry_named_callee_refused():
    text = _subprog_module(callee_name="xdp_entry")
    assert_rejected(text, "MBPF302")


def test_subprog_quoted_name_refused():
    text = _subprog_module().replace(
        "define dso_local i64 @decide(i64 noundef %0) #0 {",
        'define dso_local i64 @"decide::mangled"(i64 noundef %0) #0 {',
    )
    assert_rejected(text, "MBPF302")


def test_subprog_duplicate_callee_refused():
    text = _subprog_module()
    callee = (
        "define dso_local i64 @decide(i64 noundef %0) #0 {\n"
        + SUBPROG_CALLEE_BODY
        + "}\n"
    )
    assert text.count(callee) == 1
    text = text.replace(callee, callee + "\n" + callee)
    assert_rejected(text, "MBPF302")


def test_subprog_callee_without_entry_refused():
    text = (
        SUBPROG_MODULE_HEADER
        + "\n"
        + "define dso_local i64 @decide(i64 noundef %0) #0 {\n"
        + SUBPROG_CALLEE_BODY
        + "}\n"
        + "\n"
        + SUBPROG_ATTRS
    )
    assert_rejected(text, "MBPF302")


def test_subprog_second_attrs_refused_without_callee():
    assert_rejected(CLASSIFIER_IR + 'attributes #1 = { }\n', "MBPF309")


def test_subprog_unknown_direct_call_refused_without_callee():
    text = with_body_line(
        CLASSIFIER_IR, "%9 = tail call i64 @decide(i64 1)"
    )
    assert_rejected(text, "MBPF303")


def test_subprog_post_counts():
    audit.audit_post(
        "  %2 = tail call i64 @decide(i64 %1)\n", "subprog"
    )
    try:
        audit.audit_post(
            "  %4 = call i64 inttoptr (i64 1 to ptr)"
            "(i64 %3, ptr %2)\n",
            "subprog",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError("post audit accepted helper in subprog")


def test_subprog_callee_load_refused_any_operand():
    # Operand spelling must not matter: the purity gate refuses by
    # opcode. The inttoptr spelling trips the earlier erasure check
    # (MBPF311) before reaching the gate, and the folded constant
    # expression trips the line-shape check (MBPF321); the plain
    # spelling reaches the gate itself (MBPF303).
    cases = (
        ("ptr null", "MBPF303"),
        ("ptr getelementptr (i64, ptr null, i32 1)", "MBPF321"),
        ("ptr inttoptr (i64 0 to ptr)", "MBPF311"),
    )
    for operand, code in cases:
        callee_body = (
            "  %2 = and i64 %0, 1\n"
            "  %3 = icmp eq i64 %2, 1\n"
            "  %4 = select i1 %3, i64 1, i64 2\n"
            "  %5 = load i64, " + operand + "\n"
            "  ret i64 %5\n"
        )
        for order in ("before", "after"):
            assert_rejected(
                _subprog_module(order, callee_body=callee_body),
                code,
            )


def _tracepoint_text(lines):
    suffix = "".join(
        line + "\n"
        for line in (
            audit.LOOKUP_DECL_LINE,
            audit.PID_DECL_LINE,
            audit.UPDATE_DECL_LINE,
        )
    )
    return (
        TRACEPOINT_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def _uprobe_text(lines):
    suffix = "".join(
        line + "\n"
        for line in (
            audit.LOOKUP_DECL_LINE,
            audit.UPDATE_DECL_LINE,
        )
    )
    return (
        UPROBE_HEADER
        + "\n".join(lines)
        + "\n"
        + FOOTER.replace("}\n", "}\n" + suffix, 1)
    )


def _shape_multiset(ir_text):
    """Sorted admitted call shapes of an IR module.

    The reorder corpus proves each mutant keeps its fixture's
    exact shape multiset: only the preparation order changed, so
    only the key-freshness verdict may differ.
    """
    shapes = []
    for raw in ir_text.splitlines():
        shape = audit.match_shape(audit.strip_comment(raw).strip())
        if shape is not None:
            shapes.append(shape)
    return sorted(shapes)


def _assert_same_shapes(good, bad):
    assert _shape_multiset(good) == _shape_multiset(bad), (
        "reorder mutant changed the shape multiset"
    )


def _assert_numeric_def_order(ir_text):
    """Numeric labels and SSA definitions keep valid LLVM order.

    LLVM numbers unnamed blocks and temporaries together in
    order of appearance, so a mutant that moves a
    high-numbered definition above a low-numbered one is not
    valid IR and proves nothing about executable behavior. The
    freshness mutants below hoist preparations through named
    temporaries (dropping the moved numeric definition and
    repointing its uses) so the remaining numeric ids keep
    their committed increasing order. Three further validity
    constraints are pinned here: a digit-start alphanumeric
    name (``%58a``) is invalid unless quoted, and quoted names
    are outside the audited subset; an unnamed entry block
    consumes slot 1, so a body without a leading label must not
    define ``%1``; and numeric labels interleave with numeric
    SSA definitions in one increasing sequence, so a numeric
    label following a higher temporary (``36:`` after ``%64``)
    is invalid. Label and SSA names share one namespace, so a
    collision between them is likewise invalid.
    """
    seq = []
    defined = set()
    labels = set()
    in_body = False
    entry_labeled = None
    for raw in ir_text.splitlines():
        line = audit.strip_comment(raw).strip()
        if line.startswith("define "):
            in_body = True
            continue
        if not in_body or not line or line.startswith("!"):
            continue
        if line == "}":
            in_body = False
            continue
        code = audit.QUOTED_STRING_RE.sub('""', line)
        for name in re.findall(r"%([0-9][A-Za-z0-9_.$-]*)", code):
            assert name.isdigit(), (
                "invalid numeric-prefixed SSA name: %%%s" % name
            )
        if audit.LABEL_DEF_RE.match(line):
            labels.add(line[:-1])
            if line[:-1].isdigit():
                seq.append(int(line[:-1]))
            if entry_labeled is None:
                entry_labeled = True
            continue
        if entry_labeled is None:
            entry_labeled = False
        match = audit.SSA_DEF_RE.match(line)
        if match:
            defined.add(match.group(1))
            if match.group(1).isdigit():
                seq.append(int(match.group(1)))
    if entry_labeled is False:
        seq = [1] + seq
    assert seq == sorted(seq), (
        "numeric block/SSA ids out of order: %r" % (seq,)
    )
    assert len(set(seq)) == len(seq), (
        "numeric block/SSA id repeated: %r" % (seq,)
    )
    assert not (labels & defined), (
        "label/SSA name collision: %r" % (labels & defined,)
    )


def test_keyfresh_tracepoint_reorder_rejected():
    # Imported reordered tracepoint fixture (F-017): the committed
    # counter with key_slot1() hoisted above the filter lookup
    # (audit probe freshness_probe.mojo, freshness.raw.ll:7-10).
    # The hoisted preparation keeps its shape but takes a named
    # temporary, and the count lookup is repointed to it, so the
    # numeric SSA definitions keep valid increasing order; only
    # the execution order changed. The filter lookup would read
    # entry 1 while the audit records key 0; the audit must
    # reject, never accept with a swapped expected key.
    lines = _tracepoint_body()
    lines.remove(KEYSLOT1 % "%16")
    lines.insert(
        lines.index(KEYSLOT % "%2") + 1, KEYSLOT1 % "%kfhoist"
    )
    look = LOOKUP % ("%18", "%17", "%16")
    lines[lines.index(look)] = LOOKUP % ("%18", "%17", "%kfhoist")
    good = _tracepoint_module()
    bad = _tracepoint_text(lines)
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "lookup key operand %2" in exc.explanation, exc.explanation
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )
    assert "shared key slot" in exc.explanation, exc.explanation
    lookup_lineno = bad.splitlines().index(
        LOOKUP % ("%4", "%3", "%2")
    ) + 1
    assert exc.location == "line %d" % lookup_lineno, exc.location
    assert "immediately before" in exc.remedy, exc.remedy


def test_keyfresh_combined_reorder_rejected():
    # Combined mode is liveness-exempt, but the exemption never
    # exempts key freshness: the hoisted key-1 preparation
    # clobbers the first pair's lookup. Named-temporary hoist as
    # above, preserving valid numeric order.
    bad = COMBINED_IR.replace((KEYSLOT1 % "%16") + "\n", "", 1)
    anchor = (KEYSLOT % "%5") + "\n"
    assert bad != COMBINED_IR and anchor in bad
    bad = bad.replace(
        anchor, anchor + (KEYSLOT1 % "%kfhoist") + "\n", 1
    )
    look = (LOOKUP % ("%18", "%17", "%16")) + "\n"
    assert bad.count(look) == 1
    bad = bad.replace(
        look, (LOOKUP % ("%18", "%17", "%kfhoist")) + "\n", 1
    )
    _assert_same_shapes(COMBINED_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_uprobe_reorder_rejected():
    # Uprobe mode is liveness-exempt; the hoisted key-1
    # preparation still clobbers the filter lookup.
    # Named-temporary hoist, preserving valid numeric order.
    lines = _uprobe_body()
    lines.remove(KEYSLOT1 % "%16")
    lines.insert(
        lines.index(KEYSLOT % "%4") + 1, KEYSLOT1 % "%kfhoist"
    )
    look = LOOKUP % ("%18", "%17", "%16")
    lines[lines.index(look)] = LOOKUP % ("%18", "%17", "%kfhoist")
    good = _uprobe_module()
    bad = _uprobe_text(lines)
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_event_reorder_rejected():
    # Event mode is liveness-exempt; the hoisted sequence-key
    # preparation still clobbers the filter lookup.
    # Named-temporary hoist, preserving valid numeric order.
    lines = _event_body()
    lines.remove(KEYSLOT1 % "%16")
    lines.insert(
        lines.index(KEYSLOT % "%2") + 1, KEYSLOT1 % "%kfhoist"
    )
    look = LOOKUP % ("%18", "%17", "%16")
    lines[lines.index(look)] = LOOKUP % ("%18", "%17", "%kfhoist")
    good = _event_module()
    bad = _event_text(lines)
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_reserve_reorder_rejected():
    # Reserve mode is liveness-exempt on both termini; the hoisted
    # sequence-key preparation still clobbers the filter lookup.
    # Named-temporary hoist, preserving valid numeric order.
    for terminus in ("submit", "discard"):
        lines = _reserve_body(terminus)
        lines.remove(KEYSLOT1 % "%15")
        lines.insert(
            lines.index(KEYSLOT % "%2") + 1, KEYSLOT1 % "%kfhoist"
        )
        look = LOOKUP % ("%17", "%16", "%15")
        lines[lines.index(look)] = LOOKUP % (
            "%17", "%16", "%kfhoist"
        )
        good = _reserve_module(terminus)
        bad = _reserve_module_wrapped(lines, terminus)
        _assert_same_shapes(good, bad)
        _assert_numeric_def_order(bad)
        exc = assert_rejected(bad, "MBPF318")
        assert "would read key 1, not key 0" in exc.explanation, (
            exc.explanation
        )


def test_keyfresh_delete_reorder_rejected():
    # Delete calls are never liveness roots, so the liveness
    # check is vacuous here; key freshness still rejects the
    # hoisted key-1 preparation clobbering the first deletion.
    # Named-temporary hoist, preserving valid numeric order.
    good = _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)])
    bad = good.replace((KEYSLOT1 % "%8") + "\n", "", 1)
    anchor = (KEYSLOT % "%2") + "\n"
    assert bad != good and anchor in bad
    bad = bad.replace(
        anchor, anchor + (KEYSLOT1 % "%kfhoist") + "\n", 1
    )
    stale = (DELETE % ("%11", "%9", "%8")) + "\n"
    assert bad.count(stale) == 1
    bad = bad.replace(
        stale, (DELETE % ("%11", "%9", "%kfhoist")) + "\n", 1
    )
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "delete key operand %2" in exc.explanation, exc.explanation
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_branch_local_clobber_rejected():
    # The update's key-1 preparation moves into an unconditional
    # arm before the filter lookup, through a named temporary so
    # numeric order stays valid; the update is repointed to it.
    # The arm always executes, so the filter lookup genuinely
    # reads entry 1 while the audit records key 0. The arm labels
    # form a pure execution chain, so the clobber (not the edge)
    # is reported.
    lines = _tracepoint_body()
    lines.remove(KEYSLOT1 % "%26")
    anchor = lines.index(MAPADDR % "%3")
    lines[anchor + 1:anchor + 1] = [
        "  br label %keyfresh_arm",
        "keyfresh_arm:",
        KEYSLOT1 % "%kfhoist",
        "  br label %keyfresh_cont",
        "keyfresh_cont:",
    ]
    stale = UPDATE % ("%28", "%27", "%26", "%22")
    lines[lines.index(stale)] = UPDATE % (
        "%28", "%27", "%kfhoist", "%22"
    )
    bad = _tracepoint_text(lines)
    _assert_same_shapes(_tracepoint_module(), bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_arm_prep_consumed_after_merge_rejected():
    # The count pair's key-1 preparation moves into the miss arm
    # (named temporary, valid numeric order) and the count lookup
    # keeps consuming it after the merge. On the hit path the
    # preparation never executes, so the shared slot's value at
    # the call is ambiguous and the audit refuses the lifetime
    # even though no second preparation is visible. The use is
    # not dominated by its definition, which is exactly what
    # makes the lifetime ambiguous: no valid-IR spelling can
    # express a may-not-have-executed preparation, so the audit
    # is the first rejecting layer here as for use-before-def.
    lines = _tracepoint_body()
    lines.remove(KEYSLOT1 % "%16")
    lines.insert(lines.index("6:") + 1, KEYSLOT1 % "%kfhoist")
    look = LOOKUP % ("%18", "%17", "%16")
    lines[lines.index(look)] = LOOKUP % ("%18", "%17", "%kfhoist")
    bad = _tracepoint_text(lines)
    _assert_same_shapes(_tracepoint_module(), bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "lookup key operand %kfhoist" in exc.explanation, (
        exc.explanation
    )
    assert "control-flow edge" in exc.explanation, exc.explanation
    assert "cannot prove it reads key 1" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_repeated_key_update_rejected():
    # The update reuses the count lookup's key SSA instead of its
    # own fresh preparation, with a same-literal re-preparation
    # between them. The value happens to match, but the lifetime
    # is unproven: any re-preparation of the shared slot breaks
    # the chain, so the audit refuses it. The count dispatch is
    # straightened to an unconditional chain (dropping the dead
    # miss arm) so the reaching preparation is control-flow pure
    # and only the same-literal clobber reports; tracepoint mode
    # is liveness-exempt, so the reused SSA reaches the freshness
    # proof. Valid IR throughout: only one key operand changes
    # and no definition moves.
    lines = _tracepoint_body()
    stale = UPDATE % ("%28", "%27", "%26", "%22")
    lines[lines.index(stale)] = UPDATE % ("%28", "%27", "%16", "%22")
    cond = "  br i1 %19, label %20, label %21"
    lines[lines.index(cond)] = "  br label %21"
    drop = lines.index("20:")
    del lines[drop:drop + 2]
    bad = _tracepoint_text(lines)
    _assert_same_shapes(_tracepoint_module(), bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "update key operand %16" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 1" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_repeated_key_delete_rejected():
    # The second deletion reuses the first deletion's key SSA
    # instead of its own fresh preparation. The first deletion
    # stays fresh, so the second call is the first stale use.
    good = _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)])
    stale = DELETE % ("%11", "%9", "%8")
    assert good.count(stale) == 1
    bad = good.replace(stale, DELETE % ("%11", "%9", "%2"), 1)
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "delete key operand %2" in exc.explanation, exc.explanation
    assert "cannot prove it reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_use_before_def_rejected():
    # The lookup consumes its key SSA before the preparation
    # line: the shared slot holds no proven value there.
    # Consuming a value before its definition is definitionally
    # invalid IR, so no valid-IR counterpart can express it; the
    # audit's MBPF318 is the first rejecting layer.
    slot = (KEYSLOT % "%2") + "\n"
    look = (LOOKUP % ("%4", "%3", "%2")) + "\n"
    assert MAP_IR.count(slot) == 1 and MAP_IR.count(look) == 1
    bad = MAP_IR.replace(slot, "@@SLOT@@\n", 1)
    bad = bad.replace(look, slot, 1)
    bad = bad.replace("@@SLOT@@\n", look, 1)
    _assert_same_shapes(MAP_IR, bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "before its preparation" in exc.explanation, exc.explanation
    assert "immediately before" in exc.remedy, exc.remedy


def test_keyfresh_fallthrough_split_validates():
    # A pure fallthrough split between the update's preparation
    # and its call keeps the lifetime proven: the labels carry no
    # join, no dispatch, and no re-preparation. The split takes
    # named labels and a named filler temporary: numeric labels
    # and definitions would consume numbering slots the trailing
    # call reuses.
    good = with_orphan_block(
        MAP_IR, "%orph = add i64 1, 2",
        orphan="kfside", cont="kfcont",
    )
    _assert_numeric_def_order(good)
    assert audit.validate(good) == "map"


def test_keyfresh_fresh_preparation_validates():
    # Every exempt mode plus the strict map and delete families
    # keeps validating when each key-consuming call takes a
    # freshly prepared key: the fix rejects only stale use. The
    # committed positives also pin valid numeric order.
    good = [
        (COMBINED_IR, "combined"),
        (_tracepoint_module(), "tracepoint"),
        (_uprobe_module(), "uprobe"),
        (_event_module(), "event"),
        (_reserve_module("submit"), "reserve"),
        (_reserve_module("discard"), "reserve"),
        (MAP_IR, "map"),
        (_delete_ir([(0, KEYSLOT), (1, KEYSLOT1)]), "map"),
    ]
    for text, mode in good:
        _assert_numeric_def_order(text)
        assert audit.validate(text) == mode


def test_keyfresh_exec_order_tracepoint_rejected():
    # Block layout differs from execution order: the entry block
    # hops to a corrupting key-1 preparation laid out after the
    # function body, which branches back into the filter block.
    # Execution runs prepare(0) -> prepare(1) -> consume(key0),
    # so the filter lookup genuinely reads entry 1 while the
    # audit records key 0. A sole-predecessor count cannot see
    # this: the filter block's only predecessor has a single
    # successor. The count pair stays provably fresh (the update
    # takes the count lookup's key through a pure unconditional
    # chain), so the filter lookup is the only stale use. Valid
    # IR: the named temporary keeps numeric order and label/SSA
    # names disjoint.
    lines = _tracepoint_body()
    lines.remove(KEYSLOT1 % "%26")
    head = [KEYSLOT % "%2", MAPADDR % "%3"]
    assert lines[:2] == head
    rest = lines[2:]
    stale = UPDATE % ("%28", "%27", "%26", "%22")
    rest[rest.index(stale)] = UPDATE % ("%28", "%27", "%16", "%22")
    cond = "  br i1 %19, label %20, label %21"
    rest[rest.index(cond)] = "  br label %21"
    drop = rest.index("20:")
    del rest[drop:drop + 2]
    bad = _tracepoint_text(
        head + ["  br label %kfM", "kfF:"] + rest
        + ["kfM:", KEYSLOT1 % "%kfhoist", "  br label %kfF"]
    )
    _assert_same_shapes(_tracepoint_module(), bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "lookup key operand %2" in exc.explanation, exc.explanation
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_exec_order_delete_rejected():
    # Same layout/execution divergence over deletions: the first
    # deletion's block is split so execution runs prepare(0) ->
    # prepare(1) -> delete(key0) while the corrupting preparation
    # is laid out after the consuming call. The first deletion
    # genuinely deletes entry 1 while the audit records key 0.
    # The second deletion takes the corrupting preparation's key
    # through a pure chain and stays fresh, so the first deletion
    # is the only stale use.
    step1 = _delete_step(2, 0, KEYSLOT)
    step2 = _delete_step(8, 1, KEYSLOT1)
    bad = _family_module(
        [
            "  br label %kfF1",
            "kfF1:", step1[0], step1[1], "  br label %kfM",
            "kfF2:", step1[2], step1[3], "  br label %ok2",
            "kfM:", KEYSLOT1 % "%kfhoist", "  br label %kfF2",
            "ok2:", step2[1],
            DELETE % ("%11", "%9", "%kfhoist"),
            step2[3], step2[4], step2[5],
            "  ret i32 2",
            "drop2:", "  ret i32 1",
            "drop8:", "  ret i32 1",
        ],
        audit.DELETE_DECL_LINE,
    )
    good = _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)])
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "delete key operand %2" in exc.explanation, exc.explanation
    assert "would read key 1, not key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_plain_store_lookup_rejected():
    # A plain store to the key slot between the preparation and
    # the filter lookup corrupts the key without any second
    # preparation call: the clobber proof covers every write to
    # the cell, not just key-preparation calls.
    slot = (KEYSLOT % "%2") + "\n"
    assert MAP_IR.count(slot) == 1
    bad = MAP_IR.replace(
        slot, slot + "  store i32 1, ptr %2, align 4\n", 1
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "lookup key operand %2" in exc.explanation, exc.explanation
    assert "store at line" in exc.explanation, exc.explanation
    assert "shared key slot" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_plain_store_update_rejected():
    # Same direct corruption over the update's key.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    bad = MAP_IR.replace(
        anchor, anchor + "  store i32 9, ptr %12, align 4\n", 1
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "update key operand %12" in exc.explanation, exc.explanation
    assert "store at line" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_gep_alias_lookup_rejected():
    # The corrupting store addresses the key cell through a
    # getelementptr derived from the key slot: derived pointers
    # are part of the freshness proof.
    slot = (KEYSLOT % "%2") + "\n"
    assert MAP_IR.count(slot) == 1
    bad = MAP_IR.replace(
        slot,
        slot + "  %kfgep = getelementptr inbounds i8, ptr %2, i32 0\n"
        "  store i8 7, ptr %kfgep, align 1\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "lookup key operand %2" in exc.explanation, exc.explanation
    assert "through %kfgep" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_gep_alias_delete_rejected():
    # Same derived-pointer corruption over a deletion.
    good = _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)])
    anchor = (MAPADDR % "%3") + "\n"
    assert good.count(anchor) == 1
    bad = good.replace(
        anchor,
        anchor + "  %kfgep = getelementptr inbounds i8, ptr %2, i32 0\n"
        "  store i8 7, ptr %kfgep, align 1\n",
        1,
    )
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "delete key operand %2" in exc.explanation, exc.explanation
    assert "through %kfgep" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_ambiguous_slot_view_rejected():
    # A store through a view derived from the value slot may reach
    # the key cell (offset 12 off r10-16 is r10-4): when aliasing
    # is ambiguous the audit rejects conservatively.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    bad = MAP_IR.replace(
        anchor,
        anchor
        + "  %kfvgep = getelementptr inbounds i8, ptr %8, i32 12\n"
        "  store i8 9, ptr %kfvgep, align 1\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "update key operand %12" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_direct_slot_store_validates():
    # A store addressed directly through the value slot between a
    # key preparation and its call writes a disjoint audited cell,
    # so the key lifetime stays proven: the fix rejects only
    # writes that may reach the key cell.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    good = MAP_IR.replace(
        anchor, anchor + "  store i64 %11, ptr %8, align 8\n", 1
    )
    _assert_same_shapes(MAP_IR, good)
    _assert_numeric_def_order(good)
    assert audit.validate(good) == "map"


def test_keyfresh_freeze_alias_lookup_rejected():
    # A freeze of the key slot still addresses the key cell. The
    # opcode allowlist (WP-2) rejects freeze before dataflow, so
    # these probes now pin MBPF321; the alias proof still covers
    # freeze defensively if the allowlist ever widens.
    slot = (KEYSLOT % "%2") + "\n"
    assert MAP_IR.count(slot) == 1
    bad = MAP_IR.replace(
        slot,
        slot + "  %kffr = freeze ptr %2\n"
        "  store i32 1, ptr %kffr, align 4\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF321")
    assert "freeze" in exc.explanation, exc.explanation


def test_keyfresh_freeze_alias_update_rejected():
    # Same freeze laundering over the update's key.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    bad = MAP_IR.replace(
        anchor,
        anchor + "  %kffr = freeze ptr %12\n"
        "  store i32 9, ptr %kffr, align 4\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF321")
    assert "freeze" in exc.explanation, exc.explanation


def test_keyfresh_freeze_alias_delete_rejected():
    # Same freeze laundering over a deletion.
    good = _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)])
    anchor = (MAPADDR % "%3") + "\n"
    assert good.count(anchor) == 1
    bad = good.replace(
        anchor,
        anchor + "  %kffr = freeze ptr %2\n"
        "  store i32 1, ptr %kffr, align 4\n",
        1,
    )
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF321")
    assert "freeze" in exc.explanation, exc.explanation


def test_keyfresh_insertvalue_alias_lookup_rejected():
    # An insertvalue/extractvalue round trip launders the key-slot
    # pointer through an aggregate the extraction recovers. The
    # opcode allowlist (WP-2) rejects both aggregate opcodes
    # before dataflow, so these probes now pin MBPF321; the alias
    # proof still covers them defensively if the allowlist ever
    # widens. (The admitted one-lane-vector insert/extractELEMENT
    # pair is a different opcode family and stays allowed.)
    slot = (KEYSLOT % "%2") + "\n"
    assert MAP_IR.count(slot) == 1
    bad = MAP_IR.replace(
        slot,
        slot + "  %kfag = insertvalue {ptr} {ptr null}, ptr %2, 0\n"
        "  %kfex = extractvalue {ptr} %kfag, 0\n"
        "  store i32 1, ptr %kfex, align 4\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF321")
    assert "insertvalue" in exc.explanation, exc.explanation


def test_keyfresh_insertvalue_alias_delete_rejected():
    # Same aggregate laundering over a deletion.
    good = _delete_ir([(0, KEYSLOT), (1, KEYSLOT1)])
    anchor = (MAPADDR % "%3") + "\n"
    assert good.count(anchor) == 1
    bad = good.replace(
        anchor,
        anchor + "  %kfag = insertvalue {ptr} {ptr null}, ptr %2, 0\n"
        "  %kfex = extractvalue {ptr} %kfag, 0\n"
        "  store i32 1, ptr %kfex, align 4\n",
        1,
    )
    _assert_same_shapes(good, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF321")
    assert "insertvalue" in exc.explanation, exc.explanation


def test_keyfresh_aggregate_store_lookup_rejected():
    # A struct store through the key slot overwrites all four key
    # bytes (little-endian 01 00 00 00 reads back key 1): the
    # store parser splits the value at the top-level comma, never
    # inside the aggregate, so the clobber is analyzed, not
    # skipped.
    slot = (KEYSLOT % "%2") + "\n"
    assert MAP_IR.count(slot) == 1
    bad = MAP_IR.replace(
        slot,
        slot + "  store {i16, i16} {i16 1, i16 0}, ptr %2, align 4\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "lookup key operand %2" in exc.explanation, exc.explanation
    assert "store at line" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_aggregate_store_update_rejected():
    # Same aggregate corruption over the update's key.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    bad = MAP_IR.replace(
        anchor,
        anchor
        + "  store {i16, i16} {i16 9, i16 0}, ptr %12, align 4\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "update key operand %12" in exc.explanation, exc.explanation
    assert "store at line" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_wide_store_update_rejected():
    # A 16-byte store through the value slot (r10-16) reaches
    # r10-1, overwriting the r10-4 key cell: 2**96 lands byte 12
    # = 01 in the key's low byte, turning key 0 into key 1. The
    # benign-slot exemption accounts for store width, so only
    # provably disjoint narrow stores stay exempt.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    bad = MAP_IR.replace(
        anchor,
        anchor
        + "  store i128 79228162514264337593543950336, ptr %8, "
        "align 8\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "update key operand %12" in exc.explanation, exc.explanation
    assert "writes 16 bytes overlapping the shared key slot" in (
        exc.explanation
    ), exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_boundary_store_validates():
    # A 12-byte store at r10-16 ends exactly at r10-4 without
    # touching the key cell: the width check is exact, not a
    # blanket wide-store refusal.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    good = MAP_IR.replace(
        anchor, anchor + "  store i96 0, ptr %8, align 8\n", 1
    )
    _assert_same_shapes(MAP_IR, good)
    _assert_numeric_def_order(good)
    assert audit.validate(good) == "map"


def test_keyfresh_unknown_width_benign_rejected():
    # An aggregate store through the value slot has a
    # datalayout-dependent footprint the text route cannot size,
    # so it fails closed even though four bytes at r10-16 would
    # be disjoint: when in doubt the proof rejects.
    anchor = (MAPADDR % "%13") + "\n"
    assert MAP_IR.count(anchor) == 1
    bad = MAP_IR.replace(
        anchor,
        anchor + "  store {i16, i16} {i16 0, i16 0}, ptr %8, align 4\n",
        1,
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "update key operand %12" in exc.explanation, exc.explanation
    assert "unknown size" in exc.explanation, exc.explanation
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def test_keyfresh_unprovable_dest_rejected():
    # A store whose destination names no SSA value cannot be
    # proven disjoint from the key cell, so the live region
    # fails closed on it. (A constant expression cannot name a
    # function-local slot pointer, so no valid spelling hides a
    # slot write this way; the null destination below stands in
    # for the unprovable-destination class with valid IR.)
    slot = (KEYSLOT % "%2") + "\n"
    assert MAP_IR.count(slot) == 1
    bad = MAP_IR.replace(
        slot, slot + "  store i32 1, ptr null, align 4\n", 1
    )
    _assert_same_shapes(MAP_IR, bad)
    _assert_numeric_def_order(bad)
    exc = assert_rejected(bad, "MBPF318")
    assert "lookup key operand %2" in exc.explanation, exc.explanation
    assert "cannot be proven disjoint" in exc.explanation, (
        exc.explanation
    )
    assert "cannot prove it still reads key 0" in exc.explanation, (
        exc.explanation
    )


def _loop_body(blocks):
    return HEADER + "".join(blocks) + FOOTER


def test_loop_rejects_unbounded_self_edge():
    # A self-loop with no exit test is outside the bounded
    # slice: no header icmp proves a trip bound.
    bad = _loop_body(
        [
            "entry:\n",
            "  br label %loop\n",
            "loop:\n",
            "  br label %loop\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "loop" in exc.explanation, exc.explanation


def test_loop_rejects_varying_bound():
    # Both icmp operands are loop-defined (header phis fed
    # from the body), so no invariant bound exists.
    bad = _loop_body(
        [
            "entry:\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %body ]\n",
            "  %b = phi i64 [ 8, %entry ], [ %b2, %body ]\n",
            "  %c = icmp slt i64 %i, %b\n",
            "  br i1 %c, label %body, label %exit\n",
            "body:\n",
            "  %next = add i64 %i, 1\n",
            "  %b2 = add i64 %b, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "bound" in exc.explanation, exc.explanation


def test_loop_rejects_over_block_budget():
    # 131 reachable blocks exceed the mirrored MaxBlocks=128
    # cap even though the chain itself is acyclic.
    lines = ["entry:\n", "  br label %b1\n"]
    for num in range(1, 130):
        lines.append("b%d:\n" % num)
        lines.append("  br label %%b%d\n" % (num + 1))
    lines.append("b130:\n")
    lines.append("  ret i32 2\n")
    bad = _loop_body(lines)
    exc = assert_rejected(bad, "MBPF320")
    assert "block" in exc.explanation, exc.explanation


def _block_chain_ir(total):
    count = total - 2
    lines = [
        "entry:\n",
        "  %1 = load i64, ptr %0, align 8\n",
        (EMPTY % ("%2", "%1")) + "\n",
        "  br label %b1\n",
    ]
    for num in range(1, count + 1):
        target = "exit" if num == count else "b%d" % (num + 1)
        lines.append("b%d:\n" % num)
        lines.append("  br label %%%s\n" % target)
    lines.append("exit:\n")
    lines.append("  ret i32 2\n")
    return _loop_body(lines)


def test_loop_admits_block_budget_boundary():
    # Exactly CFG_MAX_BLOCKS=128 reachable blocks still validate,
    # mirroring the C++ `> MaxBlocks` comparison (129 fails).
    assert audit.validate(_block_chain_ir(128)) == "classifier"


def test_loop_rejects_block_budget_plus_one():
    exc = assert_rejected(_block_chain_ir(129), "MBPF320")
    assert "block limit" in exc.explanation, exc.explanation


def test_loop_admits_constant_bound():
    # Mirrors subset_loop_sum: header icmp of the IV against
    # a constant. Must keep validating (bounded loops stay
    # Lane-A under the classifier-loop mode).
    good = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %body ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  br i1 %c, label %exit, label %body\n",
            "body:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    assert audit.validate(good) == "classifier-loop"


def test_loop_admits_invariant_bound():
    # Mirrors subset_loop_pressure: header icmp of the IV
    # against a value defined outside the loop.
    good = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  %n = add i64 4, 4\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %body ]\n",
            "  %c = icmp slt i64 %i, %n\n",
            "  br i1 %c, label %body, label %exit\n",
            "body:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    assert audit.validate(good) == "classifier-loop"


def test_loop_rejects_dead_comparison():
    # R1 finding 2: the trip proof used to accept any header
    # icmp of a header phi, even one feeding nothing. This
    # mutant keeps the admitted constant-bound body but
    # disconnects the exit test (unconditional self-edge);
    # the dead comparison must not qualify the infinite loop.
    bad = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %body ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  br label %header\n",
            "body:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "loop" in exc.explanation, exc.explanation


def test_loop_rejects_self_fed_recurrence():
    # The exit test is connected, but the induction variable
    # never advances: the phi feeds itself on the loop edge.
    # Unproved recurrences stay outside the bounded slice.
    bad = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %i, %body ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  br i1 %c, label %exit, label %body\n",
            "body:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "loop" in exc.explanation, exc.explanation


def test_loop_admits_exit_test_after_header():
    # Mirrors subset_loop_sum's real emission: the header
    # holds the phis and the comparison, an unconditional
    # edge leads to the test block, and the test block's
    # condbr exits cleanly on one side and continues on the
    # other. The exit branch need not sit in the header.
    good = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %body ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  br label %test\n",
            "test:\n",
            "  br i1 %c, label %exit, label %body\n",
            "body:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    assert audit.validate(good) == "classifier-loop"


def test_loop_rejects_bypassed_exit_test():
    # R2 finding 1: the exit test must cover every backedge
    # traversal — it must dominate the latch. Here the
    # header's constant-false branch skips the test block on
    # every iteration, so the connected, clean-looking exit
    # never runs and the loop spins forever.
    bad = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %latch ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  br i1 false, label %test, label %latch\n",
            "test:\n",
            "  br i1 %c, label %exit, label %latch\n",
            "latch:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "loop" in exc.explanation, exc.explanation


def test_loop_rejects_bypass_on_live_condition():
    # Same bypass with a live (non-constant) branch
    # condition: dominance is structural, so the test that
    # does not dominate the latch proves nothing either way.
    bad = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  %u = icmp ne i64 %1, 0\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %latch ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  br i1 %u, label %test, label %latch\n",
            "test:\n",
            "  br i1 %c, label %exit, label %latch\n",
            "latch:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "loop" in exc.explanation, exc.explanation


def test_loop_rejects_nested_loops():
    # R2 finding 2: each loop below proves its own triple,
    # but the inner header sits inside the outer loop, so the
    # pair is nested — outside the admitted single-level
    # slice no matter how clean each proof looks alone.
    bad = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %outer\n",
            "outer:\n",
            "  %oi = phi i64 [ 0, %entry ], [ %onext, %outer_latch ]\n",
            "  %oc = icmp eq i64 %oi, 4\n",
            "  br i1 %oc, label %exit, label %inner\n",
            "inner:\n",
            "  %ii = phi i64 [ 0, %outer ], [ %inext, %inner_latch ]\n",
            "  %ic = icmp eq i64 %ii, %1\n",
            "  br i1 %ic, label %exit, label %inner_body\n",
            "inner_body:\n",
            "  %normal_done = icmp eq i64 %ii, 2\n",
            "  br i1 %normal_done, label %outer_latch, "
            "label %inner_latch\n",
            "inner_latch:\n",
            "  %inext = add i64 %ii, 1\n",
            "  br label %inner\n",
            "outer_latch:\n",
            "  %onext = add i64 %oi, 1\n",
            "  br label %outer\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "nested" in exc.explanation, exc.explanation


def test_loop_admits_sequential_loops():
    # Guard: two separate proven loops in one function are
    # not nesting — neither header sits in the other's loop.
    good = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %header1\n",
            "header1:\n",
            "  %i1 = phi i64 [ 0, %entry ], [ %n1, %body1 ]\n",
            "  %c1 = icmp eq i64 %i1, 4\n",
            "  br i1 %c1, label %mid, label %body1\n",
            "body1:\n",
            "  %n1 = add i64 %i1, 1\n",
            "  br label %header1\n",
            "mid:\n",
            "  br label %header2\n",
            "header2:\n",
            "  %i2 = phi i64 [ 0, %mid ], [ %n2, %body2 ]\n",
            "  %c2 = icmp eq i64 %i2, 8\n",
            "  br i1 %c2, label %exit, label %body2\n",
            "body2:\n",
            "  %n2 = add i64 %i2, 1\n",
            "  br label %header2\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    assert audit.validate(good) == "classifier-loop"


def test_loop_admits_self_loop():
    # Guard: a single-block loop (header is its own latch)
    # with a connected clean exit still proves its bound.
    good = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %spin\n",
            "spin:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %spin ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  %next = add i64 %i, 1\n",
            "  br i1 %c, label %exit, label %spin\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    assert audit.validate(good) == "classifier-loop"


def test_loop_rejects_exit_free_branch():
    # A connected comparison that never leaves the loop is no
    # exit test: both successors stay inside the cycle.
    bad = _loop_body(
        [
            "entry:\n",
            "  %1 = load i64, ptr %0, align 8\n",
            (EMPTY % ("%2", "%1")) + "\n",
            "  br label %header\n",
            "header:\n",
            "  %i = phi i64 [ 0, %entry ], [ %next, %body ]\n",
            "  %c = icmp eq i64 %i, 4\n",
            "  br i1 %c, label %body, label %body2\n",
            "body:\n",
            "  %next = add i64 %i, 1\n",
            "  br label %header\n",
            "body2:\n",
            "  br label %header\n",
            "exit:\n",
            "  ret i32 2\n",
        ]
    )
    exc = assert_rejected(bad, "MBPF319")
    assert "loop" in exc.explanation, exc.explanation


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
