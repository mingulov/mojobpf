# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the IR audit (``compiler/audit.py``).

Exercises the audit's exact codes, stages, locations, and edge cases
with inline IR modules: liveness crossings and non-crossings, operand
provenance, one-lane vector allowance, malformed reserved calls and
declarations, count vectors, first-failure ordering, and the
post-lowering checks. The ``tests/compile/unsupported/`` fixtures
cover one behavior per file; these tests cover the boundaries between
checks. Toolchain-independent: no Mojo compiler or LLVM tools needed.
Standard library only.

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
    try:
        audit.audit_post(
            "  %4 = call i64 inttoptr (i64 3 to ptr)(i64 %3, ptr %2)\n",
            "map",
        )
    except audit.AuditError as exc:
        assert exc.code == "MBPF306", exc.code
    else:
        raise AssertionError("post audit accepted helper ID 3")


def test_post_rejects_missing_lowered_call():
    try:
        audit.audit_post("  ret i32 2\n", "map")
    except audit.AuditError as exc:
        assert exc.code == "MBPF303", exc.code
    else:
        raise AssertionError("post audit accepted zero lowered calls")


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
