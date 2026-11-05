# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Controls for the Mojo IR adapter validator.

Feeds ``compiler/mojo_ir_adapter.validate`` minimal IR modules with one
of the restricted single-entrypoint shapes (classifier, map round
trip, or tracepoint counter here; the combined shape's positives
and negatives live in ``tests/ir/test_audit.py``), mutated one way
per case, and asserts each mutation is rejected against every count
vector. Every shape must keep validating, each shape must adapt
with its appended metadata blocks, and adapted bodies must stay
byte-identical outside the admitted helper-callee edits. Helper
invocations through inline assembly (including the old
read-write-constraint spellings) must be rejected: helpers lower
from reserved direct calls only.
Toolchain-independent: no Mojo compiler or LLVM tools are needed.
Standard library only.

Runnable directly (``python3 tests/ir/test_adapter_validation.py``) or
under any ``test_``-style runner.
"""

import os
import sys

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))

import mojo_ir_adapter as adapter

BASE_IR = """\
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr %0) #0 {
entry:
  %1 = load i64, ptr %0, align 8
  %2 = call ptr asm "", "=r,0"(i64 %1)
  ret i32 2
}
attributes #0 = { "target-cpu"="v3" }
"""

RET_ANCHOR = "  ret i32 2\n"


def with_body_line(extra):
    """Insert an extra line into the classifier body."""
    assert RET_ANCHOR in BASE_IR
    return BASE_IR.replace(RET_ANCHOR, "  " + extra + "\n" + RET_ANCHOR)


def assert_rejected(ir_text, code):
    try:
        adapter.validate(ir_text)
    except adapter.AdapterError as exc:
        assert exc.code == code, (exc.code, code, exc)
        assert exc.stage == "adapter.audit", (exc.stage, exc)
        return
    raise AssertionError("validator accepted input it must reject")


def assert_rejected_all(variants, code):
    for ir_text in variants:
        assert_rejected(ir_text, code)


def test_allowed_shape_validates():
    adapter.validate(BASE_IR)


def test_reject_extra_define():
    assert_rejected_all(
        [
            BASE_IR + "define i32 @evil() { ret i32 0 }\n",
            MAP_IR + "define i32 @evil() { ret i32 0 }\n",
        ]
    , "MBPF302")


def test_reject_runtime_call():
    assert_rejected_all(
        body_variants("%9 = call i32 @KGEN_runtime()")
    , "MBPF303")


def test_reject_declare():
    assert_rejected_all(
        module_variants(suffix="declare i32 @ext()\n"), "MBPF303"
    )


def test_reject_float():
    assert_rejected_all(
        body_variants("%7 = fadd double 1.0, 2.0")
    , "MBPF305")


def test_reject_vector():
    assert_rejected_all(
        body_variants(
            "%8 = add <4 x i32> zeroinitializer, zeroinitializer"
        )
    , "MBPF305")


def test_reject_scalable_vector():
    assert_rejected_all(
        body_variants(
            "%8 = add <vscale x 4 x i32> zeroinitializer, zeroinitializer"
        )
    , "MBPF305")


def test_reject_nonempty_asm():
    assert_rejected_all(
        body_variants('%6 = call ptr asm "mov $0, $1", "=r,0"(i64 %1)')
    , "MBPF303")


def test_reject_untied_cast():
    """The old untied spelling must no longer validate."""
    assert_rejected_all(
        body_variants('%6 = call ptr asm "", "=r,r"(i64 %1)')
    , "MBPF303")


def test_reject_global():
    assert_rejected_all(
        module_variants(prefix="@g = global i32 0\n"), "MBPF309"
    )


def test_reject_quoted_global_with_spaces():
    assert_rejected_all(
        module_variants(prefix='@"my global" = global i32 0\n')
    , "MBPF309")


def test_reject_invoke():
    assert_rejected_all(
        body_variants("invoke void @f() to label %x unwind label %y")
    , "MBPF304")


def test_reject_callbr_asm():
    assert_rejected_all(
        body_variants(
            'callbr ptr asm "int $3", ""() to label %ok [label %fail]'
        )
    , "MBPF306")


def test_reject_module_asm():
    assert_rejected_all(
        module_variants(suffix='module asm "int3"\n'), "MBPF309"
    )


def test_reject_define_tail():
    """No instruction may hide after the definition-line '{'."""

    def tailed(base):
        assert base.count(" #0 {") == 1
        return base.replace(" #0 {", " #0 { %evil = add i32 1, 2", 1)

    assert_rejected_all([tailed(BASE_IR), tailed(MAP_IR)], "MBPF302")


def test_reject_type_definition():
    assert_rejected_all(
        module_variants(prefix="%struct.evil = type { i32 }\n")
    , "MBPF309")


def test_reject_alias():
    assert_rejected_all(
        module_variants(prefix="@al = alias i32, ptr @xdp_entry\n")
    , "MBPF309")


def test_reject_attrs_group_1():
    assert_rejected_all(
        module_variants(suffix='attributes #1 = { "target-cpu"="v3" }\n')
    , "MBPF309")


def test_reject_stray_close_text():
    assert_rejected_all(body_variants("} garbage"), "MBPF302")


def test_reject_unterminated_body():
    def unterminated(base):
        lines = [
            line for line in base.splitlines(keepends=True)
            if line.strip() != "}"
        ]
        assert len(lines) < len(base.splitlines(keepends=True))
        return "".join(lines)

    # Doubly-invalid input: the missing brace strands the trailing
    # `attributes` line inside the body, which the opcode allowlist
    # (WP-2) rejects before the entry-structure check runs.
    assert_rejected(unterminated(BASE_IR), "MBPF321")
    assert_rejected(unterminated(MAP_IR), "MBPF313")


# The map round-trip shape: exact lines as emitted by the Mojo
# frontend for the SDK wrappers (one line per wrapper call), with the
# helper invocations as direct calls to the reserved declarations.
KEYSLOT_LINE = (
    "  %2 = call ptr asm sideeffect "
    '"r0 = r10\\0Ar0 += -4\\0A*(u32 *)(r0 + 0) = r1", '
    '"={r0},{r1},~{memory}"(i32 0)'
)
MAPADDR_LINE = (
    '  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()'
)
LOOKUP_LINE = (
    "  %4 = call i64 @__mojobpf_lookup_v1(i64 %3, ptr %2)"
)
VALSLOT_LINE = (
    "  %8 = call ptr asm sideeffect "
    '"r0 = r10\\0Ar0 += -16", "={r0}"()'
)
EMPTY_LINE = '  %9 = call ptr asm "", "=r,0"(i64 %4)'
UPDATE_LINE = (
    "  %14 = call i64 @__mojobpf_update_v1"
    "(i64 %13, ptr %12, ptr %8, i64 0)"
)
LOOKUP_DECL = "declare i64 @__mojobpf_lookup_v1(i64, ptr) #0"
UPDATE_DECL = "declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0"

# The retired helper spellings: inline assembly with read-write
# argument constraints. These cannot model the call contract and must
# stay rejected.
LEGACY_LOOKUP_LINE = (
    '  %4 = call i64 asm sideeffect "call 1", '
    '"={r0},+{r1},+{r2},~{r3},~{r4},~{r5},~{memory}"(i64 %3, ptr %2)'
)
LEGACY_UPDATE_LINE = (
    '  %14 = call i64 asm sideeffect "call 2", '
    '"={r0},+{r1},+{r2},+{r3},+{r4},~{r5},~{memory}"'
    "(i64 %13, ptr %12, ptr %8, i64 0)"
)

MAP_BODY = "\n".join(
    [
        KEYSLOT_LINE,
        MAPADDR_LINE,
        LOOKUP_LINE,
        "  %5 = icmp eq i64 %4, 0",
        "  br i1 %5, label %6, label %7",
        "6:",
        "  br label %15",
        "7:",
        VALSLOT_LINE,
        EMPTY_LINE,
        "  %10 = load i64, ptr %9, align 8",
        "  %11 = add i64 %10, 1",
        "  store i64 %11, ptr %8, align 8",
        KEYSLOT_LINE.replace("%2 =", "%12 =", 1),
        MAPADDR_LINE.replace("%3 =", "%13 =", 1),
        UPDATE_LINE,
        "  br label %15",
        "15:",
        "  ret i32 2",
    ]
)

MAP_IR = "\n".join(
    [
        adapter.HOST_DATALAYOUT,
        adapter.HOST_TRIPLE,
        adapter.ENTRY_DEFINE,
        MAP_BODY,
        "}",
        LOOKUP_DECL,
        UPDATE_DECL,
        adapter.HOST_ATTRS,
        "",
    ]
)

CLASSIFIER_BODY = "\n".join(
    [
        "entry:",
        "  %1 = load i64, ptr %0, align 8",
        '  %2 = call ptr asm "", "=r,0"(i64 %1)',
        "  ret i32 2",
    ]
)

CLASSIFIER_IR = "\n".join(
    [
        adapter.HOST_DATALAYOUT,
        adapter.HOST_TRIPLE,
        adapter.ENTRY_DEFINE,
        CLASSIFIER_BODY,
        "}",
        adapter.HOST_ATTRS,
        "",
    ]
)

# The tracepoint counter shape: one filter read through key 0, one
# current-PID/TID call, and one read-modify-write pair through key
# 1, with the context pointer unused.
KEYSLOT1_LINE = (
    "  %16 = call ptr asm sideeffect "
    '"r0 = r10\\0Ar0 += -4\\0A*(u32 *)(r0 + 0) = r1", '
    '"={r0},{r1},~{memory}"(i32 1)'
)
PID_LINE = "  %10 = call i64 @__mojobpf_get_pid_tgid_v1()"
PID_DECL = "declare i64 @__mojobpf_get_pid_tgid_v1() #0"

TRACEPOINT_BODY = "\n".join(
    [
        KEYSLOT_LINE,
        MAPADDR_LINE,
        LOOKUP_LINE,
        "  %5 = icmp eq i64 %4, 0",
        "  br i1 %5, label %6, label %7",
        "6:",
        "  br label %31",
        "7:",
        EMPTY_LINE.replace("%9 =", "%8 =", 1),
        "  %9 = load i64, ptr %8, align 8",
        PID_LINE,
        "  %11 = and i64 %10, 4294967295",
        "  %12 = icmp eq i64 %9, %11",
        "  %13 = xor i1 %12, true",
        "  br i1 %13, label %14, label %15",
        "14:",
        "  br label %30",
        "15:",
        KEYSLOT1_LINE,
        MAPADDR_LINE.replace("%3 =", "%17 =", 1),
        LOOKUP_LINE.replace("%4 =", "%18 =", 1).replace(
            "i64 %3, ptr %2", "i64 %17, ptr %16"
        ),
        "  %19 = icmp eq i64 %18, 0",
        "  br i1 %19, label %20, label %21",
        "20:",
        "  br label %29",
        "21:",
        VALSLOT_LINE.replace("%8 =", "%22 =", 1),
        EMPTY_LINE.replace("%9 =", "%23 =", 1).replace(
            "(i64 %4)", "(i64 %18)"
        ),
        "  %24 = load i64, ptr %23, align 8",
        "  %25 = add i64 %24, 1",
        "  store i64 %25, ptr %22, align 8",
        KEYSLOT1_LINE.replace("%16 =", "%26 =", 1),
        MAPADDR_LINE.replace("%3 =", "%27 =", 1),
        UPDATE_LINE.replace("%14 =", "%28 =", 1)
        .replace("i64 %13,", "i64 %27,")
        .replace("ptr %12,", "ptr %26,")
        .replace("ptr %8,", "ptr %22,"),
        "  br label %29",
        "29:",
        "  br label %30",
        "30:",
        "  br label %31",
        "31:",
        "  ret i32 0",
    ]
)

TRACEPOINT_IR = "\n".join(
    [
        adapter.HOST_DATALAYOUT,
        adapter.HOST_TRIPLE,
        adapter.TRACE_ENTRY_DEFINE,
        TRACEPOINT_BODY,
        "}",
        LOOKUP_DECL,
        PID_DECL,
        UPDATE_DECL,
        adapter.HOST_ATTRS,
        "",
    ]
)


def with_map_body_line(extra):
    """Insert an extra line into the map body."""
    anchor = "  ret i32 2\n"
    assert MAP_IR.count(anchor) == 1
    return MAP_IR.replace(anchor, "  " + extra + "\n" + anchor)


def body_variants(extra):
    """The same bad body line inserted into each admitted vector."""
    return [with_body_line(extra), with_map_body_line(extra)]


def module_variants(prefix="", suffix=""):
    """The same bad module text wrapped around each admitted vector."""
    return [prefix + BASE_IR + suffix, prefix + MAP_IR + suffix]


def test_map_shape_validates():
    adapter.validate(MAP_IR)
    adapted = adapter.adapt(MAP_IR)
    assert "mojobpf_map0" in adapted, "adapted IR must define the map"
    assert 'section ".maps"' in adapted, "adapted IR must carry .maps"
    assert ".BTF" in adapted, "adapted IR must carry .BTF"
    assert "[3 x ptr]" in adapted, "map mode must pin map+license+entry"


def test_map_adapt_lowers_only_callees():
    adapted = adapter.adapt(MAP_IR)
    lowered_lookup = LOOKUP_LINE.replace(
        "@__mojobpf_lookup_v1", "inttoptr (i64 1 to ptr)"
    )
    lowered_update = UPDATE_LINE.replace(
        "@__mojobpf_update_v1", "inttoptr (i64 2 to ptr)"
    )
    assert lowered_lookup in adapted, (
        "adapted IR must carry the lowered lookup callee"
    )
    assert lowered_update in adapted, (
        "adapted IR must carry the lowered update callee"
    )
    assert "__mojobpf_lookup_v1" not in adapted, (
        "adapted IR must not reference the lookup declaration"
    )
    assert "__mojobpf_update_v1" not in adapted, (
        "adapted IR must not reference the update declaration"
    )
    for line in MAP_BODY.splitlines():
        if line in (LOOKUP_LINE, UPDATE_LINE):
            continue
        assert line in adapted, (
            "adapted IR must keep body line byte-identical: %r" % line
        )


def test_classifier_adapts_with_license():
    adapter.validate(CLASSIFIER_IR)
    adapted = adapter.adapt(CLASSIFIER_IR)
    assert "@_license" in adapted, "adapted IR must declare the license"
    assert "[2 x ptr]" in adapted, "classifier mode must pin license+entry"
    for line in CLASSIFIER_BODY.splitlines():
        assert line in adapted, (
            "adapted IR must keep body line byte-identical: %r" % line
        )


SOCKET_DEFINE = (
    "define dso_local i32 @socket_entry(ptr noundef %0) #0 {"
)
TC_DEFINE = (
    "define dso_local i32 @tc_entry(ptr noundef %0) #0 {"
)
SOCKET_IR = CLASSIFIER_IR.replace(
    adapter.ENTRY_DEFINE, SOCKET_DEFINE, 1
)
TC_IR = CLASSIFIER_IR.replace(adapter.ENTRY_DEFINE, TC_DEFINE, 1)


def _validate_or_fail(ir_text, label):
    try:
        return adapter.validate(ir_text)
    except adapter.AdapterError as exc:
        raise AssertionError(
            "%s refused: %s" % (label, exc)
        )


def test_socket_shape_validates_and_adapts_with_section():
    assert _validate_or_fail(SOCKET_IR, "socket") == "classifier"
    adapted = adapter.adapt(SOCKET_IR)
    assert 'section "socket"' in adapted, (
        "adapted IR must carry the socket section"
    )
    assert "[2 x ptr]" in adapted, (
        "classifier mode must pin license+entry"
    )
    assert "ptr @socket_entry" in adapted, (
        "socket used marker must name the socket entrypoint"
    )
    for line in CLASSIFIER_BODY.splitlines():
        assert line in adapted, (
            "adapted IR must keep body line byte-identical: %r" % line
        )


def test_tc_shape_validates_and_adapts_with_section():
    assert _validate_or_fail(TC_IR, "tc") == "classifier"
    adapted = adapter.adapt(TC_IR)
    assert 'section "classifier"' in adapted, (
        "adapted IR must carry the classifier section"
    )
    assert "[2 x ptr]" in adapted, (
        "classifier mode must pin license+entry"
    )
    assert "ptr @tc_entry" in adapted, (
        "tc used marker must name the tc entrypoint"
    )
    for line in CLASSIFIER_BODY.splitlines():
        assert line in adapted, (
            "adapted IR must keep body line byte-identical: %r" % line
        )


def test_tracepoint_shape_validates():
    assert adapter.validate(TRACEPOINT_IR) == "tracepoint"
    adapted = adapter.adapt(TRACEPOINT_IR)
    assert (
        'section "tracepoint/syscalls/sys_enter_getpid"' in adapted
    ), "adapted IR must carry the tracepoint section"
    assert "mojobpf_map0" in adapted, "adapted IR must define the map"
    assert ".BTF" in adapted, "adapted IR must carry .BTF"
    assert "[3 x ptr]" in adapted, "tracepoint mode must pin map+license+entry"
    assert "ptr @trace_entry" in adapted, (
        "tracepoint used marker must name the tracepoint entrypoint"
    )


def test_tracepoint_adapt_lowers_only_callees():
    adapted = adapter.adapt(TRACEPOINT_IR)
    lowered_lookup = LOOKUP_LINE.replace(
        "@__mojobpf_lookup_v1", "inttoptr (i64 1 to ptr)"
    )
    lowered_update = (
        "  %28 = call i64 inttoptr (i64 2 to ptr)"
        "(i64 %27, ptr %26, ptr %22, i64 0)"
    )
    lowered_pid = PID_LINE.replace(
        "@__mojobpf_get_pid_tgid_v1", "inttoptr (i64 14 to ptr)"
    )
    assert lowered_lookup in adapted, (
        "adapted IR must carry the lowered lookup callee"
    )
    assert lowered_update in adapted, (
        "adapted IR must carry the lowered update callee"
    )
    assert lowered_pid in adapted, (
        "adapted IR must carry the lowered PID/TID callee"
    )
    assert "__mojobpf_get_pid_tgid_v1" not in adapted, (
        "adapted IR must not reference the PID/TID declaration"
    )
    lowered_second_lookup = (
        "  %18 = call i64 inttoptr (i64 1 to ptr)(i64 %17, ptr %16)"
    )
    assert lowered_second_lookup in adapted, (
        "adapted IR must lower both lookup call sites"
    )
    for line in TRACEPOINT_BODY.splitlines():
        if "inttoptr" in line or "@__mojobpf_" in line:
            continue
        assert line in adapted, (
            "adapted IR must keep body line byte-identical: %r" % line
        )


def test_reject_helper_id_3():
    bad_line = (
        '  %4 = call i64 asm sideeffect "call 3", '
        '"={r0},+{r1},+{r2},~{r3},~{r4},~{r5},~{memory}"(i64 %3, ptr %2)'
    )
    assert_rejected(MAP_IR.replace(LOOKUP_LINE, bad_line), "MBPF306")
    assert_rejected(with_body_line(bad_line.strip()), "MBPF306")


def test_reject_legacy_lookup_shape():
    assert_rejected(MAP_IR.replace(LOOKUP_LINE, LEGACY_LOOKUP_LINE), "MBPF306")
    assert_rejected(with_body_line(LEGACY_LOOKUP_LINE.strip()), "MBPF306")


def test_reject_legacy_update_shape():
    assert_rejected(MAP_IR.replace(UPDATE_LINE, LEGACY_UPDATE_LINE), "MBPF306")
    assert_rejected(with_body_line(LEGACY_UPDATE_LINE.strip()), "MBPF306")


def test_reject_legacy_missing_clobber():
    bad_line = LEGACY_LOOKUP_LINE.replace(",~{r5},~{memory}", ",~{memory}")
    assert_rejected(MAP_IR.replace(LOOKUP_LINE, bad_line), "MBPF306")
    assert_rejected(with_body_line(bad_line.strip()), "MBPF306")


def test_reject_map_wrong_symbol():
    bad_line = MAPADDR_LINE.replace("mojobpf_map0", "mojobpf_map9")
    assert_rejected(MAP_IR.replace("mojobpf_map0", "mojobpf_map9"), "MBPF303")
    assert_rejected(with_body_line(bad_line.strip()), "MBPF303")


def test_reject_lookup_constant_map():
    bad_line = LOOKUP_LINE.replace("(i64 %3,", "(i64 0,")
    assert_rejected(MAP_IR.replace(LOOKUP_LINE, bad_line), "MBPF307")
    assert_rejected(with_body_line(bad_line.strip()), "MBPF307")


def test_reject_lookup_without_map():
    no_mapaddr = MAP_IR.replace(MAPADDR_LINE + "\n", "").replace(
        MAPADDR_LINE.replace("%3 =", "%13 =", 1) + "\n", ""
    )
    assert no_mapaddr != MAP_IR
    assert_rejected(with_body_line(LOOKUP_LINE.strip()), "MBPF313")
    assert_rejected(no_mapaddr, "MBPF307")


def test_reject_mapaddr_without_lookup():
    no_lookup = MAP_IR.replace(LOOKUP_LINE + "\n", "")
    assert no_lookup != MAP_IR
    assert_rejected(with_body_line(MAPADDR_LINE.strip()), "MBPF307")
    assert_rejected(no_lookup, "MBPF313")


def test_reject_keyslot_drift():
    bad_line = KEYSLOT_LINE.replace("r0 += -4", "r0 += -8")
    assert_rejected(MAP_IR.replace("r0 += -4", "r0 += -8"), "MBPF303")
    assert_rejected(with_body_line(bad_line.strip()), "MBPF303")


def test_reject_update_wrong_shape():
    bad_line = UPDATE_LINE.replace(", i64 0)", ")")
    assert_rejected(MAP_IR.replace(UPDATE_LINE, bad_line), "MBPF314")
    assert_rejected(with_body_line(bad_line.strip()), "MBPF314")


def test_reject_update_nonzero_flags():
    bad_line = UPDATE_LINE.replace(", i64 0)", ", i64 1)")
    assert_rejected(MAP_IR.replace(UPDATE_LINE, bad_line), "MBPF314")
    assert_rejected(with_body_line(bad_line.strip()), "MBPF314")


def test_reject_double_lookup():
    assert_rejected(with_map_body_line(LOOKUP_LINE.strip()), "MBPF303")
    assert_rejected(with_body_line(LOOKUP_LINE.strip()), "MBPF313")
    assert_rejected(
        with_body_line(LOOKUP_LINE.strip()).replace(
            RET_ANCHOR,
            "  " + LOOKUP_LINE.strip() + "\n" + RET_ANCHOR,
        )
    , "MBPF303")


def test_reject_pid_with_operand():
    bad_line = (
        "  %10 = call i64 @__mojobpf_get_pid_tgid_v1(i64 %9)"
    )
    assert_rejected(TRACEPOINT_IR.replace(PID_LINE, bad_line), "MBPF314")
    assert_rejected_all(body_variants(bad_line.strip()), "MBPF314")


def test_reject_pid_tail_call():
    bad_line = (
        "  %10 = tail call i64 @__mojobpf_get_pid_tgid_v1()"
    )
    assert_rejected(TRACEPOINT_IR.replace(PID_LINE, bad_line), "MBPF313")
    assert_rejected_all(body_variants(bad_line.strip()), "MBPF313")


def test_reject_pid_decl_drift():
    bad_decl = "declare i64 @__mojobpf_get_pid_tgid_v1(i64) #0"
    assert_rejected(TRACEPOINT_IR.replace(PID_DECL, bad_decl), "MBPF313")
    assert_rejected_all(module_variants(suffix=bad_decl + "\n"), "MBPF313")


def test_reject_pid_legacy_asm():
    bad_line = (
        '  %10 = call i64 asm sideeffect "call 14", '
        '"={r0},~{memory}"()'
    )
    assert_rejected(TRACEPOINT_IR.replace(PID_LINE, bad_line), "MBPF306")
    assert_rejected_all(body_variants(bad_line.strip()), "MBPF306")


def test_reject_pid_in_map_shape():
    fresh_pid = PID_LINE.replace("%10 =", "%50 =", 1).strip()
    assert_rejected(with_map_body_line(fresh_pid), "MBPF313")
    assert_rejected(with_body_line(fresh_pid), "MBPF313")


LOADMAP_BODY = (
    "entry:\n"
    '  %2 = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)\n'
    "  %3 = call i64 @__mojobpf_skb_load_bytes_v1"
    "(ptr %0, i32 14, ptr %2, i32 1)\n"
    '  %4 = call ptr asm sideeffect "r0 = r10\\0Ar0 += -16", '
    '"={r0}"()\n'
    '  %5 = call ptr asm sideeffect "r0 = r10\\0Ar0 += -4\\0A'
    '*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)\n'
    '  %6 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", '
    '"={r0}"()\n'
    "  %7 = call i64 @__mojobpf_update_v1"
    "(i64 %6, ptr %5, ptr %4, i64 0)\n"
    "  ret i32 0\n"
)


def _loadmap_module(entry):
    import audit

    define = (
        TC_DEFINE if entry == "tc_entry" else SOCKET_DEFINE
    )
    return "\n".join(
        [
            adapter.HOST_DATALAYOUT,
            adapter.HOST_TRIPLE,
            define,
            LOADMAP_BODY,
            "}",
            audit.SKBLOAD_DECL_LINE,
            audit.UPDATE_DECL_LINE,
            adapter.HOST_ATTRS,
            "",
        ]
    )


def test_loadmap_tc_adapts_with_map():
    adapted = adapter.adapt(_loadmap_module("tc_entry"))
    assert "inttoptr (i64 26 to ptr)" in adapted
    assert "inttoptr (i64 2 to ptr)" in adapted
    assert "@mojobpf_map0" in adapted
    assert "ptr @tc_entry" in adapted
    assert ".maps" in adapted


def test_loadmap_socket_has_no_license_block():
    try:
        adapter.adapt(_loadmap_module("socket_entry"))
    except adapter.AdapterError as exc:
        assert "has no license block" in str(exc), exc
    else:
        raise AssertionError(
            "adapter built a socket/map object with no reviewed route"
        )

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
    negatives = sum(1 for name in names if "_reject" in name)
    print(
        "adapter validation: allowed shapes plus %d negative controls passed"
        % negatives
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
