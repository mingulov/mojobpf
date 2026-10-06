# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Controls for the Mojo IR adapter validator.

Feeds ``compiler/mojo_ir_adapter.validate`` minimal IR modules with one
of the two restricted single-entrypoint shapes (classifier or map
round trip), mutated one way per case, and asserts each mutation is
rejected. Both allowed shapes must keep validating, the map shape must
adapt with its appended metadata blocks, and adapted bodies must stay
byte-identical. Toolchain-independent: no Mojo compiler or LLVM tools
are needed. Standard library only.

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
  %1 = load i32, ptr %0, align 4
  %2 = call ptr asm "", "=r,r"(i64 %1)
  ret i32 2
}
attributes #0 = { "target-cpu"="v3" }
"""

RET_ANCHOR = "  ret i32 2\n"


def with_body_line(extra):
    """Insert an extra line into the entry body."""
    assert RET_ANCHOR in BASE_IR
    return BASE_IR.replace(RET_ANCHOR, "  " + extra + "\n" + RET_ANCHOR)


def assert_rejected(ir_text):
    try:
        adapter.validate(ir_text)
    except adapter.AdapterError:
        return
    raise AssertionError("validator accepted input it must reject")


def test_allowed_shape_validates():
    adapter.validate(BASE_IR)


def test_reject_extra_define():
    assert_rejected(BASE_IR + "define i32 @evil() { ret i32 0 }\n")


def test_reject_runtime_call():
    assert_rejected(with_body_line("%9 = call i32 @KGEN_runtime()"))


def test_reject_declare():
    assert_rejected(BASE_IR + "declare i32 @ext()\n")


def test_reject_float():
    assert_rejected(with_body_line("%7 = fadd double 1.0, 2.0"))


def test_reject_vector():
    assert_rejected(
        with_body_line("%8 = add <4 x i32> zeroinitializer, zeroinitializer")
    )


def test_reject_nonempty_asm():
    assert_rejected(
        with_body_line('%6 = call ptr asm "mov $0, $1", "=r,r"(i64 %1)')
    )


def test_reject_global():
    assert_rejected("@g = global i32 0\n" + BASE_IR)


def test_reject_invoke():
    assert_rejected(
        with_body_line("invoke void @f() to label %x unwind label %y")
    )


def test_reject_callbr_asm():
    assert_rejected(
        with_body_line(
            'callbr ptr asm "int $3", ""() to label %ok [label %fail]'
        )
    )


def test_reject_module_asm():
    assert_rejected(BASE_IR + 'module asm "int3"\n')


# The map round-trip shape: exact assembly lines as emitted by the Mojo
# frontend for the SDK wrappers (one line per wrapper call).
KEYSLOT_LINE = (
    "  %2 = call ptr asm sideeffect "
    '"r0 = r10\\0Ar0 += -4\\0A*(u32 *)(r0 + 0) = r1", '
    '"={r0},{r1},~{memory}"(i32 0)'
)
MAPADDR_LINE = (
    '  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()'
)
LOOKUP_LINE = (
    '  %4 = call i64 asm sideeffect "call 1", '
    '"={r0},{r1},{r2},~{r3},~{r4},~{r5}"(i64 %3, ptr %2)'
)
VALSLOT_LINE = (
    "  %8 = call ptr asm sideeffect "
    '"r0 = r10\\0Ar0 += -16", "={r0}"()'
)
EMPTY_LINE = '  %9 = call ptr asm "", "=r,r"(i64 %4)'
UPDATE_LINE = (
    '  %14 = call i64 asm sideeffect "call 2", '
    '"={r0},{r1},{r2},{r3},{r4},~{r5}"(i64 %13, ptr %12, ptr %8, i64 0)'
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
        adapter.HOST_ATTRS,
        "",
    ]
)


def test_map_shape_validates():
    adapter.validate(MAP_IR)
    adapted = adapter.adapt(MAP_IR)
    assert "mojobpf_map0" in adapted, "adapted IR must define the map"
    assert 'section ".maps"' in adapted, "adapted IR must carry .maps"
    assert ".BTF" in adapted, "adapted IR must carry .BTF"
    assert "[3 x ptr]" in adapted, "map mode must pin map+license+entry"


def test_map_adapt_preserves_body():
    adapted = adapter.adapt(MAP_IR)
    for line in MAP_BODY.splitlines():
        assert line in adapted, (
            "adapted IR must keep body line byte-identical: %r" % line
        )


def with_map_body_line(extra):
    """Insert an extra line into the map body."""
    anchor = "  ret i32 2\n"
    assert MAP_IR.count(anchor) == 1
    return MAP_IR.replace(anchor, "  " + extra + "\n" + anchor)


def test_reject_helper_id_3():
    assert_rejected(
        MAP_IR.replace(
            '%4 = call i64 asm sideeffect "call 1",',
            '%4 = call i64 asm sideeffect "call 3",',
        )
    )


def test_reject_map_wrong_symbol():
    assert_rejected(MAP_IR.replace("mojobpf_map0", "mojobpf_map9"))


def test_reject_lookup_missing_clobber():
    assert_rejected(
        MAP_IR.replace(
            '"={r0},{r1},{r2},~{r3},~{r4},~{r5}"',
            '"={r0},{r1},{r2},~{r3},~{r4}"',
        )
    )


def test_reject_lookup_without_map():
    assert_rejected(with_body_line(LOOKUP_LINE.strip()))


def test_reject_mapaddr_without_lookup():
    assert_rejected(with_body_line(MAPADDR_LINE.strip()))


def test_reject_keyslot_drift():
    assert_rejected(MAP_IR.replace("r0 += -4", "r0 += -8"))


def test_reject_update_wrong_shape():
    assert_rejected(
        MAP_IR.replace(
            "(i64 %13, ptr %12, ptr %8, i64 0)", "(i64 %13, ptr %12, ptr %8)"
        )
    )


def test_reject_double_lookup():
    assert_rejected(with_map_body_line(LOOKUP_LINE.strip()))


def main():
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("adapter validation: allowed shapes plus 18 negative controls passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
