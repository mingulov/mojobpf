# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Negative controls for the Mojo IR adapter validator.

Feeds ``compiler/mojo_ir_adapter.validate`` a minimal IR module with the
restricted single-entrypoint shape, mutated one way per case, and asserts
each mutation is rejected. The allowed empty-template ``=r,r`` assembly
cast must keep validating. Toolchain-independent: no Mojo compiler or LLVM
tools are needed. Standard library only.

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
    print("adapter validation: allowed shape plus 10 negative controls passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
