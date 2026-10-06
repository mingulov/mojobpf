; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: multi-lane vector operation. One-lane integer
; vectors are allowed, but <4 x i32> must be rejected with MBPF305
; at stage adapter.audit.
source_filename = "vector_op.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
entry:
  %1 = load i64, ptr %0, align 8
  %2 = call ptr asm "", "=r,0"(i64 %1)
  %3 = add <4 x i32> zeroinitializer, zeroinitializer
  ret i32 2
}
attributes #0 = { "target-cpu"="v3" }
