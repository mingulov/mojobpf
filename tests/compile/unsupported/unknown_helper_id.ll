; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: unknown helper ID. Helper invocations must use
; the reserved call form for helpers 1 to 3; "call 3" assembly must
; still be rejected with MBPF306 at stage adapter.audit (helper 3 is
; qualified only through its reserved pseudo-call, never as raw
; assembly).
source_filename = "unknown_helper_id.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
entry:
  %1 = load i64, ptr %0, align 8
  %2 = call ptr asm "", "=r,0"(i64 %1)
  %3 = call i64 asm sideeffect "call 3", "={r0}"()
  ret i32 2
}
attributes #0 = { "target-cpu"="v3" }
