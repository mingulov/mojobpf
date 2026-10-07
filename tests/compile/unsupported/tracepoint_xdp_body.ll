; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: classifier body under the tracepoint entry
; symbol. Only the tracepoint counter body may export
; trace_entry; a classifier body would misread the tracepoint
; context as packet metadata. The audit must reject the
; entry/family mismatch with MBPF302 at stage adapter.audit.
source_filename = "tracepoint_xdp_body.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @trace_entry(ptr noundef %0) #0 {
entry:
  %1 = load i64, ptr %0, align 8
  %2 = call ptr asm "", "=r,0"(i64 %1)
  ret i32 0
}
attributes #0 = { "target-cpu"="v3" }
