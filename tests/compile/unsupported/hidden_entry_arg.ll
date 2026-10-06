; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: hidden entry argument. The entrypoint takes an
; extra i32 parameter the kernel never passes; the audit must reject
; the definition with MBPF302 at stage adapter.audit.
source_filename = "hidden_entry_arg.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0, i32 noundef %1) #0 {
entry:
  ret i32 2
}
attributes #0 = { "target-cpu"="v3" }
