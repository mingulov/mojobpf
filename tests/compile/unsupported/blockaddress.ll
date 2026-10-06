; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: block address. Taking the address of a basic
; block enables indirect control flow the audit cannot review; it
; must reject this with MBPF306 at stage adapter.audit.
source_filename = "blockaddress.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
entry:
  %1 = load i64, ptr %0, align 8
  %2 = call ptr asm "", "=r,0"(i64 %1)
  store ptr blockaddress (@xdp_entry, %entry), ptr %0, align 8
  ret i32 2
}
attributes #0 = { "target-cpu"="v3" }
