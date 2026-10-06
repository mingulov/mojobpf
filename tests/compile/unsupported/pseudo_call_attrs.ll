; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: reserved call with attributes. The lookup call
; carries nounwind, so its effects are no longer
; conservative-by-construction; the audit must reject it with
; MBPF313 at stage adapter.audit.
source_filename = "pseudo_call_attrs.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
  %2 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %4 = call i64 @__mojobpf_lookup_v1(i64 %3, ptr %2) nounwind
  %5 = icmp eq i64 %4, 0
  br i1 %5, label %6, label %7
6:
  br label %15
7:
  %8 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %9 = call ptr asm "", "=r,0"(i64 %4)
  %10 = load i64, ptr %9, align 8
  %11 = add i64 %10, 1
  store i64 %11, ptr %8, align 8
  %12 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %13 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %14 = call i64 @__mojobpf_update_v1(i64 %13, ptr %12, ptr %8, i64 0)
  br label %15
15:
  ret i32 2
}
declare i64 @__mojobpf_lookup_v1(i64, ptr) #0
declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0
attributes #0 = { "target-cpu"="v3" }
