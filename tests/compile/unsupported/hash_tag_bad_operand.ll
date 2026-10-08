; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: hash kind tag tied to a lookup result.
; The second tag takes the lookup call result instead of a
; map-address load, so it carries no map provenance. The audit
; must reject the program with MBPF307 at stage adapter.audit.
source_filename = "hash_tag_bad_operand.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
  %2 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %tag1 = call i64 asm sideeffect "", "=r,0"(i64 %3)
  %4 = call i64 @__mojobpf_lookup_v1(i64 %tag1, ptr %2)
  %5 = icmp eq i64 %4, 0
  br i1 %5, label %miss, label %hit
miss:
  ret i32 2
hit:
  %6 = call ptr asm "", "=r,0"(i64 %4)
  %7 = load i64, ptr %6, align 8
  %8 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %9 = add i64 %7, 1
  store i64 %9, ptr %8, align 8
  %10 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %11 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %tag2 = call i64 asm sideeffect "", "=r,0"(i64 %4)
  %12 = call i64 @__mojobpf_update_v1(i64 %tag2, ptr %10, ptr %8, i64 0)
  ret i32 2
}
declare i64 @__mojobpf_lookup_v1(i64, ptr) #0
declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0
attributes #0 = { "target-cpu"="v3" }
