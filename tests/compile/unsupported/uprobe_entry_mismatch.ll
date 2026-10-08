; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: uprobe body under the XDP entry symbol.
; The body matches the uprobe count vector exactly, but the
; entrypoint symbol is xdp_entry. The audit must refuse the
; entry/family crossing with MBPF302 at stage adapter.audit.
source_filename = "uprobe_entry_mismatch.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
  %2 = getelementptr inbounds i64, ptr %0, i32 14
  %3 = load i64, ptr %2, align 8
  %4 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %5 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %6 = call i64 @__mojobpf_lookup_v1(i64 %5, ptr %4)
  %7 = icmp eq i64 %6, 0
  br i1 %7, label %8, label %9

8:                                                ; preds = %1
  br label %31

9:                                                ; preds = %1
  %10 = call ptr asm "", "=r,0"(i64 %6)
  %11 = load i64, ptr %10, align 8
  %12 = icmp eq i64 %11, %3
  %13 = xor i1 %12, true
  br i1 %13, label %14, label %15

14:                                               ; preds = %9
  br label %30

15:                                               ; preds = %9
  %16 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)
  %17 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %18 = call i64 @__mojobpf_lookup_v1(i64 %17, ptr %16)
  %19 = icmp eq i64 %18, 0
  br i1 %19, label %20, label %21

20:                                               ; preds = %15
  br label %29

21:                                               ; preds = %15
  %22 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %23 = call ptr asm "", "=r,0"(i64 %18)
  %24 = load i64, ptr %23, align 8
  %25 = add i64 %24, 1
  store i64 %25, ptr %22, align 8
  %26 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)
  %27 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %28 = call i64 @__mojobpf_update_v1(i64 %27, ptr %26, ptr %22, i64 0)
  br label %29

29:                                               ; preds = %20, %21
  br label %30

30:                                               ; preds = %14, %29
  br label %31

31:                                               ; preds = %8, %30
  ret i32 0
}

declare i64 @__mojobpf_lookup_v1(i64, ptr) #0

declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0

attributes #0 = { "target-cpu"="v3" }


