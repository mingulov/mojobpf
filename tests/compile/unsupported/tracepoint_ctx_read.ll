; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: tracepoint program reading context payload.
; The body matches the tracepoint count vector exactly, but the
; entry parameter is loaded; tracepoint programs must filter on
; the current-PID/TID helper and map state instead. The audit must
; reject the context use with MBPF317 at stage adapter.audit.
source_filename = "tracepoint_ctx_read.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @trace_entry(ptr noundef %0) #0 {
  %ctx = load i64, ptr %0, align 8
  %2 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %4 = call i64 @__mojobpf_lookup_v1(i64 %3, ptr %2)
  %5 = icmp eq i64 %4, 0
  br i1 %5, label %6, label %7
6:
  br label %31
7:
  %8 = call ptr asm "", "=r,0"(i64 %4)
  %9 = load i64, ptr %8, align 8
  %10 = call i64 @__mojobpf_get_pid_tgid_v1()
  %11 = and i64 %10, 4294967295
  %12 = icmp eq i64 %9, %11
  %13 = xor i1 %12, true
  br i1 %13, label %14, label %15
14:
  br label %30
15:
  %16 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)
  %17 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %18 = call i64 @__mojobpf_lookup_v1(i64 %17, ptr %16)
  %19 = icmp eq i64 %18, 0
  br i1 %19, label %20, label %21
20:
  br label %29
21:
  %22 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %23 = call ptr asm "", "=r,0"(i64 %18)
  %24 = load i64, ptr %23, align 8
  %25 = add i64 %24, 1
  store i64 %25, ptr %22, align 8
  %26 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)
  %27 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %28 = call i64 @__mojobpf_update_v1(i64 %27, ptr %26, ptr %22, i64 0)
  br label %29
29:
  br label %30
30:
  br label %31
31:
  ret i32 0
}
declare i64 @__mojobpf_lookup_v1(i64, ptr) #0
declare i64 @__mojobpf_get_pid_tgid_v1() #0
declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0
attributes #0 = { "target-cpu"="v3" }
