; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: a record store after the discard terminus.
; The body is the committed reserve discarder IR with one mutation:
; one more reservation store follows the terminus.
; The audit must reject it with MBPF314 at stage adapter.audit.
; ModuleID = 'reserve_discard.mojo'
source_filename = "reserve_discard.mojo"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define dso_local i32 @trace_entry(ptr noundef %0) #0 {
  %2 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %4 = call i64 @__mojobpf_lookup_v1(i64 %3, ptr %2)
  %5 = icmp eq i64 %4, 0
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  br label %85

7:                                                ; preds = %1
  %8 = call ptr asm "", "=r,0"(i64 %4)
  %9 = load i64, ptr %8, align 8
  %10 = call i64 @__mojobpf_get_pid_tgid_v1()
  %11 = and i64 %10, 4294967295
  %12 = icmp eq i64 %9, %11
  %13 = xor i1 %12, true
  br i1 %13, label %14, label %15

14:                                               ; preds = %7
  br label %84

15:                                               ; preds = %7
  %16 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)
  %17 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %18 = call i64 @__mojobpf_lookup_v1(i64 %17, ptr %16)
  %19 = icmp eq i64 %18, 0
  br i1 %19, label %20, label %21

20:                                               ; preds = %15
  br label %83

21:                                               ; preds = %15
  %22 = call ptr asm "", "=r,0"(i64 %18)
  %23 = load i64, ptr %22, align 8
  %24 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %25 = add i64 %23, 1
  store i64 %25, ptr %24, align 8
  %26 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)
  %27 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %28 = call i64 @__mojobpf_update_v1(i64 %27, ptr %26, ptr %24, i64 0)
  %29 = call i64 @__mojobpf_get_smp_processor_id_v1()
  %30 = and i64 %29, 4294967295
  %31 = trunc i64 %30 to i32
  %32 = call i64 @__mojobpf_ktime_get_ns_v1()
  %33 = call i64 @__mojobpf_get_pid_tgid_v1()
  %34 = ashr i64 %33, 32
  %35 = and i64 %34, 4294967295
  %36 = trunc i64 %35 to i32
  %37 = and i64 %33, 4294967295
  %38 = trunc i64 %37 to i32
  %39 = call i64 asm sideeffect "r0 = mojobpf_map1 ll", "={r0},~{memory}"()
  %40 = call i64 asm "", "=r,0,r"(i64 %39, i64 131072)
  %41 = call i64 @__mojobpf_ringbuf_reserve_v1(i64 %40, i64 32, i64 0)
  %42 = icmp eq i64 %41, 0
  %43 = xor i1 %42, true
  br i1 %43, label %44, label %67

44:                                               ; preds = %21
  %45 = call ptr asm "", "=r,0"(i64 %41)
  store i16 1, ptr %45, align 2
  %46 = getelementptr inbounds i8, ptr %45, i32 2
  store i16 32, ptr %46, align 2
  %47 = getelementptr inbounds i8, ptr %45, i32 4
  store i32 %36, ptr %47, align 4
  %48 = getelementptr inbounds i8, ptr %45, i32 8
  store i32 %38, ptr %48, align 4
  %49 = getelementptr inbounds i8, ptr %45, i32 12
  store i32 %31, ptr %49, align 4
  %50 = getelementptr inbounds i8, ptr %45, i32 16
  store i64 %23, ptr %50, align 8
  %51 = getelementptr inbounds i8, ptr %45, i32 24
  store i64 %32, ptr %51, align 8
  %52 = call i64 @__mojobpf_ringbuf_discard_v1(ptr %45, i64 0)
  store i16 1, ptr %45, align 2
  %53 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 2)
  %54 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %55 = call i64 @__mojobpf_lookup_v1(i64 %54, ptr %53)
  %56 = icmp eq i64 %55, 0
  br i1 %56, label %57, label %58

57:                                               ; preds = %44
  br label %66

58:                                               ; preds = %44
  %59 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %60 = call ptr asm "", "=r,0"(i64 %55)
  %61 = load i64, ptr %60, align 8
  %62 = add i64 %61, 1
  store i64 %62, ptr %59, align 8
  %63 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 2)
  %64 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %65 = call i64 @__mojobpf_update_v1(i64 %64, ptr %63, ptr %59, i64 0)
  br label %66

66:                                               ; preds = %57, %58
  br label %82

67:                                               ; preds = %21
  %68 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 3)
  %69 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %70 = call i64 @__mojobpf_lookup_v1(i64 %69, ptr %68)
  %71 = icmp eq i64 %70, 0
  br i1 %71, label %72, label %73

72:                                               ; preds = %67
  br label %81

73:                                               ; preds = %67
  %74 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %75 = call ptr asm "", "=r,0"(i64 %70)
  %76 = load i64, ptr %75, align 8
  %77 = add i64 %76, 1
  store i64 %77, ptr %74, align 8
  %78 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 3)
  %79 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %80 = call i64 @__mojobpf_update_v1(i64 %79, ptr %78, ptr %74, i64 0)
  br label %81

81:                                               ; preds = %72, %73
  br label %82

82:                                               ; preds = %66, %81
  br label %83

83:                                               ; preds = %20, %82
  br label %84

84:                                               ; preds = %14, %83
  br label %85

85:                                               ; preds = %6, %84
  ret i32 0
}

declare i64 @__mojobpf_lookup_v1(i64, ptr) #0

declare i64 @__mojobpf_get_pid_tgid_v1() #0

declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0

declare i64 @__mojobpf_get_smp_processor_id_v1() #0

declare i64 @__mojobpf_ktime_get_ns_v1() #0

declare i64 @__mojobpf_ringbuf_reserve_v1(i64, i64, i64) #0

declare i64 @__mojobpf_ringbuf_discard_v1(ptr, i64) #0

attributes #0 = { "target-cpu"="znver4" "target-features"="+adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }

!llvm.module.flags = !{!0}

!0 = !{i32 2, !"Debug Info Version", i32 3}
