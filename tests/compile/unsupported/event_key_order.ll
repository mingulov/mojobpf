; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: the filter and sequence lookups swap key slots.
; The body is the committed emitter IR with one mutation:
; the filter and sequence lookups swap key slots.
; The audit must reject it with MBPF307 at stage adapter.audit.
; ModuleID = 'emitter.mojo'
source_filename = "emitter.mojo"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define dso_local i32 @trace_entry(ptr noundef %0) #0 {
  %2 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 0)
  %3 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %4 = call i64 @__mojobpf_lookup_v1(i64 %17, ptr %16)
  %5 = icmp eq i64 %4, 0
  br i1 %5, label %6, label %7

6:                                                ; preds = %1
  br label %84

7:                                                ; preds = %1
  %8 = call ptr asm "", "=r,0"(i64 %4)
  %9 = load i64, ptr %8, align 8
  %10 = call i64 @__mojobpf_get_pid_tgid_v1()
  %11 = and i64 %10, 4294967295
  %12 = icmp eq i64 %9, %11
  %13 = xor i1 %12, true
  br i1 %13, label %14, label %15

14:                                               ; preds = %7
  br label %83

15:                                               ; preds = %7
  %16 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 1)
  %17 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %18 = call i64 @__mojobpf_lookup_v1(i64 %3, ptr %2)
  %19 = icmp eq i64 %18, 0
  br i1 %19, label %20, label %21

20:                                               ; preds = %15
  br label %82

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
  %39 = call ptr asm sideeffect "r0 = r10\0Ar0 += -64", "={r0},~{memory}"()
  store i16 1, ptr %39, align 2
  %40 = call ptr asm sideeffect "r0 = r10\0Ar0 += -62", "={r0},~{memory}"()
  store i16 32, ptr %40, align 2
  %41 = call ptr asm sideeffect "r0 = r10\0Ar0 += -60", "={r0},~{memory}"()
  store i32 %36, ptr %41, align 4
  %42 = call ptr asm sideeffect "r0 = r10\0Ar0 += -56", "={r0},~{memory}"()
  store i32 %38, ptr %42, align 4
  %43 = call ptr asm sideeffect "r0 = r10\0Ar0 += -52", "={r0},~{memory}"()
  store i32 %31, ptr %43, align 4
  %44 = call ptr asm sideeffect "r0 = r10\0Ar0 += -48", "={r0},~{memory}"()
  store i64 %23, ptr %44, align 8
  %45 = call ptr asm sideeffect "r0 = r10\0Ar0 += -40", "={r0},~{memory}"()
  store i64 %32, ptr %45, align 8
  %46 = call ptr asm sideeffect "r0 = r10\0Ar0 += -64", "={r0},~{memory}"()
  %47 = call i64 asm sideeffect "r0 = mojobpf_map1 ll", "={r0},~{memory}"()
  %48 = call i64 asm "", "=r,0,r"(i64 %47, i64 131072)
  %49 = call i64 @__mojobpf_ringbuf_output_v1(i64 %48, ptr %46, i64 32, i64 0)
  %50 = icmp eq i64 %49, 0
  br i1 %50, label %51, label %66

51:                                               ; preds = %21
  %52 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 2)
  %53 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %54 = call i64 @__mojobpf_lookup_v1(i64 %53, ptr %52)
  %55 = icmp eq i64 %54, 0
  br i1 %55, label %56, label %57

56:                                               ; preds = %51
  br label %65

57:                                               ; preds = %51
  %58 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %59 = call ptr asm "", "=r,0"(i64 %54)
  %60 = load i64, ptr %59, align 8
  %61 = add i64 %60, 1
  store i64 %61, ptr %58, align 8
  %62 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 2)
  %63 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %64 = call i64 @__mojobpf_update_v1(i64 %63, ptr %62, ptr %58, i64 0)
  br label %65

65:                                               ; preds = %56, %57
  br label %81

66:                                               ; preds = %21
  %67 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 3)
  %68 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %69 = call i64 @__mojobpf_lookup_v1(i64 %68, ptr %67)
  %70 = icmp eq i64 %69, 0
  br i1 %70, label %71, label %72

71:                                               ; preds = %66
  br label %80

72:                                               ; preds = %66
  %73 = call ptr asm sideeffect "r0 = r10\0Ar0 += -16", "={r0}"()
  %74 = call ptr asm "", "=r,0"(i64 %69)
  %75 = load i64, ptr %74, align 8
  %76 = add i64 %75, 1
  store i64 %76, ptr %73, align 8
  %77 = call ptr asm sideeffect "r0 = r10\0Ar0 += -4\0A*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}"(i32 3)
  %78 = call i64 asm sideeffect "r0 = mojobpf_map0 ll", "={r0}"()
  %79 = call i64 @__mojobpf_update_v1(i64 %78, ptr %77, ptr %73, i64 0)
  br label %80

80:                                               ; preds = %71, %72
  br label %81

81:                                               ; preds = %65, %80
  br label %82

82:                                               ; preds = %20, %81
  br label %83

83:                                               ; preds = %14, %82
  br label %84

84:                                               ; preds = %6, %83
  ret i32 0
}

declare i64 @__mojobpf_lookup_v1(i64, ptr) #0

declare i64 @__mojobpf_get_pid_tgid_v1() #0

declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0

declare i64 @__mojobpf_get_smp_processor_id_v1() #0

declare i64 @__mojobpf_ktime_get_ns_v1() #0

declare i64 @__mojobpf_ringbuf_output_v1(i64, ptr, i64, i64) #0

attributes #0 = { "target-cpu"="znver4" "target-features"="+adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }

!llvm.module.flags = !{!0}

!0 = !{i32 2, !"Debug Info Version", i32 3}
