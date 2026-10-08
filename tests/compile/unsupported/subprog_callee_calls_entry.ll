; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Negative fixture: subprogram calls back into the entrypoint.
; The call cycle must refuse with MBPF312 at stage
; adapter.audit.
; ModuleID = 'decision.mojo'
source_filename = "subprog_callee_calls_entry.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: noinline
define dso_local i64 @decide(i64 noundef %0) #0 {
  %2 = and i64 %0, 1
  %3 = icmp eq i64 %2, 1
  %4 = select i1 %3, i64 1, i64 2
  %5 = call i32 @xdp_entry(ptr %11)
  ret i64 %4
}

define dso_local i32 @xdp_entry(ptr noundef %0) #1 {
  %2 = getelementptr inbounds i32, ptr %0, i32 1
  %3 = load i32, ptr %0, align 4
  %4 = zext i32 %3 to i64
  %5 = load i32, ptr %2, align 4
  %6 = add i64 %4, 15
  %7 = zext i32 %5 to i64
  %8 = icmp ugt i64 %6, %7
  br i1 %8, label %9, label %10

9:                                                ; preds = %1
  br label %17

10:                                               ; preds = %1
  %11 = call ptr asm "", "=r,0"(i64 %4)
  %12 = getelementptr inbounds i8, ptr %11, i32 14
  %13 = load i8, ptr %12, align 1
  %14 = zext i8 %13 to i64
  %15 = tail call i64 @decide(i64 %14)
  %16 = trunc i64 %15 to i32
  br label %17

17:                                               ; preds = %9, %10
  %18 = phi i32 [ %16, %10 ], [ 2, %9 ]
  ret i32 %18
}

attributes #0 = { noinline "target-cpu"="znver4" "target-features"="+adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }
attributes #1 = { "target-cpu"="znver4" "target-features"="+adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }

!llvm.module.flags = !{!0}

!0 = !{i32 2, !"Debug Info Version", i32 3}
