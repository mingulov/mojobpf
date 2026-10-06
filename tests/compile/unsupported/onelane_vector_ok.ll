; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Positive fixture: one-lane integer numerics. The <1 x i64>
; insert, add, and extract below are the scalar representation
; the frontend folds; the audit must accept them, and the
; backend lowers them to plain scalar BPF arithmetic (see the
; lowering proof). The header uses the exact pinned host lines
; so this fixture also runs through the adapter and llc.
source_filename = "onelane_vector_ok.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
define dso_local i32 @xdp_entry(ptr noundef %0) #0 {
entry:
  %1 = load i64, ptr %0, align 8
  %2 = call ptr asm "", "=r,0"(i64 %1)
  %a = insertelement <1 x i64> zeroinitializer, i64 %1, i32 0
  %k = insertelement <1 x i64> zeroinitializer, i64 41, i32 0
  %b = add <1 x i64> %a, %k
  %c = extractelement <1 x i64> %b, i32 0
  %d = trunc i64 %c to i32
  ret i32 %d
}
attributes #0 = { "target-cpu"="znver4" "target-features"="+adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }
