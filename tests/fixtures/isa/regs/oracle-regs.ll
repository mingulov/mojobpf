; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Fixed oracle corpus for F-ISA/registers/v3 (hand-written, stable).
; One function per register role so per-role emission reads directly.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

declare i64 @extBBB(i64 %x)

define i64 @five_args(i64 %a, i64 %b, i64 %c, i64 %d, i64 %e) {
entry:
  %s1 = add i64 %a, %b
  %s2 = add i64 %s1, %c
  %s3 = add i64 %s2, %d
  %s4 = add i64 %s3, %e
  ret i64 %s4
}

define i64 @live_across_call(i64 %a, i64 %b, i64 %c, i64 %d, i64 %e) {
entry:
  %v = call i64 @extBBB(i64 %a)
  %s1 = add i64 %v, %b
  %s2 = add i64 %s1, %c
  %s3 = add i64 %s2, %d
  %s4 = add i64 %s3, %e
  ret i64 %s4
}

define i64 @spill_slots(ptr %p, i64 %a) {
entry:
  %p0 = getelementptr i64, ptr %p, i64 0
  %p1 = getelementptr i64, ptr %p, i64 1
  %p2 = getelementptr i64, ptr %p, i64 2
  %p3 = getelementptr i64, ptr %p, i64 3
  %p4 = getelementptr i64, ptr %p, i64 4
  %p5 = getelementptr i64, ptr %p, i64 5
  %p6 = getelementptr i64, ptr %p, i64 6
  %p7 = getelementptr i64, ptr %p, i64 7
  %b0 = load i64, ptr %p0, align 8
  %b1 = load i64, ptr %p1, align 8
  %b2 = load i64, ptr %p2, align 8
  %b3 = load i64, ptr %p3, align 8
  %b4 = load i64, ptr %p4, align 8
  %b5 = load i64, ptr %p5, align 8
  %b6 = load i64, ptr %p6, align 8
  %b7 = load i64, ptr %p7, align 8
  %v = call i64 @extBBB(i64 %a)
  %s1 = add i64 %v, %b0
  %s2 = add i64 %s1, %b1
  %s3 = add i64 %s2, %b2
  %s4 = add i64 %s3, %b3
  %s5 = add i64 %s4, %b4
  %s6 = add i64 %s5, %b5
  %s7 = add i64 %s6, %b6
  %s8 = add i64 %s7, %b7
  ret i64 %s8
}

define dso_local i64 @decide(i64 %n) {
entry:
  %q = udiv i64 %n, 42
  ret i64 %q
}

define i32 @xdp_entry(ptr %ctx) {
entry:
  %v = tail call i64 @decide(i64 7)
  %t = trunc i64 %v to i32
  ret i32 %t
}
