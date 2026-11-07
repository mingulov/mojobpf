; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Fixed oracle corpus for F-ISA/mem/load-store (hand-written, stable).
; One function per width/mode so per-form emission reads directly.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @ld_b_off(ptr %p) {
entry:
  %q = getelementptr i8, ptr %p, i64 14
  %v = load i8, ptr %q, align 1
  %z = zext i8 %v to i64
  ret i64 %z
}

define i64 @ld_h(ptr %p) {
entry:
  %q = getelementptr i8, ptr %p, i64 14
  %v = load i16, ptr %q, align 2
  %z = zext i16 %v to i64
  ret i64 %z
}

define i64 @ld_w(ptr %p) {
entry:
  %q = getelementptr i8, ptr %p, i64 4
  %v = load i32, ptr %q, align 4
  %z = zext i32 %v to i64
  ret i64 %z
}

define i64 @ld_dw(ptr %p) {
entry:
  %v = load i64, ptr %p, align 8
  ret i64 %v
}

define i64 @ld_sx_b(ptr %p) {
entry:
  %q = getelementptr i8, ptr %p, i64 14
  %v = load i8, ptr %q, align 1
  %s = sext i8 %v to i64
  ret i64 %s
}

define i64 @ld_sx_h(ptr %p) {
entry:
  %q = getelementptr i8, ptr %p, i64 14
  %v = load i16, ptr %q, align 2
  %s = sext i16 %v to i64
  ret i64 %s
}

define i64 @ld_sx_w(ptr %p) {
entry:
  %q = getelementptr i8, ptr %p, i64 4
  %v = load i32, ptr %q, align 4
  %s = sext i32 %v to i64
  ret i64 %s
}

define void @st_b(ptr %p, i8 %v) {
entry:
  store i8 %v, ptr %p, align 1
  ret void
}

define void @st_h(ptr %p, i16 %v) {
entry:
  %q = getelementptr i8, ptr %p, i64 4
  store i16 %v, ptr %q, align 2
  ret void
}

define void @st_w(ptr %p, i32 %v) {
entry:
  %q = getelementptr i8, ptr %p, i64 4
  store i32 %v, ptr %q, align 4
  ret void
}

define void @st_dw(ptr %p, i64 %v) {
entry:
  store i64 %v, ptr %p, align 8
  ret void
}

define void @st_imm_w(ptr %p) {
entry:
  %q = getelementptr i8, ptr %p, i64 4
  store i32 42, ptr %q, align 4
  ret void
}

define void @st_imm_dw(ptr %p) {
entry:
  store i64 7, ptr %p, align 8
  ret void
}

define i64 @ld_imm64() {
entry:
  ret i64 81985529216486895
}

define i64 @alloca_use(i64 %x) {
entry:
  %slot = alloca i64, align 8
  store i64 %x, ptr %slot, align 8
  %v = load i64, ptr %slot, align 8
  %s = add i64 %v, 1
  ret i64 %s
}
