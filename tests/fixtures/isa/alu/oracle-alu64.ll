; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Fixed oracle corpus for F-ISA/alu/arith64 (hand-written, stable).
; One function per op/source-form so per-op emission reads directly.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @add_k(i64 %x) {
  %s = add i64 %x, 100
  ret i64 %s
}

define i64 @add_x(i64 %x, i64 %y) {
  %s = add i64 %x, %y
  ret i64 %s
}

define i64 @sub_k(i64 %x) {
  %d = sub i64 %x, 100
  ret i64 %d
}

define i64 @sub_x(i64 %x, i64 %y) {
  %d = sub i64 %x, %y
  ret i64 %d
}

define i64 @mul_k(i64 %x) {
  %p = mul i64 %x, 100
  ret i64 %p
}

define i64 @mul_x(i64 %x, i64 %y) {
  %p = mul i64 %x, %y
  ret i64 %p
}

define i64 @div_k(i64 %x) {
  %q = udiv i64 %x, 42
  ret i64 %q
}

define i64 @mod_k(i64 %x) {
  %r = urem i64 %x, 42
  ret i64 %r
}

define i64 @div_x(i64 %x, i64 %y) {
  %q = udiv i64 %x, %y
  ret i64 %q
}

define i64 @mod_x(i64 %x, i64 %y) {
  %r = urem i64 %x, %y
  ret i64 %r
}

define i64 @neg64(i64 %x) {
  %n = sub i64 0, %x
  ret i64 %n
}
