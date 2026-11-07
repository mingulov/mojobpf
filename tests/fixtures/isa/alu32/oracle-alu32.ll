; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Fixed oracle corpus for F-ISA/alu/alu32 (hand-written, stable).
; One function per op/source-form so per-op emission reads directly.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i32 @add_k(i32 %x) {
  %s = add i32 %x, 100
  ret i32 %s
}

define i32 @add_x(i32 %x, i32 %y) {
  %s = add i32 %x, %y
  ret i32 %s
}

define i32 @sub_k(i32 %x) {
  %d = sub i32 %x, 100
  ret i32 %d
}

define i32 @sub_x(i32 %x, i32 %y) {
  %d = sub i32 %x, %y
  ret i32 %d
}

define i32 @mul_k(i32 %x) {
  %p = mul i32 %x, 100
  ret i32 %p
}

define i32 @mul_x(i32 %x, i32 %y) {
  %p = mul i32 %x, %y
  ret i32 %p
}

define i32 @div_k(i32 %x) {
  %q = udiv i32 %x, 42
  ret i32 %q
}

define i32 @mod_k(i32 %x) {
  %r = urem i32 %x, 42
  ret i32 %r
}

define i32 @div_x(i32 %x, i32 %y) {
  %q = udiv i32 %x, %y
  ret i32 %q
}

define i32 @mod_x(i32 %x, i32 %y) {
  %r = urem i32 %x, %y
  ret i32 %r
}

define i32 @udiv_k8(i32 %x) {
  %q = udiv i32 %x, 8
  ret i32 %q
}

define i32 @udiv_kmax(i32 %x) {
  %q = udiv i32 %x, 4294967295
  ret i32 %q
}

define i32 @urem_k7(i32 %x) {
  %r = urem i32 %x, 7
  ret i32 %r
}

define i32 @neg32(i32 %x) {
  %n = sub i32 0, %x
  ret i32 %n
}

define i32 @and_k(i32 %x) {
  %a = and i32 %x, 240
  ret i32 %a
}

define i32 @and_x(i32 %x, i32 %y) {
  %a = and i32 %x, %y
  ret i32 %a
}

define i32 @or_k(i32 %x) {
  %o = or i32 %x, 15
  ret i32 %o
}

define i32 @or_x(i32 %x, i32 %y) {
  %o = or i32 %x, %y
  ret i32 %o
}

define i32 @xor_k(i32 %x) {
  %o = xor i32 %x, 255
  ret i32 %o
}

define i32 @xor_x(i32 %x, i32 %y) {
  %o = xor i32 %x, %y
  ret i32 %o
}

define i32 @lsh_k(i32 %x) {
  %s = shl i32 %x, 3
  ret i32 %s
}

define i32 @rsh_k(i32 %x) {
  %s = lshr i32 %x, 5
  ret i32 %s
}

define i32 @arsh_k(i32 %x) {
  %s = ashr i32 %x, 7
  ret i32 %s
}

define i32 @lsh_x(i32 %x, i32 %y) {
  %s = shl i32 %x, %y
  ret i32 %s
}
