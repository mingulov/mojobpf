; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Fixed oracle corpus for F-ISA/alu/logic64 (hand-written, stable).
; One function per op/source-form so per-op emission reads directly.
; Constants avoid degenerate folds (no zero/one-mask identities,
; no shift-by-0).
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @and_k(i64 %x) {
  %z = and i64 %x, 240
  ret i64 %z
}

define i64 @and_x(i64 %x, i64 %y) {
  %z = and i64 %x, %y
  ret i64 %z
}

define i64 @or_k(i64 %x) {
  %z = or i64 %x, 15
  ret i64 %z
}

define i64 @or_x(i64 %x, i64 %y) {
  %z = or i64 %x, %y
  ret i64 %z
}

define i64 @xor_k(i64 %x) {
  %z = xor i64 %x, 255
  ret i64 %z
}

define i64 @xor_x(i64 %x, i64 %y) {
  %z = xor i64 %x, %y
  ret i64 %z
}

define i64 @shl_k(i64 %x) {
  %z = shl i64 %x, 3
  ret i64 %z
}

define i64 @lshr_k(i64 %x) {
  %z = lshr i64 %x, 5
  ret i64 %z
}

define i64 @ashr_k(i64 %x) {
  %z = ashr i64 %x, 7
  ret i64 %z
}

define i64 @shl_x(i64 %x, i64 %y) {
  %z = shl i64 %x, %y
  ret i64 %z
}

define i64 @lshr_x(i64 %x, i64 %y) {
  %z = lshr i64 %x, %y
  ret i64 %z
}

define i64 @ashr_x(i64 %x, i64 %y) {
  %z = ashr i64 %x, %y
  ret i64 %z
}
