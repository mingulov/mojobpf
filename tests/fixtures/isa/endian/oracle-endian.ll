; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/misc/endian oracle corpus: bswap emission cells
; (one BPF_END|TO_BE word + trailing exit each, or
; eliminated for unused results).
; bswap x 16/32/64 used, unused x 16/32/64 (eliminated:
; pure-and-unused folds to mov + exit, zero END words).
; Excluded: bswap-i8 (folds to nothing), shift/or idioms
; (do not fuse to BPF_END: 13 ALU slots observed), TO_LE
; (no bpfel selection path; rides the hand-asm oracle).
; Per-function comments name the sourced op; the suite pins
; the observed words.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-unknown"

declare i16 @llvm.bswap.i16(i16)
declare i32 @llvm.bswap.i32(i32)
declare i64 @llvm.bswap.i64(i64)

; bswap_16_used: bswap i16, result used
define i32 @bswap_16_used(i16 %v) {
entry:
  %s = call i16 @llvm.bswap.i16(i16 %v)
  %t = zext i16 %s to i32
  ret i32 %t
}

; bswap_32_used: bswap i32, result used
define i32 @bswap_32_used(i32 %v) {
entry:
  %s = call i32 @llvm.bswap.i32(i32 %v)
  ret i32 %s
}

; bswap_64_used: bswap i64, result used
define i64 @bswap_64_used(i64 %v) {
entry:
  %s = call i64 @llvm.bswap.i64(i64 %v)
  ret i64 %s
}

; bswap_16_unused: bswap i16, result unused (eliminated)
define i32 @bswap_16_unused(i16 %v) {
entry:
  %s = call i16 @llvm.bswap.i16(i16 %v)
  ret i32 7
}

; bswap_32_unused: bswap i32, result unused (eliminated)
define i32 @bswap_32_unused(i32 %v) {
entry:
  %s = call i32 @llvm.bswap.i32(i32 %v)
  ret i32 7
}

; bswap_64_unused: bswap i64, result unused (eliminated)
define i32 @bswap_64_unused(i64 %v) {
entry:
  %s = call i64 @llvm.bswap.i64(i64 %v)
  ret i32 7
}
