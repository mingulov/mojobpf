; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/jmp/cond oracle corpus: conditional-jump emission
; cells (one Jcc + two exits each; llc negates the sourced
; predicate over the taken arm) plus boundary, dodge-demo,
; and JSET-absence shapes. Per-function comments name the
; sourced predicate; the suite pins the observed words.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-unknown"

; jcc_jeqk_64: wants JEQ-K via ne-K(7)
define i64 @jcc_jeqk_64(i64 %a) {
  %c = icmp ne i64 %a, 7
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jeqk_32: wants JEQ-K via ne-K(7)
define i32 @jcc_jeqk_32(i32 %a) {
  %c = icmp ne i32 %a, 7
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jeqx_64: wants JEQ-X via ne-X
define i64 @jcc_jeqx_64(i64 %a, i64 %b) {
  %c = icmp ne i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jeqx_32: wants JEQ-X via ne-X
define i32 @jcc_jeqx_32(i32 %a, i32 %b) {
  %c = icmp ne i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jnek_64: wants JNE-K via eq-K(7)
define i64 @jcc_jnek_64(i64 %a) {
  %c = icmp eq i64 %a, 7
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jnek_32: wants JNE-K via eq-K(7)
define i32 @jcc_jnek_32(i32 %a) {
  %c = icmp eq i32 %a, 7
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jnex_64: wants JNE-X via eq-X
define i64 @jcc_jnex_64(i64 %a, i64 %b) {
  %c = icmp eq i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jnex_32: wants JNE-X via eq-X
define i32 @jcc_jnex_32(i32 %a, i32 %b) {
  %c = icmp eq i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jgtk_64: wants JGT-K via ule-K(100)
define i64 @jcc_jgtk_64(i64 %a) {
  %c = icmp ule i64 %a, 100
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jgtk_32: wants JGT-K via ule-K(100)
define i32 @jcc_jgtk_32(i32 %a) {
  %c = icmp ule i32 %a, 100
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jgtx_64: wants JGT-X via ule-X
define i64 @jcc_jgtx_64(i64 %a, i64 %b) {
  %c = icmp ule i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jgtx_32: wants JGT-X via ule-X
define i32 @jcc_jgtx_32(i32 %a, i32 %b) {
  %c = icmp ule i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jgek_64: wants JGE-K via ult-K(100)
define i64 @jcc_jgek_64(i64 %a) {
  %c = icmp ult i64 %a, 100
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jgek_32: wants JGE-K via ult-K(100)
define i32 @jcc_jgek_32(i32 %a) {
  %c = icmp ult i32 %a, 100
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jgex_64: wants JGE-X via ult-X
define i64 @jcc_jgex_64(i64 %a, i64 %b) {
  %c = icmp ult i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jgex_32: wants JGE-X via ult-X
define i32 @jcc_jgex_32(i32 %a, i32 %b) {
  %c = icmp ult i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jltk_64: wants JLT-K via uge-K(200)
define i64 @jcc_jltk_64(i64 %a) {
  %c = icmp uge i64 %a, 200
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jltk_32: wants JLT-K via uge-K(200)
define i32 @jcc_jltk_32(i32 %a) {
  %c = icmp uge i32 %a, 200
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jltx_64: wants JLT-X via uge-X
define i64 @jcc_jltx_64(i64 %a, i64 %b) {
  %c = icmp uge i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jltx_32: wants JLT-X via uge-X
define i32 @jcc_jltx_32(i32 %a, i32 %b) {
  %c = icmp uge i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jlek_64: wants JLE-K via ugt-K(200)
define i64 @jcc_jlek_64(i64 %a) {
  %c = icmp ugt i64 %a, 200
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jlek_32: wants JLE-K via ugt-K(200)
define i32 @jcc_jlek_32(i32 %a) {
  %c = icmp ugt i32 %a, 200
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jlex_64: wants JLE-X via ugt-X
define i64 @jcc_jlex_64(i64 %a, i64 %b) {
  %c = icmp ugt i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jlex_32: wants JLE-X via ugt-X
define i32 @jcc_jlex_32(i32 %a, i32 %b) {
  %c = icmp ugt i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jsgtk_64: wants JSGT-K via sle-K(-1)
define i64 @jcc_jsgtk_64(i64 %a) {
  %c = icmp sle i64 %a, -1
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jsgtk_32: wants JSGT-K via sle-K(-1)
define i32 @jcc_jsgtk_32(i32 %a) {
  %c = icmp sle i32 %a, -1
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jsgtx_64: wants JSGT-X via sle-X
define i64 @jcc_jsgtx_64(i64 %a, i64 %b) {
  %c = icmp sle i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jsgtx_32: wants JSGT-X via sle-X
define i32 @jcc_jsgtx_32(i32 %a, i32 %b) {
  %c = icmp sle i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jsgek_64: wants JSGE-K via slt-K(0)
define i64 @jcc_jsgek_64(i64 %a) {
  %c = icmp slt i64 %a, 0
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jsgek_32: wants JSGE-K via slt-K(0)
define i32 @jcc_jsgek_32(i32 %a) {
  %c = icmp slt i32 %a, 0
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jsgex_64: wants JSGE-X via slt-X
define i64 @jcc_jsgex_64(i64 %a, i64 %b) {
  %c = icmp slt i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jsgex_32: wants JSGE-X via slt-X
define i32 @jcc_jsgex_32(i32 %a, i32 %b) {
  %c = icmp slt i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jsltk_64: wants JSLT-K via sge-K(0)
define i64 @jcc_jsltk_64(i64 %a) {
  %c = icmp sge i64 %a, 0
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jsltk_32: wants JSLT-K via sge-K(0)
define i32 @jcc_jsltk_32(i32 %a) {
  %c = icmp sge i32 %a, 0
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jsltx_64: wants JSLT-X via sge-X
define i64 @jcc_jsltx_64(i64 %a, i64 %b) {
  %c = icmp sge i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jsltx_32: wants JSLT-X via sge-X
define i32 @jcc_jsltx_32(i32 %a, i32 %b) {
  %c = icmp sge i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jslek_64: wants JSLE-K via sgt-K(-1)
define i64 @jcc_jslek_64(i64 %a) {
  %c = icmp sgt i64 %a, -1
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jslek_32: wants JSLE-K via sgt-K(-1)
define i32 @jcc_jslek_32(i32 %a) {
  %c = icmp sgt i32 %a, -1
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jcc_jslex_64: wants JSLE-X via sgt-X
define i64 @jcc_jslex_64(i64 %a, i64 %b) {
  %c = icmp sgt i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; jcc_jslex_32: wants JSLE-X via sgt-X
define i32 @jcc_jslex_32(i32 %a, i32 %b) {
  %c = icmp sgt i32 %a, %b
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jle32_k: boundary K; GE/LE32-K observable
define i32 @jle32_k(i32 %a) {
  %c = icmp ugt i32 %a, 4294967295
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jsge32_k: boundary K; GE/LE32-K observable
define i32 @jsge32_k(i32 %a) {
  %c = icmp slt i32 %a, -2147483648
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; jsle32_k: boundary K; GE/LE32-K observable
define i32 @jsle32_k(i32 %a) {
  %c = icmp sgt i32 %a, 2147483647
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; dodge_ge64: dodge demo (rewrite/materialize/flip)
define i64 @dodge_ge64(i64 %a) {
  %c = icmp ult i64 %a, -2147483648
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; dodge_le64: dodge demo (rewrite/materialize/flip)
define i64 @dodge_le64(i64 %a) {
  %c = icmp ugt i64 %a, 4294967295
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; dodge_sge64: dodge demo (rewrite/materialize/flip)
define i64 @dodge_sge64(i64 %a) {
  %c = icmp slt i64 %a, -2147483648
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; dodge_sle64: dodge demo (rewrite/materialize/flip)
define i64 @dodge_sle64(i64 %a) {
  %c = icmp sgt i64 %a, 2147483647
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

; dodge_ge32: dodge demo (rewrite/materialize/flip)
define i32 @dodge_ge32(i32 %a) {
  %c = icmp ult i32 %a, -2147483648
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}

; JSET-absence shapes (AND+compare; backend must NOT select JSET)
define i64 @jset_abs_x64(i64 %a, i64 %b) {
entry:
  %t = and i64 %a, %b
  %c = icmp ne i64 %t, 0
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

define i64 @jset_abs_k64(i64 %a) {
entry:
  %t = and i64 %a, 3
  %c = icmp eq i64 %t, 0
  br i1 %c, label %yes, label %no
yes:
  ret i64 1
no:
  ret i64 2
}

define i32 @jset_abs_x32(i32 %a, i32 %b) {
entry:
  %t = and i32 %a, %b
  %c = icmp ne i32 %t, 0
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 2
}
