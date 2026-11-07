; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Large-divisor oracle corpus for F-ISA/alu/arith64 (hand-written,
; stable). Divisors that do not fit the 32-bit immediate field are
; ADMITTED by the audit (provably nonzero) but selected to
; register-materialized X-form by the backend.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @div_k_large(i64 %x) {
  %q = udiv i64 %x, 4294967295
  ret i64 %q
}

define i64 @mod_k_large(i64 %x) {
  %r = urem i64 %x, 4294967295
  ret i64 %r
}
