; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/atomic/ops oracle corpus: atomicrmw/cmpxchg emission
; cells (one STX|ATOMIC word + trailing exit each).
; add/sub/and/or/xor/xchg x 64/32, cmpxchg x 64/32/weak,
; nofetch x2 (seq_cst sets FETCH even for unused results),
; monotonic x2 (monotonic selects bare XADD, used or not).
; FETCH rule: ordering is the boundary, usedness is
; irrelevant. Other orderings and monotonic non-add ops are
; unobserved in this corpus (explicit non-claim).
; Excluded: min/max/umin/umax, fence, atomic load/store
; (llc 22.1.8 crashes on all of them; the audit refuses
; them first with MBPF304). Per-function comments name the
; sourced op; the suite pins the observed words.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-unknown"

; rmw_add_64: atomicrmw add i64
define i32 @rmw_add_64(ptr %p) {
entry:
  %v = atomicrmw add ptr %p, i64 5 seq_cst
  %t = trunc i64 %v to i32
  ret i32 %t
}

; rmw_add_32: atomicrmw add i32
define i32 @rmw_add_32(ptr %p) {
entry:
  %v = atomicrmw add ptr %p, i32 5 seq_cst
  ret i32 %v
}

; rmw_sub_64: atomicrmw sub i64 (NEG + ADD|FETCH)
define i32 @rmw_sub_64(ptr %p) {
entry:
  %v = atomicrmw sub ptr %p, i64 5 seq_cst
  %t = trunc i64 %v to i32
  ret i32 %t
}

; rmw_sub_32: atomicrmw sub i32
define i32 @rmw_sub_32(ptr %p) {
entry:
  %v = atomicrmw sub ptr %p, i32 5 seq_cst
  ret i32 %v
}

; rmw_and_64: atomicrmw and i64
define i32 @rmw_and_64(ptr %p) {
entry:
  %v = atomicrmw and ptr %p, i64 5 seq_cst
  %t = trunc i64 %v to i32
  ret i32 %t
}

; rmw_and_32: atomicrmw and i32
define i32 @rmw_and_32(ptr %p) {
entry:
  %v = atomicrmw and ptr %p, i32 5 seq_cst
  ret i32 %v
}

; rmw_or_64: atomicrmw or i64
define i32 @rmw_or_64(ptr %p) {
entry:
  %v = atomicrmw or ptr %p, i64 5 seq_cst
  %t = trunc i64 %v to i32
  ret i32 %t
}

; rmw_or_32: atomicrmw or i32
define i32 @rmw_or_32(ptr %p) {
entry:
  %v = atomicrmw or ptr %p, i32 5 seq_cst
  ret i32 %v
}

; rmw_xor_64: atomicrmw xor i64
define i32 @rmw_xor_64(ptr %p) {
entry:
  %v = atomicrmw xor ptr %p, i64 5 seq_cst
  %t = trunc i64 %v to i32
  ret i32 %t
}

; rmw_xor_32: atomicrmw xor i32
define i32 @rmw_xor_32(ptr %p) {
entry:
  %v = atomicrmw xor ptr %p, i32 5 seq_cst
  ret i32 %v
}

; rmw_xchg_64: atomicrmw xchg i64
define i32 @rmw_xchg_64(ptr %p) {
entry:
  %v = atomicrmw xchg ptr %p, i64 5 seq_cst
  %t = trunc i64 %v to i32
  ret i32 %t
}

; rmw_xchg_32: atomicrmw xchg i32
define i32 @rmw_xchg_32(ptr %p) {
entry:
  %v = atomicrmw xchg ptr %p, i32 5 seq_cst
  ret i32 %v
}

; cmpxchg_64: cmpxchg i64
define i32 @cmpxchg_64(ptr %p) {
entry:
  %r = cmpxchg ptr %p, i64 1, i64 2 seq_cst seq_cst
  %v = extractvalue { i64, i1 } %r, 0
  %t = trunc i64 %v to i32
  ret i32 %t
}

; cmpxchg_32: cmpxchg i32
define i32 @cmpxchg_32(ptr %p) {
entry:
  %r = cmpxchg ptr %p, i32 1, i32 2 seq_cst seq_cst
  %v = extractvalue { i32, i1 } %r, 0
  ret i32 %v
}

; cmpxchg_weak: weak cmpxchg i64 (same word as strong)
define i32 @cmpxchg_weak(ptr %p) {
entry:
  %r = cmpxchg weak ptr %p, i64 1, i64 2 seq_cst seq_cst
  %v = extractvalue { i64, i1 } %r, 0
  %t = trunc i64 %v to i32
  ret i32 %t
}

; nofetch_add_64: result unused, FETCH still set
define i32 @nofetch_add_64(ptr %p) {
entry:
  %v = atomicrmw add ptr %p, i64 5 seq_cst
  ret i32 7
}

; nofetch_xchg_32: result unused, FETCH still set
define i32 @nofetch_xchg_32(ptr %p) {
entry:
  %v = atomicrmw xchg ptr %p, i32 5 seq_cst
  ret i32 7
}

; monotonic_add_64_used: monotonic selects bare XADD even
; though the result is used (returns the addend: a bare XADD
; yields no old value).
define i32 @monotonic_add_64_used(ptr %p) {
entry:
  %v = atomicrmw add ptr %p, i64 5 monotonic
  %t = trunc i64 %v to i32
  ret i32 %t
}

; monotonic_add_64_unused: monotonic selects bare XADD for
; unused results too (usedness is irrelevant; ordering is
; the boundary).
define i32 @monotonic_add_64_unused(ptr %p) {
entry:
  %v = atomicrmw add ptr %p, i64 5 monotonic
  ret i32 7
}
