; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; Oracle rejection probe for F-ISA/registers/v3: six arguments exceed
; the BPF call convention and llc refuses the module. The admitted
; slice refuses multi-argument functions earlier (MBPF302 companions
; in compiler/tests/test_isa_regs.py).
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @six_args(i64 %a, i64 %b, i64 %c, i64 %d, i64 %e, i64 %f) {
entry:
  %s1 = add i64 %a, %b
  %s2 = add i64 %s1, %c
  %s3 = add i64 %s2, %d
  %s4 = add i64 %s3, %e
  %s5 = add i64 %s4, %f
  ret i64 %s5
}
