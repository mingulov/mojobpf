; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/jmp/uncond oracle corpus: unconditional-jump emission
; shapes (JA target = pc + off + 1) plus the two audited-out
; shapes (loop back-edge, switch chain) pinned for the record.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-unknown"

define i64 @jmp_join(i64 %x) {
entry:
  %c = icmp eq i64 %x, 0
  br i1 %c, label %yes, label %no
yes:
  %a = add i64 %x, 1
  br label %join
no:
  %b = mul i64 %x, 3
  br label %join
join:
  %v = phi i64 [ %a, %yes ], [ %b, %no ]
  %s = add i64 %v, 100
  ret i64 %s
}

define i64 @jmp_nested(i64 %x, i64 %y) {
entry:
  %c1 = icmp eq i64 %x, 0
  br i1 %c1, label %a, label %b
a:
  %c2 = icmp eq i64 %y, 0
  br i1 %c2, label %c, label %d
c:
  %t1 = add i64 %x, %y
  br label %out
d:
  %t2 = sub i64 %x, %y
  br label %out
b:
  %t3 = mul i64 %x, %y
  br label %out
out:
  %v = phi i64 [ %t1, %c ], [ %t2, %d ], [ %t3, %b ]
  ret i64 %v
}

define i64 @jmp_loop_shape(i64 %n) {
entry:
  br label %head
head:
  %i = phi i64 [ 0, %entry ], [ %next, %head ]
  %next = add i64 %i, 1
  %c = icmp ult i64 %next, %n
  br i1 %c, label %head, label %done
done:
  ret i64 %next
}

define i64 @jmp_switch_shape(i64 %n) {
entry:
  switch i64 %n, label %dflt [ i64 1, label %one
                               i64 2, label %two
                               i64 3, label %three ]
one:
  ret i64 10
two:
  ret i64 20
three:
  ret i64 30
dflt:
  ret i64 40
}
