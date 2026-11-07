; Fixed oracle corpus for F-ISA/cpu/v3-target (hand-written, stable).
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel"

define i64 @alu64(i64 %a, i64 %b) {
  %s = add i64 %a, %b
  %m = mul i64 %s, 3
  %d = udiv i64 %m, %b
  ret i64 %d
}

define i32 @cond32(i32 %x) {
entry:
  %c = icmp sgt i32 %x, 10
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 0
}

define i64 @shift64(i64 %v, i64 %n) {
  %s = ashr i64 %v, %n
  ret i64 %s
}

