; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/jmp/uncond oracle runnable (Amendment A2 agrees leg):
; an XDP-shaped hand-IR diamond with pure arms and join work.
; llc preserves the CFG (codegen runs no speculative
; middle-end passes), so the diamond emits JA where the
; admitted Mojo shapes fold to fall-through. Zero packet:
; a = b = 0 takes the no arm (v = 0), w = 100, XDP_PASS.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-unknown"

@_license = dso_local global [31 x i8] c"Apache-2.0 WITH LLVM-exception\00", section "license", align 1

define dso_local i32 @xdp_entry(ptr noundef %ctx) section "xdp" {
entry:
  %data.ptr = getelementptr i32, ptr %ctx, i32 0
  %data = load i32, ptr %data.ptr, align 4
  %end.ptr = getelementptr i32, ptr %ctx, i32 1
  %data.end = load i32, ptr %end.ptr, align 4
  %data64 = zext i32 %data to i64
  %bound = add i64 %data64, 24
  %end64 = zext i32 %data.end to i64
  %short = icmp ugt i64 %bound, %end64
  br i1 %short, label %pass, label %go
pass:
  ret i32 2
go:
  %pkt = inttoptr i64 %data64 to ptr
  %pa = getelementptr i8, ptr %pkt, i64 14
  %a8 = load i8, ptr %pa, align 1
  %pb = getelementptr i8, ptr %pkt, i64 15
  %b8 = load i8, ptr %pb, align 1
  %a = zext i8 %a8 to i64
  %b = zext i8 %b8 to i64
  %c = icmp ugt i64 %a, %b
  br i1 %c, label %yes, label %no
yes:
  %v1 = add i64 %a, 1
  br label %join
no:
  %v2 = mul i64 %b, 3
  br label %join
join:
  %v = phi i64 [ %v1, %yes ], [ %v2, %no ]
  %w = add i64 %v, 100
  %g = icmp ugt i64 %w, 200
  br i1 %g, label %drop, label %pass2
drop:
  ret i32 1
pass2:
  ret i32 2
}
