; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/atomic/ops runnable oracle: an XDP-shaped hand-IR
; program with stack-slot u64 xadd + u64 cmpxchg over packet
; bytes 14..15 and an exact-equality gate. llc emits the
; STX|ATOMIC words directly (no audit: hand IR feeds the
; backend). Zero packet: a = 10, b = 0 -> XDP_PASS. Mixed
; packet (bytes 14..15 = 1,2): a = 11, b = 2 -> XDP_DROP.
; Anything else -> XDP_ABORTED.
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
  %bound = add i64 %data64, 52
  %end64 = zext i32 %data.end to i64
  %short = icmp ugt i64 %bound, %end64
  %slot.a = alloca i64, align 8
  %slot.b = alloca i64, align 8
  br i1 %short, label %pass, label %go
pass:
  ret i32 2
go:
  %pkt = inttoptr i64 %data64 to ptr
  %pa = getelementptr i8, ptr %pkt, i64 14
  %a8 = load i8, ptr %pa, align 1
  %pb = getelementptr i8, ptr %pkt, i64 15
  %b8 = load i8, ptr %pb, align 1
  %op.a = zext i8 %a8 to i64
  %op.b = zext i8 %b8 to i64
  store i64 10, ptr %slot.a, align 8
  store i64 20, ptr %slot.b, align 8
  %old.a = atomicrmw add ptr %slot.a, i64 %op.a seq_cst
  %pair = cmpxchg ptr %slot.b, i64 20, i64 %op.b seq_cst seq_cst
  %old.b = extractvalue { i64, i1 } %pair, 0
  %a = load i64, ptr %slot.a, align 8
  %b = load i64, ptr %slot.b, align 8
  %want.a = add i64 10, %op.a
  %ok.a = icmp eq i64 %a, %want.a
  %ok.b = icmp eq i64 %b, %op.b
  %ok.oa = icmp eq i64 %old.a, 10
  %ok.ob = icmp eq i64 %old.b, 20
  %ok1 = and i1 %ok.a, %ok.b
  %ok2 = and i1 %ok.oa, %ok.ob
  %ok = and i1 %ok1, %ok2
  br i1 %ok, label %verdict, label %abort
verdict:
  %sum = add i8 %a8, %b8
  %zero = icmp eq i8 %sum, 0
  br i1 %zero, label %pass2, label %drop
drop:
  ret i32 1
pass2:
  ret i32 2
abort:
  ret i32 0
}
