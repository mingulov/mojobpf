; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/misc/endian runnable oracle: an XDP-shaped hand-IR
; program returning bswap16(u16@[14]) ^ lo16(bswap32(u32@[16]))
; ^ lo16(bswap64(u64@[16])) as its action. The backend
; inverts direct swapped==const comparisons (eliminating the
; END words), so the swaps feed an xor-combination instead.
; Every SKIPPED swap flips the verdict (skip@8/skip@13 ->
; 0x0906, skip@10 -> 0x0201, vs 258), proving each swap
; executes. Width errors are verdict-invisible on these
; packets (the u32/u64 lanes contribute lo16-zero under any
; width) and are caught by the exact-word structural pins
; instead — no width-sensitivity is claimed here.
; Zero packet: 0. Mixed packet (bytes 14..17 = 1,2,4,8):
; 0x0102 ^ 0x0000 ^ 0x0000 = 258.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-unknown"

@_license = dso_local global [31 x i8] c"Apache-2.0 WITH LLVM-exception\00", section "license", align 1
declare i16 @llvm.bswap.i16(i16)
declare i32 @llvm.bswap.i32(i32)
declare i64 @llvm.bswap.i64(i64)

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
  br i1 %short, label %pass, label %go
pass:
  ret i32 2
go:
  %pkt = inttoptr i64 %data64 to ptr
  %p16 = getelementptr i8, ptr %pkt, i64 14
  %raw16 = load i16, ptr %p16, align 2
  %p32 = getelementptr i8, ptr %pkt, i64 16
  %raw32 = load i32, ptr %p32, align 4
  %p64 = getelementptr i8, ptr %pkt, i64 16
  %raw64 = load i64, ptr %p64, align 8
  %sw16 = call i16 @llvm.bswap.i16(i16 %raw16)
  %sw32 = call i32 @llvm.bswap.i32(i32 %raw32)
  %sw64 = call i64 @llvm.bswap.i64(i64 %raw64)
  %lo32 = trunc i32 %sw32 to i16
  %lo64 = trunc i64 %sw64 to i16
  %x1 = xor i16 %sw16, %lo32
  %x2 = xor i16 %x1, %lo64
  %act = zext i16 %x2 to i32
  ret i32 %act
}
