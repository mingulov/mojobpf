; SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
; F-ISA/mem/pseudo-imm64 oracle corpus: map-global reference
; shapes as clang emits them (the @llvm.bpf.pseudo intrinsic is
; NOT selectable by llc, so the corpus uses only global
; references). Every shape must lower to the 0x18 pair with
; src_reg 0 plus an R_BPF_64_64 relocation: the pseudo kind is
; a loader rewrite, never an llc emission on v3.
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpfel-unknown-unknown"

%struct.mapdef = type { i64, i64, i64, i64 }

@map0 = dso_local global i64 0, section ".maps", align 8
@mapstruct = dso_local global %struct.mapdef zeroinitializer, section ".maps", align 8
@gvar = dso_local global i64 42, section ".data", align 8
@ksym0 = external dso_local global i64, section ".ksyms", align 8

define i64 @pseudo_fd_callarg() {
entry:
  %slot = alloca i64, align 8
  store i64 0, ptr %slot, align 8
  %v = call i64 inttoptr (i64 1 to ptr)(ptr @map0, ptr %slot)
  ret i64 %v
}

define i64 @pseudo_fd_direct() {
entry:
  %v = load i64, ptr @map0, align 8
  ret i64 %v
}

define i64 @pseudo_field_offset() {
entry:
  %f = getelementptr %struct.mapdef, ptr @mapstruct, i32 0, i32 2
  %v = load i64, ptr %f, align 8
  ret i64 %v
}

define i64 @pseudo_data() {
entry:
  %v = load i64, ptr @gvar, align 8
  ret i64 %v
}

define i64 @pseudo_ksym() {
entry:
  %v = load i64, ptr @ksym0, align 8
  ret i64 %v
}
