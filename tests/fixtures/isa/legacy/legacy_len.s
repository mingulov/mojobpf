# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/legacy/refusal: BPF_LD|LEN word (0x80). Raw emission:
# no clang BPF-asm spelling exists (`r0 = len` crashes stock
# clang). The XDP verifier rejects it ("unknown opcode 80");
# pinned live by the kernel-isa-legacy Q legs.
	.section "xdp","ax"
	.globl xdp_len
	.type xdp_len,@function
xdp_len:
	.byte 0x80; .byte 0x00; .short 0; .long 0
	.byte 0x95; .byte 0; .short 0; .long 0
	.size xdp_len, .-xdp_len
	.section "license","a"
	.globl _license
_license:
	.ascii "Apache-2.0 WITH LLVM-exception\0"
