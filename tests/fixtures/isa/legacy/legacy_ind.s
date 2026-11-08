# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/legacy/refusal: BPF_LD|IND|W word (0x800006040:
# opcode 0x40, src r6, imm 8). Raw emission: clang BPF asm
# rejects every skb[rN + k] spelling. The XDP verifier
# rejects it ("BPF_LD_[ABS|IND] instructions not allowed
# for this program type"); pinned live by the
# kernel-isa-legacy Q legs.
	.section "xdp","ax"
	.globl xdp_ind
	.type xdp_ind,@function
xdp_ind:
	.byte 0x40; .byte 0x60; .short 0; .long 8
	.byte 0x95; .byte 0; .short 0; .long 0
	.size xdp_ind, .-xdp_ind
	.section "license","a"
	.globl _license
_license:
	.ascii "Apache-2.0 WITH LLVM-exception\0"
