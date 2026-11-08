# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/legacy/refusal: BPF_LDX|B|MSH word (0xB1). Raw
# emission: no clang BPF-asm spelling selects MSH. The XDP
# verifier rejects it ("BPF_LDX uses reserved fields");
# pinned live by the kernel-isa-legacy Q legs.
	.section "xdp","ax"
	.globl xdp_msh
	.type xdp_msh,@function
xdp_msh:
	.byte 0xb1; .byte 0x00; .short 0; .long 0
	.byte 0x95; .byte 0; .short 0; .long 0
	.size xdp_msh, .-xdp_msh
	.section "license","a"
	.globl _license
_license:
	.ascii "Apache-2.0 WITH LLVM-exception\0"
