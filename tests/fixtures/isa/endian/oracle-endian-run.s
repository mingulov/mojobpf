# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/misc/endian executed hand-asm oracle: the BPF_END|TO_LE
# word (llc never selects TO_LE on bpfel: every bswap cell
# selects TO_BE). Bounds-checked u16 load at packet offset 14,
# le16 (identity on LE), returned as the action: zeros -> 0,
# mixed (bytes 14,15 = 1,2) -> 513. The direction-bit mutant
# (0xD4 -> 0xDC) swaps instead: mixed -> 258.
	.section "xdp","ax"
	.globl xdp_endian_tole
	.type xdp_endian_tole,@function
xdp_endian_tole:
	r6 = *(u32 *)(r1 + 0)
	r2 = *(u32 *)(r1 + 4)
	r3 = r6
	r3 += 16
	if r3 > r2 goto +3
	r0 = *(u16 *)(r6 + 14)
	r0 = le16 r0
	exit
	r0 = 0
	exit
	.size xdp_endian_tole, .-xdp_endian_tole
	.section "license","a"
	.globl _license
_license:
	.ascii "Apache-2.0 WITH LLVM-exception\0"
