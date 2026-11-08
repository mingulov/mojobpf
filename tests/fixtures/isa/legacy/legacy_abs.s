# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/legacy/refusal: BPF_LD|ABS|W word (0x20). The XDP
# verifier rejects it ("BPF_LD_[ABS|IND] instructions not
# allowed for this program type"); pinned live by the
# kernel-isa-legacy Q legs.
	.section "xdp","ax"
	.globl xdp_abs
	.type xdp_abs,@function
xdp_abs:
	r0 = *(u32 *)skb[0]
	exit
	.size xdp_abs, .-xdp_abs
	.section "license","a"
	.globl _license
_license:
	.ascii "Apache-2.0 WITH LLVM-exception\0"
