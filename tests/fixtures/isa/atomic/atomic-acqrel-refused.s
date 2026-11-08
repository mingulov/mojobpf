# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/atomic/ops refusal object: hand-assembled
# STORE_REL + LOAD_ACQ words. Both lanes' verifiers reject
# with "BPF_ATOMIC uses invalid atomic opcode 110/100"
# (-EINVAL); the Q suite pins that refusal (fails open: a
# future accepting kernel turns the leg RED).
	.section "xdp","ax"
	.globl xdp_acqrel_refused
	.type xdp_acqrel_refused, @function
xdp_acqrel_refused:
	r1 = r10
	r1 += -8
	r2 = 41
	store_release((u64 *)(r1 + 0), r2)
	r0 = load_acquire((u64 *)(r1 + 0))
	r0 = 2
	exit
	.size xdp_acqrel_refused, .-xdp_acqrel_refused
	.section "license","a"
	.asciz "Apache-2.0 WITH LLVM-exception"
