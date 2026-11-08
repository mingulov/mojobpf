# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/atomic/ops load-acquire refusal object: a plain store
# initializes the stack slot, then LOAD_ACQ reads it. Both
# lanes' verifiers reject with "BPF_ATOMIC uses invalid atomic
# opcode 100" (-EINVAL); the Q suite pins that refusal
# alongside the STORE_REL (110) leg.
	.section "xdp","ax"
	.globl xdp_acqonly_refused
	.type xdp_acqonly_refused, @function
xdp_acqonly_refused:
	r1 = r10
	r1 += -8
	r2 = 41
	*(u64 *)(r1 + 0) = r2
	r0 = load_acquire((u64 *)(r1 + 0))
	r0 = 2
	exit
	.size xdp_acqonly_refused, .-xdp_acqonly_refused
	.section "license","a"
	.asciz "Apache-2.0 WITH LLVM-exception"
