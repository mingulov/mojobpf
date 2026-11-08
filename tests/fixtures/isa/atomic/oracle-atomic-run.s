# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/atomic/ops executed hand-asm oracle: the bare
# (no-FETCH) XADD encoding, over a stack slot (llc emits
# bare XADD only at monotonic ordering; seq_cst always
# FETCH). No branches: the program returns the loaded value
# as its action, so action 42 proves the xadd produced
# 41+1 (a skipped op would return 41).
	.section "xdp","ax"
	.globl xdp_atomic_bare
	.type xdp_atomic_bare, @function
xdp_atomic_bare:
	r1 = r10
	r1 += -8
	r2 = 41
	*(u64 *)(r1 + 0) = r2
	r2 = 1
	lock *(u64 *)(r1 + 0) += r2
	r0 = *(u64 *)(r1 + 0)
	exit
	.size xdp_atomic_bare, .-xdp_atomic_bare
	.section "license","a"
	.asciz "Apache-2.0 WITH LLVM-exception"
