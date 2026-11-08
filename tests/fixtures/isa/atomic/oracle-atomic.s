# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/atomic/ops hand-asm corpus: llc-unproducible STX|ATOMIC
# words (bare no-FETCH XADD, LOAD_ACQ, STORE_REL). Assembled
# by stock clang; the suite pins the exact words. The bare
# XADD executes in Q (hand-asm oracle); acq/rel are rejected
# by both lanes' verifiers (pinned refusal leg in Q).
	.text
	.globl atomic_bare
atomic_bare:
	lock *(u64 *)(r1 + 0) += r2
	r0 = load_acquire((u64 *)(r1 + 0))
	store_release((u64 *)(r1 + 0), r2)
	exit
