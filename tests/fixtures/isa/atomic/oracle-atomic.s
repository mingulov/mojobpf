# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/atomic/ops hand-asm corpus: STX|ATOMIC words outside
# the seq_cst selection rule (bare no-FETCH XADD, LOAD_ACQ,
# STORE_REL). Bare XADD is llc-observable only at monotonic
# ordering (seq_cst always FETCH); acq/rel have no llc path
# at all. Assembled by stock clang; the suite pins the exact
# words. The bare XADD executes in Q (hand-asm oracle);
# acq/rel are rejected by both lanes' verifiers (pinned
# refusal leg in Q).
	.text
	.globl atomic_bare
atomic_bare:
	lock *(u64 *)(r1 + 0) += r2
	r0 = load_acquire((u64 *)(r1 + 0))
	store_release((u64 *)(r1 + 0), r2)
	exit
