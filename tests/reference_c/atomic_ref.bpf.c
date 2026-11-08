/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/atomic/ops: four stack-slot
 * atomics over packet-derived operands.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. No
 * admitted Mojo spelling emits atomics (audit-refused), so the
 * qualification suite executes this C control plus hand-built
 * oracles; the exact-equality verdicts prove every op executed
 * with the right operands.
 *
 * Shape: bounds check (52 bytes), then over packet bytes 14..17:
 * u64 xadd (A=100, add pkt[14]+1), u64 cmpxchg (B=200, 200 ->
 * pkt[15]+1), u32 or (C=0xF0, or pkt[16]|0x0F), u32 xchg (D =
 * pkt[17], xchg XCHG_VAL). Every checked value is impossible
 * without execution (nonzero offsets; D must read 0x5A).
 *
 * Behavior: zeros score A=101 B=1 C=0xFF D=0x5A (oldA=100,
 * oldB=200, oldC=0xF0, oldD=0) -> XDP_PASS (2); the mixed
 * packet (bytes 14..17 = 1,2,4,8) scores A=102 B=3 C=0xFF
 * D=0x5A (oldD=8) -> XDP_DROP (1); anything else ->
 * XDP_ABORTED (0). The suite's mutant byte-patches one word
 * of the built object: the verdict-gate JNE imm 0x5A -> 0x5B,
 * so D (still 0x5A) misses the gate -> XDP_ABORTED while the
 * atomics execute with identical operands. A -DXCHG_VAL
 * rebuild would move want and gate together and stay
 * behavior-preserving, so it cannot serve as the mutant.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/atomic_ref.bpf.c \
 *       -o out/atomic_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

#ifndef XCHG_VAL
#define XCHG_VAL 0x5A
#endif

SEC("xdp")
int xdp_atomic(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u64 a = 100;
    __u64 b = 200;
    __u32 c = 0xF0;
    __u32 d;
    __u32 want = XCHG_VAL;

    if (data + 52 > data_end)
        return XDP_PASS;
    d = pkt[17];
    __u64 old_a = __sync_fetch_and_add(&a, (__u64)pkt[14] + 1);
    __u64 old_b = __sync_val_compare_and_swap(&b, 200,
                                              (__u64)pkt[15] + 1);
    __u32 old_c = __sync_fetch_and_or(&c, (__u32)pkt[16] | 0x0F);
    __u32 old_d = __sync_lock_test_and_set(&d, want);
    if (old_a == 100 && a == 101 + (__u64)pkt[14] &&
        old_b == 200 && b == 1 + (__u64)pkt[15] &&
        old_c == 0xF0 && c == 0xFF &&
        old_d == pkt[17] && d == want) {
        if (pkt[14] + pkt[15] + pkt[16] + pkt[17] == 0)
            return XDP_PASS;
        return XDP_DROP;
    }
    return XDP_ABORTED;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
