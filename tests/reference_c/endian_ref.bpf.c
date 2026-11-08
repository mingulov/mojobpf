/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/misc/endian: three bswap widths
 * over packet-derived operands.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. No
 * admitted Mojo spelling emits BPF_END (the bswap intrinsic is
 * audit-refused), so the qualification suite executes this C
 * control plus hand-built oracles; the exact-equality verdicts
 * prove every op executed with the right operands.
 *
 * Shape: bounds check (52 bytes), then over packet bytes 14..23:
 * u16 bswap (half at [14]), u32 bswap (word at [16]), u64 bswap
 * (dword at [16]). Every checked value is impossible without
 * execution (byte-reversed mixed values).
 *
 * Behavior: zeros score (0, 0, 0) -> XDP_PASS (2); the mixed
 * packet (bytes 14..17 = 1,2,4,8) scores (0x0102, 0x04080000,
 * 0x0408000000000000) -> XDP_DROP (1); anything else ->
 * XDP_ABORTED (0). The suite's mutant byte-patches one word
 * of the built object: the verdict-gate u16 comparison, so the
 * mixed score misses the gate -> XDP_ABORTED while the swaps
 * execute with identical operands.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/endian_ref.bpf.c \
 *       -o out/endian_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

SEC("xdp")
int xdp_endian(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u16 half;
    __u32 word;
    __u64 dword;

    if (data + 52 > data_end)
        return XDP_PASS;
    half = __builtin_bswap16(*(__u16 *)(pkt + 14));
    word = __builtin_bswap32(*(__u32 *)(pkt + 16));
    dword = __builtin_bswap64(*(__u64 *)(pkt + 16));
    /* Optimization barrier (standard barrier_var idiom): without
     * it the backend inverts the swaps into the comparisons
     * (comparing raw values against pre-swapped constants) and
     * no BPF_END executes. The barrier forces the three swaps
     * to materialize; the gates below still check exact
     * constants. */
    __asm__ volatile ("" : "+r" (half), "+r" (word), "+r" (dword));
    if (half == 0x0102 && word == 0x04080000 &&
        dword == 0x0408000000000000ULL)
        return XDP_DROP;
    if (half == 0 && word == 0 && dword == 0)
        return XDP_PASS;
    return XDP_ABORTED;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
