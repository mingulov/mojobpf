/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/jmp/cond: eighteen-gate mirror.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the Mojo multi-gate fixture gate for gate (same bytes,
 * same weights, same exact-equality gate), so the qualification
 * suite executes two independent implementations and the two must
 * agree on both packets.
 *
 * Shape: bounds check (52 bytes), read packet bytes 14..51,
 * twenty compare gates accumulating a power-of-two score,
 * exact-equality gate (755497 -> XDP_PASS, 293078 -> XDP_DROP,
 * else XDP_ABORTED). No maps, no helpers, no calls.
 *
 * Behavior: 60 zero bytes score 755497 -> XDP_PASS (2); the
 * mixed packet scores 293078 -> XDP_DROP (1). The suite's mutant
 * rebuilds with -DZERO_EXPECT=755496 (zeros match neither gate
 * -> XDP_ABORTED (0)).
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/jcc_ref.bpf.c \
 *       -o out/jcc_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

#ifndef ZERO_EXPECT
#define ZERO_EXPECT 755497
#endif

SEC("xdp")
int xdp_jcc(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u64 score = 0;

    if (data + 52 > data_end)
        return XDP_PASS;
    if ((__u64)pkt[14] == (__u64)pkt[15])
        score += 1;
    if ((__u64)pkt[16] != (__u64)pkt[17])
        score += 2;
    if ((__u64)pkt[18] > (__u64)pkt[19])
        score += 4;
    if ((__u64)pkt[20] >= (__u64)pkt[21])
        score += 8;
    if ((__u64)pkt[22] < (__u64)pkt[23])
        score += 16;
    if ((__u64)pkt[24] <= (__u64)pkt[25])
        score += 32;
    if ((__s64)pkt[26] - 1 > (__s64)pkt[27] - 1)
        score += 64;
    if ((__s64)pkt[28] - 1 < (__s64)pkt[29] - 1)
        score += 128;
    if ((__s64)pkt[30] - 1 >= (__s64)pkt[31] - 1)
        score += 256;
    if ((__s64)pkt[32] - 1 <= (__s64)pkt[33] - 1)
        score += 512;
    if ((__u32)pkt[34] == (__u32)pkt[35])
        score += 1024;
    if ((__u32)pkt[36] < (__u32)pkt[37])
        score += 2048;
    if ((__u32)pkt[38] > (__u32)10)
        score += 4096;
    if ((__u64)pkt[40] == (__u64)7)
        score += 8192;
    if ((__u64)pkt[42] > (__u64)100)
        score += 16384;
    if ((__s64)pkt[44] - 1 < (__s64)0)
        score += 32768;
    if ((__u64)pkt[46] == (__u64)pkt[47])
        score += 65536;
    if ((__u64)pkt[48] != (__u64)9)
        score += 131072;
    if ((__u64)pkt[49] != (__u64)pkt[50])
        score += 262144;
    if ((__u32)pkt[51] != (__u32)5)
        score += 524288;
    if (score == (__u64)ZERO_EXPECT)
        return XDP_PASS;
    if (score == (__u64)293078)
        return XDP_DROP;
    return XDP_ABORTED;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
