/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/alu/logic64: 64-bit logic chain.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the observable contract of
 * tests/fixtures/isa/logic/logic64_minimal.mojo so the qualification
 * suite can run the same input bytes through the stock-Clang object
 * and the Mojo object: return XDP_DROP (1) when the 64-bit chain
 * over bytes 14-15 (wide lanes a/c, x0 = a | 7, x = x0 ^ 247,
 * y = c ^ 15, m = x | y, n = m ^ (a + 7), k = n & 243,
 * k2 = n & 0x1000000F3, s = k2 << 1, t = x >> 3, u = s + t,
 * sv = (long)(u - 100), ar = sv >> 2, gate = ar + k - 335)
 * exceeds 10, else XDP_PASS (2); short frames pass. No maps, no
 * helpers.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/logic64_ref.bpf.c \
 *       -o out/logic64_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

SEC("xdp")
int xdp_logic(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u64 a, c, x0, x, y, m, n, k, k2, s, t, u;
    __s64 sv, ar, gate;

    if (data + 16 > data_end)
        return XDP_PASS;
    a = (__u64)pkt[14] | ((__u64)pkt[15] << 32);
    c = (__u64)pkt[15] | ((__u64)pkt[14] << 32);
    x0 = a | 7;
    x = x0 ^ 247;
    y = c ^ 15;
    m = x | y;
    n = m ^ (a + 7);
    k = n & 243;
    k2 = n & 0x1000000F3UL;
    s = k2 << 1;
    t = x >> 3;
    u = s + t;
    sv = (__s64)(u - 100);
    ar = sv >> 2;
    gate = ar + (__s64)k - 335;
    if (gate > 10)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
