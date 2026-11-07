/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/alu/alu32: 32-bit ALU chain.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the observable contract of
 * tests/fixtures/isa/alu32/alu32_minimal.mojo so the qualification
 * suite can run the same input bytes through the stock-Clang object
 * and the Mojo object: return XDP_DROP (1) when the 32-bit chain
 * over bytes 14-20 (lanes a/c, x0 = a | 7, x = x0 ^ 247,
 * y = c ^ 15, m = x | y, n = m ^ (a + 7), k = n & 243,
 * p = a * c + 100, d = p - b16, q = d / 42, r = q % 7,
 * s = ((r ^ 15) | 16) & 255, t = (s ^ k) & m, u = t << 3,
 * v = (u >> 5) + ((u >> 1) & 7), w16 = (b17 + b18) / 42,
 * w8 = (b19 + b20) % 7, ng = 0 - (int)v, ar = (ng >> 2) + 18,
 * gate = (k >> 6) + ar + w16 + w8) exceeds 10, else XDP_PASS (2);
 * short frames pass. No maps, no helpers.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/alu32_ref.bpf.c \
 *       -o out/alu32_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

SEC("xdp")
int xdp_alu32(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u32 a, c, x0, x, y, m, n, k, p, d, q, r, s, t, u, v, gate;
    __u16 w16;
    __u8 w8;
    __s32 ng, ar;

    if (data + 24 > data_end)
        return XDP_PASS;
    a = (__u32)pkt[14] | ((__u32)pkt[15] << 16);
    c = (__u32)pkt[15] | ((__u32)pkt[14] << 16);
    x0 = a | 7;
    x = x0 ^ 247;
    y = c ^ 15;
    m = x | y;
    n = m ^ (a + 7);
    k = n & 243;
    p = a * c + 100;
    d = p - (__u32)pkt[16];
    q = d / 42;
    r = q % 7;
    s = ((r ^ 15) | 16) & 255;
    t = (s ^ k) & m;
    u = t << 3;
    v = (u >> 5) + ((u >> 1) & 7);
    w16 = (unsigned short)((unsigned short)pkt[17] + (unsigned short)pkt[18]) / 42;
    w8 = (unsigned char)((unsigned char)pkt[19] + (unsigned char)pkt[20]) % 7;
    ng = 0 - (__s32)v;
    ar = (ng >> 2) + 18;
    gate = (k >> 6) + (__u32)ar + (__u32)w16 + (__u32)w8;
    if (gate > 10)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
