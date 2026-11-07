/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/mem/load-store: memory-word chain.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the observable contract of
 * tests/fixtures/isa/mem/mem_minimal.mojo so the qualification
 * suite can run the same input bytes through the stock-Clang object
 * and the Mojo object: read ten packet bytes (14..23), two u16
 * legs, a sign-extension leg, combine under a wide ld_imm64 mask,
 * call a helper (v = (a + 100) / 42 + 7), and return XDP_DROP (1)
 * when the gate exceeds 10, else XDP_PASS (2); short frames pass.
 * No maps, no helpers.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/mem_ref.bpf.c \
 *       -o out/mem_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

static __u64 helper(__u64 n)
{
    return n / 42 + 7;
}

SEC("xdp")
int xdp_mem(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u64 a, b, c, d, e, t, v, gate;
    __u16 h, h2, h3;
    __s64 s;

    if (data + 24 > data_end)
        return XDP_PASS;
    a = pkt[14];
    b = pkt[15];
    c = pkt[16];
    d = pkt[17];
    e = pkt[18];
    h = (pkt[19] + pkt[20]) / 42;
    s = (__s8)pkt[21];
    h2 = (pkt[22] + pkt[23]) / 7;
    h3 = h + h2;
    t = ((a << 32) | b) & 0x123456789ABCDEFULL;
    v = helper(a + 100);
    gate = v + b + c + d + e + h + h2 + h3 + (__u64)s + t;
    if (gate > 10)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
