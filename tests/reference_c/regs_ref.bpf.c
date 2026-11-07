/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/registers/v3: subprogram call chain.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the observable contract of
 * tests/fixtures/isa/regs/regs_minimal.mojo so the qualification
 * suite can run the same input bytes through the stock-Clang object
 * and the Mojo object: return XDP_DROP (1) when v + b + c + d + e
 * + f + g exceeds 10, where v = helper(a + 100) = (a + 100) / 42
 * + 7 over bytes 14-20, else XDP_PASS (2); short frames pass. No
 * maps, no helpers.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/regs_ref.bpf.c \
 *       -o out/regs_ref.bpf.o
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
int xdp_regs(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u64 a, b, c, d, e, f, g, v, gate;

    if (data + 24 > data_end)
        return XDP_PASS;
    a = pkt[14];
    b = pkt[15];
    c = pkt[16];
    d = pkt[17];
    e = pkt[18];
    f = pkt[19];
    g = pkt[20];
    v = helper(a + 100);
    gate = v + b + c + d + e + f + g;
    if (gate > 10)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
