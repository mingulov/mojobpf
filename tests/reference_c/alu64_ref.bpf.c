/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/alu/arith64: 64-bit ALU chain.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the observable contract of
 * tests/fixtures/isa/alu/alu64_minimal.mojo so the qualification suite
 * can run the same input bytes through the stock-Clang object and
 * the Mojo object: return XDP_DROP (1) when the 64-bit chain over
 * byte 14 ((b + 50 - 7) * 2, q = w / 42, r = w % 5, gate =
 * (0 - q) + q + q + r + 7) exceeds 10, else XDP_PASS (2); short
 * frames pass. No maps, no helpers.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/alu64_ref.bpf.c \
 *       -o out/alu64_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

SEC("xdp")
int xdp_alu(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u64 wide, q, r, n;
    __s32 gate;

    if (data + 15 > data_end)
        return XDP_PASS;
    wide = (__u64)pkt[14] + 50;
    wide = wide - 7;
    wide = wide * 2;
    q = wide / 42;
    r = wide % 5;
    n = (__u64)0 - q;
    gate = (__s32)(n + q + q + r) + 7;
    if (gate > 10)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
