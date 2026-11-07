/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/jmp/uncond: two-call diamond.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * carries the leaf's executed JA cell (Amendment A2): no admitted
 * Mojo source emits JA (twelve probe shapes fold to fall-through,
 * merge, or refuse at the adapter), so the qualification suite
 * executes this stock-Clang diamond and a hand-IR oracle diamond
 * instead, and the two must agree.
 *
 * Shape: bounds check, read packet bytes 14/15, diamond with a
 * distinct noinline static call in EACH arm (arm_hi/arm_lo do not
 * merge, so llc must lay out an explicit skip: JA+1 at slot 11
 * onto the join work), join gate (w = v + GATE_ADD, DROP when
 * w > 200, else PASS). No maps, no helpers.
 *
 * Behavior on 60 zero bytes: a = b = 0 takes the else arm
 * (v = 5), w = 105, XDP_PASS (2). The suite's mutant rebuilds
 * with -DGATE_ADD=300 (w = 305, XDP_DROP (1)).
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/jmp_ref.bpf.c \
 *       -o out/jmp_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

#ifndef GATE_ADD
#define GATE_ADD 100
#endif

__attribute__((noinline)) static __u64 arm_hi(__u64 x)
{
    return x * 3 + 1;
}

__attribute__((noinline)) static __u64 arm_lo(__u64 x)
{
    return x + 5;
}

SEC("xdp")
int xdp_jmp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u64 a, b, v, w;

    if (data + 24 > data_end)
        return XDP_PASS;
    a = pkt[14];
    b = pkt[15];
    if (a > b)
        v = arm_hi(a);
    else
        v = arm_lo(b);
    w = v + GATE_ADD;
    if (w > 200)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
