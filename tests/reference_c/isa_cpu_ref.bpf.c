/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control for F-ISA/cpu/v3-target: minimal XDP gate.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the observable contract of
 * tests/fixtures/isa/cpu/v3_minimal.mojo so the qualification suite
 * can run the same input bytes through the stock-Clang object and
 * the Mojo object: return XDP_DROP (1) when the frame holds at least
 * 15 bytes and byte 14 plus 7 exceeds 10, else XDP_PASS (2); short
 * frames pass. No maps, no helpers.
 *
 * Build with the system Clang BPF backend, CPU pinned (unprivileged):
 *
 *   clang --target=bpf -mcpu=v3 -O2 -g -c tests/reference_c/isa_cpu_ref.bpf.c \
 *       -o out/isa_cpu_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

SEC("xdp")
int xdp_gate(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u8 *pkt = data;
    __u32 gate;

    if (data + 15 > data_end)
        return XDP_PASS;
    gate = pkt[14] + 7;
    if (gate > 10)
        return XDP_DROP;
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
