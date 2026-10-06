/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: minimal XDP program returning XDP_PASS.
 *
 * This file is a loader/verifier/runner control only. It is never a product
 * implementation: kernel-side algorithms ship in Mojo. Build with the system
 * Clang BPF backend (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/xdp_pass.bpf.c \
 *       -o out/xdp_pass.bpf.o
 *
 * Load and execute only inside the approved disposable VM via
 * tests/harness/bpf_test_run.py; expect return value 2.
 */

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

/* XDP_PASS; the program ignores its context and always passes the packet. */
SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	(void)ctx;
	return 2;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
