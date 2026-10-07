/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: GPL-only helper witness.
 *
 * Calls bpf_get_current_task (helper 35, GPL-only) once and returns
 * whether it observed a task. The program declares the project's
 * non-GPL kernel license string, so a kernel that enforces helper
 * licensing rejects the load with its GPL-restriction message
 * ("cannot call GPL-restricted function from non-GPL compatible
 * program", observed); the same shape without the call loads
 * cleanly, which attributes the rejection to the helper call
 * rather than to the section, shape, or declaration. It exists
 * only to prove that the helper-license preflight agrees with the
 * kernel: the preflight names helper 35 before submission, and the
 * kernel refuses it at load. It is never a product implementation
 * (kernel-side algorithms ship in Mojo) and it is never attached.
 *
 * The fixture keeps its own declaration unchanged: no license
 * string is altered to gain helper access, and no new license
 * grant is needed (this is original code under the project
 * license that the kernel refuses to load). The GPL-declared
 * positive (the same call admitted under a GPL-compatible
 * declaration) is deliberately out of scope: ordinary event
 * support never depends on it.
 *
 * Build with the system Clang BPF backend (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/gpl_witness.bpf.c \
 *       -o out/gpl_witness.bpf.o
 *
 * Load only inside the approved disposable VM; expect rejection.
 */

#define SEC(name) __attribute__((section(name), used))

typedef unsigned long long __u64;

static __u64 (*bpf_get_current_task)(void) = (void *)35;

SEC("tracepoint/syscalls/sys_enter_getpid")
int probe(void *ctx)
{
	__u64 task;

	(void)ctx;
	task = bpf_get_current_task();
	return task ? 0 : 1;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
