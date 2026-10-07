/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: GPL-witness positive control.
 *
 * The same tracepoint shape as gpl_witness.bpf.c with the helper
 * call removed: it returns 0 without calling anything. It loads
 * cleanly under the same non-GPL declaration, which attributes the
 * witness rejection to the helper call rather than to the section,
 * shape, or declaration. Load only inside the approved disposable
 * VM; expect success, then unload.
 */

#define SEC(name) __attribute__((section(name), used))

SEC("tracepoint/syscalls/sys_enter_getpid")
int probe(void *ctx)
{
	(void)ctx;
	return 0;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
