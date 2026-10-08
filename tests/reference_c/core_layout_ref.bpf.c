/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: CO-RE relocated field read plus existence check.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the minimal CO-RE slice so the kernel suite can compare the
 * Mojo probe against an independently written program: one lookup
 * through key 0 into a single-entry array map with a 4096-byte
 * value, one relocated u32 read at value + CO-RE(task_struct.pid),
 * one field_exists(task_struct.scx) check, and the packed test-run
 * observation word (v & 0xffff) | (ex << 16).
 *
 * The local task_struct below is deliberately phony (pid at byte 32,
 * matching neither supported lane); only a genuine loader
 * relocation yields lane-correct values. The static assertions pin
 * that phoniness: "fixing" the local layout to match a lane would
 * weaken the proof and fails here first.
 *
 * The map and the helper calls are declared in BTF form without
 * libbpf headers. Build with the system Clang BPF backend
 * (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/core_layout_ref.bpf.c \
 *       -o out/core_layout_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suite; the map value is prefilled from userspace with
 * distinct per-offset markers and read back independently.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <stddef.h>

#define SEC(name) __attribute__((section(name), used))

/* Kernel helper declarations without libbpf headers. */
static __u64 (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

/* Single-entry array map with a 4096-byte opaque value. */
struct {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*key_size)[4];
	int (*value_size)[4096];
	int (*max_entries)[1];
} mojobpf_map0 SEC(".maps");

/* struct xdp_md comes from <linux/bpf.h>. */

/* Phony local layout: pid at byte 32 (neither lane), scx present. */
struct task_struct {
	__u64 __phony_pad[4];
	int pid;
	int tgid;
	__u64 __phony2[8];
	struct {
		__u64 __w[26];
	} scx;
};

_Static_assert(offsetof(struct task_struct, pid) == 32,
	       "local pid offset must stay phony (byte 32)");
_Static_assert(offsetof(struct task_struct, scx) == 104,
	       "local scx offset must stay phony (byte 104)");

enum {
	BPF_FIELD_BYTE_OFFSET = 0,
	BPF_FIELD_EXISTS = 2,
};

SEC("xdp")
int xdp_core_ref(struct xdp_md *ctx)
{
	__u32 key = 0;
	void *slot;
	struct task_struct *slot0;
	__u64 off;
	__u32 v;
	int ex;

	(void)ctx;
	slot = (void *)(unsigned long)bpf_map_lookup_elem(&mojobpf_map0,
							  &key);
	if (!slot)
		return 0;
	slot0 = (struct task_struct *)0;
	off = __builtin_preserve_field_info(slot0->pid,
					    BPF_FIELD_BYTE_OFFSET);
	v = *(__u32 *)((char *)slot + off);
	ex = __builtin_preserve_field_info(slot0->scx, BPF_FIELD_EXISTS);
	return (int)((v & 0xffffu) | ((__u32)ex << 16));
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
