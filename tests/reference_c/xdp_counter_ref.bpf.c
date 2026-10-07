/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: XDP classifier with invocation accounting.
 *
 * This file is a loader/verifier/runner control only. It is never a
 * product implementation: kernel-side algorithms ship in Mojo. It
 * mirrors the specified packet workload so the suites can compare
 * the Mojo demos against an independently written program: return
 * XDP_DROP (1) when the frame holds at least 15 bytes and bit 0 of
 * byte 14 is set, else XDP_PASS (2); add one to entry 0 and the
 * frame length to entry 1 of a two-entry array map on every
 * invocation.
 *
 * The map is declared in BTF form without libbpf headers (the
 * struct below is written out explicitly). Build with the system
 * Clang BPF backend (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/xdp_counter_ref.bpf.c \
 *       -o out/xdp_counter_ref.bpf.o
 *
 * Load and execute only inside the approved disposable VM via the
 * kernel suites; map entries are initialized from userspace and
 * read back independently after each run.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))

/* Kernel helper declarations without libbpf headers. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(
	void *map, const void *key, const void *value, __u64 flags) = (void *)2;

/*
 * Two-entry array: entry 0 counts invocations, entry 1 sums frame
 * lengths. Both use u32 keys and u64 values.
 */
struct counter_map_def {
	int (*type)[BPF_MAP_TYPE_ARRAY];
	int (*max_entries)[2];
	__u32 *key;
	__u64 *value;
} counter_maps SEC(".maps");

SEC("xdp")
int xdp_counter_ref(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 len = ctx->data_end - ctx->data;
	__u32 key0 = 0;
	__u32 key1 = 1;
	__u64 *slot0;
	__u64 *slot1;
	__u64 next0;
	__u64 next1;
	int action = 2;

	if (data + 15 <= data_end && ((__u8 *)data)[14] % 2 == 1)
		action = 1;
	slot0 = bpf_map_lookup_elem(&counter_maps, &key0);
	slot1 = bpf_map_lookup_elem(&counter_maps, &key1);
	if (slot0 && slot1) {
		next0 = *slot0 + 1;
		next1 = *slot1 + len;
		bpf_map_update_elem(&counter_maps, &key0, &next0, 0);
		bpf_map_update_elem(&counter_maps, &key1, &next1, 0);
	}
	return action;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
