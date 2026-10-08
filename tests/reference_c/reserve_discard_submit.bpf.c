/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: discard-then-submit adversarial reservation.
 *
 * Reserves one 32-byte record, checks it for null, discards it,
 * then submits the same reservation. The submit reuses a
 * reservation the discard already released, so the kernel
 * verifier must reject the load: a discarded reservation must
 * never publish, and a submit after the discard would be a
 * second publication of nothing. It exists only to prove the
 * kernel half of the exactly-once guarantee for the
 * discard-then-submit interleaving; it is never a product
 * implementation (kernel-side algorithms ship in Mojo) and it
 * is never attached.
 *
 * Build with the system Clang BPF backend (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/reserve_discard_submit.bpf.c \
 *       -o out/reserve_discard_submit.bpf.o
 *
 * Load only inside the approved disposable VM; expect rejection.
 */

#define __uint(name, val) int (*name)[val]
#define SEC(name) __attribute__((section(name), used))

typedef unsigned long long __u64;

struct {
	__uint(type, 27);
	__uint(max_entries, 131072);
} adv_ring SEC(".maps");

static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
				    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

SEC("tracepoint/syscalls/sys_enter_getpid")
int probe(void *ctx)
{
	void *slot;

	(void)ctx;
	slot = bpf_ringbuf_reserve(&adv_ring, 32, 0);
	if (!slot)
		return 0;
	bpf_ringbuf_discard(slot, 0);
	bpf_ringbuf_submit(slot, 0);
	return 0;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
