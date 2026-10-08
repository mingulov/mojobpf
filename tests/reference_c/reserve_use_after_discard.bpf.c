/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: use-after-discard adversarial reservation.
 *
 * Reserves one 32-byte record, checks it for null, discards it,
 * then stores through the released reservation pointer. The
 * store touches memory the discard already returned to the
 * ring, so the kernel verifier must reject the load: a
 * released reservation is unusable, and no store may follow
 * the terminus. It exists only to prove the kernel half of
 * the no-use-after-discard guarantee; it is never a product
 * implementation (kernel-side algorithms ship in Mojo) and it
 * is never attached.
 *
 * Build with the system Clang BPF backend (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/reserve_use_after_discard.bpf.c \
 *       -o out/reserve_use_after_discard.bpf.o
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
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

SEC("tracepoint/syscalls/sys_enter_getpid")
int probe(void *ctx)
{
	volatile __u64 *slot;

	(void)ctx;
	slot = bpf_ringbuf_reserve(&adv_ring, 32, 0);
	if (!slot)
		return 0;
	bpf_ringbuf_discard((void *)slot, 0);
	*slot = 0xDEADBEEF;
	return 0;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
