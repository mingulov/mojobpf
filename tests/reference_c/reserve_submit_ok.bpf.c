/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: well-formed reserve/submit loader.
 *
 * Reserves one 32-byte record, checks it for null, stamps a
 * fixed pattern, and submits it exactly once. The program
 * loads cleanly on any lane with ring-buffer reservation
 * support, which attributes the adversarial fixtures'
 * rejections (double submit, submit-then-discard,
 * discard-then-submit, use-after-discard) to their
 * adversarial tails rather than to the section, shape, map,
 * or declaration. It exists only as the load/unload control
 * for the reservation negatives; it is never a product
 * implementation (kernel-side algorithms ship in Mojo) and it
 * is never attached (behavior proof stays Mojo-only).
 *
 * Build with the system Clang BPF backend (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/reserve_submit_ok.bpf.c \
 *       -o out/reserve_submit_ok.bpf.o
 *
 * Load and unload only inside the approved disposable VM.
 */

#define __uint(name, val) int (*name)[val]
#define SEC(name) __attribute__((section(name), used))

typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned short __u16;

struct {
	__uint(type, 27);
	__uint(max_entries, 131072);
} ok_ring SEC(".maps");

static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size,
				    __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

struct event_record {
	__u16 version;
	__u16 record_size;
	__u32 tgid;
	__u32 tid;
	__u32 cpu;
	__u64 sequence;
	__u64 monotonic_ns;
};

SEC("tracepoint/syscalls/sys_enter_getpid")
int probe(void *ctx)
{
	struct event_record *rec;

	(void)ctx;
	rec = bpf_ringbuf_reserve(&ok_ring, 32, 0);
	if (!rec)
		return 0;
	rec->version = 1;
	rec->record_size = 32;
	rec->tgid = 0x11111111;
	rec->tid = 0x22222222;
	rec->cpu = 0x33333333;
	rec->sequence = 0x4444444444444444ULL;
	rec->monotonic_ns = 0x5555555555555555ULL;
	bpf_ringbuf_submit(rec, 0);
	return 0;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
