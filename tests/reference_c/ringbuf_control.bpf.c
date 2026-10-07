/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: fixed-pattern ring-buffer producer.
 *
 * On every syscalls:sys_enter_getpid event this program emits one
 * 32-byte record with a fixed pattern (version 1, size 32, the
 * remaining fields constant) through its ring-buffer map with
 * bpf_ringbuf_output. It filters nothing and keeps no state: every
 * record is identical, so the drain plus decoder must reproduce
 * the pattern on every record of a control run, whatever the
 * count. It exists only to validate the observer (drain tool and
 * decoder) against live kernel bytes before the Mojo emitter is
 * measured; it is never a product implementation (kernel-side
 * algorithms ship in Mojo).
 *
 * Build with the system Clang BPF backend (unprivileged):
 *
 *   clang --target=bpf -O2 -g -c tests/reference_c/ringbuf_control.bpf.c \
 *       -o out/ringbuf_control.bpf.o
 *
 * Load and attach only inside the approved disposable VM; drive
 * with raw getpid calls and drain with tests/harness/ringbuf_drain.
 */

#define __uint(name, val) int (*name)[val]
#define SEC(name) __attribute__((section(name), used))

typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef unsigned short __u16;

/* The 128 KiB ring absorbs the workload's getpid burst plus
 * background calls without loss, so the control proves lossless
 * pattern reproduction rather than producer/consumer racing. */
struct {
	__uint(type, 27);
	__uint(max_entries, 131072);
} control_ring SEC(".maps");

static __u64 (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size,
				   __u64 flags) = (void *)130;

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
int trace_entry(void *ctx)
{
	struct event_record rec;

	(void)ctx;
	rec.version = 1;
	rec.record_size = 32;
	rec.tgid = 0x11111111u;
	rec.tid = 0x22222222u;
	rec.cpu = 0x33333333u;
	rec.sequence = 0x4444444444444444ull;
	rec.monotonic_ns = 0x5555555555555555ull;
	bpf_ringbuf_output(&control_ring, &rec, sizeof(rec), 0);
	return 0;
}

char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
