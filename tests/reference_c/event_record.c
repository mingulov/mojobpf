/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * Independent C control: the fixed 32-byte event record layout.
 *
 * This file states the record ABI as a C struct with static layout
 * assertions; it is never a product implementation (kernel-side
 * algorithms ship in Mojo). The layout suite compiles it twice:
 * once for the host (the facts below must match the ABI record and
 * the Mojo layout probe) and once for BPF with debug info (the
 * field offsets must match the encoder's IR store offsets, dumped
 * through bpftool). Any drift between the C layout, the Mojo
 * struct, the encoder stores, and the decoder fails loudly.
 *
 *   cc -O2 -o /tmp/event_record tests/reference_c/event_record.c
 *   clang --target=bpf -O2 -g -c tests/reference_c/event_record.c \
 *       -o out/event_record.bpf.o   # needs BPF_TYPE_EMIT=1 for .BTF
 */

#include <stddef.h>
#include <stdint.h>
#ifndef BPF_TYPE_EMIT
#include <stdio.h>
#endif

struct event_record {
	uint16_t version;
	uint16_t record_size;
	uint32_t tgid;
	uint32_t tid;
	uint32_t cpu;
	uint64_t sequence;
	uint64_t monotonic_ns;
};

_Static_assert(sizeof(struct event_record) == 32,
	       "event record must be exactly 32 bytes");
_Static_assert(_Alignof(struct event_record) == 8,
	       "event record must align to 8 bytes");
_Static_assert(offsetof(struct event_record, version) == 0,
	       "version must sit at byte 0");
_Static_assert(offsetof(struct event_record, record_size) == 2,
	       "record_size must sit at byte 2");
_Static_assert(offsetof(struct event_record, tgid) == 4,
	       "tgid must sit at byte 4");
_Static_assert(offsetof(struct event_record, tid) == 8,
	       "tid must sit at byte 8");
_Static_assert(offsetof(struct event_record, cpu) == 12,
	       "cpu must sit at byte 12");
_Static_assert(offsetof(struct event_record, sequence) == 16,
	       "sequence must sit at byte 16");
_Static_assert(offsetof(struct event_record, monotonic_ns) == 24,
	       "monotonic_ns must sit at byte 24");

#ifdef BPF_TYPE_EMIT
struct event_record event_record_type_emit;
#endif

#ifndef BPF_TYPE_EMIT
static void dump_known_value(void)
{
	/* A known record dumped byte by byte, so the Mojo probe's
	 * dump of the same value must agree on field order, widths,
	 * and byte order. */
	struct event_record rec = {
		.version = 1,
		.record_size = 32,
		.tgid = 0x11111111u,
		.tid = 0x22222222u,
		.cpu = 0x33333333u,
		.sequence = 0x4444444444444444ull,
		.monotonic_ns = 0x5555555555555555ull,
	};
	unsigned char *bytes = (unsigned char *)&rec;
	size_t i;

	printf("EDUMP event_record");
	for (i = 0; i < sizeof(rec); i++)
		printf(" %u", bytes[i]);
	printf("\n");
}

int main(void)
{
	printf("SIZE event_record %u\n",
	       (unsigned)sizeof(struct event_record));
	printf("ALIGN event_record %u\n",
	       (unsigned)_Alignof(struct event_record));
	dump_known_value();
	return 0;
}
#endif
