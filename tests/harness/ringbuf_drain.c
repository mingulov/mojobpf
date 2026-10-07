/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */

/*
 * ringbuf_drain: drain one pinned BPF ring-buffer map into a frame file.
 *
 * This is a loader/test harness (C): it observes kernel-produced bytes
 * and reports them; it never implements product behavior. It opens a
 * pinned ring-buffer map, memory-maps the consumer/producer/data area
 * exactly like the standard consumer protocol (writable consumer page
 * at offset 0, read-only producer page plus the twice-mapped data
 * area at offset one page), walks every available record once the
 * producer is quiescent, advances the consumer position past each
 * record, and writes one frame per record ([u32le kernel length]
 * plus the record bytes) to the output file.
 *
 * Usage:
 *   ringbuf_drain --map <pin-path> --out <frames-file>
 *       [--follow] [--timeout <sec>] [--max-records <n>]
 *
 * Without --follow the tool drains once and exits 0, printing
 * "DRAINED <records> records, <bytes> payload bytes, ring <size>"
 * plus a "RING <cons-start> <cons-end> <prod>" forensics line.
 * Draining zero records is valid (an idle run drains nothing) and
 * still exits 0. With --follow the tool additionally waits on
 * epoll for producer wakeups until --timeout seconds pass with no
 * new batch or --max-records records drain, printing one
 * "FOLLOW <records>" line per batch.
 *
 * Any tool-side failure (unopenable map, wrong map type, mmap or
 * epoll failure, short write, a busy record in one-shot mode
 * (only --follow tolerates a mid-write producer, ending the pass
 * and retrying on the next wakeup), a discarded record (the
 * copy-output producer never discards), an out-of-range record
 * length) prints "DRAINFAIL <reason>" to stderr and exits 1.
 * DRAINFAIL is the consumer-side failure category: it is distinct
 * from kernel producer loss (failed outputs counted in the state
 * map), and the suites assert the two never mix.
 *
 * Raw syscalls and libc only (no libbpf); integers below match the
 * installed linux/bpf.h values (BPF_OBJ_GET 7,
 * BPF_OBJ_GET_INFO_BY_FD 15, BPF_MAP_TYPE_RINGBUF 27, busy bit
 * 1u<<31, discard bit 1u<<30, header size 8).
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

enum {
	BPF_OBJ_GET = 7,
	BPF_OBJ_GET_INFO_BY_FD = 15,
	BPF_MAP_TYPE_RINGBUF = 27,
	RINGBUF_BUSY_BIT = 1u << 31,
	RINGBUF_DISCARD_BIT = 1u << 30,
	RINGBUF_HDR_SZ = 8,
};

union bpf_attr_get {
	struct {
		uint64_t pathname;
		uint32_t bpf_fd;
		uint32_t file_flags;
	} obj;
	struct {
		uint32_t bpf_fd;
		uint32_t info_len;
		uint64_t info;
	} info;
	char pad[80];
};

struct map_info {
	uint32_t type;
	uint32_t id;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t map_flags;
	char name[16];
	uint32_t ifindex;
	uint32_t btf_vmlinux_value_type_id;
	uint64_t netns_dev;
	uint64_t netns_ino;
	uint32_t btf_id;
	uint32_t btf_key_type_id;
	uint32_t btf_value_type_id;
};

static long bpf_syscall(long cmd, union bpf_attr_get *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static void drainfail(const char *reason)
{
	fprintf(stderr, "DRAINFAIL %s\n", reason);
}

static unsigned long load_acquire_ulong(volatile unsigned long *at)
{
	return __atomic_load_n(at, __ATOMIC_ACQUIRE);
}

static void store_release_ulong(volatile unsigned long *at,
				unsigned long value)
{
	__atomic_store_n(at, value, __ATOMIC_RELEASE);
}

static uint32_t load_acquire_u32(volatile uint32_t *at)
{
	return __atomic_load_n(at, __ATOMIC_ACQUIRE);
}

/* Drain one pass over newly available records. Returns records
 * drained, or -1 after printing DRAINFAIL. Advances *cons. When
 * busy_ok is set, a busy record ends the pass cleanly (the
 * producer is mid-write; the follow loop retries on the next
 * wakeup) instead of failing: only the one-shot mode, whose
 * contract is a quiescent producer, treats busy as fatal.
 */
static long drain_pass(volatile unsigned long *consumer_pos,
		       volatile unsigned long *producer_pos,
		       unsigned char *data, unsigned long mask,
		       unsigned long ring_size, FILE *out,
		       unsigned long *cons, unsigned long *payload,
		       int busy_ok)
{
	unsigned long prod = load_acquire_ulong(producer_pos);
	long drained = 0;

	while (*cons < prod) {
		volatile uint32_t *len_at = (volatile uint32_t *)(data +
			(*cons & mask));
		uint32_t raw = load_acquire_u32(len_at);
		uint32_t len;
		unsigned long step;
		unsigned char *sample;

		if (raw & RINGBUF_BUSY_BIT) {
			if (busy_ok)
				return drained;
			drainfail("busy record after quiescence");
			return -1;
		}
		if (raw & RINGBUF_DISCARD_BIT) {
			drainfail("discarded record (copy-output never discards)");
			return -1;
		}
		len = raw;
		if (len == 0 || len > ring_size) {
			fprintf(stderr,
				"DRAINFAIL record length %u outside 1..%lu\n",
				len, ring_size);
			return -1;
		}
		step = (unsigned long)len + RINGBUF_HDR_SZ;
		step = (step + 7) / 8 * 8;
		if (*cons + step > prod) {
			drainfail("record overruns producer position");
			return -1;
		}
		sample = (unsigned char *)len_at + RINGBUF_HDR_SZ;
		{
			unsigned char hdr[4];

			hdr[0] = (unsigned char)(len & 0xFF);
			hdr[1] = (unsigned char)((len >> 8) & 0xFF);
			hdr[2] = (unsigned char)((len >> 16) & 0xFF);
			hdr[3] = (unsigned char)((len >> 24) & 0xFF);
			if (fwrite(hdr, 1, sizeof(hdr), out) != sizeof(hdr) ||
			    fwrite(sample, 1, len, out) != len) {
				drainfail("short frame write");
				return -1;
			}
		}
		*cons += step;
		store_release_ulong(consumer_pos, *cons);
		*payload += len;
		drained++;
	}
	return drained;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s --map <pin> --out <file> [--follow] "
		"[--timeout <sec>] [--max-records <n>]\n", argv0);
}

int main(int argc, char **argv)
{
	const char *map_path = NULL;
	const char *out_path = NULL;
	int follow = 0;
	long timeout_sec = 30;
	long max_records = -1;
	union bpf_attr_get attr;
	struct map_info info;
	uint32_t info_len;
	int map_fd = -1;
	int epoll_fd = -1;
	long page_size;
	unsigned long ring_size;
	unsigned long mask;
	volatile unsigned long *consumer_pos = MAP_FAILED;
	volatile unsigned long *producer_pos = MAP_FAILED;
	unsigned char *data = NULL;
	unsigned long cons = 0;
	unsigned long cons_start = 0;
	unsigned long payload = 0;
	long total = 0;
	long pass;
	int argi;
	FILE *out = NULL;

	/* Line-buffered progress lines: the suites poll the log file
	 * while the tool runs, so no line may sit in a block buffer. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	for (argi = 1; argi < argc; argi++) {
		if (!strcmp(argv[argi], "--map") && argi + 1 < argc) {
			map_path = argv[++argi];
		} else if (!strcmp(argv[argi], "--out") && argi + 1 < argc) {
			out_path = argv[++argi];
		} else if (!strcmp(argv[argi], "--follow")) {
			follow = 1;
		} else if (!strcmp(argv[argi], "--timeout") &&
			   argi + 1 < argc) {
			timeout_sec = atol(argv[++argi]);
		} else if (!strcmp(argv[argi], "--max-records") &&
			   argi + 1 < argc) {
			max_records = atol(argv[++argi]);
		} else {
			usage(argv[0]);
			return 1;
		}
	}
	if (!map_path || !out_path || timeout_sec < 0 || max_records < -1) {
		usage(argv[0]);
		return 1;
	}

	memset(&attr, 0, sizeof(attr));
	attr.obj.pathname = (uint64_t)(uintptr_t)map_path;
	map_fd = (int)bpf_syscall(BPF_OBJ_GET, &attr);
	if (map_fd < 0) {
		fprintf(stderr, "DRAINFAIL open %s: %s\n", map_path,
			strerror(errno));
		return 1;
	}

	memset(&info, 0, sizeof(info));
	memset(&attr, 0, sizeof(attr));
	info_len = sizeof(info);
	attr.info.bpf_fd = (uint32_t)map_fd;
	attr.info.info_len = info_len;
	attr.info.info = (uint64_t)(uintptr_t)&info;
	if (bpf_syscall(BPF_OBJ_GET_INFO_BY_FD, &attr) != 0) {
		fprintf(stderr, "DRAINFAIL map info: %s\n",
			strerror(errno));
		close(map_fd);
		return 1;
	}
	if (info.type != BPF_MAP_TYPE_RINGBUF) {
		fprintf(stderr, "DRAINFAIL map %s has type %u, want %u\n",
			map_path, info.type, BPF_MAP_TYPE_RINGBUF);
		close(map_fd);
		return 1;
	}
	ring_size = info.max_entries;
	if (ring_size == 0 || (ring_size & (ring_size - 1)) != 0) {
		fprintf(stderr, "DRAINFAIL ring size %lu is not a power of two\n",
			ring_size);
		close(map_fd);
		return 1;
	}

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		drainfail("sysconf page size");
		close(map_fd);
		return 1;
	}
	mask = ring_size - 1;

	consumer_pos = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED, map_fd, 0);
	if (consumer_pos == MAP_FAILED) {
		fprintf(stderr, "DRAINFAIL mmap consumer page: %s\n",
			strerror(errno));
		close(map_fd);
		return 1;
	}
	producer_pos = mmap(NULL,
			    (size_t)page_size + 2 * (size_t)ring_size,
			    PROT_READ, MAP_SHARED, map_fd, page_size);
	if (producer_pos == MAP_FAILED) {
		fprintf(stderr, "DRAINFAIL mmap producer/data pages: %s\n",
			strerror(errno));
		munmap((void *)consumer_pos, (size_t)page_size);
		close(map_fd);
		return 1;
	}
	data = (unsigned char *)producer_pos + page_size;

	out = fopen(out_path, "wb");
	if (!out) {
		fprintf(stderr, "DRAINFAIL open %s: %s\n", out_path,
			strerror(errno));
		munmap((void *)producer_pos,
		       (size_t)page_size + 2 * (size_t)ring_size);
		munmap((void *)consumer_pos, (size_t)page_size);
		close(map_fd);
		return 1;
	}
	/* Unbuffered frame writes: a SIGKILLed consumer leaves every
	 * reported record on disk, so the crash suite can verify the
	 * killed drain's exact output. */
	setvbuf(out, NULL, _IONBF, 0);

	cons = load_acquire_ulong(consumer_pos);
	cons_start = cons;
	pass = drain_pass(consumer_pos, producer_pos, data, mask,
			  ring_size, out, &cons, &payload, follow);
	if (pass < 0) {
		fclose(out);
		munmap((void *)producer_pos,
		       (size_t)page_size + 2 * (size_t)ring_size);
		munmap((void *)consumer_pos, (size_t)page_size);
		close(map_fd);
		return 1;
	}
	total = pass;
	if (follow)
		printf("FOLLOW %ld\n", pass);

	if (follow) {
		struct epoll_event ev;
		struct epoll_event got[1];
		long idle_ms = 0;
		const long slice_ms = 100;

		epoll_fd = epoll_create1(EPOLL_CLOEXEC);
		if (epoll_fd < 0) {
			fprintf(stderr, "DRAINFAIL epoll create: %s\n",
				strerror(errno));
			fclose(out);
			munmap((void *)producer_pos,
			       (size_t)page_size + 2 * (size_t)ring_size);
			munmap((void *)consumer_pos, (size_t)page_size);
			close(map_fd);
			return 1;
		}
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = map_fd;
		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, map_fd, &ev) < 0) {
			fprintf(stderr, "DRAINFAIL epoll add: %s\n",
				strerror(errno));
			close(epoll_fd);
			fclose(out);
			munmap((void *)producer_pos,
			       (size_t)page_size + 2 * (size_t)ring_size);
			munmap((void *)consumer_pos, (size_t)page_size);
			close(map_fd);
			return 1;
		}
		while (idle_ms < timeout_sec * 1000 &&
		       (max_records < 0 || total < max_records)) {
			int ready = epoll_wait(epoll_fd, got, 1,
					       (int)slice_ms);

			if (ready < 0) {
				if (errno == EINTR)
					continue;
				fprintf(stderr, "DRAINFAIL epoll wait: %s\n",
					strerror(errno));
				close(epoll_fd);
				fclose(out);
				munmap((void *)producer_pos,
				       (size_t)page_size +
				       2 * (size_t)ring_size);
				munmap((void *)consumer_pos,
				       (size_t)page_size);
				close(map_fd);
				return 1;
			}
			if (ready == 0) {
				idle_ms += slice_ms;
				continue;
			}
			pass = drain_pass(consumer_pos, producer_pos, data,
					  mask, ring_size, out, &cons,
					  &payload, 1);
			if (pass < 0) {
				close(epoll_fd);
				fclose(out);
				munmap((void *)producer_pos,
				       (size_t)page_size +
				       2 * (size_t)ring_size);
				munmap((void *)consumer_pos,
				       (size_t)page_size);
				close(map_fd);
				return 1;
			}
			total += pass;
			printf("FOLLOW %ld\n", pass);
			fflush(stdout);
			if (pass > 0)
				idle_ms = 0;
			else
				idle_ms += slice_ms;
		}
		close(epoll_fd);
	}

	if (fclose(out) != 0) {
		drainfail("close frames file");
		munmap((void *)producer_pos,
		       (size_t)page_size + 2 * (size_t)ring_size);
		munmap((void *)consumer_pos, (size_t)page_size);
		close(map_fd);
		return 1;
	}
	{
		unsigned long prod = load_acquire_ulong(producer_pos);

		munmap((void *)producer_pos,
		       (size_t)page_size + 2 * (size_t)ring_size);
		munmap((void *)consumer_pos, (size_t)page_size);
		close(map_fd);
		printf("DRAINED %ld records, %lu payload bytes, ring %lu\n",
		       total, payload, ring_size);
		printf("RING %lu %lu %lu\n", cons_start, cons, prod);
	}
	return 0;
}
