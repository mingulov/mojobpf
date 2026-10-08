// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Suite-owned uprobe target executable (example + test fixture).
//
// This is the ONLY binary a MojoBPF uprobe program is ever
// attached to: one suite-owned executable, built non-PIE so its
// symbol addresses are fixed, carrying its own probe sites.
// Usage:
//
//   uprobe_target <calls> <value> <fifo>
//
// Calls probe_target(value) exactly <calls> times, then exits 0.
// Every call reports the value it actually passed over <fifo>
// (one 8-byte little-endian word per call), which is the oracle
// side channel the suite compares the kernel counter against:
// the probe's word alone never proves anything.
//
// probe_target is deliberately call-shaped (non-inlined, external
// linkage, one 64-bit argument): at its entry the first-argument
// register still holds the caller's value, which is what the
// uprobe program extracts. probe_never_called has the same shape
// and is never invoked, so a probe attached to it must observe
// zero hits.
//
// Build non-PIE (``cc -no-pie -fno-pie -O2``): the suite resolves
// the probe offset from the symbol address, which is fixed only
// in a non-PIE executable.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile uint64_t sink;
static volatile uint64_t probe_calls;

__attribute__((noinline)) uint64_t
probe_target(uint64_t x) {
    // The volatile increment is observable behavior: without it
    // the compiler may fold repeated calls with one argument
    // into a single call, and the probe would legitimately fire
    // once instead of once per call. Every invocation below
    // executes exactly one call instruction.
    probe_calls += 1;
    return (x ^ 0x9E3779B97F4A7C15ULL) + probe_calls;
}

__attribute__((noinline)) uint64_t
probe_never_called(uint64_t x) {
    return x + 0xD1B54A32D192ED03ULL;
}

static int
write_full(int fd, const void *buf, size_t len) {
    const char *at = (const char *)buf;
    while (len > 0) {
        ssize_t got = write(fd, at, len);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (got == 0) {
            return -1;
        }
        at += got;
        len -= (size_t)got;
    }
    return 0;
}

int
main(int argc, char **argv) {
    unsigned long long calls;
    unsigned long long value;
    char *end;
    int fifo;
    unsigned long long i;
    if (argc != 4) {
        fprintf(stderr, "usage: uprobe_target <calls> <value> <fifo>\n");
        return 2;
    }
    calls = strtoull(argv[1], &end, 0);
    if (*end != '\0') {
        fprintf(stderr, "bad calls: %s\n", argv[1]);
        return 2;
    }
    value = strtoull(argv[2], &end, 0);
    if (*end != '\0') {
        fprintf(stderr, "bad value: %s\n", argv[2]);
        return 2;
    }
    fifo = open(argv[3], O_WRONLY);
    if (fifo < 0) {
        fprintf(stderr, "open fifo %s: %s\n", argv[3], strerror(errno));
        return 1;
    }
    for (i = 0; i < calls; i++) {
        uint64_t word = (uint64_t)value;
        uint8_t le[8];
        size_t b;
        sink += probe_target((uint64_t)value);
        for (b = 0; b < 8; b++) {
            le[b] = (uint8_t)(word >> (8 * b));
        }
        if (write_full(fifo, le, sizeof(le)) != 0) {
            fprintf(stderr, "write fifo: %s\n", strerror(errno));
            close(fifo);
            return 1;
        }
    }
    close(fifo);
    printf("done calls=%llu value=%llu sink=%llu\n", calls, value,
           (unsigned long long)sink);
    return 0;
}
