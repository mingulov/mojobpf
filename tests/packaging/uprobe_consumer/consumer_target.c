// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Third-party probe target: the subscriber's own executable.
//
// The subscriber's uprobe program is attached to watched_call in
// THIS binary only, never to a system binary. Usage:
//
//   consumer_target <calls> <value> <fifo>
//
// Invokes watched_call(value) exactly <calls> times, then exits
// 0. Each invocation reports the value it passed over <fifo> as
// one 8-byte little-endian word, so the test oracle can compare
// the kernel counter against independently observed arguments.
// never_watched has the same call shape and is never invoked,
// so a probe attached to it must observe zero hits.
//
// Build non-PIE (cc -no-pie -fno-pie -O2): probe offsets are
// resolved from the symbol table, which is fixed only in a
// non-PIE executable.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile uint64_t accumulator;
static volatile uint64_t watched_calls;

__attribute__((noinline)) uint64_t
watched_call(uint64_t arg) {
    // The volatile increment is observable behavior: without it
    // the compiler may fold repeated calls with one argument
    // into a single call. Every invocation below executes
    // exactly one call instruction.
    watched_calls += 1;
    return (arg ^ 0x243F6A8885A308D3ULL) + watched_calls;
}

__attribute__((noinline)) uint64_t
never_watched(uint64_t arg) {
    return arg + 0x452821E638D01377ULL;
}

static int
write_all(int fd, const void *buf, size_t len) {
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
        fprintf(stderr, "usage: consumer_target <calls> <value> <fifo>\n");
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
        accumulator += watched_call((uint64_t)value);
        for (b = 0; b < 8; b++) {
            le[b] = (uint8_t)(word >> (8 * b));
        }
        if (write_all(fifo, le, sizeof(le)) != 0) {
            fprintf(stderr, "write fifo: %s\n", strerror(errno));
            close(fifo);
            return 1;
        }
    }
    close(fifo);
    printf("done calls=%llu value=%llu acc=%llu\n", calls, value,
           (unsigned long long)accumulator);
    return 0;
}
