// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Tracepoint attachment holder for the tracepoint counter suite.
//
// Attaches a bpftool-pinned program to a tracepoint through perf
// events, using raw syscalls only (no libbpf headers needed).
// Usage:
//   tracepoint_attach <pinned-prog> <category> <event-name>
// Reads the tracepoint id from tracefs, opens one perf event on the
// first online CPU, and attaches the pinned program with
// BPF_LINK_CREATE (the same link mechanism libbpf uses). One
// attachment is system-wide: the tracepoint probe it registers
// fires on every CPU, so worker migration cannot lose events and
// a second attachment of the same program is refused as a
// duplicate. Prints ATTACHED, then blocks on stdin until EOF and
// detaches by closing the link and event fds. The parent holds a
// release FIFO open as the holder's stdin and closes it to end
// the attachment window deterministically. Exit 0 after a clean
// detach printing DETACHED, 1 on any setup failure with the
// reason on stdout as a single line (IDFAIL names a missing
// tracepoint; the suite treats that as an
// environment-capability signal, never a pass).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int bpf_obj_get(const char *path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    return (int)syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int perf_open(__u64 config, int cpu) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.config = config;
    attr.sample_period = 1;
    return (int)syscall(SYS_perf_event_open, &attr, -1, cpu, -1, 0);
}

static int bpf_link_create(int prog_fd, int target_fd) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.link_create.prog_fd = (__u32)prog_fd;
    attr.link_create.target_fd = (__u32)target_fd;
    attr.link_create.attach_type = BPF_PERF_EVENT;
    return (int)syscall(SYS_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
}

// First online CPU from a cpu-online list ("0-3", "0,2", "7"),
// or -1 on parse failure. One attachment is system-wide, so only
// the vehicle's CPU is needed.
static int first_online_cpu(void) {
    FILE *list = fopen("/sys/devices/system/cpu/online", "r");
    char text[256];
    char *dash;
    long cpu;
    if (list == NULL) {
        return -1;
    }
    if (fgets(text, sizeof(text), list) == NULL) {
        fclose(list);
        return -1;
    }
    fclose(list);
    dash = strchr(text, '-');
    if (dash != NULL) {
        *dash = '\0';
    }
    cpu = strtol(text, NULL, 10);
    if (cpu < 0 || cpu > 4096) {
        return -1;
    }
    return (int)cpu;
}

static int read_event_id(const char *cat, const char *name, __u64 *out) {
    static const char *roots[] = {
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    };
    char path[512];
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        FILE *id;
        unsigned long long value;
        snprintf(path, sizeof(path), "%s/%s/%s/id", roots[i], cat, name);
        id = fopen(path, "r");
        if (id == NULL) {
            continue;
        }
        if (fscanf(id, "%llu", &value) == 1) {
            fclose(id);
            *out = (__u64)value;
            return 0;
        }
        fclose(id);
    }
    return -1;
}

int main(int argc, char **argv) {
    int prog_fd;
    __u64 event_id;
    int cpu;
    int event_fd;
    int link_fd;
    char drain[256];
    ssize_t got;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 4) {
        printf("USAGE tracepoint_attach <pinned-prog> <category> <name>\n");
        return 1;
    }
    prog_fd = bpf_obj_get(argv[1]);
    if (prog_fd < 0) {
        printf("OBJGET errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (read_event_id(argv[2], argv[3], &event_id) != 0) {
        printf("IDFAIL %s:%s\n", argv[2], argv[3]);
        close(prog_fd);
        return 1;
    }
    cpu = first_online_cpu();
    if (cpu < 0) {
        printf("NOCPU\n");
        close(prog_fd);
        return 1;
    }
    event_fd = perf_open(event_id, cpu);
    if (event_fd < 0) {
        printf("PERFOPEN cpu=%d errno=%d (%s)\n", cpu, errno,
               strerror(errno));
        close(prog_fd);
        return 1;
    }
    link_fd = bpf_link_create(prog_fd, event_fd);
    if (link_fd < 0) {
        printf("LINKCREATE cpu=%d errno=%d (%s)\n", cpu, errno,
               strerror(errno));
        close(event_fd);
        close(prog_fd);
        return 1;
    }
    if (ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        printf("ENABLE cpu=%d errno=%d (%s)\n", cpu, errno,
               strerror(errno));
        close(link_fd);
        close(event_fd);
        close(prog_fd);
        return 1;
    }
    printf("ATTACHED cpu=%d event_id=%llu\n", cpu,
           (unsigned long long)event_id);
    while ((got = read(STDIN_FILENO, drain, sizeof(drain))) > 0) {
    }
    close(link_fd);
    close(event_fd);
    close(prog_fd);
    printf("DETACHED\n");
    return 0;
}
