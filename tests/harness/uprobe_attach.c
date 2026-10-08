// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Uprobe attachment holder for the uprobe register suite.
//
// Attaches a bpftool-pinned program to one symbol of the
// suite-owned test executable through tracefs uprobe events and
// perf events, using raw syscalls only (no libbpf headers
// needed). Usage:
//
//   uprobe_attach <pinned-prog> <stage-dir> <binary> <offset> <event>
//
// <binary> must be the suite-owned test executable staged under
// <stage-dir>: the holder resolves both paths and refuses
// anything else (NOTESTBIN) before touching tracefs, so a
// misspelled path can never attach the probe to a system binary.
// <offset> is the hex probe FILE offset into the binary (with or
// without 0x; for the non-PIE test executable the suite maps the
// symbol address through its section headers), <event> the
// tracefs event name (created under the uprobes group and
// removed again on teardown).
//
// Prints ATTACHED, then blocks on stdin until EOF and detaches
// by closing the link and event fds and removing the tracefs
// event. The parent holds a release FIFO open as the holder's
// stdin and closes it to end the attachment window
// deterministically. Exit 0 after a clean detach printing
// DETACHED, 1 on any setup failure with the reason on stdout as
// a single line (NOTESTBIN names a refused binary; IDFAIL names
// a missing event id; the suite treats a missing tracefs
// uprobe interface as an environment-capability signal, never a
// pass).
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static int
bpf_obj_get(const char *path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    return (int)syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static int
perf_open(__u64 config, int cpu) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    // Tracefs-created uprobe events open through the tracepoint
    // perf type with their event id (the dynamic uprobe PMU type
    // is only for the direct config1/config2 PMU interface, and
    // opening a tracefs id through it fails with EINVAL).
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.config = config;
    attr.sample_period = 1;
    return (int)syscall(SYS_perf_event_open, &attr, -1, cpu, -1, 0);
}

static int
bpf_link_create(int prog_fd, int target_fd) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.link_create.prog_fd = (__u32)prog_fd;
    attr.link_create.target_fd = (__u32)target_fd;
    attr.link_create.attach_type = BPF_PERF_EVENT;
    return (int)syscall(SYS_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
}

// First online CPU from a cpu-online list ("0-3", "0,2", "7"),
// or -1 on parse failure. One attachment covers the probed
// inode on every CPU, so only the vehicle's CPU is needed.
static int
first_online_cpu(void) {
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

// Resolve path under the staged root: both are canonicalized
// and the binary must live strictly inside the stage directory.
// Returns 0 with the canonical binary in out, or -1 refusing.
static int
check_staged(const char *stage, const char *binary, char *out,
             size_t out_len) {
    char stage_real[4096];
    char bin_real[4096];
    size_t root_len;
    if (realpath(stage, stage_real) == NULL) {
        return -1;
    }
    if (realpath(binary, bin_real) == NULL) {
        return -1;
    }
    root_len = strlen(stage_real);
    if (root_len == 0 || root_len + 1 >= sizeof(bin_real)) {
        return -1;
    }
    if (strncmp(bin_real, stage_real, root_len) != 0) {
        return -1;
    }
    if (bin_real[root_len] != '/') {
        return -1;
    }
    if (strlen(bin_real) + 1 > out_len) {
        return -1;
    }
    strcpy(out, bin_real);
    return 0;
}

static int
write_text_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    ssize_t len;
    ssize_t done = 0;
    if (fd < 0) {
        return -1;
    }
    len = (ssize_t)strlen(text);
    while (done < len) {
        ssize_t got = write(fd, text + done, (size_t)(len - done));
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        if (got == 0) {
            close(fd);
            return -1;
        }
        done += got;
    }
    close(fd);
    return 0;
}

static int
read_u64_file(const char *path, unsigned long long *out) {
    FILE *id = fopen(path, "r");
    unsigned long long value;
    if (id == NULL) {
        return -1;
    }
    if (fscanf(id, "%llu", &value) != 1) {
        fclose(id);
        return -1;
    }
    fclose(id);
    *out = value;
    return 0;
}

static int
event_name_ok(const char *name) {
    size_t i;
    if (name[0] == '\0' || strlen(name) > 64) {
        return 0;
    }
    for (i = 0; name[i] != '\0'; i++) {
        char c = name[i];
        if ((c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' &&
            c != '-') {
            return 0;
        }
    }
    return 1;
}

int
main(int argc, char **argv) {
    char bin_real[4096];
    char spec[8192];
    char id_path[512];
    char rm_spec[128];
    char events_path[] = "/sys/kernel/tracing/uprobe_events";
    unsigned long long event_id;
    unsigned long long offset;
    char *end;
    int prog_fd;
    int cpu;
    int event_fd = -1;
    int link_fd = -1;
    int have_event = 0;
    int attached = 0;
    char drain[256];
    ssize_t got;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 6) {
        printf("USAGE uprobe_attach <pinned-prog> <stage-dir> "
               "<binary> <offset> <event>\n");
        return 1;
    }
    if (!event_name_ok(argv[5])) {
        printf("BADEVENT %s\n", argv[5]);
        return 1;
    }
    if (check_staged(argv[2], argv[3], bin_real, sizeof(bin_real)) !=
        0) {
        printf("NOTESTBIN %s (stage %s)\n", argv[3], argv[2]);
        return 1;
    }
    offset = strtoull(argv[4], &end, 0);
    if (*end != '\0') {
        printf("BADOFFSET %s\n", argv[4]);
        return 1;
    }
    prog_fd = bpf_obj_get(argv[1]);
    if (prog_fd < 0) {
        printf("OBJGET errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    if (access(events_path, W_OK) != 0) {
        printf("NOUPROBE uprobe_events unavailable (%s)\n",
               strerror(errno));
        close(prog_fd);
        return 1;
    }
    snprintf(spec, sizeof(spec), "p:%s %s:0x%llx\n", argv[5], bin_real,
             offset);
    if (write_text_file(events_path, spec) != 0) {
        printf("ADDEVENT errno=%d (%s)\n", errno, strerror(errno));
        close(prog_fd);
        return 1;
    }
    have_event = 1;
    snprintf(id_path, sizeof(id_path),
             "/sys/kernel/tracing/events/uprobes/%s/id", argv[5]);
    if (read_u64_file(id_path, &event_id) != 0) {
        printf("IDFAIL %s\n", argv[5]);
        goto cleanup_event;
    }
    cpu = first_online_cpu();
    if (cpu < 0) {
        printf("NOCPU\n");
        goto cleanup_event;
    }
    event_fd = perf_open((__u64)event_id, cpu);
    if (event_fd < 0) {
        printf("PERFOPEN cpu=%d errno=%d (%s)\n", cpu, errno,
               strerror(errno));
        goto cleanup_event;
    }
    link_fd = bpf_link_create(prog_fd, event_fd);
    if (link_fd < 0) {
        printf("LINKCREATE cpu=%d errno=%d (%s)\n", cpu, errno,
               strerror(errno));
        close(event_fd);
        goto cleanup_event;
    }
    if (ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        printf("ENABLE cpu=%d errno=%d (%s)\n", cpu, errno,
               strerror(errno));
        goto cleanup_event;
    }
    printf("ATTACHED cpu=%d event_id=%llu offset=0x%llx\n", cpu,
           event_id, offset);
    while ((got = read(STDIN_FILENO, drain, sizeof(drain))) > 0) {
    }
    attached = 1;
    close(link_fd);
    link_fd = -1;
    close(event_fd);
    event_fd = -1;
cleanup_event:
    if (link_fd >= 0) {
        close(link_fd);
        link_fd = -1;
    }
    if (event_fd >= 0) {
        close(event_fd);
        event_fd = -1;
    }
    if (have_event) {
        snprintf(rm_spec, sizeof(rm_spec), "-:%s\n", argv[5]);
        if (write_text_file(events_path, rm_spec) != 0) {
            printf("RMEVENT %s errno=%d (%s)\n", argv[5], errno,
                   strerror(errno));
            close(prog_fd);
            return 1;
        }
        have_event = 0;
    }
    if (attached) {
        printf("DETACHED\n");
        close(prog_fd);
        return 0;
    }
    close(prog_fd);
    return 1;
}
