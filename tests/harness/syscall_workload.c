// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Raw-syscall workload for the tracepoint counter suite.
//
// Spawns three worker threads (one monitored, two excluded) that
// issue raw getpid syscalls in a tight loop, coordinated with the
// parent over two FIFOs so no fixed sleep is needed. Usage:
//
//   syscall_workload --monitored N --excluded M
//       --phase {excluded|full}
//       --tid-file PATH --go-fifo PATH --done-fifo PATH
//
// Protocol: each worker publishes "<role> <tid>" to the TID file,
// then waits at the start barrier. The main thread (the observer,
// a fourth TID outside every worker) publishes
// "observer <tid>", then blocks reading one byte from the go FIFO.
// On release it joins the start barrier; workers run their loops
// (the excluded phase runs only the excluded workers; the full
// phase runs all three), meet at the end barrier, and the main
// thread writes "DONE monitored=<n> excl1=<m1> excl2=<m2>" to the
// done FIFO with the loop counts each worker actually executed,
// then joins and exits 0.
//
// Thread identity uses raw SYS_gettid (never getpid, which would
// self-trace). The timed loops issue raw SYS_getpid only, with no
// libc calls between the barriers. The process refuses to run
// outside the initial PID namespace, where helper-14 TIDs and
// gettid() agree. Exit 1 on usage or runtime errors, 2 outside
// the initial PID namespace.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static long monitored_loops = 0;
static long excluded_loops = 0;
static int phase_full = 0;
static const char *tid_path = NULL;

static pthread_barrier_t start_barrier;
static pthread_barrier_t end_barrier;

struct worker {
    const char *role;
    long loops;
    long done;
};

static void die(int code, const char *msg) {
    fprintf(stderr, "syscall_workload: %s\n", msg);
    exit(code);
}

static long get_tid(void) {
    return syscall(SYS_gettid);
}

static void publish_tid(const char *role, long tid) {
    FILE *out = fopen(tid_path, "a");
    if (out == NULL) {
        die(1, "cannot open TID file");
    }
    fprintf(out, "%s %ld\n", role, tid);
    if (fclose(out) != 0) {
        die(1, "cannot write TID file");
    }
}

static void barrier_wait(pthread_barrier_t *barrier, const char *what) {
    int ret = pthread_barrier_wait(barrier);
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        die(1, what);
    }
}

// The timed region: raw getpid syscalls only, no libc calls.
static long run_loops(long count) {
    long done = 0;
    for (long i = 0; i < count; i++) {
        syscall(SYS_getpid);
        done++;
    }
    return done;
}

static void *worker_main(void *arg) {
    struct worker *work = (struct worker *)arg;
    publish_tid(work->role, get_tid());
    barrier_wait(&start_barrier, "start barrier failed");
    work->done = run_loops(work->loops);
    barrier_wait(&end_barrier, "end barrier failed");
    return NULL;
}

static int same_file(const char *first, const char *second) {
    char a[64], b[64];
    ssize_t a_len = readlink(first, a, sizeof(a) - 1);
    ssize_t b_len = readlink(second, b, sizeof(b) - 1);
    if (a_len < 0 || b_len < 0) {
        return 0;
    }
    a[a_len] = '\0';
    b[b_len] = '\0';
    return strcmp(a, b) == 0;
}

static long parse_count(const char *text, const char *flag) {
    char *end = NULL;
    long value;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 0 ||
        value > 100000000L) {
        die(1, flag);
    }
    return value;
}

int main(int argc, char **argv) {
    struct worker workers[3];
    pthread_t threads[3];
    const char *go_path = NULL;
    const char *done_path = NULL;
    int go_fd = -1;
    char go_byte;
    ssize_t got;
    FILE *done = NULL;

    if (!same_file("/proc/self/ns/pid", "/proc/1/ns/pid")) {
        die(2, "must run in the initial PID namespace");
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--monitored") == 0 && i + 1 < argc) {
            monitored_loops = parse_count(argv[++i], "bad --monitored");
        } else if (strcmp(argv[i], "--excluded") == 0 && i + 1 < argc) {
            excluded_loops = parse_count(argv[++i], "bad --excluded");
        } else if (strcmp(argv[i], "--phase") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "full") == 0) {
                phase_full = 1;
            } else if (strcmp(argv[i], "excluded") == 0) {
                phase_full = 0;
            } else {
                die(1, "bad --phase (want excluded or full)");
            }
        } else if (strcmp(argv[i], "--tid-file") == 0 && i + 1 < argc) {
            tid_path = argv[++i];
        } else if (strcmp(argv[i], "--go-fifo") == 0 && i + 1 < argc) {
            go_path = argv[++i];
        } else if (strcmp(argv[i], "--done-fifo") == 0 && i + 1 < argc) {
            done_path = argv[++i];
        } else {
            die(1, "usage: --monitored N --excluded M "
                "--phase {excluded|full} "
                "--tid-file P --go-fifo P --done-fifo P");
        }
    }
    if (tid_path == NULL || go_path == NULL || done_path == NULL) {
        die(1, "missing --tid-file, --go-fifo, or --done-fifo");
    }
    workers[0].role = "monitored";
    workers[0].loops = phase_full ? monitored_loops : 0;
    workers[0].done = 0;
    workers[1].role = "excl1";
    workers[1].loops = excluded_loops;
    workers[1].done = 0;
    workers[2].role = "excl2";
    workers[2].loops = excluded_loops;
    workers[2].done = 0;
    if (pthread_barrier_init(&start_barrier, NULL, 4) != 0 ||
        pthread_barrier_init(&end_barrier, NULL, 4) != 0) {
        die(1, "barrier init failed");
    }
    for (int i = 0; i < 3; i++) {
        if (pthread_create(&threads[i], NULL, worker_main, &workers[i]) != 0) {
            die(1, "thread spawn failed");
        }
    }
    publish_tid("observer", get_tid());
    go_fd = open(go_path, O_RDONLY);
    if (go_fd < 0) {
        die(1, "cannot open go FIFO");
    }
    got = read(go_fd, &go_byte, 1);
    close(go_fd);
    if (got != 1) {
        die(1, "go handshake failed");
    }
    barrier_wait(&start_barrier, "start barrier failed");
    barrier_wait(&end_barrier, "end barrier failed");
    done = fopen(done_path, "w");
    if (done == NULL) {
        die(1, "cannot open done FIFO");
    }
    fprintf(done, "DONE monitored=%ld excl1=%ld excl2=%ld\n",
            workers[0].done, workers[1].done, workers[2].done);
    if (fclose(done) != 0) {
        die(1, "cannot write done FIFO");
    }
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }
    pthread_barrier_destroy(&start_barrier);
    pthread_barrier_destroy(&end_barrier);
    return 0;
}
