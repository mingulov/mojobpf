# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Tracepoint attach, lifetime, interruption, and cleanup proofs.

Builds the qualified counter, event emitter, and XDP objects
through the genuine pipeline on the host, compiles the raw-syscall
workload and the tracepoint attach holder with the host C
compiler, stages everything into one disposable virtme-ng guest,
and proves the tracing failure paths:

* attach failure: a bad pin path, a missing event, a
  type-mismatched program, and a duplicate attachment each yield
  their own classified holder outcome (``OBJGET``, ``IDFAIL``,
  ``LINKCREATE errno=22``, ``LINKCREATE errno=17``) with exit 1
  and no residue;
* process exit: a normal run observes its exact count, the
  workload exits 0, the holder detaches with ``DETACHED`` and
  exit 0, and the link is present during the run and gone after;
* interruption: SIGTERM and SIGKILL mid-run against the holder
  (exits 143/137) stop counting while the workload completes, and
  SIGKILL against the workload before release and mid-run (exit
  137, no completion report) freezes the counter; every kill
  targets only a process this run spawned (pid from ``$!`` plus a
  command-line and liveness recheck, so a foreign or recycled pid
  is never signalled), and detachment plus unload still clean up;
* repeated runs: five counter cycles and three emitter cycles
  leave the owned guest resources (links, pins, programs, maps),
  the shell's file descriptors, the mount table, and the child
  list exactly as found, with every cycle's count exact.

A second layer proves the map/event preflight fail-safe through
the load-and-unload wrapper: a full event preflight passes, an
unsupported map type and a missing trace event report their own
unavailability with no load attempted (never a crash or a fake
pass), and a map type the lanes disagree on gets its exact
per-lane verdict.

Protocol notes. Every run starts its own workload process (fresh
TIDs), publishes all four TIDs (the observer runs outside the
monitored TID), initializes the filter and counters with
readback, then releases the workers over a FIFO; the workers
report their executed loop counts over a second FIFO after
joining, so counter reads are quiescent by construction. Kills
land only after an explicit mid-run proof (a positive counter
sighting plus a live, non-zombie, command-line-confirmed
target); no fixed sleep synchronizes anything. The suite cleans
up every pin, attachment, process, and FIFO it creates and
asserts the guest holds no residue afterwards.

Requires ``mojo``, ``llc``, ``cc``, ``bpftool`` and ``vng`` on
PATH plus the pinned kernels. ``MOJOBPF_VNG_RELEASE`` selects the
guest lane (default ``v6.12``). A missing tool or lane is an
environment failure; a failing proof step is a proof failure.
Neither ever passes.

Runnable directly (``python3
tests/kernel/test_tracing_lifecycle.py``) or under any
``test_``-style runner. Standard library only.
"""

import hashlib
import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import lane_lock  # noqa: E402
import guest_proc  # noqa: E402
COUNTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "counter.mojo"
)
EMITTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_events", "emitter.mojo"
)
XDP_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
WORKLOAD_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "syscall_workload.c"
)
HOLDER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "tracepoint_attach.c"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

from mojobpf.verify import (  # noqa: E402
    _FORBIDDEN_GUEST_TOKENS,
    VerifyError,
    VerifyRequest,
    run_verification,
)

# The guest must test exactly the qualified bytes.
COUNTER_OBJECT_HASH = (
    "b687af78c3056e2299929cd635044875f8369f9ca6e27f626c4f55c4def8b67a"
)
EMITTER_OBJECT_HASH = (
    "dbddc75dabe4198107eca403a37bfa04934932c6cfe011ca5f46ca6df67b8770"
)
XDP_OBJECT_HASH = (
    "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c"
)

EXIT_N = 500
EXIT_M = 100
KILL_N = 2000000
KILL_M = 1000
MINI_N = 200
MINI_M = 100
REPEAT_CYCLES = 5
EMITTER_CYCLES = 3

TRACE_EVENT = "syscalls:sys_enter_getpid"
BOGUS_EVENT = "syscalls:sys_enter_no_such_event"

# Map types for the fail-safe preflight: insn_array is an
# unknown-to-observer name (bpftool has no such type, so the probe
# yields no line and the verdict is unknown, never "NOT available"),
# while arena splits the lanes (measured, pinned per lane below).
UNKNOWN_MAP = "insn_array"
SPLIT_MAP = "arena"
SPLIT_MAP_LANE = {
    "v6.12": True,
    "v6.6": False,
}

GUEST_TIMEOUT = 900


class EnvironmentFailure(Exception):
    """The toolchain or lane needed by this test is missing."""


class ProofFailure(Exception):
    """A proof step failed inside the guest."""


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def run_guest(argv, stage, timeout):
    """Run one owned child as a session leader with tree cleanup.

    Thin mapping over the shared owned runner
    (tests/harness/guest_proc.py): on timeout the whole owned
    tree (the booted guest included) is killed and reaped and an
    :class:`EnvironmentFailure` surfaces with the partial
    output; an interruption reaps the owned tree and propagates.
    Returns ``(returncode, output)``. The transcript is saved
    under ``stage``.
    """
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "guest run timed out after %ds; owned tree killed "
            "and reaped; partial output (last 2000 chars): %r"
            % (timeout, exc.output[-2000:])
        )


def check_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def vng_release():
    release = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
    if not re.fullmatch(r"v\d+\.\d+", release):
        raise EnvironmentFailure(
            "MOJOBPF_VNG_RELEASE must look like v6.12, got %r" % release
        )
    return release


def sha256_file(path):
    with guest_proc.open_consumed(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


@guest_proc.consumes_source
def build_object(source, workdir, tag, want_hash, use_sdk):
    """Build one Mojo source; assert the qualified object bytes."""
    raw_path = os.path.join(workdir, "%s.ll" % tag)
    adapted_path = os.path.join(workdir, "%s.bpf.ll" % tag)
    object_path = os.path.join(workdir, "%s.bpf.o" % tag)
    frontend = ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS]
    if use_sdk:
        frontend += ["-I", SDK_INCLUDE]
    frontend += ["-o", raw_path, source]
    proc = run_step(frontend)
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "frontend failed for %s: exit=%d stderr=%r"
            % (source, proc.returncode, proc.stderr[-1000:])
        )
    proc = run_step(
        [
            sys.executable, ADAPTER,
            "--input", raw_path, "--output", adapted_path,
        ]
    )
    if proc.returncode != 0:
        raise ProofFailure(
            "adapter failed for %s: %s%s"
            % (source, proc.stdout[-500:], proc.stderr[-500:])
        )
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
            adapted_path, "-o", object_path,
        ]
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "backend failed for %s: exit=%d stderr=%r"
            % (source, proc.returncode, proc.stderr[-1000:])
        )
    observed = sha256_file(object_path)
    if observed != want_hash:
        raise ProofFailure(
            "staged %s bytes %s do not match the qualified %s"
            % (tag, observed, want_hash)
        )
    return object_path


@guest_proc.consumes_source
def build_harness(source, output, extra=()):
    """Compile one C harness with warnings fatal."""
    proc = run_step(
        ["cc", "-O2", "-Wall", "-Wextra", "-o", output, source, *extra]
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "harness build failed for %s: exit=%d stderr=%r"
            % (source, proc.returncode, proc.stderr[-2000:])
        )
    return output


_FIXTURE = {}


def fixture():
    """Build the shared objects once per process; return their paths."""
    if "counter" in _FIXTURE:
        return _FIXTURE
    check_tools("mojo", "llc", "cc", "bpftool", "vng")
    for path in (
        COUNTER_SOURCE, EMITTER_SOURCE, XDP_SOURCE,
        WORKLOAD_SOURCE, HOLDER_SOURCE,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    workdir = guest_proc.owned_stage(prefix="mojo-lifecycle-")
    counter = build_object(
        COUNTER_SOURCE, workdir, "counter", COUNTER_OBJECT_HASH, True
    )
    emitter = build_object(
        EMITTER_SOURCE, workdir, "emitter", EMITTER_OBJECT_HASH, True
    )
    xdp = build_object(XDP_SOURCE, workdir, "xdp", XDP_OBJECT_HASH, False)
    workload = build_harness(
        WORKLOAD_SOURCE, os.path.join(workdir, "syscall_workload"),
        ("-pthread",),
    )
    holder = build_harness(
        HOLDER_SOURCE, os.path.join(workdir, "tracepoint_attach")
    )
    _FIXTURE.update(
        {
            "counter": counter,
            "emitter": emitter,
            "xdp": xdp,
            "workload": workload,
            "holder": holder,
        }
    )
    return _FIXTURE


GUEST_SCRIPT = r"""#!/bin/bash
# Tracing lifecycle guest proof: classified attach failures, an
# exact-count process exit, mid-run kills against the holder and
# the workload, and repeated counter/emitter cycles with full
# owned-resource accounting (links, pins, programs, maps, shell
# FDs, mounts, children). Blocking waits carry timeouts that fail
# loudly; kills land only after an explicit mid-run proof; nothing
# here assumes a fixed sleep.
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="__STAGE__"
EXIT_N=__EXIT_N__
EXIT_M=__EXIT_M__
KILL_N=__KILL_N__
KILL_M=__KILL_M__
MINI_N=__MINI_N__
MINI_M=__MINI_M__
REPEAT_CYCLES=__REPEAT_CYCLES__
EMITTER_CYCLES=__EMITTER_CYCLES__
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin tracing-lifecycle ==="
echo "guest-kernel: $(uname -r)"
bpftool version | head -1
echo "ncpu: $(nproc)"
echo "--- staged hashes ---"
sha256sum guest_lifecycle.sh counter.bpf.o emitter.bpf.o xdp.bpf.o syscall_workload tracepoint_attach
echo "__COUNTER_HASH__  counter.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH counter"; exit 1; }
echo "__EMITTER_HASH__  emitter.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH emitter"; exit 1; }
echo "__XDP_HASH__  xdp.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH xdp"; exit 1; }
echo "staged bytes: qualified"
echo "--- resources before ---"
map_show_filtered() {
  # bpftool 7.6 observes its own ephemeral iterator maps
  # (pid_iter.*) with per-run IDs and PIDs, and leaks its
  # skeleton maps (libbpf_global, libbpf_det_bind), so raw
  # `map show` output never compares equal across runs.
  # Drop exactly those tool-owned entries and the ephemeral
  # pids lines; suite maps (mojobpf_map*) always pass
  # through, so a real stray still fails the comparison.
  bpftool map show | awk '
    /^[0-9]+:/ { skip = ($0 ~ /name (pid_iter\.[A-Za-z0-9_.]*|libbpf_global|libbpf_det_bind)( |$)/) }
    skip { next }
    /^[[:space:]]+pids / { next }
    { print }'
  return ${PIPESTATUS[0]}
}
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$(bpftool link show)
PROGS_BEFORE=$(bpftool prog show)
MAPS_BEFORE=$(map_show_filtered)
FDS_BEFORE=$(ls /proc/$$/fd | wc -l)
# The guest boots without bpffs; the first pin auto-mounts it
# (libbpf/bpftool automount), which would read as mount drift.
# Mount upfront so the baseline is stable; verified to print
# the identical mount string before and after a pin cycle.
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
MOUNTS_BEFORE=$(mount | grep "type bpf" || true)
echo "$PINS_BEFORE"
echo "$LINKS_BEFORE"
echo "fds-before: $FDS_BEFORE"
echo "mounts-before: $MOUNTS_BEFORE"
echo "--- namespace self-check ---"
SELF_NS=$(readlink /proc/self/ns/pid)
INIT_NS=$(readlink /proc/1/ns/pid)
echo "self-ns: $SELF_NS"
echo "init-ns: $INIT_NS"
[ "$SELF_NS" = "$INIT_NS" ] || { echo "NAMESPACE-MISMATCH"; exit 1; }
echo "namespace: initial"

map_u64() {
  # map_u64 <pinned-map> <key>: print the u64 value as decimal.
  # Maps are addressed by their bpffs pin, never by numeric id:
  # freed maps drain asynchronously, so ids can name dying maps.
  bpftool map lookup pinned "$1" key "$2" 0 0 0 | python3 -c "import sys; print(int.from_bytes(bytes(int(tok, 16) for tok in sys.stdin.read().split('value:')[1].splitlines()[0].split()), 'little'))"
}

u64_bytes() {
  python3 -c "print(' '.join('%d' % b for b in ($1).to_bytes(8, 'little')))"
}

map_set_u64() {
  # map_set_u64 <pinned-map> <key> <value>: write one u64 entry.
  bpftool map update pinned "$1" key "$2" 0 0 0 value $(u64_bytes "$3")
}

link_count() {
  # link_count <listing>: the number of link entries. Each entry
  # spans a header line ("1: perf_event ...") plus indented detail
  # lines, so only headers count (0 when the listing is empty).
  printf '%s' "$1" | grep -c "^[0-9][0-9]*: " || true
}

assert_owned_alive() {
  # assert_owned_alive <pid> <label> <name>: the owned-signal gate.
  # The caller passes only pids this script spawned ($!); the gate
  # additionally requires the pid to be live, non-zombie, and still
  # running the expected binary, so a foreign or recycled pid is
  # never signalled. Fails loudly instead of signalling.
  local PID="$1"; local LABEL="$2"; local NAME="$3"
  local STATE; local CMDLINE
  kill -0 "$PID" 2>/dev/null || { echo "$LABEL-NOT-ALIVE pid=$PID"; exit 1; }
  STATE=$(awk '{print $3}' /proc/"$PID"/stat 2>/dev/null) || { echo "$LABEL-STAT-GONE pid=$PID"; exit 1; }
  [ "$STATE" != "Z" ] || { echo "$LABEL-ZOMBIE pid=$PID"; exit 1; }
  CMDLINE=$(tr '\0' ' ' </proc/"$PID"/cmdline 2>/dev/null) || { echo "$LABEL-CMDLINE-GONE pid=$PID"; exit 1; }
  case "$CMDLINE" in *"$NAME"*) ;; *) echo "$LABEL-FOREIGN-PID pid=$PID cmdline=$CMDLINE"; exit 1;; esac
  echo "$LABEL-target: pid=$PID state=$STATE cmdline=$CMDLINE"
}

residue_diff() {
  # residue_diff <label>: the four BPF listings must return to the
  # run-start baseline exactly. Freed programs and maps drain
  # asynchronously, so the comparison waits for the baseline to
  # return (bounded, fails loudly) instead of asserting instantly.
  local LABEL="$1"
  local PINS_NOW; local LINKS_NOW; local PROGS_NOW; local MAPS_NOW
  for _ in $(seq 1 600); do
    PINS_NOW=$(ls /sys/fs/bpf/)
    LINKS_NOW=$(bpftool link show)
    PROGS_NOW=$(bpftool prog show)
    MAPS_NOW=$(map_show_filtered)
    [ "$PINS_NOW" = "$PINS_BEFORE" ] && [ "$LINKS_NOW" = "$LINKS_BEFORE" ] && [ "$PROGS_NOW" = "$PROGS_BEFORE" ] && [ "$MAPS_NOW" = "$MAPS_BEFORE" ] && break
    sleep 0.1
  done
  [ "$PINS_NOW" = "$PINS_BEFORE" ] || { echo "$LABEL-STRAY-PINS"; echo "$PINS_NOW"; exit 1; }
  [ "$LINKS_NOW" = "$LINKS_BEFORE" ] || { echo "$LABEL-STRAY-LINKS"; echo "$LINKS_NOW"; exit 1; }
  [ "$PROGS_NOW" = "$PROGS_BEFORE" ] || { echo "$LABEL-STRAY-PROGS"; echo "$PROGS_NOW"; exit 1; }
  [ "$MAPS_NOW" = "$MAPS_BEFORE" ] || { echo "$LABEL-STRAY-MAPS"; echo "$MAPS_NOW"; exit 1; }
  echo "$LABEL-residue: clean"
}

wait_links() {
  # wait_links <label> <want-count>: poll until the link count
  # equals <want-count> (bounded, fails loudly). Link teardown
  # after a kill is asynchronous; creation is synchronous.
  local LABEL="$1"; local WANT="$2"; local GOT
  for _ in $(seq 1 600); do
    GOT=$(link_count "$(bpftool link show)")
    [ "$GOT" = "$WANT" ] && break
    sleep 0.1
  done
  echo "$LABEL-links: $GOT (want $WANT)"
  [ "$GOT" = "$WANT" ] || { echo "$LABEL-LINK-COUNT-MISMATCH"; exit 1; }
}

echo "--- attach failure A1: bad pin path ---"
./tracepoint_attach /sys/fs/bpf/no_such_prog_for_lifecycle syscalls sys_enter_getpid </dev/null >/tmp/lc-a1.log 2>&1
A1_EXIT=$?
echo "a1-holder: $(cat /tmp/lc-a1.log)"
echo "a1-exit: $A1_EXIT"
grep -q "^OBJGET " /tmp/lc-a1.log || { echo "A1-MARKER-MISSING"; exit 1; }
[ "$A1_EXIT" = "1" ] || { echo "A1-EXIT-MISMATCH"; exit 1; }
residue_diff a1

echo "--- attach failure A2: missing event ---"
bpftool prog load counter.bpf.o /sys/fs/bpf/lc_a2 type tracepoint >/tmp/lc-a2.load 2>&1
[ $? = 0 ] || { echo "A2-LOAD-FAILED"; cat /tmp/lc-a2.load; exit 1; }
./tracepoint_attach /sys/fs/bpf/lc_a2 syscalls sys_enter_no_such_event </dev/null >/tmp/lc-a2.log 2>&1
A2_EXIT=$?
echo "a2-holder: $(cat /tmp/lc-a2.log)"
echo "a2-exit: $A2_EXIT"
grep -q "^IDFAIL syscalls:sys_enter_no_such_event$" /tmp/lc-a2.log || { echo "A2-MARKER-MISSING"; exit 1; }
[ "$A2_EXIT" = "1" ] || { echo "A2-EXIT-MISMATCH"; exit 1; }
rm -f /sys/fs/bpf/lc_a2
residue_diff a2

echo "--- attach failure A3: type-mismatched program ---"
bpftool prog load xdp.bpf.o /sys/fs/bpf/lc_a3 type xdp >/tmp/lc-a3.load 2>&1
[ $? = 0 ] || { echo "A3-LOAD-FAILED"; cat /tmp/lc-a3.load; exit 1; }
./tracepoint_attach /sys/fs/bpf/lc_a3 syscalls sys_enter_getpid </dev/null >/tmp/lc-a3.log 2>&1
A3_EXIT=$?
echo "a3-holder: $(cat /tmp/lc-a3.log)"
echo "a3-exit: $A3_EXIT"
grep -q "^LINKCREATE .* errno=22 " /tmp/lc-a3.log || { echo "A3-MARKER-MISSING"; exit 1; }
[ "$A3_EXIT" = "1" ] || { echo "A3-EXIT-MISMATCH"; exit 1; }
rm -f /sys/fs/bpf/lc_a3
residue_diff a3

echo "--- attach failure A4: duplicate attachment ---"
bpftool prog load counter.bpf.o /sys/fs/bpf/lc_a4 type tracepoint >/tmp/lc-a4.load 2>&1
[ $? = 0 ] || { echo "A4-LOAD-FAILED"; cat /tmp/lc-a4.load; exit 1; }
LINKS_A4_0=$(bpftool link show)
rm -f a4-rel
mkfifo a4-rel
./tracepoint_attach /sys/fs/bpf/lc_a4 syscalls sys_enter_getpid <a4-rel >/tmp/lc-a4-first.log 2>&1 &
A4_FIRST=$!
exec 8<>a4-rel
for _ in $(seq 1 600); do grep -q "^ATTACHED " /tmp/lc-a4-first.log 2>/dev/null && break; kill -0 "$A4_FIRST" 2>/dev/null || break; sleep 0.1; done
grep -q "^ATTACHED " /tmp/lc-a4-first.log || { echo "A4-FIRST-ATTACH-TIMEOUT"; cat /tmp/lc-a4-first.log; exit 1; }
cat /tmp/lc-a4-first.log
./tracepoint_attach /sys/fs/bpf/lc_a4 syscalls sys_enter_getpid </dev/null >/tmp/lc-a4.log 2>&1
A4_EXIT=$?
echo "a4-holder: $(cat /tmp/lc-a4.log)"
echo "a4-exit: $A4_EXIT"
grep -q "^LINKCREATE .* errno=17 " /tmp/lc-a4.log || { echo "A4-MARKER-MISSING"; exit 1; }
[ "$A4_EXIT" = "1" ] || { echo "A4-EXIT-MISMATCH"; exit 1; }
LINKS_A4_1=$(bpftool link show)
N0=$(link_count "$LINKS_A4_0"); N1=$(link_count "$LINKS_A4_1")
echo "a4-links-during: $N0->$N1"
[ "$N1" = "$((N0 + 1))" ] || { echo "A4-LINK-COUNT-MISMATCH"; exit 1; }
exec 8>&-
wait "$A4_FIRST"
[ $? = 0 ] || { echo "A4-FIRST-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/lc-a4-first.log || { echo "A4-FIRST-DETACH-MARKER-MISSING"; exit 1; }
rm -f /sys/fs/bpf/lc_a4 a4-rel
residue_diff a4
echo "attach failures: classified"

run_counter_phase() {
  # run_counter_phase <label> <monitored-N> <excluded-M>: one full
  # counter run under one attachment with link-lifecycle asserts.
  # Prints <label> lines; fails loudly.
  local LABEL="$1"; local MON_N="$2"; local EXC_M="$3"
  local PIN; local MAP_DIR; local MAP_PIN
  local LINKS_L0; local N0; local N1
  local HOLDER_PID; local WL_PID
  local MON_TID; local OBS_TID; local FILTER_READ
  local DONE_LINE; local WL_EXIT; local COUNT; local HOLDER_EXIT
  PIN="/sys/fs/bpf/lc_$LABEL"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || { echo "$LABEL-MAPDIR-FAILED"; exit 1; }
  bpftool prog load counter.bpf.o "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/lc-$LABEL.load" 2>&1
  [ $? = 0 ] || { echo "$LABEL-LOAD-FAILED"; cat "/tmp/lc-$LABEL.load"; exit 1; }
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  [ -e "$MAP_PIN" ] || { echo "$LABEL-MAP-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }
  LINKS_L0=$(bpftool link show)
  N0=$(link_count "$LINKS_L0")
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  mkfifo "$LABEL-rel" "$LABEL-go" "$LABEL-done"
  ./tracepoint_attach "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/lc-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$MON_N" --excluded "$EXC_M" --phase full --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/lc-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/lc-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/lc-$LABEL.holder.log" || { echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/lc-$LABEL.holder.log"; exit 1; }
  [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] || { echo "$LABEL-TID-TIMEOUT"; cat "$LABEL-tids" 2>/dev/null; cat "/tmp/lc-$LABEL.wl.log"; exit 1; }
  N1=$(link_count "$(bpftool link show)")
  echo "$LABEL-links-during: $N0->$N1"
  [ "$N1" = "$((N0 + 1))" ] || { echo "$LABEL-LINK-COUNT-MISMATCH"; exit 1; }
  MON_TID=$(awk '$1=="monitored"{print $2}' "$LABEL-tids")
  OBS_TID=$(awk '$1=="observer"{print $2}' "$LABEL-tids")
  echo "$LABEL-tids: $(tr '\n' ';' < "$LABEL-tids")"
  [ "$MON_TID" != "$OBS_TID" ] || { echo "$LABEL-OBSERVER-NOT-OUTSIDE"; exit 1; }
  map_set_u64 "$MAP_PIN" 0 "$MON_TID" || { echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 1 0 || { echo "$LABEL-COUNT-INIT-FAILED"; exit 1; }
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "$LABEL-filter: want=$MON_TID readback=$FILTER_READ"
  [ "$FILTER_READ" = "$MON_TID" ] || { echo "$LABEL-FILTER-READBACK-MISMATCH"; exit 1; }
  timeout 60 bash -c "echo go > $LABEL-go" || { echo "$LABEL-GO-TIMEOUT"; exit 1; }
  DONE_LINE=$(timeout 300 cat "$LABEL-done") || { echo "$LABEL-DONE-TIMEOUT"; exit 1; }
  echo "$LABEL-done: $DONE_LINE"
  wait "$WL_PID"
  WL_EXIT=$?
  echo "$LABEL-workload-exit: $WL_EXIT"
  [ "$WL_EXIT" = "0" ] || { echo "$LABEL-WORKLOAD-FAILED"; cat "/tmp/lc-$LABEL.wl.log"; exit 1; }
  COUNT=$(map_u64 "$MAP_PIN" 1)
  echo "$LABEL-counter: $COUNT"
  exec 8>&-
  wait "$HOLDER_PID"
  HOLDER_EXIT=$?
  echo "$LABEL-holder-exit: $HOLDER_EXIT"
  [ "$HOLDER_EXIT" = "0" ] || { echo "$LABEL-DETACH-FAILED"; exit 1; }
  grep -q "^DETACHED$" "/tmp/lc-$LABEL.holder.log" || { echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }
  wait_links "$LABEL-after" "$N0"
  rm -f "$PIN" "$MAP_PIN"
  rmdir "$MAP_DIR" || { echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
}

echo "--- process exit B: exact run, clean detach ---"
run_counter_phase exit "$EXIT_N" "$EXIT_M"
residue_diff exit
echo "process exit: proven"

run_holder_kill() {
  # run_holder_kill <label> <signal> <want-exit>: attach, release a
  # large workload, wait for the first counted event (the mid-run
  # proof), assert the holder is an owned live process, signal it,
  # then prove the link is gone while the workload completes and
  # the counter froze strictly between 0 and N.
  local LABEL="$1"; local SIG="$2"; local WANT_EXIT="$3"
  local PIN; local MAP_DIR; local MAP_PIN
  local LINKS_L0; local N0
  local HOLDER_PID; local WL_PID; local MON_TID
  local SIGHTED; local HOLDER_EXIT; local DONE_LINE; local COUNT
  PIN="/sys/fs/bpf/lc_$LABEL"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || { echo "$LABEL-MAPDIR-FAILED"; exit 1; }
  bpftool prog load counter.bpf.o "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/lc-$LABEL.load" 2>&1
  [ $? = 0 ] || { echo "$LABEL-LOAD-FAILED"; cat "/tmp/lc-$LABEL.load"; exit 1; }
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  LINKS_L0=$(bpftool link show)
  N0=$(link_count "$LINKS_L0")
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  mkfifo "$LABEL-rel" "$LABEL-go" "$LABEL-done"
  ./tracepoint_attach "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/lc-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$KILL_N" --excluded "$KILL_M" --phase full --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/lc-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/lc-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/lc-$LABEL.holder.log" || { echo "$LABEL-ATTACH-TIMEOUT"; exit 1; }
  MON_TID=$(awk '$1=="monitored"{print $2}' "$LABEL-tids")
  echo "$LABEL-tids: $(tr '\n' ';' < "$LABEL-tids")"
  map_set_u64 "$MAP_PIN" 0 "$MON_TID" || { echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 1 0 || { echo "$LABEL-COUNT-INIT-FAILED"; exit 1; }
  timeout 60 bash -c "echo go > $LABEL-go" || { echo "$LABEL-GO-TIMEOUT"; exit 1; }
  SIGHTED=0
  for _ in $(seq 1 1200); do
    SIGHTED=$(map_u64 "$MAP_PIN" 1)
    [ "$SIGHTED" -gt 0 ] && break
    sleep 0.1
  done
  echo "$LABEL-sighted: $SIGHTED"
  [ "$SIGHTED" -gt 0 ] || { echo "$LABEL-NO-EVENTS"; exit 1; }
  assert_owned_alive "$HOLDER_PID" "$LABEL" "tracepoint_attach"
  assert_owned_alive "$WL_PID" "$LABEL-wl" "syscall_workload"
  kill "-$SIG" "$HOLDER_PID"
  wait "$HOLDER_PID"
  HOLDER_EXIT=$?
  echo "$LABEL-holder-exit: $HOLDER_EXIT"
  [ "$HOLDER_EXIT" = "$WANT_EXIT" ] || { echo "$LABEL-HOLDER-EXIT-MISMATCH"; exit 1; }
  grep -q "^DETACHED$" "/tmp/lc-$LABEL.holder.log" && { echo "$LABEL-UNEXPECTED-DETACH"; exit 1; }
  echo "$LABEL-detached-marker: absent (killed)"
  wait_links "$LABEL-after" "$N0"
  DONE_LINE=$(timeout 300 cat "$LABEL-done") || { echo "$LABEL-DONE-TIMEOUT"; exit 1; }
  echo "$LABEL-done: $DONE_LINE"
  wait "$WL_PID"
  [ $? = "0" ] || { echo "$LABEL-WORKLOAD-FAILED"; exit 1; }
  COUNT=$(map_u64 "$MAP_PIN" 1)
  echo "$LABEL-counter: $COUNT"
  [ "$COUNT" -gt 0 ] || { echo "$LABEL-COUNTER-EMPTY"; exit 1; }
  [ "$COUNT" -lt "$KILL_N" ] || { echo "$LABEL-COUNTER-NOT-FROZEN"; exit 1; }
  exec 8>&-
  rm -f "$PIN" "$MAP_PIN"
  rmdir "$MAP_DIR" || { echo "$LABEL-MAPDIR-NOT-EMPTY"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  residue_diff "$LABEL"
}

echo "--- interruption C1: SIGTERM the holder mid-run ---"
run_holder_kill c1 TERM 143
echo "--- interruption C2: SIGKILL the holder mid-run ---"
run_holder_kill c2 KILL 137
echo "holder interruption: proven"

echo "--- interruption C3: SIGKILL the workload before release ---"
PIN="/sys/fs/bpf/lc_c3"
MAP_DIR="$PIN-maps"
mkdir -p "$MAP_DIR" || { echo "C3-MAPDIR-FAILED"; exit 1; }
bpftool prog load counter.bpf.o "$PIN" type tracepoint pinmaps "$MAP_DIR/" >/tmp/lc-c3.load 2>&1
[ $? = 0 ] || { echo "C3-LOAD-FAILED"; cat /tmp/lc-c3.load; exit 1; }
MAP_PIN="$MAP_DIR/mojobpf_map0"
LINKS_C3_0=$(bpftool link show)
N0=$(link_count "$LINKS_C3_0")
rm -f c3-rel c3-go c3-done c3-tids
mkfifo c3-rel c3-go c3-done
./tracepoint_attach "$PIN" syscalls sys_enter_getpid <c3-rel >/tmp/lc-c3.holder.log 2>&1 &
C3_HOLDER=$!
exec 8<>c3-rel
./syscall_workload --monitored "$KILL_N" --excluded "$KILL_M" --phase full --tid-file c3-tids --go-fifo c3-go --done-fifo c3-done >/tmp/lc-c3.wl.log 2>&1 &
C3_WL=$!
for _ in $(seq 1 600); do
  grep -q "^ATTACHED " /tmp/lc-c3.holder.log 2>/dev/null && [ -f c3-tids ] && [ "$(wc -l < c3-tids)" = "4" ] && break
  kill -0 "$C3_HOLDER" 2>/dev/null || break
  kill -0 "$C3_WL" 2>/dev/null || break
  sleep 0.1
done
grep -q "^ATTACHED " /tmp/lc-c3.holder.log || { echo "C3-ATTACH-TIMEOUT"; exit 1; }
MON_TID=$(awk '$1=="monitored"{print $2}' c3-tids)
echo "c3-tids: $(tr '\n' ';' < c3-tids)"
map_set_u64 "$MAP_PIN" 0 "$MON_TID" || { echo "C3-FILTER-INIT-FAILED"; exit 1; }
map_set_u64 "$MAP_PIN" 1 0 || { echo "C3-COUNT-INIT-FAILED"; exit 1; }
assert_owned_alive "$C3_WL" "c3" "syscall_workload"
kill -KILL "$C3_WL"
wait "$C3_WL"
C3_WL_EXIT=$?
echo "c3-workload-exit: $C3_WL_EXIT"
[ "$C3_WL_EXIT" = "137" ] || { echo "C3-WORKLOAD-EXIT-MISMATCH"; exit 1; }
if timeout 10 cat c3-done >/tmp/lc-c3.done 2>&1; then echo "C3-UNEXPECTED-DONE: $(cat /tmp/lc-c3.done)"; exit 1; fi
echo "c3-done: missing (interrupted)"
C3_COUNT=$(map_u64 "$MAP_PIN" 1)
echo "c3-counter: $C3_COUNT"
[ "$C3_COUNT" = "0" ] || { echo "C3-COUNTER-NONZERO"; exit 1; }
exec 8>&-
wait "$C3_HOLDER"
[ $? = "0" ] || { echo "C3-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/lc-c3.holder.log || { echo "C3-DETACH-MARKER-MISSING"; exit 1; }
echo "c3-holder-exit: 0"
wait_links "c3-after" "$N0"
rm -f "$PIN" "$MAP_PIN"
rmdir "$MAP_DIR" || { echo "C3-MAPDIR-NOT-EMPTY"; exit 1; }
rm -f c3-rel c3-go c3-done c3-tids
residue_diff c3

echo "--- interruption C4: SIGKILL the workload mid-run ---"
PIN="/sys/fs/bpf/lc_c4"
MAP_DIR="$PIN-maps"
mkdir -p "$MAP_DIR" || { echo "C4-MAPDIR-FAILED"; exit 1; }
bpftool prog load counter.bpf.o "$PIN" type tracepoint pinmaps "$MAP_DIR/" >/tmp/lc-c4.load 2>&1
[ $? = 0 ] || { echo "C4-LOAD-FAILED"; cat /tmp/lc-c4.load; exit 1; }
MAP_PIN="$MAP_DIR/mojobpf_map0"
LINKS_C4_0=$(bpftool link show)
N0=$(link_count "$LINKS_C4_0")
rm -f c4-rel c4-go c4-done c4-tids
mkfifo c4-rel c4-go c4-done
./tracepoint_attach "$PIN" syscalls sys_enter_getpid <c4-rel >/tmp/lc-c4.holder.log 2>&1 &
C4_HOLDER=$!
exec 8<>c4-rel
./syscall_workload --monitored "$KILL_N" --excluded "$KILL_M" --phase full --tid-file c4-tids --go-fifo c4-go --done-fifo c4-done >/tmp/lc-c4.wl.log 2>&1 &
C4_WL=$!
for _ in $(seq 1 600); do
  grep -q "^ATTACHED " /tmp/lc-c4.holder.log 2>/dev/null && [ -f c4-tids ] && [ "$(wc -l < c4-tids)" = "4" ] && break
  kill -0 "$C4_HOLDER" 2>/dev/null || break
  kill -0 "$C4_WL" 2>/dev/null || break
  sleep 0.1
done
grep -q "^ATTACHED " /tmp/lc-c4.holder.log || { echo "C4-ATTACH-TIMEOUT"; exit 1; }
MON_TID=$(awk '$1=="monitored"{print $2}' c4-tids)
echo "c4-tids: $(tr '\n' ';' < c4-tids)"
map_set_u64 "$MAP_PIN" 0 "$MON_TID" || { echo "C4-FILTER-INIT-FAILED"; exit 1; }
map_set_u64 "$MAP_PIN" 1 0 || { echo "C4-COUNT-INIT-FAILED"; exit 1; }
timeout 60 bash -c "echo go > c4-go" || { echo "C4-GO-TIMEOUT"; exit 1; }
SIGHTED=0
for _ in $(seq 1 1200); do
  SIGHTED=$(map_u64 "$MAP_PIN" 1)
  [ "$SIGHTED" -gt 0 ] && break
  sleep 0.1
done
echo "c4-sighted: $SIGHTED"
[ "$SIGHTED" -gt 0 ] || { echo "C4-NO-EVENTS"; exit 1; }
assert_owned_alive "$C4_WL" "c4" "syscall_workload"
kill -KILL "$C4_WL"
wait "$C4_WL"
C4_WL_EXIT=$?
echo "c4-workload-exit: $C4_WL_EXIT"
[ "$C4_WL_EXIT" = "137" ] || { echo "C4-WORKLOAD-EXIT-MISMATCH"; exit 1; }
if timeout 10 cat c4-done >/tmp/lc-c4.done 2>&1; then echo "C4-UNEXPECTED-DONE: $(cat /tmp/lc-c4.done)"; exit 1; fi
echo "c4-done: missing (interrupted)"
C4_FIRST=$(map_u64 "$MAP_PIN" 1)
C4_SECOND=$(map_u64 "$MAP_PIN" 1)
echo "c4-counter: $C4_FIRST (reread $C4_SECOND)"
[ "$C4_FIRST" = "$C4_SECOND" ] || { echo "C4-COUNTER-NOT-FROZEN"; exit 1; }
[ "$C4_FIRST" -gt 0 ] || { echo "C4-COUNTER-EMPTY"; exit 1; }
[ "$C4_FIRST" -lt "$KILL_N" ] || { echo "C4-COUNTER-OVERFLOW"; exit 1; }
exec 8>&-
wait "$C4_HOLDER"
[ $? = "0" ] || { echo "C4-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/lc-c4.holder.log || { echo "C4-DETACH-MARKER-MISSING"; exit 1; }
echo "c4-holder-exit: 0"
wait_links "c4-after" "$N0"
rm -f "$PIN" "$MAP_PIN"
rmdir "$MAP_DIR" || { echo "C4-MAPDIR-NOT-EMPTY"; exit 1; }
rm -f c4-rel c4-go c4-done c4-tids
residue_diff c4
echo "workload interruption: proven"

echo "--- repeated runs D: counter cycles ---"
for i in $(seq 1 "$REPEAT_CYCLES"); do
  run_counter_phase "rep$i" "$MINI_N" "$MINI_M"
done
residue_diff rep
echo "counter repeats: $REPEAT_CYCLES cycles clean"

run_emitter_phase() {
  # run_emitter_phase <label>: one emitter run under one attachment
  # with exact producer accounting (attempted/successful/failed).
  # Each cycle loads a fresh ring, so no drain is needed.
  local LABEL="$1"
  local PIN; local MAP_DIR; local MAP_PIN; local RING_PIN
  local HOLDER_PID; local WL_PID; local MON_TID; local FILTER_READ
  local DONE_LINE; local ATTEMPTED; local SUCCESSFUL; local FAILED
  PIN="/sys/fs/bpf/lc_$LABEL"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || { echo "$LABEL-MAPDIR-FAILED"; exit 1; }
  bpftool prog load emitter.bpf.o "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/lc-$LABEL.load" 2>&1
  [ $? = 0 ] || { echo "$LABEL-LOAD-FAILED"; cat "/tmp/lc-$LABEL.load"; exit 1; }
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  RING_PIN="$MAP_DIR/mojobpf_map1"
  [ -e "$MAP_PIN" ] || { echo "$LABEL-MAP-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }
  [ -e "$RING_PIN" ] || { echo "$LABEL-RING-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  mkfifo "$LABEL-rel" "$LABEL-go" "$LABEL-done"
  ./tracepoint_attach "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/lc-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$MINI_N" --excluded "$MINI_M" --phase full --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/lc-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/lc-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/lc-$LABEL.holder.log" || { echo "$LABEL-ATTACH-TIMEOUT"; exit 1; }
  [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] || { echo "$LABEL-TID-TIMEOUT"; exit 1; }
  MON_TID=$(awk '$1=="monitored"{print $2}' "$LABEL-tids")
  echo "$LABEL-tids: $(tr '\n' ';' < "$LABEL-tids")"
  map_set_u64 "$MAP_PIN" 0 "$MON_TID" || { echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 1 0 || { echo "$LABEL-SEQ-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 2 0 || { echo "$LABEL-OK-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 3 0 || { echo "$LABEL-ERR-INIT-FAILED"; exit 1; }
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "$LABEL-filter: want=$MON_TID readback=$FILTER_READ"
  [ "$FILTER_READ" = "$MON_TID" ] || { echo "$LABEL-FILTER-READBACK-MISMATCH"; exit 1; }
  timeout 60 bash -c "echo go > $LABEL-go" || { echo "$LABEL-GO-TIMEOUT"; exit 1; }
  DONE_LINE=$(timeout 300 cat "$LABEL-done") || { echo "$LABEL-DONE-TIMEOUT"; exit 1; }
  echo "$LABEL-done: $DONE_LINE"
  wait "$WL_PID"
  [ $? = "0" ] || { echo "$LABEL-WORKLOAD-FAILED"; exit 1; }
  ATTEMPTED=$(map_u64 "$MAP_PIN" 1)
  SUCCESSFUL=$(map_u64 "$MAP_PIN" 2)
  FAILED=$(map_u64 "$MAP_PIN" 3)
  echo "$LABEL-accounting: attempted=$ATTEMPTED successful=$SUCCESSFUL failed=$FAILED"
  exec 8>&-
  wait "$HOLDER_PID"
  [ $? = "0" ] || { echo "$LABEL-DETACH-FAILED"; exit 1; }
  grep -q "^DETACHED$" "/tmp/lc-$LABEL.holder.log" || { echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }
  rm -f "$PIN" "$MAP_PIN" "$RING_PIN"
  rmdir "$MAP_DIR" || { echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
}

echo "--- repeated runs E: emitter cycles ---"
for i in $(seq 1 "$EMITTER_CYCLES"); do
  run_emitter_phase "ev$i"
done
residue_diff ev
echo "emitter repeats: $EMITTER_CYCLES cycles clean"

echo "--- owned-resource accounting ---"
FDS_AFTER=$(ls /proc/$$/fd | wc -l)
MOUNTS_AFTER=$(mount | grep "type bpf" || true)
echo "fds-after: $FDS_AFTER (before $FDS_BEFORE)"
[ "$FDS_AFTER" = "$FDS_BEFORE" ] || { echo "FD-LEAK"; ls -la /proc/$$/fd; exit 1; }
echo "mounts-after: $MOUNTS_AFTER"
[ "$MOUNTS_AFTER" = "$MOUNTS_BEFORE" ] || { echo "MOUNT-DRIFT"; exit 1; }
JOBS_LEFT=$(jobs -p || true)
echo "jobs-left: $JOBS_LEFT"
[ -z "$JOBS_LEFT" ] || { echo "UNREAPED-JOBS"; exit 1; }
STRAGGLERS=""
for proc in /proc/[0-9]*; do
  if tr '\0' ' ' <"$proc/cmdline" 2>/dev/null | grep -q "syscall_workloa[d]\|tracepoint_attac[h]"; then
    STRAGGLERS="$STRAGGLERS $proc"
  fi
done
echo "stragglers:$STRAGGLERS"
[ -z "$STRAGGLERS" ] || { echo "CHILD-STRAGGLERS"; exit 1; }
echo "owned resources: accounted"
residue_diff final
echo "cleanup: proven"
echo "=== end tracing-lifecycle ==="
"""


_RESULT = None
_FAILSAFE = {}
_STAGE = None


def executed():
    """Boot one guest and run every phase; cache the transcript."""
    global _RESULT, _STAGE
    if _RESULT is not None:
        return _RESULT
    fix = fixture()
    release = vng_release()
    stage = guest_proc.owned_stage(prefix="mojo-lifecycle-", dir="/tmp")
    staged_script = os.path.join(stage, "guest_lifecycle.sh")
    script = (
        GUEST_SCRIPT.replace("__STAGE__", stage)
        .replace("__EXIT_N__", str(EXIT_N))
        .replace("__EXIT_M__", str(EXIT_M))
        .replace("__KILL_N__", str(KILL_N))
        .replace("__KILL_M__", str(KILL_M))
        .replace("__MINI_N__", str(MINI_N))
        .replace("__MINI_M__", str(MINI_M))
        .replace("__REPEAT_CYCLES__", str(REPEAT_CYCLES))
        .replace("__EMITTER_CYCLES__", str(EMITTER_CYCLES))
        .replace("__COUNTER_HASH__", COUNTER_OBJECT_HASH)
        .replace("__EMITTER_HASH__", EMITTER_OBJECT_HASH)
        .replace("__XDP_HASH__", XDP_OBJECT_HASH)
    )
    with open(staged_script, "w", encoding="utf-8") as handle:
        handle.write(script)
    for source, name in (
        (fix["counter"], "counter.bpf.o"),
        (fix["emitter"], "emitter.bpf.o"),
        (fix["xdp"], "xdp.bpf.o"),
        (fix["workload"], "syscall_workload"),
        (fix["holder"], "tracepoint_attach"),
    ):
        guest_proc.copy_consumed(source, os.path.join(stage, name))
    os.chmod(stage, 0o755)
    for name in (
        "guest_lifecycle.sh", "counter.bpf.o", "emitter.bpf.o",
        "xdp.bpf.o",
    ):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "syscall_workload"), 0o755)
    os.chmod(os.path.join(stage, "tracepoint_attach"), 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the provenance case
    # compares guest-reported hashes against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        ("guest_lifecycle.sh", "counter.bpf.o", "emitter.bpf.o",
         "xdp.bpf.o", "syscall_workload", "tracepoint_attach"),
    )
    try:
        returncode, output = run_guest(
            ["vng", "--run", release, "--disable-kvm",
             "--exec", "bash %s" % staged_script],
            stage,
            GUEST_TIMEOUT,
        )
    except ProofFailure as exc:
        raise ProofFailure(
            "guest %s: %s; stage %s" % (release, exc, stage)
        )
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=(),
        progress_banner="=== begin tracing-lifecycle ===",
    )
    if verdict == "proof":
        raise ProofFailure(
            "guest %s failed with proof evidence (exit %d); "
            "stage %s\n%s"
            % (release, returncode, stage, output[-6000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "guest %s failed (exit %d); stage %s\n%s"
            % (release, returncode, stage, output[-6000:])
        )
    for marker in ("=== end tracing-lifecycle ===", "cleanup: proven"):
        if marker not in output:
            raise guest_proc.GuestMissing(
                "guest %s transcript incomplete; stage %s\n%s"
                % (release, stage, output[-6000:])
            )
    try:
        kernel = lane_lock.booted_kernel_from_output(output)
        lane_lock.check_booted_kernel(kernel, REPO_ROOT, release)
    except lane_lock.LaneLockError as exc:
        raise ProofFailure(str(exc))
    _RESULT = output
    _STAGE = stage
    return _RESULT


def test_guest_provenance():
    output = executed()
    stage = _STAGE
    assert stage is not None, "guest stage must be preserved"
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(output)
    for name in (
        "guest_lifecycle.sh",
        "counter.bpf.o",
        "emitter.bpf.o",
        "xdp.bpf.o",
        "syscall_workload",
        "tracepoint_attach",
    ):
        if rec is None:
            # No attestation context (standalone/pytest run):
            # fall back to the legacy post-hoc comparison.
            expected = sha256_file(os.path.join(stage, name))
            assert expected in output, (
                "guest must re-verify staged hash of %s" % name
            )
            continue
        expected = rec.consumed_staged_digest(name, stage)
        assert expected is not None, (
            "staged bytes missing for %s" % name
        )
        assert reported.get(name) == expected, (
            "guest must report the consumed bytes of %s" % name
        )
    print("PASS guest reported the consumed closure bytes")


def phase_lines(output, label):
    """Parse one phase's ``<label>-<key>: <value>`` lines."""
    found = {}
    prefix = label + "-"
    for line in output.splitlines():
        if not line.startswith(prefix):
            continue
        key, _, value = line[len(prefix):].partition(": ")
        found[key] = value.strip()
    return found


def require_keys(found, label, keys):
    for key in keys:
        if key not in found:
            raise ProofFailure(
                "phase %s is missing %s (saw %s)"
                % (label, key, sorted(found))
            )


def assert_link_delta(field, where):
    """Assert a ``N0->N1`` line shows exactly one added link."""
    before, arrow, after = field.partition("->")
    assert arrow == "->", (where, field)
    assert after.isdigit() and before.isdigit(), (where, field)
    assert int(after) == int(before) + 1, (where, field)
    return int(before)


def assert_links_settled(field, where):
    """Assert a ``GOT (want WANT)`` line shows the settled count."""
    match = re.fullmatch(r"(\d+) \(want (\d+)\)", field)
    assert match is not None, (where, field)
    assert int(match.group(1)) == int(match.group(2)), (where, field)
    return int(match.group(1))


def phase_tids(tids_field):
    pairs = {}
    for chunk in tids_field.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        role, _, tid = chunk.partition(" ")
        pairs[role.strip()] = tid.strip()
    if set(pairs) != {"monitored", "excl1", "excl2", "observer"}:
        raise ProofFailure("TID roles incomplete: %r" % (pairs,))
    if len(set(pairs.values())) != 4:
        raise ProofFailure("TIDs not distinct: %r" % (pairs,))
    return pairs


def assert_midrun_frozen(counter_field, kill_n=KILL_N):
    """Assert a killed-mid-run counter froze strictly between 0 and N.

    Shared by the workload-interruption oracle and its
    completed-workload control: a frozen counter equal to N proves the
    workload finished every call (it can stay alive afterwards,
    blocked opening the completion FIFO), so only 0 < frozen < N
    establishes a mid-run kill.
    """
    frozen, _, reread = counter_field.partition(" (reread ")
    assert reread.endswith(")"), counter_field
    reread = reread[:-1]
    assert frozen == reread, (
        "counter must freeze after the kill: %r" % counter_field
    )
    assert 0 < int(frozen) < kill_n, counter_field
    return int(frozen)


def test_attach_failures_classified():
    output = executed()
    expectations = (
        ("a1", "OBJGET ", "1"),
        ("a2", "IDFAIL syscalls:sys_enter_no_such_event", "1"),
        ("a3", "LINKCREATE ", "1"),
        ("a4", "LINKCREATE ", "1"),
    )
    for label, marker, exit_code in expectations:
        found = phase_lines(output, label)
        require_keys(found, label, ("holder", "exit", "residue"))
        assert found["holder"].startswith(marker), (
            "%s holder line %r must start with %r"
            % (label, found["holder"], marker)
        )
        assert found["exit"] == exit_code, (
            "%s exit %r must be %s" % (label, found["exit"], exit_code)
        )
        assert found["residue"] == "clean", (label, found["residue"])
    a3 = phase_lines(output, "a3")
    assert "errno=22" in a3["holder"], a3["holder"]
    a4 = phase_lines(output, "a4")
    assert "errno=17" in a4["holder"], a4["holder"]
    require_keys(a4, "a4", ("links-during",))
    assert_link_delta(a4["links-during"], "a4")
    assert "attach failures: classified" in output
    print(
        "PASS attach failures: OBJGET/IDFAIL/LINKCREATE-22/"
        "LINKCREATE-17, exit 1, no residue"
    )


def test_process_exit_exact():
    output = executed()
    found = phase_lines(output, "exit")
    require_keys(
        found, "exit",
        ("tids", "filter", "done", "counter", "workload-exit",
         "holder-exit", "links-during", "residue"),
    )
    tids = phase_tids(found["tids"])
    assert tids["monitored"] != tids["observer"]
    assert found["filter"] == "want=%s readback=%s" % (
        tids["monitored"], tids["monitored"],
    ), found["filter"]
    assert found["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d" % (EXIT_N, EXIT_M, EXIT_M)
    ), found["done"]
    assert found["counter"] == str(EXIT_N), (
        "expected exactly %d, observed %s" % (EXIT_N, found["counter"])
    )
    assert found["workload-exit"] == "0", found["workload-exit"]
    assert found["holder-exit"] == "0", found["holder-exit"]
    base = assert_link_delta(found["links-during"], "exit")
    after = phase_lines(output, "exit-after")
    require_keys(after, "exit-after", ("links",))
    assert assert_links_settled(after["links"], "exit-after") == base
    assert found["residue"] == "clean", found["residue"]
    assert "process exit: proven" in output
    print(
        "PASS process exit: exact %d, workload 0, holder 0, "
        "link 0->1->0" % EXIT_N
    )


def test_holder_interruption():
    output = executed()
    for label, want_exit in (("c1", "143"), ("c2", "137")):
        found = phase_lines(output, label)
        require_keys(
            found, label,
            ("tids", "sighted", "target", "holder-exit",
             "detached-marker", "done", "counter", "residue"),
        )
        tids = phase_tids(found["tids"])
        assert found["sighted"] != "0", (label, found["sighted"])
        assert int(found["sighted"]) > 0
        assert "tracepoint_attach" in found["target"], found["target"]
        assert found["holder-exit"] == want_exit, (
            "%s holder exit %r must be %s"
            % (label, found["holder-exit"], want_exit)
        )
        assert found["detached-marker"] == "absent (killed)"
        assert found["done"] == (
            "DONE monitored=%d excl1=%d excl2=%d"
            % (KILL_N, KILL_M, KILL_M)
        ), found["done"]
        counter = int(found["counter"])
        assert 0 < counter < KILL_N, (
            "%s counter %d must freeze strictly between 0 and %d"
            % (label, counter, KILL_N)
        )
        after = phase_lines(output, "%s-after" % label)
        require_keys(after, label, ("links",))
        assert_links_settled(after["links"], "%s-after" % label)
        wl_gate = phase_lines(output, "%s-wl" % label)
        require_keys(wl_gate, label, ("target",))
        assert "syscall_workload" in wl_gate["target"]
        assert found["residue"] == "clean", found["residue"]
    assert "holder interruption: proven" in output
    print(
        "PASS holder interruption: SIGTERM->143/SIGKILL->137, "
        "workload completes, 0 < counter < N, link gone"
    )


def test_workload_interruption():
    output = executed()
    c3 = phase_lines(output, "c3")
    require_keys(
        c3, "c3",
        ("tids", "target", "workload-exit", "done", "counter",
         "holder-exit", "residue"),
    )
    phase_tids(c3["tids"])
    assert "syscall_workload" in c3["target"], c3["target"]
    assert c3["workload-exit"] == "137", c3["workload-exit"]
    assert c3["done"] == "missing (interrupted)", c3["done"]
    assert c3["counter"] == "0", c3["counter"]
    assert c3["holder-exit"] == "0", c3["holder-exit"]
    after3 = phase_lines(output, "c3-after")
    require_keys(after3, "c3-after", ("links",))
    assert_links_settled(after3["links"], "c3-after")
    assert c3["residue"] == "clean", c3["residue"]
    c4 = phase_lines(output, "c4")
    require_keys(
        c4, "c4",
        ("tids", "sighted", "target", "workload-exit", "done",
         "counter", "holder-exit", "residue"),
    )
    phase_tids(c4["tids"])
    assert int(c4["sighted"]) > 0
    assert "syscall_workload" in c4["target"], c4["target"]
    assert c4["workload-exit"] == "137", c4["workload-exit"]
    assert c4["done"] == "missing (interrupted)", c4["done"]
    assert_midrun_frozen(c4["counter"])
    assert c4["holder-exit"] == "0", c4["holder-exit"]
    after4 = phase_lines(output, "c4-after")
    require_keys(after4, "c4-after", ("links",))
    assert_links_settled(after4["links"], "c4-after")
    assert c4["residue"] == "clean", c4["residue"]
    assert "workload interruption: proven" in output
    print(
        "PASS workload interruption: pre-release 137 + counter 0, "
        "mid-run 137 + 0 < frozen < N, detach clean"
    )


def test_midrun_oracle_rejects_completed_workload():
    """Control: the mid-run oracle rejects completed-workload transcripts.

    Host-only (no guest): a frozen counter equal to KILL_N must fail
    even with matching rereads, since a workload that finished every
    call can stay alive afterwards, blocked opening the completion
    FIFO. The guest layer pins the same strict bound.
    """
    for bad in (
        "%d (reread %d)" % (KILL_N, KILL_N),
        "%d (reread %d)" % (KILL_N + 1, KILL_N + 1),
        "0 (reread 0)",
        "10 (reread 11)",
        "mid-run",
    ):
        try:
            assert_midrun_frozen(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError(
                "transcript %r must fail the mid-run oracle" % (bad,)
            )
    assert assert_midrun_frozen("266329 (reread 266329)") == 266329
    assert '[ "$C4_FIRST" -lt "$KILL_N" ]' in GUEST_SCRIPT
    assert '"$C4_FIRST" -le ' not in GUEST_SCRIPT
    print(
        "PASS mid-run control: completed/empty transcripts rejected, "
        "guest layer pins the strict bound"
    )


_FAKE_SLEEPER = """\
import os
import subprocess
import sys
import time
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(300)"]
)
with open(os.environ["MOJOBPF_FAKE_PIDFILE"], "w") as handle:
    handle.write(str(child.pid))
print("MOJOBPF-PARTIAL-MARKER", flush=True)
time.sleep(300)
"""


def _pid_dead(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as handle:
            state = handle.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return True
    return state in ("Z", "X")


def test_runner_cancels_owned_group_on_timeout():
    """Control: the direct runner kills its group on timeout.

    Host-only (no guest): a fake sleeper with a grandchild is
    run through the same ``run_guest`` helper the guest boot
    uses; the timeout must kill the whole owned group (child
    and grandchild) instead of orphaning it.
    """
    scratch = tempfile.mkdtemp(prefix="mojo-lifecycle-cancel-")
    pidfile = os.path.join(scratch, "grandchild.pid")
    sleeper = os.path.join(scratch, "sleeper.py")
    with open(sleeper, "w", encoding="utf-8") as handle:
        handle.write(_FAKE_SLEEPER)
    saved = os.environ.get("MOJOBPF_FAKE_PIDFILE")
    os.environ["MOJOBPF_FAKE_PIDFILE"] = pidfile
    try:
        try:
            run_guest([sys.executable, sleeper], scratch, 5)
        except EnvironmentFailure as exc:
            assert "timed out after 5s" in str(exc), exc
            assert "killed and reaped" in str(exc), exc
            assert "MOJOBPF-PARTIAL-MARKER" in str(exc), exc
        else:
            raise AssertionError("the sleeper must time out")
        with open(pidfile, "r", encoding="utf-8") as handle:
            grandchild = int(handle.read().strip())
        deadline = time.monotonic() + 15
        while not _pid_dead(grandchild):
            assert time.monotonic() < deadline, (
                "grandchild %d survived the runner timeout"
                % grandchild
            )
            time.sleep(0.2)
    finally:
        if saved is None:
            os.environ.pop("MOJOBPF_FAKE_PIDFILE", None)
        else:
            os.environ["MOJOBPF_FAKE_PIDFILE"] = saved
        shutil.rmtree(scratch, ignore_errors=True)
    print(
        "PASS cancellation: runner timeout kills the owned group"
    )


_FAKE_MATRIX_GRANDCHILD = """\
import time
time.sleep(300)
"""


_FAKE_MATRIX_SLEEPER = """\
import os
import subprocess
import sys
import time
child = subprocess.Popen(
    [sys.executable, os.environ["MOJOBPF_FAKE_GRANDCHILD"]]
)
with open(os.environ["MOJOBPF_FAKE_PIDFILE"], "w") as handle:
    handle.write("%d %d" % (os.getpid(), child.pid))
time.sleep(300)
"""


_FAKE_MATRIX_SUITE = """\
import importlib.util
import os
import sys
spec = importlib.util.spec_from_file_location(
    "probe_target_suite", %(suite)r
)
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
target.run_guest(
    [sys.executable, %(sleeper)r], %(stagedir)r, 300
)
"""


def _load_matrix_runner():
    spec = importlib.util.spec_from_file_location(
        "matrix_runner",
        os.path.join(REPO_ROOT, "ci", "run_vm_tests.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _kill_owned_pid(pid, marker):
    """SIGKILL one probe-owned pid after a command-line recheck.

    The pid was recorded from a child this probe spawned; the
    recheck keeps a recycled pid from signalling a foreign
    process. Best-effort: missing processes are already gone.
    """
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            cmdline = handle.read().decode("utf-8", "replace")
    except OSError:
        return
    if marker not in cmdline:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + 15
    while not _pid_dead(pid) and time.monotonic() < deadline:
        time.sleep(0.2)


def test_matrix_timeout_reaps_detached_guest():
    """Control: a matrix timeout reaps the suite's detached guest.

    Host-only (no guest): a fake suite boots a sleeper through
    this suite's real ``run_guest`` (new session, own group) and
    the real matrix ``run_suite`` times the suite out; the
    sleeper and its grandchild must not survive (a bare
    suite-group kill would orphan the detached guest).
    """
    matrix = _load_matrix_runner()
    scratch = tempfile.mkdtemp(prefix="mojo-lifecycle-matrix-")
    pidfile = os.path.join(scratch, "tree.pid")
    grandchild = os.path.join(scratch, "grandchild.py")
    sleeper = os.path.join(scratch, "sleeper.py")
    fakesuite = os.path.join(scratch, "fake_suite.py")
    with open(grandchild, "w", encoding="utf-8") as handle:
        handle.write(_FAKE_MATRIX_GRANDCHILD)
    with open(sleeper, "w", encoding="utf-8") as handle:
        handle.write(_FAKE_MATRIX_SLEEPER)
    with open(fakesuite, "w", encoding="utf-8") as handle:
        handle.write(
            _FAKE_MATRIX_SUITE
            % {
                "suite": os.path.abspath(__file__),
                "sleeper": sleeper,
                "stagedir": scratch,
            }
        )
    saved_pidfile = os.environ.get("MOJOBPF_FAKE_PIDFILE")
    saved_grandchild = os.environ.get("MOJOBPF_FAKE_GRANDCHILD")
    os.environ["MOJOBPF_FAKE_PIDFILE"] = pidfile
    os.environ["MOJOBPF_FAKE_GRANDCHILD"] = grandchild
    # run_suite admits only suite ids with a pinned case list;
    # register the probe id test-locally (removed afterwards)
    # so this control reaches the timeout path it probes. The
    # pinned production table is untouched, and the timeout
    # path never judges output against the registered cases.
    matrix.SUITE_CASES["probe-fake"] = ["probe-timeout-case"]
    try:
        record = matrix.run_suite(
            "probe-fake", fakesuite,
            {"id": "probe", "release": "v6.12",
             "kernel_release": "6.12.0-061200-generic"},
            scratch, 5, "probe", [],
        )
        assert record["timed_out"] is True, record
        assert record["outcome"] == "timeout", record
        with open(record["log"], "r", encoding="utf-8") as handle:
            assert "MATRIX TIMEOUT after 5s" in handle.read()
        with open(pidfile, "r", encoding="utf-8") as handle:
            owned = [int(pid) for pid in handle.read().split()]
        assert len(owned) == 2, owned
        deadline = time.monotonic() + 15
        for pid in owned:
            while not _pid_dead(pid):
                assert time.monotonic() < deadline, (
                    "owned process %d survived the matrix timeout"
                    % pid
                )
                time.sleep(0.2)
    finally:
        matrix.SUITE_CASES.pop("probe-fake", None)
        try:
            with open(pidfile, "r", encoding="utf-8") as handle:
                survivors = [
                    int(pid) for pid in handle.read().split()
                ]
        except (OSError, ValueError):
            survivors = []
        for pid in survivors:
            _kill_owned_pid(pid, scratch)
        if saved_pidfile is None:
            os.environ.pop("MOJOBPF_FAKE_PIDFILE", None)
        else:
            os.environ["MOJOBPF_FAKE_PIDFILE"] = saved_pidfile
        if saved_grandchild is None:
            os.environ.pop("MOJOBPF_FAKE_GRANDCHILD", None)
        else:
            os.environ["MOJOBPF_FAKE_GRANDCHILD"] = saved_grandchild
        shutil.rmtree(scratch, ignore_errors=True)
    print(
        "PASS matrix composition: suite timeout reaps the "
        "detached guest tree"
    )


def test_repeated_runs_cleanup():
    output = executed()
    for index in range(1, REPEAT_CYCLES + 1):
        label = "rep%d" % index
        found = phase_lines(output, label)
        require_keys(
            found, label,
            ("tids", "filter", "done", "counter", "workload-exit",
             "holder-exit", "links-during"),
        )
        tids = phase_tids(found["tids"])
        assert found["done"] == (
            "DONE monitored=%d excl1=%d excl2=%d"
            % (MINI_N, MINI_M, MINI_M)
        ), (label, found["done"])
        assert found["counter"] == str(MINI_N), (
            "%s counter %s must be exactly %d"
            % (label, found["counter"], MINI_N)
        )
        assert found["workload-exit"] == "0"
        assert found["holder-exit"] == "0"
        assert_link_delta(found["links-during"], label)
    assert (
        "counter repeats: %d cycles clean" % REPEAT_CYCLES
    ) in output
    for index in range(1, EMITTER_CYCLES + 1):
        label = "ev%d" % index
        found = phase_lines(output, label)
        require_keys(
            found, label, ("tids", "filter", "done", "accounting")
        )
        tids = phase_tids(found["tids"])
        assert found["filter"] == "want=%s readback=%s" % (
            tids["monitored"], tids["monitored"],
        ), (label, found["filter"])
        assert found["done"] == (
            "DONE monitored=%d excl1=%d excl2=%d"
            % (MINI_N, MINI_M, MINI_M)
        ), (label, found["done"])
        assert found["accounting"] == (
            "attempted=%d successful=%d failed=0" % (MINI_N, MINI_N)
        ), (label, found["accounting"])
    assert (
        "emitter repeats: %d cycles clean" % EMITTER_CYCLES
    ) in output
    for label in ("rep", "ev", "final"):
        found = phase_lines(output, label)
        require_keys(found, label, ("residue",))
        assert found["residue"] == "clean", (label, found["residue"])
    assert "fds-after:" in output and "fds-before:" in output
    fds_after = [
        line for line in output.splitlines()
        if line.startswith("fds-after:")
    ][0]
    before = fds_after.split("(before")[1].rstrip(")").strip()
    after = fds_after.split("fds-after:")[1].split("(")[0].strip()
    assert after == before, fds_after
    mounts_before = [
        line for line in output.splitlines()
        if line.startswith("mounts-before:")
    ][0]
    mounts_after = [
        line for line in output.splitlines()
        if line.startswith("mounts-after:")
    ][0]
    assert mounts_after.split("mounts-after:")[1] == mounts_before.split(
        "mounts-before:"
    )[1], (mounts_before, mounts_after)
    jobs = [
        line for line in output.splitlines()
        if line.startswith("jobs-left:")
    ][0]
    assert jobs.split("jobs-left:")[1].strip() == "", jobs
    stragglers = [
        line for line in output.splitlines()
        if line.startswith("stragglers:")
    ][0]
    assert stragglers.split("stragglers:")[1].strip() == "", stragglers
    assert "owned resources: accounted" in output
    assert "cleanup: proven" in output
    print(
        "PASS repeated runs: %dx%d + %d emitter cycles exact, "
        "FDs/mounts/children clean"
        % (REPEAT_CYCLES, MINI_N, EMITTER_CYCLES)
    )


def verify_record(request):
    """Run one fail-safe verification; map setup faults to environment."""
    try:
        return run_verification(request)
    except VerifyError as exc:
        raise EnvironmentFailure(str(exc))


def assert_no_never_tokens(commands, where):
    for command in commands:
        for token in _FORBIDDEN_GUEST_TOKENS:
            assert token not in command, (
                "%s: guest command carries forbidden %r: %r"
                % (where, token, command)
            )


def assert_guest_lane(record, where):
    release = vng_release()
    kernel = (record.get("guest") or {}).get("kernel") or ""
    assert kernel.startswith(release[1:] + "."), (
        "%s: guest kernel %r does not match lane %s"
        % (where, kernel, release)
    )
    return kernel


def test_failsafe_negative_controls():
    """Host-only: fail-safe validation rejects hostile names outright.

    No guest boots here: a regex-shaped map name, a traversal-shaped
    trace selector, and trailing-newline variants must fail closed at
    request validation, so they can never reach a probe or a load.
    """
    for bad_map in (
        "a..ay",
        "array|ringbuf",
        "../array",
        "array\n",
    ):
        try:
            VerifyRequest(object_path="never.o", map_types=(bad_map,))
        except VerifyError:
            pass
        else:
            raise AssertionError(
                "map type %r must fail validation" % (bad_map,)
            )
    for bad_event in (
        "syscalls:../syscalls/sys_enter_getpid",
        "syscalls:..",
        "syscalls:sys_enter_getpid\n",
        "syscalls:sys_enter_getpid\ninjected=1",
    ):
        try:
            VerifyRequest(object_path="never.o", trace_event=bad_event)
        except VerifyError:
            pass
        else:
            raise AssertionError(
                "trace event %r must fail validation" % (bad_event,)
            )
    print(
        "PASS fail-safe negatives: regex/traversal/newline names "
        "rejected without a probe"
    )


def test_failsafe_map_preflight():
    fix = fixture()
    release = vng_release()
    unknown = verify_record(
        VerifyRequest(
            object_path=fix["counter"],
            release=release,
            prog_type="tracepoint",
            map_types=(UNKNOWN_MAP,),
        )
    )
    assert unknown["status"] == "unavailable", unknown["status"]
    assert unknown["stage"] == "preflight", unknown["stage"]
    assert unknown["classification"] == "environment"
    assert unknown["preflight"]["unavailable_reason"] == (
        "unsupported-map-type"
    ), unknown["preflight"]
    assert unknown["load"]["attempted"] is False, unknown["load"]
    assert unknown["guest"]["map_types_supported"] == {
        UNKNOWN_MAP: None,
    }, unknown["guest"]
    probe = unknown["guest"]["map_probe_lines"][UNKNOWN_MAP] or ""
    assert probe == "", unknown["guest"]
    section = unknown["guest"]["map_type_section"] or ""
    assert section != "", unknown["guest"]
    assert UNKNOWN_MAP not in section, unknown["guest"]
    assert_guest_lane(unknown, "unknown map refusal")
    assert_no_never_tokens(unknown["guest_commands"], "unknown map refusal")
    _FAILSAFE["uniform-map"] = (
        "lane %s: --map-type %s -> unavailable/"
        "unsupported-map-type, no load (unknown name, no probe line)"
        % (release, UNKNOWN_MAP)
    )
    print("PASS fail-safe maps: unknown-name refusal")


def test_failsafe_arena_lane_verdict():
    fix = fixture()
    release = vng_release()
    want_split = SPLIT_MAP_LANE.get(release)
    if want_split is None:
        raise EnvironmentFailure(
            "pin the %s verdict for release %s with evidence; "
            "refusing to guess" % (SPLIT_MAP, release)
        )
    split = verify_record(
        VerifyRequest(
            object_path=fix["counter"],
            release=release,
            prog_type="tracepoint",
            map_types=(SPLIT_MAP,),
        )
    )
    split_probe = (
        split["guest"]["map_probe_lines"].get(SPLIT_MAP) or ""
    )
    split_section = split["guest"]["map_type_section"] or ""
    assert split_section != "", split["guest"]
    assert SPLIT_MAP in split_section, split["guest"]
    if want_split:
        assert split["status"] == "pass", (
            split["status"], split.get("note"),
        )
        assert split["stage"] == "done", split["stage"]
        assert split["guest"]["map_types_supported"] == {
            SPLIT_MAP: True,
        }, split["guest"]
        assert "is available" in split_probe, split["guest"]
        assert split["load"]["attempted"] is True
        assert split["load"]["exit"] == 0
        assert split["unload"]["pin_absent"] is True
        _FAILSAFE["split-map"] = (
            "lane %s: --map-type %s -> pass (%s)"
            % (release, SPLIT_MAP, split_probe)
        )
    else:
        assert split["status"] == "unavailable", split["status"]
        assert split["stage"] == "preflight", split["stage"]
        assert split["preflight"]["unavailable_reason"] == (
            "unsupported-map-type"
        ), split["preflight"]
        assert split["load"]["attempted"] is False, split["load"]
        assert split["guest"]["map_types_supported"] == {
            SPLIT_MAP: False,
        }, split["guest"]
        assert "NOT available" in split_probe, split["guest"]
        _FAILSAFE["split-map"] = (
            "lane %s: --map-type %s -> unavailable/"
            "unsupported-map-type, no load (%s)"
            % (release, SPLIT_MAP, split_probe)
        )
    assert_guest_lane(split, "split map verdict")
    assert_no_never_tokens(split["guest_commands"], "split map verdict")
    print(
        "PASS fail-safe maps: per-lane %s verdict "
        "(%s)" % (SPLIT_MAP, "pass" if want_split else "refused")
    )


def test_failsafe_event_preflight():
    fix = fixture()
    release = vng_release()
    full = verify_record(
        VerifyRequest(
            object_path=fix["emitter"],
            release=release,
            prog_type="tracepoint",
            map_types=("array", "ringbuf"),
            trace_event=TRACE_EVENT,
        )
    )
    assert full["status"] == "pass", (full["status"], full.get("note"))
    assert full["stage"] == "done", full["stage"]
    assert full["classification"] is None
    assert full["guest"]["map_types_supported"] == {
        "array": True, "ringbuf": True,
    }, full["guest"]
    for name in ("array", "ringbuf"):
        probe = full["guest"]["map_probe_lines"][name] or ""
        assert "is available" in probe, full["guest"]
    assert full["guest"]["trace_event_supported"] is True, full["guest"]
    trace_id = full["guest"]["trace_event_id"] or ""
    assert trace_id.endswith(
        "syscalls/%s/id" % TRACE_EVENT.split(":")[1]
    ), full["guest"]
    assert full["load"]["attempted"] is True
    assert full["load"]["exit"] == 0
    assert full["unload"]["pin_absent"] is True
    assert full["unload"]["quiesced"] is True
    assert_guest_lane(full, "full event preflight")
    assert_no_never_tokens(full["guest_commands"], "full event preflight")
    _FAILSAFE["full-event"] = (
        "lane %s: full event preflight -> pass (trace id %s)"
        % (release, trace_id)
    )
    bogus = verify_record(
        VerifyRequest(
            object_path=fix["counter"],
            release=release,
            prog_type="tracepoint",
            trace_event=BOGUS_EVENT,
        )
    )
    assert bogus["status"] == "unavailable", bogus["status"]
    assert bogus["stage"] == "preflight", bogus["stage"]
    assert bogus["classification"] == "environment"
    assert bogus["preflight"]["unavailable_reason"] == (
        "unsupported-trace-event"
    ), bogus["preflight"]
    assert bogus["load"]["attempted"] is False, bogus["load"]
    assert bogus["guest"]["trace_event_supported"] is False, bogus["guest"]
    assert bogus["guest"]["trace_event_id"] is None, bogus["guest"]
    assert_guest_lane(bogus, "bogus event refusal")
    assert_no_never_tokens(bogus["guest_commands"], "bogus event refusal")
    _FAILSAFE["bogus-event"] = (
        "lane %s: --trace-event %s -> unavailable/"
        "unsupported-trace-event, no load" % (release, BOGUS_EVENT)
    )
    print(
        "PASS fail-safe events: full preflight passes, bogus event "
        "refused with no load"
    )


def guest_kernel(output):
    """Guest kernel release from the transcript (lane identity)."""
    for line in output.splitlines():
        if line.startswith("guest-kernel:"):
            return line.split("guest-kernel:")[1].strip()
    raise ProofFailure("guest transcript has no kernel line")


def print_board(output):
    """Print the per-phase observation board from the transcript."""
    release = vng_release()
    print("guest: %s kernel %s" % (release, guest_kernel(output)))
    print(
        "staged objects: counter=%s emitter=%s xdp=%s"
        % (
            COUNTER_OBJECT_HASH[:16],
            EMITTER_OBJECT_HASH[:16],
            XDP_OBJECT_HASH[:16],
        )
    )
    print(
        "staged sources: workload=%s holder=%s"
        % (
            sha256_file(WORKLOAD_SOURCE)[:16],
            sha256_file(HOLDER_SOURCE)[:16],
        )
    )
    for label in ("a1", "a2", "a3", "a4"):
        found = phase_lines(output, label)
        print(
            "board %s: holder=[%s] exit=%s residue=%s"
            % (
                label,
                found.get("holder", "?"),
                found.get("exit", "?"),
                found.get("residue", "?"),
            )
        )
    for label in ["exit"] + [
        "rep%d" % index for index in range(1, REPEAT_CYCLES + 1)
    ]:
        found = phase_lines(output, label)
        print(
            "board %s: counter=%s done=[%s] filter=[%s] tids=[%s]"
            % (
                label,
                found.get("counter", "?"),
                found.get("done", "?"),
                found.get("filter", "?"),
                found.get("tids", "?"),
            )
        )
    for label in ("c1", "c2"):
        found = phase_lines(output, label)
        print(
            "board %s: holder-exit=%s sighted=%s counter=%s "
            "done=[%s] tids=[%s] target=[%s] residue=%s"
            % (
                label,
                found.get("holder-exit", "?"),
                found.get("sighted", "?"),
                found.get("counter", "?"),
                found.get("done", "?"),
                found.get("tids", "?"),
                found.get("target", "?"),
                found.get("residue", "?"),
            )
        )
    for label in ("c3", "c4"):
        found = phase_lines(output, label)
        print(
            "board %s: workload-exit=%s counter=%s holder-exit=%s "
            "tids=[%s] target=[%s] residue=%s"
            % (
                label,
                found.get("workload-exit", "?"),
                found.get("counter", "?"),
                found.get("holder-exit", "?"),
                found.get("tids", "?"),
                found.get("target", "?"),
                found.get("residue", "?"),
            )
        )
    for line in output.splitlines():
        if line.startswith(("fds-before:", "fds-after:")):
            print("board %s" % line)
        elif line.startswith(("mounts-before:", "mounts-after:")):
            print("board %s" % line)
    for index in range(1, EMITTER_CYCLES + 1):
        label = "ev%d" % index
        found = phase_lines(output, label)
        print(
            "board %s: accounting=[%s] done=[%s] tids=[%s]"
            % (
                label,
                found.get("accounting", "?"),
                found.get("done", "?"),
                found.get("tids", "?"),
            )
        )
    for key in ("uniform-map", "split-map", "full-event", "bogus-event"):
        print("board failsafe %s: %s" % (key, _FAILSAFE.get(key, "not run")))


CASE_NAMES = (
    "test_attach_failures_classified",
    "test_process_exit_exact",
    "test_holder_interruption",
    "test_workload_interruption",
    "test_midrun_oracle_rejects_completed_workload",
    "test_runner_cancels_owned_group_on_timeout",
    "test_matrix_timeout_reaps_detached_guest",
    "test_repeated_runs_cleanup",
    "test_failsafe_negative_controls",
    "test_failsafe_map_preflight",
    "test_failsafe_arena_lane_verdict",
    "test_failsafe_event_preflight",
    "test_guest_provenance",
)

# No denials: every case asserts exact guest behavior positively
# (the failure-path cases pass by observing their classified
# holder outcomes).
CASE_DENIALS = {}

_VERIFY_SOURCE = os.path.join(
    REPO_ROOT, "src", "mojobpf", "verify.py"
)
_MATRIX_RUNNER = os.path.join(REPO_ROOT, "ci", "run_vm_tests.py")


# Durable inputs per case. executed() preserves the guest stage
# (_STAGE) and hands the closure off before any begin_case, so
# every transcript consumer declares the staged bytes it ran on
# (staged mirrors of its absolute sources); the
# COUNTER/EMITTER/XDP_OBJECT_HASH pins asserted at build time
# commit the same bytes independently. Host-only controls pin
# the in-suite machinery (__file__) and repo modules they
# exercise.
CASE_INPUTS = {
    "test_attach_failures_classified": {
        "sources": [COUNTER_SOURCE, XDP_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_lifecycle.sh")],
        "objects": [("stage", "counter.bpf.o"),
                    ("stage", "xdp.bpf.o"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_process_exit_exact": {
        "sources": [COUNTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_lifecycle.sh")],
        "objects": [("stage", "counter.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_holder_interruption": {
        "sources": [COUNTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_lifecycle.sh")],
        "objects": [("stage", "counter.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_workload_interruption": {
        "sources": [COUNTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_lifecycle.sh")],
        "objects": [("stage", "counter.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_midrun_oracle_rejects_completed_workload": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_runner_cancels_owned_group_on_timeout": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_matrix_timeout_reaps_detached_guest": {
        "sources": [("impl", __file__), ("impl", _MATRIX_RUNNER)],
        "objects": [],
        "corpus": [],
    },
    "test_repeated_runs_cleanup": {
        "sources": [
            COUNTER_SOURCE, EMITTER_SOURCE, WORKLOAD_SOURCE,
            HOLDER_SOURCE,
            ("stage", "guest_lifecycle.sh"),
        ],
        "objects": [("stage", "counter.bpf.o"),
                    ("stage", "emitter.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [
            COUNTER_SOURCE, EMITTER_SOURCE, XDP_SOURCE,
            WORKLOAD_SOURCE, HOLDER_SOURCE,
            ("stage", "guest_lifecycle.sh"),
        ],
        "objects": [("stage", "counter.bpf.o"),
                    ("stage", "emitter.bpf.o"),
                    ("stage", "xdp.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_failsafe_negative_controls": {
        "sources": [("impl", _VERIFY_SOURCE)],
        "objects": [],
        "corpus": [],
    },
    "test_failsafe_map_preflight": {
        "sources": [COUNTER_SOURCE, ("impl", _VERIFY_SOURCE)],
        "objects": [],
        "corpus": [],
    },
    "test_failsafe_arena_lane_verdict": {
        "sources": [COUNTER_SOURCE, ("impl", _VERIFY_SOURCE)],
        "objects": [],
        "corpus": [],
    },
    "test_failsafe_event_preflight": {
        "sources": [EMITTER_SOURCE, COUNTER_SOURCE, ("impl", _VERIFY_SOURCE)],
        "objects": [],
        "corpus": [],
    },
    "board": {
        "sources": [],
        "objects": [],
        "corpus": [],
    },
}


def _finish(rec, unavailable_seen=False):
    """Attach the guest transcript and finish the typed suite."""
    try:
        output = executed()
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        ProofFailure, AssertionError,
        subprocess.TimeoutExpired,
    ):
        code = rec.finish(
            stage_dir=_STAGE, unavailable_seen=unavailable_seen
        )
        guest_proc.discard_owned_stages()
        return code
    rec.note_transcript("guest", output)
    code = rec.finish(
        stage_dir=_STAGE, unavailable_seen=unavailable_seen
    )
    guest_proc.discard_owned_stages()
    return code


def main():
    try:
        release = vng_release()
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE in lane: %s" % exc)
        rec = guest_proc.SuiteRecorder(
            suite_id="kernel-tracing-lifecycle", suite_path=__file__,
            case_ids=list(CASE_NAMES) + ["board"],
            denials=CASE_DENIALS, inputs=CASE_INPUTS,
            lane_release="v6.12")
        # The lane is invalid, so nothing can run; the nominal
        # default lane lets the refusal seal a terminal record
        # (matrix runs always set a valid lane and embed the
        # matrix target instead).
        return rec.finish_unrun("invalid lane: %s" % exc)
    rec = guest_proc.SuiteRecorder(
        suite_id="kernel-tracing-lifecycle", suite_path=__file__,
        case_ids=list(CASE_NAMES) + ["board"],
        denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=release)
    # Attestation context: fixture consumption reads route
    # through this recorder from here (warmup included).
    guest_proc.set_active_recorder(rec)
    if not __debug__:
        return rec.finish_unrun(
            "must not run under python -O (asserts stripped)"
        )
    failures = 0
    unavailable_seen = False
    # Stage before any begin_case: the begin seals must observe
    # the staged input bytes (bytes first seen after begin can
    # never back a PASS), so warm the cached run here. A warm
    # failure is ignored: each case body retries and records it
    # per case below.
    try:
        executed()
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        ProofFailure, AssertionError, subprocess.TimeoutExpired,
        guest_proc.TargetLeaseRequired,
    ):
        pass
    for name in CASE_NAMES:
        func = globals()[name]
        rec.begin_case(name)
        try:
            hint = func()
        except guest_proc.HarnessEnvironment as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, exc.stage, exc.availability)
            return _finish(rec, unavailable_seen)
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "UNKNOWN")
            return _finish(rec, unavailable_seen)
        except subprocess.TimeoutExpired as exc:
            print("ENVIRONMENT FAILURE in %s: timed out: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "TOOLCHAIN_UNAVAILABLE")
            return _finish(rec, unavailable_seen)
        except guest_proc.TargetLeaseRequired as exc:
            print("REQUIRED-UNAVAILABLE %s: %s" % (name, exc))
            rec.end_case_not_run(name, "TARGET_RESOURCE_ABSENT")
            unavailable_seen = True
        except (AssertionError, ProofFailure) as exc:
            print("FAIL %s: %s" % (name, exc))
            rec.end_case_fail(name)
            failures += 1
        else:
            print("PASS %s" % name)
            rec.end_case_hint(name, hint)
    if failures:
        return _finish(rec, unavailable_seen)
    rec.begin_case("board")
    try:
        output = executed()
        print_board(output)
    except guest_proc.HarnessEnvironment as exc:
        print("ENVIRONMENT FAILURE in board: %s" % exc)
        rec.end_case_infra("board", exc.stage, exc.availability)
        return _finish(rec, unavailable_seen)
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE in board: %s" % exc)
        rec.end_case_infra("board", "INFRA", "UNKNOWN")
        return _finish(rec, unavailable_seen)
    except subprocess.TimeoutExpired as exc:
        print("ENVIRONMENT FAILURE in board: timed out: %s" % exc)
        rec.end_case_infra("board", "INFRA", "TOOLCHAIN_UNAVAILABLE")
        return _finish(rec, unavailable_seen)
    except guest_proc.TargetLeaseRequired as exc:
        print("REQUIRED-UNAVAILABLE board: %s" % exc)
        rec.end_case_not_run("board", "TARGET_RESOURCE_ABSENT")
        return _finish(rec, True)
    except (AssertionError, ProofFailure) as exc:
        print("FAIL board: %s" % exc)
        rec.end_case_fail("board")
        return _finish(rec, unavailable_seen)
    print("PASS board")
    rec.end_case_pass("board")
    print(
        "tracing lifecycle: attach/exit/interruption/cleanup plus "
        "fail-safe preflights in %s guests" % release
    )
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
