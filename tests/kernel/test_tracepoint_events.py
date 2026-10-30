# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Fixed-record ring-buffer output proof in a disposable guest.

Builds ``examples/tracepoint_events/emitter.mojo`` (plus the small-ring
emitter and the TGID and version mutants) through the genuine pipeline
on the host, builds the independent C control producer with the pinned
``clang --target=bpf -O2 -g``, compiles the raw-syscall workload, the
tracepoint attach holder, and the ring-buffer drain tool with the host
C compiler, stages everything into one disposable virtme-ng guest, and
proves exact fixed-record event delivery on the
``syscalls:sys_enter_getpid`` event. Guest files never leave the
virtme overlay, so every drain is published over the transcript
as one hex line per frame plus a sha256 line, and the host
rebuilds the exact drained bytes (digest-verified) before the
independent decoder observes them:

* control: the filterless C producer emits its fixed pattern on every
  getpid while the drain follows concurrently; every drained record
  reproduces the pattern byte-exactly, and at least the workload's own
  calls arrive, validating the observer before measurement;
* healthy: with the filter set to the monitored TID, exactly N=3000
  monitored getpids (plus rejected excluded calls) yield
  attempted=successful=3000, failed=0, and 3000 drained records with
  contiguous per-TID sequences 0..2999, the monitored identity, and
  non-decreasing timestamps;
* saturation: with a one-page ring and a stopped consumer, M=2000
  attempts yield attempted=successful+failed with both categories
  nonempty (1 <= successful <= 102, failed > 0); after quiescence a
  single drain receives exactly the successful prefix (sequences
  0..successful-1), so received=successful;
* crash: three workload runs under one attachment with the consumer
  SIGKILLed between drains lose nothing and duplicate nothing (2500
  contiguous sequences across the three frame files), the failed
  counter stays 0 despite the kill (consumer death is not kernel
  loss), and the restarted drain resumes at the killed consumer's
  exact position (consumer offset 80000);
* TGID mutant: the shape-clean mutant comparing the thread-group ID
  attempts nothing (all counters 0, empty drain), and the reloaded
  base object still accounts exactly N=1000, proving the suite reads
  live kernel state;
* version mutant: the shape-clean mutant writing record version 2
  still produces N=1000 kernel successes the drain transports, while
  the host decoder rejects every record as unsupported-version and
  decodes none, proving the version gate on live bytes.

Protocol notes. Attachment is a single system-wide tracepoint probe
(one link), so worker migration across CPUs cannot lose events; the
workers run without CPU affinity. Every run starts its own workload
process (fresh TIDs), publishes all four TIDs (the observer runs
outside the monitored TID), sets the filter and zeroes the counters
(userspace initialization with readback), then releases the workers
over a FIFO; the workers report their executed loop counts over a
second FIFO after joining, so every counter read and one-shot drain
is quiescent by construction. The saturation phase runs with no
consumer at all; the crash phase restarts the consumer across a
SIGKILL. No fixed sleep synchronizes anything: every wait is a FIFO
rendezvous, a reaped child, or a bounded poll for an explicit
handshake marker that fails loudly on timeout. The suite cleans up
every pin, attachment, process, and FIFO it creates and asserts the
guest holds no residue afterwards.

Requires ``mojo``, ``llc``, ``cc``, ``clang``, ``bpftool`` and ``vng``
on PATH plus the pinned kernels. ``MOJOBPF_VNG_RELEASE`` selects the
guest lane (default ``v6.12``). A missing tool or lane is an
environment failure; a failing proof step is a proof failure.
Neither ever passes.

Runnable directly (``python3
tests/kernel/test_tracepoint_events.py``) or under any
``test_``-style runner. Standard library only.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
EMITTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_events", "emitter.mojo"
)
SMALL_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_events", "emitter_small.mojo"
)
TGID_MUTANT_SOURCE = os.path.join(
    REPO_ROOT,
    "examples",
    "tracepoint_events",
    "emitter_tgid_mutated.mojo",
)
V2_MUTANT_SOURCE = os.path.join(
    REPO_ROOT,
    "examples",
    "tracepoint_events",
    "emitter_v2_mutated.mojo",
)
CONTROL_SOURCE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "ringbuf_control.bpf.c"
)
CONTROL_SOURCE_REL = os.path.join(
    "tests", "reference_c", "ringbuf_control.bpf.c"
)
WORKLOAD_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "syscall_workload.c"
)
HOLDER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "tracepoint_attach.c"
)
DRAIN_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "ringbuf_drain.c"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import guest_proc  # noqa: E402
import lane_lock  # noqa: E402
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

from mojobpf.events import (  # noqa: E402
    EventCheckError,
    EventDecodeError,
    check_accounting,
    check_event_run,
    decode_event_record,
    decode_event_stream,
)

# The guest must test exactly the qualified bytes.
EMITTER_OBJECT_HASH = (
    "dbddc75dabe4198107eca403a37bfa04934932c6cfe011ca5f46ca6df67b8770"
)
SMALL_OBJECT_HASH = (
    "09be1aaef6eff3d30d8957c9edf11e8487b441c469243bf019b9a3125575920b"
)
TGID_MUTANT_HASH = (
    "e5ecb288b6a3404d0bb26c429540a7b726a0affc3681eeba6a90e47b2830e6ec"
)
V2_MUTANT_HASH = (
    "0f7d4112cb4b6e47fa076ef069de71f824b73a00d5a5b6de0bd1897686354449"
)
# The control object embeds its build paths in DWARF, so the suite
# builds it with a fixed working directory and source spelling to
# keep these bytes reproducible.
CONTROL_OBJECT_HASH = (
    "f4f3dd6196bec8d2323fbc04086aab95b34caa70b1f8a53d11fc51373b57e008"
)

CONTROL_MON = 500
CONTROL_EXC = 100
HEALTHY_N = 3000
HEALTHY_M = 1000
SAT_M = 2000
SAT_EXC = 1000
CRASH_N1 = 1000
CRASH_N2 = 1000
CRASH_N3 = 500
MUTANT_N = 1000
MUTANT_M = 1000
STALE_N = 1000
STALE_M = 1000
V2_N = 1000
V2_M = 1000
# One page holds at most floor(4096 / (8 + 32)) records.
SMALL_RING_SLOTS = 102
# Above the kernel's maximum TID: can never match a real thread.
BOGUS_TID = 0x7FFFFFFF

CONTROL_PATTERN = (
    1, 32, 0x11111111, 0x22222222, 0x33333333,
    0x4444444444444444, 0x5555555555555555,
)

GUEST_TIMEOUT = 900


class EnvironmentFailure(Exception):
    """The toolchain or lane needed by this test is missing."""


class ProofFailure(Exception):
    """A proof step failed inside the guest."""


def run_step(argv, timeout=600, cwd=None):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        cwd=cwd,
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


def clang_version():
    proc = run_step(["clang", "--version"])
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "clang --version failed (exit %d)" % proc.returncode
        )
    first = (proc.stdout or "").splitlines()
    if not first:
        raise EnvironmentFailure("clang --version printed nothing")
    return first[0].strip()


@guest_proc.consumes_source
def build_object(source, workdir, tag, want_hash):
    """Build one Mojo source; assert the qualified object bytes."""
    raw_path = os.path.join(workdir, "%s.ll" % tag)
    adapted_path = os.path.join(workdir, "%s.bpf.ll" % tag)
    object_path = os.path.join(workdir, "%s.bpf.o" % tag)
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS,
            "-I", SDK_INCLUDE, "-o", raw_path, source,
        ]
    )
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


def build_control(workdir, want_hash):
    """Build the C control producer; assert the qualified bytes.

    The control object is only reproducible under the pinned clang,
    so a version mismatch is an environment failure, never a proof
    failure. The build runs with a fixed working directory and
    source spelling because the object embeds its build paths.
    """
    with open(LOCKFILE, encoding="utf-8") as handle:
        lock = json.load(handle)
    want_version = lock["tools"]["clang"]["version"]
    observed_version = clang_version()
    if observed_version != want_version:
        raise EnvironmentFailure(
            "clang version %r does not match the pinned %r"
            % (observed_version, want_version)
        )
    object_path = os.path.join(workdir, "control.bpf.o")
    proc = guest_proc.compile_consumed(run_step,
        [
            "clang", "--target=bpf", "-O2", "-g", "-c",
            CONTROL_SOURCE_REL, "-o", object_path,
        ],
        source=CONTROL_SOURCE_REL, cwd=REPO_ROOT,
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "control build failed: exit=%d stderr=%r"
            % (proc.returncode, proc.stderr[-2000:])
        )
    observed = sha256_file(object_path)
    if observed != want_hash:
        raise ProofFailure(
            "staged control bytes %s do not match the qualified %s"
            % (observed, want_hash)
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


GUEST_SCRIPT = r"""#!/bin/bash
# Tracepoint events guest proof. Every phase loads its object
# with bpftool (the libbpf-consumability proof), attaches with
# the owned holder over a release FIFO, drives workload runs over
# go/done FIFOs, reads the producer counters quiescently, drains
# the ring, publishes the frames over the transcript, detaches,
# and unloads. Blocking waits carry timeouts that fail loudly;
# nothing here assumes a fixed sleep.
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="__STAGE__"
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin tracepoint-events ==="
echo "guest-kernel: $(uname -r)"
bpftool version | head -1
echo "ncpu: $(nproc)"
echo "--- staged hashes ---"
sha256sum emitter.bpf.o emitter_small.bpf.o tgid_mutant.bpf.o v2_mutant.bpf.o control.bpf.o syscall_workload tracepoint_attach ringbuf_drain
echo "__EMITTER_HASH__  emitter.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH emitter"; exit 1; }
echo "__SMALL_HASH__  emitter_small.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH small"; exit 1; }
echo "__TGID_HASH__  tgid_mutant.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH tgid"; exit 1; }
echo "__V2_HASH__  v2_mutant.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH v2"; exit 1; }
echo "__CONTROL_HASH__  control.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH control"; exit 1; }
echo "staged bytes: qualified"
echo "--- pins before ---"
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
echo "$PINS_BEFORE"
echo "$LINKS_BEFORE"
echo "--- namespace self-check ---"
SELF_NS=$(readlink /proc/self/ns/pid)
INIT_NS=$(readlink /proc/1/ns/pid)
echo "self-ns: $SELF_NS"
echo "init-ns: $INIT_NS"
[ "$SELF_NS" = "$INIT_NS" ] || { echo "NAMESPACE-MISMATCH"; exit 1; }
echo "namespace: initial"
rm -f ns-tids ns-go ns-done
mkfifo ns-go ns-done
unshare --pid --fork ./syscall_workload --monitored 1 --excluded 0 --phase full --tid-file ns-tids --go-fifo ns-go --done-fifo ns-done >/dev/null 2>&1
NS_EXIT=$?
echo "unshare-workload-exit: $NS_EXIT"
[ "$NS_EXIT" = "2" ] || { echo "NAMESPACE-REFUSAL-MISSING"; exit 1; }
echo "namespace refusal: proven"
rm -f ns-tids ns-go ns-done

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

publish_frames() {
  # publish_frames <label>: print <label>.frames over the
  # transcript as one hex line per 36-byte frame plus a sha256
  # line, so the host decodes exactly the drained bytes. Guest
  # files never leave the virtme overlay; only the transcript
  # crosses to the host.
  LABEL="$1"
  python3 -c "
import hashlib
blob = open('$LABEL.frames', 'rb').read()
assert len(blob) % 36 == 0, len(blob)
for i in range(0, len(blob), 36):
    print('$LABEL-frame: %s' % blob[i:i + 36].hex())
print('$LABEL-sha256: %s' % hashlib.sha256(blob).hexdigest())
" || { echo "$LABEL-PUBLISH-FAILED"; exit 1; }
}

echo "--- unavailability probe ---"
bpftool prog load emitter.bpf.o /sys/fs/bpf/ev_unavail type tracepoint >/tmp/ev-unavail.load 2>&1
[ $? = 0 ] || { echo "UNAVAIL-LOAD-FAILED"; cat /tmp/ev-unavail.load; exit 1; }
rm -f unavail-rel
mkfifo unavail-rel
./tracepoint_attach /sys/fs/bpf/ev_unavail syscalls sys_enter_no_such_event <unavail-rel >/tmp/ev-unavail.log 2>&1 &
UNAVAIL_PID=$!
exec 9<>unavail-rel
wait "$UNAVAIL_PID"
UNAVAIL_EXIT=$?
exec 9>&-
cat /tmp/ev-unavail.log
echo "unavail-holder-exit: $UNAVAIL_EXIT"
grep -q "^IDFAIL syscalls:sys_enter_no_such_event$" /tmp/ev-unavail.log || { echo "UNAVAIL-MARKER-MISSING"; exit 1; }
[ "$UNAVAIL_EXIT" = "1" ] || { echo "UNAVAIL-EXIT-MISMATCH"; exit 1; }
echo "unavailability: proven"
rm -f /sys/fs/bpf/ev_unavail unavail-rel

echo "--- real event attach check ---"
bpftool prog load emitter.bpf.o /sys/fs/bpf/ev_probe type tracepoint >/tmp/ev-probe.load 2>&1
[ $? = 0 ] || { echo "PROBE-LOAD-FAILED"; cat /tmp/ev-probe.load; exit 1; }
rm -f probe-rel
mkfifo probe-rel
./tracepoint_attach /sys/fs/bpf/ev_probe syscalls sys_enter_getpid <probe-rel >/tmp/ev-probe.log 2>&1 &
PROBE_PID=$!
exec 9<>probe-rel
for _ in $(seq 1 600); do grep -q "^ATTACHED " /tmp/ev-probe.log 2>/dev/null && break; grep -q "^IDFAIL " /tmp/ev-probe.log 2>/dev/null && break; kill -0 "$PROBE_PID" 2>/dev/null || break; sleep 0.1; done
if grep -q "^IDFAIL " /tmp/ev-probe.log; then
  echo "TRACEPOINT-MISSING: syscalls:sys_enter_getpid is unavailable in this guest"
  wait "$PROBE_PID"
  exec 9>&-
  rm -f /sys/fs/bpf/ev_probe probe-rel
  exit 3
fi
grep -q "^ATTACHED " /tmp/ev-probe.log || { echo "PROBE-ATTACH-TIMEOUT"; cat /tmp/ev-probe.log; exit 1; }
cat /tmp/ev-probe.log
exec 9>&-
wait "$PROBE_PID"
[ $? = 0 ] || { echo "PROBE-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/ev-probe.log || { echo "PROBE-DETACH-MARKER-MISSING"; exit 1; }
echo "real event: attachable"
rm -f /sys/fs/bpf/ev_probe probe-rel

run_event_phase() {
  # run_event_phase <label> <object> <pin> <monitored> <excluded>
  # One workload run under one attachment: load, pin both maps,
  # attach, publish TIDs, initialize the four state entries with
  # readback, release, join, read the counters quiescently, drain
  # once, detach, unload. Prints <label> lines; fails loudly.
  LABEL="$1"; OBJECT="$2"; PIN="$3"; MON_N="$4"; EXC_M="$5"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || { echo "$LABEL-MAPDIR-FAILED"; exit 1; }
  bpftool prog load "$OBJECT" "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/ev-$LABEL.load" 2>&1
  [ $? = 0 ] || { echo "$LABEL-LOAD-FAILED"; cat "/tmp/ev-$LABEL.load"; exit 1; }
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  RING_PIN="$MAP_DIR/mojobpf_map1"
  [ -e "$MAP_PIN" ] || { echo "$LABEL-MAP-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }
  [ -e "$RING_PIN" ] || { echo "$LABEL-RING-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }
  MAP_ID=$(bpftool -j map show pinned "$MAP_PIN" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  RING_ID=$(bpftool -j map show pinned "$RING_PIN" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  echo "$LABEL-map-id: $MAP_ID"
  echo "$LABEL-ring-id: $RING_ID"
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  mkfifo "$LABEL-rel" "$LABEL-go" "$LABEL-done"
  "./tracepoint_attach" "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/ev-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$MON_N" --excluded "$EXC_M" --phase full --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/ev-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/ev-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/ev-$LABEL.holder.log" || { echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/ev-$LABEL.holder.log"; exit 1; }
  [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] || { echo "$LABEL-TID-TIMEOUT"; cat "$LABEL-tids" 2>/dev/null; cat "/tmp/ev-$LABEL.wl.log"; exit 1; }
  MON_TID=$(awk '$1=="monitored"{print $2}' "$LABEL-tids")
  OBS_TID=$(awk '$1=="observer"{print $2}' "$LABEL-tids")
  echo "$LABEL-tids: $(tr '\n' ';' < "$LABEL-tids")"
  [ "$MON_TID" != "$OBS_TID" ] || { echo "$LABEL-OBSERVER-NOT-OUTSIDE"; exit 1; }
  map_set_u64 "$MAP_PIN" 0 "$MON_TID" || { echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 1 0 || { echo "$LABEL-SEQ-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 2 0 || { echo "$LABEL-SUCC-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 3 0 || { echo "$LABEL-FAIL-INIT-FAILED"; exit 1; }
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "$LABEL-filter: want=$MON_TID readback=$FILTER_READ"
  [ "$FILTER_READ" = "$MON_TID" ] || { echo "$LABEL-FILTER-READBACK-MISMATCH"; exit 1; }
  timeout 60 bash -c "echo go > $LABEL-go" || { echo "$LABEL-GO-TIMEOUT"; exit 1; }
  DONE_LINE=$(timeout 120 cat "$LABEL-done") || { echo "$LABEL-DONE-TIMEOUT"; exit 1; }
  echo "$LABEL-done: $DONE_LINE"
  wait "$WL_PID"
  [ $? = 0 ] || { echo "$LABEL-WORKLOAD-FAILED"; cat "/tmp/ev-$LABEL.wl.log"; exit 1; }
  ATTEMPTED=$(map_u64 "$MAP_PIN" 1)
  SUCCESSFUL=$(map_u64 "$MAP_PIN" 2)
  FAILED=$(map_u64 "$MAP_PIN" 3)
  echo "$LABEL-counters: attempted=$ATTEMPTED successful=$SUCCESSFUL failed=$FAILED"
  DRAIN_OUT=$(./ringbuf_drain --map "$RING_PIN" --out "$LABEL.frames") || { echo "$LABEL-DRAIN-FAILED"; exit 1; }
  DRAINED_N=$(echo "$DRAIN_OUT" | awk '/^DRAINED /{print $2}')
  RING_LINE=$(echo "$DRAIN_OUT" | awk '/^RING /{print $2" "$3" "$4}')
  [ -n "$DRAINED_N" ] && [ -n "$RING_LINE" ] || { echo "$LABEL-DRAIN-PARSE-FAILED: $DRAIN_OUT"; exit 1; }
  echo "$LABEL-drained: $DRAINED_N"
  echo "$LABEL-ring: $RING_LINE"
  publish_frames "$LABEL"
  exec 8>&-
  wait "$HOLDER_PID"
  [ $? = 0 ] || { echo "$LABEL-DETACH-FAILED"; exit 1; }
  grep -q "^DETACHED$" "/tmp/ev-$LABEL.holder.log" || { echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }
  rm -f "$PIN" "$MAP_PIN" "$RING_PIN"
  rmdir "$MAP_DIR" || { echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
}

run_event_phase healthy emitter.bpf.o /sys/fs/bpf/ev_healthy __HEALTHY_N__ __HEALTHY_M__
run_event_phase saturation emitter_small.bpf.o /sys/fs/bpf/ev_sat __SAT_M__ __SAT_EXC__
run_event_phase mutant tgid_mutant.bpf.o /sys/fs/bpf/ev_mutant __MUTANT_N__ __MUTANT_M__
run_event_phase stale emitter.bpf.o /sys/fs/bpf/ev_stale __STALE_N__ __STALE_M__
run_event_phase v2 v2_mutant.bpf.o /sys/fs/bpf/ev_v2 __V2_N__ __V2_M__

echo "--- control observer validation ---"
CONTROL_PIN=/sys/fs/bpf/ev_control
CONTROL_MAP_DIR="$CONTROL_PIN-maps"
mkdir -p "$CONTROL_MAP_DIR" || { echo "CONTROL-MAPDIR-FAILED"; exit 1; }
bpftool prog load control.bpf.o "$CONTROL_PIN" type tracepoint pinmaps "$CONTROL_MAP_DIR/" >/tmp/ev-control.load 2>&1
[ $? = 0 ] || { echo "CONTROL-LOAD-FAILED"; cat /tmp/ev-control.load; exit 1; }
CONTROL_RING="$CONTROL_MAP_DIR/control_ring"
[ -e "$CONTROL_RING" ] || { echo "CONTROL-RING-PIN-MISSING"; ls -la "$CONTROL_MAP_DIR"; exit 1; }
rm -f control-rel control-go control-done control-tids
mkfifo control-rel control-go control-done
"./tracepoint_attach" "$CONTROL_PIN" syscalls sys_enter_getpid <control-rel >/tmp/ev-control.holder.log 2>&1 &
CONTROL_HOLDER=$!
exec 8<>control-rel
./ringbuf_drain --map "$CONTROL_RING" --out control.frames --follow --timeout 2 --max-records 100000 >/tmp/ev-control.drain.log 2>&1 &
CONTROL_DRAIN=$!
./syscall_workload --monitored __CONTROL_MON__ --excluded __CONTROL_EXC__ --phase full --tid-file control-tids --go-fifo control-go --done-fifo control-done >/tmp/ev-control.wl.log 2>&1 &
CONTROL_WL=$!
for _ in $(seq 1 600); do
  grep -q "^ATTACHED " /tmp/ev-control.holder.log 2>/dev/null && [ -f control-tids ] && [ "$(wc -l < control-tids)" = "4" ] && break
  kill -0 "$CONTROL_HOLDER" 2>/dev/null || break
  kill -0 "$CONTROL_WL" 2>/dev/null || break
  sleep 0.1
done
grep -q "^ATTACHED " /tmp/ev-control.holder.log || { echo "CONTROL-ATTACH-TIMEOUT"; cat /tmp/ev-control.holder.log; exit 1; }
[ -f control-tids ] && [ "$(wc -l < control-tids)" = "4" ] || { echo "CONTROL-TID-TIMEOUT"; cat /tmp/ev-control.wl.log; exit 1; }
echo "control-tids: $(tr '\n' ';' < control-tids)"
timeout 60 bash -c "echo go > control-go" || { echo "CONTROL-GO-TIMEOUT"; exit 1; }
CONTROL_DONE=$(timeout 120 cat control-done) || { echo "CONTROL-DONE-TIMEOUT"; exit 1; }
echo "control-done: $CONTROL_DONE"
wait "$CONTROL_WL"
[ $? = 0 ] || { echo "CONTROL-WORKLOAD-FAILED"; cat /tmp/ev-control.wl.log; exit 1; }
# Detach first: the producer is silent from here, so the follow
# drain's idle exit is bounded by construction, not by luck.
exec 8>&-
wait "$CONTROL_HOLDER"
[ $? = 0 ] || { echo "CONTROL-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/ev-control.holder.log || { echo "CONTROL-DETACH-MARKER-MISSING"; exit 1; }
wait "$CONTROL_DRAIN"
[ $? = 0 ] || { echo "CONTROL-DRAIN-FAILED"; cat /tmp/ev-control.drain.log; exit 1; }
CONTROL_DRAINED=$(awk '/^DRAINED /{print $2}' /tmp/ev-control.drain.log | tail -1)
CONTROL_FOLLOW_SUM=$(awk '/^FOLLOW /{sum+=$2}END{print sum+0}' /tmp/ev-control.drain.log)
echo "control-drained: $CONTROL_DRAINED"
echo "control-follow-sum: $CONTROL_FOLLOW_SUM"
[ -n "$CONTROL_DRAINED" ] || { echo "CONTROL-DRAIN-PARSE-FAILED"; cat /tmp/ev-control.drain.log; exit 1; }
[ "$CONTROL_DRAINED" = "$CONTROL_FOLLOW_SUM" ] || { echo "CONTROL-FOLLOW-MISMATCH"; cat /tmp/ev-control.drain.log; exit 1; }
publish_frames control
rm -f "$CONTROL_PIN" "$CONTROL_RING"
rmdir "$CONTROL_MAP_DIR" || { echo "CONTROL-MAPDIR-NOT-EMPTY"; ls -la "$CONTROL_MAP_DIR"; exit 1; }
rm -f control-rel control-go control-done control-tids

echo "--- consumer crash phase ---"
CRASH_PIN=/sys/fs/bpf/ev_crash
CRASH_MAP_DIR="$CRASH_PIN-maps"
mkdir -p "$CRASH_MAP_DIR" || { echo "CRASH-MAPDIR-FAILED"; exit 1; }
bpftool prog load emitter.bpf.o "$CRASH_PIN" type tracepoint pinmaps "$CRASH_MAP_DIR/" >/tmp/ev-crash.load 2>&1
[ $? = 0 ] || { echo "CRASH-LOAD-FAILED"; cat /tmp/ev-crash.load; exit 1; }
CRASH_MAP="$CRASH_MAP_DIR/mojobpf_map0"
CRASH_RING="$CRASH_MAP_DIR/mojobpf_map1"
[ -e "$CRASH_MAP" ] || { echo "CRASH-MAP-PIN-MISSING"; ls -la "$CRASH_MAP_DIR"; exit 1; }
[ -e "$CRASH_RING" ] || { echo "CRASH-RING-PIN-MISSING"; ls -la "$CRASH_MAP_DIR"; exit 1; }
rm -f crash-rel
mkfifo crash-rel
"./tracepoint_attach" "$CRASH_PIN" syscalls sys_enter_getpid <crash-rel >/tmp/ev-crash.holder.log 2>&1 &
CRASH_HOLDER=$!
exec 8<>crash-rel
for _ in $(seq 1 600); do grep -q "^ATTACHED " /tmp/ev-crash.holder.log 2>/dev/null && break; kill -0 "$CRASH_HOLDER" 2>/dev/null || break; sleep 0.1; done
grep -q "^ATTACHED " /tmp/ev-crash.holder.log || { echo "CRASH-ATTACH-TIMEOUT"; cat /tmp/ev-crash.holder.log; exit 1; }
map_set_u64 "$CRASH_MAP" 0 0 || { echo "CRASH-FILTER-INIT-FAILED"; exit 1; }
map_set_u64 "$CRASH_MAP" 1 0 || { echo "CRASH-SEQ-INIT-FAILED"; exit 1; }
map_set_u64 "$CRASH_MAP" 2 0 || { echo "CRASH-SUCC-INIT-FAILED"; exit 1; }
map_set_u64 "$CRASH_MAP" 3 0 || { echo "CRASH-FAIL-INIT-FAILED"; exit 1; }

crash_run() {
  # crash_run <tag> <monitored>: one workload run under the crash
  # attachment with the filter retargeted to this run's monitored
  # TID (the sequence and outcome counters keep accumulating).
  TAG="$1"; MON_N="$2"
  rm -f "crash-$TAG-go" "crash-$TAG-done" "crash-$TAG-tids"
  mkfifo "crash-$TAG-go" "crash-$TAG-done"
  ./syscall_workload --monitored "$MON_N" --excluded 0 --phase full --tid-file "crash-$TAG-tids" --go-fifo "crash-$TAG-go" --done-fifo "crash-$TAG-done" >"/tmp/ev-crash-$TAG.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    [ -f "crash-$TAG-tids" ] && [ "$(wc -l < "crash-$TAG-tids")" = "4" ] && break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  [ -f "crash-$TAG-tids" ] && [ "$(wc -l < "crash-$TAG-tids")" = "4" ] || { echo "CRASH-$TAG-TID-TIMEOUT"; cat "/tmp/ev-crash-$TAG.wl.log"; exit 1; }
  RUN_MON=$(awk '$1=="monitored"{print $2}' "crash-$TAG-tids")
  echo "crash-$TAG-tids: $(tr '\n' ';' < "crash-$TAG-tids")"
  map_set_u64 "$CRASH_MAP" 0 "$RUN_MON" || { echo "CRASH-$TAG-FILTER-FAILED"; exit 1; }
  FILTER_READ=$(map_u64 "$CRASH_MAP" 0)
  [ "$FILTER_READ" = "$RUN_MON" ] || { echo "CRASH-$TAG-FILTER-MISMATCH"; exit 1; }
  timeout 60 bash -c "echo go > crash-$TAG-go" || { echo "CRASH-$TAG-GO-TIMEOUT"; exit 1; }
  DONE_LINE=$(timeout 120 cat "crash-$TAG-done") || { echo "CRASH-$TAG-DONE-TIMEOUT"; exit 1; }
  echo "crash-$TAG-done: $DONE_LINE"
  wait "$WL_PID"
  [ $? = 0 ] || { echo "CRASH-$TAG-WORKLOAD-FAILED"; cat "/tmp/ev-crash-$TAG.wl.log"; exit 1; }
  rm -f "crash-$TAG-go" "crash-$TAG-done" "crash-$TAG-tids"
}

crash_run run1 __CRASH_N1__
CRASH1_OUT=$(./ringbuf_drain --map "$CRASH_RING" --out crash1.frames) || { echo "CRASH-DRAIN1-FAILED"; exit 1; }
echo "crash-drained1: $(echo "$CRASH1_OUT" | awk '/^DRAINED /{print $2}')"
echo "crash-ring1: $(echo "$CRASH1_OUT" | awk '/^RING /{print $2" "$3" "$4}')"
publish_frames crash1
crash_run run2 __CRASH_N2__
./ringbuf_drain --map "$CRASH_RING" --out crash2.frames --follow --timeout 300 --max-records 100000 >/tmp/ev-crash.drain2.log 2>&1 &
CRASH_DRAIN2=$!
for _ in $(seq 1 600); do grep -q "^FOLLOW __CRASH_N2__$" /tmp/ev-crash.drain2.log 2>/dev/null && break; kill -0 "$CRASH_DRAIN2" 2>/dev/null || break; sleep 0.1; done
grep -q "^FOLLOW __CRASH_N2__$" /tmp/ev-crash.drain2.log || { echo "CRASH-DRAIN2-TIMEOUT"; cat /tmp/ev-crash.drain2.log; exit 1; }
kill -9 "$CRASH_DRAIN2"
wait "$CRASH_DRAIN2"
KILL_EXIT=$?
echo "crash-kill-exit: $KILL_EXIT"
[ "$KILL_EXIT" = "137" ] || { echo "CRASH-KILL-EXIT-MISMATCH"; exit 1; }
kill -0 "$CRASH_DRAIN2" 2>/dev/null && { echo "CRASH-DRAIN2-STILL-ALIVE"; exit 1; }
echo "crash-killed: yes"
publish_frames crash2
crash_run run3 __CRASH_N3__
CRASH3_OUT=$(./ringbuf_drain --map "$CRASH_RING" --out crash3.frames) || { echo "CRASH-DRAIN3-FAILED"; exit 1; }
echo "crash-drained3: $(echo "$CRASH3_OUT" | awk '/^DRAINED /{print $2}')"
echo "crash-ring3: $(echo "$CRASH3_OUT" | awk '/^RING /{print $2" "$3" "$4}')"
publish_frames crash3
CRASH_ATTEMPTED=$(map_u64 "$CRASH_MAP" 1)
CRASH_SUCCESSFUL=$(map_u64 "$CRASH_MAP" 2)
CRASH_FAILED=$(map_u64 "$CRASH_MAP" 3)
echo "crash-counters: attempted=$CRASH_ATTEMPTED successful=$CRASH_SUCCESSFUL failed=$CRASH_FAILED"
exec 8>&-
wait "$CRASH_HOLDER"
[ $? = 0 ] || { echo "CRASH-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/ev-crash.holder.log || { echo "CRASH-DETACH-MARKER-MISSING"; exit 1; }
rm -f "$CRASH_PIN" "$CRASH_MAP" "$CRASH_RING"
rmdir "$CRASH_MAP_DIR" || { echo "CRASH-MAPDIR-NOT-EMPTY"; ls -la "$CRASH_MAP_DIR"; exit 1; }
rm -f crash-rel

echo "--- stray check ---"
# Freed objects drain asynchronously; wait for the pre-run
# baseline to return (bounded, fails loudly) before comparing.
for _ in $(seq 1 600); do
  PINS_AFTER=$(ls /sys/fs/bpf/)
  LINKS_AFTER=$(bpftool link show)
  PROGS_AFTER=$(bpftool prog show)
  MAPS_AFTER=$(map_show_filtered)
  [ "$PINS_AFTER" = "$PINS_BEFORE" ] && [ "$LINKS_AFTER" = "$LINKS_BEFORE" ] && [ "$PROGS_AFTER" = "$PROGS_BEFORE" ] && [ "$MAPS_AFTER" = "$MAPS_BEFORE" ] && break
  sleep 0.1
done
echo "$PINS_AFTER"
echo "$LINKS_AFTER"
[ "$PINS_AFTER" = "$PINS_BEFORE" ] || { echo "STRAY-PINS"; exit 1; }
[ "$LINKS_AFTER" = "$LINKS_BEFORE" ] || { echo "STRAY-LINKS"; exit 1; }
[ "$PROGS_AFTER" = "$PROGS_BEFORE" ] || { echo "STRAY-PROGS"; exit 1; }
[ "$MAPS_AFTER" = "$MAPS_BEFORE" ] || { echo "STRAY-MAPS"; exit 1; }
echo "cleanup: proven"
echo "=== end tracepoint-events ==="
"""

_RESULT = None


def executed():
    """Boot one guest and run every phase; cache transcript+stage.

    The first outcome, success or failure, is cached: a failed
    guest run fails every test with the same evidence instead of
    rebooting once per test.
    """
    global _RESULT
    if _RESULT is not None:
        if _RESULT[0] == "ok":
            return _RESULT[1]
        raise _RESULT[1]
    try:
        _RESULT = ("ok", _execute_once())
    except (EnvironmentFailure, ProofFailure, AssertionError) as exc:
        _RESULT = ("fail", exc)
        raise
    return _RESULT[1]


def _run_guest(argv, stage, timeout, release):
    """Run the guest command; return (exit code, output text).

    Thin mapping over the shared owned runner
    (tests/harness/guest_proc.py): a timeout surfaces as
    EnvironmentFailure carrying the partial output.
    """
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "guest %s timed out after %ds; stage %s:\n%s"
            % (release, timeout, stage, exc.output[-6000:])
        )


def _execute_once():
    check_tools("mojo", "llc", "cc", "clang", "bpftool", "vng")
    for path in (
        EMITTER_SOURCE, SMALL_SOURCE, TGID_MUTANT_SOURCE,
        V2_MUTANT_SOURCE, CONTROL_SOURCE, WORKLOAD_SOURCE,
        HOLDER_SOURCE, DRAIN_SOURCE,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    release = vng_release()
    workdir = guest_proc.owned_stage(prefix="mojo-events-")
    base_obj = build_object(
        EMITTER_SOURCE, workdir, "emitter", EMITTER_OBJECT_HASH
    )
    small_obj = build_object(
        SMALL_SOURCE, workdir, "small", SMALL_OBJECT_HASH
    )
    tgid_obj = build_object(
        TGID_MUTANT_SOURCE, workdir, "tgid", TGID_MUTANT_HASH
    )
    v2_obj = build_object(
        V2_MUTANT_SOURCE, workdir, "v2", V2_MUTANT_HASH
    )
    control_obj = build_control(workdir, CONTROL_OBJECT_HASH)
    workload = build_harness(
        WORKLOAD_SOURCE, os.path.join(workdir, "syscall_workload"),
        ("-pthread",),
    )
    holder = build_harness(
        HOLDER_SOURCE, os.path.join(workdir, "tracepoint_attach")
    )
    drain = build_harness(
        DRAIN_SOURCE, os.path.join(workdir, "ringbuf_drain")
    )
    stage = guest_proc.owned_stage(prefix="mojo-events-", dir="/tmp")
    staged_script = os.path.join(stage, "guest_events.sh")
    script = (
        GUEST_SCRIPT.replace("__STAGE__", stage)
        .replace("__EMITTER_HASH__", EMITTER_OBJECT_HASH)
        .replace("__SMALL_HASH__", SMALL_OBJECT_HASH)
        .replace("__TGID_HASH__", TGID_MUTANT_HASH)
        .replace("__V2_HASH__", V2_MUTANT_HASH)
        .replace("__CONTROL_HASH__", CONTROL_OBJECT_HASH)
        .replace("__CONTROL_MON__", str(CONTROL_MON))
        .replace("__CONTROL_EXC__", str(CONTROL_EXC))
        .replace("__HEALTHY_N__", str(HEALTHY_N))
        .replace("__HEALTHY_M__", str(HEALTHY_M))
        .replace("__SAT_M__", str(SAT_M))
        .replace("__SAT_EXC__", str(SAT_EXC))
        .replace("__CRASH_N1__", str(CRASH_N1))
        .replace("__CRASH_N2__", str(CRASH_N2))
        .replace("__CRASH_N3__", str(CRASH_N3))
        .replace("__MUTANT_N__", str(MUTANT_N))
        .replace("__MUTANT_M__", str(MUTANT_M))
        .replace("__STALE_N__", str(STALE_N))
        .replace("__STALE_M__", str(STALE_M))
        .replace("__V2_N__", str(V2_N))
        .replace("__V2_M__", str(V2_M))
    )
    with open(staged_script, "w", encoding="utf-8") as handle:
        handle.write(script)
    for source, name in (
        (base_obj, "emitter.bpf.o"),
        (small_obj, "emitter_small.bpf.o"),
        (tgid_obj, "tgid_mutant.bpf.o"),
        (v2_obj, "v2_mutant.bpf.o"),
        (control_obj, "control.bpf.o"),
        (workload, "syscall_workload"),
        (holder, "tracepoint_attach"),
        (drain, "ringbuf_drain"),
    ):
        guest_proc.copy_consumed(source, os.path.join(stage, name))
    os.chmod(stage, 0o755)
    for name in (
        "guest_events.sh", "emitter.bpf.o", "emitter_small.bpf.o",
        "tgid_mutant.bpf.o", "v2_mutant.bpf.o", "control.bpf.o",
    ):
        os.chmod(os.path.join(stage, name), 0o644)
    for name in ("syscall_workload", "tracepoint_attach", "ringbuf_drain"):
        os.chmod(os.path.join(stage, name), 0o755)
    # Preflight observations for provenance comparisons. Host readers
    # separately consume logged buffers; this scan proves no guest use.
    guest_proc.consume_declared_inputs(
        stage,
        extra=(
            "emitter.bpf.o", "emitter_small.bpf.o",
            "tgid_mutant.bpf.o", "v2_mutant.bpf.o",
            "control.bpf.o",
            "syscall_workload", "tracepoint_attach",
            "ringbuf_drain", "guest_events.sh",
        ),
    )
    returncode, output = _run_guest(
        ["vng", "--run", release, "--disable-kvm",
        "--exec", "bash %s" % staged_script],
        stage, GUEST_TIMEOUT,
        release,
    )
    if "TRACEPOINT-MISSING:" in output:
        raise EnvironmentFailure(
            "guest %s lacks syscalls:sys_enter_getpid; "
            "stage %s" % (release, stage)
        )
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=(),
        progress_banner="=== begin tracepoint-events ===",
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
    for marker in ("=== end tracepoint-events ===", "cleanup: proven"):
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
    rec = guest_proc.active_recorder()
    if rec is not None:
        # The guest must report the consumed helper bytes (the
        # objects self-verify against their pins in-guest); a
        # swap between the consumption seal and the guest's
        # reads fails here instead of executing unattested.
        reported = guest_proc.parse_reported_hashes(output)
        for name in (
            "syscall_workload", "tracepoint_attach",
            "ringbuf_drain",
        ):
            expected = rec.consumed_staged_digest(name, stage)
            if expected is None or reported.get(name) != expected:
                raise ProofFailure(
                    "guest did not consume the sealed bytes of %s"
                    % name
                )
    return (output, stage)


def phase_lines(output, label):
    """Parse one phase's <label> lines into a dict of observations."""
    found = {}
    for line in output.splitlines():
        if not line.startswith(label + "-"):
            continue
        key, _, value = line[len(label) + 1:].partition(": ")
        found[key] = value.strip()
    return found


def require_keys(phase, label, keys):
    for key in keys:
        if key not in phase:
            raise ProofFailure(
                "phase %s is missing %s in: %r" % (label, key, phase)
            )


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


def phase_counters(counters_field):
    match = re.fullmatch(
        r"attempted=(\d+) successful=(\d+) failed=(\d+)",
        counters_field.strip(),
    )
    if not match:
        raise ProofFailure(
            "counters field malformed: %r" % (counters_field,)
        )
    return tuple(int(group) for group in match.groups())


def guest_ncpu(output):
    for line in output.splitlines():
        if line.startswith("ncpu:"):
            value = line.split("ncpu:")[1].strip()
            if re.fullmatch(r"[1-9][0-9]*", value):
                return int(value)
    raise ProofFailure("guest ncpu missing or malformed")


def frames_blob(output, label):
    """Rebuild one drain file's bytes from its transcript lines.

    The guest publishes one ``<label>-frame: <72 hex>`` line per
    36-byte frame plus a ``<label>-sha256:`` line; guest files
    never leave the virtme overlay. Every line is strictly
    validated and the rebuilt bytes must match the published
    digest, so transcript corruption fails loudly instead of
    decoding as kernel data.
    """
    chunks = []
    digest = None
    frame_prefix = label + "-frame: "
    sha_prefix = label + "-sha256: "
    for line in output.splitlines():
        if line.startswith(frame_prefix):
            text = line[len(frame_prefix):].strip()
            if not re.fullmatch(r"[0-9a-f]{72}", text):
                raise ProofFailure(
                    "%s frame line malformed: %r" % (label, line)
                )
            chunks.append(bytes.fromhex(text))
        elif line.startswith(sha_prefix):
            digest = line[len(sha_prefix):].strip()
    if digest is None:
        raise ProofFailure("%s sha256 line missing" % label)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ProofFailure(
            "%s sha256 malformed: %r" % (label, digest)
        )
    blob = b"".join(chunks)
    observed = hashlib.sha256(blob).hexdigest()
    if observed != digest:
        raise ProofFailure(
            "%s transcript bytes %s do not match the published %s"
            % (label, observed, digest)
        )
    return blob


def decode_frames(output, label):
    try:
        return decode_event_stream(frames_blob(output, label))
    except EventDecodeError as exc:
        raise ProofFailure(
            "%s fails decoding: %s" % (label, exc)
        ) from exc


def check_run(records, expect_tgid, expect_tid, max_cpu, name):
    try:
        return check_event_run(
            records,
            expect_tgid=expect_tgid,
            expect_tid=expect_tid,
            max_cpu=max_cpu,
        )
    except EventCheckError as exc:
        raise ProofFailure(
            "%s fails its run check: %s" % (name, exc)
        ) from exc


def check_balance(attempted, successful, failed, received, gaps, name):
    try:
        check_accounting(
            attempted=attempted,
            successful=successful,
            failed=failed,
            received=received,
            gap_total=gaps,
        )
    except EventCheckError as exc:
        raise ProofFailure(
            "%s fails accounting: %s" % (name, exc)
        ) from exc


def test_control_pattern_reproduced():
    output, stage = executed()
    phase = phase_lines(output, "control")
    require_keys(phase, "control", ("tids", "done", "drained", "follow-sum"))
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (CONTROL_MON, CONTROL_EXC, CONTROL_EXC)
    ), phase["done"]
    drained = int(phase["drained"])
    # The control filters nothing, so every workload call emits;
    # background calls only add more identical records.
    floor = CONTROL_MON + 2 * CONTROL_EXC
    assert drained >= floor, (drained, floor)
    assert phase["follow-sum"] == phase["drained"], phase
    records = decode_frames(output, "control")
    assert len(records) == drained, (len(records), drained)
    want = CONTROL_PATTERN
    for index, record in enumerate(records):
        observed = (
            record.version, record.record_size, record.tgid,
            record.tid, record.cpu, record.sequence,
            record.monotonic_ns,
        )
        assert observed == want, (index, observed)
    print(
        "PASS control: %d records reproduce the fixed pattern "
        "(workload floor %d)" % (drained, floor)
    )


def test_healthy_exact_accounting():
    output, stage = executed()
    max_cpu = guest_ncpu(output)
    phase = phase_lines(output, "healthy")
    require_keys(
        phase, "healthy",
        ("tids", "done", "filter", "counters", "drained", "ring"),
    )
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (HEALTHY_N, HEALTHY_M, HEALTHY_M)
    ), phase["done"]
    assert phase["filter"] == "want=%s readback=%s" % (
        tids["monitored"], tids["monitored"],
    ), phase["filter"]
    attempted, successful, failed = phase_counters(phase["counters"])
    assert (attempted, successful, failed) == (
        HEALTHY_N, HEALTHY_N, 0,
    ), (attempted, successful, failed)
    assert phase["drained"] == str(HEALTHY_N), phase["drained"]
    assert phase["ring"] == "0 %d %d" % (
        HEALTHY_N * 40, HEALTHY_N * 40,
    ), phase["ring"]
    records = decode_frames(output, "healthy")
    report = check_run(
        records,
        int(tids["observer"]),
        int(tids["monitored"]),
        max_cpu,
        "healthy.frames",
    )
    assert report.received == HEALTHY_N, report
    assert report.first_sequence == 0, report
    assert report.last_sequence == HEALTHY_N - 1, report
    assert report.gap_total == 0, report
    check_balance(
        attempted, successful, failed, report.received,
        report.gap_total, "healthy",
    )
    print(
        "PASS healthy: attempted=successful=received=%d failed=0 "
        "sequences 0..%d contiguous" % (HEALTHY_N, HEALTHY_N - 1)
    )


def test_saturation_explicit_loss():
    output, stage = executed()
    max_cpu = guest_ncpu(output)
    phase = phase_lines(output, "saturation")
    require_keys(
        phase, "saturation",
        ("tids", "done", "filter", "counters", "drained", "ring"),
    )
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (SAT_M, SAT_EXC, SAT_EXC)
    ), phase["done"]
    attempted, successful, failed = phase_counters(phase["counters"])
    assert attempted == SAT_M, attempted
    # Both producer categories are nonempty: the ring filled
    # mid-run instead of failing everything or nothing.
    assert 1 <= successful <= SMALL_RING_SLOTS, successful
    assert failed == attempted - successful, (failed, attempted)
    assert failed > 0, failed
    assert phase["drained"] == str(successful), phase["drained"]
    assert phase["ring"] == "0 %d %d" % (
        successful * 40, successful * 40,
    ), phase["ring"]
    records = decode_frames(output, "saturation")
    report = check_run(
        records,
        int(tids["observer"]),
        int(tids["monitored"]),
        max_cpu,
        "saturation.frames",
    )
    assert report.received == successful, report
    # A stopped consumer loses a tail, never a middle: the drained
    # records are exactly the successful prefix.
    assert report.first_sequence == 0, report
    assert report.last_sequence == successful - 1, report
    assert report.gap_total == 0, report
    assert [record.sequence for record in records] == list(
        range(successful)
    )
    trailing = attempted - 1 - report.last_sequence
    assert trailing == failed, (trailing, failed)
    print(
        "PASS saturation: attempted=%d successful=%d failed=%d "
        "received=%d (prefix 0..%d)"
        % (attempted, successful, failed, report.received, successful - 1)
    )


def test_crash_keeps_position_no_kernel_loss():
    output, stage = executed()
    max_cpu = guest_ncpu(output)
    phase = phase_lines(output, "crash")
    require_keys(
        phase, "crash",
        ("drained1", "ring1", "drained3", "ring3", "counters",
         "kill-exit", "killed", "run1-tids", "run2-tids",
         "run3-tids", "run1-done", "run2-done", "run3-done"),
    )
    assert phase["killed"] == "yes", phase
    assert phase["kill-exit"] == "137", phase
    assert phase["run1-done"] == (
        "DONE monitored=%d excl1=0 excl2=0" % CRASH_N1
    ), phase["run1-done"]
    assert phase["run2-done"] == (
        "DONE monitored=%d excl1=0 excl2=0" % CRASH_N2
    ), phase["run2-done"]
    assert phase["run3-done"] == (
        "DONE monitored=%d excl1=0 excl2=0" % CRASH_N3
    ), phase["run3-done"]
    assert phase["drained1"] == str(CRASH_N1), phase["drained1"]
    assert phase["ring1"] == "0 %d %d" % (
        CRASH_N1 * 40, CRASH_N1 * 40,
    ), phase["ring1"]
    # The restarted drain resumes exactly where the killed consumer
    # stopped: the kernel kept the consumer position.
    assert phase["drained3"] == str(CRASH_N3), phase["drained3"]
    assert phase["ring3"] == "%d %d %d" % (
        (CRASH_N1 + CRASH_N2) * 40,
        (CRASH_N1 + CRASH_N2 + CRASH_N3) * 40,
        (CRASH_N1 + CRASH_N2 + CRASH_N3) * 40,
    ), phase["ring3"]
    attempted, successful, failed = phase_counters(phase["counters"])
    total = CRASH_N1 + CRASH_N2 + CRASH_N3
    assert (attempted, successful, failed) == (total, total, 0), (
        attempted, successful, failed,
    )
    runs = []
    for tag, name, count in (
        ("run1", "crash1", CRASH_N1),
        ("run2", "crash2", CRASH_N2),
        ("run3", "crash3", CRASH_N3),
    ):
        tids = phase_tids(phase["%s-tids" % tag])
        expect_tgid = int(tids["observer"])
        expect_tid = int(tids["monitored"])
        records = decode_frames(output, name)
        assert len(records) == count, (name, len(records), count)
        # Sequences continue across runs (one attachment), so the
        # global contiguity check below subsumes per-run gaps;
        # here each run proves its own identity, CPU range, and
        # non-decreasing timestamps.
        previous_now = None
        for index, record in enumerate(records):
            assert record.tgid == expect_tgid, (name, index, record)
            assert record.tid == expect_tid, (name, index, record)
            assert record.cpu < max_cpu, (name, index, record)
            if previous_now is not None:
                assert record.monotonic_ns >= previous_now, (
                    name, index, record,
                )
            previous_now = record.monotonic_ns
        runs.append(records)
    sequences = [record.sequence for run in runs for record in run]
    assert sequences == list(range(total)), (
        "crash lost or duplicated records: %d sequences" % len(sequences)
    )
    print(
        "PASS crash: SIGKILLed consumer loses nothing (%d contiguous "
        "sequences), failed stays 0, drain resumes at offset %d"
        % (total, (CRASH_N1 + CRASH_N2) * 40)
    )


def test_tgid_mutant_zeroes_and_stale_reloads():
    output, stage = executed()
    max_cpu = guest_ncpu(output)
    mutant = phase_lines(output, "mutant")
    require_keys(
        mutant, "mutant",
        ("tids", "done", "filter", "counters", "drained", "ring"),
    )
    tids = phase_tids(mutant["tids"])
    assert mutant["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (MUTANT_N, MUTANT_M, MUTANT_M)
    ), mutant["done"]
    attempted, successful, failed = phase_counters(mutant["counters"])
    assert (attempted, successful, failed) == (0, 0, 0), (
        attempted, successful, failed,
    )
    assert mutant["drained"] == "0", mutant["drained"]
    assert mutant["ring"] == "0 0 0", mutant["ring"]
    assert frames_blob(output, "mutant") == b"", "mutant drained"
    stale = phase_lines(output, "stale")
    require_keys(
        stale, "stale",
        ("tids", "done", "filter", "counters", "drained", "ring"),
    )
    tids = phase_tids(stale["tids"])
    assert stale["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (STALE_N, STALE_M, STALE_M)
    ), stale["done"]
    attempted, successful, failed = phase_counters(stale["counters"])
    assert (attempted, successful, failed) == (STALE_N, STALE_N, 0), (
        attempted, successful, failed,
    )
    records = decode_frames(output, "stale")
    report = check_run(
        records,
        int(tids["observer"]),
        int(tids["monitored"]),
        max_cpu,
        "stale.frames",
    )
    assert report.received == STALE_N, report
    assert report.first_sequence == 0, report
    assert report.last_sequence == STALE_N - 1, report
    assert report.gap_total == 0, report
    check_balance(
        attempted, successful, failed, report.received,
        report.gap_total, "stale",
    )
    print(
        "PASS mutant/stale: TGID mutant attempts nothing, reloaded "
        "base accounts exactly %d" % STALE_N
    )


def test_v2_decoder_rejects_live_records():
    output, stage = executed()
    phase = phase_lines(output, "v2")
    require_keys(
        phase, "v2",
        ("tids", "done", "filter", "counters", "drained", "ring"),
    )
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d" % (V2_N, V2_M, V2_M)
    ), phase["done"]
    attempted, successful, failed = phase_counters(phase["counters"])
    # The kernel produced and transported every record: only the
    # decoder objects to the version.
    assert (attempted, successful, failed) == (V2_N, V2_N, 0), (
        attempted, successful, failed,
    )
    assert phase["drained"] == str(V2_N), phase["drained"]
    assert phase["ring"] == "0 %d %d" % (V2_N * 40, V2_N * 40), phase["ring"]
    blob = frames_blob(output, "v2")
    assert len(blob) == V2_N * (4 + 32), len(blob)
    try:
        decode_event_stream(blob)
    except EventDecodeError as exc:
        assert "unsupported-version" in str(exc), exc
    else:
        raise ProofFailure("v2.frames decoded but must be rejected")
    rejected = 0
    for index in range(V2_N):
        offset = index * (4 + 32) + 4
        try:
            decode_event_record(blob, offset)
        except EventDecodeError as exc:
            assert "unsupported-version" in str(exc), (index, exc)
            rejected += 1
        else:
            raise ProofFailure(
                "v2 record %d decoded but must be rejected" % index
            )
    assert rejected == V2_N, rejected
    print(
        "PASS v2: kernel produced %d records, decoder rejected all "
        "%d as unsupported-version" % (V2_N, rejected)
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
    print(
        "guest: %s kernel %s ncpu %d"
        % (release, guest_kernel(output), guest_ncpu(output))
    )
    print(
        "staged objects: emitter=%s small=%s tgid=%s v2=%s control=%s"
        % (
            EMITTER_OBJECT_HASH[:16],
            SMALL_OBJECT_HASH[:16],
            TGID_MUTANT_HASH[:16],
            V2_MUTANT_HASH[:16],
            CONTROL_OBJECT_HASH[:16],
        )
    )
    print(
        "staged sources: workload=%s holder=%s drain=%s control=%s"
        % (
            sha256_file(WORKLOAD_SOURCE)[:16],
            sha256_file(HOLDER_SOURCE)[:16],
            sha256_file(DRAIN_SOURCE)[:16],
            sha256_file(CONTROL_SOURCE)[:16],
        )
    )
    control = phase_lines(output, "control")
    print(
        "board control: drained=%s follow-sum=%s done=[%s] tids=[%s]"
        % (
            control.get("drained", "?"),
            control.get("follow-sum", "?"),
            control.get("done", "?"),
            control.get("tids", "?"),
        )
    )
    for label in ("healthy", "saturation", "mutant", "stale", "v2"):
        phase = phase_lines(output, label)
        print(
            "board %s: counters=[%s] drained=%s ring=[%s] done=[%s] "
            "filter=[%s] tids=[%s]"
            % (
                label,
                phase.get("counters", "?"),
                phase.get("drained", "?"),
                phase.get("ring", "?"),
                phase.get("done", "?"),
                phase.get("filter", "?"),
                phase.get("tids", "?"),
            )
        )
    crash = phase_lines(output, "crash")
    print(
        "board crash: counters=[%s] drained1=%s ring1=[%s] drained3=%s "
        "ring3=[%s] kill-exit=%s killed=%s"
        % (
            crash.get("counters", "?"),
            crash.get("drained1", "?"),
            crash.get("ring1", "?"),
            crash.get("drained3", "?"),
            crash.get("ring3", "?"),
            crash.get("kill-exit", "?"),
            crash.get("killed", "?"),
        )
    )


# No denials: every case asserts exact guest behavior positively.
CASE_DENIALS = {}


# Durable inputs per case: repo sources plus the staged objects
# each phase loads (resolved against the guest stage at finish).
CASE_INPUTS = {
    "test_control_pattern_reproduced": {
        "sources": [
            CONTROL_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
            DRAIN_SOURCE,
        ],
        "objects": [("stage", "control.bpf.o")],
        "corpus": [],
    },
    "test_healthy_exact_accounting": {
        "sources": [
            EMITTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
            DRAIN_SOURCE,
        ],
        "objects": [("stage", "emitter.bpf.o")],
        "corpus": [],
    },
    "test_saturation_explicit_loss": {
        "sources": [
            SMALL_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
            DRAIN_SOURCE,
        ],
        "objects": [("stage", "emitter_small.bpf.o")],
        "corpus": [],
    },
    "test_crash_keeps_position_no_kernel_loss": {
        "sources": [
            EMITTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
            DRAIN_SOURCE,
        ],
        "objects": [("stage", "emitter.bpf.o")],
        "corpus": [],
    },
    "test_tgid_mutant_zeroes_and_stale_reloads": {
        "sources": [
            TGID_MUTANT_SOURCE, EMITTER_SOURCE, WORKLOAD_SOURCE,
            HOLDER_SOURCE, DRAIN_SOURCE,
        ],
        "objects": [
            ("stage", "tgid_mutant.bpf.o"),
            ("stage", "emitter.bpf.o"),
        ],
        "corpus": [],
    },
    "test_v2_decoder_rejects_live_records": {
        "sources": [
            V2_MUTANT_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
            DRAIN_SOURCE,
        ],
        "objects": [("stage", "v2_mutant.bpf.o")],
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
    stage = None
    try:
        output, stage = executed()
        rec.note_transcript("guest", output)
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        ProofFailure, AssertionError,
        subprocess.TimeoutExpired,
    ):
        pass
    code = rec.finish(
        stage_dir=stage, unavailable_seen=unavailable_seen
    )
    guest_proc.discard_owned_stages()
    return code


def main():
    names = sorted(k for k in globals() if k.startswith("test_"))
    try:
        release = vng_release()
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE in lane: %s" % exc)
        rec = guest_proc.SuiteRecorder(
            suite_id="kernel-events", suite_path=__file__,
            case_ids=names + ["board"],
            denials=CASE_DENIALS, inputs=CASE_INPUTS,
            lane_release="v6.12")
        # The lane is invalid, so nothing can run; the nominal
        # default lane lets the refusal seal a terminal record
        # (matrix runs always set a valid lane and embed the
        # matrix target instead).
        return rec.finish_unrun("invalid lane: %s" % exc)
    rec = guest_proc.SuiteRecorder(
        suite_id="kernel-events", suite_path=__file__,
        case_ids=names + ["board"],
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
        AssertionError, ProofFailure, subprocess.TimeoutExpired,
        guest_proc.TargetLeaseRequired,
    ):
        pass
    for name in names:
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
        output, _stage = executed()
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
    print("tracepoint events: ring-buffer output proof passed")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())


