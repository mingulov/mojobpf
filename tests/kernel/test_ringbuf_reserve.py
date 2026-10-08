# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Explicit ring-reservation ownership proof in a disposable guest.

Builds ``tests/compile/reserve_submit.mojo`` (plus the small-ring
submitter and the discard emitter) through the genuine pipeline
on the host, builds the independent C reservation fixtures with
the pinned ``clang --target=bpf -O2 -g``, compiles the
raw-syscall workload, the tracepoint attach holder, and the
ring-buffer drain tool with the host C compiler, stages
everything into one disposable virtme-ng guest, and proves
exactly-once reservation ownership on the
``syscalls:sys_enter_getpid`` event. Guest files never leave the
virtme overlay, so every drain is published over the transcript
as one hex line per frame plus a sha256 line, and the host
rebuilds the exact drained bytes (digest-verified) before the
independent decoder observes them:

* submit: with the filter set to the monitored TID, exactly
  N=3000 monitored getpids yield attempted=successful=3000,
  failed=0, and 3000 drained records with contiguous per-TID
  sequences 0..2999, the monitored identity, and
  non-decreasing timestamps, so every reserve published
  exactly once and every submit published exactly one record;
* discard: N=1000 monitored getpids yield
  attempted=released+failed with zero drained records, so
  every reserve discarded published nothing while the counters
  prove every attempt ran;
* saturation: with a one-page ring and a stopped consumer,
  M=2000 attempts yield attempted=released+failed with both
  categories nonempty; after quiescence a single drain
  receives exactly the released prefix, so null reservations
  reconcile as explicit failures;
* adversarial interleavings: the four independent C fixtures
  (double submit, submit-then-discard, discard-then-submit,
  use-after-discard) are all rejected at load with pinned
  verifier markers while the well-formed C control loads and
  unloads cleanly on the same lane, attributing every
  rejection to its adversarial tail;
* license: the built reservation objects pass inspection
  cleanly under the reservation capability profile, the
  helper-license preflight admits the used helpers (1, 2, 3,
  5, 8, 14, 131, 132, 133) under the project's non-GPL
  declaration, and the same preflight still refuses the
  GPL-only witness there, so the admission is not vacuous.

Protocol notes. Attachment is a single system-wide tracepoint
probe (one link), so worker migration across CPUs cannot lose
events; the workers run without CPU affinity. Every run starts
its own workload process (fresh TIDs), publishes all four TIDs
(the observer runs outside the monitored TID), sets the filter
and zeroes the counters (userspace initialization with
readback), then releases the workers over a FIFO; the workers
report their executed loop counts over a second FIFO after
joining, so every counter read and one-shot drain is quiescent
by construction. The saturation phase runs with no consumer at
all. No fixed sleep synchronizes anything: every wait is a FIFO
rendezvous, a reaped child, or a bounded poll for an explicit
handshake marker that fails loudly on timeout. The suite cleans
up every pin, attachment, process, and FIFO it creates and
asserts the guest holds no residue afterwards.

Requires ``mojo``, ``llc``, ``cc``, ``clang``, ``bpftool`` and
``vng`` on PATH plus the pinned kernels. ``MOJOBPF_VNG_RELEASE``
selects the guest lane (default ``v6.12``). A missing tool or
lane is an environment failure; a failing proof step is a proof
failure. Neither ever passes.

Runnable directly (``python3
tests/kernel/test_ringbuf_reserve.py``) or under any
``test_``-style runner. Standard library only.
"""

import hashlib
import json
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
SUBMIT_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_submit.mojo"
)
SMALL_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_submit_small.mojo"
)
DISCARD_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_discard.mojo"
)
OK_SOURCE_REL = os.path.join(
    "tests", "reference_c", "reserve_submit_ok.bpf.c"
)
DOUBLE_SUBMIT_SOURCE_REL = os.path.join(
    "tests", "reference_c", "reserve_double_submit.bpf.c"
)
SUBMIT_DISCARD_SOURCE_REL = os.path.join(
    "tests", "reference_c", "reserve_submit_discard.bpf.c"
)
DISCARD_SUBMIT_SOURCE_REL = os.path.join(
    "tests", "reference_c", "reserve_discard_submit.bpf.c"
)
USE_AFTER_DISCARD_SOURCE_REL = os.path.join(
    "tests", "reference_c", "reserve_use_after_discard.bpf.c"
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

from mojobpf.events import (  # noqa: E402
    EventDecodeError,
    check_accounting,
    check_event_run,
    decode_event_stream,
)

# The guest must test exactly the qualified bytes.
SUBMIT_OBJECT_HASH = (
    "a13ccf31f05427060c4c25308ae4570b72ca13e49d9a46c13545f32a423abf88"
)
SMALL_OBJECT_HASH = (
    "3150bfca0b6fb9ebb0f25f4d47fe6d1440a9ce99762b33c833a7c63c15fe5144"
)
DISCARD_OBJECT_HASH = (
    "49c4e584fc95782755fa5324170354833d018b6596aeb95e9384fe69953df90f"
)
# The C fixtures embed their build paths in DWARF, so the suite
# builds them with a fixed working directory and source spelling
# to keep these bytes reproducible.
OK_OBJECT_HASH = (
    "6814a5135cd0809375adb33db3eff28551a58562f6ef6bac661474b9829ebc45"
)
DOUBLE_SUBMIT_OBJECT_HASH = (
    "71b94878677216695c2458e57a53994bc6f3f39e925d9e07f6e3d2d7abac8bed"
)
SUBMIT_DISCARD_OBJECT_HASH = (
    "dc8c4838fb49b5fc8061b9d0cbaa377af90ae0cd3f1548a1d4b5f90cc81962fd"
)
DISCARD_SUBMIT_OBJECT_HASH = (
    "282ad3bc5416a09dedc463f627281b57d74f5ad0a9b54185768262b3be9ccd02"
)
USE_AFTER_DISCARD_OBJECT_HASH = (
    "5c4decbc0bd6c7c8444437cd7631c7359441daac0824d2e992f7296919f8fb94"
)

# The kernel's per-fixture rejection class markers (observed in
# the verifier log on both lanes; the full raw logs are
# preserved alongside). A released reservation reads back as a
# scalar, so a second terminus fails argument checking while a
# store through the released pointer fails the access check.
DOUBLE_SUBMIT_MARKER = "type=scalar expected=ringbuf_mem"
SUBMIT_DISCARD_MARKER = "type=scalar expected=ringbuf_mem"
DISCARD_SUBMIT_MARKER = "type=scalar expected=ringbuf_mem"
USE_AFTER_DISCARD_MARKER = "invalid mem access 'scalar'"

SUBMIT_N = 3000
SUBMIT_M = 1000
DISCARD_N = 1000
DISCARD_M = 1000
SAT_M = 2000
SAT_EXC = 1000
# One page holds at most floor(4096 / (8 + 32)) records.
SMALL_RING_SLOTS = 102

PROFILE = "linux-bpfel-v3-reserve"
APACHE = "Apache-2.0 WITH LLVM-exception"

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
    with open(path, "rb") as handle:
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


def build_object(source, workdir, tag, want_hash):
    """Build one Mojo source; assert the qualified object bytes."""
    raw_path = os.path.join(workdir, "%s.ll" % tag)
    adapted_path = os.path.join(workdir, "%s.bpf.ll" % tag)
    object_path = os.path.join(workdir, "%s.bpf.o" % tag)
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm",
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


def build_c(source_rel, workdir, tag, want_hash):
    """Build one C fixture; assert the qualified object bytes.

    The fixture objects are only reproducible under the pinned
    clang, so a version mismatch is an environment failure,
    never a proof failure. The build runs with a fixed working
    directory and source spelling because the objects embed
    their build paths.
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
    object_path = os.path.join(workdir, "%s.bpf.o" % tag)
    proc = run_step(
        [
            "clang", "--target=bpf", "-O2", "-g", "-c",
            source_rel, "-o", object_path,
        ],
        cwd=REPO_ROOT,
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "clang failed for %s: exit=%d stderr=%r"
            % (source_rel, proc.returncode, proc.stderr[-1000:])
        )
    observed = sha256_file(object_path)
    if observed != want_hash:
        raise ProofFailure(
            "staged %s bytes %s do not match the qualified %s"
            % (tag, observed, want_hash)
        )
    return object_path


def build_harness(source, output, extra=()):
    proc = run_step(["cc", "-O2", source, "-o", output] + list(extra))
    if proc.returncode != 0:
        raise ProofFailure(
            "harness build failed for %s: %s%s"
            % (source, proc.stdout[-500:], proc.stderr[-500:])
        )
    return output


def _decode_partial(value):
    """Decode timed-out child output, which arrives as bytes.

    ``communicate`` collects raw bytes and decodes only on
    success, so ``TimeoutExpired.stdout``/``stderr`` stay bytes
    even in text mode; concatenating them as strings raises
    ``TypeError`` and loses the partial evidence.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _scan_processes():
    """Snapshot the host pid/parent/group/state table.

    Best-effort: processes that exit mid-scan are skipped, and a
    missing ``/proc`` yields an empty table. This is the owned
    process tracking composition, kept local so the suite stays
    directly runnable.
    """
    table = {}
    try:
        entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return table
    for entry in entries:
        try:
            pid = int(entry)
            with open("/proc/%s/stat" % entry, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)
        except (OSError, ValueError):
            continue
        if len(fields) != 2:
            continue
        rest = fields[1].split()
        if len(rest) < 3:
            continue
        try:
            ppid = int(rest[1])
            pgid = int(rest[2])
        except ValueError:
            continue
        table[pid] = (ppid, pgid, rest[0])
    return table


def _owned_descendants(root, table):
    """Return the pids whose parent chain reaches ``root``.

    Only parent links from a ``_scan_processes`` snapshot are
    followed, so foreign processes are never collected -- but
    orphans already reparented past ``root`` are invisible too,
    which is why the tree kill snapshots before signalling and
    remembers every owned group it saw.
    """
    children = {}
    for pid, (ppid, _pgid, _state) in table.items():
        children.setdefault(ppid, []).append(pid)
    owned = []
    stack = list(children.get(root, []))
    while stack:
        pid = stack.pop()
        owned.append(pid)
        stack.extend(children.get(pid, []))
    return owned


def _signal_live_owned(pgid, table, seen_groups):
    """SIGKILL the living owned tree once; extend the seen groups.

    Only owned pids are signalled: living descendants of the
    guest child plus groups observed holding an owned member --
    never a bare pid used as a group id. Only groups that still
    show a living member are signalled, so dead groups are left
    alone once empty. Returns the living owned pids plus the
    groups that still hold a living member.
    """
    descendants = _owned_descendants(pgid, table)
    for pid in descendants:
        seen_groups.add(table[pid][1])
    live_owned = [
        pid for pid in descendants
        if table[pid][2] not in ("Z", "X")
    ]
    live_groups = set()
    for _ppid, member_pgid, state in table.values():
        if member_pgid in seen_groups and state not in ("Z", "X"):
            live_groups.add(member_pgid)
    for group in sorted(live_groups):
        try:
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    for pid in live_owned:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    return live_owned, live_groups


def _kill_guest_tree(pgid):
    """SIGKILL the guest tree; wait for every owned group to empty.

    The guest runner boots as a session leader (its own process
    group), so killing only the direct child would orphan the
    qemu tree. The owned tree is snapshotted BEFORE signalling --
    dead parents reparent their orphans and the chain is lost
    afterwards -- and every group that ever held an owned member
    stays a kill candidate while it shows a living member, which
    also reaps already-reparented stragglers that kept their
    group. Zombies count as gone and the wait is best-effort:
    whatever remains, the timeout verdict below stands. Without
    ``/proc`` the snapshot is empty and only the guest group is
    killed.
    """
    seen_groups = {pgid}
    deadline = time.monotonic() + 30
    first = True
    while time.monotonic() < deadline:
        table = _scan_processes()
        if not table and first:
            # No snapshot (no /proc): fall back to the guest
            # group alone.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            return
        first = False
        live_owned, live_groups = _signal_live_owned(
            pgid, table, seen_groups
        )
        if not live_owned and not live_groups:
            return
        time.sleep(0.2)


def _run_guest(argv, stage, timeout):
    """Run the guest command; return (exit code, output text).

    The guest boots as a session leader, so a timeout kills the
    whole owned guest tree (the runner group plus any detached
    qemu groups it booted), never just the direct child. Both
    the success transcript and the timed-out partial transcript
    are saved to the stage ``guest.log``; a timeout raises
    ``EnvironmentFailure`` carrying the partial output.
    """
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _kill_guest_tree(proc.pid)
        try:
            stdout, stderr = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        output = (
            _decode_partial(exc.stdout)
            + _decode_partial(exc.stderr)
            + (stdout or "")
            + (stderr or "")
        )
        with open(
            os.path.join(stage, "guest.log"), "w", encoding="utf-8"
        ) as handle:
            handle.write("guest timeout after %ds (partial)\n" % timeout)
            handle.write(output)
        raise EnvironmentFailure(
            "guest run timed out after %ds (stage kept at %s):\n%s"
            % (timeout, stage, output[-4000:])
        )
    output = (stdout or "") + (stderr or "")
    with open(
        os.path.join(stage, "guest.log"), "w", encoding="utf-8"
    ) as handle:
        handle.write("guest exit: %d\n" % proc.returncode)
        handle.write(output)
    return proc.returncode, output


# The guest script loads the reservation objects, attaches each
# phase over the owned holder, drives workload runs over go/done
# FIFOs, reads the producer counters quiescently, drains the
# ring, publishes the frames over the transcript, attempts the
# adversarial loads, detaches, unloads, and proves no residue.
# Blocking waits carry timeouts that fail loudly; nothing here
# assumes a fixed sleep.
GUEST_SCRIPT = r"""#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="__STAGE__"
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin ringbuf-reserve ==="
echo "guest-kernel: $(uname -r)"
bpftool version | head -1
echo "ncpu: $(nproc)"
echo "--- staged hashes ---"
sha256sum submit.bpf.o submit_small.bpf.o discard.bpf.o reserve_ok.bpf.o adv_double_submit.bpf.o adv_submit_discard.bpf.o adv_discard_submit.bpf.o adv_use_after_discard.bpf.o syscall_workload tracepoint_attach ringbuf_drain
echo "__SUBMIT_HASH__  submit.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH submit"; exit 1; }
echo "__SMALL_HASH__  submit_small.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH small"; exit 1; }
echo "__DISCARD_HASH__  discard.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH discard"; exit 1; }
echo "__OK_HASH__  reserve_ok.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH ok"; exit 1; }
echo "__DOUBLE_SUBMIT_HASH__  adv_double_submit.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH adv-ds"; exit 1; }
echo "__SUBMIT_DISCARD_HASH__  adv_submit_discard.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH adv-sd"; exit 1; }
echo "__DISCARD_SUBMIT_HASH__  adv_discard_submit.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH adv-ds2"; exit 1; }
echo "__USE_AFTER_DISCARD_HASH__  adv_use_after_discard.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH adv-uad"; exit 1; }
echo "staged bytes: qualified"
echo "--- pins before ---"
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$(bpftool link show)
PROGS_BEFORE=$(bpftool prog show)
MAPS_BEFORE=$(bpftool map show)
echo "$PINS_BEFORE"
echo "$LINKS_BEFORE"
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
bpftool prog load submit.bpf.o /sys/fs/bpf/rs_unavail type tracepoint >/tmp/rs-unavail.load 2>&1
[ $? = 0 ] || { echo "UNAVAIL-LOAD-FAILED"; cat /tmp/rs-unavail.load; exit 1; }
rm -f unavail-rel
mkfifo unavail-rel
./tracepoint_attach /sys/fs/bpf/rs_unavail syscalls sys_enter_no_such_event <unavail-rel >/tmp/rs-unavail.log 2>&1 &
UNAVAIL_PID=$!
exec 9<>unavail-rel
wait "$UNAVAIL_PID"
UNAVAIL_EXIT=$?
exec 9>&-
cat /tmp/rs-unavail.log
echo "unavail-holder-exit: $UNAVAIL_EXIT"
grep -q "^IDFAIL syscalls:sys_enter_no_such_event$" /tmp/rs-unavail.log || { echo "UNAVAIL-MARKER-MISSING"; exit 1; }
[ "$UNAVAIL_EXIT" = "1" ] || { echo "UNAVAIL-EXIT-MISMATCH"; exit 1; }
echo "unavailability: proven"
rm -f /sys/fs/bpf/rs_unavail unavail-rel

echo "--- real event attach check ---"
bpftool prog load submit.bpf.o /sys/fs/bpf/rs_probe type tracepoint >/tmp/rs-probe.load 2>&1
[ $? = 0 ] || { echo "PROBE-LOAD-FAILED"; cat /tmp/rs-probe.load; exit 1; }
rm -f probe-rel
mkfifo probe-rel
./tracepoint_attach /sys/fs/bpf/rs_probe syscalls sys_enter_getpid <probe-rel >/tmp/rs-probe.log 2>&1 &
PROBE_PID=$!
exec 9<>probe-rel
for _ in $(seq 1 600); do grep -q "^ATTACHED " /tmp/rs-probe.log 2>/dev/null && break; grep -q "^IDFAIL " /tmp/rs-probe.log 2>/dev/null && break; kill -0 "$PROBE_PID" 2>/dev/null || break; sleep 0.1; done
if grep -q "^IDFAIL " /tmp/rs-probe.log; then
  echo "TRACEPOINT-MISSING: syscalls:sys_enter_getpid is unavailable in this guest"
  wait "$PROBE_PID"
  exec 9>&-
  rm -f /sys/fs/bpf/rs_probe probe-rel
  exit 3
fi
grep -q "^ATTACHED " /tmp/rs-probe.log || { echo "PROBE-ATTACH-TIMEOUT"; cat /tmp/rs-probe.log; exit 1; }
cat /tmp/rs-probe.log
exec 9>&-
wait "$PROBE_PID"
[ $? = 0 ] || { echo "PROBE-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/rs-probe.log || { echo "PROBE-DETACH-MARKER-MISSING"; exit 1; }
echo "real event: attachable"
rm -f /sys/fs/bpf/rs_probe probe-rel

run_reserve_phase() {
  # run_reserve_phase <label> <object> <pin> <monitored> <excluded>
  # One workload run under one attachment: load, pin both maps,
  # attach, publish TIDs, initialize the four state entries with
  # readback, release, join, read the counters quiescently, drain
  # once, detach, unload. Prints <label> lines; fails loudly.
  LABEL="$1"; OBJECT="$2"; PIN="$3"; MON_N="$4"; EXC_M="$5"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || { echo "$LABEL-MAPDIR-FAILED"; exit 1; }
  bpftool prog load "$OBJECT" "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/rs-$LABEL.load" 2>&1
  [ $? = 0 ] || { echo "$LABEL-LOAD-FAILED"; cat "/tmp/rs-$LABEL.load"; exit 1; }
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
  "./tracepoint_attach" "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/rs-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$MON_N" --excluded "$EXC_M" --phase full --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/rs-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/rs-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/rs-$LABEL.holder.log" || { echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/rs-$LABEL.holder.log"; exit 1; }
  [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] || { echo "$LABEL-TID-TIMEOUT"; cat "$LABEL-tids" 2>/dev/null; cat "/tmp/rs-$LABEL.wl.log"; exit 1; }
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
  [ $? = 0 ] || { echo "$LABEL-WORKLOAD-FAILED"; cat "/tmp/rs-$LABEL.wl.log"; exit 1; }
  ATTEMPTED=$(map_u64 "$MAP_PIN" 1)
  SUCCESSFUL=$(map_u64 "$MAP_PIN" 2)
  FAILED=$(map_u64 "$MAP_PIN" 3)
  echo "$LABEL-counters: attempted=$ATTEMPTED successful=$SUCCESSFUL failed=$FAILED"
  DRAIN_OUT=$(./ringbuf_drain --map "$RING_PIN" --out "$LABEL.frames") || { echo "$LABEL-DRAIN-FAILED"; exit 1; }
  DRAINED_N=$(echo "$DRAIN_OUT" | awk '/^DRAINED /{print $2}')
  DISCARDED_N=$(echo "$DRAIN_OUT" | awk '/^DISCARDED /{print $2}')
  RING_LINE=$(echo "$DRAIN_OUT" | awk '/^RING /{print $2" "$3" "$4}')
  [ -n "$DRAINED_N" ] && [ -n "$DISCARDED_N" ] && [ -n "$RING_LINE" ] || { echo "$LABEL-DRAIN-PARSE-FAILED: $DRAIN_OUT"; exit 1; }
  echo "$LABEL-drained: $DRAINED_N"
  echo "$LABEL-discarded: $DISCARDED_N"
  echo "$LABEL-ring: $RING_LINE"
  publish_frames "$LABEL"
  exec 8>&-
  wait "$HOLDER_PID"
  [ $? = 0 ] || { echo "$LABEL-DETACH-FAILED"; exit 1; }
  grep -q "^DETACHED$" "/tmp/rs-$LABEL.holder.log" || { echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }
  rm -f "$PIN" "$MAP_PIN" "$RING_PIN"
  rmdir "$MAP_DIR" || { echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
}

run_reserve_phase submit submit.bpf.o /sys/fs/bpf/rs_submit __SUBMIT_N__ __SUBMIT_M__
run_reserve_phase discard discard.bpf.o /sys/fs/bpf/rs_discard __DISCARD_N__ __DISCARD_M__
run_reserve_phase saturation submit_small.bpf.o /sys/fs/bpf/rs_sat __SAT_M__ __SAT_EXC__

echo "--- well-formed control ---"
bpftool prog load reserve_ok.bpf.o /sys/fs/bpf/rs_ok type tracepoint >/tmp/rs-ok.log 2>&1
OK_EXIT=$?
echo "ok-load-exit: $OK_EXIT"
cat /tmp/rs-ok.log
[ "$OK_EXIT" = "0" ] || { echo "CONTROL-LOAD-FAILED: this lane cannot load reservation programs"; exit 3; }
rm -f /sys/fs/bpf/rs_ok
echo "control: loaded+unloaded"

echo "--- adversarial: double submit ---"
bpftool prog load adv_double_submit.bpf.o /sys/fs/bpf/rs_adv_ds type tracepoint >/tmp/rs-adv-ds.log 2>&1
ADV_DS_EXIT=$?
echo "adv-ds-load-exit: $ADV_DS_EXIT"
echo "=== BEGIN adv-ds-log ==="
cat /tmp/rs-adv-ds.log
echo "=== END adv-ds-log ==="
[ "$ADV_DS_EXIT" != "0" ] || { echo "ADV-DS-UNEXPECTEDLY-LOADED"; exit 1; }
grep -q "__DOUBLE_SUBMIT_MARKER__" /tmp/rs-adv-ds.log || { echo "ADV-DS-MARKER-MISSING"; exit 1; }
echo "adv-ds: rejected with marker"
rm -f /sys/fs/bpf/rs_adv_ds

echo "--- adversarial: submit then discard ---"
bpftool prog load adv_submit_discard.bpf.o /sys/fs/bpf/rs_adv_sd type tracepoint >/tmp/rs-adv-sd.log 2>&1
ADV_SD_EXIT=$?
echo "adv-sd-load-exit: $ADV_SD_EXIT"
echo "=== BEGIN adv-sd-log ==="
cat /tmp/rs-adv-sd.log
echo "=== END adv-sd-log ==="
[ "$ADV_SD_EXIT" != "0" ] || { echo "ADV-SD-UNEXPECTEDLY-LOADED"; exit 1; }
grep -q "__SUBMIT_DISCARD_MARKER__" /tmp/rs-adv-sd.log || { echo "ADV-SD-MARKER-MISSING"; exit 1; }
echo "adv-sd: rejected with marker"
rm -f /sys/fs/bpf/rs_adv_sd

echo "--- adversarial: discard then submit ---"
bpftool prog load adv_discard_submit.bpf.o /sys/fs/bpf/rs_adv_dsub type tracepoint >/tmp/rs-adv-dsub.log 2>&1
ADV_DSUB_EXIT=$?
echo "adv-dsub-load-exit: $ADV_DSUB_EXIT"
echo "=== BEGIN adv-dsub-log ==="
cat /tmp/rs-adv-dsub.log
echo "=== END adv-dsub-log ==="
[ "$ADV_DSUB_EXIT" != "0" ] || { echo "ADV-DSUB-UNEXPECTEDLY-LOADED"; exit 1; }
grep -q "__DISCARD_SUBMIT_MARKER__" /tmp/rs-adv-dsub.log || { echo "ADV-DSUB-MARKER-MISSING"; exit 1; }
echo "adv-dsub: rejected with marker"
rm -f /sys/fs/bpf/rs_adv_dsub

echo "--- adversarial: use after discard ---"
bpftool prog load adv_use_after_discard.bpf.o /sys/fs/bpf/rs_adv_uad type tracepoint >/tmp/rs-adv-uad.log 2>&1
ADV_UAD_EXIT=$?
echo "adv-uad-load-exit: $ADV_UAD_EXIT"
echo "=== BEGIN adv-uad-log ==="
cat /tmp/rs-adv-uad.log
echo "=== END adv-uad-log ==="
[ "$ADV_UAD_EXIT" != "0" ] || { echo "ADV-UAD-UNEXPECTEDLY-LOADED"; exit 1; }
grep -q "__USE_AFTER_DISCARD_MARKER__" /tmp/rs-adv-uad.log || { echo "ADV-UAD-MARKER-MISSING"; exit 1; }
echo "adv-uad: rejected with marker"
rm -f /sys/fs/bpf/rs_adv_uad

echo "--- stray check ---"
for _ in $(seq 1 600); do
  PINS_AFTER=$(ls /sys/fs/bpf/)
  LINKS_AFTER=$(bpftool link show)
  PROGS_AFTER=$(bpftool prog show)
  MAPS_AFTER=$(bpftool map show)
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
echo "=== end ringbuf-reserve ==="
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


def _execute_once():
    check_tools(
        "mojo", "llc", "cc", "clang", "bpftool", "vng"
    )
    for path in (
        SUBMIT_SOURCE, SMALL_SOURCE, DISCARD_SOURCE,
        WORKLOAD_SOURCE, HOLDER_SOURCE, DRAIN_SOURCE,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    for rel in (
        OK_SOURCE_REL, DOUBLE_SUBMIT_SOURCE_REL,
        SUBMIT_DISCARD_SOURCE_REL, DISCARD_SUBMIT_SOURCE_REL,
        USE_AFTER_DISCARD_SOURCE_REL,
    ):
        if not os.path.isfile(os.path.join(REPO_ROOT, rel)):
            raise EnvironmentFailure("missing repo file: %s" % rel)
    release = vng_release()
    workdir = tempfile.mkdtemp(prefix="mojo-reserve-")
    submit_obj = build_object(
        SUBMIT_SOURCE, workdir, "submit", SUBMIT_OBJECT_HASH
    )
    small_obj = build_object(
        SMALL_SOURCE, workdir, "small", SMALL_OBJECT_HASH
    )
    discard_obj = build_object(
        DISCARD_SOURCE, workdir, "discard", DISCARD_OBJECT_HASH
    )
    ok_obj = build_c(
        OK_SOURCE_REL, workdir, "ok", OK_OBJECT_HASH
    )
    double_submit_obj = build_c(
        DOUBLE_SUBMIT_SOURCE_REL, workdir, "adv_ds",
        DOUBLE_SUBMIT_OBJECT_HASH,
    )
    submit_discard_obj = build_c(
        SUBMIT_DISCARD_SOURCE_REL, workdir, "adv_sd",
        SUBMIT_DISCARD_OBJECT_HASH,
    )
    discard_submit_obj = build_c(
        DISCARD_SUBMIT_SOURCE_REL, workdir, "adv_dsub",
        DISCARD_SUBMIT_OBJECT_HASH,
    )
    use_after_discard_obj = build_c(
        USE_AFTER_DISCARD_SOURCE_REL, workdir, "adv_uad",
        USE_AFTER_DISCARD_OBJECT_HASH,
    )
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
    stage = tempfile.mkdtemp(prefix="mojo-reserve-", dir="/tmp")
    staged_script = os.path.join(stage, "guest_reserve.sh")
    script = (
        GUEST_SCRIPT.replace("__STAGE__", stage)
        .replace("__SUBMIT_HASH__", SUBMIT_OBJECT_HASH)
        .replace("__SMALL_HASH__", SMALL_OBJECT_HASH)
        .replace("__DISCARD_HASH__", DISCARD_OBJECT_HASH)
        .replace("__OK_HASH__", OK_OBJECT_HASH)
        .replace("__DOUBLE_SUBMIT_HASH__", DOUBLE_SUBMIT_OBJECT_HASH)
        .replace("__SUBMIT_DISCARD_HASH__", SUBMIT_DISCARD_OBJECT_HASH)
        .replace("__DISCARD_SUBMIT_HASH__", DISCARD_SUBMIT_OBJECT_HASH)
        .replace(
            "__USE_AFTER_DISCARD_HASH__", USE_AFTER_DISCARD_OBJECT_HASH
        )
        .replace("__DOUBLE_SUBMIT_MARKER__", DOUBLE_SUBMIT_MARKER)
        .replace("__SUBMIT_DISCARD_MARKER__", SUBMIT_DISCARD_MARKER)
        .replace("__DISCARD_SUBMIT_MARKER__", DISCARD_SUBMIT_MARKER)
        .replace(
            "__USE_AFTER_DISCARD_MARKER__", USE_AFTER_DISCARD_MARKER
        )
        .replace("__SUBMIT_N__", str(SUBMIT_N))
        .replace("__SUBMIT_M__", str(SUBMIT_M))
        .replace("__DISCARD_N__", str(DISCARD_N))
        .replace("__DISCARD_M__", str(DISCARD_M))
        .replace("__SAT_M__", str(SAT_M))
        .replace("__SAT_EXC__", str(SAT_EXC))
    )
    with open(staged_script, "w", encoding="utf-8") as handle:
        handle.write(script)
    for source, name in (
        (submit_obj, "submit.bpf.o"),
        (small_obj, "submit_small.bpf.o"),
        (discard_obj, "discard.bpf.o"),
        (ok_obj, "reserve_ok.bpf.o"),
        (double_submit_obj, "adv_double_submit.bpf.o"),
        (submit_discard_obj, "adv_submit_discard.bpf.o"),
        (discard_submit_obj, "adv_discard_submit.bpf.o"),
        (use_after_discard_obj, "adv_use_after_discard.bpf.o"),
        (workload, "syscall_workload"),
        (holder, "tracepoint_attach"),
        (drain, "ringbuf_drain"),
    ):
        shutil.copyfile(source, os.path.join(stage, name))
    os.chmod(stage, 0o755)
    for name in (
        "guest_reserve.sh", "submit.bpf.o", "submit_small.bpf.o",
        "discard.bpf.o", "reserve_ok.bpf.o",
        "adv_double_submit.bpf.o", "adv_submit_discard.bpf.o",
        "adv_discard_submit.bpf.o", "adv_use_after_discard.bpf.o",
    ):
        os.chmod(os.path.join(stage, name), 0o644)
    for name in ("syscall_workload", "tracepoint_attach", "ringbuf_drain"):
        os.chmod(os.path.join(stage, name), 0o755)
    retcode, output = _run_guest(
        ["vng", "--run", release, "--disable-kvm",
         "--exec", "bash %s" % staged_script],
        stage,
        GUEST_TIMEOUT,
    )
    if "TRACEPOINT-MISSING:" in output:
        raise EnvironmentFailure(
            "guest %s lacks syscalls:sys_enter_getpid; "
            "stage kept at %s" % (release, stage)
        )
    if "CONTROL-LOAD-FAILED:" in output:
        raise EnvironmentFailure(
            "guest %s cannot load reservation programs; "
            "stage kept at %s" % (release, stage)
        )
    if retcode != 0:
        raise ProofFailure(
            "guest %s failed (exit %d); stage kept at %s\n%s"
            % (release, retcode, stage, output[-6000:])
        )
    for marker in ("=== end ringbuf-reserve ===", "cleanup: proven"):
        if marker not in output:
            raise ProofFailure(
                "guest %s transcript incomplete; stage kept at %s\n%s"
                % (release, stage, output[-6000:])
            )
    kernel = ""
    for line in output.splitlines():
        if line.startswith("guest-kernel:"):
            kernel = line.split("guest-kernel:")[1].strip()
    if not kernel.startswith(release[1:] + "."):
        raise ProofFailure(
            "guest kernel %r does not match lane %s" % (kernel, release)
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
    except AssertionError as exc:
        raise ProofFailure("%s fails identity: %s" % (name, exc)) from exc


def check_balance(attempted, successful, failed, received, gaps, name):
    try:
        check_accounting(
            attempted=attempted,
            successful=successful,
            failed=failed,
            received=received,
            gap_total=gaps,
        )
    except AssertionError as exc:
        raise ProofFailure(
            "%s fails accounting: %s" % (name, exc)
        ) from exc


def adv_log(output, tag):
    """Extract one adversarial load log from the transcript."""
    begin = "=== BEGIN %s-log ===" % tag
    end = "=== END %s-log ===" % tag
    lines = []
    inside = False
    for line in output.splitlines():
        if line == begin:
            inside = True
            continue
        if line == end:
            inside = False
            continue
        if inside:
            lines.append(line)
    if not lines:
        raise ProofFailure("%s log missing from transcript" % tag)
    return "\n".join(lines)


def test_submit_publishes_exactly_once():
    output, _stage = executed()
    phase = phase_lines(output, "submit")
    require_keys(
        phase, "submit",
        ("tids", "filter", "done", "counters", "drained",
         "discarded", "ring"),
    )
    tids = phase_tids(phase["tids"])
    attempted, successful, failed = phase_counters(phase["counters"])
    assert attempted == SUBMIT_N, (attempted, SUBMIT_N)
    assert successful == SUBMIT_N, (successful, SUBMIT_N)
    assert failed == 0, (failed,)
    assert phase["drained"] == str(SUBMIT_N), (phase["drained"],)
    assert phase["ring"] == "0 %d %d" % (
        SUBMIT_N * 40, SUBMIT_N * 40,
    ), (phase["ring"],)
    records = decode_frames(output, "submit")
    report = check_run(
        records,
        int(tids["observer"]),
        int(tids["monitored"]),
        guest_ncpu(output),
        "submit",
    )
    assert report.received == SUBMIT_N, (report.received, SUBMIT_N)
    assert report.first_sequence == 0, (report.first_sequence,)
    assert report.last_sequence == SUBMIT_N - 1, (report.last_sequence,)
    assert report.gap_total == 0, (report.gap_total,)
    check_balance(
        attempted, successful, failed,
        report.received, report.gap_total, "submit",
    )
    assert phase["discarded"] == "0", (phase["discarded"],)
    print(
        "PASS submit: %d/%d/%d counters, %d contiguous records, "
        "0 discarded slots"
        % (attempted, successful, failed, report.received)
    )


def test_discard_publishes_nothing():
    output, _stage = executed()
    phase = phase_lines(output, "discard")
    require_keys(
        phase, "discard",
        ("tids", "filter", "done", "counters", "drained",
         "discarded", "ring"),
    )
    attempted, released, failed = phase_counters(phase["counters"])
    assert attempted == DISCARD_N, (attempted, DISCARD_N)
    assert attempted == released + failed, (attempted, released, failed)
    assert released == DISCARD_N, (released, DISCARD_N)
    assert failed == 0, (failed,)
    records = decode_frames(output, "discard")
    assert len(records) == 0, (len(records),)
    assert phase["drained"] == "0", (phase["drained"],)
    assert phase["discarded"] == str(DISCARD_N), (phase["discarded"],)
    print(
        "PASS discard: %d attempts released %d, %d records "
        "drained, %s discarded slots consumed"
        % (attempted, released, len(records), phase["discarded"])
    )


def test_saturation_null_reserve_accounting():
    output, _stage = executed()
    phase = phase_lines(output, "saturation")
    require_keys(
        phase, "saturation",
        ("tids", "filter", "done", "counters", "drained",
         "discarded", "ring"),
    )
    tids = phase_tids(phase["tids"])
    attempted, successful, failed = phase_counters(phase["counters"])
    assert attempted == SAT_M, (attempted, SAT_M)
    # Both producer categories are nonempty: the ring filled
    # mid-run instead of failing everything or nothing.
    assert 1 <= successful <= SMALL_RING_SLOTS, (successful,)
    assert failed == attempted - successful, (failed, attempted)
    assert failed > 0, (failed,)
    assert phase["drained"] == str(successful), (phase["drained"],)
    assert phase["discarded"] == "0", (phase["discarded"],)
    assert phase["ring"] == "0 %d %d" % (
        successful * 40, successful * 40,
    ), (phase["ring"],)
    records = decode_frames(output, "saturation")
    report = check_run(
        records,
        int(tids["observer"]),
        int(tids["monitored"]),
        guest_ncpu(output),
        "saturation",
    )
    assert report.received == successful, (report.received,)
    # A stopped consumer loses a tail, never a middle: the
    # drained records are exactly the successful prefix.
    assert report.first_sequence == 0, (report.first_sequence,)
    assert report.last_sequence == successful - 1, (
        report.last_sequence, successful,
    )
    assert report.gap_total == 0, (report.gap_total,)
    assert [record.sequence for record in records] == list(
        range(successful)
    )
    trailing = attempted - 1 - report.last_sequence
    assert trailing == failed, (trailing, failed)
    print(
        "PASS saturation: attempted=%d successful=%d failed=%d "
        "received=%d (prefix 0..%d), 0 discarded slots"
        % (
            attempted, successful, failed, report.received,
            successful - 1,
        )
    )


def test_adversarial_interleavings_rejected():
    output, _stage = executed()
    assert "control: loaded+unloaded" in output
    assert "ok-load-exit: 0" in output
    cases = (
        ("adv-ds", "adv-ds-load-exit", DOUBLE_SUBMIT_MARKER),
        ("adv-sd", "adv-sd-load-exit", SUBMIT_DISCARD_MARKER),
        ("adv-dsub", "adv-dsub-load-exit", DISCARD_SUBMIT_MARKER),
        ("adv-uad", "adv-uad-load-exit", USE_AFTER_DISCARD_MARKER),
    )
    for tag, exit_label, marker in cases:
        exit_line = None
        for line in output.splitlines():
            if line.startswith(exit_label + ":"):
                exit_line = line.split(exit_label + ":")[1].strip()
        assert exit_line is not None, "no %s line" % exit_label
        assert exit_line != "0", "%s unexpectedly loaded" % tag
        log = adv_log(output, tag)
        assert marker in log, (tag, log[-2000:])
        assert "%s: rejected with marker" % tag in output, (tag,)
    assert "cleanup: proven" in output
    print(
        "PASS adversarial: 4/4 rejected with markers "
        "(control loaded+unloaded)"
    )


def test_no_residue():
    output, _stage = executed()
    assert "cleanup: proven" in output
    print("PASS residue: pins/links/progs/maps equal before/after")


def test_license_gate_and_preflight():
    import mojobpf.inspect as inspect_module

    from mojobpf.helpers import lookup_helper, profile_helper_ids
    from mojobpf.manifest import lookup_profile

    profile = lookup_profile(PROFILE)
    assert profile.helper_ids == (
        1, 2, 3, 5, 8, 14, 130, 131, 132, 133,
    ), (
        profile.helper_ids,
    )
    assert profile_helper_ids(PROFILE) == (131, 132, 133), (
        profile_helper_ids(PROFILE)
    )
    for helper_id in (131, 132, 133):
        entry = lookup_helper(helper_id)
        assert entry is not None, (helper_id,)
        assert entry.gpl_only is False, (helper_id,)
        assert PROFILE in entry.profiles, (helper_id, entry.profiles)
    inspect_module.preflight_helper_licenses(
        (1, 2, 3, 5, 8, 14, 131, 132, 133), APACHE, PROFILE
    )
    try:
        inspect_module.preflight_helper_licenses((35,), APACHE, PROFILE)
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF709", (exc.diagnostic,)
    else:
        raise AssertionError("expected the preflight to refuse helper 35")
    print(
        "PASS license: preflight admits 131/132/133, refuses 35 "
        "(MBPF709)"
    )


def guest_kernel(output):
    for line in output.splitlines():
        if line.startswith("guest-kernel:"):
            return line.split("guest-kernel:")[1].strip()
    return "unknown"


def print_board(output):
    print("board kernel=%s" % guest_kernel(output))
    for label in ("submit", "discard", "saturation"):
        phase = phase_lines(output, label)
        records = decode_frames(output, label)
        print(
            "board %s counters=%s drained=%s discarded=%s records=%d"
            % (
                label, phase.get("counters"), phase.get("drained"),
                phase.get("discarded"), len(records),
            )
        )
    print("board adv-ds rejected with %r" % (DOUBLE_SUBMIT_MARKER,))
    print("board adv-sd rejected with %r" % (SUBMIT_DISCARD_MARKER,))
    print("board adv-dsub rejected with %r" % (DISCARD_SUBMIT_MARKER,))
    print("board adv-uad rejected with %r" % (USE_AFTER_DISCARD_MARKER,))


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except (AssertionError, ProofFailure) as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        except Exception as exc:
            print(
                "FAIL %s: unexpected %s: %s"
                % (name, type(exc).__name__, exc)
            )
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    output, _stage = executed()
    print_board(output)
    print("ringbuf reserve: submit/discard/saturation ownership, "
          "adversarial, residue and license checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
