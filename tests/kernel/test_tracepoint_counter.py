# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Exact tracepoint counter proof in a disposable guest.

Builds ``examples/tracepoint_counter/counter.mojo`` (and its TGID
mutant) through the genuine pipeline on the host, compiles the raw-
syscall workload and the tracepoint attach holder with the host C
compiler, stages everything into one disposable virtme-ng guest,
and proves exact TID-filtered counting on the
``syscalls:sys_enter_getpid`` event:

* excluded phase: with the filter set to an idle monitored TID,
  two excluded workers issuing 1000 raw getpid calls each (plus
  any background system activity) leave the counter at exactly 0;
* exact phase: the monitored worker issuing exactly N=10000 raw
  getpid calls observes exactly 10000, with the excluded workers'
  calls rejected;
* unavailability: attaching to a deliberately missing event
  reports the environment-capability failure accurately (and a
  missing real event fails the suite as an environment failure,
  never a pass);
* wrong filter: a filter TID that performs no calls observes 0
  against the N=10000 expectation as an explicit controlled
  mismatch, never silently absorbed;
* TGID mutant: the shape-clean mutant comparing the thread-group
  ID observes 0 against N, and the reloaded base object still
  observes exactly N, proving the suite reads live kernel state.

Protocol notes. Attachment is a single system-wide tracepoint
probe (one link; a second attachment of the same program is
refused as a duplicate); the workers run without CPU affinity,
and the exact count is consistent with system-wide coverage.
Migration itself is not sampled (no per-CPU attribution), so
the guest CPU count is recorded in the transcript and the
board. Every run starts its
own workload process (fresh TIDs), publishes all four TIDs (the
observer runs outside the monitored TID), sets the filter and
resets the counter, then releases the workers over a FIFO; the
workers report their executed loop counts over a second FIFO
after joining, so the counter read is quiescent by construction.
No fixed sleep synchronizes anything: every wait is a FIFO
rendezvous, a reaped child, or a bounded poll for an explicit
handshake marker that fails loudly on timeout. The suite cleans
up every pin, attachment, process, and FIFO it creates and
asserts the guest holds no residue afterwards.

Requires ``mojo``, ``llc``, ``cc``, ``bpftool`` and ``vng`` on
PATH plus the pinned kernels. ``MOJOBPF_VNG_RELEASE`` selects the
guest lane (default ``v6.12``). A missing tool or lane is an
environment failure; a failing proof step is a proof failure.
Neither ever passes.

Runnable directly (``python3
tests/kernel/test_tracepoint_counter.py``) or under any
``test_``-style runner. Standard library only.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import guest_proc  # noqa: E402
import lane_lock  # noqa: E402
import tool_admission  # noqa: E402
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
COUNTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "counter.mojo"
)
MUTANT_SOURCE = os.path.join(
    REPO_ROOT,
    "examples",
    "tracepoint_counter",
    "counter_tgid_mutated.mojo",
)
WORKLOAD_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "syscall_workload.c"
)
HOLDER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "tracepoint_attach.c"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# The guest must test exactly the qualified bytes.
TRACEPOINT_OBJECT_HASH = (
    "b687af78c3056e2299929cd635044875f8369f9ca6e27f626c4f55c4def8b67a"
)
MUTANT_OBJECT_HASH = (
    "05414e1da026919dd91d69485992533f87eb4c7ce16b167b73f3a94c001eae5c"
)

MONITORED_N = 10000
EXCLUDED_M = 1000
# Above the kernel's maximum TID: can never match a real thread.
BOGUS_TID = 0x7FFFFFFF

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
# Tracepoint counter guest proof. Every phase loads its object
# with bpftool (the libbpf-consumability proof), attaches with
# the owned holder over a release FIFO, drives one workload run
# over go/done FIFOs, reads the counter quiescently, detaches,
# and unloads. Blocking waits carry timeouts that fail loudly;
# nothing here assumes a fixed sleep.
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="__STAGE__"
MONITORED_N=__MONITORED_N__
EXCLUDED_M=__EXCLUDED_M__
BOGUS_TID=__BOGUS_TID__
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
__BPFTOOL_PROLOGUE__
echo "=== begin tracepoint ==="
echo "guest-kernel: $(uname -r)"
echo "guest-nproc: $(nproc)"
"$BPFTOOL" version | head -1
echo "--- staged hashes ---"
sha256sum guest_tracepoint.sh trace.bpf.o mutant.bpf.o syscall_workload tracepoint_attach
echo "--- pins before ---"
map_show_filtered() {
  # bpftool 7.6 observes its own ephemeral iterator maps
  # (pid_iter.*) with per-run IDs and PIDs, and leaks its
  # skeleton maps (libbpf_global, libbpf_det_bind), so raw
  # `map show` output never compares equal across runs.
  # Drop exactly those tool-owned entries and the ephemeral
  # pids lines; suite maps (mojobpf_map*) always pass
  # through, so a real stray still fails the comparison.
  "$BPFTOOL" map show | awk '
    /^[0-9]+:/ { skip = ($0 ~ /name (pid_iter\.[A-Za-z0-9_.]*|libbpf_global|libbpf_det_bind)( |$)/) }
    skip { next }
    /^[[:space:]]+pids / { next }
    { print }'
  return ${PIPESTATUS[0]}
}
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$("$BPFTOOL" link show)
PROGS_BEFORE=$("$BPFTOOL" prog show)
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
  _mu_out=$(set -o pipefail; "$BPFTOOL" map lookup pinned "$1" key "$2" 0 0 0 | python3 -c "import json,re,sys; kid=int(sys.argv[1]); key='%02x 00 00 00' % kid; text=sys.stdin.read(); assert (not text.lstrip().startswith(chr(123))) or (d:=json.loads(text,object_pairs_hook=lambda p:dict(p) if len(p)==len(dict(p)) else None)) and sorted(d)==['key','value'] and type(d['key']) is int and d['key']==kid and type(d['value']) is int and 0<=d['value']<2**64 and (print(d['value']) or sys.exit(0)); assert text.count('value:') == 1, 'want exactly one value section'; assert text.count('key:') == 1, 'want exactly one key echo'; head = text.split('value:')[0]; val = text.split('value:')[1]; assert re.fullmatch('key: ' + key + '([ ]+|' + chr(10) + ')', head), 'want exactly the key echo before the value'; vlines = val.splitlines(); raw = vlines[0] if vlines else ''; assert all(not l.strip() for l in vlines[1:]), 'want no trailing content after value'; b = bytes.fromhex(raw); assert len(b) == 8, 'want exactly 8 value bytes'; print(int.from_bytes(b, 'little'))" "$2") && echo "$_mu_out"
}

u64_bytes() {
  python3 -c "print(' '.join('%d' % b for b in ($1).to_bytes(8, 'little')))"
}

map_set_u64() {
  # map_set_u64 <pinned-map> <key> <value>: write one u64 entry.
  "$BPFTOOL" map update pinned "$1" key "$2" 0 0 0 value $(u64_bytes "$3")
}

echo "--- unavailability probe ---"
"$BPFTOOL" prog load trace.bpf.o /sys/fs/bpf/tp_unavail type tracepoint >/tmp/tp-unavail.load 2>&1
[ $? = 0 ] || { echo "UNAVAIL-LOAD-FAILED"; cat /tmp/tp-unavail.load; exit 1; }
rm -f unavail-rel
mkfifo unavail-rel
./tracepoint_attach /sys/fs/bpf/tp_unavail syscalls sys_enter_no_such_event <unavail-rel >/tmp/tp-unavail.log 2>&1 &
UNAVAIL_PID=$!
exec 9<>unavail-rel
wait "$UNAVAIL_PID"
UNAVAIL_EXIT=$?
exec 9>&-
cat /tmp/tp-unavail.log
echo "unavail-holder-exit: $UNAVAIL_EXIT"
grep -q "^IDFAIL syscalls:sys_enter_no_such_event$" /tmp/tp-unavail.log || { echo "UNAVAIL-MARKER-MISSING"; exit 1; }
[ "$UNAVAIL_EXIT" = "1" ] || { echo "UNAVAIL-EXIT-MISMATCH"; exit 1; }
echo "unavailability: proven"
rm -f /sys/fs/bpf/tp_unavail unavail-rel

echo "--- real event attach check ---"
"$BPFTOOL" prog load trace.bpf.o /sys/fs/bpf/tp_probe type tracepoint >/tmp/tp-probe.load 2>&1
[ $? = 0 ] || { echo "PROBE-LOAD-FAILED"; cat /tmp/tp-probe.load; exit 1; }
rm -f probe-rel
mkfifo probe-rel
./tracepoint_attach /sys/fs/bpf/tp_probe syscalls sys_enter_getpid <probe-rel >/tmp/tp-probe.log 2>&1 &
PROBE_PID=$!
exec 9<>probe-rel
for _ in $(seq 1 600); do grep -q "^ATTACHED " /tmp/tp-probe.log 2>/dev/null && break; grep -q "^IDFAIL " /tmp/tp-probe.log 2>/dev/null && break; kill -0 "$PROBE_PID" 2>/dev/null || break; sleep 0.1; done
if grep -q "^IDFAIL " /tmp/tp-probe.log; then
  echo "TRACEPOINT-MISSING: syscalls:sys_enter_getpid is unavailable in this guest"
  wait "$PROBE_PID"
  exec 9>&-
  rm -f /sys/fs/bpf/tp_probe probe-rel
  exit 3
fi
grep -q "^ATTACHED " /tmp/tp-probe.log || { echo "PROBE-ATTACH-TIMEOUT"; cat /tmp/tp-probe.log; exit 1; }
cat /tmp/tp-probe.log
exec 9>&-
wait "$PROBE_PID"
[ $? = 0 ] || { echo "PROBE-DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/tp-probe.log || { echo "PROBE-DETACH-MARKER-MISSING"; exit 1; }
echo "real event: attachable"
rm -f /sys/fs/bpf/tp_probe probe-rel

run_phase() {
  # run_phase <label> <object> <pin> <phase> <filter-mode>
  # filter-mode: monitored | bogus. Prints <label> lines; fails loudly.
  LABEL="$1"; OBJECT="$2"; PIN="$3"; PHASE="$4"; FILTER_MODE="$5"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || { echo "$LABEL-MAPDIR-FAILED"; exit 1; }
  "$BPFTOOL" prog load "$OBJECT" "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/tp-$LABEL.load" 2>&1
  [ $? = 0 ] || { echo "$LABEL-LOAD-FAILED"; cat "/tmp/tp-$LABEL.load"; exit 1; }
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  [ -e "$MAP_PIN" ] || { echo "$LABEL-MAP-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }
  MAP_ID=$("$BPFTOOL" -j map show pinned "$MAP_PIN" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  echo "$LABEL-map-id: $MAP_ID"
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  mkfifo "$LABEL-rel" "$LABEL-go" "$LABEL-done"
  "./tracepoint_attach" "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/tp-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$MONITORED_N" --excluded "$EXCLUDED_M" --phase "$PHASE" --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/tp-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/tp-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/tp-$LABEL.holder.log" || { echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/tp-$LABEL.holder.log"; exit 1; }
  [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] || { echo "$LABEL-TID-TIMEOUT"; cat "$LABEL-tids" 2>/dev/null; cat "/tmp/tp-$LABEL.wl.log"; exit 1; }
  MON_TID=$(awk '$1=="monitored"{print $2}' "$LABEL-tids")
  OBS_TID=$(awk '$1=="observer"{print $2}' "$LABEL-tids")
  echo "$LABEL-tids: $(tr '\n' ';' < "$LABEL-tids")"
  [ "$MON_TID" != "$OBS_TID" ] || { echo "$LABEL-OBSERVER-NOT-OUTSIDE"; exit 1; }
  if [ "$FILTER_MODE" = "bogus" ]; then FILTER_TID="$BOGUS_TID"; else FILTER_TID="$MON_TID"; fi
  map_set_u64 "$MAP_PIN" 0 "$FILTER_TID" || { echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 1 0 || { echo "$LABEL-COUNT-INIT-FAILED"; exit 1; }
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "$LABEL-filter: want=$FILTER_TID readback=$FILTER_READ"
  [ "$FILTER_READ" = "$FILTER_TID" ] || { echo "$LABEL-FILTER-READBACK-MISMATCH"; exit 1; }
  timeout 60 bash -c "echo go > $LABEL-go" || { echo "$LABEL-GO-TIMEOUT"; exit 1; }
  DONE_LINE=$(timeout 120 cat "$LABEL-done") || { echo "$LABEL-DONE-TIMEOUT"; exit 1; }
  echo "$LABEL-done: $DONE_LINE"
  wait "$WL_PID"
  [ $? = 0 ] || { echo "$LABEL-WORKLOAD-FAILED"; cat "/tmp/tp-$LABEL.wl.log"; exit 1; }
  COUNT=$(map_u64 "$MAP_PIN" 1)
  echo "$LABEL-counter: $COUNT"
  exec 8>&-
  wait "$HOLDER_PID"
  [ $? = 0 ] || { echo "$LABEL-DETACH-FAILED"; exit 1; }
  grep -q "^DETACHED$" "/tmp/tp-$LABEL.holder.log" || { echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }
  rm -f "$PIN" "$MAP_PIN"
  rmdir "$MAP_DIR" || { echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
}

run_phase excluded trace.bpf.o /sys/fs/bpf/tp_excluded excluded monitored
run_phase exact trace.bpf.o /sys/fs/bpf/tp_exact full monitored
run_phase wrongfilter trace.bpf.o /sys/fs/bpf/tp_wrong full bogus
run_phase mutant mutant.bpf.o /sys/fs/bpf/tp_mutant full monitored
run_phase stale trace.bpf.o /sys/fs/bpf/tp_stale full monitored

echo "--- stray check ---"
# Freed objects drain asynchronously; wait for the pre-run
# baseline to return (bounded, fails loudly) before comparing.
for _ in $(seq 1 600); do
  PINS_AFTER=$(ls /sys/fs/bpf/)
  LINKS_AFTER=$("$BPFTOOL" link show)
  PROGS_AFTER=$("$BPFTOOL" prog show)
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
echo "=== end tracepoint ==="
"""

_RESULT = None
_STAGE = None
_ATTEMPT_ERROR = None


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


def executed():
    """Boot one guest and run every phase; cache the transcript.

    The attempt outcome is recorded: a failure raises the
    recorded error on later calls instead of rerunning the
    guest solely to recover finish evidence (the failed
    attempt's stage stays preserved in _STAGE).
    """
    global _ATTEMPT_ERROR
    if _RESULT is not None:
        return _RESULT
    if _ATTEMPT_ERROR is not None:
        raise _ATTEMPT_ERROR
    try:
        return _executed_once()
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        ProofFailure, AssertionError, subprocess.TimeoutExpired,
        guest_proc.TargetLeaseRequired,
        tool_admission.ToolAdmissionError,
    ) as exc:
        _ATTEMPT_ERROR = exc
        raise


def _executed_once():
    """Run the single guest attempt; see executed()."""
    global _RESULT, _STAGE
    check_tools("mojo", "llc", "cc", "bpftool", "vng")
    for path in (
        COUNTER_SOURCE, MUTANT_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    release = vng_release()
    workdir = guest_proc.owned_stage(prefix="mojo-tracepoint-")
    base_obj = build_object(
        COUNTER_SOURCE, workdir, "trace", TRACEPOINT_OBJECT_HASH
    )
    mutant_obj = build_object(
        MUTANT_SOURCE, workdir, "mutant", MUTANT_OBJECT_HASH
    )
    workload = build_harness(
        WORKLOAD_SOURCE, os.path.join(workdir, "syscall_workload"),
        ("-pthread",),
    )
    holder = build_harness(
        HOLDER_SOURCE, os.path.join(workdir, "tracepoint_attach")
    )
    # Lease before staging, after builds: an unleased run
    # refuses here, never as an admission failure.
    guest_proc.require_target_lease("tracepoint")
    try:
        pins = tool_admission.stage_tool_pins(
            {"PATH": os.environ.get("PATH", "")}
        )
    except tool_admission.ToolMissingError as exc:
        raise EnvironmentFailure(str(exc))
    prologue = (
        tool_admission.render_prologue(pins)
        + "\n"
        + tool_admission.render_guest_mount()
    )
    stage = guest_proc.owned_stage(prefix="mojo-tracepoint-", dir="/tmp")
    # Preserve immediately: a failure below must still
    # finalize this stage, never stage_dir=None.
    _STAGE = stage
    staged_script = os.path.join(stage, "guest_tracepoint.sh")
    script = (
        GUEST_SCRIPT.replace("__STAGE__", stage)
        .replace("__MONITORED_N__", str(MONITORED_N))
        .replace("__EXCLUDED_M__", str(EXCLUDED_M))
        .replace("__BOGUS_TID__", str(BOGUS_TID))
        .replace("__BPFTOOL_PROLOGUE__", prologue)
    )
    with open(staged_script, "w", encoding="utf-8") as handle:
        handle.write(script)
    for source, name in (
        (base_obj, "trace.bpf.o"),
        (mutant_obj, "mutant.bpf.o"),
        (workload, "syscall_workload"),
        (holder, "tracepoint_attach"),
    ):
        guest_proc.copy_consumed(source, os.path.join(stage, name))
    os.chmod(stage, 0o755)
    for name in (
        "guest_tracepoint.sh", "trace.bpf.o", "mutant.bpf.o",
        "syscall_workload", "tracepoint_attach",
    ):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "syscall_workload"), 0o755)
    os.chmod(os.path.join(stage, "tracepoint_attach"), 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the provenance case
    # compares guest-reported hashes against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        ("guest_tracepoint.sh", "trace.bpf.o", "mutant.bpf.o",
         "syscall_workload", "tracepoint_attach"),
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
        progress_banner="=== begin tracepoint ===",
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
    for marker in ("=== end tracepoint ===", "cleanup: proven"):
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
    return _RESULT


def phase_lines(output, label):
    """Parse one run_phase block into a dict of its observations."""
    found = {}
    for line in output.splitlines():
        if not line.startswith(label + "-"):
            continue
        key, _, value = line[len(label) + 1:].partition(": ")
        found[key] = value.strip()
    for key in ("tids", "done", "counter", "filter"):
        if key not in found:
            raise ProofFailure(
                "phase %s is missing %s in:\n%s"
                % (label, key, output[-4000:])
            )
    return found


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


def test_excluded_phase_zero():
    output = executed()
    phase = phase_lines(output, "excluded")
    tids = phase_tids(phase["tids"])
    assert tids["monitored"] != tids["observer"]
    assert phase["done"] == (
        "DONE monitored=0 excl1=%d excl2=%d" % (EXCLUDED_M, EXCLUDED_M)
    ), phase["done"]
    assert phase["filter"] == "want=%s readback=%s" % (
        tids["monitored"], tids["monitored"],
    ), phase["filter"]
    assert phase["counter"] == "0", (
        "excluded workers must leave the counter at 0, got %s"
        % phase["counter"]
    )
    print(
        "PASS excluded phase: 2x%d foreign getpid calls counted 0"
        % EXCLUDED_M
    )


def test_exact_count():
    output = executed()
    phase = phase_lines(output, "exact")
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (MONITORED_N, EXCLUDED_M, EXCLUDED_M)
    ), phase["done"]
    assert phase["filter"] == "want=%s readback=%s" % (
        tids["monitored"], tids["monitored"],
    ), phase["filter"]
    assert phase["counter"] == str(MONITORED_N), (
        "expected exactly %d, observed %s"
        % (MONITORED_N, phase["counter"])
    )
    print("PASS exact count: %d monitored calls counted %d"
          % (MONITORED_N, MONITORED_N))


def test_missing_tracepoint_unavailability():
    output = executed()
    assert "unavailability: proven" in output
    assert "IDFAIL syscalls:sys_enter_no_such_event" in output
    assert "unavail-holder-exit: 1" in output
    assert "real event: attachable" in output
    print("PASS missing tracepoint reports environment-unavailability")


def test_wrong_filter_mismatch():
    output = executed()
    phase = phase_lines(output, "wrongfilter")
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (MONITORED_N, EXCLUDED_M, EXCLUDED_M)
    ), phase["done"]
    assert phase["filter"] == "want=%d readback=%d" % (
        BOGUS_TID, BOGUS_TID,
    ), phase["filter"]
    assert BOGUS_TID != int(tids["monitored"])
    assert phase["counter"] == "0", phase["counter"]
    assert phase["counter"] != str(MONITORED_N), (
        "wrong-filter run must mismatch N=%d, got %s"
        % (MONITORED_N, phase["counter"])
    )
    print(
        "PASS wrong filter: bogus TID observes 0 against N=%d "
        "(controlled mismatch)" % MONITORED_N
    )


def test_tgid_mutant_mismatch_and_stale_base():
    output = executed()
    mutant = phase_lines(output, "mutant")
    stale = phase_lines(output, "stale")
    mutant_tids = phase_tids(mutant["tids"])
    stale_tids = phase_tids(stale["tids"])
    assert mutant["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (MONITORED_N, EXCLUDED_M, EXCLUDED_M)
    ), mutant["done"]
    assert mutant["filter"] == "want=%s readback=%s" % (
        mutant_tids["monitored"], mutant_tids["monitored"],
    ), mutant["filter"]
    assert mutant["counter"] == "0", (
        "TGID mutant must observe 0, got %s" % mutant["counter"]
    )
    assert stale["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (MONITORED_N, EXCLUDED_M, EXCLUDED_M)
    ), stale["done"]
    assert stale["counter"] == str(MONITORED_N), (
        "reloaded base must still observe %d, got %s"
        % (MONITORED_N, stale["counter"])
    )
    assert stale["counter"] != mutant["counter"], (
        "stale base (%s) must fail the mutant expectation (%s)"
        % (stale["counter"], mutant["counter"])
    )
    print(
        "PASS TGID mutant observes 0, reloaded base observes %d"
        % MONITORED_N
    )


def test_guest_provenance():
    output = executed()
    stage = _STAGE
    assert stage is not None, "guest stage must be preserved"
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(output)
    for name in (
        "guest_tracepoint.sh",
        "trace.bpf.o",
        "mutant.bpf.o",
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


def guest_kernel(output):
    """Guest kernel release from the transcript (lane identity)."""
    for line in output.splitlines():
        if line.startswith("guest-kernel:"):
            return line.split("guest-kernel:")[1].strip()
    raise ProofFailure("guest transcript has no kernel line")


def guest_nproc(output):
    """Guest CPU count from the transcript (SMP-ness record)."""
    for line in output.splitlines():
        if line.startswith("guest-nproc:"):
            value = line.split("guest-nproc:")[1].strip()
            if re.fullmatch(r"[1-9][0-9]*", value):
                return int(value)
    raise ProofFailure("guest transcript has no valid nproc line")


def print_board(output):
    """Print the per-phase observation board from the transcript."""
    release = vng_release()
    print(
        "guest: %s kernel %s nproc %d"
        % (release, guest_kernel(output), guest_nproc(output))
    )
    print(
        "staged objects: trace=%s mutant=%s"
        % (TRACEPOINT_OBJECT_HASH[:16], MUTANT_OBJECT_HASH[:16])
    )
    print(
        "staged sources: workload=%s holder=%s"
        % (
            sha256_file(WORKLOAD_SOURCE)[:16],
            sha256_file(HOLDER_SOURCE)[:16],
        )
    )
    for label in ("excluded", "exact", "wrongfilter", "mutant", "stale"):
        phase = phase_lines(output, label)
        print(
            "board %s: counter=%s done=[%s] filter=[%s] tids=[%s]"
            % (
                label,
                phase["counter"],
                phase["done"],
                phase["filter"],
                phase["tids"],
            )
        )


CASE_NAMES = (
    "test_excluded_phase_zero",
    "test_exact_count",
    "test_missing_tracepoint_unavailability",
    "test_wrong_filter_mismatch",
    "test_tgid_mutant_mismatch_and_stale_base",
    "test_guest_provenance",
)

# No denials: every case asserts exact guest behavior positively
# (the mismatch controls pass by observing their pinned zeros).
CASE_DENIALS = {}


# Durable inputs per case. executed() preserves the guest stage
# (_STAGE) and hands the closure off before any begin_case, so
# every transcript consumer declares the staged bytes it ran on;
# the TRACEPOINT_OBJECT_HASH/MUTANT_OBJECT_HASH pins asserted at
# build time commit the same bytes independently.
CASE_INPUTS = {
    "test_excluded_phase_zero": {
        "sources": [COUNTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_tracepoint.sh")],
        "objects": [("stage", "trace.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_exact_count": {
        "sources": [COUNTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_tracepoint.sh")],
        "objects": [("stage", "trace.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_missing_tracepoint_unavailability": {
        "sources": [COUNTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_tracepoint.sh")],
        "objects": [("stage", "trace.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_wrong_filter_mismatch": {
        "sources": [COUNTER_SOURCE, WORKLOAD_SOURCE, HOLDER_SOURCE,
                    ("stage", "guest_tracepoint.sh")],
        "objects": [("stage", "trace.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_tgid_mutant_mismatch_and_stale_base": {
        "sources": [
            COUNTER_SOURCE, MUTANT_SOURCE, WORKLOAD_SOURCE,
            HOLDER_SOURCE,
            ("stage", "guest_tracepoint.sh"),
        ],
        "objects": [("stage", "trace.bpf.o"),
                    ("stage", "mutant.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [
            COUNTER_SOURCE, MUTANT_SOURCE, WORKLOAD_SOURCE,
            HOLDER_SOURCE,
            ("stage", "guest_tracepoint.sh"),
        ],
        "objects": [("stage", "trace.bpf.o"),
                    ("stage", "mutant.bpf.o"),
                    ("stage", "syscall_workload"),
                    ("stage", "tracepoint_attach")],
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
    except guest_proc.TargetLeaseRequired as exc:
        # A cached lease refusal finalizes explicitly as
        # lease-gated unavailable (A1M4-4): the class would
        # otherwise only be caught implicitly through its
        # AssertionError base.
        print("REQUIRED-UNAVAILABLE executed: %s" % exc)
        code = rec.finish(stage_dir=_STAGE, unavailable_seen=True)
        guest_proc.discard_owned_stages()
        return code
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        tool_admission.ToolAdmissionError, ProofFailure,
        AssertionError, subprocess.TimeoutExpired,
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
            suite_id="kernel-tracepoint", suite_path=__file__,
            case_ids=list(CASE_NAMES) + ["board"],
            denials=CASE_DENIALS, inputs=CASE_INPUTS,
            lane_release="v6.12")
        # The lane is invalid, so nothing can run; the nominal
        # default lane lets the refusal seal a terminal record
        # (matrix runs always set a valid lane and embed the
        # matrix target instead).
        return rec.finish_unrun("invalid lane: %s" % exc)
    rec = guest_proc.SuiteRecorder(
        suite_id="kernel-tracepoint", suite_path=__file__,
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
    unavailable_seen = False
    try:
        output = executed()
    except guest_proc.HarnessEnvironment as exc:
        print("ENVIRONMENT FAILURE in executed: %s" % exc)
        rec.begin_case(CASE_NAMES[0])
        rec.end_case_infra(
            CASE_NAMES[0], exc.stage, exc.availability
        )
        return _finish(rec, unavailable_seen)
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE in executed: %s" % exc)
        rec.begin_case(CASE_NAMES[0])
        rec.end_case_infra(CASE_NAMES[0], "INFRA", "UNKNOWN")
        return _finish(rec, unavailable_seen)
    except subprocess.TimeoutExpired as exc:
        print("ENVIRONMENT FAILURE in executed: timed out: %s" % exc)
        rec.begin_case(CASE_NAMES[0])
        rec.end_case_infra(
            CASE_NAMES[0], "INFRA", "TOOLCHAIN_UNAVAILABLE"
        )
        return _finish(rec, unavailable_seen)
    except guest_proc.TargetLeaseRequired as exc:
        print("REQUIRED-UNAVAILABLE executed: %s" % exc)
        for pending in list(CASE_NAMES) + ["board"]:
            rec.begin_case(pending)
            rec.end_case_not_run(pending, "TARGET_RESOURCE_ABSENT")
        return _finish(rec, True)
    except tool_admission.ToolAdmissionError as exc:
        print("ADMISSION FAILURE in executed: %s" % exc)
        rec.begin_case(CASE_NAMES[0])
        rec.end_case_fail(CASE_NAMES[0])
        return _finish(rec, unavailable_seen)
    except (AssertionError, ProofFailure) as exc:
        # A cached handoff refusal (AssertionError) finalizes
        # here like a proof failure: a formal FAIL on the
        # preserved attempt, never an escape before case
        # recording (A1M4-4). The lease arm above stays first:
        # lease refusal is an AssertionError subclass and must
        # keep its required-unavailable report.
        print("FAIL executed: %s" % exc)
        rec.begin_case(CASE_NAMES[0])
        rec.end_case_fail(CASE_NAMES[0])
        return _finish(rec, unavailable_seen)
    failures = 0
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
        except tool_admission.ToolAdmissionError as exc:
            print("ADMISSION FAILURE in %s: %s" % (name, exc))
            rec.end_case_fail(name)
            failures += 1
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
        print_board(output)
    except guest_proc.HarnessEnvironment as exc:
        print("ENVIRONMENT FAILURE in board: %s" % exc)
        rec.end_case_infra(
            "board", exc.stage, exc.availability
        )
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
    except tool_admission.ToolAdmissionError as exc:
        print("ADMISSION FAILURE in board: %s" % exc)
        rec.end_case_fail("board")
        return _finish(rec, unavailable_seen)
    except (AssertionError, ProofFailure) as exc:
        print("FAIL board: %s" % exc)
        rec.end_case_fail("board")
        return _finish(rec, unavailable_seen)
    print("PASS board")
    rec.end_case_pass("board")
    print(
        "tracepoint counter: exact %d + excluded zeros + mismatch "
        "controls in one %s guest" % (MONITORED_N, release)
    )
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
