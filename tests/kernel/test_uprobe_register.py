# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Kernel proof for the controlled uprobe register counter (vng guest suite).

Attaches the Mojo-built uprobe counter to the suite-owned test
executable inside a disposable vng guest and proves the probe
observes exactly the probed calls with the extracted register
value matching an independent oracle:

* match: N calls carrying the expected argument value are
  counted exactly N, with every oracle word equal to the value
  the suite requested;
* mismatch: M calls carrying a different value leave the counter
  at 0, with every oracle word equal to the other value (the
  probe distinguishes values; it does not count hits blindly);
* inverted: the inverted mutant counts exactly the M mismatching
  calls, proving the suite reads live kernel state and the
  mutant is behaviorally distinct;
* reload: the reloaded base object counts exactly N again;
* never: a probe attached to the never-called symbol observes 0
  while the workload's N calls proceed normally;
* unavailability: a guest without the tracefs uprobe interface
  reports the environment-capability failure accurately (never a
  pass, never a proof failure);
* bad-offset: an out-of-range probe offset fails the perf open
  loudly (the file-offset resolution rule is load-bearing);
* verifier: the out-of-bounds context mutant clears host
  inspection but the kernel verifier rejects it with the pinned
  line, proving the audit's register pin matters;
* residue: no leaked pins, links, programs, maps, or tracefs
  events against the boot baseline.

The attach target is always the suite-owned test executable
staged by this suite: the holder resolves the binary path and
refuses anything outside the stage directory (NOTESTBIN) before
touching tracefs, and the host suite proves that refusal
directly. No system binary is ever named; no host process is
ever attached to. Only the vng guest performs BPF loads and
uprobes attaches; the host only builds and stages.

The guest release comes from ``MOJOBPF_VNG_RELEASE`` (``v6.12``
by default); the guest kernel must match the requested lane or
the suite fails. The runner boots the guest as a session leader
and kills the whole owned guest tree on timeout (the matrix
runner's owned-process-tracking composition, kept local so the
suite stays directly runnable).

Requires mojo, llc, cc, bpftool, vng, readelf, and nm on PATH. A
missing tool, an unbootable guest, or a guest without the kprobe
program type or the tracefs uprobe interface is reported as an
environment failure; anything else that fails is a proof
failure. Neither ever passes.

Runnable directly (``python3
tests/kernel/test_uprobe_register.py``) or under any
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
import lane_lock  # noqa: E402
import guest_proc  # noqa: E402
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
COUNTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "uprobe_counter", "counter.mojo"
)
MUTANT_SOURCE = os.path.join(
    REPO_ROOT,
    "examples",
    "uprobe_counter",
    "counter_inverted_mutated.mojo",
)
TARGET_SOURCE = os.path.join(
    REPO_ROOT, "examples", "uprobe_counter", "target.c"
)
HOLDER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "uprobe_attach.c"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Qualified object bytes (independent direct-path pins; the
# structure suite pins the same bytes).
UPROBE_OBJECT_HASH = (
    "efdc0af7f50f27d45494135bbb2715200701c337f3686f2381c11b71c0e6b7aa"
)
MUTANT_OBJECT_HASH = (
    "4ed4c334b1f8e0d3be6a14a7fff72419d818b16ef69b85288cf47a366fdacb1e"
)
ADV_CTX_OBJECT_HASH = (
    "37897da0b30efcf2ffd7ddce1b285b57bb2562ecb7a130c79c1c71520b3ed228"
)

# The out-of-bounds context mutant: one textual replacement over
# a copy of the adapted IR (anchor count asserted), compiled
# with llc. The mutant IR never passes through the adapter: it
# is test provenance, not a tool output. The injected word
# (14000, byte 112000) lies outside the kernel's uprobe context,
# so the verifier must reject the load.
ADV_MUTANT = (
    "adv_ctx_oob",
    (
        (
            "getelementptr inbounds i64, ptr %0, i32 14",
            "getelementptr inbounds i64, ptr %0, i32 14000",
            1,
        ),
    ),
    "getelementptr inbounds i64, ptr %0, i32 14000",
)
ADV_CTX_REJECT_LINE = (
    "dereference of modified ctx ptr R1 off=112000 disallowed"
)

PROFILE = "linux-bpfel-v3-uprobe"
MATCH_N = 1000
MISMATCH_M = 500
EXPECTED_ARG = 41
OTHER_ARG = 43
VNG_TIMEOUT = 1200


class EnvironmentFailure(Exception):
    """The guest, lane, or toolchain is missing, broken, or incapable."""


class ProofFailure(Exception):
    """The proof failed: the product did not behave as specified."""


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


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
def build_mutant_object(source, workdir, tag, want_hash):
    """Build the kernel-negative object from hand-mutated IR."""
    raw_path = os.path.join(workdir, "%s.ll" % tag)
    adapted_path = os.path.join(workdir, "%s.bpf.ll" % tag)
    mutant_path = os.path.join(workdir, "%s.mutant.bpf.ll" % tag)
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
    with guest_proc.open_consumed(adapted_path, encoding="utf-8") as handle:
        adapted = handle.read()
    name, replacements, injected = ADV_MUTANT
    for old, new, expected in replacements:
        found = adapted.count(old)
        if found != expected:
            raise ProofFailure(
                "mutant %s: anchor found %d times, expected %d "
                "(adapted IR drifted)" % (name, found, expected)
            )
        adapted = adapted.replace(old, new)
    if injected not in adapted:
        raise ProofFailure(
            "mutant %s: injected address missing" % name
        )
    with open(mutant_path, "w", encoding="utf-8") as handle:
        handle.write(adapted)
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
            mutant_path, "-o", object_path,
        ]
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "backend failed for mutant %s: exit=%d stderr=%r"
            % (name, proc.returncode, proc.stderr[-1000:])
        )
    observed = sha256_file(object_path)
    if observed != want_hash:
        raise ProofFailure(
            "staged %s bytes %s do not match the qualified %s"
            % (tag, observed, want_hash)
        )
    return object_path


@guest_proc.consumes_source
def build_target(source, output):
    """Compile the test executable: non-PIE, warnings fatal."""
    proc = run_step(
        [
            "cc", "-no-pie", "-fno-pie", "-O2", "-Wall", "-Wextra",
            "-o", output, source,
        ]
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "target build failed for %s: exit=%d stderr=%r"
            % (source, proc.returncode, proc.stderr[-2000:])
        )
    return output


@guest_proc.consumes_source
def build_holder(source, output):
    """Compile the attach holder with warnings fatal."""
    proc = run_step(
        ["cc", "-O2", "-Wall", "-Wextra", "-o", output, source]
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "holder build failed for %s: exit=%d stderr=%r"
            % (source, proc.returncode, proc.stderr[-2000:])
        )
    return output


def crosscheck_nm_values(target_path, values):
    """Cross-check readelf symbol values against ``nm`` output.

    ``values`` maps both probe names to their readelf ``st_value``.
    Refuses a failed ``nm`` run, missing or non-text symbols, and
    any address disagreement: the two tools must name the same
    bytes.
    """
    check = run_step(["nm", target_path])
    if check.returncode != 0:
        raise ProofFailure("nm failed: %s" % check.stderr[-500:])
    nm_values = {}
    for line in check.stdout.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        if parts[2] not in ("probe_target", "probe_never_called"):
            continue
        if parts[1] != "T":
            raise ProofFailure(
                "nm must show %s as global text, found: %s"
                % (parts[2], line.strip())
            )
        nm_values[parts[2]] = int(parts[0], 16)
    if set(nm_values) != {"probe_target", "probe_never_called"}:
        raise ProofFailure(
            "nm is missing probe symbols: %r" % (nm_values,)
        )
    for name in nm_values:
        if nm_values[name] != values[name]:
            raise ProofFailure(
                "nm/readelf disagree on %s: nm=0x%x readelf=0x%x"
                % (name, nm_values[name], values[name])
            )


def resolve_target_offsets(target_path):
    """Resolve probe file offsets from the staged binary bytes.

    Returns ``{"probe_target": "0x..", "probe_never_called":
    "0x.."}`` with FILE offsets (symbol value mapped through its
    section headers). Refuses anything but a non-PIE executable
    whose symbols both live in ``.text``: the suite attaches to
    its own bytes only, and the offset rule is pinned here, not
    guessed in the guest. ``nm`` cross-checks both readelf values.
    """
    header = run_step(["readelf", "-h", "-W", target_path])
    if header.returncode != 0:
        raise ProofFailure(
            "readelf -h failed: %s" % header.stderr[-500:]
        )
    if "Type: EXEC" not in header.stdout.replace(
        "(Executable file)", ""
    ) and "EXEC" not in header.stdout:
        raise ProofFailure(
            "test executable must be non-PIE (ET_EXEC):\n%s"
            % header.stdout
        )
    sections = run_step(["readelf", "-S", "-W", target_path])
    if sections.returncode != 0:
        raise ProofFailure(
            "readelf -S failed: %s" % sections.stderr[-500:]
        )
    section_map = {}
    for line in sections.stdout.splitlines():
        match = re.match(
            r"\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)",
            line,
        )
        if match:
            section_map[int(match.group(1))] = (
                match.group(2),
                int(match.group(3), 16),
                int(match.group(4), 16),
            )
    symbols = run_step(["readelf", "-s", "-W", target_path])
    if symbols.returncode != 0:
        raise ProofFailure(
            "readelf -s failed: %s" % symbols.stderr[-500:]
        )
    offsets = {}
    values = {}
    for line in symbols.stdout.splitlines():
        match = re.match(
            r"\s*\d+:\s+([0-9a-f]+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+"
            r"(\d+)\s+(\S+)",
            line,
        )
        if not match:
            continue
        value, sym_type, bind, ndx, name = (
            int(match.group(1), 16),
            match.group(2),
            match.group(3),
            int(match.group(4)),
            match.group(5),
        )
        if name not in ("probe_target", "probe_never_called"):
            continue
        if sym_type != "FUNC" or bind != "GLOBAL":
            raise ProofFailure(
                "probe symbol %s must be a global function: %s"
                % (name, line.strip())
            )
        if ndx not in section_map:
            raise ProofFailure(
                "probe symbol %s has no section: %s"
                % (name, line.strip())
            )
        section_name, vma, file_off = section_map[ndx]
        if section_name != ".text":
            raise ProofFailure(
                "probe symbol %s must live in .text, found %s"
                % (name, section_name)
            )
        offsets[name] = "0x%x" % (value - vma + file_off)
        values[name] = value
    if set(offsets) != {"probe_target", "probe_never_called"}:
        raise ProofFailure(
            "probe symbols missing from test executable: %r" % (offsets,)
        )
    if offsets["probe_target"] == offsets["probe_never_called"]:
        raise ProofFailure("probe symbols must be distinct")
    crosscheck_nm_values(target_path, values)
    return offsets


def _run_guest(argv, stage, timeout):
    """Run the guest command; return (exit code, output text).

    Thin mapping over the shared owned runner
    (tests/harness/guest_proc.py): a timeout surfaces as
    EnvironmentFailure carrying the partial output.
    """
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "guest run timed out after %ds (stage %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


GUEST_SCRIPT = r"""#!/bin/bash
# Uprobe register guest proof. Every phase loads its object with
# bpftool (the libbpf-consumability proof), attaches with the
# owned holder over a release FIFO to one symbol of the
# suite-owned test executable, drives one workload run whose
# every call reports its argument over an oracle FIFO, reads the
# counter quiescently, detaches, and unloads. Blocking waits
# carry timeouts that fail loudly; nothing here assumes a fixed
# sleep.
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="__STAGE__"
MATCH_N=__MATCH_N__
MISMATCH_M=__MISMATCH_M__
EXPECTED_ARG=__EXPECTED_ARG__
OTHER_ARG=__OTHER_ARG__
TARGET_OFFSET="__TARGET_OFFSET__"
NEVER_OFFSET="__NEVER_OFFSET__"
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin uprobe ==="
echo "guest-kernel: $(uname -r)"
echo "guest-nproc: $(nproc)"
bpftool version | head -1
echo "--- staged hashes ---"
sha256sum uprobe.bpf.o mutant.bpf.o advctx.bpf.o uprobe_target uprobe_attach guest_uprobe.sh
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
EVENTS_BEFORE=$(cat /sys/kernel/tracing/uprobe_events)
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

echo "--- preflight ---"
bpftool feature probe kernel >feature.txt 2>&1
grep -q "eBPF program_type kprobe is available" feature.txt || { echo "KPROBE-MISSING"; exit 3; }
[ -w /sys/kernel/tracing/uprobe_events ] || { echo "UPROBE-IFACE-MISSING"; exit 3; }
echo "preflight: kprobe + uprobe interface present"

echo "--- unavailability probe ---"
bpftool prog load uprobe.bpf.o /sys/fs/bpf/up_unavail type kprobe >/tmp/up-unavail.load 2>&1
[ $? = 0 ] || { echo "UNAVAIL-LOAD-FAILED"; cat /tmp/up-unavail.load; exit 1; }
timeout 60 unshare -m bash -c 'mount -t tmpfs uprobetmpfs /sys/kernel/tracing && exec ./uprobe_attach "$1" "$2" "$3" "$4" up_unavail' _ /sys/fs/bpf/up_unavail "$STAGE" "$STAGE/uprobe_target" "$TARGET_OFFSET" </dev/null >/tmp/up-unavail.log 2>&1
UNAVAIL_EXIT=$?
cat /tmp/up-unavail.log
echo "unavail-holder-exit: $UNAVAIL_EXIT"
grep -q "^NOUPROBE " /tmp/up-unavail.log || { echo "UNAVAIL-MARKER-MISSING"; exit 1; }
[ "$UNAVAIL_EXIT" = "1" ] || { echo "UNAVAIL-EXIT-MISMATCH"; exit 1; }
echo "unavailability: proven"
rm -f /sys/fs/bpf/up_unavail

echo "--- bad-offset probe ---"
bpftool prog load uprobe.bpf.o /sys/fs/bpf/up_badoff type kprobe >/tmp/up-badoff.load 2>&1
[ $? = 0 ] || { echo "BADOFF-LOAD-FAILED"; cat /tmp/up-badoff.load; exit 1; }
rm -f badoff-rel
mkfifo badoff-rel
./uprobe_attach /sys/fs/bpf/up_badoff "$STAGE" "$STAGE/uprobe_target" 0xffffff00 up_badoff <badoff-rel >/tmp/up-badoff.log 2>&1 &
BADOFF_PID=$!
exec 9<>badoff-rel
wait "$BADOFF_PID"
BADOFF_EXIT=$?
exec 9>&-
cat /tmp/up-badoff.log
echo "badoff-holder-exit: $BADOFF_EXIT"
grep -q "^PERFOPEN " /tmp/up-badoff.log || { echo "BADOFF-MARKER-MISSING"; exit 1; }
[ "$BADOFF_EXIT" = "1" ] || { echo "BADOFF-EXIT-MISMATCH"; exit 1; }
echo "bad-offset: proven"
rm -f /sys/fs/bpf/up_badoff badoff-rel

run_phase() {
  # run_phase <label> <object> <pin> <offset> <filter> <calls> <value>.
  # Prints <label> lines; fails loudly.
  LABEL="$1"; OBJECT="$2"; PIN="$3"; OFFSET="$4"; FILTER="$5"; CALLS="$6"; VALUE="$7"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || { echo "$LABEL-MAPDIR-FAILED"; exit 1; }
  bpftool prog load "$OBJECT" "$PIN" type kprobe pinmaps "$MAP_DIR/" >"/tmp/up-$LABEL.load" 2>&1
  [ $? = 0 ] || { echo "$LABEL-LOAD-FAILED"; cat "/tmp/up-$LABEL.load"; exit 1; }
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  [ -e "$MAP_PIN" ] || { echo "$LABEL-MAP-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-ora"
  mkfifo "$LABEL-rel" "$LABEL-ora"
  ./uprobe_attach "$PIN" "$STAGE" "$STAGE/uprobe_target" "$OFFSET" "up_$LABEL" <"$LABEL-rel" >"/tmp/up-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/up-$LABEL.holder.log" 2>/dev/null && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/up-$LABEL.holder.log" || { echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/up-$LABEL.holder.log"; exit 1; }
  map_set_u64 "$MAP_PIN" 0 "$FILTER" || { echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }
  map_set_u64 "$MAP_PIN" 1 0 || { echo "$LABEL-COUNT-INIT-FAILED"; exit 1; }
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "$LABEL-filter: want=$FILTER readback=$FILTER_READ"
  [ "$FILTER_READ" = "$FILTER" ] || { echo "$LABEL-FILTER-READBACK-MISMATCH"; exit 1; }
  timeout 300 python3 - "$LABEL" "$CALLS" "$VALUE" <<'PYEOF' || { echo "$LABEL-ORACLE-FAILED"; exit 1; }
import struct, subprocess, sys
label, calls, value = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
proc = subprocess.Popen(['./uprobe_target', str(calls), str(value), label + '-ora'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
with open(label + '-ora', 'rb') as reader:
    data = reader.read()
out, err = proc.communicate()
print('%s-target-exit: %d' % (label, proc.returncode))
print('%s-target-out: %s %s' % (label, out.strip(), err.strip()))
if proc.returncode != 0:
    sys.exit(1)
words = struct.unpack('<%dQ' % (len(data) // 8), data) if data else ()
print('%s-oracle: n=%d distinct=%s' % (label, len(words), sorted(set(words))))
PYEOF
  COUNT=$(map_u64 "$MAP_PIN" 1)
  echo "$LABEL-counter: $COUNT"
  exec 8>&-
  wait "$HOLDER_PID"
  [ $? = 0 ] || { echo "$LABEL-DETACH-FAILED"; exit 1; }
  grep -q "^DETACHED$" "/tmp/up-$LABEL.holder.log" || { echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }
  rm -f "$PIN" "$MAP_PIN"
  rmdir "$MAP_DIR" || { echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }
  rm -f "$LABEL-rel" "$LABEL-ora"
}

run_phase match uprobe.bpf.o /sys/fs/bpf/up_match "$TARGET_OFFSET" "$EXPECTED_ARG" "$MATCH_N" "$EXPECTED_ARG"
run_phase mismatch uprobe.bpf.o /sys/fs/bpf/up_mismatch "$TARGET_OFFSET" "$EXPECTED_ARG" "$MISMATCH_M" "$OTHER_ARG"
run_phase inverted mutant.bpf.o /sys/fs/bpf/up_inverted "$TARGET_OFFSET" "$EXPECTED_ARG" "$MISMATCH_M" "$OTHER_ARG"
run_phase reload uprobe.bpf.o /sys/fs/bpf/up_reload "$TARGET_OFFSET" "$EXPECTED_ARG" "$MATCH_N" "$EXPECTED_ARG"
run_phase never uprobe.bpf.o /sys/fs/bpf/up_never "$NEVER_OFFSET" "$EXPECTED_ARG" "$MATCH_N" "$EXPECTED_ARG"

echo "--- vlog ---"
bpftool -d prog load uprobe.bpf.o /sys/fs/bpf/up_vlog type kprobe >/tmp/up-vlog.load 2>&1
[ $? = 0 ] || { echo "VLOG-LOAD-FAILED"; cat /tmp/up-vlog.load; exit 1; }
cat /tmp/up-vlog.load
rm -f /sys/fs/bpf/up_vlog
echo "vlog: captured"

echo "--- adv-ctx ---"
bpftool prog load advctx.bpf.o /sys/fs/bpf/up_advctx type kprobe pinmaps /sys/fs/bpf/up_advctx_maps/ >/tmp/up-advctx.load 2>&1
echo "advctx-load-exit: $?"
cat /tmp/up-advctx.load
grep -q "dereference of modified ctx ptr R1 off=112000 disallowed" /tmp/up-advctx.load || { echo "ADVCTX-MARKER-MISSING"; exit 1; }
[ -e /sys/fs/bpf/up_advctx ] && { echo "ADVCTX-PIN-LEAKED"; exit 1; }
rm -rf /sys/fs/bpf/up_advctx_maps
echo "adv-ctx: rejected"

echo "--- stray check ---"
# Freed objects drain asynchronously; wait for the pre-run
# baseline to return (bounded, fails loudly) before comparing.
for _ in $(seq 1 600); do
  PINS_AFTER=$(ls /sys/fs/bpf/)
  LINKS_AFTER=$(bpftool link show)
  PROGS_AFTER=$(bpftool prog show)
  MAPS_AFTER=$(map_show_filtered)
  EVENTS_AFTER=$(cat /sys/kernel/tracing/uprobe_events)
  [ "$PINS_AFTER" = "$PINS_BEFORE" ] && [ "$LINKS_AFTER" = "$LINKS_BEFORE" ] && [ "$PROGS_AFTER" = "$PROGS_BEFORE" ] && [ "$MAPS_AFTER" = "$MAPS_BEFORE" ] && [ "$EVENTS_AFTER" = "$EVENTS_BEFORE" ] && break
  sleep 0.1
done
echo "$PINS_AFTER"
echo "$LINKS_AFTER"
[ "$PINS_AFTER" = "$PINS_BEFORE" ] || { echo "STRAY-PINS"; exit 1; }
[ "$LINKS_AFTER" = "$LINKS_BEFORE" ] || { echo "STRAY-LINKS"; exit 1; }
[ "$PROGS_AFTER" = "$PROGS_BEFORE" ] || { echo "STRAY-PROGS"; exit 1; }
[ "$MAPS_AFTER" = "$MAPS_BEFORE" ] || { echo "STRAY-MAPS"; exit 1; }
[ "$EVENTS_AFTER" = "$EVENTS_BEFORE" ] || { echo "STRAY-EVENTS"; cat /sys/kernel/tracing/uprobe_events; exit 1; }
echo "cleanup: proven"
echo "=== end uprobe ==="
"""

_RESULT = None
_OFFSETS = None
_STAGE = None


def executed():
    """Boot one guest and run every phase; cache the transcript."""
    global _RESULT, _OFFSETS, _STAGE
    if _RESULT is not None:
        return _RESULT
    for tool in (
        "mojo", "llc", "cc", "bpftool", "vng", "readelf", "nm",
    ):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        COUNTER_SOURCE, MUTANT_SOURCE, TARGET_SOURCE, HOLDER_SOURCE,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    release = vng_release()
    workdir = guest_proc.owned_stage(prefix="mojo-uprobe-")
    base_obj = build_object(
        COUNTER_SOURCE, workdir, "uprobe", UPROBE_OBJECT_HASH
    )
    mutant_obj = build_object(
        MUTANT_SOURCE, workdir, "mutant", MUTANT_OBJECT_HASH
    )
    advctx_obj = build_mutant_object(
        COUNTER_SOURCE, workdir, "advctx", ADV_CTX_OBJECT_HASH
    )
    target = build_target(
        TARGET_SOURCE, os.path.join(workdir, "uprobe_target")
    )
    holder = build_holder(
        HOLDER_SOURCE, os.path.join(workdir, "uprobe_attach")
    )
    offsets = resolve_target_offsets(target)
    _OFFSETS = offsets
    stage = guest_proc.owned_stage(prefix="mojo-uprobe-", dir="/tmp")
    staged_script = os.path.join(stage, "guest_uprobe.sh")
    script = (
        GUEST_SCRIPT.replace("__STAGE__", stage)
        .replace("__MATCH_N__", str(MATCH_N))
        .replace("__MISMATCH_M__", str(MISMATCH_M))
        .replace("__EXPECTED_ARG__", str(EXPECTED_ARG))
        .replace("__OTHER_ARG__", str(OTHER_ARG))
        .replace("__TARGET_OFFSET__", offsets["probe_target"])
        .replace("__NEVER_OFFSET__", offsets["probe_never_called"])
    )
    with open(staged_script, "w", encoding="utf-8") as handle:
        handle.write(script)
    for source, name in (
        (base_obj, "uprobe.bpf.o"),
        (mutant_obj, "mutant.bpf.o"),
        (advctx_obj, "advctx.bpf.o"),
        (target, "uprobe_target"),
        (holder, "uprobe_attach"),
    ):
        guest_proc.copy_consumed(source, os.path.join(stage, name))
    os.chmod(stage, 0o755)
    for name in (
        "guest_uprobe.sh", "uprobe.bpf.o", "mutant.bpf.o",
        "advctx.bpf.o", "uprobe_target", "uprobe_attach",
    ):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "uprobe_target"), 0o755)
    os.chmod(os.path.join(stage, "uprobe_attach"), 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(),
        stage,
        (
            "uprobe.bpf.o", "mutant.bpf.o", "advctx.bpf.o",
            "uprobe_target", "uprobe_attach",
            "guest_uprobe.sh",
        ),
    )
    exit_code, output = _run_guest(
        [
            "vng", "--run", release, "--disable-kvm",
            "--exec", "bash %s" % staged_script,
        ],
        stage,
        VNG_TIMEOUT,
    )
    if "KPROBE-MISSING" in output or "UPROBE-IFACE-MISSING" in output:
        raise EnvironmentFailure(
            "guest %s lacks the kprobe program type or the tracefs "
            "uprobe interface; stage %s" % (release, stage)
        )
    verdict = guest_proc.classify_guest_exit(
        exit_code, output,
        records=(),
        progress_banner="=== begin uprobe ===",
        product_markers=(
            "ADVCTX-MARKER-MISSING",
            "ADVCTX-PIN-LEAKED",
        ),
    )
    if verdict == "proof":
        raise ProofFailure(
            "guest %s failed with proof evidence (exit %d); "
            "stage %s\n%s"
            % (release, exit_code, stage, output[-6000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "guest %s failed (exit %d); stage %s\n%s"
            % (release, exit_code, stage, output[-6000:])
        )
    for marker in ("=== end uprobe ===", "cleanup: proven"):
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
        # The guest must report the consumed staged bytes; a
        # swap between the consumption seal and the guest's
        # reads fails here instead of executing unattested.
        reported = guest_proc.parse_reported_hashes(output)
        for name in (
            "uprobe.bpf.o", "mutant.bpf.o", "advctx.bpf.o",
            "uprobe_target", "uprobe_attach",
            "guest_uprobe.sh",
        ):
            expected = rec.consumed_staged_digest(name, stage)
            if expected is None or reported.get(name) != expected:
                raise ProofFailure(
                    "guest did not consume the sealed bytes of %s"
                    % name
                )
    _RESULT = output
    _STAGE = stage
    return _RESULT


def phase_lines(output, label):
    """Parse one run_phase block into a dict of its observations."""
    found = {}
    for line in output.splitlines():
        if not line.startswith(label + "-"):
            continue
        key, _, value = line[len(label) + 1:].partition(": ")
        found[key] = value.strip()
    for key in ("target-exit", "target-out", "oracle", "counter",
                "filter"):
        if key not in found:
            raise ProofFailure(
                "phase %s is missing %s in:\n%s"
                % (label, key, output[-4000:])
            )
    return found


def parse_oracle(field):
    """Parse ``n=<n> distinct=[..]``; return (n, distinct list)."""
    match = re.fullmatch(r"n=(\d+) distinct=\[(.*)\]", field)
    if not match:
        raise ProofFailure("unparseable oracle field: %r" % (field,))
    count = int(match.group(1))
    distinct = [
        int(chunk) for chunk in match.group(2).split(",") if chunk.strip()
    ]
    return count, distinct


def check_phase(label, calls, value):
    """Assert one phase's board: workload, oracle, filter, counter."""
    output = executed()
    phase = phase_lines(output, label)
    assert phase["target-exit"] == "0", (
        "%s: workload exit %s" % (label, phase["target-exit"])
    )
    assert phase["target-out"].startswith(
        "done calls=%d value=%d" % (calls, value)
    ), "%s: %r" % (label, phase["target-out"])
    count, distinct = parse_oracle(phase["oracle"])
    assert count == calls, (
        "%s: oracle reports %d calls, want %d"
        % (label, count, calls)
    )
    assert distinct == [value], (
        "%s: oracle words %r, want all %d"
        % (label, distinct, value)
    )
    assert phase["filter"] == "want=%d readback=%d" % (
        EXPECTED_ARG, EXPECTED_ARG,
    ), "%s: %r" % (label, phase["filter"])
    return phase


def test_match_exact_with_oracle():
    phase = check_phase("match", MATCH_N, EXPECTED_ARG)
    assert phase["counter"] == str(MATCH_N), (
        "expected exactly %d, observed %s"
        % (MATCH_N, phase["counter"])
    )
    print(
        "PASS match: %d calls x %d counted %d, oracle agrees"
        % (MATCH_N, EXPECTED_ARG, MATCH_N)
    )


def test_mismatch_zero_with_oracle():
    phase = check_phase("mismatch", MISMATCH_M, OTHER_ARG)
    assert phase["counter"] == "0", (
        "mismatching calls must leave the counter at 0, got %s"
        % phase["counter"]
    )
    print(
        "PASS mismatch: %d calls x %d counted 0, oracle agrees"
        % (MISMATCH_M, OTHER_ARG)
    )


def test_inverted_counts_mismatches():
    phase = check_phase("inverted", MISMATCH_M, OTHER_ARG)
    assert phase["counter"] == str(MISMATCH_M), (
        "inverted mutant must count the %d mismatches, got %s"
        % (MISMATCH_M, phase["counter"])
    )
    print(
        "PASS inverted: %d mismatching calls counted %d (live state)"
        % (MISMATCH_M, MISMATCH_M)
    )


def test_reload_live_state():
    phase = check_phase("reload", MATCH_N, EXPECTED_ARG)
    assert phase["counter"] == str(MATCH_N), (
        "reloaded base must count exactly %d, got %s"
        % (MATCH_N, phase["counter"])
    )
    print(
        "PASS reload: reloaded base counts %d again" % MATCH_N
    )


def test_never_called_zero():
    phase = check_phase("never", MATCH_N, EXPECTED_ARG)
    assert phase["counter"] == "0", (
        "probe on the never-called symbol must observe 0, got %s"
        % phase["counter"]
    )
    print(
        "PASS never-called: %d workload calls observed 0" % MATCH_N
    )


def test_unavailability_reported():
    output = executed()
    assert "unavailability: proven" in output
    assert "unavail-holder-exit: 1" in output
    assert "preflight: kprobe + uprobe interface present" in output
    print("PASS missing uprobe interface reports unavailability")


def test_bad_offset_refused():
    output = executed()
    assert "bad-offset: proven" in output
    assert "badoff-holder-exit: 1" in output
    assert "errno=22" in output, (
        "bad-offset perf open must fail EINVAL"
    )
    print("PASS out-of-range offset fails the perf open loudly")


def test_verifier_rejects_oob_context():
    output = executed()
    report = guest_proc.inspect_consumed(
        os.path.join(_STAGE, "advctx.bpf.o"),
        PROFILE,
    )
    assert report.ok is True, (
        "the out-of-bounds context mutant must clear host-side "
        "inspection so the kernel verifier is its first rejecting "
        "layer",
        report.to_dict(),
    )
    assert "adv-ctx: rejected" in output
    assert "advctx-load-exit: 255" in output, output[-2000:]
    assert ADV_CTX_REJECT_LINE in output
    print("PASS verifier rejects the out-of-bounds context read")


def test_vlog_captured():
    output = executed()
    assert "vlog: captured" in output
    assert "func#0 @0" in output, "verifier log must show one function"
    if vng_release() == "v6.6":
        assert "0: R1=ctx(off=0,imm=0) R10=fp0" in output
    else:
        assert "0: R1=ctx() R10=fp0" in output
    assert "0: (79) r6 = *(u64 *)(r1 +112)" in output, (
        "verifier log must show the pinned context-word load"
    )
    assert "processed 42 insns" in output, output[-2000:]
    assert "stack depth 16" in output, output[-2000:]
    print("PASS verifier log: ctx+112 load, 42 insns, stack depth 16")


def test_no_residue():
    output = executed()
    assert "cleanup: proven" in output
    print("PASS residue: pins/links/progs/maps/events equal before/after")


def test_holder_refuses_non_test_binary():
    workdir = tempfile.mkdtemp(prefix="mojo-uprobe-holder-")
    try:
        holder = build_holder(
            HOLDER_SOURCE, os.path.join(workdir, "uprobe_attach")
        )
        stage = tempfile.mkdtemp(prefix="mojo-uprobe-stage-")
        try:
            proc = run_step(
                [holder, "/sys/fs/bpf/nope", stage, "/bin/true",
                 "0x0", "up_refused"]
            )
            assert proc.returncode == 1, proc.returncode
            assert proc.stdout.startswith(
                "NOTESTBIN /bin/true"
            ), proc.stdout
            assert "uprobe_events" not in proc.stdout
        finally:
            shutil.rmtree(stage)
    finally:
        shutil.rmtree(workdir)
    print("PASS holder refuses a non-test-binary target (NOTESTBIN)")


def test_offsets_resolve_to_text():
    workdir = guest_proc.owned_stage(prefix="mojo-uprobe-offsets-")
    target = build_target(
        TARGET_SOURCE, os.path.join(workdir, "uprobe_target")
    )
    offsets = resolve_target_offsets(target)
    for name, offset in offsets.items():
        value = int(offset, 0)
        assert 0 < value < 0x10000, (name, offset)
    print(
        "PASS offsets resolve into .text: %s"
        % (", ".join(
            "%s=%s" % item for item in sorted(offsets.items())
        ),)
    )


def test_license_gate_and_preflight():
    import mojobpf.inspect as inspect_module

    from mojobpf.helpers import lookup_helper, profile_helper_ids
    from mojobpf.manifest import lookup_profile

    profile = lookup_profile(PROFILE)
    assert profile.helper_ids == (1, 2, 3, 5, 8, 14, 130), (
        profile.helper_ids,
    )
    assert profile_helper_ids(PROFILE) == (), (
        "the registry records only capability-profile helpers; "
        "the uprobe slice adds none"
    )
    for helper_id in (1, 2):
        entry = lookup_helper(helper_id)
        assert entry is not None, (helper_id,)
        assert entry.gpl_only is False, (helper_id,)
    inspect_module.preflight_helper_licenses(
        (1, 2), "Apache-2.0 WITH LLVM-exception", PROFILE
    )
    try:
        inspect_module.preflight_helper_licenses(
            (35,), "Apache-2.0 WITH LLVM-exception", PROFILE
        )
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF709", (exc.diagnostic,)
    else:
        raise AssertionError("expected the preflight to refuse helper 35")
    print("PASS license: preflight admits 1/2, refuses 35 (MBPF709)")


# No denials: every case asserts exact guest behavior positively.
CASE_DENIALS = {}


# Durable inputs per case: repo sources plus the staged objects
# each phase loads (resolved against the guest stage at finish).
CASE_INPUTS = {
    "test_match_exact_with_oracle": {
        "sources": [COUNTER_SOURCE, TARGET_SOURCE, HOLDER_SOURCE],
        "objects": [("stage", "uprobe.bpf.o")],
        "corpus": [],
    },
    "test_mismatch_zero_with_oracle": {
        "sources": [COUNTER_SOURCE, TARGET_SOURCE, HOLDER_SOURCE],
        "objects": [("stage", "uprobe.bpf.o")],
        "corpus": [],
    },
    "test_inverted_counts_mismatches": {
        "sources": [MUTANT_SOURCE, TARGET_SOURCE, HOLDER_SOURCE],
        "objects": [("stage", "mutant.bpf.o")],
        "corpus": [],
    },
    "test_reload_live_state": {
        "sources": [COUNTER_SOURCE, TARGET_SOURCE, HOLDER_SOURCE],
        "objects": [("stage", "uprobe.bpf.o")],
        "corpus": [],
    },
    "test_never_called_zero": {
        "sources": [COUNTER_SOURCE, TARGET_SOURCE, HOLDER_SOURCE],
        "objects": [("stage", "uprobe.bpf.o")],
        "corpus": [],
    },
    "test_unavailability_reported": {
        "sources": [COUNTER_SOURCE, TARGET_SOURCE, HOLDER_SOURCE],
        "objects": [("stage", "uprobe.bpf.o")],
        "corpus": [],
    },
    "test_bad_offset_refused": {
        "sources": [COUNTER_SOURCE, TARGET_SOURCE, HOLDER_SOURCE],
        "objects": [("stage", "uprobe.bpf.o")],
        "corpus": [],
    },
    "test_verifier_rejects_oob_context": {
        "sources": [COUNTER_SOURCE],
        "objects": [("stage", "advctx.bpf.o")],
        "corpus": [],
    },
    "test_vlog_captured": {
        "sources": [COUNTER_SOURCE],
        "objects": [("stage", "uprobe.bpf.o")],
        "corpus": [],
    },
    "test_no_residue": {
        "sources": [COUNTER_SOURCE, MUTANT_SOURCE],
        "objects": [],
        "corpus": [],
    },
    "test_holder_refuses_non_test_binary": {
        "sources": [HOLDER_SOURCE],
        "objects": [],
        "corpus": [],
    },
    "test_offsets_resolve_to_text": {
        "sources": [TARGET_SOURCE],
        "objects": [],
        "corpus": [],
    },
    "test_license_gate_and_preflight": {
        # A1: implementation evidence (imported before any recorder
        # exists), never execution attestation.
        "sources": [
            ("impl", os.path.join(
                REPO_ROOT, "src", "mojobpf", "helpers.py")),
            ("impl", os.path.join(
                REPO_ROOT, "src", "mojobpf", "manifest.py")),
            ("impl", os.path.join(
                REPO_ROOT, "src", "mojobpf", "inspect.py")),
        ],
        "objects": [],
        "corpus": [],
    },
}


# A1: every transcript-consuming case executes the same staged
# guest run: declare the shared staged script and helpers as
# their evidence identities (host-only cases excluded).
for _case_id in (
    "test_match_exact_with_oracle",
    "test_mismatch_zero_with_oracle",
    "test_inverted_counts_mismatches",
    "test_reload_live_state",
    "test_never_called_zero",
    "test_unavailability_reported",
    "test_bad_offset_refused",
    "test_verifier_rejects_oob_context",
    "test_vlog_captured",
    "test_no_residue",
):
    CASE_INPUTS[_case_id]["sources"] += [
        ("stage", "guest_uprobe.sh"),
        ("stage", "uprobe_target"),
        ("stage", "uprobe_attach"),
    ]


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
            stage_dir=None, unavailable_seen=unavailable_seen
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
    names = sorted(k for k in globals() if k.startswith("test_"))
    try:
        release = vng_release()
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE in lane: %s" % exc)
        rec = guest_proc.SuiteRecorder(
            suite_id="kernel-uprobe", suite_path=__file__,
            case_ids=names,
            denials=CASE_DENIALS, inputs=CASE_INPUTS,
            lane_release="v6.12")
        # The lane is invalid, so nothing can run; the nominal
        # default lane lets the refusal seal a terminal record
        # (matrix runs always set a valid lane and embed the
        # matrix target instead).
        return rec.finish_unrun("invalid lane: %s" % exc)
    rec = guest_proc.SuiteRecorder(
        suite_id="kernel-uprobe", suite_path=__file__,
        case_ids=names,
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
    if failures or unavailable_seen:
        return _finish(rec, unavailable_seen)
    print("uprobe register: boards, oracle, negatives, residue")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
