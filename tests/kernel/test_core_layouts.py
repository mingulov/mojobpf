# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the minimal CO-RE vertical slice: one relocated
field read plus one existence check, proven on two kernel layouts.

Builds ``tests/core/core_read.mojo`` through the genuine pipeline
(``mojo build --emit llvm`` -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable Linux
guest and proves the same object bytes load and behave correctly on
that lane's kernel BTF. Run once per lane directly::

    MOJOBPF_VNG_RELEASE=v6.12 python3 tests/kernel/test_core_layouts.py
    MOJOBPF_VNG_RELEASE=v6.6 python3 tests/kernel/test_core_layouts.py

The two direct runs share nothing but the committed source; the
two-lane identical-bytes board is assembled from their digests.

The probe performs one relocated u32 read at
``map_value + CO-RE(task_struct.pid)`` plus one
``field_exists(task_struct.scx)`` check guarding two distinct
return arms (the exists arm folds ``0x10000`` into the masked
read, the missing arm returns the masked read alone), and
returns the packed observation word ``(v & 0xffff) | (ex <<
16)``. Each lane executes a different guard arm. The guest prefills
the 4096-byte map value with lane-agnostic markers (M66 at byte
2456, M612 at byte 2752; zeros elsewhere, including the phony
local offset 32), so the only way to observe the lane's marker is
a genuine loader relocation to the lane's offset. The existence
bit is 1 on v6.12 (scx present) and 0 on v6.6 (scx absent).

Loader negatives are post-adapter textual mutations of the
pinned-good adapted IR, asserting the loader's explicit
diagnostics; the adapter never emits them (adapter refusal is
pinned host-side by ``tests/core/test_core_audit.py``):

* field mutant: local member ``pid`` renamed to ``pid_nope``
  (present locally, missing on target) -> kernel verifier names
  the unresolvable relocation ``task_struct.pid_nope``.
* member mutant: accessor rewritten to index 999 (out of range
  locally) -> libbpf userspace parse failure.
* type mutant: ``task_struct`` renamed to ``task_struct_nope`` ->
  kernel verifier names the missing type.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng``
(virtme-ng) with a cached guest image on PATH (default release
v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane). Missing
tools fail loudly as environment failures, never as passes.
Staged file hashes are re-verified inside the guest so the
observed words are tied to the exact bytes built here.

Runnable directly (``python3 tests/kernel/test_core_layouts.py``)
or under any ``test_``-style runner. Standard library only. The
guest boot takes a few minutes under software emulation; all
cases share a single boot. A host-only stand-in control proves
the runner timeout path (tree-kill plus partial log) without
booting a guest.
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
CORE_SOURCE = os.path.join(REPO_ROOT, "tests", "core", "core_read.mojo")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
READER = os.path.join(REPO_ROOT, "tests", "core", "btfext_reader.py")
SDK_DIR = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
LAYOUTS_DIR = os.path.join(REPO_ROOT, "tests", "core", "layouts")

# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
GUEST_KERNEL_PREFIX = (
    VNG_RELEASE[1:] if VNG_RELEASE.startswith("v") else VNG_RELEASE
)
VNG_TIMEOUT = 900

# Lane-agnostic prefill markers (u32, little-endian in the map value).
MARKER_66 = 0xCAFE0660
MARKER_612 = 0xCAFE0612

# Mutant provenance: (tag, [(old, new, expected_count)], pinned log text).
# Counts are asserted so silent IR drift fails the build loudly.
MUTANTS = (
    ("field",
     [("name: \"pid\"", "name: \"pid_nope\"", 1)],
     "task_struct.pid_nope (0:1 @ offset 32)"),
    ("member",
     [("llvm.task_struct:0:32$0:1", "llvm.task_struct:0:32$0:999", 2)],
     "0:999 failed"),
    ("type",
     [("llvm.task_struct:", "llvm.task_struct_nope:", 4),
      ("name: \"task_struct\"", "name: \"task_struct_nope\"", 1)],
     "task_struct_nope.pid (0:1 @ offset 32)"),
)


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


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
    """Snapshot the process table into ``{pid: (ppid, pgid, state)}``.

    Best-effort: processes that exit mid-scan are skipped, and a
    missing ``/proc`` yields an empty table. This is the matrix
    runner's owned-process-tracking composition
    (``ci/run_vm_tests.py``), kept local so the suite stays
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


def lane_key():
    key = VNG_RELEASE if VNG_RELEASE.startswith("v") else "v" + VNG_RELEASE
    if key not in ("v6.6", "v6.12"):
        raise EnvironmentFailure(
            "unsupported lane %r: no recorded task_struct layout "
            "(lanes with evidence: v6.6, v6.12)" % VNG_RELEASE
        )
    return key


def load_lane_facts():
    """pid byte offset, scx presence, and member count per lane."""
    facts = {}
    for lane in ("v6.6", "v6.12"):
        path = os.path.join(LAYOUTS_DIR, lane + ".json")
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing layout file: %s" % path)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        members = data["members"]
        facts[lane] = {
            "pid_off": members["pid"]["bits_offset"] // 8,
            "scx": "scx" in members,
            "count": data["member_count"],
        }
    return facts


def expected_retval(lane, facts):
    marker = MARKER_66 if lane == "v6.6" else MARKER_612
    exists = 1 if facts[lane]["scx"] else 0
    return (marker & 0xFFFF) | (exists << 16)


def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", "-I", SDK_DIR,
         "-o", raw_path, source]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         adapted_path, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "llc failed for %s (exit %d):\n%s\n%s"
            % (adapted_path, proc.returncode, proc.stdout, proc.stderr)
        )
    return {"raw": raw_path, "adapted": adapted_path, "object": object_path}


def build_mutant(adapted_path, workdir, tag, replacements):
    """Post-adapter textual mutation; asserts exact replacement counts."""
    with open(adapted_path, "r", encoding="utf-8") as handle:
        text = handle.read()
    for old, new, count in replacements:
        found = text.count(old)
        if found != count:
            raise AssertionError(
                "mutant %s: expected %d of %r, found %d "
                "(adapted IR drifted)" % (tag, count, old, found)
            )
        text = text.replace(old, new)
    mutant_ll = os.path.join(workdir, "mutant_%s.bpf.ll" % tag)
    mutant_obj = os.path.join(workdir, "mutant_%s.bpf.o" % tag)
    with open(mutant_ll, "w", encoding="utf-8") as handle:
        handle.write(text)
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         mutant_ll, "-o", mutant_obj]
    )
    if proc.returncode != 0 or not os.path.isfile(mutant_obj):
        raise AssertionError(
            "llc failed for mutant %s (exit %d):\n%s\n%s"
            % (tag, proc.returncode, proc.stdout, proc.stderr)
        )
    return mutant_obj


def run_reader(object_path):
    """Independent relocation listing; shares no code with the loader."""
    proc = run_step([sys.executable, READER, object_path])
    if proc.returncode != 0:
        raise AssertionError(
            "independent reader failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    return proc.stdout


GUEST_SCRIPT = """#!/bin/bash
set -u
STAGE="{stage}"
EXPECTED_DIGEST="{digest}"
OFF66={off66}
OFF612={off612}
M66={m66}
M612={m612}
cd "$STAGE" || exit 3
echo "guest-kernel: $(uname -r)"
echo "guest-stage: $STAGE"

emit() {{
  tag="$1"; body="$2"
  echo "=== BEGIN $tag exit=0 ==="
  echo "$body"
  echo "=== END $tag ==="
}}

echo "=== staged hashes (guest re-verification) ==="
sha256sum core.bpf.o mutant_field.bpf.o mutant_member.bpf.o mutant_type.bpf.o pkt.bin

echo "=== case layout-oracle ==="
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /tmp/kbtf.c 2>/tmp/kbtf.err
dump_exit=$?
oracle=$(python3 -c "import re; t=open('/tmp/kbtf.c').read(); i=t.find('struct task_struct {{'); b=t[i:t.find('}};',i)] if i>=0 else ''; print('ts=%d pid=%d scx=%d' % (1 if i>=0 else 0, 1 if re.search('[^_a-z]pid;', b) else 0, 1 if re.search('[^_a-z]scx;', b) else 0))")
ts=$(echo "$oracle" | grep -oE 'ts=[01]' | cut -d= -f2)
pid=$(echo "$oracle" | grep -oE 'pid=[01]' | cut -d= -f2)
scx=$(echo "$oracle" | grep -oE 'scx=[01]' | cut -d= -f2)
emit layout-oracle "$(printf '{{"dump_exit": %d, "task_struct": %d, "pid": %d, "scx": %d}}' "$dump_exit" "$ts" "$pid" "$scx")"

echo "=== case load ==="
guest_digest=$(sha256sum core.bpf.o | cut -d' ' -f1)
if [ "$guest_digest" = "$EXPECTED_DIGEST" ]; then digest_ok=1; else digest_ok=0; fi
LIBBPF_DEBUG=1 bpftool prog load core.bpf.o /sys/fs/bpf/p51_core > /tmp/load.stdout 2> /tmp/load.stderr
load_exit=$?
echo "--- full load transcript (guest writes are ephemeral; stdout is durable) ---"
cat /tmp/load.stdout /tmp/load.stderr
echo "--- end load transcript ---"
if [ -e /sys/fs/bpf/p51_core ]; then prog_pinned=1; else prog_pinned=0; fi
mapid=$(bpftool map list 2>/dev/null | grep 'name mojobpf_map0' | cut -d: -f1 | head -1)
if [ -n "$mapid" ]; then bpftool map pin id "$mapid" /sys/fs/bpf/p51_map0 2>&1; fi
if [ -e /sys/fs/bpf/p51_map0 ]; then map_pinned=1; else map_pinned=0; fi
emit load "$(printf '{{"load_exit": %d, "digest_ok": %d, "prog_pinned": %d, "map_pinned": %d}}' "$load_exit" "$digest_ok" "$prog_pinned" "$map_pinned")"

echo "=== case prefill ==="
hexbytes=$(python3 -c "import struct; b=bytearray(4096); struct.pack_into('<I',b,$OFF66,$M66); struct.pack_into('<I',b,$OFF612,$M612); print(' '.join('%02x' % x for x in b))")
bpftool map update pinned /sys/fs/bpf/p51_map0 key hex 00 00 00 00 value hex $hexbytes > /tmp/prefill.log 2>&1
update_exit=$?
cat /tmp/prefill.log
bpftool map dump pinned /sys/fs/bpf/p51_map0 > /tmp/mapdump.txt 2>&1
if tr -d '\n' < /tmp/mapdump.txt | grep -q '60 06 fe ca' && tr -d '\n' < /tmp/mapdump.txt | grep -q '12 06 fe ca'; then marker_seen=1; else marker_seen=0; fi
emit prefill "$(printf '{{"update_exit": %d, "marker_seen": %d}}' "$update_exit" "$marker_seen")"

echo "=== case run ==="
run_out=$(bpftool prog run pinned /sys/fs/bpf/p51_core data_in "$STAGE/pkt.bin" repeat 3 2>&1)
run_exit=$?
echo "$run_out"
retval=$(echo "$run_out" | grep -oE 'Return value: [0-9]+' | cut -d' ' -f3)
if [ -z "$retval" ]; then retval=-1; fi
emit run "$(printf '{{"run_exit": %d, "retval": %d}}' "$run_exit" "$retval")"

try_mutant() {{
  tag="$1"; obj="$2"; pattern="$3"
  echo "=== case mutant-$tag ==="
  out=$(bpftool prog load "$obj" /sys/fs/bpf/p51_m$tag 2>&1)
  code=$?
  echo "$out"
  if echo "$out" | grep -F -q "$pattern"; then matched=1; else matched=0; fi
  if [ -e /sys/fs/bpf/p51_m$tag ]; then pinned=1; else pinned=0; fi
  rm -f /sys/fs/bpf/p51_m$tag
  emit mutant-$tag "$(printf '{{"load_exit": %d, "matched": %d, "pinned": %d}}' "$code" "$matched" "$pinned")"
}}
try_mutant field mutant_field.bpf.o '{pat_field}'
try_mutant member mutant_member.bpf.o '{pat_member}'
try_mutant type mutant_type.bpf.o '{pat_type}'

echo "=== case hide-btf ==="
if command -v unshare >/dev/null 2>&1; then capable=1; else capable=0; fi
hide_exit=-1; hide_matched=0; hide_pinned=0
if [ "$capable" = 1 ]; then
  mkdir -p /tmp/emptybtf
  hide_out=$(unshare -m bash -c 'mount --bind /tmp/emptybtf /sys/kernel/btf && bpftool prog load core.bpf.o /sys/fs/bpf/p51_hide' 2>&1)
  hide_exit=$?
  echo "$hide_out"
  if echo "$hide_out" | grep -F -q 'kernel BTF is missing'; then hide_matched=1; fi
  if [ -e /sys/fs/bpf/p51_hide ]; then hide_pinned=1; fi
  rm -f /sys/fs/bpf/p51_hide
fi
emit hide-btf "$(printf '{{"capable": %d, "load_exit": %d, "matched": %d, "pinned": %d}}' "$capable" "$hide_exit" "$hide_matched" "$hide_pinned")"

echo "=== case unload ==="
rm -f /sys/fs/bpf/p51_core /sys/fs/bpf/p51_map0
shopt -s nullglob
p51pins=(/sys/fs/bpf/p51*)
remaining=${{#p51pins[@]}}
if [ "$remaining" = 0 ]; then cleanup_ok=1; else cleanup_ok=0; fi
emit unload "$(printf '{{"cleanup_ok": %d}}' "$cleanup_ok")"
echo "=== end guest_core ==="
"""

CASES = (
    "layout-oracle",
    "load",
    "prefill",
    "run",
    "mutant-field",
    "mutant-member",
    "mutant-type",
    "hide-btf",
    "unload",
)


def guest_run():
    """Build objects, boot one guest, return parsed case results."""
    lane = lane_key()
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (CORE_SOURCE, ADAPTER, READER):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    facts = load_lane_facts()
    stage = tempfile.mkdtemp(prefix="mojo-core-", dir="/tmp")
    with open(os.path.join(stage, "pkt.bin"), "wb") as handle:
        handle.write(bytes(64))
    built = build_object(CORE_SOURCE, stage, "core")
    object_path = built["object"]
    digest = sha256_file(object_path)
    reader_out = run_reader(object_path)
    mutant_paths = {}
    for tag, replacements, _ in MUTANTS:
        mutant_paths[tag] = build_mutant(
            built["adapted"], stage, tag, replacements
        )
    patterns = {tag: pinned for tag, _, pinned in MUTANTS}
    script = GUEST_SCRIPT.format(
        stage=stage,
        digest=digest,
        off66=facts["v6.6"]["pid_off"],
        off612=facts["v6.12"]["pid_off"],
        m66=MARKER_66,
        m612=MARKER_612,
        pat_field=patterns["field"],
        pat_member=patterns["member"],
        pat_type=patterns["type"],
    )
    script_path = os.path.join(stage, "guest_core.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in (
        "core.bpf.o",
        "mutant_field.bpf.o",
        "mutant_member.bpf.o",
        "mutant_type.bpf.o",
        "pkt.bin",
        "guest_core.sh",
    ):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm",
         "--exec", "bash %s" % script_path],
        stage,
        VNG_TIMEOUT,
    )
    if returncode != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+) exit=(\d+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        try:
            record = json.loads(body)
        except ValueError:
            raise EnvironmentFailure(
                "guest case %s produced invalid JSON (stage %s):\n%s"
                % (tag, stage, body[-1000:])
            )
        record["_case_exit"] = int(exit_code)
        results[tag] = record
    missing = [tag for tag in CASES if tag not in results]
    if missing:
        raise EnvironmentFailure(
            "guest output lacks cases %s (stage kept at %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    board = {
        "lane": lane,
        "kernel_prefix": GUEST_KERNEL_PREFIX,
        "object_sha256": digest,
        "expected_retval": expected_retval(lane, facts),
        "reader": reader_out,
        "results": results,
    }
    with open(os.path.join(stage, "board.json"), "w", encoding="utf-8") as handle:
        json.dump(board, handle, indent=2, sort_keys=True)
    return {
        "lane": lane,
        "facts": facts,
        "stage": stage,
        "output": output,
        "digest": digest,
        "reader": reader_out,
        "results": results,
    }


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def _proc_cmdlines_containing(needle):
    """Return the pids whose command line still contains ``needle``."""
    found = []
    want = needle.encode("utf-8")
    try:
        entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        raise EnvironmentFailure(
            "/proc is unavailable for the survivor scan"
        )
    for entry in entries:
        try:
            with open("/proc/%s/cmdline" % entry, "rb") as handle:
                cmdline = handle.read()
        except OSError:
            continue
        if want in cmdline:
            found.append(int(entry))
    return found


def test_runner_timeout_kills_tree_and_saves_partial():
    # Host-only stand-in control for the timeout path (no guest
    # boot): a session leader printing one partial line then
    # sleeping past the timeout with a named descendant must
    # surface as EnvironmentFailure (never TypeError), must save
    # the partial line to the stage guest.log, and must leave no
    # descendant behind.
    for tool in ("bash", "sleep"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    marker = "core-standin-%d" % os.getpid()
    stage = tempfile.mkdtemp(prefix="mojo-core-standin-")
    argv = [
        "bash", "-c",
        "echo %s-PARTIAL; (exec -a %s-child sleep 60) & "
        "exec -a %s-leader sleep 60" % (marker, marker, marker),
    ]
    try:
        _run_guest(argv, stage, timeout=10)
    except EnvironmentFailure as exc:
        message = str(exc)
    else:
        raise AssertionError("stand-in run unexpectedly finished")
    assert "timed out after 10s" in message, message
    assert ("%s-PARTIAL" % marker) in message, message
    log_path = os.path.join(stage, "guest.log")
    assert os.path.isfile(log_path), "timeout must save a partial guest.log"
    with open(log_path, "r", encoding="utf-8") as handle:
        log = handle.read()
    assert "partial" in log.splitlines()[0], log[:200]
    assert ("%s-PARTIAL" % marker) in log, log[-500:]
    survivors = _proc_cmdlines_containing(marker)
    assert survivors == [], (
        "stand-in descendants survived the timeout: %s" % survivors
    )


def test_lane_layout_facts():
    facts = executed()["facts"]
    assert facts["v6.6"]["pid_off"] == 2456, "v6.6 pid offset must be 2456"
    assert facts["v6.12"]["pid_off"] == 2752, "v6.12 pid offset must be 2752"
    assert facts["v6.6"]["scx"] is False, "v6.6 must lack task_struct.scx"
    assert facts["v6.12"]["scx"] is True, "v6.12 must have task_struct.scx"
    assert facts["v6.6"]["count"] == 260, "v6.6 member count must be 260"
    assert facts["v6.12"]["count"] == 270, "v6.12 member count must be 270"


def test_reader_relocations():
    reader = executed()["reader"]
    assert "task_struct" in reader and "pid" in reader, (
        "reader must name the task_struct pid relocation:\n%s" % reader
    )
    assert "FIELD_BYTE_OFFSET" in reader and "0:1" in reader, (
        "reader must show the byte-offset accessor 0:1:\n%s" % reader
    )
    assert "local_off=32" in reader, (
        "reader must show the phony local offset 32:\n%s" % reader
    )
    assert "scx" in reader and "FIELD_EXISTS" in reader, (
        "reader must show the scx existence check:\n%s" % reader
    )


def test_guest_provenance():
    run = executed()
    assert "guest-kernel: %s" % GUEST_KERNEL_PREFIX in run["output"], (
        "guest kernel must be v%s" % GUEST_KERNEL_PREFIX
    )
    assert run["digest"] in run["output"], (
        "guest must re-verify the staged object hash %s" % run["digest"]
    )


def test_layout_oracle_matches_lane():
    run = executed()
    record = run["results"]["layout-oracle"]
    assert record["dump_exit"] == 0, "guest BTF dump must succeed"
    assert record["task_struct"] == 1, "target must define task_struct"
    assert record["pid"] == 1, "target task_struct must define pid"
    lane_scx = 1 if run["facts"][run["lane"]]["scx"] else 0
    assert record["scx"] == lane_scx, (
        "%s: target scx presence must be %d" % (run["lane"], lane_scx)
    )


def test_load_pins_program_and_map():
    record = executed()["results"]["load"]
    assert record["digest_ok"] == 1, "guest digest must match host digest"
    assert record["load_exit"] == 0, "object must load cleanly"
    assert record["prog_pinned"] == 1, "program pin must exist after load"
    assert record["map_pinned"] == 1, "map pin must exist after load"


def test_prefill_markers_present():
    record = executed()["results"]["prefill"]
    assert record["update_exit"] == 0, "prefill map update must succeed"
    assert record["marker_seen"] == 1, "both markers must be visible in map"


def test_relocated_read_matches_lane_marker():
    run = executed()
    record = run["results"]["run"]
    assert record["run_exit"] == 0, "test-run must succeed"
    lane = run["lane"]
    marker = MARKER_66 if lane == "v6.6" else MARKER_612
    observed = record["retval"] & 0xFFFF
    assert observed == (marker & 0xFFFF), (
        "%s: relocated read must observe marker 0x%04x, got 0x%04x "
        "(full word 0x%08x)"
        % (lane, marker & 0xFFFF, observed, record["retval"])
    )
    assert record["retval"] == expected_retval(lane, run["facts"]), (
        "%s: packed word must be 0x%08x, got 0x%08x"
        % (lane, expected_retval(lane, run["facts"]), record["retval"])
    )


def test_exists_bit_matches_lane_layout():
    # The guarded case: each lane executes its own guard arm
    # (v6.12 the exists arm folding 0x10000, v6.6 the missing
    # arm), so the high half proves which arm ran, not just a
    # packed bit.
    run = executed()
    record = run["results"]["run"]
    lane = run["lane"]
    expected = 1 if run["facts"][lane]["scx"] else 0
    observed = (record["retval"] >> 16) & 0xFFFF
    assert observed == expected, (
        "%s: existence bit must be %d, got %d (word 0x%08x)"
        % (lane, expected, observed, record["retval"])
    )


def test_missing_field_fails_explicitly():
    record = executed()["results"]["mutant-field"]
    assert record["load_exit"] != 0, "pid_nope load must fail"
    assert record["matched"] == 1, (
        "loader must name task_struct.pid_nope with accessor 0:1"
    )
    assert record["pinned"] == 0, "failed load must leave no pin"


def test_malformed_and_missing_type_fail_explicitly():
    member = executed()["results"]["mutant-member"]
    assert member["load_exit"] != 0, "index-999 load must fail"
    assert member["matched"] == 1, "libbpf must report the 0:999 failure"
    assert member["pinned"] == 0, "failed load must leave no pin"
    wrong = executed()["results"]["mutant-type"]
    assert wrong["load_exit"] != 0, "missing-type load must fail"
    assert wrong["matched"] == 1, "loader must name task_struct_nope"
    assert wrong["pinned"] == 0, "failed load must leave no pin"


def test_absent_target_btf_fails_explicitly():
    record = executed()["results"]["hide-btf"]
    assert record["capable"] == 1, "guest must provide unshare(1)"
    assert record["load_exit"] != 0, "load without target BTF must fail"
    assert record["matched"] == 1, "loader must report missing kernel BTF"
    assert record["pinned"] == 0, "failed load must leave no pin"


def test_cleanup_ok():
    run = executed()
    assert run["results"]["unload"]["cleanup_ok"] == 1, (
        "guest must remove every p51 pin"
    )
    assert "PIN STILL PRESENT" not in run["output"], "pins must be removed"


def print_board(run):
    lane = run["lane"]
    record = run["results"]["run"]
    print("lane: %s (guest kernel v%s)" % (lane, GUEST_KERNEL_PREFIX))
    print("object sha256: %s" % run["digest"])
    print("reader identities: task_struct pid FIELD_BYTE_OFFSET 0:1; "
          "scx FIELD_EXISTS")
    print("retval: 0x%08x (marker 0x%04x, exists %d)" % (
        record["retval"],
        record["retval"] & 0xFFFF,
        (record["retval"] >> 16) & 0xFFFF,
    ))
    for tag in ("mutant-field", "mutant-member", "mutant-type", "hide-btf"):
        rec = run["results"][tag]
        print("%s: exit=%d matched=%d pinned=%d" % (
            tag, rec["load_exit"], rec["matched"], rec["pinned"]))
    print("cleanup_ok: %d" % run["results"]["unload"]["cleanup_ok"])
    print("guest stage kept at: %s" % run["stage"])


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
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("core layouts: same bytes load and relocate on %s" % lane_key())
    print_board(executed())
    return 0


if __name__ == "__main__":
    sys.exit(main())
