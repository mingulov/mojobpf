# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Cross-architecture portability proof for the supported subset.

Builds one representative object per supported shape through the
genuine pipeline (``mojo build --emit llvm`` with the packaged SDK
on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable Linux
guest and proves the SAME behavior the x86 lanes prove, on whatever
architecture the guest runs:

* architecture-neutral XDP first: the base classifier and its
  single-line mutation against three packet fixtures (drop, pass,
  short), predicted by an independent restatement of the rule;
* layout/endian behavior: a 41-to-42 map round trip (u32 key, u64
  value), boundary-constant endian words (network-order and
  little-endian multi-byte fields), and a ones-complement checksum
  window over network-order words;
* every helper the supported subset admits (IDs 1, 2, 3, 5, 8, 14,
  130): lookup/update through the round trip, delete through a
  delete probe, pid/tgid through an exact-count tracepoint run,
  clock/cpu/ringbuf-output through a healthy event drain;
* every map kind the subset admits: ARRAY (round trip, delete,
  counter), PERCPU_ARRAY (one rmw entry read through raw ``bpf()``
  plus the ``bpftool -j map dump`` oracle), RINGBUF (event drain
  decoded by the product decoder).

The counter and emitter objects must be byte-identical to the
qualified bytes the tracing suites pin, so the observations here
are tied to exactly those bytes.

Lane selection: ``MOJOBPF_VNG_RELEASE`` selects the kernel release
(default v6.12) exactly like the other guest suites.
``MOJOBPF_VNG_ARCH`` selects a cross-architecture guest (only
``arm64`` is supported; unset means the native host architecture)
and ``MOJOBPF_VNG_ROOT`` must then point at the matching guest
root directory. Cross runs map the stage into the guest with an
explicit ``--rwdir guestpath=hostpath`` pair (virtme rejects host
paths outside a cross root), provision the guest observer
(``bpftool``) over user-mode networking after fixing the guest
clock from a staged host epoch, and build the raw-syscall C
holders with the matching cross compiler; native runs use the
host toolchain directly. Where the kernel interface differs by
architecture, the suite selects explicitly: the raw ``bpf()``
reader uses syscall 321 on x86-64 and 280 on AArch64 and refuses
anything else.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng``
(virtme-ng) with a cached guest image on PATH, plus ``cc`` (native
runs) or ``aarch64-linux-gnu-gcc`` (arm64 runs); cross runs also
need guest user-mode networking for the one-package provisioning.
Missing tools fail loudly as environment failures, never as
passes.

Runnable directly (``python3 tests/kernel/test_arch_portability.py``)
or under any ``test_``-style runner. Standard library only. The
guest boot plus the case runs take several minutes under software
emulation; all cases share a single boot.
"""

import hashlib
import json
import os
import platform
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
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.events import (  # noqa: E402
    EventDecodeError,
    check_accounting,
    check_event_run,
    decode_event_stream,
)

EXAMPLE_DIR = os.path.join(REPO_ROOT, "examples", "xdp_pass")
BASE_SOURCE = os.path.join(EXAMPLE_DIR, "xdp_pass.mojo")
MUTATED_SOURCE = os.path.join(EXAMPLE_DIR, "xdp_pass_mutated.mojo")
COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
MAP_SOURCE = os.path.join(COMPILE_DIR, "map_roundtrip.mojo")
DELETE_SOURCE = os.path.join(COMPILE_DIR, "maps_delete1.mojo")
ENDIAN_SOURCE = os.path.join(COMPILE_DIR, "scalar_endian.mojo")
CHECKSUM_SOURCE = os.path.join(COMPILE_DIR, "checksum_window.mojo")
PERCPU_SOURCE = os.path.join(COMPILE_DIR, "percpu_rmw1.mojo")
COUNTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "counter.mojo"
)
EMITTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_events", "emitter.mojo"
)
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")
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

# The guest must test exactly the qualified bytes the tracing
# suites pin (same sources, same pipeline, same hashes).
TRACEPOINT_OBJECT_HASH = (
    "b687af78c3056e2299929cd635044875f8369f9ca6e27f626c4f55c4def8b67a"
)
EMITTER_OBJECT_HASH = (
    "dbddc75dabe4198107eca403a37bfa04934932c6cfe011ca5f46ca6df67b8770"
)

XDP_DROP = 1
XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
GUEST_KERNEL_PREFIX = (
    VNG_RELEASE[1:] if VNG_RELEASE.startswith("v") else VNG_RELEASE
)
# Cross-architecture selection. Unset (the default) runs the native
# host architecture; "arm64" runs an AArch64 guest whose root comes
# from MOJOBPF_VNG_ROOT.
VNG_ARCH = os.environ.get("MOJOBPF_VNG_ARCH", "")
VNG_ROOT = os.environ.get("MOJOBPF_VNG_ROOT", "")
VNG_TIMEOUT = 1800

MAP_NAME = "mojobpf_map0"
INIT_VALUE = 41
HIT_VALUE = 42

# Exact-count workloads. Smaller than the tracing suites' own N
# (same exact-match semantics: the observed count must equal N).
COUNTER_N = 1000
COUNTER_M = 100
EVENT_N = 500
EVENT_M = 100

FIXTURES = ("pkt_drop.bin", "pkt_pass.bin", "pkt_short.bin")


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


class ProofFailure(AssertionError):
    """The guest ran but the portability proof does not hold."""


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


def check_tools(*names):
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise EnvironmentFailure(
            "required tool(s) not on PATH: %s" % ", ".join(missing)
        )


def build_object(source, workdir, name, want_hash=None):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", "-I", SDK_INCLUDE,
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
        [sys.executable, ADAPTER, "--input", raw_path,
         "--output", adapted_path]
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
    if want_hash is not None:
        observed = sha256_file(object_path)
        if observed != want_hash:
            raise AssertionError(
                "object %s is not the qualified bytes:\nobserved %s\n"
                "expected %s" % (object_path, observed, want_hash)
            )
    return object_path


def build_harness(source, output, cc):
    proc = run_step([cc, "-O2", "-o", output, source])
    if proc.returncode != 0 or not os.path.isfile(output):
        raise AssertionError(
            "%s failed for %s (exit %d):\n%s\n%s"
            % (cc, source, proc.returncode, proc.stdout, proc.stderr)
        )
    return output


def classify_xdp(frame):
    """Independent prediction of the base classifier rule."""
    if len(frame) >= 15 and (frame[14] & 1) == 1:
        return XDP_DROP
    return XDP_PASS


def classify_xdp_mutated(frame):
    """Independent prediction of the inverted-bit mutation."""
    if len(frame) >= 15 and (frame[14] & 1) == 0:
        return XDP_DROP
    return XDP_PASS


def endian_drop_frame():
    """28-byte frame matching every endian boundary constant."""
    frame = bytearray(28)
    frame[14:16] = (0x0000).to_bytes(2, "big")
    frame[16:18] = (0xFFFF).to_bytes(2, "big")
    frame[18:20] = (0x00FF).to_bytes(2, "big")
    frame[20:22] = (0x8001).to_bytes(2, "big")
    frame[22:24] = (0xFF00).to_bytes(2, "little")
    frame[24:28] = (0x80000001).to_bytes(4, "little")
    return bytes(frame)


def endian_pass_frame():
    """Same frame with one network-order word broken (0x8001->0x0001)."""
    frame = bytearray(endian_drop_frame())
    frame[20] = 0x00
    return bytes(frame)


def cksum_digest(words):
    """Ones-complement checksum of network-order words.

    Folded carry loop plus the final complement, matching the
    specified checksum rule.
    """
    total = sum(words)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def cksum_frames():
    """(drop, pass) 24-byte checksum frames from the local oracle."""
    words = (0x1234, 0x5678, 0x9ABC, 0xDEF0)
    digest = cksum_digest(words)
    wrong = (digest + 1) & 0xFFFF
    assert wrong != digest
    head = b"".join(word.to_bytes(2, "big") for word in words)
    drop = bytes(14) + head + digest.to_bytes(2, "big")
    passing = bytes(14) + head + wrong.to_bytes(2, "big")
    return drop, passing


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


# Raw per-CPU map reader staged into the guest. The bpf() syscall
# number differs by guest architecture (321 on x86-64, 280 on
# AArch64), so the reader selects it from the guest machine name
# explicitly and refuses anything else; a hardcoded number would
# silently issue the wrong syscall on the other architecture.
PERCPU_READER_SOURCE = '''\\
import ctypes
import os
import platform
import sys

_MACHINE = platform.machine()
if _MACHINE == "x86_64":
    SYS_BPF = 321
elif _MACHINE == "aarch64":
    SYS_BPF = 280
else:
    raise OSError("unsupported guest arch for raw bpf(): " + _MACHINE)
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7

libc = ctypes.CDLL("libc.so.6", use_errno=True)


class ObjGetAttr(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class ElemAttr(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("pad", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


def bpf(cmd, attr):
    rc = libc.syscall(
        SYS_BPF, ctypes.c_int(cmd), ctypes.byref(attr),
        ctypes.c_uint(ctypes.sizeof(attr)),
    )
    if rc < 0:
        err = ctypes.get_errno()
        raise OSError(err, "bpf cmd %d failed" % cmd)
    return rc


def read_key(fd, key, value_size, ncpu):
    stride = (value_size + 7) // 8 * 8
    key_buf = ctypes.create_string_buffer(key.to_bytes(4, "little"))
    got_buf = ctypes.create_string_buffer(ncpu * stride)
    get_attr = ElemAttr(
        map_fd=fd, pad=0,
        key=ctypes.addressof(key_buf),
        value=ctypes.addressof(got_buf), flags=0,
    )
    bpf(BPF_MAP_LOOKUP_ELEM, get_attr)
    return bytes(got_buf)


def main(argv):
    verb = argv[1]
    pin, key, value_size, ncpu = (
        argv[2], int(argv[3]), int(argv[4]), int(argv[5])
    )
    stride = (value_size + 7) // 8 * 8
    path = ctypes.create_string_buffer(pin.encode("ascii"))
    get = ObjGetAttr(
        pathname=ctypes.addressof(path), bpf_fd=0, file_flags=0
    )
    fd = bpf(BPF_OBJ_GET, get)
    try:
        if verb == "init":
            base, step = int(argv[6]), int(argv[7])
            key_buf = ctypes.create_string_buffer(
                key.to_bytes(4, "little")
            )
            put = bytearray()
            for cpu in range(ncpu):
                put.extend(
                    (base + cpu * step).to_bytes(value_size, "little")
                )
                put.extend(bytes(stride - value_size))
            put_buf = ctypes.create_string_buffer(bytes(put))
            upd = ElemAttr(
                map_fd=fd, pad=0,
                key=ctypes.addressof(key_buf),
                value=ctypes.addressof(put_buf), flags=0,
            )
            bpf(BPF_MAP_UPDATE_ELEM, upd)
            sys.stdout.write("update_ok=1\\n")
        elif verb != "read":
            raise ValueError("unknown verb %r" % verb)
        raw = read_key(fd, key, value_size, ncpu)
        sys.stdout.write("read_ok=1\\n")
        sys.stdout.write("raw=" + raw.hex() + "\\n")
    finally:
        os.close(fd)


main(sys.argv)
'''

PERCPU_READER_NAME = "pcpu_probe.py"


NATIVE_PROVISION = """\
command -v bpftool >/dev/null || { echo "NATIVE-BPFTOOL-MISSING"; exit 1; }
echo "observer: native (host root)"
"""

CROSS_PROVISION = """\
echo "host-epoch: $(cat host_epoch)"
date -u --set="@$(cat host_epoch)" >/dev/null || { echo "CLOCK-SET-FAILED"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update >/tmp/arch-apt-update.log 2>&1 || { echo "APT-UPDATE-FAILED"; tail -5 /tmp/arch-apt-update.log; exit 1; }
apt-get install -y --no-install-recommends bpftool >/tmp/arch-apt-install.log 2>&1 || { echo "APT-INSTALL-FAILED"; tail -5 /tmp/arch-apt-install.log; exit 1; }
echo "observer: provisioned (apt bpftool)"
"""

GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_arch ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
echo "guest-arch: $(uname -m)"
echo "possible=$(cat /sys/devices/system/cpu/possible)"
echo "online=$(cat /sys/devices/system/cpu/online)"
echo "nproc=$(nproc)"
echo "nprocall=$(nproc --all)"
{provision}
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum {staged_names}
le32() {{
  printf '%d 0 0 0' "$1"
}}
u64_bytes() {{
  python3 -c "import sys; print(' '.join(str(b) for b in int(sys.argv[1]).to_bytes(8, 'little')))" "$1"
}}
map_info() {{
  out="$1"
  python3 - "$out" >/tmp/arch-mapinfo.stderr 2>&1 <<'PYEOF'
import json
import subprocess
import sys
fields = sys.argv[1]
info = {{"map_found": "0"}}
try:
    raw = subprocess.run(
        ["bpftool", "-j", "map", "show"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for entry in json.loads(raw.stdout or "[]"):
        if entry.get("name") == "{map_name}":
            info = {{
                "map_found": "1",
                "map_id": str(entry.get("id")),
                "map_type": str(entry.get("type")),
                "map_key": str(entry.get("bytes_key")),
                "map_value": str(entry.get("bytes_value")),
                "map_entries": str(entry.get("max_entries")),
            }}
except Exception as exc:
    info = {{"map_found": "0", "map_error": str(exc)}}
with open(fields, "a") as handle:
    for key in sorted(info):
        handle.write("%s=%s\\n" % (key, info[key]))
PYEOF
  echo "mapinfo_exit=$?" >> "$out"
}}
map_u64() {{
  bpftool map lookup pinned "$1" key "$2" 0 0 0 | python3 -c "import sys; print(int.from_bytes(bytes(int(tok, 16) for tok in sys.stdin.read().split('value:')[1].splitlines()[0].split()), 'little'))"
}}
map_set_u64() {{
  bpftool map update pinned "$1" key "$2" 0 0 0 value $(u64_bytes "$3")
}}
harness_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/xdp-$tag.json"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
map_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_arch_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  bpftool map update id "$map_id" key 0 0 0 0 value {init_bytes} >/tmp/xdp-$tag.update 2>&1
  echo "init_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.before 2>&1
  echo "before_exit=$?" >> "$out"
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.after 2>&1
  echo "after_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag before ---"
  cat /tmp/xdp-$tag.before
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  echo "--- $tag after ---"
  cat /tmp/xdp-$tag.after
  echo "=== END $tag ==="
}}
op_probe() {{
  tag="$1"; obj="$2"; entries="$3"
  pin="/sys/fs/bpf/mojobpf_arch_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  k=0
  while [ "$k" -lt "$entries" ]; do
    bpftool map lookup id "$map_id" key $(le32 "$k") > /tmp/xdp-$tag.key$k 2>&1
    echo "key${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  k=0
  while [ "$k" -lt "$entries" ]; do
    echo "--- $tag key$k ---"
    cat /tmp/xdp-$tag.key$k
    k=$((k + 1))
  done
  echo "=== END $tag ==="
}}
percpu_case() {{
  tag="$1"; obj="$2"; entries="$3"
  pin="/sys/fs/bpf/mojobpf_arch_$tag"
  mappin="/sys/fs/bpf/mojobpf_arc_$tag"
  out="/tmp/pcpu-$tag.fields"
  : > "$out"
  ncpu=$(nproc --all)
  echo "ncpu=$ncpu" >> "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/pcpu-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  if [ -n "$map_id" ]; then
    bpftool map pin id "$map_id" "$mappin" >/tmp/pcpu-$tag.pin 2>&1
    echo "map_pin_exit=$?" >> "$out"
  else
    echo "map_pin_exit=skip" >> "$out"
  fi
  k=0
  while [ "$k" -lt "$entries" ]; do
    python3 {reader} init "$mappin" "$k" 8 "$ncpu" {init} 0 > /tmp/pcpu-$tag.init$k 2>/tmp/pcpu-$tag.init$k.err
    echo "init${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/pcpu-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  k=0
  while [ "$k" -lt "$entries" ]; do
    python3 {reader} read "$mappin" "$k" 8 "$ncpu" > /tmp/pcpu-$tag.key$k 2>/tmp/pcpu-$tag.key$k.err
    echo "key${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  bpftool -j map dump pinned "$mappin" > /tmp/pcpu-$tag.dump 2>&1
  echo "dump_exit=$?" >> "$out"
  rm -f "$pin" "$mappin"
  if [ -e "$pin" ] || [ -e "$mappin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/pcpu-$tag.run
  k=0
  while [ "$k" -lt "$entries" ]; do
    echo "--- $tag init$k ---"
    cat /tmp/pcpu-$tag.init$k
    echo "--- $tag key$k ---"
    cat /tmp/pcpu-$tag.key$k
    k=$((k + 1))
  done
  echo "--- $tag dump ---"
  cat /tmp/pcpu-$tag.dump
  echo "=== END $tag ==="
}}
publish_frames() {{
  LABEL="$1"
  python3 -c "
import hashlib
blob = open('$LABEL.frames', 'rb').read()
assert len(blob) % 36 == 0, len(blob)
for i in range(0, len(blob), 36):
    print('$LABEL-frame: %s' % blob[i:i + 36].hex())
print('$LABEL-sha256: %s' % hashlib.sha256(blob).hexdigest())
" || {{ echo "$LABEL-PUBLISH-FAILED"; exit 1; }}
}}
run_phase() {{
  LABEL="$1"; OBJECT="$2"; PIN="$3"; MON_N="$4"; EXC_M="$5"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-FAILED"; exit 1; }}
  bpftool prog load "$OBJECT" "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/arch-$LABEL.load" 2>&1
  [ $? = 0 ] || {{ echo "$LABEL-LOAD-FAILED"; cat "/tmp/arch-$LABEL.load"; exit 1; }}
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  [ -e "$MAP_PIN" ] || {{ echo "$LABEL-MAP-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }}
  MAP_ID=$(bpftool -j map show pinned "$MAP_PIN" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  echo "$LABEL-map-id: $MAP_ID"
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  mkfifo "$LABEL-rel" "$LABEL-go" "$LABEL-done"
  "./tracepoint_attach" "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/arch-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$MON_N" --excluded "$EXC_M" --phase full --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/arch-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/arch-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/arch-$LABEL.holder.log" || {{ echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/arch-$LABEL.holder.log"; exit 1; }}
  [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] || {{ echo "$LABEL-TID-TIMEOUT"; cat "$LABEL-tids" 2>/dev/null; cat "/tmp/arch-$LABEL.wl.log"; exit 1; }}
  MON_TID=$(awk '$1=="monitored"{{print $2}}' "$LABEL-tids")
  OBS_TID=$(awk '$1=="observer"{{print $2}}' "$LABEL-tids")
  echo "$LABEL-tids: $(tr '\\n' ';' < "$LABEL-tids")"
  [ "$MON_TID" != "$OBS_TID" ] || {{ echo "$LABEL-OBSERVER-NOT-OUTSIDE"; exit 1; }}
  map_set_u64 "$MAP_PIN" 0 "$MON_TID" || {{ echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }}
  map_set_u64 "$MAP_PIN" 1 0 || {{ echo "$LABEL-COUNT-INIT-FAILED"; exit 1; }}
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "$LABEL-filter: want=$MON_TID readback=$FILTER_READ"
  [ "$FILTER_READ" = "$MON_TID" ] || {{ echo "$LABEL-FILTER-READBACK-MISMATCH"; exit 1; }}
  timeout 60 bash -c "echo go > $LABEL-go" || {{ echo "$LABEL-GO-TIMEOUT"; exit 1; }}
  DONE_LINE=$(timeout 300 cat "$LABEL-done") || {{ echo "$LABEL-DONE-TIMEOUT"; exit 1; }}
  echo "$LABEL-done: $DONE_LINE"
  wait "$WL_PID"
  [ $? = 0 ] || {{ echo "$LABEL-WORKLOAD-FAILED"; cat "/tmp/arch-$LABEL.wl.log"; exit 1; }}
  COUNT=$(map_u64 "$MAP_PIN" 1)
  echo "$LABEL-counter: $COUNT"
  exec 8>&-
  wait "$HOLDER_PID"
  [ $? = 0 ] || {{ echo "$LABEL-DETACH-FAILED"; exit 1; }}
  grep -q "^DETACHED$" "/tmp/arch-$LABEL.holder.log" || {{ echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }}
  rm -f "$PIN" "$MAP_PIN"
  rmdir "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }}
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
}}
run_event_phase() {{
  LABEL="$1"; OBJECT="$2"; PIN="$3"; MON_N="$4"; EXC_M="$5"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-FAILED"; exit 1; }}
  bpftool prog load "$OBJECT" "$PIN" type tracepoint pinmaps "$MAP_DIR/" >"/tmp/arch-$LABEL.load" 2>&1
  [ $? = 0 ] || {{ echo "$LABEL-LOAD-FAILED"; cat "/tmp/arch-$LABEL.load"; exit 1; }}
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  RING_PIN="$MAP_DIR/mojobpf_map1"
  [ -e "$MAP_PIN" ] || {{ echo "$LABEL-MAP-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }}
  [ -e "$RING_PIN" ] || {{ echo "$LABEL-RING-PIN-MISSING"; ls -la "$MAP_DIR"; exit 1; }}
  MAP_ID=$(bpftool -j map show pinned "$MAP_PIN" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  RING_ID=$(bpftool -j map show pinned "$RING_PIN" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
  echo "$LABEL-map-id: $MAP_ID"
  echo "$LABEL-ring-id: $RING_ID"
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
  mkfifo "$LABEL-rel" "$LABEL-go" "$LABEL-done"
  "./tracepoint_attach" "$PIN" syscalls sys_enter_getpid <"$LABEL-rel" >"/tmp/arch-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  ./syscall_workload --monitored "$MON_N" --excluded "$EXC_M" --phase full --tid-file "$LABEL-tids" --go-fifo "$LABEL-go" --done-fifo "$LABEL-done" >"/tmp/arch-$LABEL.wl.log" 2>&1 &
  WL_PID=$!
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/arch-$LABEL.holder.log" 2>/dev/null && [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    kill -0 "$WL_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/arch-$LABEL.holder.log" || {{ echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/arch-$LABEL.holder.log"; exit 1; }}
  [ -f "$LABEL-tids" ] && [ "$(wc -l < "$LABEL-tids")" = "4" ] || {{ echo "$LABEL-TID-TIMEOUT"; cat "$LABEL-tids" 2>/dev/null; cat "/tmp/arch-$LABEL.wl.log"; exit 1; }}
  MON_TID=$(awk '$1=="monitored"{{print $2}}' "$LABEL-tids")
  OBS_TID=$(awk '$1=="observer"{{print $2}}' "$LABEL-tids")
  echo "$LABEL-tids: $(tr '\\n' ';' < "$LABEL-tids")"
  [ "$MON_TID" != "$OBS_TID" ] || {{ echo "$LABEL-OBSERVER-NOT-OUTSIDE"; exit 1; }}
  map_set_u64 "$MAP_PIN" 0 "$MON_TID" || {{ echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }}
  map_set_u64 "$MAP_PIN" 1 0 || {{ echo "$LABEL-SEQ-INIT-FAILED"; exit 1; }}
  map_set_u64 "$MAP_PIN" 2 0 || {{ echo "$LABEL-SUCC-INIT-FAILED"; exit 1; }}
  map_set_u64 "$MAP_PIN" 3 0 || {{ echo "$LABEL-FAIL-INIT-FAILED"; exit 1; }}
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "$LABEL-filter: want=$MON_TID readback=$FILTER_READ"
  [ "$FILTER_READ" = "$MON_TID" ] || {{ echo "$LABEL-FILTER-READBACK-MISMATCH"; exit 1; }}
  timeout 60 bash -c "echo go > $LABEL-go" || {{ echo "$LABEL-GO-TIMEOUT"; exit 1; }}
  DONE_LINE=$(timeout 300 cat "$LABEL-done") || {{ echo "$LABEL-DONE-TIMEOUT"; exit 1; }}
  echo "$LABEL-done: $DONE_LINE"
  wait "$WL_PID"
  [ $? = 0 ] || {{ echo "$LABEL-WORKLOAD-FAILED"; cat "/tmp/arch-$LABEL.wl.log"; exit 1; }}
  ATTEMPTED=$(map_u64 "$MAP_PIN" 1)
  SUCCESSFUL=$(map_u64 "$MAP_PIN" 2)
  FAILED=$(map_u64 "$MAP_PIN" 3)
  echo "$LABEL-counters: attempted=$ATTEMPTED successful=$SUCCESSFUL failed=$FAILED"
  DRAIN_OUT=$(./ringbuf_drain --map "$RING_PIN" --out "$LABEL.frames") || {{ echo "$LABEL-DRAIN-FAILED"; exit 1; }}
  DRAINED_N=$(echo "$DRAIN_OUT" | awk '/^DRAINED /{{print $2}}')
  RING_LINE=$(echo "$DRAIN_OUT" | awk '/^RING /{{print $2" "$3" "$4}}')
  [ -n "$DRAINED_N" ] && [ -n "$RING_LINE" ] || {{ echo "$LABEL-DRAIN-PARSE-FAILED: $DRAIN_OUT"; exit 1; }}
  echo "$LABEL-drained: $DRAINED_N"
  echo "$LABEL-ring: $RING_LINE"
  publish_frames "$LABEL"
  exec 8>&-
  wait "$HOLDER_PID"
  [ $? = 0 ] || {{ echo "$LABEL-DETACH-FAILED"; exit 1; }}
  grep -q "^DETACHED$" "/tmp/arch-$LABEL.holder.log" || {{ echo "$LABEL-DETACH-MARKER-MISSING"; exit 1; }}
  rm -f "$PIN" "$MAP_PIN" "$RING_PIN"
  rmdir "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }}
  rm -f "$LABEL-rel" "$LABEL-go" "$LABEL-done" "$LABEL-tids"
}}
echo "=== run baseline ==="
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$(bpftool link show)
PROGS_BEFORE=$(bpftool prog show)
MAPS_BEFORE=$(bpftool map show)
echo "baseline-pins: $(echo "$PINS_BEFORE" | wc -l)"
echo "baseline-links: $(printf '%s' "$LINKS_BEFORE" | grep -c "^[0-9][0-9]*: " || true)"
{commands}
echo "=== pin check ==="
# Residue must return to the run-start baseline exactly. Freed
# programs, maps, and links drain asynchronously, so the
# comparison waits for the baseline to return (bounded, fails
# loudly) instead of asserting instantly. Owned pins must be
# gone absolutely; boot-owned entries (a tracing link the 6.6
# kernel autoloads) are baseline, never residue.
for _ in $(seq 1 600); do
  PINS_NOW=$(ls /sys/fs/bpf/)
  LINKS_NOW=$(bpftool link show)
  PROGS_NOW=$(bpftool prog show)
  MAPS_NOW=$(bpftool map show)
  if [ "$PINS_NOW" = "$PINS_BEFORE" ] && [ "$LINKS_NOW" = "$LINKS_BEFORE" ] && [ "$PROGS_NOW" = "$PROGS_BEFORE" ] && [ "$MAPS_NOW" = "$MAPS_BEFORE" ]; then break; fi
  sleep 0.1
done
stray=0
for pin in /sys/fs/bpf/mojobpf_arch_* /sys/fs/bpf/mojobpf_arc_*; do
  if [ -e "$pin" ]; then echo "STRAY-OWNED-PIN: $pin"; stray=1; fi
done
for pin in /sys/fs/bpf/tp_arch_* /sys/fs/bpf/ev_arch_*; do
  if [ -e "$pin" ]; then echo "STRAY-OWNED-PIN: $pin"; stray=1; fi
done
if [ "$PINS_NOW" != "$PINS_BEFORE" ]; then echo "STRAY-PINS"; echo "$PINS_NOW"; stray=1; fi
if [ "$LINKS_NOW" != "$LINKS_BEFORE" ]; then echo "STRAY-LINKS"; echo "$LINKS_NOW"; stray=1; fi
if [ "$PROGS_NOW" != "$PROGS_BEFORE" ]; then echo "STRAY-PROGS"; echo "$PROGS_NOW"; stray=1; fi
if [ "$MAPS_NOW" != "$MAPS_BEFORE" ]; then echo "STRAY-MAPS"; echo "$MAPS_NOW"; stray=1; fi
if [ "$stray" -eq 0 ]; then echo "residue clean"; fi
echo "=== end guest_arch ==="
"""


def hexle(value):
    return value.to_bytes(8, byteorder="little").hex()


def parse_fields(body):
    fields = {}
    for line in body.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip()
    return fields


def parse_lookup_hex(body, marker):
    """Extract the looked-up value bytes as compact lowercase hex."""
    section = body.split(marker, 1)[1]
    match = re.search(r"value:\s*([0-9a-fA-F ]+)", section)
    assert match, "no bpftool value line after %r" % marker
    return match.group(1).replace(" ", "").lower()


def parse_run_action(body, marker):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


def parse_possible_list(text):
    """Parse a kernel CPU list (``0-15``, ``0-3,8-11``, ``0``)."""
    text = text.strip()
    if not text:
        raise ValueError("empty CPU list")
    cpus = []
    for part in text.split(","):
        if "-" in part:
            first, _, last = part.partition("-")
            if not first.isdigit() or not last.isdigit():
                raise ValueError("bad CPU range %r" % part)
            if int(first) > int(last):
                raise ValueError("reversed CPU range %r" % part)
            cpus.extend(range(int(first), int(last) + 1))
        else:
            if not part.isdigit():
                raise ValueError("bad CPU id %r" % part)
            cpus.append(int(part))
    return cpus


def decode_percpu_values(raw, value_size, ncpu):
    stride = (value_size + 7) // 8 * 8
    expect = ncpu * stride
    assert len(raw) == expect, (
        "raw buffer is %d bytes, want %d for %d CPUs"
        % (len(raw), expect, ncpu)
    )
    values = []
    for cpu in range(ncpu):
        chunk = raw[cpu * stride:cpu * stride + value_size]
        values.append(int.from_bytes(chunk, "little"))
    return values


def parse_raw_values(body, marker, ncpu):
    """Decode one helper readback section to per-CPU integers."""
    section = body.split(marker, 1)[1]
    end = section.find("--- ")
    if end != -1:
        section = section[:end]
    end = section.find("=== END")
    if end != -1:
        section = section[:end]
    fields = parse_fields(section)
    assert fields.get("read_ok") == "1", (
        "helper read failed after %r: %r" % (marker, section[-500:])
    )
    raw = bytes.fromhex(fields["raw"])
    return decode_percpu_values(raw, 8, ncpu)


def decode_bpftool_percpu_dump(doc):
    """Decode ``bpftool -j map dump`` output to {key: [per-CPU ints]}."""
    decoded = {}
    for entry in doc:
        key = int.from_bytes(
            bytes(int(byte, 16) for byte in entry["key"]), "little"
        )
        values = []
        for slot in entry["values"]:
            values.append(
                (
                    slot["cpu"],
                    int.from_bytes(
                        bytes(int(byte, 16) for byte in slot["value"]),
                        "little",
                    ),
                )
            )
        values.sort()
        decoded[key] = [value for _, value in values]
    return decoded


def parse_dump(body, marker, tag):
    """Decode one bpftool JSON dump section with the oracle decoder."""
    section = body.split(marker, 1)[1]
    end = section.find("=== END %s ===" % tag)
    if end != -1:
        section = section[:end]
    end = section.find("--- ")
    if end != -1:
        section = section[:end]
    return decode_bpftool_percpu_dump(json.loads(section))


def phase_lines(output, label):
    """Parse one phase's <label> lines into a dict of observations."""
    found = {}
    for line in output.splitlines():
        if not line.startswith(label + "-"):
            continue
        key, _, value = line[len(label) + 1:].partition(": ")
        found[key] = value.strip()
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


def guest_run():
    if VNG_ARCH not in ("", "arm64"):
        raise EnvironmentFailure(
            "MOJOBPF_VNG_ARCH must be empty (native) or 'arm64', got %r"
            % VNG_ARCH
        )
    cross = bool(VNG_ARCH)
    if cross and not os.path.isdir(VNG_ROOT):
        raise EnvironmentFailure(
            "MOJOBPF_VNG_ROOT must point at the %s guest root, got %r"
            % (VNG_ARCH, VNG_ROOT)
        )
    cc = "aarch64-linux-gnu-gcc" if cross else "cc"
    tools = ["mojo", "llc", "vng", cc]
    if not cross:
        tools.append("bpftool")
    check_tools(*tools)
    workdir = tempfile.mkdtemp(prefix="mojo-arch-build-")
    base_obj = build_object(BASE_SOURCE, workdir, "base")
    mutated_obj = build_object(MUTATED_SOURCE, workdir, "mutated")
    map_obj = build_object(MAP_SOURCE, workdir, "map42")
    del_obj = build_object(DELETE_SOURCE, workdir, "del1")
    endian_obj = build_object(ENDIAN_SOURCE, workdir, "endian")
    cksum_obj = build_object(CHECKSUM_SOURCE, workdir, "cksum")
    pcpu_obj = build_object(PERCPU_SOURCE, workdir, "pcpu1")
    counter_obj = build_object(
        COUNTER_SOURCE, workdir, "counter",
        want_hash=TRACEPOINT_OBJECT_HASH,
    )
    emitter_obj = build_object(
        EMITTER_SOURCE, workdir, "emitter",
        want_hash=EMITTER_OBJECT_HASH,
    )
    workload = build_harness(
        WORKLOAD_SOURCE, os.path.join(workdir, "syscall_workload"), cc
    )
    holder = build_harness(
        HOLDER_SOURCE, os.path.join(workdir, "tracepoint_attach"), cc
    )
    drain = build_harness(
        DRAIN_SOURCE, os.path.join(workdir, "ringbuf_drain"), cc
    )
    packets = {}
    for fixture in FIXTURES:
        with open(os.path.join(EXAMPLE_DIR, fixture), "rb") as handle:
            packets[fixture] = handle.read()
    endian_drop = endian_drop_frame()
    endian_pass = endian_pass_frame()
    cksum_drop, cksum_pass = cksum_frames()
    if cross:
        root_tmp = os.path.join(VNG_ROOT, "tmp")
        if not os.path.isdir(root_tmp):
            raise EnvironmentFailure(
                "guest root has no tmp dir: %s" % root_tmp
            )
        stage = tempfile.mkdtemp(prefix="mojo-arch-", dir=root_tmp)
        guest_stage = os.path.join("/tmp", os.path.basename(stage))
    else:
        stage = tempfile.mkdtemp(prefix="mojo-arch-", dir="/tmp")
        guest_stage = stage
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": base_obj,
        "mutated.bpf.o": mutated_obj,
        "map42.bpf.o": map_obj,
        "del1.bpf.o": del_obj,
        "endian.bpf.o": endian_obj,
        "cksum.bpf.o": cksum_obj,
        "pcpu1.bpf.o": pcpu_obj,
        "counter.bpf.o": counter_obj,
        "emitter.bpf.o": emitter_obj,
        "syscall_workload": workload,
        "tracepoint_attach": holder,
        "ringbuf_drain": drain,
    }
    for fixture in FIXTURES:
        staged[fixture] = os.path.join(EXAMPLE_DIR, fixture)
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    blobs = {
        "endian_drop.bin": endian_drop,
        "endian_pass.bin": endian_pass,
        "cksum_drop.bin": cksum_drop,
        "cksum_pass.bin": cksum_pass,
        "data.bin": bytes(60),
        PERCPU_READER_NAME: PERCPU_READER_SOURCE.encode("utf-8"),
    }
    if cross:
        blobs["host_epoch"] = ("%d\n" % int(time.time())).encode("ascii")
    for name, data in blobs.items():
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    staged_names = sorted(list(staged) + list(blobs))
    commands = []
    for fixture in FIXTURES:
        key = fixture[len("pkt_"):-len(".bin")]
        commands.append(
            "harness_case xdp-base-%s base.bpf.o %d %s"
            % (key, classify_xdp(packets[fixture]), fixture)
        )
        commands.append(
            "harness_case xdp-mut-%s mutated.bpf.o %d %s"
            % (key, classify_xdp_mutated(packets[fixture]), fixture)
        )
    commands.append(
        "harness_case endian-drop endian.bpf.o %d endian_drop.bin"
        % XDP_DROP
    )
    commands.append(
        "harness_case endian-pass endian.bpf.o %d endian_pass.bin"
        % XDP_PASS
    )
    commands.append(
        "harness_case cksum-drop cksum.bpf.o %d cksum_drop.bin" % XDP_DROP
    )
    commands.append(
        "harness_case cksum-pass cksum.bpf.o %d cksum_pass.bin" % XDP_PASS
    )
    commands.append("map_case map42 map42.bpf.o")
    commands.append("op_probe del1 del1.bpf.o 1")
    commands.append("percpu_case pcpu1 pcpu1.bpf.o 1")
    commands.append(
        "run_phase aport counter.bpf.o /sys/fs/bpf/tp_arch_aport %d %d"
        % (COUNTER_N, COUNTER_M)
    )
    commands.append(
        "run_event_phase aportev emitter.bpf.o /sys/fs/bpf/ev_arch_aportev"
        " %d %d" % (EVENT_N, EVENT_M)
    )
    script = GUEST_SCRIPT.format(
        stage=guest_stage,
        staged_names=" ".join(staged_names),
        provision=CROSS_PROVISION if cross else NATIVE_PROVISION,
        map_name=MAP_NAME,
        init_bytes="41 0 0 0 0 0 0 0",
        reader=PERCPU_READER_NAME,
        init=INIT_VALUE,
        commands="\n".join(commands),
    )
    script_path = os.path.join(stage, "guest_arch.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in staged_names + ["guest_arch.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    for name in ("syscall_workload", "tracepoint_attach", "ringbuf_drain"):
        os.chmod(os.path.join(stage, name), 0o755)
    os.chmod(stage, 0o755)
    if cross:
        argv = [
            "vng", "--arch", VNG_ARCH, "--root", VNG_ROOT,
            "--run", VNG_RELEASE, "--disable-kvm",
            "--network", "user",
            "--rwdir", "%s=%s" % (guest_stage, stage),
            "--exec", "bash %s/guest_arch.sh" % guest_stage,
        ]
    else:
        argv = [
            "vng", "--run", VNG_RELEASE, "--disable-kvm",
            "--exec", "bash %s" % script_path,
        ]
    code, output = _run_guest(argv, stage, VNG_TIMEOUT)
    if code != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (code, stage, output[-4000:])
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
        record["_harness_exit"] = int(exit_code)
        results[tag] = record
    for match in re.finditer(
        r"=== BEGIN (\S+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, body = match.groups()
        if tag not in results:
            results[tag] = {"body": body}
    return {
        "stage": stage,
        "guest_stage": guest_stage,
        "cross": cross,
        "output": output,
        "results": results,
    }


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def test_oracle_frames():
    # Host-only: the endian/checksum frames must encode the
    # documented rules exactly.
    drop = endian_drop_frame()
    passing = endian_pass_frame()
    assert len(drop) == 28 and len(passing) == 28
    assert int.from_bytes(drop[14:16], "big") == 0x0000
    assert int.from_bytes(drop[16:18], "big") == 0xFFFF
    assert int.from_bytes(drop[18:20], "big") == 0x00FF
    assert int.from_bytes(drop[20:22], "big") == 0x8001
    assert int.from_bytes(drop[22:24], "little") == 0xFF00
    assert int.from_bytes(drop[24:28], "little") == 0x80000001
    assert passing[:20] == drop[:20] and passing[22:] == drop[22:]
    assert int.from_bytes(passing[20:22], "big") == 0x0001
    words = (0x1234, 0x5678, 0x9ABC, 0xDEF0)
    assert cksum_digest(words) == 0x1DA6, hex(cksum_digest(words))
    assert cksum_digest((0xFFFF, 0x0001)) == 0xFFFE
    assert cksum_digest((0xFFFF, 0xFFFF)) == 0x0000
    cksum_drop, cksum_pass = cksum_frames()
    assert len(cksum_drop) == 24 and len(cksum_pass) == 24
    seen = tuple(
        int.from_bytes(cksum_drop[off:off + 2], "big")
        for off in (14, 16, 18, 20)
    )
    assert seen == words
    assert int.from_bytes(cksum_drop[22:24], "big") == cksum_digest(words)
    assert cksum_pass[:22] == cksum_drop[:22]
    assert int.from_bytes(cksum_pass[22:24], "big") != cksum_digest(words)


def test_parse_possible_list_forms():
    assert parse_possible_list("0-15\n") == list(range(16))
    assert parse_possible_list("0-3,8-11") == [0, 1, 2, 3, 8, 9, 10, 11]
    assert parse_possible_list("0") == [0]
    for bad in ("", "-3", "4-2", "a-b"):
        try:
            parse_possible_list(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("CPU list %r must be rejected" % bad)


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
    marker = "arch-standin-%d" % os.getpid()
    stage = tempfile.mkdtemp(prefix="mojo-arch-standin-")
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
    table = _scan_processes()
    survivors = [
        pid for pid in _owned_descendants(os.getpid(), table)
        if table[pid][2] not in ("Z", "X")
    ]
    assert not survivors, "stand-in descendants survived: %r" % survivors


def guest_ncpu(output):
    match = re.search(r"^nprocall=(\d+)$", output, re.M)
    assert match, "guest reported no nprocall line"
    return int(match.group(1))


def test_guest_identity():
    run = executed()
    output = run["output"]
    want_arch = "aarch64" if run["cross"] else platform.machine()
    match = re.search(r"^guest-arch: (\S+)$", output, re.M)
    assert match, "guest reported no architecture"
    assert match.group(1) == want_arch, (
        "guest arch %s does not match the selected %s"
        % (match.group(1), want_arch)
    )
    match = re.search(r"^guest-kernel: (\S+)$", output, re.M)
    assert match, "guest reported no kernel release"
    assert match.group(1).startswith(GUEST_KERNEL_PREFIX), (
        "guest kernel %s does not match release %s"
        % (match.group(1), VNG_RELEASE)
    )
    assert "\nguest-id: 0:0\n" in output, "guest is not root"
    if run["cross"]:
        assert "observer: provisioned (apt bpftool)" in output
    else:
        assert "observer: native (host root)" in output
    assert re.search(r"^bpftool v\d", output, re.M), "no bpftool version line"
    assert re.search(r"^using libbpf v", output, re.M), "no libbpf version line"
    possible = re.search(r"^possible=(\S+)$", output, re.M)
    assert possible, "guest reported no possible-CPU list"
    ncpu = guest_ncpu(output)
    assert ncpu >= 1
    assert len(parse_possible_list(possible.group(1))) == ncpu, (
        "possible-list count disagrees with nprocall (%d)" % ncpu
    )
    assert "=== staged hashes ===" in output
    for name in (
        "base.bpf.o", "counter.bpf.o", "emitter.bpf.o",
        "syscall_workload", "tracepoint_attach", "ringbuf_drain",
    ):
        assert re.search(r"^[0-9a-f]{64}  %s$" % name, output, re.M), (
            "staged hash for %s missing" % name
        )


def check_harness_case(tag, want_action):
    run = executed()
    assert tag in run["results"], "guest output lacks case %s" % tag
    record = run["results"][tag]
    assert record["_harness_exit"] == 0, (
        "%s: harness exit %d (%s/%s)"
        % (
            tag,
            record["_harness_exit"],
            record.get("stage"),
            record.get("classification"),
        )
    )
    assert record["actual_action"] == want_action, (
        "%s: observed action %r, want %r"
        % (tag, record["actual_action"], want_action)
    )


def test_xdp_neutral():
    packets = {}
    for fixture in FIXTURES:
        with open(os.path.join(EXAMPLE_DIR, fixture), "rb") as handle:
            packets[fixture] = handle.read()
    assert classify_xdp(packets["pkt_drop.bin"]) == XDP_DROP
    assert classify_xdp(packets["pkt_pass.bin"]) == XDP_PASS
    assert classify_xdp(packets["pkt_short.bin"]) == XDP_PASS
    assert classify_xdp_mutated(packets["pkt_drop.bin"]) == XDP_PASS
    assert classify_xdp_mutated(packets["pkt_pass.bin"]) == XDP_DROP
    assert classify_xdp_mutated(packets["pkt_short.bin"]) == XDP_PASS
    for fixture in FIXTURES:
        key = fixture[len("pkt_"):-len(".bin")]
        check_harness_case(
            "xdp-base-%s" % key, classify_xdp(packets[fixture])
        )
        check_harness_case(
            "xdp-mut-%s" % key, classify_xdp_mutated(packets[fixture])
        )


def test_endian_words():
    check_harness_case("endian-drop", XDP_DROP)
    check_harness_case("endian-pass", XDP_PASS)


def test_checksum_window():
    check_harness_case("cksum-drop", XDP_DROP)
    check_harness_case("cksum-pass", XDP_PASS)


def check_array_identity(tag, entries):
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    assert fields.get("load_exit") == "0", "%s: load failed" % tag
    assert fields.get("mapinfo_exit") == "0", "%s: mapinfo failed" % tag
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "array", "%s: not an array map" % tag
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", "%s: value is not u64" % tag
    assert fields.get("map_entries") == str(entries), (
        "%s: not %d entries" % (tag, entries)
    )
    return fields


def test_map_roundtrip_42():
    tag = "map42"
    fields = check_array_identity(tag, 1)
    assert fields.get("init_exit") == "0", "%s: init failed" % tag
    assert fields.get("before_exit") == "0", "%s: before failed" % tag
    assert fields.get("run_exit") == "0", "%s: run failed" % tag
    assert fields.get("after_exit") == "0", "%s: after failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body, "--- %s run ---" % tag) == XDP_PASS, (
        "%s: test-run action must be PASS" % tag
    )
    assert parse_lookup_hex(body, "before ---") == hexle(INIT_VALUE), (
        "%s: entry must start at %d" % (tag, INIT_VALUE)
    )
    assert parse_lookup_hex(body, "after ---") == hexle(HIT_VALUE), (
        "%s: entry must move to %d" % (tag, HIT_VALUE)
    )


def test_delete_probe():
    tag = "del1"
    fields = check_array_identity(tag, 1)
    assert fields.get("run_exit") == "0", "%s: run failed" % tag
    assert fields.get("key0_exit") == "0", "%s: key0 lookup failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body, "--- %s run ---" % tag) == XDP_PASS, (
        "%s: test-run action must be PASS" % tag
    )
    assert parse_lookup_hex(body, "key0 ---") == hexle(0), (
        "%s: entry must still read zero" % tag
    )


def test_percpu_rmw1():
    tag = "pcpu1"
    ncpu = guest_ncpu(executed()["output"])
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    assert fields.get("load_exit") == "0", "%s: load failed" % tag
    assert fields.get("mapinfo_exit") == "0", "%s: mapinfo failed" % tag
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "percpu_array", (
        "%s: not a per-CPU array map" % tag
    )
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", "%s: value is not u64" % tag
    assert fields.get("map_entries") == "1", "%s: not 1 entry" % tag
    assert fields.get("map_pin_exit") == "0", "%s: map pin failed" % tag
    assert fields.get("init0_exit") == "0", "%s: init0 failed" % tag
    assert fields.get("run_exit") == "0", "%s: run failed" % tag
    assert fields.get("key0_exit") == "0", "%s: key0 read failed" % tag
    assert fields.get("dump_exit") == "0", "%s: dump failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    assert fields.get("ncpu") == str(ncpu), (
        "%s: guest ncpu %s disagrees with %d"
        % (tag, fields.get("ncpu"), ncpu)
    )
    assert parse_run_action(body, "--- %s run ---" % tag) == XDP_PASS, (
        "%s: test-run action must be PASS" % tag
    )
    before = parse_raw_values(body, "init0 ---", ncpu)
    assert before == [INIT_VALUE] * ncpu, (
        "%s: entry must start at %d on every CPU, got %r"
        % (tag, INIT_VALUE, before)
    )
    observed = parse_raw_values(body, "key0 ---", ncpu)
    assert sorted(observed) == sorted(
        [INIT_VALUE] * (ncpu - 1) + [HIT_VALUE]
    ), (
        "%s: entry must hold one %d among %ds, got %r"
        % (tag, HIT_VALUE, INIT_VALUE, observed)
    )
    assert sum(observed) == INIT_VALUE * ncpu + 1, (
        "%s: entry total must be %d, got %d"
        % (tag, INIT_VALUE * ncpu + 1, sum(observed))
    )
    oracle = parse_dump(body, "--- %s dump ---" % tag, tag)
    assert oracle[0] == observed, (
        "%s: bpftool dump %r disagrees with raw %r"
        % (tag, oracle[0], observed)
    )


def test_counter_exact():
    output = executed()["output"]
    phase = phase_lines(output, "aport")
    for key in ("tids", "done", "filter", "counter"):
        assert key in phase, "aport phase is missing %s" % key
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (COUNTER_N, COUNTER_M, COUNTER_M)
    ), phase["done"]
    assert phase["filter"] == "want=%s readback=%s" % (
        tids["monitored"], tids["monitored"],
    ), phase["filter"]
    assert phase["counter"] == str(COUNTER_N), phase["counter"]


def test_event_healthy():
    output = executed()["output"]
    max_cpu = guest_ncpu(output)
    phase = phase_lines(output, "aportev")
    for key in ("tids", "done", "filter", "counters", "drained", "ring"):
        assert key in phase, "aportev phase is missing %s" % key
    tids = phase_tids(phase["tids"])
    assert phase["done"] == (
        "DONE monitored=%d excl1=%d excl2=%d"
        % (EVENT_N, EVENT_M, EVENT_M)
    ), phase["done"]
    assert phase["filter"] == "want=%s readback=%s" % (
        tids["monitored"], tids["monitored"],
    ), phase["filter"]
    attempted, successful, failed = phase_counters(phase["counters"])
    assert (attempted, successful, failed) == (EVENT_N, EVENT_N, 0), (
        attempted, successful, failed,
    )
    assert phase["drained"] == str(EVENT_N), phase["drained"]
    assert phase["ring"] == "0 %d %d" % (
        EVENT_N * 40, EVENT_N * 40,
    ), phase["ring"]
    try:
        records = decode_event_stream(frames_blob(output, "aportev"))
    except EventDecodeError as exc:
        raise ProofFailure("aportev fails decoding: %s" % exc)
    report = check_event_run(
        records,
        expect_tgid=int(tids["observer"]),
        expect_tid=int(tids["monitored"]),
        max_cpu=max_cpu,
    )
    assert report.received == EVENT_N, report
    assert report.first_sequence == 0, report
    assert report.last_sequence == EVENT_N - 1, report
    assert report.gap_total == 0, report
    check_accounting(
        attempted=attempted,
        successful=successful,
        failed=failed,
        received=report.received,
        gap_total=report.gap_total,
    )


def test_residue_clean():
    output = executed()["output"]
    assert "baseline-links:" in output, "guest recorded no residue baseline"
    assert "residue clean" in output, output[-2000:]
    assert "STRAY-" not in output, "guest left residue"


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
    print("arch portability: guest behavior matches on this lane")
    print("guest stage kept at: %s" % executed()["stage"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
