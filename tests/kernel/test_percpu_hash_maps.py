# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the per-CPU hash map SDK slice.

Builds the one-pair per-CPU-hash round trip
(``tests/compile/percpuhash_rmw1.mojo``), the two-pair round trip
(``tests/compile/percpuhash_rmw2.mojo``), the four-pair round trip
(``tests/compile/percpuhash_rmw4.mojo``), the one-deletion
per-CPU-hash probe (``tests/compile/percpuhash_delete1.mojo``), and
the out-of-bounds and unchecked negatives through the genuine
pipeline (``mojo build --emit llvm`` with the packaged SDK on the
import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable
2-CPU Linux guest and drives the per-CPU-hash map lifecycle
with unmodified bpftool plus a staged raw-syscall probe for the
per-CPU value buffers.

Lifecycle/count legs run the 1-entry shape (exactly one program
update per run), miss runs the 2-entry shape with at most one
live entry, and delete runs the 1-entry shape. The 2-4-entry
round-trip shapes stay proven by the host structural suite.
Iteration and the full-map leg run the 4-entry shape at safe
occupancy (userspace only). Every per-CPU value assertion pins
exact per-slot bytes on both CPUs: the running CPU's slot moves
while the other CPU's slot stays, and the per-entry total is
exact. Test-runs are pinned with ``taskset`` so the running CPU
is deterministic:

* lifecycle: load the program, read the libbpf-created map parameters,
  initialize key 0 to 41 on both CPUs from userspace, execute one
  kernel test-run pinned to CPU 0, and read the key back
  independently (CPU 0 must observe 42 and CPU 1 must still
  observe 41, with exact little-endian bytes; keys 1-3 must miss
  before and after the run);
* exact counts: from a fresh load initialized to 1000 on both
  CPUs, a 10-repeat run pinned to CPU 0 must observe exactly
  1010 on CPU 0 with CPU 1 still at 1000, and five further runs
  exactly 1015 with CPU 1 still at 1000;
* miss path: on a fresh map every key misses (userspace and kernel
  agree); one test-run inserts nothing; inserting key 0 from
  userspace and running again observes exactly CPU 0 incremented
  while every other key still misses;
* deletion: the delete probe observes success on every present key
  (the XDP_PASS action) and every entry is gone afterwards; a
  userspace re-insert reads back exactly on both CPUs, a
  userspace delete removes it, and deleting an absent key fails
  explicitly;
* iteration: arbitrary u32 keys (including 0xDEADBEEF) insert and
  read back with exact little-endian key bytes and exact
  per-CPU value bytes; a get-next-key walk plus a JSON dump
  observe exactly the inserted set (hash order is unspecified,
  so the assertion is set equality, never order); short keys
  and values are refused instead of misdecoded;
* full map: four sequential inserts into the 4-entry map all
  succeed and the fifth fails ``E2BIG`` (the LRU contrast,
  where the fifth insert evicts instead of failing); the dump
  holds exactly the four entries with exact per-CPU values;
* isolation: from a fresh load initialized to 41 on both CPUs,
  a run pinned to CPU 0 moves only slot 0 to 42 and a run
  pinned to CPU 1 moves only slot 1 to 42, proving each CPU
  reads and writes its own slot;
* control: a pinned stock-C object (the D3 control) driven
  identically to the Mojo object observes byte-identical
  per-CPU values and an identical JSON dump;
* the out-of-bounds fixture is rejected by the kernel verifier at load
  (layout mismatch is never silently misdecoded);
* the unchecked-dereference fixture is rejected by the kernel verifier
  at load (the missing-null-check negative).

The two kernel-layer negatives go through the load/test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is).

Per-CPU value bytes travel two independent paths: the staged
probe reads the exact raw per-CPU buffer through ``bpf()``
(decoded only by this file's decoder) and ``bpftool -j map
dump`` cross-checks every slot (the independent oracle). The
guest reports 2 CPUs and the host asserts the count before any
per-CPU assertion runs.

The license gate agrees with the kernel: the built per-CPU-hash
objects pass inspection cleanly under the per-CPU-hash
capability profile, the helper-license preflight admits the
used helpers (1, 2, 3) under the project's non-GPL declaration,
and the same preflight still refuses the GPL-only witness
there, so the admission is not vacuous.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng`` (virtme-ng)
with a cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools fail loudly as
environment failures, never as passes. The per-CPU-hash kind has
no parsed lowering yet, so MOJOBPF_GUEST_ROUTE=parsed is refused
here; the default lane-a keeps the committed pins.

Runnable directly (``python3 tests/kernel/test_percpu_hash_maps.py``) or
under any ``test_``-style runner. Standard library only. The guest boot
takes a few minutes under software emulation; all cases share one boot.
The guest command runs as a session leader and a timeout kills the
whole owned guest tree (the runner group plus any detached emulator
groups it booted), never just the direct child.
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
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import lane_lock  # noqa: E402
import guest_proc  # noqa: E402
import tool_admission  # noqa: E402
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
# Lifecycle/count/isolation legs run the 1-entry shape (exactly
# one program update per run, the proven-safe pattern); miss
# runs the 2-entry shape with at most one live entry; delete
# runs the 1-entry shape. Iteration and the full-map leg run
# the 4-entry shape at safe occupancy (userspace only).
RMW1_SOURCE = os.path.join(COMPILE_DIR, "percpuhash_rmw1.mojo")
RMW2_SOURCE = os.path.join(COMPILE_DIR, "percpuhash_rmw2.mojo")
RMW4_SOURCE = os.path.join(COMPILE_DIR, "percpuhash_rmw4.mojo")
DELETE_SOURCE = os.path.join(COMPILE_DIR, "percpuhash_delete1.mojo")
OOB_SOURCE = os.path.join(COMPILE_DIR, "percpuhash_oob.mojo")
UNCHECKED_SOURCE = os.path.join(COMPILE_DIR, "percpuhash_unchecked.mojo")
CREF_SOURCE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "percpuhash_roundtrip_ref.bpf.c"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900
# Guest object route. Lane-A keeps the committed
# kernel-behavior pins; the per-CPU-hash kind has no parsed
# lowering yet, so MOJOBPF_GUEST_ROUTE=parsed is refused in
# build_object. Anything else fails loudly: a new route must
# earn its own builder.
GUEST_ROUTE = os.environ.get("MOJOBPF_GUEST_ROUTE", "lane-a")
# Guest CPU count: the suite boots with --cpus 2 and asserts
# the reported count before any per-CPU assertion runs.
WANT_NCPU = 2

INIT_VALUE = 41
AFTER_VALUE = 42
COUNT_INIT = 1000
COUNT_FIRST_REPEAT = 10
COUNT_FIRST_VALUE = COUNT_INIT + COUNT_FIRST_REPEAT
COUNT_SECOND_REPEAT = 5
COUNT_SECOND_VALUE = COUNT_FIRST_VALUE + COUNT_SECOND_REPEAT
MAP_NAME = "mojobpf_map0"
PERCPUHASH_PROFILE = "linux-bpfel-v3-percpu-hash"
APACHE = "Apache-2.0 WITH LLVM-exception"

MISS_ABSENT_KEY = 5
MISS_INSERT_VALUE = 7
MISS_AFTER_VALUE = 8
DEL_INIT = 9
DEL_REINSERT_KEY = 1
DEL_REINSERT_VALUE = 5
# (key, base, step) triples for the iteration case: small keys
# plus a full-width key/value pair pinning little-endian
# layout. Slot cpu holds base + cpu * step, so every slot
# carries distinct bytes.
ITER_TRIPLES = (
    (7, 700, 1),
    (42, 4200, 10),
    (0xDEADBEEF, 0x1122334455667788, 0x100),
)
# Lifecycle/count/delete/isolation legs keep exactly these keys
# live.
LIVE_KEYS = (0,)
# Keys the 1-entry lifecycle shape never touches: they must miss
# before and after every run.
ABSENT_KEYS = (1, 2, 3)
# Full-map case: this many sequential inserts into the 4-entry
# map (per-CPU values 40+k on every slot); the first four must
# succeed and the fifth must fail E2BIG, the LRU contrast.
FULL_TOTAL = 5
FULL_BASE_VALUE = 40

OOB_LOG_LINE = "invalid access to map value"
UNCHECKED_LOG_LINE = "invalid mem access 'map_value_or_null'"


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def hexle(value):
    """Lowercase hex of a u64 value without spaces (bpftool byte order)."""
    return "".join(
        "%02x" % byte for byte in value.to_bytes(8, byteorder="little")
    )


def key_bytes(key):
    """Space-separated LE bytes of a u32 key for bpftool arguments."""
    return " ".join(
        "%d" % byte for byte in key.to_bytes(4, byteorder="little")
    )


def value_bytes(value):
    """Space-separated LE bytes of a u64 for bpftool value arguments."""
    return " ".join(
        "%d" % byte for byte in value.to_bytes(8, byteorder="little")
    )


# ---------------------------------------------------------------------------
# Independent per-CPU decoder (host-side; the guest prints raw facts only).
# ---------------------------------------------------------------------------

def parse_possible_list(text):
    """Parse a kernel CPU list (``0-15``, ``0-3,8-11``, ``0``) to CPU ids."""
    cleaned = text.strip()
    if not cleaned:
        raise ValueError("empty CPU list")
    cpus = []
    for part in cleaned.split(","):
        part = part.strip()
        if "-" in part:
            first, _, last = part.partition("-")
            cpus.extend(range(int(first), int(last) + 1))
        else:
            cpus.append(int(part))
    ordered = sorted(set(cpus))
    if not ordered or any(cpu < 0 for cpu in ordered):
        raise ValueError("invalid CPU list: %r" % text)
    return ordered


def percpu_stride(value_size):
    """Return the per-CPU stride: values are 8-byte aligned in memory."""
    if value_size <= 0:
        raise ValueError("value size must be positive")
    return (value_size + 7) // 8 * 8


def decode_percpu_values(raw, value_size, ncpu):
    """Decode one key's raw per-CPU buffer to little-endian integers."""
    stride = percpu_stride(value_size)
    expect = ncpu * stride
    if len(raw) != expect:
        raise ValueError(
            "raw buffer holds %d bytes, expected %d (%d CPUs x stride %d)"
            % (len(raw), expect, ncpu, stride)
        )
    values = []
    for cpu in range(ncpu):
        slot = raw[cpu * stride:(cpu + 1) * stride]
        values.append(int.from_bytes(slot[:value_size], "little"))
    return values


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


def test_key_value_byte_helpers():
    assert key_bytes(0) == "0 0 0 0"
    assert key_bytes(0xDEADBEEF) == "239 190 173 222"
    assert value_bytes(42) == "42 0 0 0 0 0 0 0"
    assert value_bytes(0x1122334455667788) == "136 119 102 85 68 51 34 17"
    assert hexle(42) == "2a00000000000000"
    assert hexle(0x1122334455667788) == "8877665544332211"


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


def test_percpu_stride_padding():
    assert percpu_stride(8) == 8
    assert percpu_stride(4) == 8
    try:
        percpu_stride(0)
    except ValueError:
        pass
    else:
        raise AssertionError("zero value size must be rejected")


def test_decode_values_exact():
    raw = b"".join(
        (41 + (cpu == 2)).to_bytes(8, "little") for cpu in range(4)
    )
    assert decode_percpu_values(raw, 8, 4) == [41, 41, 42, 41]
    try:
        decode_percpu_values(raw, 8, 5)
    except ValueError:
        pass
    else:
        raise AssertionError("short buffer must be rejected")


def test_decode_bpftool_dump_shape():
    doc = [
        {
            "key": ["0x00", "0x00", "0x00", "0x00"],
            "values": [
                {"cpu": 1, "value": ["0x2a", "0x00", "0x00", "0x00",
                                     "0x00", "0x00", "0x00", "0x00"]},
                {"cpu": 0, "value": ["0x29", "0x00", "0x00", "0x00",
                                     "0x00", "0x00", "0x00", "0x00"]},
            ],
        }
    ]
    assert decode_bpftool_percpu_dump(doc) == {0: [41, 42]}


# In-guest syscall helper (staged into the guest; prints raw facts only).
# ---------------------------------------------------------------------------
#
# The helper performs raw bpf() syscalls against a pinned map: write
# one key's full per-CPU buffer (init) or read it back (read). It
# prints the raw buffer as hex and never decodes it; decoding stays
# host-side in this file so the decoder above is what the assertions
# exercise.

HELPER_SOURCE = '''\
import ctypes
import os
import sys

SYS_BPF = 321
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

HELPER_NAME = "pcpu_probe.py"


def sha256_file(path):
    digest = hashlib.sha256()
    with guest_proc.open_consumed(path, "rb") as handle:
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


@guest_proc.consumes_source
def build_c(source, workdir):
    """Build the stock-C control object with the pinned clang."""
    object_path = os.path.join(workdir, "percpuhash_cref.bpf.o")
    proc = run_step(
        ["clang", "--target=bpf", "-mcpu=v3", "-O2", "-g", "-c",
         source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "C reference build failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if "warning:" in proc.stderr.lower() or "error:" in proc.stderr.lower():
        raise AssertionError(
            "C reference build diagnostics:\n%s" % proc.stderr
        )
    return object_path


@guest_proc.consumes_source
def build_object(source, workdir, name, entries=1):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        [
            "mojo",
            "build",
            "--emit",
            "llvm",
            *FRONTEND_TARGET_FLAGS,
            "-I",
            SDK_INCLUDE,
            "-o",
            raw_path,
            source,
        ]
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
    if GUEST_ROUTE == "lane-a":
        proc = run_step(
            [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
        )
    elif GUEST_ROUTE == "parsed":
        raise EnvironmentFailure(
            "per-CPU-hash kind has no parsed lowering yet; "
            "run with MOJOBPF_GUEST_ROUTE unset (lane-a)"
        )
    else:
        raise EnvironmentFailure(
            "unknown MOJOBPF_GUEST_ROUTE %r (want lane-a or parsed)"
            % (GUEST_ROUTE,)
        )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            adapted_path,
            "-o",
            object_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


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


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
{bpftool_prologue}
echo "=== begin guest_percpu_hash ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "possible=$(cat /sys/devices/system/cpu/possible)"
echo "online=$(cat /sys/devices/system/cpu/online)"
echo "nproc=$(nproc)"
echo "nprocall=$(nproc --all)"
echo "=== staged hashes ==="
sha256sum bpf_test_run.py pcpu_probe.py percpuhash_rmw1.bpf.o percpuhash_rmw2.bpf.o percpuhash_rmw4.bpf.o percpuhash_del.bpf.o percpuhash_oob.bpf.o percpuhash_unchecked.bpf.o percpuhash_cref.bpf.o data.bin guest_percpu_hash.sh
map_info() {{
  out="$1"
  python3 - "$out" >/tmp/xdp-mapinfo.stderr 2>&1 <<'PYEOF'
import json
import subprocess
import sys
fields = sys.argv[1]
info = {{"map_found": "0"}}
try:
    raw = subprocess.run(
        [{bpftool_argv0}, "-j", "map", "show"],
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
unpin_map() {{
  tag="$1"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  rm -f "$pin" "$mappin"
  if [ -e "$pin" ] || [ -e "$mappin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
}}
life_case() {{
  tag="life"; obj="percpuhash_rmw1.bpf.o"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  ncpu=$(nproc --all)
  for key in {live_keys}; do
    python3 pcpu_probe.py init "$mappin" "$key" 8 "$ncpu" {init_base} {init_step} > /tmp/xdp-$tag.init$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  for key in {live_keys}; do
    "$BPFTOOL" map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.before$key 2>&1
    echo "before${{key}}_exit=$?" >> "$out"
  done
  for key in {absent_keys}; do
    "$BPFTOOL" map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.absent$key 2>&1
    echo "absent${{key}}_exit=$?" >> "$out"
  done
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  for key in {live_keys}; do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/xdp-$tag.after$key 2>&1
    echo "after${{key}}_exit=$?" >> "$out"
  done
  "$BPFTOOL" -j map dump pinned "$mappin" > /tmp/xdp-$tag.dump 2>/tmp/xdp-$tag.dump.err
  echo "dump_exit=$?" >> "$out"
  for key in {absent_keys}; do
    "$BPFTOOL" map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.stillabsent$key 2>&1
    echo "stillabsent${{key}}_exit=$?" >> "$out"
  done
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  for key in {live_keys}; do
    echo "--- $tag init$key ---"
    cat /tmp/xdp-$tag.init$key
  done
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  for key in {live_keys}; do
    echo "--- $tag after$key ---"
    cat /tmp/xdp-$tag.after$key
  done
  echo "--- $tag dump ---"
  cat /tmp/xdp-$tag.dump
  for key in {absent_keys}; do
    echo "--- $tag absent$key ---"
    cat /tmp/xdp-$tag.absent$key
  done
  for key in {absent_keys}; do
    echo "--- $tag stillabsent$key ---"
    cat /tmp/xdp-$tag.stillabsent$key
  done
  echo "=== END $tag ==="
}}
count_case() {{
  tag="count"; obj="percpuhash_rmw1.bpf.o"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  ncpu=$(nproc --all)
  for key in {live_keys}; do
    python3 pcpu_probe.py init "$mappin" "$key" 8 "$ncpu" {count_init_base} {count_init_step} > /tmp/xdp-$tag.update$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat {first_repeat} > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  for key in {live_keys}; do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/xdp-$tag.after1$key 2>&1
    echo "after1_${{key}}_exit=$?" >> "$out"
  done
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat {second_repeat} > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  for key in {live_keys}; do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/xdp-$tag.after2$key 2>&1
    echo "after2_${{key}}_exit=$?" >> "$out"
  done
  "$BPFTOOL" -j map dump pinned "$mappin" > /tmp/xdp-$tag.dump 2>/tmp/xdp-$tag.dump.err
  echo "dump_exit=$?" >> "$out"
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  for key in {live_keys}; do
    echo "--- $tag after1_$key ---"
    cat /tmp/xdp-$tag.after1$key
  done
  echo "--- $tag run2 ---"
  cat /tmp/xdp-$tag.run2
  for key in {live_keys}; do
    echo "--- $tag after2_$key ---"
    cat /tmp/xdp-$tag.after2$key
  done
  echo "--- $tag dump ---"
  cat /tmp/xdp-$tag.dump
  echo "=== END $tag ==="
}}
miss_case() {{
  tag="miss"; obj="percpuhash_rmw2.bpf.o"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  ncpu=$(nproc --all)
  for key in 0 1 2 3 {absent_key}; do
    "$BPFTOOL" map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.fresh$key 2>&1
    echo "fresh${{key}}_exit=$?" >> "$out"
  done
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  for key in 0 1 2 3 {absent_key}; do
    "$BPFTOOL" map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.still$key 2>&1
    echo "still${{key}}_exit=$?" >> "$out"
  done
  python3 pcpu_probe.py init "$mappin" 0 8 "$ncpu" {miss_init_base} {miss_init_step} > /tmp/xdp-$tag.insert 2>&1
  echo "insert_exit=$?" >> "$out"
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  python3 pcpu_probe.py read "$mappin" 0 8 "$ncpu" > /tmp/xdp-$tag.got0 2>&1
  echo "got0_exit=$?" >> "$out"
  for key in 1 2 3 {absent_key}; do
    "$BPFTOOL" map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.rest$key 2>&1
    echo "rest${{key}}_exit=$?" >> "$out"
  done
  "$BPFTOOL" -j map dump pinned "$mappin" > /tmp/xdp-$tag.dump 2>/tmp/xdp-$tag.dump.err
  echo "dump_exit=$?" >> "$out"
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  for key in 0 1 2 3 {absent_key}; do
    echo "--- $tag fresh$key ---"
    cat /tmp/xdp-$tag.fresh$key
  done
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  for key in 0 1 2 3 {absent_key}; do
    echo "--- $tag still$key ---"
    cat /tmp/xdp-$tag.still$key
  done
  echo "--- $tag run2 ---"
  cat /tmp/xdp-$tag.run2
  echo "--- $tag got0 ---"
  cat /tmp/xdp-$tag.got0
  for key in 1 2 3 {absent_key}; do
    echo "--- $tag rest$key ---"
    cat /tmp/xdp-$tag.rest$key
  done
  echo "--- $tag dump ---"
  cat /tmp/xdp-$tag.dump
  echo "=== END $tag ==="
}}
delete_case() {{
  tag="delete"; obj="percpuhash_del.bpf.o"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  ncpu=$(nproc --all)
  for key in {live_keys}; do
    python3 pcpu_probe.py init "$mappin" "$key" 8 "$ncpu" {del_base} {del_step} > /tmp/xdp-$tag.init$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  for key in {live_keys}; do
    "$BPFTOOL" map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.gone$key 2>&1
    echo "gone${{key}}_exit=$?" >> "$out"
  done
  python3 pcpu_probe.py init "$mappin" {del_reinsert_key} 8 "$ncpu" {del_reinsert_base} {del_reinsert_step} > /tmp/xdp-$tag.reinsert 2>&1
  echo "reinsert_exit=$?" >> "$out"
  python3 pcpu_probe.py read "$mappin" {del_reinsert_key} 8 "$ncpu" > /tmp/xdp-$tag.rehit 2>&1
  echo "rehit_exit=$?" >> "$out"
  "$BPFTOOL" map delete id "$map_id" key {del_reinsert_key} 0 0 0 > /tmp/xdp-$tag.udel 2>&1
  echo "udel_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key {del_reinsert_key} 0 0 0 > /tmp/xdp-$tag.ugone 2>&1
  echo "ugone_exit=$?" >> "$out"
  "$BPFTOOL" map delete id "$map_id" key {del_reinsert_key} 0 0 0 > /tmp/xdp-$tag.umiss 2>&1
  echo "umiss_exit=$?" >> "$out"
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  for key in {live_keys}; do
    echo "--- $tag gone$key ---"
    cat /tmp/xdp-$tag.gone$key
  done
  echo "--- $tag rehit ---"
  cat /tmp/xdp-$tag.rehit
  echo "--- $tag ugone ---"
  cat /tmp/xdp-$tag.ugone
  echo "--- $tag umiss ---"
  cat /tmp/xdp-$tag.umiss
  echo "=== END $tag ==="
}}
iter_case() {{
  tag="iter"; obj="percpuhash_rmw4.bpf.o"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  # Pin every map operation to one CPU for deterministic
  # placement; the per-CPU values themselves are set
  # explicitly per slot by the probe.
  PIN="taskset -c 0"
  ncpu=$(nproc --all)
  $PIN "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  $PIN "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  $PIN python3 pcpu_probe.py init "$mappin" {iter0_key} 8 "$ncpu" {iter0_base} {iter0_step} > /tmp/xdp-$tag.ins0 2>&1
  echo "ins0_exit=$?" >> "$out"
  $PIN python3 pcpu_probe.py init "$mappin" {iter1_key} 8 "$ncpu" {iter1_base} {iter1_step} > /tmp/xdp-$tag.ins1 2>&1
  echo "ins1_exit=$?" >> "$out"
  $PIN python3 pcpu_probe.py init "$mappin" {iter2_key} 8 "$ncpu" {iter2_base} {iter2_step} > /tmp/xdp-$tag.ins2 2>&1
  echo "ins2_exit=$?" >> "$out"
  $PIN "$BPFTOOL" -j map dump id "$map_id" > /tmp/xdp-$tag.dump1 2>/tmp/xdp-$tag.dump1.err
  echo "dump1_exit=$?" >> "$out"
  $PIN "$BPFTOOL" map getnext id "$map_id" key {iter0_key_le} > /tmp/xdp-$tag.gx0 2>&1
  echo "gx0_exit=$?" >> "$out"
  $PIN "$BPFTOOL" map getnext id "$map_id" key {iter1_key_le} > /tmp/xdp-$tag.gx1 2>&1
  echo "gx1_exit=$?" >> "$out"
  $PIN "$BPFTOOL" map getnext id "$map_id" key {iter2_key_le} > /tmp/xdp-$tag.gx2 2>&1
  echo "gx2_exit=$?" >> "$out"
  $PIN "$BPFTOOL" map delete id "$map_id" key {iter1_key_le} > /tmp/xdp-$tag.shrink 2>&1
  echo "shrink_exit=$?" >> "$out"
  $PIN "$BPFTOOL" -j map dump id "$map_id" > /tmp/xdp-$tag.dump2 2>/tmp/xdp-$tag.dump2.err
  echo "dump2_exit=$?" >> "$out"
  $PIN "$BPFTOOL" map update id "$map_id" key 0 0 value 1 0 0 0 0 0 0 0 > /tmp/xdp-$tag.shortkey 2>&1
  echo "shortkey_exit=$?" >> "$out"
  $PIN "$BPFTOOL" map update id "$map_id" key 0 0 0 0 value 1 0 0 0 > /tmp/xdp-$tag.shortval 2>&1
  echo "shortval_exit=$?" >> "$out"
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag dump1 ---"
  cat /tmp/xdp-$tag.dump1
  echo "--- $tag gx0 ---"
  cat /tmp/xdp-$tag.gx0
  echo "--- $tag gx1 ---"
  cat /tmp/xdp-$tag.gx1
  echo "--- $tag gx2 ---"
  cat /tmp/xdp-$tag.gx2
  echo "--- $tag dump2 ---"
  cat /tmp/xdp-$tag.dump2
  echo "--- $tag shortkey ---"
  cat /tmp/xdp-$tag.shortkey
  echo "--- $tag shortval ---"
  cat /tmp/xdp-$tag.shortval
  echo "=== END $tag ==="
}}
full_case() {{
  tag="full"; obj="percpuhash_rmw4.bpf.o"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  ncpu=$(nproc --all)
  k=0
  while [ "$k" -lt {full_last_key} ]; do
    python3 pcpu_probe.py init "$mappin" "$k" 8 "$ncpu" $(({full_base} + k)) 0 > /tmp/xdp-$tag.ins$k 2>&1
    echo "ins${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  python3 pcpu_probe.py init "$mappin" {full_last_key} 8 "$ncpu" $(({full_base} + {full_last_key})) 0 > /tmp/xdp-$tag.insfull 2>&1
  echo "insfull_exit=$?" >> "$out"
  "$BPFTOOL" -j map dump pinned "$mappin" > /tmp/xdp-$tag.dump 2>/tmp/xdp-$tag.dump.err
  echo "dump_exit=$?" >> "$out"
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag insfull ---"
  cat /tmp/xdp-$tag.insfull
  echo "--- $tag dump ---"
  cat /tmp/xdp-$tag.dump
  echo "=== END $tag ==="
}}
isol_case() {{
  tag="isol"; obj="percpuhash_rmw1.bpf.o"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  ncpu=$(nproc --all)
  for key in {live_keys}; do
    python3 pcpu_probe.py init "$mappin" "$key" 8 "$ncpu" {init_base} {init_step} > /tmp/xdp-$tag.init$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run0 2>&1
  echo "run0_exit=$?" >> "$out"
  for key in {live_keys}; do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/xdp-$tag.iso0$key 2>&1
    echo "iso0_${{key}}_exit=$?" >> "$out"
  done
  taskset -c 1 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  for key in {live_keys}; do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/xdp-$tag.iso1$key 2>&1
    echo "iso1_${{key}}_exit=$?" >> "$out"
  done
  "$BPFTOOL" -j map dump pinned "$mappin" > /tmp/xdp-$tag.dump 2>/tmp/xdp-$tag.dump.err
  echo "dump_exit=$?" >> "$out"
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run0 ---"
  cat /tmp/xdp-$tag.run0
  for key in {live_keys}; do
    echo "--- $tag iso0_$key ---"
    cat /tmp/xdp-$tag.iso0$key
  done
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  for key in {live_keys}; do
    echo "--- $tag iso1_$key ---"
    cat /tmp/xdp-$tag.iso1$key
  done
  echo "--- $tag dump ---"
  cat /tmp/xdp-$tag.dump
  echo "=== END $tag ==="
}}
control_side() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_phash_$tag"
  mappin="/sys/fs/bpf/mojobpf_pphm_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map pin id "$map_id" "$mappin" >/tmp/xdp-$tag.pin 2>&1
  echo "map_pin_exit=$?" >> "$out"
  ncpu=$(nproc --all)
  python3 pcpu_probe.py init "$mappin" 0 8 "$ncpu" {init_base} {init_step} > /tmp/xdp-$tag.init 2>&1
  echo "init_exit=$?" >> "$out"
  taskset -c 0 "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  python3 pcpu_probe.py read "$mappin" 0 8 "$ncpu" > /tmp/xdp-$tag.after 2>&1
  echo "after_exit=$?" >> "$out"
  "$BPFTOOL" -j map dump pinned "$mappin" > /tmp/xdp-$tag.dump 2>/tmp/xdp-$tag.dump.err
  echo "dump_exit=$?" >> "$out"
  unpin_map "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  echo "--- $tag after ---"
  cat /tmp/xdp-$tag.after
  echo "--- $tag dump ---"
  cat /tmp/xdp-$tag.dump
  echo "=== END $tag ==="
}}
neg_case() {{
  tag="$1"; obj="$2"
  out="/tmp/xdp-$tag.json"
  pin="/sys/fs/bpf/mojobpf-neg-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-neg-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action {action} \\
    --data-in data.bin {harness_flags} --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-neg-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== BEGIN residue ==="
echo "--- residue prog ---"
"$BPFTOOL" -j prog show 2>&1; prog_exit=$?
echo "--- residue map ---"
"$BPFTOOL" -j map show 2>&1; map_exit=$?
echo "residue_prog_exit=$prog_exit"
echo "residue_map_exit=$map_exit"
echo "=== END residue ==="
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_phash_* /sys/fs/bpf/mojobpf_pphm_* /sys/fs/bpf/mojobpf-neg-* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_percpu_hash ==="
"""

CASES = (
    ("life", "percpuhash_rmw1.bpf.o", "life"),
    ("count", "percpuhash_rmw1.bpf.o", "count"),
    ("miss", "percpuhash_rmw2.bpf.o", "miss"),
    ("delete", "percpuhash_del.bpf.o", "delete"),
    ("iter", "percpuhash_rmw4.bpf.o", "iter"),
    ("full", "percpuhash_rmw4.bpf.o", "full"),
    ("isol", "percpuhash_rmw1.bpf.o", "isol"),
    ("oob", "percpuhash_oob.bpf.o", "neg"),
    ("unchecked", "percpuhash_unchecked.bpf.o", "neg"),
    ("controlm", "percpuhash_rmw1.bpf.o", "control-side"),
    ("controlc", "percpuhash_cref.bpf.o", "control-side"),
)


def guest_run():
    """Build all objects, boot one guest, return parsed case results."""
    for tool in ("mojo", "llc", "clang", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        RMW1_SOURCE,
        RMW2_SOURCE,
        RMW4_SOURCE,
        DELETE_SOURCE,
        OOB_SOURCE,
        UNCHECKED_SOURCE,
        CREF_SOURCE,
        ADAPTER,
        HARNESS,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-percpu-hash-", dir="/tmp")
    staged = {
        "bpf_test_run.py": HARNESS,
        "percpuhash_rmw1.bpf.o": build_object(RMW1_SOURCE, stage, "percpuhash_rmw1"),
        "percpuhash_rmw2.bpf.o": build_object(
            RMW2_SOURCE, stage, "percpuhash_rmw2", entries=2,
        ),
        "percpuhash_rmw4.bpf.o": build_object(
            RMW4_SOURCE, stage, "percpuhash_rmw4", entries=4,
        ),
        "percpuhash_del.bpf.o": build_object(DELETE_SOURCE, stage, "percpuhash_del"),
        "percpuhash_oob.bpf.o": build_object(OOB_SOURCE, stage, "percpuhash_oob"),
        "percpuhash_unchecked.bpf.o": build_object(
            UNCHECKED_SOURCE, stage, "percpuhash_unchecked"
        ),
        "percpuhash_cref.bpf.o": build_c(CREF_SOURCE, stage),
    }
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(60))
    with open(os.path.join(stage, HELPER_NAME), "w",
              encoding="utf-8") as handle:
        handle.write(HELPER_SOURCE)
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, kind in CASES:
        if kind == "neg":
            commands.append("neg_case %s %s" % (tag, obj))
        elif kind == "control-side":
            # Sequential sides: the C control declares the same
            # map symbol, so the Mojo side unloads before the C
            # side loads (CASES order is execution order).
            commands.append("control_side %s %s" % (tag, obj))
        else:
            commands.append("%s_case" % kind)
    # Lease before staging, after builds: the build drills
    # run unleased and must reach their injected failures, while
    # an unleased run must still refuse here, never as an
    # admission failure.
    guest_proc.require_target_lease("guest_run")
    try:
        pins = tool_admission.stage_tool_pins(
            {"PATH": os.environ.get("PATH", "")}
        )
    except tool_admission.ToolMissingError as exc:
        raise EnvironmentFailure(str(exc))
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init_base=INIT_VALUE,
        init_step=0,
        count_init_base=COUNT_INIT,
        count_init_step=0,
        first_repeat=COUNT_FIRST_REPEAT,
        second_repeat=COUNT_SECOND_REPEAT,
        absent_key=MISS_ABSENT_KEY,
        miss_init_base=MISS_INSERT_VALUE,
        miss_init_step=0,
        del_base=DEL_INIT,
        del_step=0,
        del_reinsert_key=DEL_REINSERT_KEY,
        del_reinsert_base=DEL_REINSERT_VALUE,
        del_reinsert_step=0,
        iter0_key=ITER_TRIPLES[0][0],
        iter0_base=ITER_TRIPLES[0][1],
        iter0_step=ITER_TRIPLES[0][2],
        iter0_key_le=key_bytes(ITER_TRIPLES[0][0]),
        iter1_key=ITER_TRIPLES[1][0],
        iter1_base=ITER_TRIPLES[1][1],
        iter1_step=ITER_TRIPLES[1][2],
        iter1_key_le=key_bytes(ITER_TRIPLES[1][0]),
        iter2_key=ITER_TRIPLES[2][0],
        iter2_base=ITER_TRIPLES[2][1],
        iter2_step=ITER_TRIPLES[2][2],
        iter2_key_le=key_bytes(ITER_TRIPLES[2][0]),
        live_keys=" ".join(str(key) for key in LIVE_KEYS),
        absent_keys=" ".join(str(key) for key in ABSENT_KEYS),
        full_base=FULL_BASE_VALUE,
        full_last_key=FULL_TOTAL - 1,
        action=XDP_PASS,
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
        bpftool_argv0=json.dumps(pins["path"]),
        harness_flags=tool_admission.render_harness_flags(
            pins, pin_path="$pin", owned_root="/sys/fs/bpf",
            ownership_token="mojobpf-neg-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_percpu_hash.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + [
        HELPER_NAME, "data.bin", "guest_percpu_hash.sh",
    ]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + (HELPER_NAME, "data.bin", "guest_percpu_hash.sh"),
    )
    code, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm", "--cpus", "2",
         "--exec", "bash %s" % script_path],
        stage,
        VNG_TIMEOUT,
    )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+)(?: exit=(\d+))? ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        results[tag] = {
            "exit": int(exit_code) if exit_code is not None else None,
            "body": body,
        }
    verdict = guest_proc.classify_guest_exit(
        code, output,
        records=list(results.values()),
        progress_banner="=== begin guest_percpu_hash ===",
    )
    if verdict == "proof":
        raise AssertionError(
            "vng guest run failed with proof evidence (exit %d, "
            "stage %s):\n%s"
            % (code, stage, output[-4000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage %s):\n%s"
            % (code, stage, output[-4000:])
        )
    missing = [tag for tag, _, _ in CASES if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    if "residue" not in results:
        raise guest_proc.GuestMissing(
            "guest output lacks the residue block (stage %s):\n%s"
            % (stage, output[-4000:])
        )
    return {"stage": stage, "output": output, "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def parse_fields(body):
    fields = {}
    for line in body.splitlines():
        if "=" in line and not line.startswith(("key:", "---", "Return")):
            key, _, value = line.partition("=")
            key = key.strip()
            if key and " " not in key:
                fields[key] = value.strip()
    return fields


def section_text(body, marker):
    """Return the transcript after ``--- <marker>`` up to the next one."""
    section = body.split("--- %s" % marker, 1)[1]
    end = section.find("--- ")
    if end != -1:
        section = section[:end]
    end = section.find("=== END")
    if end != -1:
        section = section[:end]
    return section


def parse_run_action(body, marker="run ---"):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


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


def parse_dump(body, marker, tag):
    """Decode one bpftool JSON dump section with the oracle decoder."""
    section = body.split(marker, 1)[1]
    end = section.find("=== END %s ===" % tag)
    if end != -1:
        section = section[:end]
    end = section.find("--- ")
    if end != -1:
        section = section[:end]
    try:
        doc = json.loads(section)
    except ValueError:
        raise guest_proc.GuestMissing(
            "%s: bpftool dump is not JSON:\n%s" % (tag, section[-500:])
        )
    return decode_bpftool_percpu_dump(doc)


def guest_ncpu():
    output = executed()["output"]
    match = re.search(r"^nprocall=(\d+)$", output, re.M)
    assert match, "guest reported no nprocall line"
    return int(match.group(1))


def check_cpu_facts():
    output = executed()["output"]
    possible = re.search(r"^possible=(\S+)$", output, re.M)
    assert possible, "guest reported no possible-CPU list"
    ncpu = guest_ncpu()
    assert len(parse_possible_list(possible.group(1))) == ncpu, (
        "possible-list count disagrees with nproc --all (%d)" % ncpu
    )
    assert ncpu == WANT_NCPU, (
        "guest must report %d CPUs, observed %d" % (WANT_NCPU, ncpu)
    )
    return ncpu


def check_map_identity(tag):
    """Assert the libbpf-created map is the declared per-CPU-hash map.

    Lifecycle/count/delete/isolation legs run 1-entry maps (at
    most one live entry beside any program run); miss runs the
    2-entry map with at most one live entry; iteration and the
    full-map leg run the 4-entry shape.
    """
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    if tag in ("life", "count", "delete", "isol", "controlm", "controlc"):
        want_entries = "1"
    elif tag == "miss":
        want_entries = "2"
    else:
        want_entries = "4"
    assert fields.get("load_exit") == "0", "%s: load failed" % tag
    assert fields.get("mapinfo_exit") == "0", "%s: mapinfo failed" % tag
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "percpu_hash", (
        "%s: not a per-CPU-hash map" % tag
    )
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", "%s: value size is not u64" % tag
    assert fields.get("map_entries") == want_entries, (
        "%s: expected %s entries, observed %s"
        % (tag, want_entries, fields.get("map_entries"))
    )
    assert fields.get("map_pin_exit") == "0", (
        "%s: map pin failed" % tag
    )
    return fields


def test_cpu_facts_agree():
    check_cpu_facts()


def test_lifecycle_init_run_observe():
    ncpu = check_cpu_facts()
    fields = check_map_identity("life")
    for key in LIVE_KEYS:
        for stem in ("init%d", "before%d", "after%d"):
            name = (stem % key) + "_exit"
            assert fields.get(name) == "0", "life: %s=%r" % (
                name, fields.get(name))
    assert fields.get("dump_exit") == "0", "life: dump failed"
    for key in ABSENT_KEYS:
        for stem in ("absent%d", "stillabsent%d"):
            name = (stem % key) + "_exit"
            assert fields.get(name) != "0", (
                "life: key %d must miss, never hit" % key
            )
    assert fields.get("run_exit") == "0", "life: run failed"
    assert fields.get("unload_ok") == "1", "life: pin was not removed"
    body = executed()["results"]["life"]["body"]
    assert parse_run_action(body) == XDP_PASS, "test-run action must be PASS"
    for key in LIVE_KEYS:
        before = parse_raw_values(body, "--- life init%d ---" % key, ncpu)
        after = parse_raw_values(body, "--- life after%d ---" % key, ncpu)
        assert before == [INIT_VALUE] * ncpu, (
            "key %d: userspace init must read back %d on every "
            "slot first, got %r" % (key, INIT_VALUE, before)
        )
        assert after == [AFTER_VALUE] + [INIT_VALUE] * (ncpu - 1), (
            "key %d: CPU 0 must move to %d with every other slot "
            "at %d, got %r" % (key, AFTER_VALUE, INIT_VALUE, after)
        )
        assert sum(after) == INIT_VALUE * ncpu + 1, (
            "key %d: total must move by exactly one, got %r"
            % (key, after)
        )
    dump = parse_dump(body, "--- life dump ---", "life")
    assert dump == {0: [AFTER_VALUE, INIT_VALUE]}, (
        "life dump: %r" % (dump,)
    )
    for key in ABSENT_KEYS:
        assert "Not found" in section_text(
            body, "life absent%d ---" % key
        ), (
            "life: key %d must report a miss before the run" % key
        )
        assert "Not found" in section_text(
            body, "life stillabsent%d ---" % key
        ), (
            "life: key %d must still miss after the run" % key
        )


def test_exact_counts_after_quiescence():
    ncpu = check_cpu_facts()
    fields = check_map_identity("count")
    for key in LIVE_KEYS:
        assert fields.get("init%d_exit" % key) == "0", (
            "count: init%d failed" % key
        )
        assert fields.get("after1_%d_exit" % key) == "0", (
            "count: after1_%d failed" % key
        )
        assert fields.get("after2_%d_exit" % key) == "0", (
            "count: after2_%d failed" % key
        )
    assert fields.get("run1_exit") == "0", "count: run1 failed"
    assert fields.get("run2_exit") == "0", "count: run2 failed"
    assert fields.get("dump_exit") == "0", "count: dump failed"
    assert fields.get("unload_ok") == "1", "count: pin was not removed"
    body = executed()["results"]["count"]["body"]
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    for key in LIVE_KEYS:
        after1 = parse_raw_values(body, "--- count after1_%d ---" % key, ncpu)
        after2 = parse_raw_values(body, "--- count after2_%d ---" % key, ncpu)
        assert after1 == [COUNT_FIRST_VALUE] + [COUNT_INIT] * (ncpu - 1), (
            "key %d: after %d runs CPU 0 must read %d with every "
            "other slot at %d, got %r"
            % (key, COUNT_FIRST_REPEAT, COUNT_FIRST_VALUE,
               COUNT_INIT, after1)
        )
        assert after2 == [COUNT_SECOND_VALUE] + [COUNT_INIT] * (ncpu - 1), (
            "key %d: after %d more runs CPU 0 must read %d with "
            "every other slot at %d, got %r"
            % (key, COUNT_SECOND_REPEAT, COUNT_SECOND_VALUE,
               COUNT_INIT, after2)
        )
        assert sum(after2) == COUNT_INIT * ncpu + COUNT_FIRST_REPEAT + COUNT_SECOND_REPEAT, (
            "key %d: total must move by exactly the run count, got %r"
            % (key, after2)
        )
    dump = parse_dump(body, "--- count dump ---", "count")
    assert dump == {0: [COUNT_SECOND_VALUE, COUNT_INIT]}, (
        "count dump: %r" % (dump,)
    )


def test_miss_path_inserts_nothing():
    fields = check_map_identity("miss")
    keys = (0, 1, 2, 3, MISS_ABSENT_KEY)
    for key in keys:
        assert fields.get("fresh%d_exit" % key) != "0", (
            "miss: fresh lookup of key %d must fail" % key
        )
        assert fields.get("still%d_exit" % key) != "0", (
            "miss: key %d must still miss after the test-run" % key
        )
    assert fields.get("run1_exit") == "0", "miss: run1 failed"
    assert fields.get("unload_ok") == "1", "miss: pin was not removed"
    body = executed()["results"]["miss"]["body"]
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    for key in keys:
        assert "Not found" in section_text(body, "miss fresh%d ---" % key), (
            "miss: fresh key %d must report a miss, never a value" % key
        )
        assert "Not found" in section_text(body, "miss still%d ---" % key), (
            "miss: key %d must still report a miss after run1" % key
        )


def test_scoped_update_after_insert():
    ncpu = check_cpu_facts()
    fields = parse_fields(executed()["results"]["miss"]["body"])
    assert fields.get("insert_exit") == "0", "miss: insert failed"
    assert fields.get("run2_exit") == "0", "miss: run2 failed"
    assert fields.get("got0_exit") == "0", "miss: key 0 must hit now"
    assert fields.get("dump_exit") == "0", "miss: dump failed"
    for key in (1, 2, 3, MISS_ABSENT_KEY):
        assert fields.get("rest%d_exit" % key) != "0", (
            "miss: key %d must still miss after run2" % key
        )
    body = executed()["results"]["miss"]["body"]
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    got = parse_raw_values(body, "--- miss got0 ---", ncpu)
    assert got == [MISS_AFTER_VALUE] + [MISS_INSERT_VALUE] * (ncpu - 1), (
        "key 0: CPU 0 must move to %d with every other slot at "
        "%d, got %r" % (MISS_AFTER_VALUE, MISS_INSERT_VALUE, got)
    )
    dump = parse_dump(body, "--- miss dump ---", "miss")
    assert dump == {0: [MISS_AFTER_VALUE, MISS_INSERT_VALUE]}, (
        "miss dump: %r" % (dump,)
    )
    for key in (1, 2, 3, MISS_ABSENT_KEY):
        assert "Not found" in section_text(body, "miss rest%d ---" % key), (
            "miss: key %d must report a miss after run2" % key
        )


def test_kernel_delete_removes_entries():
    fields = check_map_identity("delete")
    for key in LIVE_KEYS:
        assert fields.get("init%d_exit" % key) == "0", (
            "delete: init%d failed" % key
        )
        assert fields.get("gone%d_exit" % key) != "0", (
            "delete: key %d must be gone after the test-run" % key
        )
    assert fields.get("run_exit") == "0", "delete: run failed"
    assert fields.get("unload_ok") == "1", "delete: pin was not removed"
    body = executed()["results"]["delete"]["body"]
    assert parse_run_action(body) == XDP_PASS, (
        "delete probe must observe success on every key"
    )
    for key in LIVE_KEYS:
        assert "Not found" in section_text(
            body, "delete gone%d ---" % key
        ), "delete: key %d must report a miss after the run" % key


def test_userspace_delete_lifecycle():
    ncpu = check_cpu_facts()
    fields = parse_fields(executed()["results"]["delete"]["body"])
    assert fields.get("reinsert_exit") == "0", "delete: reinsert failed"
    assert fields.get("rehit_exit") == "0", "delete: reinsert must hit"
    assert fields.get("udel_exit") == "0", "delete: userspace delete failed"
    assert fields.get("ugone_exit") != "0", (
        "delete: deleted key must miss afterwards"
    )
    assert fields.get("umiss_exit") != "0", (
        "delete: deleting an absent key must fail"
    )
    body = executed()["results"]["delete"]["body"]
    rehit = parse_raw_values(body, "--- delete rehit ---", ncpu)
    assert rehit == [DEL_REINSERT_VALUE] * ncpu, (
        "reinserted key: every slot must read %d, observed %r"
        % (DEL_REINSERT_VALUE, rehit)
    )
    assert "Not found" in section_text(body, "delete ugone ---"), (
        "delete: removed key must report a miss"
    )
    assert "No such file or directory" in section_text(
        body, "delete umiss ---"
    ), "delete: absent-key delete must report ENOENT"


def parse_next_key(body, marker):
    """Return the get-next-key successor as an int, or None on ENOENT."""
    section = section_text(body, marker)
    match = re.search(
        r"next key:\s*([0-9a-fA-F][0-9a-fA-F ]*)", section
    )
    if match is None:
        assert "No such file or directory" in section, (
            "get-next-key without a successor must report ENOENT:\n%s"
            % section
        )
        return None
    raw = bytes(int(byte, 16) for byte in match.group(1).split())
    assert len(raw) == 4, "successor key must be 4 bytes: %r" % section
    return int.from_bytes(raw, "little")


def assert_walk_chain(succ):
    """Fail unless ``succ`` is one complete acyclic chain.

    ``succ`` maps every probed key to its successor (None at the
    terminal ENOENT): exactly one terminus, distinct successors,
    no self-successor, and every chain terminating without
    revisiting a key.
    """
    misses = sum(1 for target in succ.values() if target is None)
    assert misses == 1, (
        "the walk must end exactly once, misses=%d" % misses
    )
    assert len(set(succ.values())) == 3, (
        "walk successors must be distinct: %r" % (succ,)
    )
    for start, target in sorted(succ.items()):
        assert target != start, "walk successor of %r is itself" % (start,)
    for start in succ:
        seen = set()
        node = start
        while node is not None:
            assert node not in seen, "walk cycles at %r: %r" % (node, succ)
            seen.add(node)
            node = succ[node]


def assert_residue_clean(body):
    """Fail unless both residue enumerations ran clean and empty.

    The enumeration exits must be 0, both sections must be valid
    JSON lists, and neither may mention an owned program or map.
    """
    if (
        "--- residue prog ---" not in body
        or "--- residue map ---" not in body
        or "residue_prog_exit=" not in body
    ):
        raise AssertionError(
            "residue body malformed, missing section markers:\n%s" % body
        )
    prog_text, rest = body.split("--- residue map ---", 1)
    prog_text = prog_text.split("--- residue prog ---", 1)[1]
    map_text = rest.split("residue_prog_exit=", 1)[0]
    exits = {}
    for line in body.splitlines():
        if line.startswith("residue_prog_exit="):
            exits["prog"] = line.split("=", 1)[1].strip()
        elif line.startswith("residue_map_exit="):
            exits["map"] = line.split("=", 1)[1].strip()
    assert exits.get("prog") == "0", (
        "residue prog enumeration failed: %r" % (exits,)
    )
    assert exits.get("map") == "0", (
        "residue map enumeration failed: %r" % (exits,)
    )
    try:
        prog_doc = json.loads(prog_text)
        map_doc = json.loads(map_text)
    except ValueError:
        raise guest_proc.GuestMissing(
            "residue enumeration is not valid JSON:\n%s" % body
        )
    assert isinstance(prog_doc, list), "residue prog is not a list"
    assert isinstance(map_doc, list), "residue map is not a list"
    assert "mojobpf" not in prog_text + map_text, (
        "no owned program or map may survive the run:\n%s" % body
    )


def test_residue_checks_refuse_blind_spots():
    # Host-only negatives (no guest boot): failed or invalid
    # enumerations must fail loudly, never pass as clean.
    assert_residue_clean(
        "--- residue prog ---\n[]\n"
        "--- residue map ---\n[]\n"
        "residue_prog_exit=0\nresidue_map_exit=0\n"
    )
    for bad, label in (
        ("--- residue prog ---\n[]\n"
         "--- residue map ---\n[]\n"
         "residue_prog_exit=1\nresidue_map_exit=0\n",
         "failed prog enumeration"),
        ("--- residue prog ---\n[]\n"
         "--- residue map ---\nnot json\n"
         "residue_prog_exit=0\nresidue_map_exit=0\n",
         "invalid map JSON"),
        ("--- residue prog ---\n[]\n"
         "--- residue map ---\n[]\n"
         "residue_map_exit=0\n",
         "missing prog exit"),
        ("--- residue prog ---\n"
         "[{\"name\": \"mojobpf_phash_x\"}]\n"
         "--- residue map ---\n[]\n"
         "residue_prog_exit=0\nresidue_map_exit=0\n",
         "surviving owned program"),
    ):
        try:
            assert_residue_clean(bad)
        except (AssertionError, guest_proc.HarnessEnvironment):
            pass
        else:
            raise AssertionError("%s must be refused" % label)


def test_walk_chain_refuses_broken_chains():
    # Host-only negatives for the chain mechanics (no guest boot):
    # both saved lane walks pass, and every broken shape fails.
    assert_walk_chain({7: 0xDEADBEEF, 42: 7, 0xDEADBEEF: None})
    assert_walk_chain({7: 42, 42: None, 0xDEADBEEF: 7})
    for bad, label in (
        ({7: None, 42: None, 0xDEADBEEF: None}, "three terminals"),
        ({7: 42, 42: 7, 0xDEADBEEF: 7}, "duplicate successor"),
        ({7: 7, 42: 0xDEADBEEF, 0xDEADBEEF: None}, "self successor"),
        ({7: 42, 42: 7, 0xDEADBEEF: None}, "two-cycle"),
    ):
        try:
            assert_walk_chain(bad)
        except AssertionError:
            pass
        else:
            raise AssertionError("%s must be refused" % label)


def test_iteration_set_and_bytes():
    ncpu = check_cpu_facts()
    fields = check_map_identity("iter")
    for name in ("ins0_exit", "ins1_exit", "ins2_exit", "dump1_exit",
                 "dump2_exit", "shrink_exit"):
        assert fields.get(name) == "0", "iter: %s=%r" % (
            name, fields.get(name))
    assert fields.get("unload_ok") == "1", "iter: pin was not removed"
    body = executed()["results"]["iter"]["body"]
    want = {
        key: [base + cpu * step for cpu in range(ncpu)]
        for key, base, step in ITER_TRIPLES
    }
    dump1 = parse_dump(body, "--- iter dump1 ---", "iter")
    assert dump1 == want, (
        "dump1: expected %r, observed %r" % (want, dump1)
    )
    # The full-width pair pins little-endian key bytes and exact
    # per-slot value bytes.
    doc = json.loads(section_text(body, "iter dump1 ---").strip())
    wide = [
        entry for entry in doc
        if entry["key"] == ["0xef", "0xbe", "0xad", "0xde"]
    ]
    assert len(wide) == 1, "dump1 must carry the 0xDEADBEEF key once"
    slots = sorted(
        (slot["cpu"], slot["value"]) for slot in wide[0]["values"]
    )
    assert [cpu for cpu, _ in slots] == [0, 1], (
        "dump1 must carry both CPU slots for the wide key"
    )
    assert slots[0][1] == [
        "0x88", "0x77", "0x66", "0x55",
        "0x44", "0x33", "0x22", "0x11",
    ], "dump1 must carry the exact wide slot-0 bytes"
    assert slots[1][1] == [
        "0x88", "0x78", "0x66", "0x55",
        "0x44", "0x33", "0x22", "0x11",
    ], "dump1 must carry the exact wide slot-1 bytes"
    # Hash order is unspecified, so the walk asserts chain
    # mechanics, not order: getnext from every inserted key must
    # form one complete acyclic chain -- distinct successors, no
    # self-successor, exactly one terminal ENOENT -- with exits
    # coherent with the outcomes (0 on a successor, nonzero on
    # ENOENT). The exact set itself is pinned by the JSON dumps
    # above and below.
    succ = {}
    for probe, key in (("gx0", ITER_TRIPLES[0][0]),
                       ("gx1", ITER_TRIPLES[1][0]),
                       ("gx2", ITER_TRIPLES[2][0])):
        successor = parse_next_key(body, "iter %s ---" % probe)
        exit_code = fields.get("%s_exit" % probe)
        if successor is None:
            assert exit_code != "0", (
                "iter %s: the terminal ENOENT must exit nonzero, got %r"
                % (probe, exit_code)
            )
            succ[key] = None
        else:
            assert exit_code == "0", (
                "iter %s: a successor walk must exit 0, got %r"
                % (probe, exit_code)
            )
            assert successor in want, (
                "walk successor %r is outside the inserted set" % successor
            )
            succ[key] = successor
    assert_walk_chain(succ)
    dump2 = parse_dump(body, "--- iter dump2 ---", "iter")
    shrunk = {
        key: value for key, value in want.items()
        if key != ITER_TRIPLES[1][0]
    }
    assert dump2 == shrunk, (
        "dump2: expected %r, observed %r" % (shrunk, dump2)
    )


def test_sizes_refused():
    fields = parse_fields(executed()["results"]["iter"]["body"])
    assert fields.get("shortkey_exit") != "0", (
        "update with a short key must fail"
    )
    assert fields.get("shortval_exit") != "0", (
        "update with a short value must fail"
    )
    body = executed()["results"]["iter"]["body"]
    # bpftool validates the value against the per-CPU slot size
    # (8), not the whole per-CPU buffer.
    assert "value expected 8 bytes got 4" in section_text(
        body, "iter shortval ---"
    ), "short value update must name the size mismatch"


def test_full_map_refuses_fifth_insert():
    ncpu = check_cpu_facts()
    fields = check_map_identity("full")
    last = FULL_TOTAL - 1
    for key in range(last):
        assert fields.get("ins%d_exit" % key) == "0", (
            "full: ins%d failed" % key
        )
    assert fields.get("insfull_exit") != "0", (
        "full: the fifth insert into the 4-entry map must fail"
    )
    assert fields.get("dump_exit") == "0", "full: dump failed"
    assert fields.get("unload_ok") == "1", "full: pin was not removed"
    body = executed()["results"]["full"]["body"]
    section = section_text(body, "full insfull ---")
    assert "Errno 7" in section, (
        "full: the fifth insert must fail E2BIG:\n%s" % section[-500:]
    )
    assert "update_ok" not in section, (
        "full: the fifth insert must not report success"
    )
    dump = parse_dump(body, "--- full dump ---", "full")
    want = {
        key: [FULL_BASE_VALUE + key] * ncpu for key in range(last)
    }
    assert dump == want, (
        "full dump: expected %r, observed %r" % (want, dump)
    )


def test_isolation_moves_only_running_cpu():
    ncpu = check_cpu_facts()
    fields = check_map_identity("isol")
    for key in LIVE_KEYS:
        assert fields.get("init%d_exit" % key) == "0", (
            "isol: init%d failed" % key
        )
        assert fields.get("iso0_%d_exit" % key) == "0", (
            "isol: iso0_%d failed" % key
        )
        assert fields.get("iso1_%d_exit" % key) == "0", (
            "isol: iso1_%d failed" % key
        )
    assert fields.get("run0_exit") == "0", "isol: run0 failed"
    assert fields.get("run1_exit") == "0", "isol: run1 failed"
    assert fields.get("dump_exit") == "0", "isol: dump failed"
    assert fields.get("unload_ok") == "1", "isol: pin was not removed"
    body = executed()["results"]["isol"]["body"]
    assert parse_run_action(body, "run0 ---") == XDP_PASS
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    for key in LIVE_KEYS:
        iso0 = parse_raw_values(body, "--- isol iso0_%d ---" % key, ncpu)
        iso1 = parse_raw_values(body, "--- isol iso1_%d ---" % key, ncpu)
        assert iso0 == [AFTER_VALUE] + [INIT_VALUE] * (ncpu - 1), (
            "key %d: the CPU-0 run must move only slot 0 to %d, "
            "got %r" % (key, AFTER_VALUE, iso0)
        )
        assert iso1 == [AFTER_VALUE] * ncpu, (
            "key %d: the CPU-1 run must move only slot 1 to %d, "
            "got %r" % (key, AFTER_VALUE, iso1)
        )
        assert sum(iso1) == INIT_VALUE * ncpu + 2, (
            "key %d: total must move by exactly two, got %r"
            % (key, iso1)
        )
    dump = parse_dump(body, "--- isol dump ---", "isol")
    assert dump == {0: [AFTER_VALUE] * ncpu}, (
        "isol dump: %r" % (dump,)
    )


def test_control_matches_mojo_bytes():
    ncpu = check_cpu_facts()
    for tag in ("controlm", "controlc"):
        fields = check_map_identity(tag)
        for name in ("init_exit", "run_exit", "after_exit", "dump_exit"):
            assert fields.get(name) == "0", "%s: %s=%r" % (
                tag, name, fields.get(name))
        assert fields.get("unload_ok") == "1", (
            "%s: pin was not removed" % tag
        )
    bodies = {
        tag: executed()["results"][tag]["body"]
        for tag in ("controlm", "controlc")
    }
    for tag, body in bodies.items():
        assert parse_run_action(body) == XDP_PASS, (
            "%s: test-run action must be PASS" % tag
        )
    reads = {
        tag: parse_raw_values(body, "--- %s after ---" % tag, ncpu)
        for tag, body in bodies.items()
    }
    assert reads["controlm"] == reads["controlc"], (
        "C control must observe the same per-CPU bytes as Mojo: "
        "mojo %r vs C %r" % (reads["controlm"], reads["controlc"])
    )
    assert reads["controlm"] == [AFTER_VALUE] + [INIT_VALUE] * (ncpu - 1), (
        "both sides must move CPU 0 to %d, got %r"
        % (AFTER_VALUE, reads["controlm"])
    )
    dumps = {
        tag: parse_dump(body, "--- %s dump ---" % tag, tag)
        for tag, body in bodies.items()
    }
    assert dumps["controlm"] == dumps["controlc"], (
        "C control dump must equal the Mojo dump: %r vs %r"
        % (dumps["controlm"], dumps["controlc"])
    )


def check_verifier_rejection(tag, log_line):
    run = executed()
    record = run["results"][tag]
    try:
        doc = json.loads(record["body"])
    except ValueError:
        raise guest_proc.GuestMissing(
            "%s: harness did not emit JSON:\n%s" % (tag, record["body"][-500:])
        )
    hint = guest_proc.check_harness_exit(
        tag, exit=record["exit"],
        classification=doc.get("classification"),
        stage=doc.get("stage"),
        contract_version=doc.get("contract_version"),
        note=doc.get("note"), expect=4)
    assert doc.get("stage") == "load", "%s: expected load stage" % tag
    assert doc.get("classification") == "verifier", (
        "%s: expected verifier classification, got %r"
        % (tag, doc.get("classification"))
    )
    blob = json.dumps(doc.get("commands", []))
    assert log_line in blob, (
        "%s: kernel verifier log must contain %r" % (tag, log_line)
    )
    return guest_proc.combine_outcomes(hint)


def test_oob_rejected_by_verifier():
    """Wrong value size: first rejecting layer is the kernel verifier."""
    return check_verifier_rejection("oob", OOB_LOG_LINE)


def test_unchecked_rejected_by_verifier():
    """Unchecked dereference: first rejecting layer is the kernel verifier."""
    return check_verifier_rejection("unchecked", UNCHECKED_LOG_LINE)


def test_license_gate_agrees():
    """Inspection + preflight agree with the kernel on per-CPU-hash objects."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
    from mojobpf import inspect as inspect_module  # noqa: E402

    stage = executed()["stage"]
    for name in ("percpuhash_rmw1.bpf.o", "percpuhash_rmw2.bpf.o", "percpuhash_rmw4.bpf.o",
                 "percpuhash_del.bpf.o"):
        report = guest_proc.inspect_consumed(
            os.path.join(stage, name),
            PERCPUHASH_PROFILE,
        )
        assert report.ok is True, (name, report.to_dict())
    assert inspect_module.preflight_helper_licenses(
        [1, 2, 3], APACHE, PERCPUHASH_PROFILE
    ) is None
    try:
        inspect_module.preflight_helper_licenses(
            [35], APACHE, PERCPUHASH_PROFILE
        )
    except Exception as exc:  # noqa: BLE001 - assert the carried code
        assert exc.diagnostic.code == "MBPF709", exc.diagnostic
        assert exc.diagnostic.stage == "inspect.license", exc.diagnostic
    else:
        raise AssertionError(
            "the preflight must still refuse the GPL-only witness"
        )


def test_guest_provenance():
    run = executed()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "pin absent (unloaded)" in run["output"], "pins must be removed"
    assert "PIN STILL PRESENT" not in run["output"], "pins must be removed"
    for tag in ("oob", "unchecked"):
        record = run["results"][tag]
        body = record["body"]
        try:
            doc = json.loads(body)
        except ValueError:
            raise guest_proc.GuestMissing(
                "%s: harness did not emit JSON:\n%s" % (tag, body[-500:])
            )
        guest_proc.check_harness_exit(
            tag, exit=record["exit"],
            classification=doc.get("classification"),
            stage=doc.get("stage"),
            contract_version=doc.get("contract_version"),
            note=doc.get("note"), expect=4)
        assert doc.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
        assert doc.get("cleanup_ok") is None, (
            "%s: harness must leave cleanup_ok unset" % tag
        )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in (
        "bpf_test_run.py",
        HELPER_NAME,
        "percpuhash_rmw2.bpf.o",
        "percpuhash_rmw4.bpf.o",
        "percpuhash_del.bpf.o",
        "percpuhash_oob.bpf.o",
        "percpuhash_unchecked.bpf.o",
        "percpuhash_cref.bpf.o",
        "data.bin",
        "guest_percpu_hash.sh",
    ):
        if rec is None:
            # No attestation context (standalone/pytest run):
            # fall back to the legacy post-hoc comparison.
            expected = sha256_file(
                os.path.join(run["stage"], name)
            )
            assert expected in run["output"], (
                "guest must re-verify staged hash of %s" % name
            )
            continue
        expected = rec.consumed_staged_digest(name, run["stage"])
        assert expected is not None, (
            "staged bytes missing for %s" % name
        )
        assert reported.get(name) == expected, (
            "guest must report the consumed bytes of %s" % name
        )
    assert_residue_clean(run["results"]["residue"]["body"])


# The verifier negatives are denials: each expects the wire-derived
# FAIL at VERIFY (the bad object observably rejected at load) and
# passes only its own cell when the denial is observed with
# evidence. They guard the lifecycle: the per-CPU-hash object must load
# and run (positive) while the bad objects must observably not
# load (denials), proving the load observation is not vacuous.
CASE_DENIALS = {
    "test_oob_rejected_by_verifier": (
        "test_lifecycle_init_run_observe", "VERIFY"
    ),
    "test_unchecked_rejected_by_verifier": (
        "test_lifecycle_init_run_observe", "VERIFY"
    ),
}


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Host-only unit tests pin in-file helpers through the suite
# source; every other case pins the sources it depends on. A
# class with any missing file digests to zeros and can never
# back a PASS.
CASE_INPUTS = {
    "test_key_value_byte_helpers": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_cpu_facts_agree": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_parse_possible_list_forms": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_percpu_stride_padding": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_decode_values_exact": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_decode_bpftool_dump_shape": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_lifecycle_init_run_observe": {
        "sources": [RMW1_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw1.bpf.o")],
        "corpus": [],
    },
    "test_exact_counts_after_quiescence": {
        "sources": [RMW1_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw1.bpf.o")],
        "corpus": [],
    },
    "test_miss_path_inserts_nothing": {
        "sources": [RMW2_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw2.bpf.o")],
        "corpus": [],
    },
    "test_scoped_update_after_insert": {
        "sources": [RMW2_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw2.bpf.o")],
        "corpus": [],
    },
    "test_kernel_delete_removes_entries": {
        "sources": [DELETE_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_del.bpf.o")],
        "corpus": [],
    },
    "test_userspace_delete_lifecycle": {
        "sources": [DELETE_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_del.bpf.o")],
        "corpus": [],
    },
    "test_residue_checks_refuse_blind_spots": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_walk_chain_refuses_broken_chains": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_iteration_set_and_bytes": {
        "sources": [RMW4_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw4.bpf.o")],
        "corpus": [],
    },
    "test_sizes_refused": {
        "sources": [RMW4_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw4.bpf.o")],
        "corpus": [],
    },
    "test_full_map_refuses_fifth_insert": {
        "sources": [RMW4_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw4.bpf.o")],
        "corpus": [],
    },
    "test_isolation_moves_only_running_cpu": {
        "sources": [RMW1_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw1.bpf.o")],
        "corpus": [],
    },
    "test_control_matches_mojo_bytes": {
        "sources": [RMW1_SOURCE, CREF_SOURCE, ("stage", HELPER_NAME)],
        "objects": [("stage", "percpuhash_rmw1.bpf.o"),
                    ("stage", "percpuhash_cref.bpf.o")],
        "corpus": [],
    },
    "test_oob_rejected_by_verifier": {
        "sources": [OOB_SOURCE],
        "objects": [("stage", "percpuhash_oob.bpf.o")],
        "corpus": [],
    },
    "test_unchecked_rejected_by_verifier": {
        "sources": [UNCHECKED_SOURCE],
        "objects": [("stage", "percpuhash_unchecked.bpf.o")],
        "corpus": [],
    },
    "test_license_gate_agrees": {
        "sources": [RMW1_SOURCE, RMW2_SOURCE, RMW4_SOURCE,
                    DELETE_SOURCE],
        "objects": [("stage", "percpuhash_rmw1.bpf.o"),
                    ("stage", "percpuhash_rmw2.bpf.o"),
                    ("stage", "percpuhash_rmw4.bpf.o"),
                    ("stage", "percpuhash_del.bpf.o")],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [RMW1_SOURCE, RMW2_SOURCE, RMW4_SOURCE,
                    DELETE_SOURCE, OOB_SOURCE,
                    UNCHECKED_SOURCE, HARNESS,
                    ("stage", HELPER_NAME),
                    ("stage", "guest_percpu_hash.sh")],
        "objects": [("stage", "percpuhash_rmw1.bpf.o"),
                    ("stage", "percpuhash_rmw2.bpf.o"),
                    ("stage", "percpuhash_rmw4.bpf.o"),
                    ("stage", "percpuhash_del.bpf.o"),
                    ("stage", "percpuhash_oob.bpf.o"),
                    ("stage", "percpuhash_unchecked.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
}


def _finish(rec, unavailable_seen=False):
    """Attach the guest transcript and finish the typed suite."""
    stage = None
    try:
        run = executed()
        stage = run["stage"]
        rec.note_transcript("guest", run["output"])
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        tool_admission.ToolAdmissionError, AssertionError,
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
    rec = guest_proc.SuiteRecorder(
        suite_id="kernel-percpu-hash", suite_path=__file__,
        case_ids=names, denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
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
        tool_admission.ToolAdmissionError, AssertionError,
        subprocess.TimeoutExpired, guest_proc.TargetLeaseRequired,
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
        except tool_admission.ToolAdmissionError as exc:
            print("ADMISSION FAILURE in %s: %s" % (name, exc))
            rec.end_case_fail(name, "INFRA")
            failures += 1
        except subprocess.TimeoutExpired as exc:
            print("ENVIRONMENT FAILURE in %s: timed out: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "TOOLCHAIN_UNAVAILABLE")
            return _finish(rec, unavailable_seen)
        except guest_proc.TargetLeaseRequired as exc:
            print("REQUIRED-UNAVAILABLE %s: %s" % (name, exc))
            rec.end_case_not_run(name, "TARGET_RESOURCE_ABSENT")
            unavailable_seen = True
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            rec.end_case_fail(name)
            failures += 1
        else:
            print("PASS %s" % name)
            rec.end_case_hint(name, hint)
    if failures or unavailable_seen:
        return _finish(rec, unavailable_seen)
    print("percpuhash maps: lifecycle, count, miss, delete, iteration, "
          "full, isolation, control, negative, license and provenance "
          "checks passed")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
