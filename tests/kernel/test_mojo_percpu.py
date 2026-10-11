# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the Mojo-authored per-CPU programs.

Builds the per-CPU read-modify-write shapes (1 to 4 pairs), the
per-CPU delete probes (1 to 4 deletions), and the per-CPU combined
workload through the genuine pipeline (``mojo build --emit llvm``
with the packaged SDK on the import path ->
``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel -mcpu=v3``),
then boots one disposable Linux guest and proves Mojo-driven
per-CPU events with exact totals:

* read-modify-write lifecycle per entry: every entry starts at 41
  on every CPU, one test-run moves exactly one CPU to 42, and the
  per-entry total is exact;
* exact per-entry totals after repeated runs (no lost or doubled
  updates on any CPU of any entry);
* delete probes observe -EINVAL on every key (the XDP_PASS
  action) and every per-CPU slot still reads back zero;
* the combined workload counts invocations and frame bytes on
  both paths (drop and pass) with exact per-entry totals.

Per-CPU values are read back through raw ``bpf()`` syscalls (the
exact per-CPU buffer, decoded only by this file's decoder) and
cross-checked against ``bpftool -j map dump`` (the independent
oracle). Totals are migration-proof: each run touches exactly one
CPU, so the total moves by exactly the run count whatever CPU
runs it. Staged file hashes are re-verified inside the guest so
every observation is tied to the exact bytes built here.

The decoder unit tests at the top of this file run without any
guest; the guest-backed tests share one boot. Standard library
only.

Requires a working Mojo compiler, LLVM ``llc``, ``bpftool``, and
``vng`` (virtme-ng) with a cached guest image on PATH
(default release v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane).
Missing tools fail loudly as environment failures, never as
passes.

Runnable directly (``python3 tests/kernel/test_mojo_percpu.py``)
or under any ``test_``-style runner. The guest boot plus the case
runs take several minutes under software emulation; all cases
share a single boot.
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
COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

XDP_PASS = 2
XDP_DROP = 1
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 1500

MAP_NAME = "mojobpf_map0"
INIT_VALUE = 41
HIT_VALUE = 42
COUNT_INIT = 7
COUNT_FIRST_REPEAT = 5
COUNT_SECOND_REPEAT = 9
FRAME_LEN = 60

RMW_SOURCES = {
    count: os.path.join(COMPILE_DIR, "percpu_rmw%d.mojo" % count)
    for count in (1, 2, 3, 4)
}
DELETE_SOURCES = {
    count: os.path.join(COMPILE_DIR, "percpu_delete%d.mojo" % count)
    for count in (1, 2, 3, 4)
}
COMBINED_SOURCE = os.path.join(COMPILE_DIR, "percpu_combined.mojo")


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


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


# ---------------------------------------------------------------------------
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


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm", "-I", SDK_INCLUDE,
            "-o", raw_path, source,
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


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_mojopcpu ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "possible=$(cat /sys/devices/system/cpu/possible)"
echo "online=$(cat /sys/devices/system/cpu/online)"
echo "nproc=$(nproc)"
echo "nprocall=$(nproc --all)"
echo "=== staged hashes ==="
sha256sum {staged_names} guest_mojopcpu.sh
map_info() {{
  out="$1"
  python3 - "$out" >/tmp/pcpu-mapinfo.stderr 2>&1 <<'PYEOF'
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
load_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_pcpu_$tag"
  mappin="/sys/fs/bpf/mojobpf_pc_$tag"
  out="/tmp/pcpu-$tag.fields"
  rm -f "$pin" "$mappin"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/pcpu-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  if [ "$(grep '^load_exit=' "$out" | cut -d= -f2)" != "0" ]; then
    echo "--- $tag load ---" >> "$out"
    cat /tmp/pcpu-$tag.load >> "$out"
  fi
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  if [ -n "$map_id" ]; then
    bpftool map pin id "$map_id" "$mappin" >/tmp/pcpu-$tag.pin 2>&1
    echo "map_pin_exit=$?" >> "$out"
  else
    echo "map_pin_exit=skip" >> "$out"
  fi
}}
unload_case() {{
  tag="$1"
  pin="/sys/fs/bpf/mojobpf_pcpu_$tag"
  mappin="/sys/fs/bpf/mojobpf_pc_$tag"
  out="/tmp/pcpu-$tag.fields"
  rm -f "$pin" "$mappin"
  if [ -e "$pin" ] || [ -e "$mappin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
}}
pcpu_life() {{
  tag="$1"; obj="$2"; entries="$3"
  ncpu=$(nproc --all)
  load_case "$tag" "$obj"
  out="/tmp/pcpu-$tag.fields"
  mappin="/sys/fs/bpf/mojobpf_pc_$tag"
  for key in $(seq 0 $((entries - 1))); do
    python3 pcpu_probe.py init "$mappin" "$key" 8 "$ncpu" {init_value} 0 > /tmp/pcpu-$tag.init$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "/sys/fs/bpf/mojobpf_pcpu_$tag" data_in data.bin repeat 1 > /tmp/pcpu-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  for key in $(seq 0 $((entries - 1))); do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/pcpu-$tag.key$key 2>&1
    echo "key${{key}}_exit=$?" >> "$out"
  done
  bpftool -j map dump pinned "$mappin" > /tmp/pcpu-$tag.dump 2>&1
  echo "dump_exit=$?" >> "$out"
  unload_case "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  for key in $(seq 0 $((entries - 1))); do
    echo "--- $tag init$key ---"
    cat /tmp/pcpu-$tag.init$key
  done
  echo "--- $tag run ---"
  cat /tmp/pcpu-$tag.run
  for key in $(seq 0 $((entries - 1))); do
    echo "--- $tag key$key ---"
    cat /tmp/pcpu-$tag.key$key
  done
  echo "--- $tag dump ---"
  cat /tmp/pcpu-$tag.dump
  echo "=== END $tag ==="
}}
pcpu_count() {{
  tag="$1"; obj="$2"; entries="$3"
  ncpu=$(nproc --all)
  load_case "$tag" "$obj"
  out="/tmp/pcpu-$tag.fields"
  mappin="/sys/fs/bpf/mojobpf_pc_$tag"
  for key in $(seq 0 $((entries - 1))); do
    python3 pcpu_probe.py init "$mappin" "$key" 8 "$ncpu" {count_init} 0 > /tmp/pcpu-$tag.init$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "/sys/fs/bpf/mojobpf_pcpu_$tag" data_in data.bin repeat {first_repeat} > /tmp/pcpu-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  for key in $(seq 0 $((entries - 1))); do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/pcpu-$tag.after1key$key 2>&1
    echo "after1key${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "/sys/fs/bpf/mojobpf_pcpu_$tag" data_in data.bin repeat {second_repeat} > /tmp/pcpu-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  for key in $(seq 0 $((entries - 1))); do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/pcpu-$tag.after2key$key 2>&1
    echo "after2key${{key}}_exit=$?" >> "$out"
  done
  bpftool -j map dump pinned "$mappin" > /tmp/pcpu-$tag.dump 2>&1
  echo "dump_exit=$?" >> "$out"
  unload_case "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  for key in $(seq 0 $((entries - 1))); do
    echo "--- $tag init$key ---"
    cat /tmp/pcpu-$tag.init$key
  done
  echo "--- $tag run1 ---"
  cat /tmp/pcpu-$tag.run1
  for key in $(seq 0 $((entries - 1))); do
    echo "--- $tag after1key$key ---"
    cat /tmp/pcpu-$tag.after1key$key
  done
  echo "--- $tag run2 ---"
  cat /tmp/pcpu-$tag.run2
  for key in $(seq 0 $((entries - 1))); do
    echo "--- $tag after2key$key ---"
    cat /tmp/pcpu-$tag.after2key$key
  done
  echo "--- $tag dump ---"
  cat /tmp/pcpu-$tag.dump
  echo "=== END $tag ==="
}}
pcpu_del() {{
  tag="$1"; obj="$2"; entries="$3"
  ncpu=$(nproc --all)
  load_case "$tag" "$obj"
  out="/tmp/pcpu-$tag.fields"
  mappin="/sys/fs/bpf/mojobpf_pc_$tag"
  bpftool prog run pinned "/sys/fs/bpf/mojobpf_pcpu_$tag" data_in data.bin repeat 1 > /tmp/pcpu-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  for key in $(seq 0 $((entries - 1))); do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/pcpu-$tag.key$key 2>&1
    echo "key${{key}}_exit=$?" >> "$out"
  done
  bpftool -j map dump pinned "$mappin" > /tmp/pcpu-$tag.dump 2>&1
  echo "dump_exit=$?" >> "$out"
  unload_case "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/pcpu-$tag.run
  for key in $(seq 0 $((entries - 1))); do
    echo "--- $tag key$key ---"
    cat /tmp/pcpu-$tag.key$key
  done
  echo "--- $tag dump ---"
  cat /tmp/pcpu-$tag.dump
  echo "=== END $tag ==="
}}
pcpu_comb() {{
  tag="comb"; obj="pcpu_comb.bpf.o"
  ncpu=$(nproc --all)
  load_case "$tag" "$obj"
  out="/tmp/pcpu-$tag.fields"
  mappin="/sys/fs/bpf/mojobpf_pc_$tag"
  bpftool prog run pinned "/sys/fs/bpf/mojobpf_pcpu_$tag" data_in drop.bin repeat 1 > /tmp/pcpu-$tag.rundrop 2>&1
  echo "rundrop_exit=$?" >> "$out"
  bpftool prog run pinned "/sys/fs/bpf/mojobpf_pcpu_$tag" data_in pass.bin repeat 1 > /tmp/pcpu-$tag.runpass 2>&1
  echo "runpass_exit=$?" >> "$out"
  for key in 0 1; do
    python3 pcpu_probe.py read "$mappin" "$key" 8 "$ncpu" > /tmp/pcpu-$tag.key$key 2>&1
    echo "key${{key}}_exit=$?" >> "$out"
  done
  bpftool -j map dump pinned "$mappin" > /tmp/pcpu-$tag.dump 2>&1
  echo "dump_exit=$?" >> "$out"
  unload_case "$tag"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag rundrop ---"
  cat /tmp/pcpu-$tag.rundrop
  echo "--- $tag runpass ---"
  cat /tmp/pcpu-$tag.runpass
  for key in 0 1; do
    echo "--- $tag key$key ---"
    cat /tmp/pcpu-$tag.key$key
  done
  echo "--- $tag dump ---"
  cat /tmp/pcpu-$tag.dump
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_pcpu_* /sys/fs/bpf/mojobpf_pc_*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_mojopcpu ==="
"""

CASES = (
    ("life1", "pcpu_rmw1.bpf.o", "pcpu_life", 1),
    ("life2", "pcpu_rmw2.bpf.o", "pcpu_life", 2),
    ("life3", "pcpu_rmw3.bpf.o", "pcpu_life", 3),
    ("life4", "pcpu_rmw4.bpf.o", "pcpu_life", 4),
    ("count1", "pcpu_rmw1.bpf.o", "pcpu_count", 1),
    ("count2", "pcpu_rmw2.bpf.o", "pcpu_count", 2),
    ("count3", "pcpu_rmw3.bpf.o", "pcpu_count", 3),
    ("count4", "pcpu_rmw4.bpf.o", "pcpu_count", 4),
    ("deli1", "pcpu_del1.bpf.o", "pcpu_del", 1),
    ("deli2", "pcpu_del2.bpf.o", "pcpu_del", 2),
    ("deli3", "pcpu_del3.bpf.o", "pcpu_del", 3),
    ("deli4", "pcpu_del4.bpf.o", "pcpu_del", 4),
    ("comb", "pcpu_comb.bpf.o", "pcpu_comb", 2),
)


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
            "vng guest run timed out after %ds (stage %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


def guest_run():
    """Build all objects, boot one guest, return parsed case results."""
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    sources = (
        list(RMW_SOURCES.values())
        + list(DELETE_SOURCES.values())
        + [COMBINED_SOURCE, ADAPTER]
    )
    for path in sources:
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-mojopcpu-", dir="/tmp")
    staged = {}
    for entries, source in RMW_SOURCES.items():
        staged["pcpu_rmw%d.bpf.o" % entries] = build_object(
            source, stage, "rmw%d" % entries
        )
    for entries, source in DELETE_SOURCES.items():
        staged["pcpu_del%d.bpf.o" % entries] = build_object(
            source, stage, "del%d" % entries
        )
    staged["pcpu_comb.bpf.o"] = build_object(
        COMBINED_SOURCE, stage, "comb"
    )
    with open(os.path.join(stage, HELPER_NAME), "w",
              encoding="utf-8") as handle:
        handle.write(HELPER_SOURCE)
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(FRAME_LEN))
    drop = bytearray(bytes(FRAME_LEN))
    drop[14] = 0x01
    with open(os.path.join(stage, "drop.bin"), "wb") as handle:
        handle.write(bytes(drop))
    passed = bytearray(bytes(FRAME_LEN))
    passed[14] = 0x00
    with open(os.path.join(stage, "pass.bin"), "wb") as handle:
        handle.write(bytes(passed))
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, kind, entries in CASES:
        if kind == "pcpu_comb":
            commands.append(kind)
        else:
            commands.append("%s %s %s %d" % (kind, tag, obj, entries))
    script = GUEST_SCRIPT.format(
        stage=stage,
        staged_names=" ".join(
            sorted(list(staged) + [
                HELPER_NAME, "data.bin", "drop.bin", "pass.bin",
            ])
        ),
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init_value=INIT_VALUE,
        count_init=COUNT_INIT,
        first_repeat=COUNT_FIRST_REPEAT,
        second_repeat=COUNT_SECOND_REPEAT,
    )
    script_path = os.path.join(stage, "guest_mojopcpu.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in (
        list(staged)
        + [HELPER_NAME, "data.bin", "drop.bin", "pass.bin",
           "guest_mojopcpu.sh"]
    ):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # Consumption seal: hash the staged bytes the guest is about
    # to execute, before any execution reads them.
    guest_proc.consume_declared_inputs(stage, extra=tuple(staged) + ("data.bin", "drop.bin", "pass.bin"))
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm",
        "--exec", "bash %s" % script_path],
        stage, VNG_TIMEOUT,
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
        returncode, output,
        records=list(results.values()),
        progress_banner="=== begin guest_mojopcpu ===",
    )
    if verdict == "proof":
        raise AssertionError(
            "vng guest run failed with proof evidence (exit %d, "
            "stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    missing = [tag for tag, _, _, _ in CASES if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
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


def parse_run_action(body, marker):
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


def parse_dump(body, marker="--- comb dump ---", tag="comb"):
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


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_map_identity(tag, entries):
    """Assert the libbpf-created map is the declared N-entry per-CPU map."""
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    assert fields.get("load_exit") == "0", "%s: load failed" % tag
    assert fields.get("mapinfo_exit") == "0", "%s: mapinfo failed" % tag
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "percpu_array", (
        "%s: not a per-CPU array map" % tag
    )
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", (
        "%s: value size is not u64" % tag
    )
    assert fields.get("map_entries") == str(entries), (
        "%s: not %d entries" % (tag, entries)
    )
    assert fields.get("map_pin_exit") == "0", (
        "%s: map pin failed" % tag
    )
    return fields


def check_cpu_facts():
    output = executed()["output"]
    possible = re.search(r"^possible=(\S+)$", output, re.M)
    assert possible, "guest reported no possible-CPU list"
    ncpu = guest_ncpu()
    assert len(parse_possible_list(possible.group(1))) == ncpu, (
        "possible-list count disagrees with nproc --all (%d)" % ncpu
    )
    assert ncpu >= 1
    return ncpu


def test_cpu_facts_agree():
    check_cpu_facts()


def check_rmw_lifecycle(entries):
    tag = "life%d" % entries
    ncpu = check_cpu_facts()
    fields = check_map_identity(tag, entries)
    for key in range(entries):
        assert fields.get("init%d_exit" % key) == "0", (
            "%s: init%d failed" % (tag, key)
        )
        assert fields.get("key%d_exit" % key) == "0", (
            "%s: key%d read failed" % (tag, key)
        )
    assert fields.get("run_exit") == "0", "%s: run failed" % tag
    assert fields.get("dump_exit") == "0", "%s: dump failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body, "run ---") == XDP_PASS, (
        "%s: test-run action must be PASS" % tag
    )
    want_sorted = sorted(
        [INIT_VALUE] * (ncpu - 1) + [HIT_VALUE]
    )
    oracle = parse_dump(body, "--- %s dump ---" % tag, tag)
    for key in range(entries):
        before = parse_raw_values(body, "init%d ---" % key, ncpu)
        assert before == [INIT_VALUE] * ncpu, (
            "%s: entry %d must start at %d on every CPU, got %r"
            % (tag, key, INIT_VALUE, before)
        )
        observed = parse_raw_values(body, "key%d ---" % key, ncpu)
        assert sorted(observed) == want_sorted, (
            "%s: entry %d must hold one %d among %ds, got %r"
            % (tag, key, HIT_VALUE, INIT_VALUE, observed)
        )
        assert sum(observed) == INIT_VALUE * ncpu + 1, (
            "%s: entry %d total must be %d, got %d"
            % (tag, key, INIT_VALUE * ncpu + 1, sum(observed))
        )
        assert oracle[key] == observed, (
            "%s: entry %d bpftool dump %r disagrees with raw %r"
            % (tag, key, oracle[key], observed)
        )


def test_rmw_lifecycle_one_entry():
    check_rmw_lifecycle(1)


def test_rmw_lifecycle_two_entries():
    check_rmw_lifecycle(2)


def test_rmw_lifecycle_three_entries():
    check_rmw_lifecycle(3)


def test_rmw_lifecycle_four_entries():
    check_rmw_lifecycle(4)


def check_rmw_counts(entries):
    tag = "count%d" % entries
    ncpu = check_cpu_facts()
    fields = check_map_identity(tag, entries)
    for key in range(entries):
        assert fields.get("init%d_exit" % key) == "0", (
            "%s: init%d failed" % (tag, key)
        )
        assert fields.get("after1key%d_exit" % key) == "0", (
            "%s: after1key%d failed" % (tag, key)
        )
        assert fields.get("after2key%d_exit" % key) == "0", (
            "%s: after2key%d failed" % (tag, key)
        )
    assert fields.get("run1_exit") == "0", "%s: run1 failed" % tag
    assert fields.get("run2_exit") == "0", "%s: run2 failed" % tag
    assert fields.get("dump_exit") == "0", "%s: dump failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    first_total = COUNT_INIT * ncpu + COUNT_FIRST_REPEAT
    second_total = first_total + COUNT_SECOND_REPEAT
    oracle = parse_dump(body, "--- %s dump ---" % tag, tag)
    for key in range(entries):
        before = parse_raw_values(body, "init%d ---" % key, ncpu)
        assert before == [COUNT_INIT] * ncpu, (
            "%s: entry %d must start at %d on every CPU, got %r"
            % (tag, key, COUNT_INIT, before)
        )
        after1 = parse_raw_values(body, "after1key%d ---" % key, ncpu)
        after2 = parse_raw_values(body, "after2key%d ---" % key, ncpu)
        assert all(value >= COUNT_INIT for value in after1), (
            "%s: entry %d lost an update: %r" % (tag, key, after1)
        )
        assert sum(after1) == first_total, (
            "%s: entry %d total after %d runs must be %d, got %d"
            % (tag, key, COUNT_FIRST_REPEAT, first_total, sum(after1))
        )
        assert all(
            later >= earlier for later, earlier in zip(after2, after1)
        ), "%s: entry %d moved backwards: %r -> %r" % (tag, key, after1, after2)
        assert sum(after2) == second_total, (
            "%s: entry %d total after %d more runs must be %d, got %d"
            % (tag, key, COUNT_SECOND_REPEAT, second_total, sum(after2))
        )
        assert oracle[key] == after2, (
            "%s: entry %d bpftool dump %r disagrees with raw %r"
            % (tag, key, oracle[key], after2)
        )


def test_rmw_exact_counts_one_entry():
    check_rmw_counts(1)


def test_rmw_exact_counts_two_entries():
    check_rmw_counts(2)


def test_rmw_exact_counts_three_entries():
    check_rmw_counts(3)


def test_rmw_exact_counts_four_entries():
    check_rmw_counts(4)


def check_delete(entries):
    tag = "deli%d" % entries
    ncpu = check_cpu_facts()
    fields = check_map_identity(tag, entries)
    assert fields.get("run_exit") == "0", "%s: run failed" % tag
    for key in range(entries):
        assert fields.get("key%d_exit" % key) == "0", (
            "%s: key%d read failed" % (tag, key)
        )
    assert fields.get("dump_exit") == "0", "%s: dump failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body, "run ---") == XDP_PASS, (
        "%s: test-run action must be PASS" % tag
    )
    oracle = parse_dump(body, "--- %s dump ---" % tag, tag)
    for key in range(entries):
        observed = parse_raw_values(body, "key%d ---" % key, ncpu)
        assert observed == [0] * ncpu, (
            "%s: entry %d must still read zero on every CPU, got %r"
            % (tag, key, observed)
        )
        assert oracle[key] == [0] * ncpu, (
            "%s: entry %d bpftool dump disagrees: %r" % (tag, key, oracle[key])
        )


def test_delete_refused_one_entry():
    check_delete(1)


def test_delete_refused_two_entries():
    check_delete(2)


def test_delete_refused_three_entries():
    check_delete(3)


def test_delete_refused_four_entries():
    check_delete(4)


def test_combined_counts_both_paths():
    tag = "comb"
    ncpu = check_cpu_facts()
    fields = check_map_identity(tag, 2)
    assert fields.get("rundrop_exit") == "0", "%s: drop run failed" % tag
    assert fields.get("runpass_exit") == "0", "%s: pass run failed" % tag
    assert fields.get("key0_exit") == "0", "%s: key0 read failed" % tag
    assert fields.get("key1_exit") == "0", "%s: key1 read failed" % tag
    assert fields.get("dump_exit") == "0", "%s: dump failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body, "rundrop ---") == XDP_DROP, (
        "%s: drop frame must report DROP" % tag
    )
    assert parse_run_action(body, "runpass ---") == XDP_PASS, (
        "%s: pass frame must report PASS" % tag
    )
    invocations = parse_raw_values(body, "key0 ---", ncpu)
    frame_bytes = parse_raw_values(body, "key1 ---", ncpu)
    assert sum(invocations) == 2, (
        "%s: entry 0 total must be 2, got %d" % (tag, sum(invocations))
    )
    assert sum(frame_bytes) == 2 * FRAME_LEN, (
        "%s: entry 1 total must be %d, got %d"
        % (tag, 2 * FRAME_LEN, sum(frame_bytes))
    )
    oracle = parse_dump(body, "--- %s dump ---" % tag, tag)
    assert oracle[0] == invocations, (
        "%s: entry 0 bpftool dump disagrees: %r" % (tag, oracle[0])
    )
    assert oracle[1] == frame_bytes, (
        "%s: entry 1 bpftool dump disagrees: %r" % (tag, oracle[1])
    )


def test_guest_provenance_and_cleanup():
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
    names = (
        ["pcpu_rmw%d.bpf.o" % entries for entries in (1, 2, 3, 4)]
        + ["pcpu_del%d.bpf.o" % entries for entries in (1, 2, 3, 4)]
        + ["pcpu_comb.bpf.o", HELPER_NAME, "data.bin", "drop.bin",
           "pass.bin", "guest_mojopcpu.sh"]
    )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in names:
        expected = (
            rec.consumed_staged_digest(name, run["stage"])
            if rec is not None else None
        )
        if expected is None:
            # No attestation context (standalone/pytest run):
            # fall back to the legacy post-hoc comparison.
            expected = sha256_file(
                os.path.join(run["stage"], name)
            )
            assert expected in run["output"], (
                "guest must re-verify staged hash of %s" % name
            )
            continue
        assert reported.get(name) == expected, (
            "guest must report the consumed bytes of %s" % name
        )


# No denials: no harness records flow through this suite (raw
# syscalls plus bpftool text/JSON only), so there are no
# expected-failure wire cases.
CASE_DENIALS = {}


def _helper():
    return ("stage", HELPER_NAME)


def _rmw_inputs(entries):
    return {
        "sources": [RMW_SOURCES[entries], _helper()],
        "objects": [("stage", "pcpu_rmw%d.bpf.o" % entries)],
        "corpus": [],
    }


def _del_inputs(entries):
    return {
        "sources": [DELETE_SOURCES[entries], _helper()],
        "objects": [("stage", "pcpu_del%d.bpf.o" % entries)],
        "corpus": [],
    }


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Decoder unit tests pin in-file helpers through the suite
# source; guest-backed cases additionally declare the staged
# syscall helper whose readbacks they decode. A class with any
# missing file digests to zeros and can never back a PASS.
CASE_INPUTS = {
    "test_parse_possible_list_forms": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_percpu_stride_padding": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_decode_values_exact": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_decode_bpftool_dump_shape": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_cpu_facts_agree": {
        "sources": [("stage", "guest_mojopcpu.sh")],
        "objects": [],
        "corpus": [],
    },
    "test_rmw_lifecycle_one_entry": _rmw_inputs(1),
    "test_rmw_lifecycle_two_entries": _rmw_inputs(2),
    "test_rmw_lifecycle_three_entries": _rmw_inputs(3),
    "test_rmw_lifecycle_four_entries": _rmw_inputs(4),
    "test_rmw_exact_counts_one_entry": _rmw_inputs(1),
    "test_rmw_exact_counts_two_entries": _rmw_inputs(2),
    "test_rmw_exact_counts_three_entries": _rmw_inputs(3),
    "test_rmw_exact_counts_four_entries": _rmw_inputs(4),
    "test_delete_refused_one_entry": _del_inputs(1),
    "test_delete_refused_two_entries": _del_inputs(2),
    "test_delete_refused_three_entries": _del_inputs(3),
    "test_delete_refused_four_entries": _del_inputs(4),
    "test_combined_counts_both_paths": {
        "sources": [COMBINED_SOURCE, _helper()],
        "objects": [("stage", "pcpu_comb.bpf.o")],
        "corpus": [],
    },
    "test_guest_provenance_and_cleanup": {
        "sources": ([RMW_SOURCES[n] for n in (1, 2, 3, 4)]
                    + [DELETE_SOURCES[n] for n in (1, 2, 3, 4)]
                    + [COMBINED_SOURCE, _helper()]),
        "objects": ([("stage", "pcpu_rmw%d.bpf.o" % n)
                     for n in (1, 2, 3, 4)]
                    + [("stage", "pcpu_del%d.bpf.o" % n)
                       for n in (1, 2, 3, 4)]
                    + [("stage", "pcpu_comb.bpf.o")]),
        "corpus": [],
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
        AssertionError, subprocess.TimeoutExpired,
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
        suite_id="kernel-mojopercpu", suite_path=__file__,
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
        AssertionError, subprocess.TimeoutExpired,
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
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            rec.end_case_fail(name)
            failures += 1
        else:
            print("PASS %s" % name)
            rec.end_case_hint(name, hint)
    if failures or unavailable_seen:
        return _finish(rec, unavailable_seen)
    print("mojo per-CPU: lifecycle, count, delete and combined checks passed")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())

