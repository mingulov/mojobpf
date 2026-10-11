# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the hash map SDK slice.

Builds the four-pair hash round trip (``tests/compile/hash_rmw4.mojo``),
the four-deletion hash probe (``tests/compile/hash_delete4.mojo``), and
the out-of-bounds and unchecked negatives through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import path ->
``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel -mcpu=v3``),
then boots one disposable Linux guest and drives the four-entry hash
map lifecycle with unmodified bpftool:

* lifecycle: load the program, read the libbpf-created map parameters,
  initialize keys 0-3 to 41 from userspace, execute one kernel
  test-run, and read every key back independently (each must observe
  42 with exact little-endian bytes);
* exact counts: from a fresh load initialized to 1000, a 10-repeat run
  must observe exactly 1010 on every key and five further runs
  exactly 1015;
* miss path: on a fresh map every key misses (userspace and kernel
  agree); one test-run inserts nothing; inserting key 0 from
  userspace and running again observes exactly key 0 incremented
  while every other key still misses;
* deletion: the delete probe observes success on every present key
  (the XDP_PASS action) and every entry is gone afterwards; a
  userspace re-insert reads back exactly, a userspace delete
  removes it, and deleting an absent key fails explicitly;
* iteration: arbitrary u32 keys (including 0xDEADBEEF) insert and
  read back with exact little-endian key/value bytes; a get-next-key
  walk plus a JSON dump observe exactly the inserted set (hash
  order is unspecified, so the assertion is set equality, never
  order); filling the 4-entry budget refuses the fifth insert;
  short keys and values are refused instead of misdecoded;
* the out-of-bounds fixture is rejected by the kernel verifier at load
  (layout mismatch is never silently misdecoded);
* the unchecked-dereference fixture is rejected by the kernel verifier
  at load (the missing-null-check negative).

The two kernel-layer negatives go through the load/test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is).

The license gate agrees with the kernel: the built hash objects pass
inspection cleanly under the hash capability profile, the
helper-license preflight admits the used helpers (1, 2, 3) under the
project's non-GPL declaration, and the same preflight still refuses
the GPL-only witness there, so the admission is not vacuous.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng`` (virtme-ng)
with a cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools fail loudly as
environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_hash_maps.py``) or
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
COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
RMW_SOURCE = os.path.join(COMPILE_DIR, "hash_rmw4.mojo")
DELETE_SOURCE = os.path.join(COMPILE_DIR, "hash_delete4.mojo")
OOB_SOURCE = os.path.join(COMPILE_DIR, "hash_oob.mojo")
UNCHECKED_SOURCE = os.path.join(COMPILE_DIR, "hash_unchecked.mojo")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900

INIT_VALUE = 41
AFTER_VALUE = 42
COUNT_INIT = 1000
COUNT_FIRST_REPEAT = 10
COUNT_FIRST_VALUE = COUNT_INIT + COUNT_FIRST_REPEAT
COUNT_SECOND_REPEAT = 5
COUNT_SECOND_VALUE = COUNT_FIRST_VALUE + COUNT_SECOND_REPEAT
MAP_NAME = "mojobpf_map0"
HASH_PROFILE = "linux-bpfel-v3-hash"
APACHE = "Apache-2.0 WITH LLVM-exception"

MISS_ABSENT_KEY = 5
MISS_INSERT_VALUE = 7
MISS_AFTER_VALUE = 8
DEL_INIT = 9
DEL_REINSERT_KEY = 1
DEL_REINSERT_VALUE = 5
# (key, value) pairs for the iteration case: small keys plus a
# full-width key/value pair pinning little-endian layout.
ITER_PAIRS = (
    (7, 700),
    (42, 4200),
    (0xDEADBEEF, 0x1122334455667788),
)
FILL_KEYS = (100, 101)
OVER_KEY = 102

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


def decode_bpftool_hash_dump(doc):
    """Decode ``bpftool -j map dump`` output to {key int: value int}."""
    decoded = {}
    for entry in doc:
        key = int.from_bytes(
            bytes(int(byte, 16) for byte in entry["key"]), "little"
        )
        value = int.from_bytes(
            bytes(int(byte, 16) for byte in entry["value"]), "little"
        )
        decoded[key] = value
    return decoded


def test_key_value_byte_helpers():
    assert key_bytes(0) == "0 0 0 0"
    assert key_bytes(0xDEADBEEF) == "239 190 173 222"
    assert value_bytes(42) == "42 0 0 0 0 0 0 0"
    assert value_bytes(0x1122334455667788) == "136 119 102 85 68 51 34 17"
    assert hexle(42) == "2a00000000000000"
    assert hexle(0x1122334455667788) == "8877665544332211"


def test_decode_bpftool_hash_dump_shape():
    doc = [
        {
            "key": ["0x2a", "0x00", "0x00", "0x00"],
            "value": ["0x68", "0x10", "0x00", "0x00",
                      "0x00", "0x00", "0x00", "0x00"],
        },
        {
            "key": ["0xef", "0xbe", "0xad", "0xde"],
            "value": ["0x88", "0x77", "0x66", "0x55",
                      "0x44", "0x33", "0x22", "0x11"],
        },
    ]
    assert decode_bpftool_hash_dump(doc) == {
        42: 4200,
        0xDEADBEEF: 0x1122334455667788,
    }
    assert decode_bpftool_hash_dump([]) == {}


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
def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        [
            "mojo",
            "build",
            "--emit",
            "llvm",
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
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
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
echo "=== begin guest_hash ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py hash_rmw.bpf.o hash_del.bpf.o hash_oob.bpf.o hash_unchecked.bpf.o data.bin
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
life_case() {{
  tag="life"; obj="hash_rmw.bpf.o"
  pin="/sys/fs/bpf/mojobpf_hash_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  for key in 0 1 2 3; do
    bpftool map update id "$map_id" key $key 0 0 0 value {init_bytes} >/tmp/xdp-$tag.init$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  for key in 0 1 2 3; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.before$key 2>&1
    echo "before${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  for key in 0 1 2 3; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.after$key 2>&1
    echo "after${{key}}_exit=$?" >> "$out"
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  for key in 0 1 2 3; do
    echo "--- $tag before$key ---"
    cat /tmp/xdp-$tag.before$key
  done
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  for key in 0 1 2 3; do
    echo "--- $tag after$key ---"
    cat /tmp/xdp-$tag.after$key
  done
  echo "=== END $tag ==="
}}
count_case() {{
  tag="count"; obj="hash_rmw.bpf.o"
  pin="/sys/fs/bpf/mojobpf_hash_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  for key in 0 1 2 3; do
    bpftool map update id "$map_id" key $key 0 0 0 value {count_init_bytes} >/tmp/xdp-$tag.update$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat {first_repeat} > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  for key in 0 1 2 3; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.after1$key 2>&1
    echo "after1_${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat {second_repeat} > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  for key in 0 1 2 3; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.after2$key 2>&1
    echo "after2_${{key}}_exit=$?" >> "$out"
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  for key in 0 1 2 3; do
    echo "--- $tag after1_$key ---"
    cat /tmp/xdp-$tag.after1$key
  done
  echo "--- $tag run2 ---"
  cat /tmp/xdp-$tag.run2
  for key in 0 1 2 3; do
    echo "--- $tag after2_$key ---"
    cat /tmp/xdp-$tag.after2$key
  done
  echo "=== END $tag ==="
}}
miss_case() {{
  tag="miss"; obj="hash_rmw.bpf.o"
  pin="/sys/fs/bpf/mojobpf_hash_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  for key in 0 1 2 3 {absent_key}; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.fresh$key 2>&1
    echo "fresh${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  for key in 0 1 2 3 {absent_key}; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.still$key 2>&1
    echo "still${{key}}_exit=$?" >> "$out"
  done
  bpftool map update id "$map_id" key 0 0 0 0 value {miss_init_bytes} >/tmp/xdp-$tag.insert 2>&1
  echo "insert_exit=$?" >> "$out"
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.got0 2>&1
  echo "got0_exit=$?" >> "$out"
  for key in 1 2 3 {absent_key}; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.rest$key 2>&1
    echo "rest${{key}}_exit=$?" >> "$out"
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
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
  echo "=== END $tag ==="
}}
delete_case() {{
  tag="delete"; obj="hash_del.bpf.o"
  pin="/sys/fs/bpf/mojobpf_hash_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  for key in 0 1 2 3; do
    bpftool map update id "$map_id" key $key 0 0 0 value {del_init_bytes} >/tmp/xdp-$tag.init$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  for key in 0 1 2 3; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.gone$key 2>&1
    echo "gone${{key}}_exit=$?" >> "$out"
  done
  bpftool map update id "$map_id" key {del_reinsert_key} 0 0 0 value {del_reinsert_bytes} >/tmp/xdp-$tag.reinsert 2>&1
  echo "reinsert_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key {del_reinsert_key} 0 0 0 > /tmp/xdp-$tag.rehit 2>&1
  echo "rehit_exit=$?" >> "$out"
  bpftool map delete id "$map_id" key {del_reinsert_key} 0 0 0 > /tmp/xdp-$tag.udel 2>&1
  echo "udel_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key {del_reinsert_key} 0 0 0 > /tmp/xdp-$tag.ugone 2>&1
  echo "ugone_exit=$?" >> "$out"
  bpftool map delete id "$map_id" key {del_reinsert_key} 0 0 0 > /tmp/xdp-$tag.umiss 2>&1
  echo "umiss_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  for key in 0 1 2 3; do
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
  tag="iter"; obj="hash_rmw.bpf.o"
  pin="/sys/fs/bpf/mojobpf_hash_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  bpftool map update id "$map_id" key {iter0_key} value {iter0_value} >/tmp/xdp-$tag.ins0 2>&1
  echo "ins0_exit=$?" >> "$out"
  bpftool map update id "$map_id" key {iter1_key} value {iter1_value} >/tmp/xdp-$tag.ins1 2>&1
  echo "ins1_exit=$?" >> "$out"
  bpftool map update id "$map_id" key {iter2_key} value {iter2_value} >/tmp/xdp-$tag.ins2 2>&1
  echo "ins2_exit=$?" >> "$out"
  bpftool -j map dump id "$map_id" > /tmp/xdp-$tag.dump1 2>/tmp/xdp-$tag.dump1.err
  echo "dump1_exit=$?" >> "$out"
  bpftool map getnext id "$map_id" key {iter0_key} > /tmp/xdp-$tag.gx0 2>&1
  echo "gx0_exit=$?" >> "$out"
  bpftool map getnext id "$map_id" key {iter1_key} > /tmp/xdp-$tag.gx1 2>&1
  echo "gx1_exit=$?" >> "$out"
  bpftool map getnext id "$map_id" key {iter2_key} > /tmp/xdp-$tag.gx2 2>&1
  echo "gx2_exit=$?" >> "$out"
  bpftool map delete id "$map_id" key {iter1_key} > /tmp/xdp-$tag.shrink 2>&1
  echo "shrink_exit=$?" >> "$out"
  bpftool -j map dump id "$map_id" > /tmp/xdp-$tag.dump2 2>/tmp/xdp-$tag.dump2.err
  echo "dump2_exit=$?" >> "$out"
  bpftool map update id "$map_id" key {fill0_key} value {fill_value} >/tmp/xdp-$tag.fill0 2>&1
  echo "fill0_exit=$?" >> "$out"
  bpftool map update id "$map_id" key {fill1_key} value {fill_value} >/tmp/xdp-$tag.fill1 2>&1
  echo "fill1_exit=$?" >> "$out"
  bpftool map update id "$map_id" key {over_key} value {fill_value} > /tmp/xdp-$tag.over 2>&1
  echo "over_exit=$?" >> "$out"
  bpftool map update id "$map_id" key 0 0 value 1 0 0 0 0 0 0 0 > /tmp/xdp-$tag.shortkey 2>&1
  echo "shortkey_exit=$?" >> "$out"
  bpftool map update id "$map_id" key 0 0 0 0 value 1 0 0 0 > /tmp/xdp-$tag.shortval 2>&1
  echo "shortval_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
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
  echo "--- $tag over ---"
  cat /tmp/xdp-$tag.over
  echo "--- $tag shortkey ---"
  cat /tmp/xdp-$tag.shortkey
  echo "--- $tag shortval ---"
  cat /tmp/xdp-$tag.shortval
  echo "=== END $tag ==="
}}
neg_case() {{
  tag="$1"; obj="$2"
  out="/tmp/xdp-$tag.json"
  python3 bpf_test_run.py --object "$obj" --expect-action {action} \\
    --data-in data.bin --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== BEGIN residue ==="
echo "--- residue prog ---"
bpftool -j prog show 2>&1; prog_exit=$?
echo "--- residue map ---"
bpftool -j map show 2>&1; map_exit=$?
echo "residue_prog_exit=$prog_exit"
echo "residue_map_exit=$map_exit"
echo "=== END residue ==="
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_hash_* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_hash ==="
"""

CASES = (
    ("life", "hash_rmw.bpf.o", "life"),
    ("count", "hash_rmw.bpf.o", "count"),
    ("miss", "hash_rmw.bpf.o", "miss"),
    ("delete", "hash_del.bpf.o", "delete"),
    ("iter", "hash_rmw.bpf.o", "iter"),
    ("oob", "hash_oob.bpf.o", "neg"),
    ("unchecked", "hash_unchecked.bpf.o", "neg"),
)


def guest_run():
    """Build all objects, boot one guest, return parsed case results."""
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        RMW_SOURCE,
        DELETE_SOURCE,
        OOB_SOURCE,
        UNCHECKED_SOURCE,
        ADAPTER,
        HARNESS,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-hash-", dir="/tmp")
    staged = {
        "bpf_test_run.py": HARNESS,
        "hash_rmw.bpf.o": build_object(RMW_SOURCE, stage, "hash_rmw"),
        "hash_del.bpf.o": build_object(DELETE_SOURCE, stage, "hash_del"),
        "hash_oob.bpf.o": build_object(OOB_SOURCE, stage, "hash_oob"),
        "hash_unchecked.bpf.o": build_object(
            UNCHECKED_SOURCE, stage, "hash_unchecked"
        ),
    }
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(60))
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, kind in CASES:
        if kind == "neg":
            commands.append("neg_case %s %s" % (tag, obj))
        else:
            commands.append("%s_case" % kind)
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init_bytes=value_bytes(INIT_VALUE),
        count_init_bytes=value_bytes(COUNT_INIT),
        first_repeat=COUNT_FIRST_REPEAT,
        second_repeat=COUNT_SECOND_REPEAT,
        absent_key=MISS_ABSENT_KEY,
        miss_init_bytes=value_bytes(MISS_INSERT_VALUE),
        del_init_bytes=value_bytes(DEL_INIT),
        del_reinsert_key=DEL_REINSERT_KEY,
        del_reinsert_bytes=value_bytes(DEL_REINSERT_VALUE),
        iter0_key=key_bytes(ITER_PAIRS[0][0]),
        iter0_value=value_bytes(ITER_PAIRS[0][1]),
        iter1_key=key_bytes(ITER_PAIRS[1][0]),
        iter1_value=value_bytes(ITER_PAIRS[1][1]),
        iter2_key=key_bytes(ITER_PAIRS[2][0]),
        iter2_value=value_bytes(ITER_PAIRS[2][1]),
        fill0_key=key_bytes(FILL_KEYS[0]),
        fill1_key=key_bytes(FILL_KEYS[1]),
        fill_value=value_bytes(1),
        over_key=key_bytes(OVER_KEY),
        action=XDP_PASS,
    )
    script_path = os.path.join(stage, "guest_hash.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_hash.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # Preflight observations for provenance comparisons. Host readers
    # separately consume logged buffers; this scan proves no guest use.
    guest_proc.consume_declared_inputs(stage, extra=tuple(staged) + ("data.bin",))
    code, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm",
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
        progress_banner="=== begin guest_hash ===",
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


def parse_lookup_hex(body, marker):
    """Extract the looked-up value bytes as compact lowercase hex."""
    section = body.split(marker, 1)[1]
    match = re.search(r"value:\s*([0-9a-fA-F ]+)", section)
    assert match, "no bpftool value line after %r" % marker
    return match.group(1).replace(" ", "").lower()


def parse_run_action(body, marker="run ---"):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


def check_map_identity(tag):
    """Assert the libbpf-created map is the declared 4-entry hash."""
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    assert fields.get("load_exit") == "0", "%s: load failed" % tag
    assert fields.get("mapinfo_exit") == "0", "%s: mapinfo failed" % tag
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "hash", "%s: not a hash map" % tag
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", "%s: value size is not u64" % tag
    assert fields.get("map_entries") == "4", "%s: not four entries" % tag
    return fields


def test_lifecycle_init_run_observe():
    fields = check_map_identity("life")
    for key in range(4):
        for stem in ("init%d", "before%d", "after%d"):
            name = (stem % key) + "_exit"
            assert fields.get(name) == "0", "life: %s=%r" % (
                name, fields.get(name))
    assert fields.get("run_exit") == "0", "life: run failed"
    assert fields.get("unload_ok") == "1", "life: pin was not removed"
    body = executed()["results"]["life"]["body"]
    assert parse_run_action(body) == XDP_PASS, "test-run action must be PASS"
    for key in range(4):
        before = parse_lookup_hex(body, "before%d ---" % key)
        after = parse_lookup_hex(body, "after%d ---" % key)
        assert before == hexle(INIT_VALUE), (
            "key %d: userspace init must read back %d first, got %s"
            % (key, INIT_VALUE, before)
        )
        assert after == hexle(AFTER_VALUE), (
            "key %d: expected map value %s, observed %s"
            % (key, hexle(AFTER_VALUE), after)
        )


def test_exact_counts_after_quiescence():
    fields = check_map_identity("count")
    for key in range(4):
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
    assert fields.get("unload_ok") == "1", "count: pin was not removed"
    body = executed()["results"]["count"]["body"]
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    for key in range(4):
        after1 = parse_lookup_hex(body, "after1_%d ---" % key)
        after2 = parse_lookup_hex(body, "after2_%d ---" % key)
        assert after1 == hexle(COUNT_FIRST_VALUE), (
            "key %d: after %d runs expected %s, observed %s"
            % (key, COUNT_FIRST_REPEAT, hexle(COUNT_FIRST_VALUE),
               after1)
        )
        assert after2 == hexle(COUNT_SECOND_VALUE), (
            "key %d: after %d more runs expected %s, observed %s"
            % (key, COUNT_SECOND_REPEAT, hexle(COUNT_SECOND_VALUE),
               after2)
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
    fields = parse_fields(executed()["results"]["miss"]["body"])
    assert fields.get("insert_exit") == "0", "miss: insert failed"
    assert fields.get("run2_exit") == "0", "miss: run2 failed"
    assert fields.get("got0_exit") == "0", "miss: key 0 must hit now"
    for key in (1, 2, 3, MISS_ABSENT_KEY):
        assert fields.get("rest%d_exit" % key) != "0", (
            "miss: key %d must still miss after run2" % key
        )
    body = executed()["results"]["miss"]["body"]
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    got = parse_lookup_hex(body, "got0 ---")
    assert got == hexle(MISS_AFTER_VALUE), (
        "key 0: expected %s, observed %s"
        % (hexle(MISS_AFTER_VALUE), got)
    )
    for key in (1, 2, 3, MISS_ABSENT_KEY):
        assert "Not found" in section_text(body, "miss rest%d ---" % key), (
            "miss: key %d must report a miss after run2" % key
        )


def test_kernel_delete_removes_entries():
    fields = check_map_identity("delete")
    for key in range(4):
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
    for key in range(4):
        assert "Not found" in section_text(
            body, "delete gone%d ---" % key
        ), "delete: key %d must report a miss after the run" % key


def test_userspace_delete_lifecycle():
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
    rehit = parse_lookup_hex(body, "rehit ---")
    assert rehit == hexle(DEL_REINSERT_VALUE), (
        "reinserted key: expected %s, observed %s"
        % (hexle(DEL_REINSERT_VALUE), rehit)
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
         "[{\"name\": \"mojobpf_hash_x\"}]\n"
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
    fields = check_map_identity("iter")
    for name in ("ins0_exit", "ins1_exit", "ins2_exit", "dump1_exit",
                 "dump2_exit", "shrink_exit"):
        assert fields.get(name) == "0", "iter: %s=%r" % (
            name, fields.get(name))
    assert fields.get("unload_ok") == "1", "iter: pin was not removed"
    body = executed()["results"]["iter"]["body"]
    want = dict(ITER_PAIRS)
    try:
        dump1 = json.loads(section_text(body, "iter dump1 ---").strip())
    except ValueError:
        raise guest_proc.GuestMissing(
            "iter dump1: bpftool dump is not JSON:\n%s" % body[-500:]
        )
    assert decode_bpftool_hash_dump(dump1) == want, (
        "dump1: expected %r, observed %r"
        % (want, decode_bpftool_hash_dump(dump1))
    )
    # The full-width pair pins little-endian key/value layout.
    wide = [
        entry for entry in dump1
        if entry["key"] == ["0xef", "0xbe", "0xad", "0xde"]
    ]
    assert len(wide) == 1, "dump1 must carry the 0xDEADBEEF key once"
    assert wide[0]["value"] == [
        "0x88", "0x77", "0x66", "0x55",
        "0x44", "0x33", "0x22", "0x11",
    ], "dump1 must carry the exact wide value bytes"
    # Hash order is unspecified, so the walk asserts chain
    # mechanics, not order: getnext from every inserted key must
    # form one complete acyclic chain -- distinct successors, no
    # self-successor, exactly one terminal ENOENT -- with exits
    # coherent with the outcomes (0 on a successor, nonzero on
    # ENOENT). The exact set itself is pinned by the JSON dumps
    # above and below.
    succ = {}
    for probe, key in (("gx0", ITER_PAIRS[0][0]),
                       ("gx1", ITER_PAIRS[1][0]),
                       ("gx2", ITER_PAIRS[2][0])):
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
    try:
        dump2 = json.loads(section_text(body, "iter dump2 ---").strip())
    except ValueError:
        raise guest_proc.GuestMissing(
            "iter dump2: bpftool dump is not JSON:\n%s" % body[-500:]
        )
    shrunk = {
        key: value for key, value in want.items()
        if key != ITER_PAIRS[1][0]
    }
    assert decode_bpftool_hash_dump(dump2) == shrunk, (
        "dump2: expected %r, observed %r"
        % (shrunk, decode_bpftool_hash_dump(dump2))
    )


def test_budget_and_sizes_refused():
    fields = parse_fields(executed()["results"]["iter"]["body"])
    assert fields.get("fill0_exit") == "0", "iter: fill0 failed"
    assert fields.get("fill1_exit") == "0", "iter: fill1 failed"
    assert fields.get("over_exit") != "0", (
        "the fifth insert into a 4-entry map must fail"
    )
    assert fields.get("shortkey_exit") != "0", (
        "update with a short key must fail"
    )
    assert fields.get("shortval_exit") != "0", (
        "update with a short value must fail"
    )
    body = executed()["results"]["iter"]["body"]
    assert "Argument list too long" in section_text(body, "iter over ---"), (
        "the over-budget insert must report E2BIG"
    )
    assert "expected 8 bytes got 4" in section_text(
        body, "iter shortval ---"
    ), "short value update must name the size mismatch"


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
    """Inspection + preflight agree with the kernel on hash objects."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
    from mojobpf import inspect as inspect_module  # noqa: E402

    stage = executed()["stage"]
    for name in ("hash_rmw.bpf.o", "hash_del.bpf.o"):
        report = guest_proc.inspect_consumed(
            os.path.join(stage, name),
            HASH_PROFILE,
        )
        assert report.ok is True, (name, report.to_dict())
    assert inspect_module.preflight_helper_licenses(
        [1, 2, 3], APACHE, HASH_PROFILE
    ) is None
    try:
        inspect_module.preflight_helper_licenses(
            [35], APACHE, HASH_PROFILE
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
        "hash_rmw.bpf.o",
        "hash_del.bpf.o",
        "hash_oob.bpf.o",
        "hash_unchecked.bpf.o",
        "data.bin",
    ):
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
    assert_residue_clean(run["results"]["residue"]["body"])


# The verifier negatives are denials: each expects the wire-derived
# FAIL at VERIFY (the bad object observably rejected at load) and
# passes only its own cell when the denial is observed with
# evidence. They guard the lifecycle: the hash object must load
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
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_decode_bpftool_hash_dump_shape": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_lifecycle_init_run_observe": {
        "sources": [RMW_SOURCE],
        "objects": [("stage", "hash_rmw.bpf.o")],
        "corpus": [],
    },
    "test_exact_counts_after_quiescence": {
        "sources": [RMW_SOURCE],
        "objects": [("stage", "hash_rmw.bpf.o")],
        "corpus": [],
    },
    "test_miss_path_inserts_nothing": {
        "sources": [RMW_SOURCE],
        "objects": [("stage", "hash_rmw.bpf.o")],
        "corpus": [],
    },
    "test_scoped_update_after_insert": {
        "sources": [RMW_SOURCE],
        "objects": [("stage", "hash_rmw.bpf.o")],
        "corpus": [],
    },
    "test_kernel_delete_removes_entries": {
        "sources": [DELETE_SOURCE],
        "objects": [("stage", "hash_del.bpf.o")],
        "corpus": [],
    },
    "test_userspace_delete_lifecycle": {
        "sources": [DELETE_SOURCE],
        "objects": [("stage", "hash_del.bpf.o")],
        "corpus": [],
    },
    "test_residue_checks_refuse_blind_spots": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_walk_chain_refuses_broken_chains": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_iteration_set_and_bytes": {
        "sources": [RMW_SOURCE],
        "objects": [("stage", "hash_rmw.bpf.o")],
        "corpus": [],
    },
    "test_budget_and_sizes_refused": {
        "sources": [RMW_SOURCE],
        "objects": [("stage", "hash_rmw.bpf.o")],
        "corpus": [],
    },
    "test_oob_rejected_by_verifier": {
        "sources": [OOB_SOURCE],
        "objects": [("stage", "hash_oob.bpf.o")],
        "corpus": [],
    },
    "test_unchecked_rejected_by_verifier": {
        "sources": [UNCHECKED_SOURCE],
        "objects": [("stage", "hash_unchecked.bpf.o")],
        "corpus": [],
    },
    "test_license_gate_agrees": {
        "sources": [RMW_SOURCE, DELETE_SOURCE],
        "objects": [("stage", "hash_rmw.bpf.o"),
                    ("stage", "hash_del.bpf.o")],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [RMW_SOURCE, DELETE_SOURCE, OOB_SOURCE,
                    UNCHECKED_SOURCE, HARNESS],
        "objects": [("stage", "hash_rmw.bpf.o"),
                    ("stage", "hash_del.bpf.o"),
                    ("stage", "hash_oob.bpf.o"),
                    ("stage", "hash_unchecked.bpf.o")],
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
        suite_id="kernel-hash", suite_path=__file__,
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
    print("hash maps: lifecycle, count, miss, delete, iteration, "
          "negative, license and provenance checks passed")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
