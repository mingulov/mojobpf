# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Per-CPU map decoding and kernel semantics proof.

Scope note: the MojoBPF pipeline emits exactly one map shape, the
one-entry array with u32 keys and u64 values; a manifest requesting a
per-CPU map is refused with ``MBPF205`` and no Mojo-authored per-CPU
program exists. This suite therefore proves the two halves that do not
need one: the independent per-CPU decoder in this file (possible-CPU
count handling plus 8-byte value-stride padding) and the kernel-side
per-CPU semantics, observed through unmodified bpftool and raw
``bpf()`` syscalls inside one disposable Linux guest.

Guest plan: create two ``percpu_array`` maps with unmodified bpftool (a
u64 map with 4 entries, a u32 map with 2 entries), initialize distinct
per-CPU values per key through the ``BPF_MAP_UPDATE_ELEM`` syscall, and
read them back through ``BPF_MAP_LOOKUP_ELEM`` (raw bytes, decoded only
by this file's decoder) and through ``bpftool -j map dump`` (the
independent cross-check oracle). The suite asserts exact per-CPU
values, exact totals and byte sums after quiescence, exact raw bytes
including padding, first-to-last key iteration with end-of-map
termination, and kernel refusals for invalid sizes, out-of-range keys,
and element deletion.

The decoder unit tests at the top of this file run without any guest;
the guest-backed tests share one boot. Standard library only.

Requires ``vng`` (virtme-ng) with a cached guest image on PATH
(default release v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane)
for the guest-backed tests. Missing tools fail loudly as environment
failures, never as passes.

Runnable directly (``python3 tests/kernel/test_percpu_maps.py``) or
under any ``test_``-style runner.
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

# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
GUEST_KERNEL_PREFIX = (
    VNG_RELEASE[1:] if VNG_RELEASE.startswith("v") else VNG_RELEASE
)
VNG_TIMEOUT = 900

MAP64_PIN = "/sys/fs/bpf/mjbpf_pc64"
MAP32_PIN = "/sys/fs/bpf/mjbpf_pc32"
MAP64_ENTRIES = 4
MAP32_ENTRIES = 2
KEY_SIZE = 4
VALUE64_SIZE = 8
VALUE32_SIZE = 4

# value(cpu) = base + cpu * step, with base per key.
PATTERN64_BASE = 1000
PATTERN32_BASE = 100
PATTERN_STEP = 1


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


# ---------------------------------------------------------------------------
# Independent per-CPU decoder.
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


def possible_cpu_count(text):
    """Return the possible-CPU count described by a kernel CPU list."""
    return len(parse_possible_list(text))


def percpu_stride(value_size):
    """Return the per-CPU stride: values are 8-byte aligned in memory."""
    if value_size <= 0:
        raise ValueError("value size must be positive")
    return (value_size + 7) // 8 * 8


def decode_percpu_values(raw, value_size, ncpu):
    """Decode one key's raw per-CPU buffer to little-endian integers.

    ``raw`` holds ``ncpu`` values laid out back to back with
    :func:`percpu_stride` bytes each; only the first ``value_size``
    bytes of each slot carry the value and the padding is skipped.
    """
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


def expected_percpu_buffer(base, step, value_size, ncpu):
    """Build the exact raw buffer for ``base + cpu * step`` values."""
    stride = percpu_stride(value_size)
    width = (value_size + 7) // 8 * 8 if value_size > 8 else value_size
    blob = bytearray()
    for cpu in range(ncpu):
        blob.extend((base + cpu * step).to_bytes(width, "little"))
        blob.extend(bytes(stride - width))
    return bytes(blob)


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
    assert possible_cpu_count("0-15\n") == 16
    assert possible_cpu_count("0-3,8-11") == 8
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
    assert percpu_stride(1) == 8
    assert percpu_stride(3) == 8
    assert percpu_stride(16) == 16
    try:
        percpu_stride(0)
    except ValueError:
        pass
    else:
        raise AssertionError("zero value size must be rejected")


def test_decode_unpadded_values():
    raw = b"".join(
        (1000 + cpu).to_bytes(8, "little") for cpu in range(4)
    )
    assert decode_percpu_values(raw, 8, 4) == [1000, 1001, 1002, 1003]
    try:
        decode_percpu_values(raw, 8, 5)
    except ValueError:
        pass
    else:
        raise AssertionError("short buffer must be rejected")


def test_decode_padded_values_skips_padding():
    raw = b"".join(
        (100 + cpu).to_bytes(4, "little") + b"\x00" * 4
        for cpu in range(4)
    )
    assert decode_percpu_values(raw, 4, 4) == [100, 101, 102, 103]
    naive = [
        int.from_bytes(raw[cpu * 4:cpu * 4 + 4], "little")
        for cpu in range(4)
    ]
    assert naive != [100, 101, 102, 103], (
        "stride-4 decoding must misdecode padded data (control)"
    )


def test_expected_buffer_round_trip():
    blob = expected_percpu_buffer(100, 1, 4, 4)
    assert blob == b"".join(
        (100 + cpu).to_bytes(4, "little") + b"\x00" * 4
        for cpu in range(4)
    )
    assert decode_percpu_values(blob, 4, 4) == [100, 101, 102, 103]
    blob64 = expected_percpu_buffer(1000, 1, 8, 3)
    assert decode_percpu_values(blob64, 8, 3) == [1000, 1001, 1002]


def test_decode_bpftool_dump_shape():
    doc = [
        {
            "key": ["0x00", "0x00", "0x00", "0x00"],
            "values": [
                {"cpu": 1, "value": ["0xe9", "0x03", "0x00", "0x00"]},
                {"cpu": 0, "value": ["0xe8", "0x03", "0x00", "0x00"]},
            ],
        }
    ]
    assert decode_bpftool_percpu_dump(doc) == {0: [1000, 1001]}


# ---------------------------------------------------------------------------
# In-guest syscall helper (staged into the guest; prints raw facts only).
# ---------------------------------------------------------------------------
#
# The helper performs raw bpf() syscalls against a pinned map: update one
# key's full per-CPU buffer, then read it back. It prints the raw buffer
# as hex and never decodes it; decoding stays host-side in this file so
# the decoder above is what the assertions exercise.

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


def main(argv):
    pin, key, value_size, ncpu, base, step = (
        argv[1], int(argv[2]), int(argv[3]), int(argv[4]),
        int(argv[5]), int(argv[6]),
    )
    stride = (value_size + 7) // 8 * 8
    path = ctypes.create_string_buffer(pin.encode("ascii"))
    get = ObjGetAttr(
        pathname=ctypes.addressof(path), bpf_fd=0, file_flags=0
    )
    fd = bpf(BPF_OBJ_GET, get)
    try:
        key_buf = ctypes.create_string_buffer(
            key.to_bytes(4, "little")
        )
        put = bytearray()
        for cpu in range(ncpu):
            put.extend((base + cpu * step).to_bytes(value_size, "little"))
            put.extend(bytes(stride - value_size))
        put_buf = ctypes.create_string_buffer(bytes(put))
        upd = ElemAttr(
            map_fd=fd, pad=0,
            key=ctypes.addressof(key_buf),
            value=ctypes.addressof(put_buf), flags=0,
        )
        bpf(BPF_MAP_UPDATE_ELEM, upd)
        got_buf = ctypes.create_string_buffer(ncpu * stride)
        get_attr = ElemAttr(
            map_fd=fd, pad=0,
            key=ctypes.addressof(key_buf),
            value=ctypes.addressof(got_buf), flags=0,
        )
        bpf(BPF_MAP_LOOKUP_ELEM, get_attr)
        sys.stdout.write("update_ok=1\\n")
        sys.stdout.write(
            "raw=" + bytes(got_buf).hex() + "\\n"
        )
    finally:
        os.close(fd)


main(sys.argv)
'''

HELPER_NAME = "percpu_roundtrip.py"


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_percpu ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "possible=$(cat /sys/devices/system/cpu/possible)"
echo "online=$(cat /sys/devices/system/cpu/online)"
echo "nproc=$(nproc)"
echo "nprocall=$(nproc --all)"
echo "=== staged hashes ==="
sha256sum percpu_roundtrip.py
roundtrip() {{
  tag="$1"; pin="$2"; key="$3"; vsize="$4"; ncpu="$5"; base="$6"; step="$7"
  out="/tmp/percpu-$tag.txt"
  python3 percpu_roundtrip.py "$pin" "$key" "$vsize" "$ncpu" "$base" "$step" > "$out" 2>&1
  echo "helper_exit=$?" >> "$out"
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "=== END $tag ==="
}}
dump() {{
  tag="$1"; pin="$2"
  echo "=== BEGIN $tag ==="
  bpftool -j map dump pinned "$pin" 2>&1
  echo "=== END $tag ==="
}}
bpftool map create {map64_pin} type percpu_array key 4 value 8 entries {map64_entries} name mjbpf_pc64
echo "create64_exit=$?"
bpftool map create {map32_pin} type percpu_array key 4 value 4 entries {map32_entries} name mjbpf_pc32
echo "create32_exit=$?"
echo "=== BEGIN identity ==="
bpftool -j map show name mjbpf_pc64 2>&1
bpftool -j map show name mjbpf_pc32 2>&1
echo "=== END identity ==="
{commands}
echo "=== BEGIN walk ==="
bpftool map getnext pinned {map64_pin} key 0 0 0 0 2>&1; echo "walk0_exit=$?"
bpftool map getnext pinned {map64_pin} key 1 0 0 0 2>&1; echo "walk1_exit=$?"
bpftool map getnext pinned {map64_pin} key 2 0 0 0 2>&1; echo "walk2_exit=$?"
bpftool map getnext pinned {map64_pin} key 3 0 0 0 2>&1; echo "walk3_exit=$?"
echo "=== END walk ==="
echo "=== BEGIN invalid ==="
bpftool map create /sys/fs/bpf/mojobpf_badkey type percpu_array key 3 value 8 entries 2 name mojobpf_badkey 2>&1; echo "badkey_exit=$?"
bpftool map create /sys/fs/bpf/mojobpf_badval type percpu_array key 4 value 0 entries 2 name mojobpf_badval 2>&1; echo "badval_exit=$?"
bpftool map update pinned {map64_pin} key 0 0 0 0 value 1 0 0 0 2>&1; echo "shortval_exit=$?"
bpftool map lookup pinned {map64_pin} key 9 0 0 0 2>&1; echo "badlookup_exit=$?"
bpftool map delete pinned {map64_pin} key 0 0 0 0 2>&1; echo "delete_exit=$?"
echo "=== END invalid ==="
rm -f {map64_pin} {map32_pin} /sys/fs/bpf/mojobpf_badkey /sys/fs/bpf/mojobpf_badval
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mjbpf_pc* /sys/fs/bpf/mojobpf_bad*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_percpu ==="
"""

BROADCAST_VALUE = 7777777

ROUNDTRIPS64 = tuple(
    ("k64_%d" % key, MAP64_PIN, key, VALUE64_SIZE,
     PATTERN64_BASE, PATTERN_STEP)
    for key in range(MAP64_ENTRIES)
)
ROUNDTRIPS32 = tuple(
    ("k32_%d" % key, MAP32_PIN, key, VALUE32_SIZE,
     PATTERN32_BASE, PATTERN_STEP)
    for key in range(MAP32_ENTRIES)
)
DUMPS = ("d64a", "d64a2", "d64b", "d32a", "d32a2")

CASE_TAGS = (
    tuple(tag for tag, _, _, _, _, _ in ROUNDTRIPS64)
    + tuple(tag for tag, _, _, _, _, _ in ROUNDTRIPS32)
    + DUMPS
    + ("identity", "walk", "invalid")
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def guest_run():
    """Stage the helper, boot one guest, return parsed case results."""
    if shutil.which("vng") is None:
        raise EnvironmentFailure("vng not found on PATH")
    stage = tempfile.mkdtemp(prefix="mojo-percpu-", dir="/tmp")
    helper_path = os.path.join(stage, HELPER_NAME)
    with open(helper_path, "w", encoding="utf-8") as handle:
        handle.write(HELPER_SOURCE)
    # The helper needs no guest CPU facts baked in: the CPU count is
    # discovered in-guest and passed per call below.
    commands = []
    # Possible-CPU count via nproc --all; the cpu-facts test pins it
    # against the possible list, the online list, nproc, and the bpftool
    # per-CPU entry count, so any disagreement fails loudly.
    ncpu_shell = "$(nproc --all)"
    for tag, pin, key, vsize, base, step in ROUNDTRIPS64:
        commands.append(
            "roundtrip %s %s %d %d %s %d %d"
            % (tag, pin, key, vsize, ncpu_shell, base * (key + 1), step)
        )
    commands.append("dump d64a %s" % MAP64_PIN)
    commands.append("dump d64a2 %s" % MAP64_PIN)
    bcast = " ".join(
        "%d" % byte
        for byte in BROADCAST_VALUE.to_bytes(8, "little")
    )
    commands.append(
        "bpftool map update pinned %s key 3 0 0 0 value %s 2>&1; "
        "echo \"bcast_exit=$?\"" % (MAP64_PIN, bcast)
    )
    commands.append("dump d64b %s" % MAP64_PIN)
    for tag, pin, key, vsize, base, step in ROUNDTRIPS32:
        commands.append(
            "roundtrip %s %s %d %d %s %d %d"
            % (tag, pin, key, vsize, ncpu_shell, base * (key + 1), step)
        )
    commands.append("dump d32a %s" % MAP32_PIN)
    commands.append("dump d32a2 %s" % MAP32_PIN)
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        map64_pin=MAP64_PIN,
        map32_pin=MAP32_PIN,
        map64_entries=MAP64_ENTRIES,
        map32_entries=MAP32_ENTRIES,
    )
    script_path = os.path.join(stage, "guest_percpu.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in (HELPER_NAME, "guest_percpu.sh"):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    try:
        proc = subprocess.run(
            ["vng", "--run", VNG_RELEASE, "--disable-kvm",
             "--exec", "bash %s" % script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VNG_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage kept at %s):\n%s"
            % (VNG_TIMEOUT, stage, (exc.stdout or "") + (exc.stderr or ""))
        )
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (proc.returncode, stage, output[-4000:])
        )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, body = match.groups()
        results[tag] = body
    missing = [tag for tag in CASE_TAGS if tag not in results]
    if missing:
        raise EnvironmentFailure(
            "guest output lacks cases %s (stage kept at %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    return {"stage": stage, "output": output, "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def toplevel(output, field):
    """Read one toplevel ``field=value`` line from the guest output."""
    match = re.search(r"^%s=(.*)$" % field, output, re.MULTILINE)
    assert match, "guest output lacks %s" % field
    return match.group(1).strip()


def guest_ncpu():
    """Possible-CPU count of the guest, from its own possible list."""
    return possible_cpu_count(toplevel(executed()["output"], "possible"))


def roundtrip_raw(tag):
    """Raw lookup buffer of one syscall round trip, as bytes."""
    body = executed()["results"][tag]
    assert "helper_exit=0" in body, "%s: helper failed:\n%s" % (tag, body)
    assert "update_ok=1" in body, "%s: update failed:\n%s" % (tag, body)
    match = re.search(r"^raw=([0-9a-f]+)$", body, re.MULTILINE)
    assert match, "%s: no raw buffer:\n%s" % (tag, body)
    return bytes.fromhex(match.group(1))


def dump_doc(tag):
    """Parse one ``bpftool -j map dump`` case body as JSON."""
    body = executed()["results"][tag]
    try:
        return json.loads(body)
    except ValueError:
        raise AssertionError(
            "%s: bpftool dump is not JSON:\n%s" % (tag, body[-500:])
        )


def predicted(key, base, step, ncpu):
    return [base * (key + 1) + cpu * step for cpu in range(ncpu)]


def test_guest_cpu_facts_agree():
    output = executed()["output"]
    possible = toplevel(output, "possible")
    online = toplevel(output, "online")
    nproc = int(toplevel(output, "nproc"))
    nprocall = int(toplevel(output, "nprocall"))
    assert possible_cpu_count(possible) == nproc, (
        "possible %r disagrees with nproc %d" % (possible, nproc)
    )
    assert possible_cpu_count(possible) == nprocall, (
        "possible %r disagrees with nproc --all %d" % (possible, nprocall)
    )
    assert possible_cpu_count(online) == nproc, (
        "online %r disagrees with nproc %d" % (online, nproc)
    )
    for tag in ("d64a", "d32a"):
        decoded = decode_bpftool_percpu_dump(dump_doc(tag))
        for key, values in sorted(decoded.items()):
            assert len(values) == nproc, (
                "%s key %d: bpftool reports %d CPUs, guest has %d"
                % (tag, key, len(values), nproc)
            )


def test_map_identity_per_kind():
    body = executed()["results"]["identity"]
    docs = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("{"):
            docs.append(json.loads(line))
    assert len(docs) == 2, "expected two map identity records"
    by_name = {doc["name"]: doc for doc in docs}
    info64 = by_name["mjbpf_pc64"]
    assert info64["type"] == "percpu_array"
    assert info64["bytes_key"] == KEY_SIZE
    assert info64["bytes_value"] == VALUE64_SIZE
    assert info64["max_entries"] == MAP64_ENTRIES
    info32 = by_name["mjbpf_pc32"]
    assert info32["type"] == "percpu_array"
    assert info32["bytes_key"] == KEY_SIZE
    assert info32["bytes_value"] == VALUE32_SIZE
    assert info32["max_entries"] == MAP32_ENTRIES


def test_u64_exact_per_cpu_values():
    ncpu = guest_ncpu()
    for tag, _, key, _, base, step in ROUNDTRIPS64:
        raw = roundtrip_raw(tag)
        expect = predicted(key, base, step, ncpu)
        assert decode_percpu_values(raw, VALUE64_SIZE, ncpu) == expect, (
            "%s: decoded values differ from the initialized pattern" % tag
        )
        assert raw == expected_percpu_buffer(
            base * (key + 1), step, VALUE64_SIZE, ncpu
        ), "%s: raw bytes differ from the exact expected buffer" % tag
    decoded = decode_bpftool_percpu_dump(dump_doc("d64a"))
    assert sorted(decoded) == list(range(MAP64_ENTRIES)), (
        "dump must carry all %d keys" % MAP64_ENTRIES
    )
    for _, _, key, _, base, step in ROUNDTRIPS64:
        expect = predicted(key, base, step, ncpu)
        assert decoded[key] == expect, (
            "bpftool cross-check for key %d differs from the pattern" % key
        )


def test_u64_exact_totals_and_byte_sums():
    ncpu = guest_ncpu()
    decoded = decode_bpftool_percpu_dump(dump_doc("d64a"))
    for _, _, key, _, base, step in ROUNDTRIPS64:
        expect = predicted(key, base, step, ncpu)
        assert sum(decoded[key]) == sum(expect), (
            "key %d total %d, expected %d"
            % (key, sum(decoded[key]), sum(expect))
        )
        raw = expected_percpu_buffer(
            base * (key + 1), step, VALUE64_SIZE, ncpu
        )
        assert sum(roundtrip_raw("k64_%d" % key)) == sum(raw), (
            "key %d byte sum differs from the exact buffer" % key
        )


def test_u32_padding_exact():
    ncpu = guest_ncpu()
    for tag, _, key, _, base, step in ROUNDTRIPS32:
        raw = roundtrip_raw(tag)
        expect = predicted(key, base, step, ncpu)
        assert decode_percpu_values(raw, VALUE32_SIZE, ncpu) == expect, (
            "%s: padded decode differs from the pattern" % tag
        )
        assert raw == expected_percpu_buffer(
            base * (key + 1), step, VALUE32_SIZE, ncpu
        ), "%s: raw bytes (with padding) differ" % tag
        naive = [
            int.from_bytes(raw[i * 4:i * 4 + 4], "little")
            for i in range(ncpu)
        ]
        assert naive != expect, (
            "%s: stride-4 decoding must misdecode (control)" % tag
        )
    decoded = decode_bpftool_percpu_dump(dump_doc("d32a"))
    for _, _, key, _, base, step in ROUNDTRIPS32:
        assert decoded[key] == predicted(key, base, step, ncpu), (
            "bpftool cross-check for u32 key %d differs" % key
        )


def test_dumps_stable_after_quiescence():
    assert dump_doc("d64a") == dump_doc("d64a2"), (
        "consecutive u64 dumps must agree exactly"
    )
    assert dump_doc("d32a") == dump_doc("d32a2"), (
        "consecutive u32 dumps must agree exactly"
    )


def test_broadcast_update_replaces_all_cpus():
    output = executed()["output"]
    assert toplevel(output, "bcast_exit") == "0", "broadcast update failed"
    ncpu = guest_ncpu()
    decoded = decode_bpftool_percpu_dump(dump_doc("d64b"))
    assert decoded[3] == [BROADCAST_VALUE] * ncpu, (
        "userspace update must replace every per-CPU copy"
    )
    for key in (0, 1, 2):
        assert decoded[key] == predicted(
            key, PATTERN64_BASE, PATTERN_STEP, ncpu
        ), "broadcast must leave other keys untouched"


def test_first_to_last_key_walk():
    body = executed()["results"]["walk"]
    assert "walk0_exit=0" in body, "getnext from key 0 must succeed"
    assert "walk1_exit=0" in body, "getnext from key 1 must succeed"
    assert "walk2_exit=0" in body, "getnext from key 2 must succeed"
    assert "walk3_exit=254" in body, (
        "getnext from the last key must fail with ENOENT"
    )
    assert "No such file or directory" in body, (
        "end of iteration must report ENOENT"
    )
    assert "next key:\n01 00 00 00" in body, "walk must visit key 1"
    assert "next key:\n02 00 00 00" in body, "walk must visit key 2"
    assert "next key:\n03 00 00 00" in body, "walk must visit key 3"


def test_invalid_sizes_refused():
    body = executed()["results"]["invalid"]
    assert "badkey_exit=255" in body, "key size 3 must be refused"
    assert "Invalid argument" in body, "bad sizes must report EINVAL"
    assert "badval_exit=255" in body, "value size 0 must be refused"
    assert "shortval_exit=255" in body, "short value update must fail"


def test_bad_key_and_delete_refused():
    body = executed()["results"]["invalid"]
    assert "badlookup_exit=254" in body, "out-of-range lookup must fail"
    assert "Not found" in body, "out-of-range lookup must miss, not decode"
    assert "delete_exit=234" in body, "per-CPU delete must fail"
    assert "delete failed: Invalid argument" in body, (
        "array-family delete must report EINVAL"
    )


def test_guest_provenance_and_cleanup():
    run = executed()
    assert "guest-kernel: %s" % GUEST_KERNEL_PREFIX in run["output"], (
        "guest kernel must be v%s" % GUEST_KERNEL_PREFIX
    )
    assert toplevel(run["output"], "create64_exit") == "0"
    assert toplevel(run["output"], "create32_exit") == "0"
    assert "pin absent (unloaded)" in run["output"], "pins must be removed"
    assert "PIN STILL PRESENT" not in run["output"], "pins must be removed"
    expected = sha256_file(os.path.join(run["stage"], HELPER_NAME))
    assert expected in run["output"], "guest must re-verify the helper hash"


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
    print("per-CPU maps: decoder, round trip and refusal checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
