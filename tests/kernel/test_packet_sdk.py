# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the packet-SDK and scalar-boundary programs.

Builds the packet fixtures (``tests/compile/packet_*.mojo``) and the
scalar-boundary fixtures (``tests/compile/scalar_*.mojo``) through
the genuine pipeline (``mojo build --emit llvm`` with the packaged
SDK on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable Linux
guest and executes the kernel test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is)
against crafted frames. An independent reimplementation of each
shape's specified rule predicts every expectation; short frames
prove the guard path by taking it.

Shapes and rules (XDP_DROP is 1, XDP_PASS is 2; every guard fails
closed to XDP_DROP):

* fixed_byte: drop when the frame holds at least 15 bytes and bit 0
  of byte 14 is set, else pass;
* var_offset: with off = length mod 64, drop when the frame holds
  byte ``off`` and bit 0 of that byte is set, else pass;
* half: drop when the frame holds at least 16 bytes and bytes 14-15
  read 0x3412 little-endian, else pass;
* word: drop when the frame holds at least 18 bytes and bytes 14-17
  read 0x78563412 little-endian, else pass;
* short_guard: pass when the frame holds at least 64 bytes and byte
  63 is 0x5A, else drop;
* cursor: drop when the frame holds at least 16 bytes, bit 0 of byte
  14 is set, and byte 15 is 0x34, else pass;
* endian: drop when the frame holds at least 28 bytes and every
  asserted word matches its boundary constant (network-order
  0x0000/0xFFFF/0x00FF/0x8001 at bytes 14/16/18/20, little-endian
  0xFF00 at byte 22, little-endian 0x80000001 at byte 24), else
  pass; the oracle decodes with ``int.from_bytes``, never the
  shift-or assembly the SDK performs;
* guard_edge: drop when the frame holds at least 14 bytes and byte
  13 is 0xA5, else pass; a frame of exactly 14 bytes proceeds
  while shorter frames trip the guard, pinning the need-equals-
  length edge.

Boundary frames on the older shapes pin all-zero, all-ones, and
extreme bytes through the same rules. Two negative fixtures
compile and must be rejected by the kernel verifier at load with
their predicted log lines: the unguarded shape (no guard at all)
and the last-byte shape (the backend rewrites its address into
prohibited packet-end arithmetic). Staged file hashes are
re-verified inside the guest so the observed actions are tied to
the exact bytes built here.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng``
(virtme-ng) with a cached guest image on PATH (default release
v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools
fail loudly as environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_packet_sdk.py``) or
under any ``test_``-style runner. Standard library only. The guest
boot takes a few minutes under software emulation; all cases share a
single boot.
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
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_DROP = 1
XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900

SHAPES = (
    "packet_fixed_byte",
    "packet_var_offset",
    "packet_half",
    "packet_word",
    "packet_short_guard",
    "packet_cursor",
    "scalar_endian",
    "scalar_guard_edge",
)

# Negative (shape, guest tag, predicted verifier log line) triples:
# each object compiles through the genuine pipeline and passes the
# IR audit, but the kernel verifier must refuse it at load.
NEGATIVES = (
    ("packet_unguarded", "unguarded", "invalid access to packet"),
    ("scalar_addr_edge", "addr-edge",
     "pointer arithmetic on pkt_end prohibited"),
)


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def frame(size, patches):
    """Zero frame of `size` bytes with {offset: value} applied."""
    buf = bytearray(size)
    for offset, value in patches.items():
        buf[offset] = value
    return bytes(buf)


def classify(shape, data):
    """Independent prediction of the specified rule for a shape."""
    if shape == "packet_fixed_byte":
        if len(data) < 15:
            return XDP_DROP
        if (data[14] & 1) == 1:
            return XDP_DROP
        return XDP_PASS
    if shape == "packet_var_offset":
        off = len(data) & 63
        if off + 1 > len(data):
            return XDP_DROP
        if (data[off] & 1) == 1:
            return XDP_DROP
        return XDP_PASS
    if shape == "packet_half":
        if len(data) < 16:
            return XDP_DROP
        if data[14] | (data[15] << 8) == 0x3412:
            return XDP_DROP
        return XDP_PASS
    if shape == "packet_word":
        if len(data) < 18:
            return XDP_DROP
        word = data[14] | (data[15] << 8) | (data[16] << 16) | (data[17] << 24)
        if word == 0x78563412:
            return XDP_DROP
        return XDP_PASS
    if shape == "packet_short_guard":
        if len(data) < 64:
            return XDP_DROP
        if data[63] == 0x5A:
            return XDP_PASS
        return XDP_DROP
    if shape == "packet_cursor":
        if len(data) < 16:
            return XDP_DROP
        if (data[14] & 1) == 1 and data[15] == 0x34:
            return XDP_DROP
        return XDP_PASS
    if shape == "scalar_endian":
        if len(data) < 28:
            return XDP_DROP
        be_words = [
            int.from_bytes(data[off : off + 2], "big")
            for off in (14, 16, 18, 20)
        ]
        if be_words != [0x0000, 0xFFFF, 0x00FF, 0x8001]:
            return XDP_PASS
        if int.from_bytes(data[22:24], "little") != 0xFF00:
            return XDP_PASS
        if int.from_bytes(data[24:28], "little") != 0x80000001:
            return XDP_PASS
        return XDP_DROP
    if shape == "scalar_guard_edge":
        if len(data) < 14:
            return XDP_DROP
        if data[13] == 0xA5:
            return XDP_DROP
        return XDP_PASS
    raise AssertionError("unknown shape: %s" % shape)


# frame key -> (size, {offset: value}).
FRAMES = {
    "fixed-drop": (60, {14: 1}),
    "fixed-pass": (60, {14: 0}),
    "fixed-short": (10, {}),
    "var-64-drop": (64, {0: 1}),
    "var-64-pass": (64, {0: 0}),
    "var-100-drop": (100, {36: 1}),
    "var-100-pass": (100, {36: 0}),
    "var-65-drop": (65, {1: 1}),
    "var-60-guard": (60, {}),
    "var-10-guard": (10, {}),
    "half-drop": (60, {14: 0x12, 15: 0x34}),
    "half-pass": (60, {}),
    "half-short": (10, {}),
    "word-drop": (60, {14: 0x12, 15: 0x34, 16: 0x56, 17: 0x78}),
    "word-pass": (60, {}),
    "word-short": (10, {}),
    "sg-pass": (64, {63: 0x5A}),
    "sg-content": (64, {}),
    "sg-short": (60, {}),
    "cursor-drop": (60, {14: 1, 15: 0x34}),
    "cursor-pass-bit": (60, {14: 1, 15: 0}),
    "cursor-pass-mark": (60, {14: 0, 15: 0x34}),
    "cursor-short": (10, {}),
    "fixed-fe": (60, {14: 0xFE}),
    "fixed-ff": (60, {14: 0xFF}),
    "half-zero": (60, {14: 0x00, 15: 0x00}),
    "half-ones": (60, {14: 0xFF, 15: 0xFF}),
    "word-ones": (60, {14: 0xFF, 15: 0xFF, 16: 0xFF, 17: 0xFF}),
    "word-lowhalf": (60, {14: 0x12, 15: 0x34, 16: 0x00, 17: 0x00}),
    "endian-drop": (28, {14: 0x00, 15: 0x00, 16: 0xFF, 17: 0xFF,
                         18: 0x00, 19: 0xFF, 20: 0x80, 21: 0x01,
                         22: 0x00, 23: 0xFF, 24: 0x01, 25: 0x00,
                         26: 0x00, 27: 0x80}),
    "endian-flip-be0": (28, {14: 0x01, 15: 0x00, 16: 0xFF, 17: 0xFF,
                             18: 0x00, 19: 0xFF, 20: 0x80, 21: 0x01,
                             22: 0x00, 23: 0xFF, 24: 0x01, 25: 0x00,
                             26: 0x00, 27: 0x80}),
    "endian-flip-be1": (28, {14: 0x00, 15: 0x00, 16: 0xFF, 17: 0x00,
                             18: 0x00, 19: 0xFF, 20: 0x80, 21: 0x01,
                             22: 0x00, 23: 0xFF, 24: 0x01, 25: 0x00,
                             26: 0x00, 27: 0x80}),
    "endian-flip-be2": (28, {14: 0x00, 15: 0x00, 16: 0xFF, 17: 0xFF,
                             18: 0x01, 19: 0xFF, 20: 0x80, 21: 0x01,
                             22: 0x00, 23: 0xFF, 24: 0x01, 25: 0x00,
                             26: 0x00, 27: 0x80}),
    "endian-flip-be3": (28, {14: 0x00, 15: 0x00, 16: 0xFF, 17: 0xFF,
                             18: 0x00, 19: 0xFF, 20: 0x00, 21: 0x01,
                             22: 0x00, 23: 0xFF, 24: 0x01, 25: 0x00,
                             26: 0x00, 27: 0x80}),
    "endian-flip-le16": (28, {14: 0x00, 15: 0x00, 16: 0xFF, 17: 0xFF,
                              18: 0x00, 19: 0xFF, 20: 0x80, 21: 0x01,
                              22: 0x01, 23: 0xFF, 24: 0x01, 25: 0x00,
                              26: 0x00, 27: 0x80}),
    "endian-flip-le32": (28, {14: 0x00, 15: 0x00, 16: 0xFF, 17: 0xFF,
                              18: 0x00, 19: 0xFF, 20: 0x80, 21: 0x01,
                              22: 0x00, 23: 0xFF, 24: 0x01, 25: 0x00,
                              26: 0x00, 27: 0x00}),
    "endian-short27": (27, {}),
    "endian-short10": (10, {}),
    "edge14-drop": (14, {13: 0xA5}),
    "edge14-pass": (14, {}),
    "edge60-drop": (60, {13: 0xA5}),
    "edge13-guard": (13, {}),
    "edge1-guard": (1, {}),
}

# tag -> (shape, frame key). The tag doubles as the staged file stem.
CASES = {
    "fixed-drop": ("packet_fixed_byte", "fixed-drop"),
    "fixed-pass": ("packet_fixed_byte", "fixed-pass"),
    "fixed-short": ("packet_fixed_byte", "fixed-short"),
    "var-64-drop": ("packet_var_offset", "var-64-drop"),
    "var-64-pass": ("packet_var_offset", "var-64-pass"),
    "var-100-drop": ("packet_var_offset", "var-100-drop"),
    "var-100-pass": ("packet_var_offset", "var-100-pass"),
    "var-65-drop": ("packet_var_offset", "var-65-drop"),
    "var-60-guard": ("packet_var_offset", "var-60-guard"),
    "var-10-guard": ("packet_var_offset", "var-10-guard"),
    "half-drop": ("packet_half", "half-drop"),
    "half-pass": ("packet_half", "half-pass"),
    "half-short": ("packet_half", "half-short"),
    "word-drop": ("packet_word", "word-drop"),
    "word-pass": ("packet_word", "word-pass"),
    "word-short": ("packet_word", "word-short"),
    "sg-pass": ("packet_short_guard", "sg-pass"),
    "sg-content": ("packet_short_guard", "sg-content"),
    "sg-short": ("packet_short_guard", "sg-short"),
    "cursor-drop": ("packet_cursor", "cursor-drop"),
    "cursor-pass-bit": ("packet_cursor", "cursor-pass-bit"),
    "cursor-pass-mark": ("packet_cursor", "cursor-pass-mark"),
    "cursor-short": ("packet_cursor", "cursor-short"),
    "fixed-fe": ("packet_fixed_byte", "fixed-fe"),
    "fixed-ff": ("packet_fixed_byte", "fixed-ff"),
    "half-zero": ("packet_half", "half-zero"),
    "half-ones": ("packet_half", "half-ones"),
    "word-ones": ("packet_word", "word-ones"),
    "word-lowhalf": ("packet_word", "word-lowhalf"),
    "endian-drop": ("scalar_endian", "endian-drop"),
    "endian-flip-be0": ("scalar_endian", "endian-flip-be0"),
    "endian-flip-be1": ("scalar_endian", "endian-flip-be1"),
    "endian-flip-be2": ("scalar_endian", "endian-flip-be2"),
    "endian-flip-be3": ("scalar_endian", "endian-flip-be3"),
    "endian-flip-le16": ("scalar_endian", "endian-flip-le16"),
    "endian-flip-le32": ("scalar_endian", "endian-flip-le32"),
    "endian-short27": ("scalar_endian", "endian-short27"),
    "endian-short10": ("scalar_endian", "endian-short10"),
    "edge14-drop": ("scalar_guard_edge", "edge14-drop"),
    "edge14-pass": ("scalar_guard_edge", "edge14-pass"),
    "edge60-drop": ("scalar_guard_edge", "edge60-drop"),
    "edge13-guard": ("scalar_guard_edge", "edge13-guard"),
    "edge1-guard": ("scalar_guard_edge", "edge1-guard"),
}

# Tags whose frames are too short for the shape's loads: the observed
# action must come from the guard path (the verifier would have
# rejected an unguarded program at load instead).
GUARD_TAGS = (
    "fixed-short",
    "var-60-guard",
    "var-10-guard",
    "half-short",
    "word-short",
    "sg-short",
    "cursor-short",
    "endian-short27",
    "endian-short10",
    "edge13-guard",
    "edge1-guard",
)


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


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_packet ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum {hash_files}
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/pkt-$tag.json"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" --output "$out" >/tmp/pkt-$tag.stdout 2>/tmp/pkt-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
echo "=== end guest_packet ==="
"""


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
    for path in (ADAPTER, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]:
        source = os.path.join(COMPILE_DIR, shape + ".mojo")
        if not os.path.isfile(source):
            raise EnvironmentFailure("missing fixture: %s" % source)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-packet-", dir="/tmp")
    staged = {"bpf_test_run.py": HARNESS}
    for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]:
        source = os.path.join(COMPILE_DIR, shape + ".mojo")
        staged[shape + ".bpf.o"] = build_object(source, stage, shape)
    packets = {}
    for key, (size, patches) in FRAMES.items():
        packets[key] = frame(size, patches)
    for key, data in packets.items():
        with open(os.path.join(stage, key + ".bin"), "wb") as handle:
            handle.write(data)
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag in sorted(CASES):
        shape, key = CASES[tag]
        commands.append(
            "run_case %s %s.bpf.o %d %s.bin"
            % (tag, shape, classify(shape, packets[key]), key)
        )
    for neg_shape, neg_tag, _log in NEGATIVES:
        commands.append(
            "run_case %s %s.bpf.o %d fixed-drop.bin"
            % (neg_tag, neg_shape, XDP_PASS)
        )
    hash_files = " ".join(
        ["bpf_test_run.py"]
        + [shape + ".bpf.o" for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]]
        + [key + ".bin" for key in sorted(packets)]
    )
    script = GUEST_SCRIPT.format(
        stage=stage, commands="\n".join(commands), hash_files=hash_files
    )
    script_path = os.path.join(stage, "guest_packet.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + [key + ".bin" for key in packets]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "guest_packet.sh"), 0o644)
    os.chmod(stage, 0o755)
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm",
        "--exec", "bash %s" % script_path],
        stage, VNG_TIMEOUT,
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
            raise guest_proc.GuestMissing(
                "guest case %s produced invalid JSON (stage %s):\n%s"
                % (tag, stage, body[-1000:])
            )
        record["_harness_exit"] = int(exit_code)
        results[tag] = record
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=list(results.values()),
        progress_banner="=== begin guest_packet ===",
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
    missing = [tag for tag in list(sorted(CASES)) + [neg[1] for neg in NEGATIVES]
               if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    return {
        "stage": stage,
        "output": output,
        "packets": packets,
        "results": results,
    }


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def check_case(tag, shape, key):
    """One case: harness exit 0 with the oracle-predicted action."""
    run = executed()
    record = run["results"][tag]
    guest_proc.check_harness_exit(
        tag, exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    predicted = classify(shape, run["packets"][key])
    assert record["actual_action"] == predicted, (
        "%s: predicted %d, observed %r" % (tag, predicted,
                                           record.get("actual_action"))
    )
    return predicted, record["actual_action"]


def test_frame_bytes():
    for key, (size, patches) in sorted(FRAMES.items()):
        data = frame(size, patches)
        assert len(data) == size, "%s: %d bytes" % (key, len(data))
        for offset, value in patches.items():
            assert data[offset] == value, "%s byte %d" % (key, offset)
        plain = bytearray(size)
        for offset, value in patches.items():
            plain[offset] = value
        assert data == bytes(plain), "%s: bytes outside patches" % key
    assert classify("packet_fixed_byte", frame(60, {14: 1})) == XDP_DROP
    assert classify("packet_fixed_byte", frame(60, {14: 0})) == XDP_PASS
    assert classify("packet_fixed_byte", frame(10, {})) == XDP_DROP
    assert classify("packet_var_offset", frame(64, {0: 1})) == XDP_DROP
    assert classify("packet_var_offset", frame(100, {36: 0})) == XDP_PASS
    assert classify("packet_var_offset", frame(60, {})) == XDP_DROP
    assert classify("packet_half", frame(60, {14: 0x12, 15: 0x34})) == XDP_DROP
    assert classify("packet_word", frame(10, {})) == XDP_DROP
    assert classify("packet_short_guard", frame(64, {63: 0x5A})) == XDP_PASS
    assert classify("packet_cursor", frame(60, {14: 1, 15: 0x34})) == XDP_DROP
    full = {14: 0x00, 15: 0x00, 16: 0xFF, 17: 0xFF, 18: 0x00, 19: 0xFF,
            20: 0x80, 21: 0x01, 22: 0x00, 23: 0xFF, 24: 0x01, 25: 0x00,
            26: 0x00, 27: 0x80}
    assert classify("scalar_endian", frame(28, full)) == XDP_DROP
    flipped = dict(full)
    flipped[27] = 0x00
    assert classify("scalar_endian", frame(28, flipped)) == XDP_PASS
    assert classify("scalar_endian", frame(27, {})) == XDP_DROP
    assert classify("scalar_guard_edge", frame(14, {13: 0xA5})) == XDP_DROP
    assert classify("scalar_guard_edge", frame(14, {})) == XDP_PASS
    assert classify("scalar_guard_edge", frame(13, {})) == XDP_DROP
    assert classify("scalar_guard_edge", frame(1, {})) == XDP_DROP
    assert classify("packet_fixed_byte", frame(60, {14: 0xFE})) == XDP_PASS
    assert classify("packet_fixed_byte", frame(60, {14: 0xFF})) == XDP_DROP
    assert classify("packet_half", frame(60, {14: 0xFF, 15: 0xFF})) == XDP_PASS
    assert classify("packet_word", frame(60, {14: 0x12, 15: 0x34})) == XDP_PASS


def test_fixed_byte_actions():
    for tag in ("fixed-drop", "fixed-pass", "fixed-short"):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_var_offset_actions():
    for tag in (
        "var-64-drop",
        "var-64-pass",
        "var-100-drop",
        "var-100-pass",
        "var-65-drop",
        "var-60-guard",
        "var-10-guard",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_half_actions():
    for tag in ("half-drop", "half-pass", "half-short"):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_word_actions():
    for tag in ("word-drop", "word-pass", "word-short"):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_short_guard_actions():
    for tag in ("sg-pass", "sg-content", "sg-short"):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_cursor_actions():
    for tag in (
        "cursor-drop",
        "cursor-pass-bit",
        "cursor-pass-mark",
        "cursor-short",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_scalar_endian_actions():
    for tag in (
        "endian-drop",
        "endian-flip-be0",
        "endian-flip-be1",
        "endian-flip-be2",
        "endian-flip-be3",
        "endian-flip-le16",
        "endian-flip-le32",
        "endian-short27",
        "endian-short10",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_scalar_guard_edge_actions():
    for tag in (
        "edge14-drop",
        "edge14-pass",
        "edge60-drop",
        "edge13-guard",
        "edge1-guard",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_boundary_frames():
    for tag in (
        "fixed-fe",
        "fixed-ff",
        "half-zero",
        "half-ones",
        "word-ones",
        "word-lowhalf",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_guard_paths():
    """Short frames prove the guard path: DROP with too few bytes."""
    run = executed()
    needs = {
        "packet_fixed_byte": 15,
        "packet_half": 16,
        "packet_word": 18,
        "packet_short_guard": 64,
        "packet_cursor": 16,
        "scalar_endian": 28,
        "scalar_guard_edge": 14,
    }
    for tag in GUARD_TAGS:
        shape, key = CASES[tag]
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record["actual_action"] == XDP_DROP, (
            "%s: guard path must fail closed to DROP, got %r"
            % (tag, record.get("actual_action"))
        )
        size = len(run["packets"][key])
        if shape == "packet_var_offset":
            off = size & 63
            assert off + 1 > size, (
                "%s: length %d holds its offset byte, not a guard case"
                % (tag, size)
            )
        else:
            assert size < needs[shape], (
                "%s: length %d covers need %d, not a guard case"
                % (tag, size, needs[shape])
            )


def test_negatives_rejected_by_verifier():
    """Negatives: first rejecting layer is the kernel verifier."""
    run = executed()
    hints = []
    for _shape, tag, log_line in NEGATIVES:
        record = run["results"][tag]
        hints.append(guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=4))
        assert record.get("stage") == "load", (
            "%s: expected load stage" % tag
        )
        assert record.get("classification") == "verifier", (
            "%s: expected verifier classification, got %r"
            % (tag, record.get("classification"))
        )
        blob = json.dumps(record.get("commands", []))
        assert log_line in blob, (
            "%s: kernel verifier log must contain %r" % (tag, log_line)
        )
    return guest_proc.combine_outcomes(*hints)


def test_guest_provenance():
    run = executed()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "pin absent (unloaded)" in run["output"], "pin must be removed"
    assert "PIN STILL PRESENT" not in run["output"], "pin must be removed"
    neg_tags = [neg[1] for neg in NEGATIVES]
    for tag in list(sorted(CASES)) + neg_tags:
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"),
            expect=4 if tag in neg_tags else 0)
        assert record.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
        if tag in [neg[1] for neg in NEGATIVES]:
            assert record.get("cleanup_ok") is None, (
                "%s: harness must leave cleanup_ok unset" % tag
            )
        else:
            assert record.get("cleanup_ok") is True, (
                "%s: harness must report cleanup_ok" % tag
            )
    names = (
        ["bpf_test_run.py"]
        + [shape + ".bpf.o" for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]]
        + [key + ".bin" for key in sorted(run["packets"])]
    )
    for name in names:
        expected = sha256_file(os.path.join(run["stage"], name))
        assert expected in run["output"], (
            "guest must re-verify staged hash of %s" % name
        )


# The verifier negatives are a denial: the case expects the
# wire-derived FAIL at VERIFY (both bad objects observably
# rejected at load) and passes only its own cell when the denial
# is observed with evidence. It guards the shape proofs: good
# objects must load and behave per the oracle (positive) while
# the bad ones must observably not load (denial), proving the
# load observation is not vacuous.
CASE_DENIALS = {
    "test_negatives_rejected_by_verifier": (
        "test_fixed_byte_actions", "VERIFY"
    ),
}


def _shape_source(shape):
    return os.path.join(COMPILE_DIR, shape + ".mojo")


def _shape_object(shape):
    return ("stage", shape + ".bpf.o")


def _neg_shapes():
    return [neg[0] for neg in NEGATIVES]


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Frames are generated from the in-file FRAMES table (pinned by
# test_frame_bytes through the suite source), so the durable
# sources are the shape programs; a class with any missing file
# digests to zeros and can never back a PASS.
CASE_INPUTS = {
    "test_frame_bytes": {
        "sources": [__file__],
        "objects": [],
        "corpus": [],
    },
    "test_fixed_byte_actions": {
        "sources": [_shape_source("packet_fixed_byte")],
        "objects": [_shape_object("packet_fixed_byte")],
        "corpus": [],
    },
    "test_var_offset_actions": {
        "sources": [_shape_source("packet_var_offset")],
        "objects": [_shape_object("packet_var_offset")],
        "corpus": [],
    },
    "test_half_actions": {
        "sources": [_shape_source("packet_half")],
        "objects": [_shape_object("packet_half")],
        "corpus": [],
    },
    "test_word_actions": {
        "sources": [_shape_source("packet_word")],
        "objects": [_shape_object("packet_word")],
        "corpus": [],
    },
    "test_short_guard_actions": {
        "sources": [_shape_source("packet_short_guard")],
        "objects": [_shape_object("packet_short_guard")],
        "corpus": [],
    },
    "test_cursor_actions": {
        "sources": [_shape_source("packet_cursor")],
        "objects": [_shape_object("packet_cursor")],
        "corpus": [],
    },
    "test_scalar_endian_actions": {
        "sources": [_shape_source("scalar_endian")],
        "objects": [_shape_object("scalar_endian")],
        "corpus": [],
    },
    "test_scalar_guard_edge_actions": {
        "sources": [_shape_source("scalar_guard_edge")],
        "objects": [_shape_object("scalar_guard_edge")],
        "corpus": [],
    },
    "test_boundary_frames": {
        "sources": [_shape_source(shape) for shape in (
            "packet_fixed_byte", "packet_half", "packet_word")],
        "objects": [_shape_object(shape) for shape in (
            "packet_fixed_byte", "packet_half", "packet_word")],
        "corpus": [],
    },
    "test_guard_paths": {
        "sources": [_shape_source(shape) for shape in SHAPES],
        "objects": [_shape_object(shape) for shape in SHAPES],
        "corpus": [],
    },
    "test_negatives_rejected_by_verifier": {
        "sources": [_shape_source(shape) for shape in _neg_shapes()],
        "objects": [_shape_object(shape) for shape in _neg_shapes()],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [_shape_source(shape)
                    for shape in list(SHAPES) + _neg_shapes()] + [HARNESS],
        "objects": [_shape_object(shape)
                    for shape in list(SHAPES) + _neg_shapes()],
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
        suite_id="kernel-packet", suite_path=__file__,
        case_ids=names, denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
    if not __debug__:
        return rec.finish_unrun(
            "must not run under python -O (asserts stripped)"
        )
    failures = 0
    unavailable_seen = False
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
    run = executed()
    print("per-shape predicted-vs-observed actions:")
    for tag in sorted(CASES):
        shape, key = CASES[tag]
        predicted = classify(shape, run["packets"][key])
        observed = run["results"][tag]["actual_action"]
        print("  %-16s shape=%-18s predicted=%d observed=%d"
              % (tag, shape, predicted, observed))
    print("packet sdk: guest behavior and guard-path checks passed")
    print("guest stage: %s (removed after the run)" % run["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())

