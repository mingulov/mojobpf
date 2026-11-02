# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the parse/checksum-SDK programs.

Builds every ``tests/compile/{parse,checksum}_*.mojo`` fixture through
the genuine pipeline (``mojo build --emit llvm`` with the packaged SDK
on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable Linux
guest and executes the kernel test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is)
against crafted frames. An independent reimplementation of each
shape's specified rule predicts every expectation; truncated frames
prove the guard paths by taking them.

Shapes and rules (XDP_DROP is 1, XDP_PASS is 2; every guard fails
closed to XDP_DROP; header fields are network order):

* parse_eth: drop when the frame holds at least 14 bytes and the
  bytes-12-13 field reads IPv4 (0x0800), else pass;
* parse_vlan: drop when the frame holds at least 18 bytes, the
  bytes-12-13 field is the 802.1Q tag protocol (0x8100), the inner
  EtherType at bytes 16-17 is IPv4, and the tag-control VLAN
  identifier is 7, else pass;
* parse_trunc: drop when the frame holds fewer than 14 bytes (first
  guard); untagged frames of at least 14 bytes drop on outer IPv4,
  else pass; tagged frames below 18 bytes drop (second guard) while
  tagged frames of at least 18 bytes drop on inner IPv4, else pass;
* checksum_window: drop when the frame holds at least 24 bytes and
  the ones-complement checksum of the four network-order words at
  bytes 14-15, 16-17, 18-19, and 20-21 equals the expected
  network-order word at bytes 22-23, else pass.

The oracle below is mechanically distinct from the Mojo under test:
multi-byte fields decode with ``int.from_bytes`` (never the
little-endian assemble-plus-swap the SDK performs) and the checksum
fold runs as a carry loop rather than the SDK's two-stage fold, so a
shared endianness or folding misunderstanding cannot hide. The
checksum cases prove exact equality: dropping frames carry expected
words equal to the oracle digest across at least three distinct
digest values (including carry-fold and all-ones windows plus a
permuted window proving a genuine sum), while passing frames carry
wrong or off-by-one expected words.

Staged file hashes are re-verified inside the guest so the observed
actions are tied to the exact bytes built here.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng``
(virtme-ng) with a cached guest image on PATH (default release
v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools
fail loudly as environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_parse_checksum_sdk.py``)
or under any ``test_``-style runner. Standard library only. The guest
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
import tool_admission  # noqa: E402
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
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
    "parse_eth",
    "parse_vlan",
    "parse_trunc",
    "checksum_window",
)

ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_VLAN = 0x8100
VLAN_ID_MATCH = 7
CKSUM_WINDOW = (14, 16, 18, 20)
CKSUM_EXPECT_OFF = 22


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def frame(size, patches):
    """Zero frame of `size` bytes with {offset: value} applied."""
    buf = bytearray(size)
    for offset, value in patches.items():
        buf[offset] = value
    return bytes(buf)


def be16(data, off):
    """Network-order 16-bit field at `off` (independent primitive)."""
    return int.from_bytes(data[off : off + 2], "big")


def cksum_oracle(data):
    """Ones-complement checksum of the window words (independent fold)."""
    total = 0
    for off in CKSUM_WINDOW:
        total += int.from_bytes(data[off : off + 2], "big")
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def classify(shape, data):
    """Independent prediction of the specified rule for a shape."""
    if shape == "parse_eth":
        if len(data) < 14:
            return XDP_DROP
        if be16(data, 12) == ETH_TYPE_IPV4:
            return XDP_DROP
        return XDP_PASS
    if shape == "parse_vlan":
        if len(data) < 18:
            return XDP_DROP
        tagged = be16(data, 12) == ETH_TYPE_VLAN
        inner_ipv4 = be16(data, 16) == ETH_TYPE_IPV4
        vid = be16(data, 14) & 0x0FFF
        if tagged and inner_ipv4 and vid == VLAN_ID_MATCH:
            return XDP_DROP
        return XDP_PASS
    if shape == "parse_trunc":
        if len(data) < 14:
            return XDP_DROP
        outer = be16(data, 12)
        if outer == ETH_TYPE_VLAN:
            if len(data) < 18:
                return XDP_DROP
            if be16(data, 16) == ETH_TYPE_IPV4:
                return XDP_DROP
            return XDP_PASS
        if outer == ETH_TYPE_IPV4:
            return XDP_DROP
        return XDP_PASS
    if shape == "checksum_window":
        if len(data) < 24:
            return XDP_DROP
        if cksum_oracle(data) == be16(data, CKSUM_EXPECT_OFF):
            return XDP_DROP
        return XDP_PASS
    raise AssertionError("unknown shape: %s" % shape)


# frame key -> (size, {offset: value}).
FRAMES = {
    "eth-ipv4-drop": (60, {12: 0x08, 13: 0x00}),
    "eth-arp-pass": (60, {12: 0x08, 13: 0x06}),
    "eth-ipv6-pass": (60, {12: 0x86, 13: 0xDD}),
    "eth-short": (10, {}),
    "vlan-match-drop": (
        60,
        {12: 0x81, 13: 0x00, 14: 0x00, 15: 0x07, 16: 0x08, 17: 0x00},
    ),
    "vlan-inner-pass": (
        60,
        {12: 0x81, 13: 0x00, 14: 0x00, 15: 0x07, 16: 0x08, 17: 0x06},
    ),
    "vlan-vid-pass": (
        60,
        {12: 0x81, 13: 0x00, 14: 0x00, 15: 0x08, 16: 0x08, 17: 0x00},
    ),
    "vlan-untagged-pass": (60, {12: 0x08, 13: 0x00}),
    "vlan-short14": (14, {12: 0x81, 13: 0x00}),
    "vlan-short10": (10, {}),
    "trunc-untagged-ipv4-drop": (14, {12: 0x08, 13: 0x00}),
    "trunc-untagged-arp-pass": (14, {12: 0x08, 13: 0x06}),
    "trunc-tagged-short14": (14, {12: 0x81, 13: 0x00}),
    "trunc-tagged-short16": (16, {12: 0x81, 13: 0x00}),
    "trunc-tagged-ipv4-drop": (20, {12: 0x81, 13: 0x00, 16: 0x08, 17: 0x00}),
    "trunc-tagged-arp-pass": (20, {12: 0x81, 13: 0x00, 16: 0x08, 17: 0x06}),
    "trunc-short10": (10, {}),
    "cksum-basic-drop": (
        60,
        {
            14: 0x00, 15: 0x01, 16: 0x00, 17: 0x02,
            18: 0x00, 19: 0x03, 20: 0x00, 21: 0x04,
            22: 0xFF, 23: 0xF5,
        },
    ),
    "cksum-carry-drop": (
        60,
        {
            14: 0xFF, 15: 0xFF, 16: 0x00, 17: 0x01,
            18: 0x00, 19: 0x00, 20: 0x00, 21: 0x00,
            22: 0xFF, 23: 0xFE,
        },
    ),
    "cksum-perm-drop": (
        60,
        {
            14: 0x00, 15: 0x04, 16: 0x00, 17: 0x03,
            18: 0x00, 19: 0x02, 20: 0x00, 21: 0x01,
            22: 0xFF, 23: 0xF5,
        },
    ),
    "cksum-maxfold-drop": (
        60,
        {
            14: 0xFF, 15: 0xFF, 16: 0xFF, 17: 0xFF,
            18: 0xFF, 19: 0xFF, 20: 0xFF, 21: 0xFF,
            22: 0x00, 23: 0x00,
        },
    ),
    "cksum-offbyone-pass": (
        60,
        {
            14: 0x00, 15: 0x01, 16: 0x00, 17: 0x02,
            18: 0x00, 19: 0x03, 20: 0x00, 21: 0x04,
            22: 0xFF, 23: 0xF4,
        },
    ),
    "cksum-wronghi-pass": (
        60,
        {
            14: 0x00, 15: 0x01, 16: 0x00, 17: 0x02,
            18: 0x00, 19: 0x03, 20: 0x00, 21: 0x04,
            22: 0xFE, 23: 0xF5,
        },
    ),
    "cksum-compl-pass": (60, {}),
    "cksum-short": (20, {}),
}

# tag -> (shape, frame key). The tag doubles as the staged file stem.
CASES = {
    "eth-ipv4-drop": ("parse_eth", "eth-ipv4-drop"),
    "eth-arp-pass": ("parse_eth", "eth-arp-pass"),
    "eth-ipv6-pass": ("parse_eth", "eth-ipv6-pass"),
    "eth-short": ("parse_eth", "eth-short"),
    "vlan-match-drop": ("parse_vlan", "vlan-match-drop"),
    "vlan-inner-pass": ("parse_vlan", "vlan-inner-pass"),
    "vlan-vid-pass": ("parse_vlan", "vlan-vid-pass"),
    "vlan-untagged-pass": ("parse_vlan", "vlan-untagged-pass"),
    "vlan-short14": ("parse_vlan", "vlan-short14"),
    "vlan-short10": ("parse_vlan", "vlan-short10"),
    "trunc-untagged-ipv4-drop": ("parse_trunc", "trunc-untagged-ipv4-drop"),
    "trunc-untagged-arp-pass": ("parse_trunc", "trunc-untagged-arp-pass"),
    "trunc-tagged-short14": ("parse_trunc", "trunc-tagged-short14"),
    "trunc-tagged-short16": ("parse_trunc", "trunc-tagged-short16"),
    "trunc-tagged-ipv4-drop": ("parse_trunc", "trunc-tagged-ipv4-drop"),
    "trunc-tagged-arp-pass": ("parse_trunc", "trunc-tagged-arp-pass"),
    "trunc-short10": ("parse_trunc", "trunc-short10"),
    "cksum-basic-drop": ("checksum_window", "cksum-basic-drop"),
    "cksum-carry-drop": ("checksum_window", "cksum-carry-drop"),
    "cksum-perm-drop": ("checksum_window", "cksum-perm-drop"),
    "cksum-maxfold-drop": ("checksum_window", "cksum-maxfold-drop"),
    "cksum-offbyone-pass": ("checksum_window", "cksum-offbyone-pass"),
    "cksum-wronghi-pass": ("checksum_window", "cksum-wronghi-pass"),
    "cksum-compl-pass": ("checksum_window", "cksum-compl-pass"),
    "cksum-short": ("checksum_window", "cksum-short"),
}

# Tags whose frames are too short for the shape's loads: the observed
# action must come from the guard path (the verifier would have
# rejected an unguarded program at load instead). The two
# trunc-tagged-short tags specifically prove the second tier: at 14-17
# bytes they clear the first guard (untagged 14-byte frames proceed to
# content dispatch) yet cannot reach the bytes-16-17 loads.
GUARD_TAGS = (
    "eth-short",
    "vlan-short14",
    "vlan-short10",
    "trunc-short10",
    "trunc-tagged-short14",
    "trunc-tagged-short16",
    "cksum-short",
)

# Checksum tags whose expected word equals the oracle digest (kernel
# DROP proves the kernel digest matched the oracle digest exactly).
CKSUM_DROP_TAGS = (
    "cksum-basic-drop",
    "cksum-carry-drop",
    "cksum-perm-drop",
    "cksum-maxfold-drop",
)


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
{bpftool_prologue}
echo "=== begin guest_parse ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum {hash_files}
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/ps-$tag.json"
  pin="/sys/fs/bpf/mojobpf-ps-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-ps-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" >/tmp/ps-$tag.stdout 2>/tmp/ps-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-ps-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-ps-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_parse ==="
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
    for shape in SHAPES:
        source = os.path.join(COMPILE_DIR, shape + ".mojo")
        if not os.path.isfile(source):
            raise EnvironmentFailure("missing fixture: %s" % source)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-parse-", dir="/tmp")
    staged = {"bpf_test_run.py": HARNESS}
    for shape in SHAPES:
        source = os.path.join(COMPILE_DIR, shape + ".mojo")
        staged[shape + ".bpf.o"] = build_object(source, stage, shape)
    packets = {}
    for key, (size, patches) in FRAMES.items():
        packets[key] = frame(size, patches)
    for key, data in packets.items():
        with open(os.path.join(stage, key + ".bin"), "wb") as handle:
            handle.write(data)
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
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
    hash_files = " ".join(
        ["bpf_test_run.py"]
        + [shape + ".bpf.o" for shape in SHAPES]
        + [key + ".bin" for key in sorted(packets)]
        + ["guest_parse.sh"]
    )
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
        stage=stage, commands="\n".join(commands), hash_files=hash_files,
        bpftool_prologue=tool_admission.render_prologue(pins),
        harness_flags=tool_admission.render_harness_flags(
            pins, pin_path="$pin", owned_root="/sys/fs/bpf",
            ownership_token="mojobpf-ps-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_parse.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + [key + ".bin" for key in packets]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "guest_parse.sh"), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + tuple(key + ".bin" for key in packets)
        + ("guest_parse.sh",),
    )
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
        progress_banner="=== begin guest_parse ===",
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
    missing = [tag for tag in sorted(CASES) if tag not in results]
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
    assert be16(frame(60, {12: 0x08, 13: 0x00}), 12) == 0x0800
    assert be16(frame(60, {12: 0x81, 13: 0x00}), 12) == 0x8100
    assert cksum_oracle(frame(60, {15: 1, 17: 2, 19: 3, 21: 4})) == 0xFFF5
    assert cksum_oracle(frame(60, {})) == 0xFFFF
    assert classify("parse_eth", frame(60, {12: 0x08, 13: 0x00})) == XDP_DROP
    assert classify("parse_eth", frame(60, {12: 0x08, 13: 0x06})) == XDP_PASS
    assert classify("parse_eth", frame(10, {})) == XDP_DROP
    assert classify("parse_vlan", frame(60, {12: 0x81, 15: 7, 16: 8})) == (
        XDP_DROP
    )
    assert classify("parse_vlan", frame(60, {12: 0x08})) == XDP_PASS
    assert classify("parse_trunc", frame(14, {12: 0x08, 13: 0x06})) == XDP_PASS
    assert classify("parse_trunc", frame(14, {12: 0x81})) == XDP_DROP
    assert classify("parse_trunc", frame(20, {12: 0x81, 16: 8})) == XDP_DROP
    assert classify("checksum_window", frame(60, {})) == XDP_PASS
    assert classify("checksum_window", frame(20, {})) == XDP_DROP


def test_eth_actions():
    for tag in (
        "eth-ipv4-drop",
        "eth-arp-pass",
        "eth-ipv6-pass",
        "eth-short",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_vlan_actions():
    for tag in (
        "vlan-match-drop",
        "vlan-inner-pass",
        "vlan-vid-pass",
        "vlan-untagged-pass",
        "vlan-short14",
        "vlan-short10",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_trunc_actions():
    for tag in (
        "trunc-untagged-ipv4-drop",
        "trunc-untagged-arp-pass",
        "trunc-tagged-short14",
        "trunc-tagged-short16",
        "trunc-tagged-ipv4-drop",
        "trunc-tagged-arp-pass",
        "trunc-short10",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_checksum_actions():
    for tag in (
        "cksum-basic-drop",
        "cksum-carry-drop",
        "cksum-perm-drop",
        "cksum-maxfold-drop",
        "cksum-offbyone-pass",
        "cksum-wronghi-pass",
        "cksum-compl-pass",
        "cksum-short",
    ):
        shape, key = CASES[tag]
        check_case(tag, shape, key)


def test_checksum_exactness():
    """DROP frames prove kernel digest == oracle digest, 3+ values."""
    run = executed()
    digests = set()
    for tag in CKSUM_DROP_TAGS:
        shape, key = CASES[tag]
        data = run["packets"][key]
        assert len(data) >= 24, "%s: not a full-window case" % tag
        oracle = cksum_oracle(data)
        expected = be16(data, CKSUM_EXPECT_OFF)
        assert oracle == expected, (
            "%s: frame ill-formed (oracle %04x vs expected %04x)"
            % (tag, oracle, expected)
        )
        digests.add(oracle)
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record["actual_action"] == XDP_DROP, (
            "%s: kernel digest must equal the oracle digest "
            "(else the frame would pass), got action %r"
            % (tag, record.get("actual_action"))
        )
    assert len(digests) >= 3, (
        "checksum equality needs 3+ distinct digests, got %r" % digests
    )
    # Passing frames are well-formed counter-cases: the oracle digest
    # genuinely differs from the carried expected word, so a kernel
    # that always agreed (or never folded) would fail them.
    for tag in ("cksum-offbyone-pass", "cksum-wronghi-pass", "cksum-compl-pass"):
        _shape, key = CASES[tag]
        data = run["packets"][key]
        assert cksum_oracle(data) != be16(data, CKSUM_EXPECT_OFF), (
            "%s: passing frame must mismatch" % tag
        )
    basic = run["packets"]["cksum-basic-drop"]
    offbyone = run["packets"]["cksum-offbyone-pass"]
    assert be16(offbyone, CKSUM_EXPECT_OFF) == be16(basic, CKSUM_EXPECT_OFF) - 1, (
        "off-by-one frame must differ by exactly 1"
    )


def test_guard_paths():
    """Truncated frames prove the guard paths: DROP with too few bytes."""
    run = executed()
    needs = {
        "parse_eth": 14,
        "parse_vlan": 18,
        "checksum_window": 24,
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
        if shape == "parse_trunc":
            if tag == "trunc-short10":
                assert size < 14, (
                    "%s: length %d covers the first guard" % (tag, size)
                )
            else:
                data = run["packets"][key]
                assert be16(data, 12) == ETH_TYPE_VLAN, (
                    "%s: second-tier proof needs a tagged frame" % tag
                )
                assert 14 <= size < 18, (
                    "%s: length %d is not a second-tier case" % (tag, size)
                )
        else:
            assert size < needs[shape], (
                "%s: length %d covers need %d, not a guard case"
                % (tag, size, needs[shape])
            )
    # The second tier is conditional: untagged 14-byte frames proceed
    # past the first guard to content dispatch instead of dropping.
    assert run["results"]["trunc-untagged-arp-pass"]["actual_action"] == (
        XDP_PASS
    ), "untagged 14-byte frame must pass the first guard"


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
    for tag in sorted(CASES):
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
        assert record.get("cleanup_ok") is True, (
            "%s: harness must report cleanup_ok" % tag
        )
    names = (
        ["bpf_test_run.py"]
        + [shape + ".bpf.o" for shape in SHAPES]
        + [key + ".bin" for key in sorted(run["packets"])]
        + ["guest_parse.sh"]
    )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in names:
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


# No denials: every case expects harness success (exit 0)
# with the oracle-predicted action; there are no
# expected-failure wire cases in this suite.
CASE_DENIALS = {}


def _shape_source(shape):
    return os.path.join(COMPILE_DIR, shape + ".mojo")


def _shape_object(shape):
    return ("stage", shape + ".bpf.o")


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Frames are generated from the in-file FRAMES table (pinned by
# test_frame_bytes through the suite source), so the durable
# sources are the shape programs; a class with any missing file
# digests to zeros and can never back a PASS.
CASE_INPUTS = {
    "test_frame_bytes": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
    "test_eth_actions": {
        "sources": [_shape_source("parse_eth")],
        "objects": [_shape_object("parse_eth")],
        "corpus": [],
    },
    "test_vlan_actions": {
        "sources": [_shape_source("parse_vlan")],
        "objects": [_shape_object("parse_vlan")],
        "corpus": [],
    },
    "test_trunc_actions": {
        "sources": [_shape_source("parse_trunc")],
        "objects": [_shape_object("parse_trunc")],
        "corpus": [],
    },
    "test_checksum_actions": {
        "sources": [_shape_source("checksum_window")],
        "objects": [_shape_object("checksum_window")],
        "corpus": [],
    },
    "test_checksum_exactness": {
        "sources": [_shape_source("checksum_window")],
        "objects": [_shape_object("checksum_window")],
        "corpus": [],
    },
    "test_guard_paths": {
        "sources": [_shape_source(shape) for shape in SHAPES],
        "objects": [_shape_object(shape) for shape in SHAPES],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [_shape_source(shape) for shape in SHAPES] + [HARNESS]
        + [("stage", "guest_parse.sh")],
        "objects": [_shape_object(shape) for shape in SHAPES],
        "corpus": [("stage", key + ".bin") for key in sorted(FRAMES)],
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
        suite_id="kernel-parse", suite_path=__file__,
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
    run = executed()
    print("per-shape predicted-vs-observed actions:")
    for tag in sorted(CASES):
        shape, key = CASES[tag]
        predicted = classify(shape, run["packets"][key])
        observed = run["results"][tag]["actual_action"]
        print("  %-24s shape=%-15s predicted=%d observed=%d"
              % (tag, shape, predicted, observed))
    print("checksum digests (oracle, exact match required):")
    for tag in CKSUM_DROP_TAGS:
        _shape, key = CASES[tag]
        print("  %-24s digest=%04x"
              % (tag, cksum_oracle(run["packets"][key])))
    print("parse/checksum sdk: guest behavior and guard-path checks passed")
    print("guest stage: %s (removed after the run)" % run["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
