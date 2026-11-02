# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel accounting proof for the packet demos.

Builds the packet-classifier, invocation-counter, and combined
packet-counter demos plus the independent C reference through
their genuine pipelines (Mojo: ``mojo build --emit llvm`` with the
packaged SDK on the import path -> ``compiler/mojo_ir_adapter.py``
-> ``llc -mtriple=bpfel -mcpu=v3``; C: pinned ``clang
--target=bpf -O2 -g``), then boots one disposable Linux guest and
runs the full 68-frame corpus (33 fixed frames, 32 seeded frames, 3
minimized regressions) with repeat 1:

* the classifier must return the oracle action on every frame
  (33-frame subset pinned to 16 drops / 17 passes / 9,590 bytes);
* the counter, initialized to 1000 from userspace, must read back
  exactly 1000+i+1 after frame i and return PASS on every frame;
  its known divergence (constant PASS where the oracle drops) is
  pinned to occur exactly on the oracle-drop frames, never
  elsewhere;
* the combined packet counter, initialized to (1000, 2000), must
  return the oracle action and read back exactly (1000+i+1,
  2000+cumbytes) after frame i: the packet workload whole in one
  Mojo program;
* the C reference, initialized to (1000, 2000), must return the
  oracle action and read back exactly (1000+i+1, 2000+cumbytes)
  after frame i, proving the same apparatus on an independently
  written combined workload.

The same boot proves mutation sensitivity behaviorally (the
action-flipped classifier and counter mutants fail their base
expectations with precisely the flipped values; the plus-two slot
mutant observes 1002 where 1001 is expected; the combined bit
mutant flips actions exactly and the combined byte-sum mutant
observes 2001 where 2015 is expected on the 15-byte frame),
sidecar-less loading (each final Mojo object loads, runs, and
unloads from a directory containing only itself through direct
unmodified ``bpftool``, with no repo helper in the load path), and
loader detection of the relocation mutant (the object with one map
relocation removed fails to load while the intact object loads and
runs). Staged file hashes are re-verified inside the guest so every
observation is tied to the exact bytes built here.

Requires a working Mojo compiler, LLVM ``llc``, Clang, ``bpftool``,
and ``vng`` (virtme-ng) with a cached guest image on PATH
(default release v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane).
Missing tools fail loudly as environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_xdp_accounting.py``)
or under any ``test_``-style runner. Standard library only. The
guest boot plus the corpus runs take several minutes under software
emulation; all cases share a single boot.
"""

import hashlib
import json
import os
import re
import shutil
import struct
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
CLASSIFIER_DIR = os.path.join(REPO_ROOT, "examples", "packet_classifier")
COUNTER_DIR = os.path.join(REPO_ROOT, "examples", "xdp_counter")
COMBINED_DIR = os.path.join(REPO_ROOT, "examples", "packet_counter")
CORPUS_DIR = os.path.join(CLASSIFIER_DIR, "corpus")
SPEC_MANIFEST = os.path.join(CORPUS_DIR, "manifest.json")
CLASSIFIER_SOURCE = os.path.join(CLASSIFIER_DIR, "classifier.mojo")
CLASSIFIER_MUTATED = os.path.join(CLASSIFIER_DIR, "classifier_mutated.mojo")
COUNTER_SOURCE = os.path.join(COUNTER_DIR, "counter.mojo")
COUNTER_MUTATED = os.path.join(COUNTER_DIR, "counter_mutated.mojo")
COUNTER_SLOT_MUTATED = os.path.join(COUNTER_DIR, "counter_slot_mutated.mojo")
COMBINED_SOURCE = os.path.join(COMBINED_DIR, "packet_counter.mojo")
COMBINED_BIT_MUTATED = os.path.join(
    COMBINED_DIR, "packet_counter_bit_mutated.mojo"
)
COMBINED_SUM_MUTATED = os.path.join(
    COMBINED_DIR, "packet_counter_bytesum_mutated.mojo"
)
C_SOURCE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "xdp_counter_ref.bpf.c"
)
SEEDED_MANIFEST = os.path.join(
    REPO_ROOT, "tests", "differential", "seeded_manifest.json"
)
REGRESSION_DIR = os.path.join(
    REPO_ROOT, "tests", "differential", "packets_regressions"
)
REGRESSION_MANIFEST = os.path.join(REGRESSION_DIR, "manifest.json")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_DROP = 1
XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 1500

SEED = 20261007
LCG_A = 1103515245
LCG_C = 12345
LCG_M = 0x80000000
N_SEEDED = 32
SEEDED_FIXED_LENGTHS = (14, 15, 16)
SEEDED_MIN_LENGTH = 17
SEEDED_MAX_LENGTH = 1500

HEADER = bytes(
    [0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02, 0x08, 0x00]
)

MOJO_MAP_NAME = "mojobpf_map0"
C_MAP_NAME = "counter_maps"
COUNTER_INIT = 1000
C_INIT0 = 1000
C_INIT1 = 2000
COMBINED_INIT0 = 1000
COMBINED_INIT1 = 2000


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def lcg_next(state):
    return (LCG_A * state + LCG_C) % LCG_M


def generate_seeded():
    """Regenerate the 32 seeded (name, bytes) frames (pinned hashes)."""
    frames = []
    state = SEED

    def take_byte():
        nonlocal_state = lcg_next(state)
        return nonlocal_state, (nonlocal_state >> 16) & 0xFF

    for index in range(N_SEEDED):
        if index < len(SEEDED_FIXED_LENGTHS):
            length = SEEDED_FIXED_LENGTHS[index]
        else:
            state = lcg_next(state)
            length = SEEDED_MIN_LENGTH + (
                state % (SEEDED_MAX_LENGTH - SEEDED_MIN_LENGTH + 1)
            )
        frame = bytearray(length)
        frame[:14] = HEADER
        if length >= 15:
            state, byte14 = take_byte()
            frame[14] = byte14
            for pos in range(15, length):
                state, fill = take_byte()
                frame[pos] = fill
        frames.append(("s%02d_%04d.bin" % (index, length), bytes(frame)))
    return frames


def classify(frame):
    """Independent prediction of the classifier rule."""
    if len(frame) >= 15 and (frame[14] % 2) == 1:
        return XDP_DROP
    return XDP_PASS


def classify_mutated(frame):
    """Independent prediction of the inverted-bit mutation."""
    if len(frame) >= 15 and (frame[14] % 2) == 0:
        return XDP_DROP
    return XDP_PASS


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with guest_proc.open_consumed(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hexargs(value):
    """Eight bare-decimal byte arguments (bpftool map-update order).

    The loader parses unprefixed value bytes as decimal (a ``41``
    initializes 41, as the round-trip suite proves), so non-numeric
    spellings fail; emit each little-endian byte in decimal.
    """
    return " ".join(
        str(byte) for byte in value.to_bytes(8, byteorder="little")
    )


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def load_corpus():
    """Load and verify all 68 frames; return [(name, bytes)] in order."""
    with guest_proc.open_consumed(SPEC_MANIFEST, "r", encoding="utf-8") as handle:
        spec = json.load(handle)
    assert spec["totals"] == {
        "invocations": 33, "drops": 16, "passes": 17, "bytes": 9590,
    }
    frames = []
    for entry in spec["frames"]:
        with guest_proc.open_consumed(os.path.join(CORPUS_DIR, entry["file"]), "rb") as handle:
            raw = handle.read()
        assert sha256_bytes(raw) == entry["sha256"], entry["file"]
        assert classify(raw) == entry["action"], entry["file"]
        frames.append((entry["file"], raw))
    assert len(frames) == 33
    with guest_proc.open_consumed(SEEDED_MANIFEST, "r", encoding="utf-8") as handle:
        seeded_manifest = json.load(handle)
    assert seeded_manifest["seed"] == SEED
    pinned = {entry["name"]: entry for entry in seeded_manifest["frames"]}
    for name, raw in generate_seeded():
        assert name in pinned, name
        assert sha256_bytes(raw) == pinned[name]["sha256"], name
        assert classify(raw) == pinned[name]["action"], name
        frames.append((name, raw))
    assert len(frames) == 33 + N_SEEDED
    with guest_proc.open_consumed(REGRESSION_MANIFEST, "r", encoding="utf-8") as handle:
        regressions = json.load(handle)
    for entry in regressions["frames"]:
        with guest_proc.open_consumed(os.path.join(REGRESSION_DIR, entry["file"]), "rb") as handle:
            raw = handle.read()
        assert sha256_bytes(raw) == entry["sha256"], entry["file"]
        assert classify(raw) == entry["action"], entry["file"]
        frames.append((entry["file"], raw))
    assert len(frames) == 33 + N_SEEDED + len(regressions["frames"])
    return frames


def stage_verified_frames(stage, frames):
    """Stage validated frame buffers; never reopen originals.

    ``frames`` are the ``(name, raw)`` pairs ``load_corpus``
    verified against the manifest hashes. Staging writes
    exactly those buffers: a payload substituted into an
    original after validation cannot reach the guest,
    because the originals are never read again.
    """
    staged = {}
    for name, raw in frames:
        path = os.path.join(stage, name)
        with open(path, "wb") as handle:
            handle.write(raw)
        staged[name] = path
    return staged


@guest_proc.consumes_source
def build_mojo(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS,
         "-I", SDK_INCLUDE, "-o", raw_path, source]
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
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


def build_c(workdir):
    object_path = os.path.join(workdir, "c_ref.bpf.o")
    proc = guest_proc.compile_consumed(run_step,
        ["clang", "--target=bpf", "-O2", "-g", "-c",
         C_SOURCE, "-o", object_path], source=C_SOURCE,
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


def corrupt_relocation(image):
    """Remove the first .relxdp entry; return (mutant, span)."""
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, _fl, _ad, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        sections.append((sh_name, sh_type, sh_offset, sh_size))
    strtab = sections[e_shstrndx]
    blob = image[strtab[2]:strtab[2] + strtab[3]]
    relxdp = None
    for (sh_name, sh_type, sh_offset, sh_size) in sections:
        end = blob.index(b"\x00", sh_name)
        if blob[sh_name:end] == b".relxdp":
            relxdp = (sh_offset, sh_size)
    assert relxdp is not None and relxdp[1] == 32
    mutant = bytearray(image)
    mutant[relxdp[0]:relxdp[0] + 16] = b"\x00" * 16
    return bytes(mutant), (relxdp[0], relxdp[0] + 16)


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
{bpftool_prologue}
echo "=== begin guest_acct ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum {staged_list}
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/xdp-$tag.json"
  pin="/sys/fs/bpf/mojobpf-acct-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-acct-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-acct-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
map_info() {{
  out="$1"; want="$2"
  python3 - "$out" "$want" >/tmp/xdp-mapinfo.stderr 2>&1 <<'PYEOF'
import json
import subprocess
import sys
fields, want = sys.argv[1], sys.argv[2]
info = {{"map_found": "0"}}
try:
    raw = subprocess.run(
        [{bpftool_argv0}, "-j", "map", "show"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for entry in json.loads(raw.stdout or "[]"):
        if entry.get("name") == want:
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
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_acct_* /sys/fs/bpf/mojobpf_solo_* /sys/fs/bpf/mojobpf_m2 /sys/fs/bpf/mojobpf-acct-* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_acct ==="
"""

CUMULATIVE_CASE = """echo "=== BEGIN {tag} ==="
pin="/sys/fs/bpf/mojobpf_acct_{tag}"
out="/tmp/xdp-{tag}.fields"
: > "$out"
"$BPFTOOL" prog load {obj} "$pin" type xdp >/tmp/xdp-{tag}.load 2>&1
echo "load_exit=$?" >> "$out"
map_info "$out" "{map_name}"
map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
{init_commands}
echo "init_exit=$?" >> "$out"
idx=0
for f in {frame_list}; do
  echo "--- {tag} run $idx $f ---"
  "$BPFTOOL" prog run pinned "$pin" data_in "$f" repeat 1 2>&1 | grep -i "return value"
  echo "run_exit=${{PIPESTATUS[0]}}"
  echo "--- {tag} dump $idx $f ---"
  "$BPFTOOL" map dump id "$map_id" 2>&1
  echo "dump_exit=$?"
  idx=$((idx + 1))
done
cat "$out"
rm -f "$pin"
if [ -e "$pin" ]; then echo "unload_ok=0"; else echo "unload_ok=1"; fi
echo "=== END {tag} ==="
"""

SOLO_CASE = """echo "=== BEGIN {tag} ==="
dir="/tmp/solo_{tag}"
rm -rf "$dir"; mkdir -p "$dir"; cp "{obj}" "$dir/"
echo "--- {tag} ls ---"
ls -A "$dir"
pin="/sys/fs/bpf/mojobpf_solo_{tag}"
"$BPFTOOL" prog load "$dir/{obj}" "$pin" type xdp >/tmp/xdp-{tag}.load 2>&1
echo "load_exit=$?"
{extra_commands}
rm -f "$pin"
if [ -e "$pin" ]; then echo "unload_ok=0"; else echo "unload_ok=1"; fi
echo "=== END {tag} ==="
"""

SLOT_CASE = """echo "=== BEGIN slot ==="
pin="/sys/fs/bpf/mojobpf_acct_slot"
"$BPFTOOL" prog load counter_slot.bpf.o "$pin" type xdp >/tmp/xdp-slot.load 2>&1
echo "load_exit=$?"
map_info /tmp/xdp-slot.fields "{map_name}"
map_id=$(grep '^map_id=' /tmp/xdp-slot.fields | cut -d= -f2)
"$BPFTOOL" map update id "$map_id" key 0 0 0 0 value {init} >/tmp/xdp-slot.init 2>&1
echo "init_exit=$?"
"$BPFTOOL" prog run pinned "$pin" data_in {frame} repeat 1 2>&1 | grep -i "return value"
echo "run_exit=${{PIPESTATUS[0]}}"
"$BPFTOOL" map dump id "$map_id" 2>&1
cat /tmp/xdp-slot.fields
rm -f "$pin"
if [ -e "$pin" ]; then echo "unload_ok=0"; else echo "unload_ok=1"; fi
echo "=== END slot ==="
"""

SUM_CASE = """echo "=== BEGIN cmb_sum ==="
pin="/sys/fs/bpf/mojobpf_acct_cmb_sum"
"$BPFTOOL" prog load combined_sum.bpf.o "$pin" type xdp >/tmp/xdp-cmb_sum.load 2>&1
echo "load_exit=$?"
map_info /tmp/xdp-cmb_sum.fields "{map_name}"
map_id=$(grep '^map_id=' /tmp/xdp-cmb_sum.fields | cut -d= -f2)
"$BPFTOOL" map update id "$map_id" key 0 0 0 0 value {init0} >/tmp/xdp-cmb_sum.init0 2>&1 && "$BPFTOOL" map update id "$map_id" key 1 0 0 0 value {init1} >/tmp/xdp-cmb_sum.init1 2>&1
echo "init_exit=$?"
"$BPFTOOL" prog run pinned "$pin" data_in {frame} repeat 1 2>&1 | grep -i "return value"
echo "run_exit=${{PIPESTATUS[0]}}"
"$BPFTOOL" map dump id "$map_id" 2>&1
cat /tmp/xdp-cmb_sum.fields
rm -f "$pin"
if [ -e "$pin" ]; then echo "unload_ok=0"; else echo "unload_ok=1"; fi
echo "=== END cmb_sum ==="
"""

M2_CASE = """echo "=== BEGIN m2load ==="
pin="/sys/fs/bpf/mojobpf_m2"
"$BPFTOOL" prog load corrupt.bpf.o "$pin" type xdp >/tmp/xdp-m2.load 2>&1
echo "load_exit=$?"
echo "--- m2load log ---"
cat /tmp/xdp-m2.load
if [ -e "$pin" ]; then echo "pin_exists=1"; rm -f "$pin"; else echo "pin_exists=0"; fi
echo "=== END m2load ==="
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
    """Build everything, boot one guest, return parsed results."""
    for tool in ("mojo", "llc", "clang", "bpftool", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        CLASSIFIER_SOURCE, CLASSIFIER_MUTATED, COUNTER_SOURCE,
        COUNTER_MUTATED, COUNTER_SLOT_MUTATED, COMBINED_SOURCE,
        COMBINED_BIT_MUTATED, COMBINED_SUM_MUTATED, C_SOURCE, ADAPTER,
        HARNESS, SPEC_MANIFEST, SEEDED_MANIFEST, REGRESSION_MANIFEST,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK dir: %s" % SDK_INCLUDE)
    frames = load_corpus()
    by_name = dict(frames)
    stage = guest_proc.owned_stage(prefix="mojo-acct-", dir="/tmp")
    classifier_obj = build_mojo(CLASSIFIER_SOURCE, stage, "classifier")
    classifier_mut = build_mojo(CLASSIFIER_MUTATED, stage, "classifier_mut")
    counter_obj = build_mojo(COUNTER_SOURCE, stage, "counter")
    counter_mut = build_mojo(COUNTER_MUTATED, stage, "counter_mut")
    counter_slot = build_mojo(COUNTER_SLOT_MUTATED, stage, "counter_slot")
    combined_obj = build_mojo(COMBINED_SOURCE, stage, "combined")
    combined_bit = build_mojo(COMBINED_BIT_MUTATED, stage, "combined_bit")
    combined_sum = build_mojo(COMBINED_SUM_MUTATED, stage, "combined_sum")
    c_obj = build_c(stage)
    with guest_proc.open_consumed(counter_obj, "rb") as handle:
        corrupt_image, _span = corrupt_relocation(handle.read())
    corrupt_obj = os.path.join(stage, "corrupt.bpf.o")
    with open(corrupt_obj, "wb") as handle:
        handle.write(corrupt_image)
    staged = {
        "bpf_test_run.py": HARNESS,
        "classifier.bpf.o": classifier_obj,
        "classifier_mut.bpf.o": classifier_mut,
        "counter.bpf.o": counter_obj,
        "counter_mut.bpf.o": counter_mut,
        "counter_slot.bpf.o": counter_slot,
        "combined.bpf.o": combined_obj,
        "combined_bit.bpf.o": combined_bit,
        "combined_sum.bpf.o": combined_sum,
        "c_ref.bpf.o": c_obj,
        "corrupt.bpf.o": corrupt_obj,
    }
    staged.update(stage_verified_frames(stage, frames))
    for name, src in staged.items():
        if os.path.join(stage, name) == src:
            continue
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers. Under a recorder a
    # missing digest is refused before launch (never substituted
    # with a fresh filesystem hash); without one the standalone
    # fallback hashes the staged files directly.
    rec = guest_proc.active_recorder()
    handed = guest_proc.stage_consumed_for_guest(
        rec, stage, tuple(staged),
    )
    if rec is None:
        host_hashes = {
            name: sha256_file(os.path.join(stage, name))
            for name in staged
        }
    else:
        host_hashes = guest_proc.require_handed_digests(
            handed, tuple(staged)
        )
    frame_list = " ".join(name for name, _ in frames)
    commands = []
    for index, (name, raw) in enumerate(frames):
        commands.append(
            "run_case clf_%02d classifier.bpf.o %d %s"
            % (index, classify(raw), name)
        )
    commands.append(CUMULATIVE_CASE.format(
        tag="counter", obj="counter.bpf.o", map_name=MOJO_MAP_NAME,
        init_commands=(
            '"$BPFTOOL" map update id "$map_id" key 0 0 0 0 value %s '
            ">/tmp/xdp-counter.init 2>&1" % hexargs(COUNTER_INIT)
        ),
        frame_list=frame_list,
    ))
    commands.append(CUMULATIVE_CASE.format(
        tag="cref", obj="c_ref.bpf.o", map_name=C_MAP_NAME,
        init_commands=(
            '"$BPFTOOL" map update id "$map_id" key 0 0 0 0 value %s '
            ">/tmp/xdp-cref.init0 2>&1 && "
            '"$BPFTOOL" map update id "$map_id" key 1 0 0 0 value %s '
            ">/tmp/xdp-cref.init1 2>&1"
            % (hexargs(C_INIT0), hexargs(C_INIT1))
        ),
        frame_list=frame_list,
    ))
    commands.append(CUMULATIVE_CASE.format(
        tag="combined", obj="combined.bpf.o", map_name=MOJO_MAP_NAME,
        init_commands=(
            '"$BPFTOOL" map update id "$map_id" key 0 0 0 0 value %s '
            ">/tmp/xdp-combined.init0 2>&1 && "
            '"$BPFTOOL" map update id "$map_id" key 1 0 0 0 value %s '
            ">/tmp/xdp-combined.init1 2>&1"
            % (hexargs(COMBINED_INIT0), hexargs(COMBINED_INIT1))
        ),
        frame_list=frame_list,
    ))
    drop_frame = "f0015_01.bin"
    pass_frame = "f0015_00.bin"
    assert classify(by_name[drop_frame]) == XDP_DROP
    assert classify(by_name[pass_frame]) == XDP_PASS
    commands.append(
        "run_case stale_clf_drop classifier_mut.bpf.o %d %s"
        % (classify(by_name[drop_frame]), drop_frame)
    )
    commands.append(
        "run_case stale_clf_pass classifier_mut.bpf.o %d %s"
        % (classify(by_name[pass_frame]), pass_frame)
    )
    commands.append(
        "run_case stale_cnt counter_mut.bpf.o %d %s" % (XDP_PASS, pass_frame)
    )
    commands.append(
        "run_case stale_cmb_bit combined_bit.bpf.o %d %s"
        % (classify(by_name[drop_frame]), drop_frame)
    )
    commands.append(
        "run_case stale_cmb_pass combined_bit.bpf.o %d %s"
        % (classify(by_name[pass_frame]), pass_frame)
    )
    commands.append(SLOT_CASE.format(
        map_name=MOJO_MAP_NAME, init=hexargs(COUNTER_INIT), frame=pass_frame,
    ))
    commands.append(SUM_CASE.format(
        map_name=MOJO_MAP_NAME, init0=hexargs(COMBINED_INIT0),
        init1=hexargs(COMBINED_INIT1), frame=pass_frame,
    ))
    commands.append(SOLO_CASE.format(
        tag="solo_clf", obj="classifier.bpf.o",
        extra_commands=(
            '"$BPFTOOL" prog run pinned "$pin" data_in %s repeat 1 2>&1 '
            '| grep -i "return value"' % drop_frame
        ),
    ))
    commands.append(SOLO_CASE.format(
        tag="solo_cnt", obj="counter.bpf.o",
        extra_commands="\n".join([
            'map_info /tmp/xdp-solo_cnt.fields "%s"' % MOJO_MAP_NAME,
            'map_id=$(grep \'^map_id=\' /tmp/xdp-solo_cnt.fields | cut -d= -f2)',
            '"$BPFTOOL" map update id "$map_id" key 0 0 0 0 value %s '
            ">/tmp/xdp-solo_cnt.init 2>&1" % hexargs(COUNTER_INIT),
            'echo "init_exit=$?"',
            '"$BPFTOOL" prog run pinned "$pin" data_in %s repeat 1 2>&1 '
            '| grep -i "return value"' % pass_frame,
            'echo "run_exit=${PIPESTATUS[0]}"',
            '"$BPFTOOL" map dump id "$map_id" 2>&1',
            'cat /tmp/xdp-solo_cnt.fields',
        ]),
    ))
    commands.append(SOLO_CASE.format(
        tag="solo_cmb", obj="combined.bpf.o",
        extra_commands="\n".join([
            'map_info /tmp/xdp-solo_cmb.fields "%s"' % MOJO_MAP_NAME,
            'map_id=$(grep \'^map_id=\' /tmp/xdp-solo_cmb.fields | cut -d= -f2)',
            '"$BPFTOOL" map update id "$map_id" key 0 0 0 0 value %s '
            ">/tmp/xdp-solo_cmb.init0 2>&1 && "
            '"$BPFTOOL" map update id "$map_id" key 1 0 0 0 value %s '
            ">/tmp/xdp-solo_cmb.init1 2>&1"
            % (hexargs(COMBINED_INIT0), hexargs(COMBINED_INIT1)),
            'echo "init_exit=$?"',
            '"$BPFTOOL" prog run pinned "$pin" data_in %s repeat 1 2>&1 '
            '| grep -i "return value"' % pass_frame,
            'echo "run_exit=${PIPESTATUS[0]}"',
            '"$BPFTOOL" map dump id "$map_id" 2>&1',
            'cat /tmp/xdp-solo_cmb.fields',
        ]),
    ))
    commands.append(M2_CASE)
    commands.append(
        "run_case m2revert counter.bpf.o %d %s" % (XDP_PASS, pass_frame)
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
        stage=stage,
        staged_list=" ".join(sorted(staged) + ["guest_acct.sh"]),
        commands="\n".join(commands),
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
        bpftool_argv0=json.dumps(pins["path"]),
        harness_flags=tool_admission.render_harness_flags(
            pins, pin_path="$pin", owned_root="/sys/fs/bpf",
            ownership_token="mojobpf-acct-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_acct.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    os.chmod(script_path, 0o644)
    # The generated script joins the handoff late (it cannot be
    # consumed before it exists); the watch extends to it and the
    # guest reports it alongside the staged inputs.
    script_handed = guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage, ("guest_acct.sh",),
    )
    if guest_proc.active_recorder() is None:
        host_hashes["guest_acct.sh"] = sha256_file(script_path)
    else:
        host_hashes.update(guest_proc.require_handed_digests(
            script_handed, ("guest_acct.sh",)
        ))
    os.chmod(stage, 0o755)
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm",
        "--exec", "bash %s" % script_path],
        stage, VNG_TIMEOUT,
    )
    run_cases = {}
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
        run_cases[tag] = record
    blocks = {}
    for match in re.finditer(
        r"=== BEGIN ([A-Za-z0-9_]+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, body = match.groups()
        blocks[tag] = body
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=list(run_cases.values()),
        progress_banner="=== begin guest_acct ===",
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
    wanted_run = ["clf_%02d" % index for index in range(len(frames))] + [
        "stale_clf_drop", "stale_clf_pass", "stale_cnt",
        "stale_cmb_bit", "stale_cmb_pass", "m2revert",
    ]
    missing_run = [tag for tag in wanted_run if tag not in run_cases]
    if missing_run:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing_run), stage, output[-4000:])
        )
    wanted_blocks = (
        "counter", "cref", "combined", "slot", "cmb_sum",
        "solo_clf", "solo_cnt", "solo_cmb", "m2load",
    )
    missing_blocks = [tag for tag in wanted_blocks if tag not in blocks]
    if missing_blocks:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing_blocks), stage, output[-4000:])
        )
    transcript = os.path.join(stage, "guest_transcript.txt")
    with open(transcript, "w", encoding="utf-8") as handle:
        handle.write(output)
    print("guest stage: %s" % stage)
    print("guest transcript: %s (%d bytes)" % (transcript, len(output)))
    sys.stdout.flush()
    return {
        "stage": stage,
        "output": output,
        "frames": frames,
        "host_hashes": host_hashes,
        "run_cases": run_cases,
        "blocks": blocks,
    }


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


def parse_cumulative(body, tag, count):
    """Parse per-frame (action, {key: value}) rows from a dump transcript."""
    runs = []
    dumps = []
    current = None
    for line in body.splitlines():
        run_mark = re.match(
            r"--- %s run (\d+) (\S+) ---$" % re.escape(tag), line
        )
        if run_mark:
            current = {"index": int(run_mark.group(1)),
                       "frame": run_mark.group(2), "action": None,
                       "run_exit": None}
            runs.append(current)
            continue
        dump_mark = re.match(
            r"--- %s dump (\d+) (\S+) ---$" % re.escape(tag), line
        )
        if dump_mark:
            current = {"index": int(dump_mark.group(1)),
                       "frame": dump_mark.group(2), "entries": {}}
            dumps.append(current)
            continue
        ret = re.search(r"[Rr]eturn value:\s*(\d+)", line)
        if ret and current is not None and "action" in current:
            current["action"] = int(ret.group(1))
            continue
        if line.startswith("run_exit=") and current is not None:
            current["run_exit"] = line.split("=", 1)[1]
            continue
        pair = re.match(
            r"key:\s*((?:[0-9a-fA-F]{2} ?)+)\s+"
            r"value:\s*((?:[0-9a-fA-F]{2} ?)+)\s*$",
            line,
        )
        if pair and current is not None and "entries" in current:
            key = int.from_bytes(
                bytes(int(tok, 16) for tok in pair.group(1).split()),
                byteorder="little",
            )
            value = int.from_bytes(
                bytes(int(tok, 16) for tok in pair.group(2).split()),
                byteorder="little",
            )
            current["entries"][key] = value
            continue
        # BTF-described maps dump as JSON with decoded integers.
        jkey = re.match(r'^\s*"key":\s*(\d+),?\s*$', line)
        if jkey and current is not None and "entries" in current:
            current["_pending"] = int(jkey.group(1))
            continue
        jvalue = re.match(r'^\s*"value":\s*(\d+)\s*$', line)
        if jvalue and current is not None and "_pending" in current:
            current["entries"][current.pop("_pending")] = int(jvalue.group(1))
    assert len(runs) == count, "%s: %d runs, want %d" % (tag, len(runs), count)
    assert len(dumps) == count, "%s: %d dumps, want %d" % (tag, len(dumps), count)
    return runs, dumps


def check_map_identity(tag, body, entries):
    fields = parse_fields(body)
    for key in ("load_exit", "mapinfo_exit", "init_exit"):
        assert fields.get(key) == "0", "%s: %s=%r" % (tag, key, fields.get(key))
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "array", "%s: not an array map" % tag
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", "%s: value size is not u64" % tag
    assert fields.get("map_entries") == entries, (
        "%s: entries %r, want %s" % (tag, fields.get("map_entries"), entries)
    )


def dump_values(body):
    """Parse {key: value} from one map dump (text or JSON form)."""
    values = {}
    pending = None
    for line in body.splitlines():
        pair = re.match(
            r"key:\s*((?:[0-9a-fA-F]{2} ?)+)\s+"
            r"value:\s*((?:[0-9a-fA-F]{2} ?)+)\s*$",
            line,
        )
        if pair:
            key = int.from_bytes(
                bytes(int(tok, 16) for tok in pair.group(1).split()),
                byteorder="little",
            )
            values[key] = int.from_bytes(
                bytes(int(tok, 16) for tok in pair.group(2).split()),
                byteorder="little",
            )
            continue
        jkey = re.match(r'^\s*"key":\s*(\d+),?\s*$', line)
        if jkey:
            pending = int(jkey.group(1))
            continue
        jvalue = re.match(r'^\s*"value":\s*(\d+)\s*$', line)
        if jvalue and pending is not None:
            values[pending] = int(jvalue.group(1))
            pending = None
    return values


def test_classifier_matches_oracle():
    run = executed()
    frames = run["frames"]
    matched = 0
    for index, (name, raw) in enumerate(frames):
        record = run["run_cases"].get("clf_%02d" % index)
        assert record is not None, "missing case for %s" % name
        guest_proc.check_harness_exit(
            "clf_%02d" % index, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record["actual_action"] == classify(raw), (
            "%s: observed %r, oracle %d"
            % (name, record["actual_action"], classify(raw))
        )
        matched += 1
    spec = frames[:33]
    drops = sum(1 for _, raw in spec if classify(raw) == 1)
    total = sum(len(raw) for _, raw in spec)
    assert (len(spec), drops, total) == (33, 16, 9590)
    print("PASS classifier: %d/%d actions match the oracle" % (matched, matched))


def test_counter_accumulates_exactly():
    run = executed()
    frames = run["frames"]
    body = run["blocks"].get("counter")
    assert body is not None, "missing counter block"
    check_map_identity("counter", body, "1")
    runs, dumps = parse_cumulative(body, "counter", len(frames))
    for position, ((name, raw), case, dump) in enumerate(
        zip(frames, runs, dumps)
    ):
        assert case["frame"] == name, (case["frame"], name)
        assert case["run_exit"] == "0", "%s: run_exit %r" % (name, case.get("run_exit"))
        assert case["action"] == XDP_PASS, "%s: action %r" % (name, case["action"])
        assert dump["frame"] == name
        assert dump["entries"] == {0: COUNTER_INIT + position + 1}, (
            "%s: map %r" % (name, dump["entries"])
        )
    assert "unload_ok=1" in body, "counter pin was not removed"
    print(
        "PASS counter: %d/%d per-frame values exact, final %d"
        % (len(frames), len(frames), COUNTER_INIT + len(frames))
    )


def test_counter_divergence_pinned_to_drops():
    run = executed()
    frames = run["frames"]
    body = run["blocks"].get("counter")
    runs, _ = parse_cumulative(body, "counter", len(frames))
    diverged = []
    for (name, raw), case in zip(frames, runs):
        assert case["action"] == XDP_PASS, name
        if case["action"] != classify(raw):
            diverged.append(name)
    expected = [name for name, raw in frames if classify(raw) == XDP_DROP]
    assert diverged == expected, (
        "divergence must occur exactly on oracle-drop frames"
    )
    assert diverged, "expected some oracle-drop frames"
    print(
        "PASS counter divergence pinned: %d drop frames, 0 elsewhere"
        % len(diverged)
    )


def test_c_reference_matches_oracle():
    run = executed()
    frames = run["frames"]
    body = run["blocks"].get("cref")
    assert body is not None, "missing cref block"
    check_map_identity("cref", body, "2")
    runs, dumps = parse_cumulative(body, "cref", len(frames))
    cumbytes = 0
    for position, ((name, raw), case, dump) in enumerate(
        zip(frames, runs, dumps)
    ):
        cumbytes += len(raw)
        assert case["frame"] == name, (case["frame"], name)
        assert case["run_exit"] == "0", "%s: run_exit %r" % (name, case.get("run_exit"))
        assert case["action"] == classify(raw), (
            "%s: C action %r, oracle %d"
            % (name, case["action"], classify(raw))
        )
        assert dump["frame"] == name
        assert dump["entries"] == {
            0: C_INIT0 + position + 1,
            1: C_INIT1 + cumbytes,
        }, "%s: C maps %r" % (name, dump["entries"])
    assert "unload_ok=1" in body, "C pin was not removed"
    print(
        "PASS C reference: %d/%d actions and both map entries exact"
        % (len(frames), len(frames))
    )


def test_combined_matches_oracle():
    run = executed()
    frames = run["frames"]
    body = run["blocks"].get("combined")
    assert body is not None, "missing combined block"
    check_map_identity("combined", body, "2")
    runs, dumps = parse_cumulative(body, "combined", len(frames))
    cumbytes = 0
    for position, ((name, raw), case, dump) in enumerate(
        zip(frames, runs, dumps)
    ):
        cumbytes += len(raw)
        assert case["frame"] == name, (case["frame"], name)
        assert case["run_exit"] == "0", "%s: run_exit %r" % (name, case.get("run_exit"))
        assert case["action"] == classify(raw), (
            "%s: combined action %r, oracle %d"
            % (name, case["action"], classify(raw))
        )
        assert dump["frame"] == name
        assert dump["entries"] == {
            0: COMBINED_INIT0 + position + 1,
            1: COMBINED_INIT1 + cumbytes,
        }, "%s: combined maps %r" % (name, dump["entries"])
    assert "unload_ok=1" in body, "combined pin was not removed"
    print(
        "PASS combined: %d/%d actions and both map entries exact"
        % (len(frames), len(frames))
    )


def check_stale(tag):
    """One stale record: harness exit 1 with the old observed action."""
    record = executed()["run_cases"].get(tag)
    assert record is not None
    return guest_proc.check_harness_exit(
        tag, exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=1)


def test_mutants_detected_in_guest():
    run = executed()
    cases = run["run_cases"]
    frames = dict(run["frames"])
    hints = []
    drop = cases.get("stale_clf_drop")
    assert drop is not None
    hints.append(check_stale("stale_clf_drop"))
    assert drop["actual_action"] == classify_mutated(frames["f0015_01.bin"])
    assert drop["actual_action"] != classify(frames["f0015_01.bin"])
    passed = cases.get("stale_clf_pass")
    assert passed is not None
    hints.append(check_stale("stale_clf_pass"))
    assert passed["actual_action"] == classify_mutated(frames["f0015_00.bin"])
    assert passed["actual_action"] != classify(frames["f0015_00.bin"])
    cnt = cases.get("stale_cnt")
    assert cnt is not None
    hints.append(check_stale("stale_cnt"))
    assert cnt["actual_action"] == XDP_DROP, cnt["actual_action"]
    cmb_drop = cases.get("stale_cmb_bit")
    assert cmb_drop is not None
    hints.append(check_stale("stale_cmb_bit"))
    assert cmb_drop["actual_action"] == classify_mutated(
        frames["f0015_01.bin"]
    )
    assert cmb_drop["actual_action"] != classify(frames["f0015_01.bin"])
    cmb_pass = cases.get("stale_cmb_pass")
    assert cmb_pass is not None
    hints.append(check_stale("stale_cmb_pass"))
    assert cmb_pass["actual_action"] == classify_mutated(
        frames["f0015_00.bin"]
    )
    assert cmb_pass["actual_action"] != classify(frames["f0015_00.bin"])
    slot = run["blocks"].get("slot")
    assert slot is not None, "missing slot block"
    fields = parse_fields(slot)
    assert fields.get("load_exit") == "0", fields
    assert fields.get("init_exit") == "0", fields
    assert "unload_ok=1" in slot
    values = dump_values(slot)
    assert values == {0: COUNTER_INIT + 2}, (
        "slot mutant must observe %d, got %r" % (COUNTER_INIT + 2, values)
    )
    cmb_sum = run["blocks"].get("cmb_sum")
    assert cmb_sum is not None, "missing cmb_sum block"
    sum_fields = parse_fields(cmb_sum)
    assert sum_fields.get("load_exit") == "0", sum_fields
    assert sum_fields.get("init_exit") == "0", sum_fields
    assert sum_fields.get("map_entries") == "2", sum_fields
    assert "unload_ok=1" in cmb_sum
    sum_values = dump_values(cmb_sum)
    pass_len = len(frames["f0015_00.bin"])
    assert pass_len == 15, pass_len
    assert sum_values == {0: COMBINED_INIT0 + 1, 1: COMBINED_INIT1 + 1}, (
        "byte-sum mutant must observe the +1 sums, got %r" % (sum_values,)
    )
    assert COMBINED_INIT1 + 1 != COMBINED_INIT1 + pass_len, (
        "the 15-byte frame must distinguish +1 from +len"
    )
    print(
        "PASS mutants detected: 2 classifier + 1 action + 1 slot-value "
        "+ 2 combined-bit + 1 combined-bytesum"
    )
    return guest_proc.combine_outcomes(*hints)


def test_sidecarless_loads():
    run = executed()
    solo_clf = run["blocks"].get("solo_clf")
    assert solo_clf is not None, "missing solo_clf block"
    section = solo_clf.split("--- solo_clf ls ---", 1)[1]
    listed = []
    for line in section.splitlines()[1:]:
        if line.startswith("load_exit"):
            break
        if line.strip():
            listed.append(line.strip())
    assert listed == ["classifier.bpf.o"], listed
    assert "load_exit=0" in solo_clf
    match = re.search(r"[Rr]eturn value:\s*(\d+)", solo_clf)
    assert match and int(match.group(1)) == XDP_DROP, solo_clf[-500:]
    assert "unload_ok=1" in solo_clf
    solo_cnt = run["blocks"].get("solo_cnt")
    assert solo_cnt is not None, "missing solo_cnt block"
    section = solo_cnt.split("--- solo_cnt ls ---", 1)[1]
    listed = []
    for line in section.splitlines()[1:]:
        if line.startswith("load_exit"):
            break
        if line.strip():
            listed.append(line.strip())
    assert listed == ["counter.bpf.o"], listed
    fields = parse_fields(solo_cnt)
    assert fields.get("load_exit") == "0", fields
    assert fields.get("init_exit") == "0", fields
    assert fields.get("map_entries") == "1", fields
    match = re.search(r"[Rr]eturn value:\s*(\d+)", solo_cnt)
    assert match and int(match.group(1)) == XDP_PASS
    values = {}
    for line in solo_cnt.splitlines():
        pair = re.match(
            r"key:\s*((?:[0-9a-fA-F]{2} ?)+)\s+"
            r"value:\s*((?:[0-9a-fA-F]{2} ?)+)\s*$",
            line,
        )
        if pair:
            values[int(pair.group(1).split()[0], 16)] = int.from_bytes(
                bytes(int(tok, 16) for tok in pair.group(2).split()),
                byteorder="little",
            )
    assert values == {0: COUNTER_INIT + 1}, values
    assert "unload_ok=1" in solo_cnt
    solo_cmb = run["blocks"].get("solo_cmb")
    assert solo_cmb is not None, "missing solo_cmb block"
    section = solo_cmb.split("--- solo_cmb ls ---", 1)[1]
    listed = []
    for line in section.splitlines()[1:]:
        if line.startswith("load_exit"):
            break
        if line.strip():
            listed.append(line.strip())
    assert listed == ["combined.bpf.o"], listed
    cmb_fields = parse_fields(solo_cmb)
    assert cmb_fields.get("load_exit") == "0", cmb_fields
    assert cmb_fields.get("init_exit") == "0", cmb_fields
    assert cmb_fields.get("map_entries") == "2", cmb_fields
    match = re.search(r"[Rr]eturn value:\s*(\d+)", solo_cmb)
    assert match and int(match.group(1)) == XDP_PASS
    cmb_values = dump_values(solo_cmb)
    solo_len = len(dict(run["frames"])["f0015_00.bin"])
    assert solo_len == 15, solo_len
    assert cmb_values == {
        0: COMBINED_INIT0 + 1,
        1: COMBINED_INIT1 + solo_len,
    }, "solo combined values must be exact, got %r" % (cmb_values,)
    assert "unload_ok=1" in solo_cmb
    print(
        "PASS sidecar-less direct-bpftool loads: "
        "classifier + counter + combined"
    )


def test_relocation_mutant_rejected_by_loader():
    run = executed()
    block = run["blocks"].get("m2load")
    assert block is not None, "missing m2load block"
    fields = parse_fields(block)
    assert fields.get("load_exit") not in (None, "0"), (
        "corrupted object must fail to load, got %r" % fields
    )
    assert fields.get("pin_exists") == "0", "failed load left its pin"
    log = block.split("--- m2load log ---", 1)[1]
    assert log.strip(), "loader must explain the failure"
    revert = run["run_cases"].get("m2revert")
    assert revert is not None
    guest_proc.check_harness_exit(
        "m2revert", exit=revert["_harness_exit"],
        classification=revert.get("classification"),
        stage=revert.get("stage"),
        contract_version=revert.get("contract_version"),
        note=revert.get("note"), expect=0)
    assert revert["actual_action"] == XDP_PASS
    print(
        "PASS relocation mutant fails to load (exit %s), intact object passes"
        % fields.get("load_exit")
    )


def test_corpus_byte_total():
    run = executed()
    frames = run["frames"]
    spec_bytes = sum(len(raw) for _, raw in frames[:33])
    assert spec_bytes == 9590, spec_bytes
    assert sum(len(raw) for _, raw in frames) == 32013, (
        "grand corpus total changed"
    )
    print("PASS corpus totals: spec 9590 bytes, grand 32013 bytes")


def test_guest_provenance():
    run = executed()
    output = run["output"]
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(output)
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "bpftool" in output, "bpftool version not recorded"
    assert "pin absent (unloaded)" in output, "pins were left behind"
    section = output.split("=== staged hashes ===", 1)[1]
    reported = {}
    for line in section.splitlines():
        match = re.match(r"^([0-9a-f]{64})  (\S+)$", line.strip())
        if match:
            reported[match.group(2)] = match.group(1)
    for name, digest in sorted(run["host_hashes"].items()):
        assert digest is not None, (
            "staged bytes missing for %s" % name
        )
        assert reported.get(name) == digest, (
            "staged hash mismatch for %s" % name
        )
    print(
        "PASS provenance: guest %s, bpftool recorded, %d staged hashes match"
        % (observed_kernel, len(run["host_hashes"]))
    )


# The mutants case is a denial: it expects the wire-derived
# FAIL at RUNTIME on every stale record (each mutant observably
# failing its base expectation) and passes only its own cell
# when the denial is observed with evidence. It guards the
# classifier oracle: base expectations must match (positive)
# while the mutants must observably mismatch (denial), proving
# the oracle is not vacuous.
CASE_DENIALS = {
    "test_mutants_detected_in_guest": (
        "test_classifier_matches_oracle", "RUNTIME"
    ),
}


def _manifests():
    return [SPEC_MANIFEST, SEEDED_MANIFEST, REGRESSION_MANIFEST]


def _frame_names():
    """Staged frame basenames, derived without reading contents.

    Names only: the manifests' contents (hashes, actions) are
    consumed with verification at load_corpus; the staged frame
    bytes join the guest handoff and the provenance comparison.
    """
    names = []
    with open(SPEC_MANIFEST, encoding="utf-8") as handle:
        spec = json.load(handle)
    names.extend(entry["file"] for entry in spec["frames"])
    names.extend(name for name, _raw in generate_seeded())
    with open(REGRESSION_MANIFEST, encoding="utf-8") as handle:
        regressions = json.load(handle)
    names.extend(entry["file"] for entry in regressions["frames"])
    return names


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Corpus entries are the manifests pinning every frame hash; a
# class with any missing file digests to zeros and can never
# back a PASS.
CASE_INPUTS = {
    "test_classifier_matches_oracle": {
        "sources": [CLASSIFIER_SOURCE],
        "objects": [("stage", "classifier.bpf.o")],
        "corpus": _manifests(),
    },
    "test_counter_accumulates_exactly": {
        "sources": [COUNTER_SOURCE],
        "objects": [("stage", "counter.bpf.o")],
        "corpus": _manifests(),
    },
    "test_counter_divergence_pinned_to_drops": {
        "sources": [COUNTER_SOURCE],
        "objects": [("stage", "counter.bpf.o")],
        "corpus": _manifests(),
    },
    "test_c_reference_matches_oracle": {
        "sources": [C_SOURCE],
        "objects": [("stage", "c_ref.bpf.o")],
        "corpus": _manifests(),
    },
    "test_combined_matches_oracle": {
        "sources": [COMBINED_SOURCE],
        "objects": [("stage", "combined.bpf.o")],
        "corpus": _manifests(),
    },
    "test_mutants_detected_in_guest": {
        "sources": [CLASSIFIER_MUTATED, COUNTER_MUTATED,
                    COUNTER_SLOT_MUTATED, COMBINED_BIT_MUTATED,
                    COMBINED_SUM_MUTATED],
        "objects": [("stage", "classifier_mut.bpf.o"),
                    ("stage", "counter_mut.bpf.o"),
                    ("stage", "counter_slot.bpf.o"),
                    ("stage", "combined_bit.bpf.o"),
                    ("stage", "combined_sum.bpf.o")],
        "corpus": [SPEC_MANIFEST],
    },
    "test_sidecarless_loads": {
        "sources": [CLASSIFIER_SOURCE, COUNTER_SOURCE, COMBINED_SOURCE],
        "objects": [("stage", "classifier.bpf.o"),
                    ("stage", "counter.bpf.o"),
                    ("stage", "combined.bpf.o")],
        "corpus": [SPEC_MANIFEST],
    },
    "test_relocation_mutant_rejected_by_loader": {
        "sources": [COUNTER_SOURCE],
        "objects": [("stage", "corrupt.bpf.o"),
                    ("stage", "counter.bpf.o")],
        "corpus": [SPEC_MANIFEST],
    },
    "test_corpus_byte_total": {
        "sources": _manifests(),
        "objects": [],
        "corpus": _manifests(),
    },
    "test_guest_provenance": {
        "sources": [CLASSIFIER_SOURCE, COUNTER_SOURCE, COMBINED_SOURCE,
                    C_SOURCE, HARNESS,
                    ("stage", "guest_acct.sh")],
        "objects": [("stage", "classifier.bpf.o"),
                    ("stage", "classifier_mut.bpf.o"),
                    ("stage", "counter.bpf.o"),
                    ("stage", "counter_mut.bpf.o"),
                    ("stage", "counter_slot.bpf.o"),
                    ("stage", "combined.bpf.o"),
                    ("stage", "combined_bit.bpf.o"),
                    ("stage", "combined_sum.bpf.o"),
                    ("stage", "c_ref.bpf.o"),
                    ("stage", "corrupt.bpf.o")],
        "corpus": _manifests() + [
            ("stage", name) for name in _frame_names()
        ],
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
        suite_id="kernel-accounting", suite_path=__file__,
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
    print(
        "accounting: %d frames proven in-guest "
        "(classifier + counter + combined + C reference + mutants + loader)"
        % len(run["frames"])
    )
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())

