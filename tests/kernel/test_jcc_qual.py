# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/jmp/cond: conditional jumps execute.

This suite executes the genuine multi-gate Mojo fixture
(``tests/fixtures/isa/jcc/jcc_minimal.mojo``: twenty compare
gates over packet bytes 14..51, each adding a power-of-two
weight, with an exact-equality mid-gate after gate 10) and
the mirroring stock-C control, on the zero and mixed
packets. The score is a bitmask, so the exact-equality
gates prove EVERY arm executed: zeros score exactly 809 at
the mid-gate and 755497 at the final gate (XDP_PASS), mixed
exactly 214 and 293078 (XDP_DROP); any other score returns
XDP_ABORTED. The mid-gate also bounds verifier path
exploration (twenty sequential bitmask gates exceed the
complexity limit). A single-constant Mojo mutant (zeros
expectation 755497 -> 755496, expecting XDP_ABORTED) and a
stale-object leg (base object against the DROP expectation,
which must fail at RUNTIME) complete the behavior proof, with
an independent packet oracle and guest-side hash
re-verification of every staged byte. The executed objects'
bytes are decoded host-side over the xdp section to prove the
Jcc words (exact words with verified pc+off+1 targets),
the no-loop corollary (CFG acyclicity), JSET/JA32 absence,
and the single-word mutant. The oracle-only opcodes (JNE,
unselected K forms) ride the host corpus pins, never
executed here.

Standalone: ``python3 tests/kernel/test_jcc_qual.py`` (exit 0 on
proof, exit 2 on environment failure; MOJOBPF_VNG_RELEASE selects
the matrix lane). Missing tools fail loudly as environment failures
before any guest boots.
"""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

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
from mojobpf.toolchain import admit_tools  # noqa: E402

SUITE_ID = "kernel-isa-jcc"
FIX_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "isa", "jcc")
MOJO_SOURCE = os.path.join(FIX_DIR, "jcc_minimal.mojo")
MOJO_MUTANT = os.path.join(FIX_DIR, "jcc_minimal_mutated.mojo")
C_SOURCE = os.path.join(REPO_ROOT, "tests", "reference_c",
                        "jcc_ref.bpf.c")
PACKET = os.path.join(FIX_DIR, "pkt_zero60.bin")
PACKET_MIXED = os.path.join(FIX_DIR, "pkt_mixed60.bin")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_ABORTED = 0
XDP_DROP = 1
XDP_PASS = 2

# Byte-exact conditional-jump words, observed at RED from the
# staged strict-route builds and decode-verified (every target
# lands inside xdp). Each entry is (slot, word): 20 gates plus
# the bounds check (slot 5), the two mid-gate sites, and the
# two score gates. The mutant differs only at the zeros-gate
# word (slot 153).
JCC_MOJO = (
    (5, 0x95232D),
    (13, 0x1451D),
    (19, 0x1451D),
    (27, 0x1562D),
    (35, 0x1563D),
    (43, 0x156AD),
    (51, 0x156BD),
    (61, 0x1566D),
    (71, 0x156CD),
    (81, 0x1567D),
    (91, 0x156DD),
    (94, 0xD600010315),
    (96, 0x32900010315),
    (99, 0x100370256),
    (104, 0x1451E),
    (110, 0x145AE),
    (115, 0xA00010426),
    (120, 0x700010416),
    (125, 0x6400010426),
    (131, 0x104C5),
    (137, 0x1451D),
    (140, 0x900010316),
    (144, 0x1341D),
    (147, 0x500010116),
    (150, 0x478D600010215),
    (153, 0xB872900010215),
)
JCC_C = (
    (5, 0x6A232D),
    (10, 0x1241E),
    (14, 0x1241E),
    (20, 0x1452E),
    (24, 0x134AE),
    (30, 0x145AE),
    (34, 0x1242E),
    (40, 0x1252E),
    (46, 0x135AE),
    (50, 0x134AE),
    (54, 0x1342E),
    (56, 0x32900010215),
    (57, 0xD600360255),
    (62, 0x1451E),
    (68, 0x145AE),
    (73, 0xA00010426),
    (78, 0x700010416),
    (83, 0x6400010326),
    (88, 0x10216),
    (94, 0x1451E),
    (97, 0x900010316),
    (101, 0x1341E),
    (104, 0x500010116),
    (107, 0x478D600010215),
    (110, 0xB872900010215),
)
BASE_GATE_WORD = 0xB872900010215
MUT_GATE_WORD = 0xB872800010215
JCC_MUT = tuple(
    (slot, MUT_GATE_WORD if word == BASE_GATE_WORD else word)
    for slot, word in JCC_MOJO
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_jmp_qual import (  # noqa: E402  (sibling qual module)
    _assert_acyclic,
    _signed_off,
)


# (tag, object key, expected action, want harness exit, staged packet)
# The bitmask gate proves every arm executed: zeros must score
# exactly 755497 (PASS), mixed exactly 293078 (DROP); the mutant
# (zeros expectation off by one) matches neither gate (ABORTED).
CASES = (
    ("base-zero", "base.bpf.o", XDP_PASS, 0, "pkt_zero60.bin"),
    ("base-mixed", "base.bpf.o", XDP_DROP, 0, "pkt_mixed60.bin"),
    ("c-zero", "cref.bpf.o", XDP_PASS, 0, "pkt_zero60.bin"),
    ("c-mixed", "cref.bpf.o", XDP_DROP, 0, "pkt_mixed60.bin"),
    ("mut-zero", "mutated.bpf.o", XDP_ABORTED, 0, "pkt_zero60.bin"),
    ("stale", "base.bpf.o", XDP_DROP, 1, "pkt_zero60.bin"),
)

VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = int(os.environ.get("MOJOBPF_VNG_TIMEOUT", "1500"))


class EnvironmentFailure(AssertionError):
    """The lane cannot run honestly (missing tool/fixture/lease)."""


def run_step(argv):
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True,
                              check=False)
    except OSError as exc:
        raise EnvironmentFailure(
            "cannot execute %s: %s" % (argv[0], exc))


@guest_proc.consumes_source
def build_c(source, workdir, name, extra=()):
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["clang", "--target=bpf", "-mcpu=v3", "-O2", "-g",
         *extra, "-c", source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "C reference build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "warning:" in proc.stderr.lower() or "error:" in proc.stderr.lower():
        raise AssertionError(
            "C reference build diagnostics for %s:\n%s"
            % (source, proc.stderr)
        )
    return object_path


@guest_proc.consumes_source
def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".raw.ll")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS,
         "-I", os.path.join(REPO_ROOT, "src", "mojobpf",
                            "resources", "sdk"),
         "-o", raw_path, source]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    spec_path = os.path.join(workdir, name + ".spec.json")
    with open(spec_path, "w", encoding="utf-8") as handle:
        json.dump({
            "schema_version": 1,
            "model_id": "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1",
            "profile_id": "linux-bpfel-v3",
            "entry": "xdp_entry",
            "program_type": "xdp",
            "section": "xdp",
            "kernel_license": "Apache-2.0 WITH LLVM-exception",
            "cpu": "v3",
            "features": "",
            "map": None,
        }, handle)
    report_path = os.path.join(workdir, name + ".report.json")
    lowered_path = os.path.join(workdir, name + ".bpf.ll")
    lower = os.environ.get("MOJOBPF_LOWER") or "mojobpf-lower"
    proc = run_step(
        [lower, "--mode", "lower", "--input", raw_path,
         "--spec", spec_path, "--report", report_path,
         "--output", lowered_path, "--emit", "llvm"]
    )
    if proc.returncode != 0 or not os.path.isfile(lowered_path):
        raise AssertionError(
            "strict lower failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
    if report.get("ok") is not True:
        raise AssertionError(
            "strict lower report not ok for %s:\n%s"
            % (source, json.dumps(report)[:2000])
        )
    flags = (report.get("target_facts", {}).get("isa_cpu", {})
             .get("resolved_llc_flags"))
    if flags != ["-mtriple=bpfel", "-mcpu=v3"]:
        raise AssertionError(
            "unexpected resolved llc flags for %s: %r"
            % (source, flags)
        )
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["llc", *flags, "-filetype=obj", lowered_path,
         "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "llc failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
{bpftool_prologue}
echo "=== begin guest_isa_jcc ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o cref.bpf.o pkt_zero60.bin pkt_mixed60.bin guest_isa_jcc.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-jcc-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-jcc-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-jcc-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-jcc-$tag.stdout 2>/tmp/isa-jcc-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-jcc-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-jcc-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_jcc ==="
"""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_guest(argv, stage, timeout):
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


def guest_run():
    """Build all objects, boot one guest, return parsed case results."""
    admitted, diagnostics = admit_tools(
        lockfile_path=os.path.join(REPO_ROOT, "toolchains.lock.json"),
        names=("mojo", "llc"),
    )
    if sorted(admitted) != ["llc", "mojo"]:
        raise EnvironmentFailure(
            "pinned toolchain admission failed: %s"
            % "; ".join("%s %s" % (item.code, item.explanation)
                        for item in diagnostics)
        )
    print("pinned tools admitted: mojo=%s llc=%s"
          % (admitted["mojo"].version, admitted["llc"].version))
    for tool in ("clang", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (MOJO_SOURCE, MOJO_MUTANT, C_SOURCE, PACKET,
                 PACKET_MIXED, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    stage = guest_proc.owned_stage(prefix="mojo-isa-jcc-", dir="/tmp")
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        packet = handle.read()
    with guest_proc.open_consumed(PACKET_MIXED, "rb") as handle:
        packet_mixed = handle.read()
    base_obj = build_object(MOJO_SOURCE, stage, "base")
    mutated_obj = build_object(MOJO_MUTANT, stage, "mutated")
    cref_obj = build_c(C_SOURCE, stage, "cref")
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": base_obj,
        "mutated.bpf.o": mutated_obj,
        "cref.bpf.o": cref_obj,
        "pkt_zero60.bin": PACKET,
        "pkt_mixed60.bin": PACKET_MIXED,
    }
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, expect, _, data in CASES:
        commands.append(
            "run_case %s %s %d %s" % (tag, obj, expect, data)
        )
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
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
        harness_flags=tool_admission.render_harness_flags(
            pins, pin_path="$pin", owned_root="/sys/fs/bpf",
            ownership_token="mojobpf-isa-jcc-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_jcc.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_isa_jcc.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("guest_isa_jcc.sh",),
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
        progress_banner="=== begin guest_isa_jcc ===",
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
    missing = [tag for tag, _, _, _, _ in CASES if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    print("inputs: pkt_zero60.bin sha256=%s pkt_mixed60.bin sha256=%s"
          % (hashlib.sha256(packet).hexdigest(),
             hashlib.sha256(packet_mixed).hexdigest()))
    return {"stage": stage, "output": output, "packet": packet,
            "packet_mixed": packet_mixed, "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


MIXED_GATE_BYTES = bytes([
    1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1,
    0, 1, 1, 0, 1, 0, 0, 1, 11, 0, 7, 0, 101, 0, 1,
    0, 1, 0, 9, 1, 0, 5,
])


def test_fixture_bytes():
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        frame = handle.read()
    assert len(frame) == 60, "packet fixture has %d bytes" % len(frame)
    assert frame == bytes(60), "packet fixture must be zero bytes"
    assert executed()["packet"] == frame
    with guest_proc.open_consumed(PACKET_MIXED, "rb") as handle:
        mixed = handle.read()
    assert len(mixed) == 60, "mixed fixture has %d bytes" % len(mixed)
    assert mixed[:14] == bytes(14), "mixed fixture must zero bytes 0..13"
    assert mixed[14:52] == MIXED_GATE_BYTES, (
        "mixed fixture gate bytes 14..51 mismatch: %r"
        % (list(mixed[14:52]),)
    )
    assert mixed[52:] == bytes(8), "mixed fixture must zero bytes 52..59"
    assert executed()["packet_mixed"] == mixed


def _staged_section_words(stage, name, section):
    with open(os.path.join(stage, name), "rb") as handle:
        data = handle.read()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        if data[base + row[0]:end] == section.encode():
            text = data[row[4]:row[4] + row[5]]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError(
        "%s section missing in staged %s" % (section, name))


JCC_CODES = (0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
               0xA0, 0xB0, 0xC0, 0xD0)
JSET_OPCODES = (0x45, 0x4D, 0x46, 0x4E)
JA32_OPCODE = 0x06


def _jcc_entries(words):
    # Every conditional-jump word: classes 0x05 (64-bit) and
    # 0x06 (32-bit) under the Jcc code set, mirroring the host
    # corpus decoder. JA/CALL/EXIT are not conditional jumps.
    # JSET x4 and JA32 raise on sight: both pinned absent (the
    # bounds check selects JGT-X, not JSET).
    entries = []
    for slot, word in enumerate(words):
        opcode = word & 0xFF
        if opcode == JA32_OPCODE:
            raise AssertionError(
                "slot %d carries JA32, pinned absent" % (slot,)
            )
        if opcode in JSET_OPCODES:
            raise AssertionError(
                "slot %d carries JSET, pinned absent" % (slot,)
            )
        if opcode in (0x05, 0x85, 0x95):
            continue
        if (opcode & 0x07 in (0x05, 0x06)
                and opcode & 0xF0 in JCC_CODES):
            entries.append((slot, word))
    return entries


def test_jcc_guest_objects_admit_jcc():
    stage = executed()["stage"]
    base_xdp = _staged_section_words(stage, "base.bpf.o", "xdp")
    mut_xdp = _staged_section_words(stage, "mutated.bpf.o", "xdp")
    cref_xdp = _staged_section_words(stage, "cref.bpf.o", "xdp")
    assert sum(1 for ours, theirs in zip(JCC_MUT, JCC_MOJO)
               if ours != theirs) == 1, (
        "mutant pins must differ from base in one entry"
    )
    for tag, words, pin in (
        ("base", base_xdp, JCC_MOJO),
        ("mutant", mut_xdp, JCC_MUT),
        ("cref", cref_xdp, JCC_C),
    ):
        found = _jcc_entries(words)
        assert found == list(pin), (
            "executed %s must carry exactly the pinned Jcc "
            "words, got %r"
            % (tag, [(slot, hex(word)) for slot, word in found],)
        )
        for slot, word in found:
            target = slot + _signed_off(word) + 1
            assert 0 <= target < len(words), (
                "executed %s Jcc at slot %d targets %d, "
                "outside" % (tag, slot, target)
            )
        _assert_acyclic(tag, words)
        assert words[-1] == 0x95, (
            "executed %s must trail an exit" % (tag,)
        )
    assert len(mut_xdp) == len(base_xdp), "mutant must not move layout"
    assert len(cref_xdp) == 113, (
        "C control must keep its 113-slot shape, got %d"
        % (len(cref_xdp),)
    )
    diff = [index for index, (ours, theirs)
            in enumerate(zip(base_xdp, mut_xdp))
            if ours != theirs]
    assert len(diff) == 1, (
        "mutant must differ in exactly one word, got %r" % (diff,)
    )
    slot = diff[0]
    assert base_xdp[slot] & 0xFF == 0x15, (
        "mutant diff at slot %d must be the JEQ-K gate, got %s"
        % (slot, hex(base_xdp[slot]),)
    )
    assert (base_xdp[slot] >> 32) == 755497, (
        "base gate constant must be 755497, got %d"
        % (base_xdp[slot] >> 32,)
    )
    assert (mut_xdp[slot] >> 32) == 755496, (
        "mutant gate constant must be 755496, got %d"
        % (mut_xdp[slot] >> 32,)
    )


def test_jcc_base_zero_returns_pass():
    # All-zero frame: every gate takes its zeros arm, the bitmask
    # gate matches 755497 exactly, PASS. Any other arm pattern
    # scores a different bitmask and misses the gate, so PASS
    # proves every gate executed.
    record = executed()["results"]["base-zero"]
    guest_proc.check_harness_exit(
        "base-zero", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "jcc base object must return XDP_PASS on zeros, got %r"
        % (record.get("actual_action"),)
    )


def test_jcc_base_mixed_returns_drop():
    # Mixed frame: every gate takes its mixed arm, the bitmask
    # gate matches 293078 exactly, DROP.
    record = executed()["results"]["base-mixed"]
    guest_proc.check_harness_exit(
        "base-mixed", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_DROP, (
        "jcc base object must return XDP_DROP on mixed, got %r"
        % (record.get("actual_action"),)
    )


def test_jcc_c_zero_matches_base():
    run = executed()
    record = run["results"]["c-zero"]
    guest_proc.check_harness_exit(
        "c-zero", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == run["results"][
        "base-zero"]["actual_action"], (
        "independent C control must agree on zeros"
    )


def test_jcc_c_mixed_matches_base():
    run = executed()
    record = run["results"]["c-mixed"]
    guest_proc.check_harness_exit(
        "c-mixed", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == run["results"][
        "base-mixed"]["actual_action"], (
        "independent C control must agree on mixed"
    )


def test_jcc_mutation_aborts():
    run = executed()
    record = run["results"]["mut-zero"]
    guest_proc.check_harness_exit(
        "mut-zero", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_ABORTED, (
        "single-constant mutant must miss both gates, got %r"
        % (record.get("actual_action"),)
    )
    assert record["actual_action"] != run["results"]["base-zero"][
        "actual_action"], "rebuilt mutant must change the action"


def test_jcc_stale_object_fails():
    record = executed()["results"]["stale"]
    hint = guest_proc.check_harness_exit(
        "stale", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=1)
    assert record["classification"] == "runtime", (
        "stale: expected runtime classification, got %r"
        % (record.get("classification"),)
    )
    assert record["actual_action"] == XDP_PASS, (
        "stale object must still produce its old action 2, got %r"
        % (record.get("actual_action"),)
    )
    return guest_proc.combine_outcomes(hint)


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
    for tag, _, _, want_exit, _ in CASES:
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=want_exit)
        assert record.get("cleanup_ok") is True, (
            "%s: harness must report cleanup_ok" % tag
        )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in ("bpf_test_run.py", "base.bpf.o", "mutated.bpf.o",
                 "cref.bpf.o", "pkt_zero60.bin", "pkt_mixed60.bin",
                 "guest_isa_jcc.sh"):
        if rec is None:
            expected = sha256_file(os.path.join(run["stage"], name))
            assert expected in run["output"], (
                "guest must re-verify staged hash of %s" % name
            )
            continue
        expected = rec.consumed_staged_digest(name, run["stage"])
        assert expected is not None, "staged bytes missing for %s" % name
        assert reported.get(name) == expected, (
            "guest must report the consumed bytes of %s" % name
        )


CASE_DENIALS = {
    "test_jcc_stale_object_fails": (
        "test_jcc_mutation_aborts", "RUNTIME"
    ),
}

CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": [PACKET, PACKET_MIXED],
        "objects": [],
        "corpus": [PACKET, PACKET_MIXED],
    },
    "test_jcc_base_zero_returns_pass": {
        "sources": [MOJO_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_jcc_base_mixed_returns_drop": {
        "sources": [MOJO_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET_MIXED],
    },
    "test_jcc_c_zero_matches_base": {
        "sources": [MOJO_SOURCE, C_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "cref.bpf.o")],
        "corpus": [PACKET],
    },
    "test_jcc_c_mixed_matches_base": {
        "sources": [MOJO_SOURCE, C_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "cref.bpf.o")],
        "corpus": [PACKET_MIXED],
    },
    "test_jcc_guest_objects_admit_jcc": {
        "sources": [MOJO_SOURCE, MOJO_MUTANT, C_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "cref.bpf.o")],
        "corpus": [],
    },
    "test_jcc_mutation_aborts": {
        "sources": [MOJO_MUTANT],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [PACKET],
    },
    "test_jcc_stale_object_fails": {
        "sources": [MOJO_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_guest_provenance": {
        "sources": [MOJO_SOURCE, MOJO_MUTANT, C_SOURCE, HARNESS,
                    ("stage", "guest_isa_jcc.sh")],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "cref.bpf.o")],
        "corpus": [PACKET, PACKET_MIXED],
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
        suite_id=SUITE_ID, suite_path=__file__,
        case_ids=names, denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
    guest_proc.set_active_recorder(rec)
    if not __debug__:
        return rec.finish_unrun(
            "must not run under python -O (asserts stripped)"
        )
    failures = 0
    unavailable_seen = False
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
    print("isa jcc: 20-gate bitmask behavior, C agreement, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
