# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/atomic/ops: stack atomics execute, acq/rel refuse.

No admitted Mojo spelling emits atomics (audit-refused: entry
MBPF319, subprogram MBPF304, cmpxchg MBPF305), so this suite
executes the stock-C control (four stack-slot atomics over
packet-derived operands) plus three hand-built oracles: hand-IR
(xadd + cmpxchg + exact gate), hand-asm (bare no-FETCH XADD,
returning the computed value 42 as its action), and two
hand-asm refusal objects (STORE_REL / LOAD_ACQ words, which
both lanes' verifiers reject with exact "invalid atomic
opcode" messages). A single-word ops mutant (verdict-gate
imm 0x5A -> 0x5B, expecting XDP_ABORTED) and a stale-object
leg (base object
against the DROP expectation, failing at RUNTIME) complete
the behavior proof, with an independent packet oracle and
guest-side hash re-verification of every staged byte. The
executed objects' bytes are decoded host-side over the xdp
section to prove the STX|ATOMIC words (exact words per
object), the no-acq/rel rule on executed objects, the
single-word mutant, CFG acyclicity, and trailing exits.
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
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "harness"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import lane_lock  # noqa: E402
import guest_proc  # noqa: E402
import tool_admission  # noqa: E402
from mojobpf.toolchain import admit_tools  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_jmp_qual import (  # noqa: E402  (sibling qual module)
    _assert_acyclic,
)

SUITE_ID = "kernel-isa-atomic"
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = int(os.environ.get("MOJOBPF_VNG_TIMEOUT", "1500"))


class EnvironmentFailure(AssertionError):
    """The lane cannot run honestly (missing tool/fixture/lease)."""

C_SOURCE = os.path.join(REPO_ROOT, "tests", "reference_c",
                        "atomic_ref.bpf.c")
OLL_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                          "atomic", "oracle-atomic-run.ll")
OASM_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                           "atomic", "oracle-atomic-run.s")
REFUSED_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                              "atomic", "atomic-acqrel-refused.s")
ACQONLY_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                              "atomic", "atomic-acqonly-refused.s")
PACKET = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                      "atomic", "pkt_zero64.bin")
PACKET_MIXED = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                            "atomic", "pkt_mixed64.bin")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_ABORTED = 0
XDP_DROP = 1
XDP_PASS = 2
OASM_ACTION = 42

# Byte-exact STX|ATOMIC words per staged object: (slot, word),
# observed at RED, decode-verified (class 0xDB/0xC3, UAPI imm,
# stack offsets, trailing exits).
CREF_ATOMIC = (
    (16, 0x1FFF83ADB),
    (20, 0xF1FFF01ADB),
    (28, 0x41FFEC5AC3),
    (30, 0xE1FFE81AC3),
)
OLL_ATOMIC = (
    (14, 0x1FFF83ADB),
    (16, 0xF1FFF02ADB),
)
OASM_ATOMIC = (
    (5, 0x21DB),
)
REFUSED_ATOMIC = (
    (3, 0x110000021DB),
    (4, 0x100000010DB),
)
ACQONLY_ATOMIC = (
    (4, 0x100000010DB),
)

# The verdict-gate materialization the mutant patches: (slot,
# base word, mutant word). A -D rebuild would move BOTH the
# stored want (slot 29) and the gate (slot 50) together and
# stay behavior-preserving; the mutant patches only the gate
# so the atomics execute with identical operands while the
# verdict flips to ABORTED.
MUT_WORD = (50, 0x5A00070556, 0x5B00070556)
# The untouched want materialization (identical in base and
# mutant, proving the patch is exactly one word).
WANT_WORD = (29, 0x5A000001B4)

# Pinned verifier rejection messages (observed pre-seal on
# both lanes; the refusal legs assert these substrings in
# the load stderr).
STORE_REL_MESSAGE = "BPF_ATOMIC uses invalid atomic opcode 110"
LOAD_ACQ_MESSAGE = "BPF_ATOMIC uses invalid atomic opcode 100"
ACQREL_LANE = {
    "v6.12": "refuse",
    "v6.6": "refuse",
    "v7.0.14": "accept",
    "v7.2": "accept",
    "v7.4-rc1": "accept",
}


def acqrel_mode():
    """Recorded acq/rel verdict: refuse on 6.x, accept on 7.x.

    7.x verifiers accept the release/acquire atomic opcodes
    (observed: the refused object loads and runs, returning
    2); 6.x refuses them with the pinned opcode messages.
    Unpinned releases refuse to guess.
    """
    try:
        return ACQREL_LANE[VNG_RELEASE]
    except KeyError:
        raise EnvironmentFailure(
            "pin the acqrel verdict for release %s with "
            "evidence; refusing to guess" % VNG_RELEASE
        )


def _acqrel_case(tag, obj):
    """CASES row for an acq/rel leg on this release."""
    if acqrel_mode() == "accept":
        return (tag, obj, XDP_PASS, 0, "pkt_zero64.bin")
    return (tag, obj, XDP_ABORTED, 4, "pkt_zero64.bin")

CASES = [
    ("c-zero", "cref.bpf.o", XDP_PASS, 0, "pkt_zero64.bin"),
    ("c-mixed", "cref.bpf.o", XDP_DROP, 0, "pkt_mixed64.bin"),
    ("oll-zero", "oll.bpf.o", XDP_PASS, 0, "pkt_zero64.bin"),
    ("oll-mixed", "oll.bpf.o", XDP_DROP, 0, "pkt_mixed64.bin"),
    ("oasm", "oasm.bpf.o", OASM_ACTION, 0, "pkt_zero64.bin"),
    _acqrel_case("acqrel", "refused.bpf.o"),
    _acqrel_case("acqonly", "acqonly.bpf.o"),
    ("mut-zero", "mutated.bpf.o", XDP_ABORTED, 0, "pkt_zero64.bin"),
    ("stale", "cref.bpf.o", XDP_DROP, 1, "pkt_zero64.bin"),
]


def run_step(argv, timeout=900):
    return subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True,
                          timeout=timeout)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _section_file_range(object_path, section):
    with open(object_path, "rb") as handle:
        data = handle.read()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    _, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        if data[base + row[0]:end] == section.encode():
            return row[4], row[5]
    raise AssertionError(
        "%s section missing in %s" % (section, object_path))


def _staged_section_words(stage, name, section):
    start, size = _section_file_range(
        os.path.join(stage, name), section)
    with open(os.path.join(stage, name), "rb") as handle:
        data = handle.read()
    text = data[start:start + size]
    assert len(text) % 8 == 0
    return [word for (word,) in struct.iter_unpack("<Q", text)]


def _atomic_entries(words):
    return [(slot, word) for slot, word in enumerate(words)
            if word & 0xFF in (0xDB, 0xC3)]


@guest_proc.consumes_source
def build_c(source, workdir, name, extra=()):
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["clang", "--target=bpf", "-mcpu=v3", "-O2", "-g",
         *extra, "-c", source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "C build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


@guest_proc.consumes_source
def build_oracle(source, workdir):
    object_path = os.path.join(workdir, "oll.bpf.o")
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "oracle build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


@guest_proc.consumes_source
def build_asm(source, workdir, name):
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["clang", "--target=bpf", "-mcpu=v3",
         "-c", source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "asm build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


def build_mutant(base_path, workdir):
    """Single-word ops mutant: copy the base object, patch the gate.

    The base object is copied byte-for-byte, then exactly the
    MUT_WORD verdict-gate immediate flips 0x5A -> 0x5B. The
    expected base word is asserted before patching so codegen
    drift fails loud instead of patching the wrong slot. No
    consumes_source wrapper: the only source is C_SOURCE,
    already consumed by the base build, and the staged bytes
    are tracked by stage_consumed_for_guest.
    """
    slot, base_word, mut_word = MUT_WORD
    start, size = _section_file_range(base_path, "xdp")
    assert size % 8 == 0
    with open(base_path, "rb") as handle:
        data = bytearray(handle.read())
    offset = start + slot * 8
    (seen,) = struct.unpack_from("<Q", data, offset)
    assert seen == base_word, (
        "mutant base word drifted at slot %d: got %#x, want %#x"
        % (slot, seen, base_word)
    )
    struct.pack_into("<Q", data, offset, mut_word)
    object_path = os.path.join(workdir, "mutated.bpf.o")
    with open(object_path, "wb") as handle:
        handle.write(data)
    return object_path


GUEST_SCRIPT = """#!/bin/bash
set -u
cd "{stage}"
{bpftool_prologue}
echo "=== begin guest_isa_atomic ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py cref.bpf.o mutated.bpf.o oll.bpf.o oasm.bpf.o refused.bpf.o acqonly.bpf.o pkt_zero64.bin pkt_mixed64.bin guest_isa_atomic.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-atomic-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-atomic-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-atomic-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-atomic-$tag.stdout 2>/tmp/isa-atomic-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-atomic-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-atomic-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_atomic ==="
"""


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
        names=("llc",),
    )
    if sorted(admitted) != ["llc"]:
        raise EnvironmentFailure(
            "pinned llc admission failed: %s"
            % "; ".join("%s %s" % (item.code, item.explanation)
                        for item in diagnostics)
        )
    print("pinned tools admitted: llc=%s" % admitted["llc"].version)
    for tool in ("clang", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (C_SOURCE, OLL_SOURCE, OASM_SOURCE, REFUSED_SOURCE,
                 ACQONLY_SOURCE, PACKET, PACKET_MIXED, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    stage = guest_proc.owned_stage(prefix="mojo-isa-atomic-", dir="/tmp")
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        packet = handle.read()
    with guest_proc.open_consumed(PACKET_MIXED, "rb") as handle:
        packet_mixed = handle.read()
    cref_obj = build_c(C_SOURCE, stage, "cref")
    mutated_obj = build_mutant(cref_obj, stage)
    oll_obj = build_oracle(OLL_SOURCE, stage)
    oasm_obj = build_asm(OASM_SOURCE, stage, "oasm")
    refused_obj = build_asm(REFUSED_SOURCE, stage, "refused")
    acqonly_obj = build_asm(ACQONLY_SOURCE, stage, "acqonly")
    staged = {
        "bpf_test_run.py": HARNESS,
        "cref.bpf.o": cref_obj,
        "mutated.bpf.o": mutated_obj,
        "oll.bpf.o": oll_obj,
        "oasm.bpf.o": oasm_obj,
        "refused.bpf.o": refused_obj,
        "acqonly.bpf.o": acqonly_obj,
        "pkt_zero64.bin": PACKET,
        "pkt_mixed64.bin": PACKET_MIXED,
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
            ownership_token="mojobpf-isa-atomic-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_atomic.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_isa_atomic.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("guest_isa_atomic.sh",),
    )
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, *guest_proc.vng_accelerator_argv(),
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
        progress_banner="=== begin guest_isa_atomic ===",
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
    print("inputs: pkt_zero64.bin sha256=%s pkt_mixed64.bin sha256=%s"
          % (hashlib.sha256(packet).hexdigest(),
             hashlib.sha256(packet_mixed).hexdigest()))
    return {"stage": stage, "output": output, "packet": packet,
            "packet_mixed": packet_mixed, "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


MIXED_OPERANDS = bytes([1, 2, 4, 8])


def test_fixture_bytes():
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        frame = handle.read()
    assert len(frame) == 64, "packet fixture has %d bytes" % len(frame)
    assert frame == bytes(64), "packet fixture must be zero bytes"
    assert executed()["packet"] == frame
    with guest_proc.open_consumed(PACKET_MIXED, "rb") as handle:
        mixed = handle.read()
    assert len(mixed) == 64, "mixed fixture has %d bytes" % len(mixed)
    assert mixed[:14] == bytes(14), "mixed fixture must zero bytes 0..13"
    assert mixed[14:18] == MIXED_OPERANDS, (
        "mixed fixture operand bytes 14..17 mismatch: %r"
        % (list(mixed[14:18]),)
    )
    assert mixed[18:] == bytes(46), "mixed fixture must zero bytes 18..63"
    assert executed()["packet_mixed"] == mixed


def test_atomic_c_zero_returns_pass():
    # Zeros: A=101 B=1 C=0xFF D=0x5A with matching old
    # values, sum == 0 -> PASS. Every equality is impossible
    # without its op executing (nonzero offsets; D must read
    # 0x5A), so PASS proves all four atomics ran.
    record = executed()["results"]["c-zero"]
    guest_proc.check_harness_exit(
        "c-zero", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "atomic C control must return XDP_PASS on zeros, got %r"
        % (record.get("actual_action"),)
    )


def test_atomic_c_mixed_returns_drop():
    # Mixed (1,2,4,8): A=102 B=3 C=0xFF D=0x5A, sum != 0 -> DROP.
    record = executed()["results"]["c-mixed"]
    guest_proc.check_harness_exit(
        "c-mixed", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_DROP, (
        "atomic C control must return XDP_DROP on mixed, got %r"
        % (record.get("actual_action"),)
    )


def test_atomic_oracles_execute():
    run = executed()
    for tag, want in (("oll-zero", XDP_PASS), ("oll-mixed", XDP_DROP)):
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record["actual_action"] == want, (
            "hand-IR oracle %s must return %d, got %r"
            % (tag, want, record.get("actual_action"),)
        )
    record = run["results"]["oasm"]
    guest_proc.check_harness_exit(
        "oasm", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == OASM_ACTION, (
        "hand-asm bare-XADD oracle must return 42, got %r"
        % (record.get("actual_action"),)
    )


def _load_stderr(record):
    for command in record.get("commands", []):
        argv = command.get("argv", [])
        if len(argv) >= 3 and argv[1:3] == ["prog", "load"]:
            return command.get("stderr", "")
    raise AssertionError("harness record carries no prog load command")


def test_atomic_acqrel_refused():
    run = executed()
    hints = []
    for tag, message in (("acqrel", STORE_REL_MESSAGE),
                         ("acqonly", LOAD_ACQ_MESSAGE)):
        record = run["results"][tag]
        if acqrel_mode() == "accept":
            hints.append(guest_proc.check_harness_exit(
                tag, exit=record["_harness_exit"],
                classification=record.get("classification"),
                stage=record.get("stage"),
                contract_version=record.get("contract_version"),
                note=record.get("note"), expect=0))
            assert record["actual_action"] == XDP_PASS, (
                "%s: accepted acq/rel leg must return XDP_PASS, "
                "observed %r" % (tag, record["actual_action"]))
            continue
        hints.append(guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=4))
        assert record["classification"] == "verifier", (
            "%s: expected verifier classification, got %r"
            % (tag, record.get("classification"),)
        )
        stderr = _load_stderr(record)
        assert message in stderr, (
            "%s: expected %r in load stderr, got %r"
            % (tag, message, stderr[-500:],)
        )
    return guest_proc.combine_outcomes(*hints)


def test_atomic_mutation_aborts():
    run = executed()
    record = run["results"]["mut-zero"]
    guest_proc.check_harness_exit(
        "mut-zero", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_ABORTED, (
        "gate mutant must miss the gate, got %r"
        % (record.get("actual_action"),)
    )
    assert record["actual_action"] != run["results"]["c-zero"][
        "actual_action"], "rebuilt mutant must change the action"


def test_atomic_stale_object_fails():
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


def test_atomic_guest_objects_admit_atomics():
    stage = executed()["stage"]
    cref_xdp = _staged_section_words(stage, "cref.bpf.o", "xdp")
    mut_xdp = _staged_section_words(stage, "mutated.bpf.o", "xdp")
    oll_xdp = _staged_section_words(stage, "oll.bpf.o", "xdp")
    oasm_xdp = _staged_section_words(stage, "oasm.bpf.o", "xdp")
    refused_xdp = _staged_section_words(stage, "refused.bpf.o", "xdp")
    acqonly_xdp = _staged_section_words(stage, "acqonly.bpf.o", "xdp")
    for tag, words, pin in (
        ("cref", cref_xdp, CREF_ATOMIC),
        ("mutant", mut_xdp, CREF_ATOMIC),
        ("oll", oll_xdp, OLL_ATOMIC),
        ("oasm", oasm_xdp, OASM_ATOMIC),
        ("refused", refused_xdp, REFUSED_ATOMIC),
        ("acqonly", acqonly_xdp, ACQONLY_ATOMIC),
    ):
        found = _atomic_entries(words)
        assert found == list(pin), (
            "executed %s must carry exactly the pinned STX|ATOMIC "
            "words, got %r"
            % (tag, [(slot, hex(word)) for slot, word in found],)
        )
        _assert_acyclic(tag, words)
        assert words[-1] == 0x95, (
            "executed %s must trail an exit" % (tag,)
        )
    for tag, words in (("cref", cref_xdp), ("mutant", mut_xdp),
                       ("oll", oll_xdp), ("oasm", oasm_xdp)):
        for slot, word in _atomic_entries(words):
            imm = (word >> 32) & 0xFFFFFFFF
            assert imm not in (0x100, 0x110), (
                "executed %s slot %d carries acq/rel" % (tag, slot)
            )
    assert (len(cref_xdp), len(mut_xdp), len(oll_xdp),
            len(oasm_xdp), len(refused_xdp),
            len(acqonly_xdp)) == (59, 59, 32, 8, 7, 7), (
        "executed objects must keep their decoded shapes"
    )
    diff = [index for index, (ours, theirs)
            in enumerate(zip(cref_xdp, mut_xdp))
            if ours != theirs]
    assert diff == [MUT_WORD[0]], (
        "mutant must differ in exactly the gate word, got %r"
        % (diff,)
    )
    slot, base_word, mut_word = MUT_WORD
    assert cref_xdp[slot] == base_word, (slot, hex(cref_xdp[slot]))
    assert mut_xdp[slot] == mut_word, (slot, hex(mut_xdp[slot]))
    want_slot, want_word = WANT_WORD
    assert cref_xdp[want_slot] == want_word, (
        want_slot, hex(cref_xdp[want_slot]))
    assert mut_xdp[want_slot] == want_word, (
        want_slot, hex(mut_xdp[want_slot]))


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
        if want_exit == 4:
            # Load-refused legs never pin: the harness leaves
            # cleanup_ok unset (array/hash-maps precedent); the
            # global pin-absence checks above prove no residue.
            assert record.get("cleanup_ok") is None, (
                "%s: harness must leave cleanup_ok unset" % tag
            )
            continue
        assert record.get("cleanup_ok") is True, (
            "%s: harness must report cleanup_ok" % tag
        )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in ("bpf_test_run.py", "cref.bpf.o", "mutated.bpf.o",
                 "oll.bpf.o", "oasm.bpf.o", "refused.bpf.o",
                 "acqonly.bpf.o", "pkt_zero64.bin", "pkt_mixed64.bin",
                 "guest_isa_atomic.sh"):
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
    "test_atomic_stale_object_fails": (
        "test_atomic_mutation_aborts", "RUNTIME"
    ),
}
if acqrel_mode() == "refuse":
    # The verifier denial exists only on refusing releases;
    # on accepting releases the leg is positive (a denial
    # entry would reject its PASS observation).
    CASE_DENIALS["test_atomic_acqrel_refused"] = (
        "test_atomic_oracles_execute", "VERIFY"
    )

CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": [PACKET, PACKET_MIXED],
        "objects": [],
        "corpus": [PACKET, PACKET_MIXED],
    },
    "test_atomic_c_zero_returns_pass": {
        "sources": [C_SOURCE],
        "objects": [("stage", "cref.bpf.o")],
        "corpus": [PACKET],
    },
    "test_atomic_c_mixed_returns_drop": {
        "sources": [C_SOURCE],
        "objects": [("stage", "cref.bpf.o")],
        "corpus": [PACKET_MIXED],
    },
    "test_atomic_oracles_execute": {
        "sources": [OLL_SOURCE, OASM_SOURCE],
        "objects": [("stage", "oll.bpf.o"),
                    ("stage", "oasm.bpf.o")],
        "corpus": [PACKET, PACKET_MIXED],
    },
    "test_atomic_acqrel_refused": {
        "sources": [REFUSED_SOURCE, ACQONLY_SOURCE],
        "objects": [("stage", "refused.bpf.o"),
                    ("stage", "acqonly.bpf.o")],
        "corpus": [PACKET],
    },
    "test_atomic_guest_objects_admit_atomics": {
        "sources": [C_SOURCE, OLL_SOURCE, OASM_SOURCE,
                    REFUSED_SOURCE, ACQONLY_SOURCE],
        "objects": [("stage", "cref.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "oll.bpf.o"),
                    ("stage", "oasm.bpf.o"),
                    ("stage", "refused.bpf.o"),
                    ("stage", "acqonly.bpf.o")],
        "corpus": [],
    },
    "test_atomic_mutation_aborts": {
        "sources": [C_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [PACKET],
    },
    "test_atomic_stale_object_fails": {
        "sources": [C_SOURCE],
        "objects": [("stage", "cref.bpf.o")],
        "corpus": [PACKET],
    },
    "test_guest_provenance": {
        "sources": [C_SOURCE, OLL_SOURCE, OASM_SOURCE,
                    REFUSED_SOURCE, ACQONLY_SOURCE, HARNESS,
                    ("stage", "guest_isa_atomic.sh")],
        "objects": [("stage", "cref.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "oll.bpf.o"),
                    ("stage", "oasm.bpf.o"),
                    ("stage", "refused.bpf.o"),
                    ("stage", "acqonly.bpf.o")],
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
    print("isa atomic: C behaviors, oracle executions, acq/rel refusals, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
