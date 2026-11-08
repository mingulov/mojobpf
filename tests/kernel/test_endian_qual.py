# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/misc/endian: BPF_END executes, TO_LE is identity.

No admitted Mojo spelling emits BPF_END (the bswap intrinsic
is audit-refused: MBPF319 `nocallback` at entry AND
subprogram sites), so this suite executes the stock-C
control (bswap16/32/64 over packet-derived operands, zeros
PASS / mixed DROP) plus two hand-built oracles: hand-IR
(xor-combined swaps returned as the action: zeros 0, mixed
258) and hand-asm (TO_LE identity over a packet u16: zeros
0, mixed 513). A direction-bit mutant (0xD4 -> 0xDC, mixed
258) proves the TO_LE word's direction bit matters, a C
gate mutant (mixed ABORTED) proves verdict sensitivity, and
a stale-object leg (base object against the DROP
expectation, failing at RUNTIME) completes the behavior
proof, with an independent packet oracle and guest-side hash
re-verification of every staged byte. The executed objects'
bytes are decoded host-side over the xdp section to prove
the BPF_END words (exact words per object), the
TO_BE-only rule on compiler-emitted objects, both
single-word mutants, CFG acyclicity, and trailing exits.
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

SUITE_ID = "kernel-isa-endian"
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = int(os.environ.get("MOJOBPF_VNG_TIMEOUT", "1500"))


class EnvironmentFailure(AssertionError):
    """The lane cannot run honestly (missing tool/fixture/lease)."""


C_SOURCE = os.path.join(REPO_ROOT, "tests", "reference_c",
                        "endian_ref.bpf.c")
OLL_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                          "endian", "oracle-endian-run.ll")
OASM_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                           "endian", "oracle-endian-run.s")
PACKET = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                      "endian", "pkt_zero64.bin")
PACKET_MIXED = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                            "endian", "pkt_mixed64.bin")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_ABORTED = 0
XDP_DROP = 1
XDP_PASS = 2
OLL_MIXED = 258
TOLE_MIXED = 513
TOLE_MUT_MIXED = 258

# Byte-exact BPF_END words per staged object: (slot, word),
# observed at RED, decode-verified (opcode 0xDC/0xD4, width
# imm, regs, trailing exits).
CREF_ENDIAN = (
    (7, 0x40000002DC),
    (9, 0x10000001DC),
    (11, 0x20000003DC),
)
OLL_ENDIAN = (
    (8, 0x20000002DC),
    (10, 0x10000000DC),
    (13, 0x40000001DC),
)
OASM_ENDIAN = (
    (6, 0x10000000D4),
)
MUTDIR_ENDIAN = (
    (6, 0x10000000DC),
)

# The C verdict-gate materialization the mutant patches:
# (slot, base word, mutant word). The u16 comparison imm
# 0x0102 -> 0x0103 makes the mixed score miss the gate
# (-> ABORTED) while the swaps execute identically.
MUT_WORD = (14, 0x10200050456, 0x10300050456)
# The direction-bit mutant: TO_LE -> TO_BE on the hand-asm
# oracle (mixed 513 -> 258).
DIR_WORD = (6, 0x10000000D4, 0x10000000DC)

CASES = [
    ("c-zero", "cref.bpf.o", XDP_PASS, 0, "pkt_zero64.bin"),
    ("c-mixed", "cref.bpf.o", XDP_DROP, 0, "pkt_mixed64.bin"),
    ("oll-zero", "oll.bpf.o", XDP_ABORTED, 0, "pkt_zero64.bin"),
    ("oll-mixed", "oll.bpf.o", OLL_MIXED, 0, "pkt_mixed64.bin"),
    ("tole-zero", "oasm.bpf.o", XDP_ABORTED, 0, "pkt_zero64.bin"),
    ("tole-mixed", "oasm.bpf.o", TOLE_MIXED, 0, "pkt_mixed64.bin"),
    ("tole-mut", "mutdir.bpf.o", TOLE_MUT_MIXED, 0, "pkt_mixed64.bin"),
    ("mut-mixed", "mutated.bpf.o", XDP_ABORTED, 0, "pkt_mixed64.bin"),
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


def _endian_entries(words):
    return [(slot, word) for slot, word in enumerate(words)
            if word & 0xFF in (0xDC, 0xD4)]


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


def build_patched(base_path, workdir, name, patch):
    """Single-word ops mutant: copy the base object, patch one word.

    The base object is copied byte-for-byte, then exactly the
    patch (slot, base word, mutant word) flips. The expected
    base word is asserted before patching so codegen drift
    fails loud instead of patching the wrong slot. No
    consumes_source wrapper: the only source is already
    consumed by the base build, and the staged bytes are
    tracked by stage_consumed_for_guest.
    """
    slot, base_word, mut_word = patch
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
    object_path = os.path.join(workdir, name + ".bpf.o")
    with open(object_path, "wb") as handle:
        handle.write(data)
    return object_path


GUEST_SCRIPT = """#!/bin/bash
set -u
cd "{stage}"
{bpftool_prologue}
echo "=== begin guest_isa_endian ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py cref.bpf.o mutated.bpf.o oll.bpf.o oasm.bpf.o mutdir.bpf.o pkt_zero64.bin pkt_mixed64.bin guest_isa_endian.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-endian-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-endian-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-endian-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-endian-$tag.stdout 2>/tmp/isa-endian-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-endian-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-endian-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_endian ==="
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
    for path in (C_SOURCE, OLL_SOURCE, OASM_SOURCE, PACKET,
                 PACKET_MIXED, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    stage = guest_proc.owned_stage(prefix="mojo-isa-endian-", dir="/tmp")
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        packet = handle.read()
    with guest_proc.open_consumed(PACKET_MIXED, "rb") as handle:
        packet_mixed = handle.read()
    cref_obj = build_c(C_SOURCE, stage, "cref")
    mutated_obj = build_patched(cref_obj, stage, "mutated", MUT_WORD)
    oll_obj = build_oracle(OLL_SOURCE, stage)
    oasm_obj = build_asm(OASM_SOURCE, stage, "oasm")
    mutdir_obj = build_patched(oasm_obj, stage, "mutdir", DIR_WORD)
    staged = {
        "bpf_test_run.py": HARNESS,
        "cref.bpf.o": cref_obj,
        "mutated.bpf.o": mutated_obj,
        "oll.bpf.o": oll_obj,
        "oasm.bpf.o": oasm_obj,
        "mutdir.bpf.o": mutdir_obj,
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
            ownership_token="mojobpf-isa-endian-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_endian.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_isa_endian.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("guest_isa_endian.sh",),
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
        progress_banner="=== begin guest_isa_endian ===",
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
    with guest_proc.open_consumed(PACKET_MIXED, "rb") as handle:
        mixed = handle.read()
    assert len(mixed) == 64, "mixed fixture has %d bytes" % len(mixed)
    assert mixed[14:18] == MIXED_OPERANDS, (
        "mixed packet bytes 14..17 drive the swap verdicts, got %r"
        % (mixed[14:18],)
    )


def test_endian_c_zero_returns_pass():
    record = executed()["results"]["c-zero"]
    hint = guest_proc.check_harness_exit(
        "c-zero", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "c-zero must return PASS, got %r"
        % (record.get("actual_action"),)
    )
    return guest_proc.combine_outcomes(hint)


def test_endian_c_mixed_returns_drop():
    record = executed()["results"]["c-mixed"]
    hint = guest_proc.check_harness_exit(
        "c-mixed", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_DROP, (
        "c-mixed must return DROP, got %r"
        % (record.get("actual_action"),)
    )
    return guest_proc.combine_outcomes(hint)


def test_endian_oracles_execute():
    run = executed()
    for tag, want in (("oll-zero", XDP_ABORTED),
                      ("oll-mixed", OLL_MIXED),
                      ("tole-zero", XDP_ABORTED),
                      ("tole-mixed", TOLE_MIXED),
                      ("tole-mut", TOLE_MUT_MIXED)):
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record["actual_action"] == want, (
            "%s must return %r, got %r"
            % (tag, want, record.get("actual_action"),)
        )
    assert (run["results"]["tole-mixed"]["actual_action"]
            != run["results"]["tole-mut"]["actual_action"]), (
        "direction mutant must change the action"
    )


def test_endian_mutation_aborts():
    run = executed()
    record = run["results"]["mut-mixed"]
    guest_proc.check_harness_exit(
        "mut-mixed", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_ABORTED, (
        "gate mutant must miss the gate, got %r"
        % (record.get("actual_action"),)
    )
    assert record["actual_action"] != run["results"]["c-mixed"][
        "actual_action"], "rebuilt mutant must change the action"


def test_endian_stale_object_fails():
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


def test_endian_guest_objects_admit_endian():
    stage = executed()["stage"]
    cref_xdp = _staged_section_words(stage, "cref.bpf.o", "xdp")
    mut_xdp = _staged_section_words(stage, "mutated.bpf.o", "xdp")
    oll_xdp = _staged_section_words(stage, "oll.bpf.o", "xdp")
    oasm_xdp = _staged_section_words(stage, "oasm.bpf.o", "xdp")
    mutdir_xdp = _staged_section_words(stage, "mutdir.bpf.o", "xdp")
    for tag, words, pin in (
        ("cref", cref_xdp, CREF_ENDIAN),
        ("mutant", mut_xdp, CREF_ENDIAN),
        ("oll", oll_xdp, OLL_ENDIAN),
        ("oasm", oasm_xdp, OASM_ENDIAN),
        ("mutdir", mutdir_xdp, MUTDIR_ENDIAN),
    ):
        found = _endian_entries(words)
        assert found == list(pin), (
            "executed %s must carry exactly the pinned BPF_END "
            "words, got %r"
            % (tag, [(slot, hex(word)) for slot, word in found],)
        )
        _assert_acyclic(tag, words)
        assert words[-1] == 0x95, (
            "executed %s must trail an exit" % (tag,)
        )
    for tag, words in (("cref", cref_xdp), ("mutant", mut_xdp),
                       ("oll", oll_xdp)):
        for slot, word in _endian_entries(words):
            assert word & 0xFF == 0xDC, (
                "compiler-emitted %s slot %d must be TO_BE, got %#x"
                % (tag, slot, word)
            )
    assert (len(cref_xdp), len(mut_xdp), len(oll_xdp),
            len(oasm_xdp), len(mutdir_xdp)) == (29, 29, 17, 10, 10), (
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
    dirdiff = [index for index, (ours, theirs)
               in enumerate(zip(oasm_xdp, mutdir_xdp))
               if ours != theirs]
    assert dirdiff == [DIR_WORD[0]], (
        "direction mutant must differ in exactly the END word, "
        "got %r" % (dirdiff,)
    )
    dslot, dbase, dmut = DIR_WORD
    assert oasm_xdp[dslot] == dbase, (dslot, hex(oasm_xdp[dslot]))
    assert mutdir_xdp[dslot] == dmut, (dslot, hex(mutdir_xdp[dslot]))


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
    for name in ("bpf_test_run.py", "cref.bpf.o", "mutated.bpf.o",
                 "oll.bpf.o", "oasm.bpf.o", "mutdir.bpf.o",
                 "pkt_zero64.bin", "pkt_mixed64.bin",
                 "guest_isa_endian.sh"):
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
    "test_endian_stale_object_fails": (
        "test_endian_mutation_aborts", "RUNTIME"
    ),
}

CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": [PACKET, PACKET_MIXED],
        "objects": [],
        "corpus": [PACKET, PACKET_MIXED],
    },
    "test_endian_c_zero_returns_pass": {
        "sources": [C_SOURCE],
        "objects": [("stage", "cref.bpf.o")],
        "corpus": [PACKET],
    },
    "test_endian_c_mixed_returns_drop": {
        "sources": [C_SOURCE],
        "objects": [("stage", "cref.bpf.o")],
        "corpus": [PACKET_MIXED],
    },
    "test_endian_oracles_execute": {
        "sources": [OLL_SOURCE, OASM_SOURCE],
        "objects": [("stage", "oll.bpf.o"),
                    ("stage", "oasm.bpf.o"),
                    ("stage", "mutdir.bpf.o")],
        "corpus": [PACKET, PACKET_MIXED],
    },
    "test_endian_guest_objects_admit_endian": {
        "sources": [C_SOURCE, OLL_SOURCE, OASM_SOURCE],
        "objects": [("stage", "cref.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "oll.bpf.o"),
                    ("stage", "oasm.bpf.o"),
                    ("stage", "mutdir.bpf.o")],
        "corpus": [],
    },
    "test_endian_mutation_aborts": {
        "sources": [C_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [PACKET_MIXED],
    },
    "test_endian_stale_object_fails": {
        "sources": [C_SOURCE],
        "objects": [("stage", "cref.bpf.o")],
        "corpus": [PACKET],
    },
    "test_guest_provenance": {
        "sources": [C_SOURCE, OLL_SOURCE, OASM_SOURCE, HARNESS,
                    ("stage", "guest_isa_endian.sh")],
        "objects": [("stage", "cref.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "oll.bpf.o"),
                    ("stage", "oasm.bpf.o"),
                    ("stage", "mutdir.bpf.o")],
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
    print("isa endian: C behaviors, oracle executions, direction mutant, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
