# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/alu/alu32: the admitted 32-bit ALU chain runs.

Builds ``tests/fixtures/isa/alu32/alu32_minimal.mojo`` (32-bit
add/sub/mul/div/mod/and/or/xor/neg/lsh/rsh/arsh over packet bytes
plus u16/u8 division legs, expecting XDP_PASS) and its
single-constant mutant (+18 to +28, expecting XDP_DROP) through the
genuine parsed pipeline (``mojo build --emit llvm`` ->
``mojobpf-lower --mode lower`` emission, whose report's resolved
llc flags feed the backend -> ``llc -mtriple=bpfel``). Boots one
guest per lane and test-runs both objects plus a stock-C control
and a stale-object leg (base object against the mutant
expectation, which must fail at RUNTIME), with an independent
packet oracle, a single-constant source mutation, and guest-side
hash re-verification of every staged byte. The executed objects'
bytes are decoded host-side to prove the full admitted 32-bit mix
is present, the 32-bit divisions reduced (no DIV32/MOD32 word is
emitted), and no shift X-form word is emitted.

Standalone: ``python3 tests/kernel/test_alu32_qual.py`` (exit 0 on
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

SUITE_ID = "kernel-isa-alu32"
FIX_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "isa", "alu32")
BASE_SOURCE = os.path.join(FIX_DIR, "alu32_minimal.mojo")
MUTATED_SOURCE = os.path.join(FIX_DIR, "alu32_minimal_mutated.mojo")
PACKET = os.path.join(FIX_DIR, "pkt_zero60.bin")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")
C_SOURCE = os.path.join(REPO_ROOT, "tests", "reference_c",
                        "alu32_ref.bpf.c")

XDP_DROP = 1
XDP_PASS = 2

# Byte-exact admitted 32-bit words (observed from the genuine
# pipeline, decode-verified against the fixture chain: 16-bit lane
# builds (LSH-K-16 x2, OR-X x2), MUL32-X (p), SUB32-X (d),
# u16/u8 input sums, the div/mod reductions (64-bit magic for
# d // 42 and q % 7; pure-32-bit magic for w16 // 42 and w8 % 7),
# ADD-K 7/100, the reassociated x/y/m logic cluster (XOR-K 15,
# OR-K 7, XOR-K -9, OR-X — correct on the live low 8 bits; the
# downstream & 243 masks the rest), XOR-K 15, OR-K 16, XOR-X,
# AND-X (t), the split v sum (RSH-K 2, LSH-K 2, AND-K 4, ADD-X),
# RSH-K 6, NEG32, ARSH-K 2, gate adds, ADD-K 18, and the unsigned
# 32-bit gate JGT32-K r4, 10, +1). The gate word is pinned as
# observed; JMP32 qualification belongs to F-ISA/jmp/cond.
ALU32_ADD_K_WORDS = (0x6400000204, 0x0700000504)
ALU32_ADD_K_BASE = 0x1200000404
ALU32_ADD_K_MUT = 0x1C00000404
ALU32_ADD_X_WORDS = (0x610C, 0x030C, 0x060C, 0x240C, 0x040C,
                     0x340C, 0x140C)
ALU32_SUB_X_WORDS = (0x121C, 0x021C, 0x061C, 0x611C)
ALU32_MUL_K_WORDS = (0x0700000024, 0x2500000024, 0x0700000624,
                     0x061900000324)
ALU32_MUL_X_WORD = 0x022C
ALU32_OR_K_WORDS = (0x0700000444, 0x1000000244)
ALU32_OR_X_WORDS = (0x204C, 0x144C, 0x044C)
ALU32_AND_K_WORDS = (0xFF00000054, 0xFE00000654, 0xF300000054,
                     0x0400000254, 0xFF00000154)
ALU32_AND_X_WORD = 0x425C
ALU32_LSH_K_WORDS = (0x1000000264, 0x1000000164, 0x0200000264)
ALU32_RSH_K_WORDS = (0x0100000274, 0x0800000074, 0x0100000674,
                     0x0200000674, 0x0200000474, 0x0600000074,
                     0x1000000374)
ALU32_NEG_WORD = 0x0484
ALU32_XOR_K_WORDS = (0x0F000000A4, 0xF7000004A4, 0x0F000002A4)
ALU32_XOR_X_WORDS = (0x50AC, 0x02AC)
ALU32_MOV_K_WORDS = (0x02000000B4, 0x01000000B4, 0x02000000B4)
ALU32_MOV_WORDS = (0x52BC, 0x10BC, 0x54BC, 0x42BC, 0x10BC,
                   0x16BC, 0x40BC, 0x24BC)
ALU32_ARSH_K_WORD = 0x02000004C4
ALU32_MUL64_K_WORDS = (0x30C30C3100000227, 0x2492492500000027)
ALU32_RSH64_K_WORDS = (0x2200000277, 0x2000000077)
ALU32_GATE_WORD = 0x0A00010426

# (tag, object key, expected action, want harness exit)
CASES = (
    ("base", "base.bpf.o", XDP_PASS, 0),
    ("cref", "c_ref.bpf.o", XDP_PASS, 0),
    ("mut", "mutated.bpf.o", XDP_DROP, 0),
    ("stale", "base.bpf.o", XDP_DROP, 1),
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


def lower_tool():
    explicit = os.environ.get("MOJOBPF_LOWER")
    if explicit:
        if not os.access(explicit, os.X_OK):
            raise EnvironmentFailure(
                "MOJOBPF_LOWER is not executable: %s" % explicit)
        return explicit
    found = shutil.which("mojobpf-lower")
    if found is None:
        raise EnvironmentFailure(
            "mojobpf-lower not found (MOJOBPF_LOWER or PATH)")
    return found


def lower_spec():
    return {"schema_version": 1,
            "model_id": "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1",
            "profile_id": "linux-bpfel-v3", "entry": "xdp_entry",
            "program_type": "xdp", "section": "xdp",
            "kernel_license": "Apache-2.0 WITH LLVM-exception",
            "cpu": "v3", "features": "", "map": None}


@guest_proc.consumes_source
def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(["mojo", "build", "--emit", "llvm",
                     *FRONTEND_TARGET_FLAGS, "-o", raw_path, source])
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    spec_path = os.path.join(workdir, name + ".spec.json")
    report_path = os.path.join(workdir, name + ".report.json")
    with open(spec_path, "w", encoding="utf-8") as handle:
        json.dump(lower_spec(), handle)
    proc = run_step([lower_tool(), "--mode", "lower",
                     "--input", raw_path, "--spec", spec_path,
                     "--report", report_path, "--output", adapted_path,
                     "--emit", "llvm"])
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "parsed lowering failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if not os.path.isfile(report_path):
        raise AssertionError(
            "parsed lowering wrote no report for %s" % source
        )
    with open(report_path, encoding="utf-8") as handle:
        report = json.load(handle)
    if report.get("ok") is not True:
        raise AssertionError(
            "parsed lowering report not ok for %s:\n%s"
            % (source, json.dumps(report)[:2000])
        )
    flags = (report.get("target_facts", {}).get("isa_cpu", {})
             .get("resolved_llc_flags"))
    if flags != ["-mtriple=bpfel", "-mcpu=v3"]:
        raise AssertionError(
            "unexpected resolved llc flags for %s: %r" % (source, flags)
        )
    proc = run_step(["llc", *flags, "-filetype=obj", adapted_path,
                     "-o", object_path])
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


@guest_proc.consumes_source
def build_c(source, workdir):
    object_path = os.path.join(workdir, "c_ref.bpf.o")
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


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
{bpftool_prologue}
echo "=== begin guest_isa_alu32 ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o c_ref.bpf.o pkt_zero60.bin guest_isa_alu32.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-alu32-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-alu32-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-alu32-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-alu32-$tag.stdout 2>/tmp/isa-alu32-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-alu32-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-alu32-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_alu32 ==="
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
    """Build both objects, boot one guest, return parsed case results."""
    admitted, diagnostics = admit_tools(
        lockfile_path=os.path.join(REPO_ROOT, "toolchains.lock.json"),
        names=("mojo", "llc"),
    )
    if sorted(admitted) != ["llc", "mojo"]:
        raise EnvironmentFailure(
            "pinned mojo/llc admission failed: %s"
            % "; ".join("%s %s" % (item.code, item.explanation)
                        for item in diagnostics)
        )
    print("pinned tools admitted: mojo=%s llc=%s"
          % (admitted["mojo"].version, admitted["llc"].version))
    for tool in ("clang", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    lower_tool()
    for path in (BASE_SOURCE, MUTATED_SOURCE, C_SOURCE, PACKET,
                 HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    stage = guest_proc.owned_stage(prefix="mojo-isa-alu32-", dir="/tmp")
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        packet = handle.read()
    base_obj = build_object(BASE_SOURCE, stage, "base")
    mutated_obj = build_object(MUTATED_SOURCE, stage, "mutated")
    c_obj = build_c(C_SOURCE, stage)
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": base_obj,
        "mutated.bpf.o": mutated_obj,
        "c_ref.bpf.o": c_obj,
        "pkt_zero60.bin": PACKET,
    }
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, expect, _ in CASES:
        commands.append(
            "run_case %s %s %d pkt_zero60.bin" % (tag, obj, expect)
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
            ownership_token="mojobpf-isa-alu32-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_alu32.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_isa_alu32.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("guest_isa_alu32.sh",),
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
        progress_banner="=== begin guest_isa_alu32 ===",
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
    return {"stage": stage, "output": output, "packet": packet,
            "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def test_fixture_bytes():
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        frame = handle.read()
    assert len(frame) == 60, "packet fixture has %d bytes" % len(frame)
    assert frame == bytes(60), "packet fixture must be zero bytes"
    assert executed()["packet"] == frame


def _staged_xdp_words(stage, name):
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
        if data[base + row[0]:end] == b"xdp":
            text = data[row[4]:row[4] + row[5]]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError("xdp section missing in staged %s" % name)


def test_alu32_guest_object_admits_alu():
    stage = executed()["stage"]
    base_words = _staged_xdp_words(stage, "base.bpf.o")
    mut_words = _staged_xdp_words(stage, "mutated.bpf.o")
    for tag, words, add_k_mut in (
        ("base", base_words, ALU32_ADD_K_BASE),
        ("mutant", mut_words, ALU32_ADD_K_MUT),
    ):
        for name, opcode, expected in (
            ("ADD32-X", 0x0C, list(ALU32_ADD_X_WORDS)),
            ("SUB32-X", 0x1C, list(ALU32_SUB_X_WORDS)),
            ("MUL32-K", 0x24, list(ALU32_MUL_K_WORDS)),
            ("MUL32-X", 0x2C, [ALU32_MUL_X_WORD]),
            ("OR32-K", 0x44, list(ALU32_OR_K_WORDS)),
            ("OR32-X", 0x4C, list(ALU32_OR_X_WORDS)),
            ("AND32-K", 0x54, list(ALU32_AND_K_WORDS)),
            ("AND32-X", 0x5C, [ALU32_AND_X_WORD]),
            ("LSH32-K", 0x64, list(ALU32_LSH_K_WORDS)),
            ("RSH32-K", 0x74, list(ALU32_RSH_K_WORDS)),
            ("NEG32", 0x84, [ALU32_NEG_WORD]),
            ("XOR32-K", 0xA4, list(ALU32_XOR_K_WORDS)),
            ("XOR32-X", 0xAC, list(ALU32_XOR_X_WORDS)),
            ("MOV32-K", 0xB4, list(ALU32_MOV_K_WORDS)),
            ("MOV32", 0xBC, list(ALU32_MOV_WORDS)),
            ("ARSH32-K", 0xC4, [ALU32_ARSH_K_WORD]),
            ("MUL64-K", 0x27, list(ALU32_MUL64_K_WORDS)),
            ("RSH64-K", 0x77, list(ALU32_RSH64_K_WORDS)),
        ):
            found = [word for word in words if word & 0xFF == opcode]
            assert found == expected, (
                "executed %s must carry the byte-exact %s words, got %r"
                % (tag, name, [hex(word) for word in found],)
            )
        addk = [word for word in words if word & 0xFF == 0x04]
        assert addk == list(ALU32_ADD_K_WORDS) + [add_k_mut], (
            "executed %s must carry the byte-exact ADD32-K words, "
            "got %r" % (tag, [hex(word) for word in addk],)
        )
        refused = [word for word in words
                   if word & 0xFF in (0x34, 0x94, 0x3C, 0x9C)]
        assert not refused, (
            "executed %s must emit no DIV32/MOD32 word (admitted "
            "divisions reduce), got %r"
            % (tag, [hex(word) for word in refused],)
        )
        shiftx = [word for word in words
                  if word & 0xFF in (0x6C, 0x7C, 0xCC)]
        assert not shiftx, (
            "executed %s must emit no shift X-form word, got %r"
            % (tag, [hex(word) for word in shiftx],)
        )
        gate = [word for word in words if word & 0xFF == 0x26]
        assert gate == [ALU32_GATE_WORD], (
            "executed %s must keep the byte-exact unsigned gate, got %r"
            % (tag, [hex(word) for word in gate],)
        )
    assert mut_words != base_words, "mutant bytes must differ"


def test_alu32_base_returns_pass():
    record = executed()["results"]["base"]
    guest_proc.check_harness_exit(
        "base", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "alu32 base object must return XDP_PASS, got %r"
        % (record.get("actual_action"),)
    )


def test_alu32_c_control_matches_base():
    run = executed()
    record = run["results"]["cref"]
    guest_proc.check_harness_exit(
        "cref", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "stock-C -mcpu=v3 control must return XDP_PASS, got %r"
        % (record.get("actual_action"),)
    )
    assert record["actual_action"] == run["results"]["base"][
        "actual_action"], "same input bytes must agree"


def test_alu32_mutation_changes_action():
    run = executed()
    record = run["results"]["mut"]
    guest_proc.check_harness_exit(
        "mut", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_DROP
    assert record["actual_action"] != run["results"]["base"][
        "actual_action"], "rebuilt mutant must change the action"


def test_alu32_stale_object_fails():
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
    for tag, _, _, want_exit in CASES:
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
                 "c_ref.bpf.o", "pkt_zero60.bin", "guest_isa_alu32.sh"):
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
    "test_alu32_stale_object_fails": (
        "test_alu32_mutation_changes_action", "RUNTIME"
    ),
}

CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": [PACKET],
        "objects": [],
        "corpus": [PACKET],
    },
    "test_alu32_base_returns_pass": {
        "sources": [BASE_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_alu32_c_control_matches_base": {
        "sources": [C_SOURCE],
        "objects": [("stage", "c_ref.bpf.o")],
        "corpus": [PACKET],
    },
    "test_alu32_guest_object_admits_alu": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o")],
        "corpus": [],
    },
    "test_alu32_mutation_changes_action": {
        "sources": [MUTATED_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [PACKET],
    },
    "test_alu32_stale_object_fails": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_guest_provenance": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE, C_SOURCE, HARNESS,
                    ("stage", "guest_isa_alu32.sh")],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "c_ref.bpf.o")],
        "corpus": [PACKET],
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
    print("isa alu32: guest behavior, C control, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
