# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/mem/load-store: packet loads and stack spills run.

Builds ``tests/fixtures/isa/mem/mem_minimal.mojo`` (entry reads ten
packet bytes, two u16 legs, a sign-extension leg, a wide ld_imm64
mask, and an @export helper call forcing r10 spills, expecting
XDP_PASS) and its single-constant mutant (+7 to +17 in the helper,
expecting XDP_DROP) through the genuine parsed pipeline (``mojo
build --emit llvm`` -> ``mojobpf-lower --mode lower`` under the
linux-bpfel-v3-subprog profile, whose report's resolved llc flags
feed the backend -> ``llc -mtriple=bpfel``). Boots one guest per
lane and test-runs both objects plus a stock-C control and a
stale-object leg (base object against the mutant expectation, which
must fail at RUNTIME), with an independent packet oracle, a
single-constant source mutation, and guest-side hash re-verification
of every staged byte. The executed objects' bytes are decoded
host-side over the xdp + callee sections to prove the memory words
(LDXB packet offsets 14..23, LDXW context reads, STX/LDX spill
pairs, LSH+ARSH sign extension, the ld_imm64 pair, and the absence
of ST and MEMSX selection) and that r10 appears only as a memory
base. Half-width memory words widen to W on this route; H-width
end-to-end evidence lives in the record slice (STXH in its
tracepoint object, proven by the kernel-ringbuf suite).

Standalone: ``python3 tests/kernel/test_mem_qual.py`` (exit 0 on
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

SUITE_ID = "kernel-isa-mem"
FIX_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "isa", "mem")
BASE_SOURCE = os.path.join(FIX_DIR, "mem_minimal.mojo")
MUTATED_SOURCE = os.path.join(FIX_DIR, "mem_minimal_mutated.mojo")
PACKET = os.path.join(FIX_DIR, "pkt_zero60.bin")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")
C_SOURCE = os.path.join(REPO_ROOT, "tests", "reference_c",
                        "mem_ref.bpf.c")

XDP_DROP = 1
XDP_PASS = 2

# Byte-exact memory words (observed from the genuine pipeline,
# decode-verified against the fixture: the entry reads the ctx
# pair (LDXW offsets 4, 0), ten packet bytes (LDXB offsets
# 14..23), spills four live values to r10 slots before the call
# (STXDW), two to W slots (STXW), calls once, reloads DW + W,
# sign-extends via a consecutive LSH64-imm/ARSH64-imm 56 pair,
# truncates via shifts, and combines under a wide ld_imm64 mask
# before gating). MEMSX opcodes (LDX class with mode 0x80)
# must not appear: they are v4-only.
MEM_CTX_WORDS = (0x41361, 0x1161)
MEM_PKT_OFFSETS = tuple(range(14, 24))
MEM_CALL_WORD = 0xFFFFFFFF00001085
MEM_SPILL_DW_WORDS = (0xFFF82A7B, 0xFFF02A7B, 0xFFE02A7B,
                      0xFFD02A7B)
MEM_SPILL_W_WORDS = (0xFFE82A63, 0xFFD82A63)
MEM_RELOAD_DW_WORDS = (0xFFD0A179, 0xFFE0A279, 0xFFF0A279,
                       0xFFF8A279)
MEM_RELOAD_W_WORDS = (0xFFD8A261, 0xFFE8A261)
MEM_SEXT_WORDS = (0x3800000667, 0x38000006C7)
MEM_IMM64_WORDS = (0xEF00000118, 0x6700000000)
# MEMSX mode is 0x80 (not 0x20, which is BPF_ABS): the signed
# loads are LDX-class 0x81/0x89/0x91. Probed: -mcpu=v4 emits
# 0x91 for sext loads and plain STX for truncating stores, so
# these three are the whole observable MEMSX space.
MEM_MEMSX_OPS = frozenset((0x81, 0x89, 0x91))
MEM_CALLEE_HEAD = (0x10BF, 0x2A00000037)
MEM_CALLEE_ADD_BASE = 0x0700000007
MEM_CALLEE_ADD_MUT = 0x1100000007
MEM_GATE_WORD = 0x0A00010025


def _r10_violation(word):
    # Same rule as the host suite: r10 appears only as the memory
    # base (STX low nibble / LDX high nibble), never as a written
    # destination or a value source.
    opcode = word & 0xFF
    low, high = (word >> 8) & 0xF, (word >> 12) & 0xF
    klass = opcode & 0x07
    if klass == 0x03:  # STX: value nibble must not be r10
        return high == 0xA
    if klass == 0x02:  # ST: no value register at all
        return high != 0x0
    if klass == 0x01:  # LDX: dst nibble must not be r10
        return low == 0xA
    if klass == 0x00:  # LD: dst nibble must not be r10
        return low == 0xA
    return low == 0xA or high == 0xA


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
            "profile_id": "linux-bpfel-v3-subprog", "entry": "xdp_entry",
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
echo "=== begin guest_isa_mem ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o c_ref.bpf.o pkt_zero60.bin guest_isa_mem.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-mem-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-mem-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-mem-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-mem-$tag.stdout 2>/tmp/isa-mem-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-mem-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-mem-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_mem ==="
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
    stage = guest_proc.owned_stage(prefix="mojo-isa-mem-", dir="/tmp")
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
            ownership_token="mojobpf-isa-mem-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_mem.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_isa_mem.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("guest_isa_mem.sh",),
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
        progress_banner="=== begin guest_isa_mem ===",
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


def test_mem_guest_object_admits_words():
    stage = executed()["stage"]
    base_xdp = _staged_section_words(stage, "base.bpf.o", "xdp")
    mut_xdp = _staged_section_words(stage, "mutated.bpf.o", "xdp")
    base_text = _staged_section_words(stage, "base.bpf.o", ".text")
    mut_text = _staged_section_words(stage, "mutated.bpf.o", ".text")
    assert base_xdp == mut_xdp, "mutant must not move the entry"
    for tag, words in (("base", base_xdp), ("mutant", mut_xdp)):
        call = [word for word in words if word & 0xFF == 0x85]
        assert call == [MEM_CALL_WORD], (
            "executed %s must call exactly once, got %r"
            % (tag, [hex(word) for word in call],)
        )
        ctx = [word for word in words
               if word & 0xFF == 0x61
               and (word >> 12) & 0xF == 0x1]
        assert ctx == list(MEM_CTX_WORDS), (
            "executed %s must read the ctx pair first, got %r"
            % (tag, [hex(word) for word in ctx],)
        )
        pkt = sorted((word >> 16) & 0xFFFF
                     for word in words if word & 0xFF == 0x71)
        assert pkt == list(MEM_PKT_OFFSETS), (
            "executed %s must load packet bytes 14..23, got %r"
            % (tag, pkt,)
        )
        spills = [word for word in words if word & 0xFF == 0x7B]
        assert spills == list(MEM_SPILL_DW_WORDS), (
            "executed %s must spill four DW slots, got %r"
            % (tag, [hex(word) for word in spills],)
        )
        spillsw = [word for word in words if word & 0xFF == 0x63]
        assert spillsw == list(MEM_SPILL_W_WORDS), (
            "executed %s must spill two W slots, got %r"
            % (tag, [hex(word) for word in spillsw],)
        )
        call_at = words.index(MEM_CALL_WORD)
        assert all(words.index(word) < call_at for word in spills), (
            "executed %s must spill before the call" % (tag,)
        )
        reloads = [word for word in words
                   if word & 0xFF == 0x79
                   and (word >> 12) & 0xF == 0xA]
        assert reloads == list(MEM_RELOAD_DW_WORDS), (
            "executed %s must reload four DW slots, got %r"
            % (tag, [hex(word) for word in reloads],)
        )
        reloadsw = [word for word in words
                    if word & 0xFF == 0x61
                    and (word >> 12) & 0xF == 0xA]
        assert reloadsw == list(MEM_RELOAD_W_WORDS), (
            "executed %s must reload two W slots, got %r"
            % (tag, [hex(word) for word in reloadsw],)
        )
        sext = [(words[index], words[index + 1])
                for index in range(len(words) - 1)
                if (words[index], words[index + 1])
                == MEM_SEXT_WORDS]
        assert len(sext) == 1, (
            "executed %s must sign-extend via one LSH+ARSH pair, "
            "got %d" % (tag, len(sext),)
        )
        imm = [(words[index], words[index + 1])
               for index in range(len(words) - 1)
               if words[index] & 0xFF == 0x18]
        assert imm == [MEM_IMM64_WORDS], (
            "executed %s must carry one exact ld_imm64 pair, got %r"
            % (tag, [[hex(part) for part in pair] for pair in imm],)
        )
        st = [word for word in words if word & 0x07 == 0x02]
        assert not st, (
            "executed %s must not select ST, got %r"
            % (tag, [hex(word) for word in st],)
        )
        memsx = [word for word in words
                 if word & 0xFF in MEM_MEMSX_OPS]
        assert not memsx, (
            "executed %s must not select v4 MEMSX, got %r"
            % (tag, [hex(word) for word in memsx],)
        )
        gate = [word for word in words if word & 0xFF == 0x25]
        assert gate == [MEM_GATE_WORD], (
            "executed %s must keep the byte-exact gate, got %r"
            % (tag, [hex(word) for word in gate],)
        )
        bad = [word for word in words if _r10_violation(word)]
        assert not bad, (
            "executed %s xdp must keep r10 read-only, got %r"
            % (tag, [hex(word) for word in bad],)
        )
    for tag, words, add in (
        ("base", base_text, MEM_CALLEE_ADD_BASE),
        ("mutant", mut_text, MEM_CALLEE_ADD_MUT),
    ):
        assert words == list(MEM_CALLEE_HEAD) + [add, 0x95], (
            "executed %s callee must keep the r1/r0 shape, got %r"
            % (tag, [hex(word) for word in words],)
        )
        bad = [word for word in words if _r10_violation(word)]
        assert not bad, (
            "executed %s callee must keep r10 read-only, got %r"
            % (tag, [hex(word) for word in bad],)
        )
    assert mut_text != base_text, "mutant callee bytes must differ"


def test_mem_base_returns_pass():
    record = executed()["results"]["base"]
    guest_proc.check_harness_exit(
        "base", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "mem base object must return XDP_PASS, got %r"
        % (record.get("actual_action"),)
    )


def test_mem_c_control_matches_base():
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


def test_mem_mutation_changes_action():
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


def test_mem_stale_object_fails():
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
                 "c_ref.bpf.o", "pkt_zero60.bin", "guest_isa_mem.sh"):
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
    "test_mem_stale_object_fails": (
        "test_mem_mutation_changes_action", "RUNTIME"
    ),
}

CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": [PACKET],
        "objects": [],
        "corpus": [PACKET],
    },
    "test_mem_base_returns_pass": {
        "sources": [BASE_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_mem_c_control_matches_base": {
        "sources": [C_SOURCE],
        "objects": [("stage", "c_ref.bpf.o")],
        "corpus": [PACKET],
    },
    "test_mem_guest_object_admits_words": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o")],
        "corpus": [],
    },
    "test_mem_mutation_changes_action": {
        "sources": [MUTATED_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [PACKET],
    },
    "test_mem_stale_object_fails": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_guest_provenance": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE, C_SOURCE, HARNESS,
                    ("stage", "guest_isa_mem.sh")],
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
    print("isa mem: guest behavior, C control, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
