# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/mem/pseudo-imm64: map pseudo references load.

Builds ``tests/compile/map_roundtrip.mojo`` (single-entry array
map round trip, expecting XDP_PASS) and its single-constant
mutant (+1 to +2 in the write-back, same action) through the
genuine parsed pipeline (``mojo build --emit llvm`` with the
SDK include -> ``mojobpf-lower --mode lower`` under the
linux-bpfel-v3 map profile, whose report's resolved llc flags
feed the backend -> ``llc -mtriple=bpfel``). Boots one guest per
lane and test-runs both objects plus a stock-C control and a
stale-object leg (base object against the DROP expectation,
which must fail at RUNTIME), with guest-side hash
re-verification of every staged byte. The staged objects' bytes
are decoded host-side to prove the file-level pseudo encoding
(src-0 ld_imm64 pairs + R_BPF_64_64 relocations), and each
object is loaded and its pinned program dumped (``bpftool prog
dump xlated``) to prove the loaded image carries exactly the
MAP_FD pseudo kind at both reference sites, with the +1/+2
add-immediate distinguishing base from mutant and no other
pseudo kind present. Map-cell value behavior stays owned by
the kernel-map suite (cited, not duplicated).

Standalone: ``python3 tests/kernel/test_pseudo_qual.py`` (exit 0 on
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

SUITE_ID = "kernel-isa-pseudo"
COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
BASE_SOURCE = os.path.join(COMPILE_DIR, "map_roundtrip.mojo")
MUTATED_SOURCE = os.path.join(COMPILE_DIR, "map_roundtrip_mutated.mojo")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources",
                           "sdk")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")
C_SOURCE = os.path.join(REPO_ROOT, "tests", "reference_c",
                        "map_roundtrip_ref.bpf.c")

XDP_DROP = 1
XDP_PASS = 2

# File-level pseudo encoding (observed from the genuine
# pipeline, decode-verified: 22 xdp slots, src-0 ld_imm64
# pairs at slots 4 and 16, one R_BPF_64_64 relocation per
# pair against mojobpf_map0, single-word mutant diff at slot
# 10: ADD64-K r1, 1 vs 2).
PSEUDO_SLOTS = 22
PSEUDO_PAIR_SLOTS = (4, 16)
PSEUDO_PAIR_WORD = 0x118
PSEUDO_RELOCS = ((32, 1, "mojobpf_map0"), (128, 1, "mojobpf_map0"))
PSEUDO_MUT_SLOT = 10
PSEUDO_ADD_BASE = 0x0100000107
PSEUDO_ADD_MUT = 0x0200000107
# Loaded-image pins (frozen at RED from the pinned bpftool's
# observed text dump; its -j JSON carries disasm strings only,
# so text is the pinned surface): the verifier inlines the
# array lookup (bias +6/264, bounds check, shift) and both
# reference sites load as `(18) r1 = map[id:N]` at pcs 4/22;
# the write-back add (pc 16) is 1 vs 2. Post-load xlated cannot
# distinguish MAP_FD from MAP_IDX (both render map[id] and both
# yield CONST_PTR_TO_MAP); the FD specificity is the loader's
# (fresh R_BPF_64_64 resolution writes BPF_PSEUDO_MAP_FD), and
# the suite additionally rules out VALUE (+off) and BTF_ID
# (ksym) forms by exact-line match.
PSEUDO_DUMP_SITES = ((4, "(18) r1 = map[id:N]"),
                     (22, "(18) r1 = map[id:N]"))
PSEUDO_DUMP_ADD_BASE = [(6, 264), (16, 1)]
PSEUDO_DUMP_ADD_MUT = [(6, 264), (16, 2)]


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


# (tag, object key, expected action, want harness exit). The
# mutant keeps the action (only the write-back constant moves);
# the mutation proof lives in the dump add-immediate.
CASES = (
    ("base", "base.bpf.o", XDP_PASS, 0),
    ("cref", "c_ref.bpf.o", XDP_PASS, 0),
    ("mut", "mutated.bpf.o", XDP_PASS, 0),
    ("stale", "base.bpf.o", XDP_DROP, 1),
)

# (dump tag, object key) for the loaded-image pseudo decode.
DUMP_CASES = (
    ("dump-base", "base.bpf.o"),
    ("dump-cref", "c_ref.bpf.o"),
    ("dump-mut", "mutated.bpf.o"),
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
            "cpu": "v3", "features": "",
            "map": {"symbol": "mojobpf_map0", "type": 2,
                    "key_bits": 32, "value_bits": 64,
                    "max_entries": 1, "flags": 0}}


@guest_proc.consumes_source
def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(["mojo", "build", "--emit", "llvm",
                     *FRONTEND_TARGET_FLAGS, "-I", SDK_INCLUDE,
                     "-o", raw_path, source])
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
echo "=== begin guest_isa_pseudo ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o c_ref.bpf.o data.bin guest_isa_pseudo.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-pseudo-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-pseudo-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-pseudo-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-pseudo-$tag.stdout 2>/tmp/isa-pseudo-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-pseudo-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
dump_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf-isa-pseudo-$tag"
  mkdir -p "$pin"
  "$BPFTOOL" prog load "$obj" "$pin/prog" >/tmp/isa-pseudo-$tag.load 2>&1
  code=$?
  "$BPFTOOL" prog dump xlated pinned "$pin/prog" >/tmp/isa-pseudo-$tag.xlated 2>&1
  "$BPFTOOL" prog show pinned "$pin/prog" >/tmp/isa-pseudo-$tag.show 2>&1
  rm -f "$pin/prog"
  rmdir "$pin" 2>/dev/null
  python3 - "$tag" "$code" <<'PYEOF'
import json
import sys
tag, code = sys.argv[1], int(sys.argv[2])
def slurp(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()
record = {{
  "load_exit": code,
  "xlated": slurp("/tmp/isa-pseudo-%s.xlated" % tag),
  "show": slurp("/tmp/isa-pseudo-%s.show" % tag),
  "load_log": slurp("/tmp/isa-pseudo-%s.load" % tag)[-2000:],
}}
with open("/tmp/isa-pseudo-%s.json" % tag, "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, indent=2, sort_keys=True) + chr(10))
PYEOF
  echo "=== BEGIN $tag exit=$code ==="
  cat "/tmp/isa-pseudo-$tag.json"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-pseudo-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_pseudo ==="
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
    for path in (BASE_SOURCE, MUTATED_SOURCE, C_SOURCE, HARNESS,
                 SDK_INCLUDE):
        if not os.path.exists(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    stage = guest_proc.owned_stage(prefix="mojo-isa-pseudo-", dir="/tmp")
    packet = bytes(60)
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(packet)
    base_obj = build_object(BASE_SOURCE, stage, "base")
    mutated_obj = build_object(MUTATED_SOURCE, stage, "mutated")
    c_obj = build_c(C_SOURCE, stage)
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": base_obj,
        "mutated.bpf.o": mutated_obj,
        "c_ref.bpf.o": c_obj,
    }
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, expect, _ in CASES:
        commands.append(
            "run_case %s %s %d data.bin" % (tag, obj, expect)
        )
    for tag, obj in DUMP_CASES:
        commands.append("dump_case %s %s" % (tag, obj))
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
            ownership_token="mojobpf-isa-pseudo-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_pseudo.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_isa_pseudo.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("data.bin", "guest_isa_pseudo.sh"),
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
        progress_banner="=== begin guest_isa_pseudo ===",
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
    missing += [tag for tag, _ in DUMP_CASES if tag not in results]
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
    run = executed()
    staged = os.path.join(run["stage"], "data.bin")
    with open(staged, "rb") as handle:
        frame = handle.read()
    assert len(frame) == 60, "staged input has %d bytes" % len(frame)
    assert frame == bytes(60), "staged input must be zero bytes"
    assert run["packet"] == frame


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


def _staged_relocs(stage, name, rel_section):
    with open(os.path.join(stage, name), "rb") as handle:
        data = handle.read()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    sections = {}
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        sections[data[base + row[0]:end].decode()] = row
    row = sections[rel_section]
    blob = data[row[4]:row[4] + row[5]]
    assert len(blob) % 16 == 0
    symtab = sections[".symtab"]
    strtab = sections[".strtab"]
    syms = data[symtab[4]:symtab[4] + symtab[5]]
    strings = data[strtab[4]:strtab[4] + strtab[5]]
    assert len(syms) % 24 == 0
    entries = []
    for index in range(len(syms) // 24):
        st_name = struct.unpack_from("<I", syms, index * 24)[0]
        end = strings.index(b"\x00", st_name)
        entries.append(strings[st_name:end].decode())
    return [(offset, info & 0xFFFFFFFF, entries[info >> 32])
            for offset, info in struct.iter_unpack("<QQ", blob)]


def test_pseudo_guest_object_admits_pairs():
    stage = executed()["stage"]
    base_xdp = _staged_section_words(stage, "base.bpf.o", "xdp")
    mut_xdp = _staged_section_words(stage, "mutated.bpf.o", "xdp")
    diffs = [(index, base, mut)
             for index, (base, mut) in enumerate(zip(base_xdp, mut_xdp))
             if base != mut]
    assert len(base_xdp) == len(mut_xdp) == PSEUDO_SLOTS, (
        "staged objects must carry %d xdp slots, got %d/%d"
        % (PSEUDO_SLOTS, len(base_xdp), len(mut_xdp)))
    assert diffs == [(PSEUDO_MUT_SLOT, PSEUDO_ADD_BASE,
                      PSEUDO_ADD_MUT)], (
        "mutant must differ only at slot %d, got %r"
        % (PSEUDO_MUT_SLOT,
           [(index, hex(base), hex(mut))
            for index, base, mut in diffs],))
    for tag, words in (("base", base_xdp), ("mutant", mut_xdp)):
        pairs = [index for index, word in enumerate(words)
                 if word & 0xFF == 0x18]
        assert pairs == list(PSEUDO_PAIR_SLOTS), (
            "staged %s must carry pairs at %r, got %r"
            % (tag, list(PSEUDO_PAIR_SLOTS), pairs))
        for slot in pairs:
            assert words[slot] == PSEUDO_PAIR_WORD, (
                "staged %s pair at %d must be src-0/imm-0, got %#x"
                % (tag, slot, words[slot]))
            assert words[slot + 1] == 0, (
                "staged %s pair high half at %d must be zero, got %#x"
                % (tag, slot, words[slot + 1]))
        obj = "base.bpf.o" if tag == "base" else "mutated.bpf.o"
        relocs = _staged_relocs(stage, obj, ".relxdp")
        assert relocs == list(PSEUDO_RELOCS), (
            "staged %s must carry exactly the map relocs, got %r"
            % (tag, relocs))
        assert [slot for slot, _, _ in
                [(off // 8, typ, sym) for off, typ, sym in relocs]
                ] == pairs, (
            "staged %s relocs must sit on the pair slots" % (tag,))
        movs = [word for word in words
                if word & 0xFF in (0xBF, 0xBC)
                and (word >> 12) & 0xF == 0xA]
        assert movs == [0xA2BF, 0xA2BF, 0xA3BF], (
            "staged %s must copy the frame pointer exactly "
            "thrice (key/value slots), got %r"
            % (tag, [hex(word) for word in movs],))
        bad = [word for word in words
               if _r10_violation(word) and word not in movs]
        assert not bad, (
            "staged %s xdp must keep r10 read-only outside "
            "frame-pointer copies, got %r"
            % (tag, [hex(word) for word in bad],)
        )


def test_pseudo_base_returns_pass():
    record = executed()["results"]["base"]
    guest_proc.check_harness_exit(
        "base", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "pseudo base object must return XDP_PASS, got %r"
        % (record.get("actual_action"),)
    )


def test_pseudo_c_control_matches_base():
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


def test_pseudo_mutation_changes_add():
    run = executed()
    record = run["results"]["mut"]
    guest_proc.check_harness_exit(
        "mut", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "mutant must keep the action, got %r"
        % (record.get("actual_action"),))
    base_add = _dump_add_lines(
        run["results"]["dump-base"]["xlated"])
    mut_add = _dump_add_lines(run["results"]["dump-mut"]["xlated"])
    assert base_add == PSEUDO_DUMP_ADD_BASE, (
        "base dump add lines moved, got %r" % (base_add,))
    assert mut_add == PSEUDO_DUMP_ADD_MUT, (
        "mutant dump add lines moved, got %r" % (mut_add,))
    assert mut_add != base_add, (
        "rebuilt mutant must change the dumped add-immediate")


def _dump_map_sites(xlated):
    # [(pc, normalized line)] for every map reference; the map
    # id is load-dynamic, so it normalizes to map[id:N].
    sites = []
    for match in re.finditer(r"^\s*(\d+):(.*map\[.*)$", xlated,
                             re.MULTILINE):
        line = re.sub(r"map\[id:\d+\]", "map[id:N]", match.group(2))
        sites.append((int(match.group(1)), line.strip()))
    return sites


def _dump_add_lines(xlated):
    # [(pc, value)] of every r1 add-immediate: the verifier's
    # array-value bias plus the write-back constant (the mutant
    # split). Pcs are loader/verifier-placed.
    return [(int(match.group(1)), int(match.group(2)))
            for match in re.finditer(
                r"^\s*(\d+):\s*\(07\)\s*r1\s*\+=\s*(\d+)\s*$",
                xlated, re.MULTILINE)]


def test_pseudo_dump_carries_map_fd():
    run = executed()
    for tag in ("dump-base", "dump-cref", "dump-mut"):
        record = run["results"][tag]
        assert record["load_exit"] == 0, (
            "%s: bpftool load must succeed, log tail:\n%s"
            % (tag, record.get("load_log", "")))
        print("=== %s xlated ===\n%s" % (tag, record["xlated"]))
        print("=== %s show ===\n%s" % (tag, record["show"]))
        assert "ksym" not in record["xlated"], (
            "%s: no BTF_ID kind may appear" % (tag,))
    for tag in ("dump-base", "dump-cref", "dump-mut"):
        sites = _dump_map_sites(run["results"][tag]["xlated"])
        assert sites == list(PSEUDO_DUMP_SITES), (
            "%s: loaded image must carry exactly the MAP_FD "
            "sites, got %r" % (tag, sites))
    for tag in ("dump-base", "dump-cref", "dump-mut"):
        record = run["results"][tag]
        shown = re.search(r"map_ids\s+([\d,]+)", record["show"])
        assert shown, (
            "%s: prog show must list map_ids:\n%s"
            % (tag, record["show"]))
        owned = set(shown.group(1).split(","))
        for match in re.finditer(r"map\[id:(\d+)\]",
                                 record["xlated"]):
            assert match.group(1) in owned, (
                "%s: dumped map id %s is not owned by the load"
                % (tag, match.group(1)))


def test_pseudo_stale_object_fails():
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
                 "c_ref.bpf.o", "data.bin", "guest_isa_pseudo.sh"):
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
    "test_pseudo_stale_object_fails": (
        "test_pseudo_mutation_changes_add", "RUNTIME"
    ),
}

CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": [],
        "objects": [],
        "corpus": [("stage", "data.bin")],
    },
    "test_pseudo_base_returns_pass": {
        "sources": [BASE_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_pseudo_c_control_matches_base": {
        "sources": [C_SOURCE],
        "objects": [("stage", "c_ref.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_pseudo_guest_object_admits_pairs": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o")],
        "corpus": [],
    },
    "test_pseudo_dump_carries_map_fd": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE, C_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "c_ref.bpf.o")],
        "corpus": [],
    },
    "test_pseudo_mutation_changes_add": {
        "sources": [MUTATED_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_pseudo_stale_object_fails": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_guest_provenance": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE, C_SOURCE, HARNESS,
                    ("stage", "guest_isa_pseudo.sh")],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "c_ref.bpf.o")],
        "corpus": [("stage", "data.bin")],
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
    print("isa pseudo: guest behavior, C control, dump decode, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
