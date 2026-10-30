# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the parse/checksum-SDK programs.

Builds every ``tests/compile/{parse,checksum}_*.mojo`` fixture through
the genuine pipeline (``mojo build --emit llvm`` with the packaged SDK
on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and asserts three things. First, each
fixture passes the unmodified adapter audit as the classifier shape
(the audit file itself is untouched: the parse/checksum programs reuse
the single-reinterpretation shape). Second, each object is a minimal
single-entrypoint BPF relocatable: EM_BPF machine type, exactly one
executable section holding exactly one function (``xdp_entry``), the
exact license bytes, no call instructions, no code relocations, and
no undefined symbols. Third, no packet dereference is unguarded: in
each positive fixture's IR, every load fed by the reinterpreted
packet address is covered by a length guard of sufficient need whose
tripped branch returns XDP_DROP (1). The truncated-header shape
carries two start-based guards (14 and 18 bytes) and each is checked
separately, including that the bytes-16-17 loads are covered only by
the second guard. The checksum shape additionally carries the genuine
fold-and-complement arithmetic (two carry folds plus the final
complement) rather than a constant digest.

The pre-existing unguarded packet fixture serves as the negative
control without adding new files: it carries packet loads with no
guard pattern at all, proving the check discriminates (the kernel
suite for the packet slice proves the verifier then rejects that
object at load).

The IR guard coverage here and the in-kernel verifier acceptance in
``tests/kernel/test_parse_checksum_sdk.py`` together establish that no
unguarded packet dereference reaches the kernel.

Requires a working Mojo compiler and LLVM ``llc`` on PATH (for
example the project pixi environment plus system LLVM). A missing
tool is reported as an environment failure; a failing frontend,
adapter, or backend step is a proof failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_parse_struct.py``) or
under any ``test_``-style runner. Standard library only.
"""

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
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
import audit  # noqa: E402

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_REL = 9
SHT_RELA = 4
SHN_UNDEF = 0
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"

SSA = r"%?[A-Za-z0-9_.$-]+"
DEFINE_RE = re.compile(r"^define\s+\S+\s+i32\s+@xdp_entry\(ptr[^)]*\)")
ASM_RE = re.compile(r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+\"\",\s*\"=r,0\"")
GEP_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*getelementptr\b.*?\bptr\s+("
    + SSA
    + r")\s*,\s*(.*)$"
)
LOAD_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*load\s+(i\d+),\s*ptr\s+(" + SSA + r")"
)
ICMP_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*icmp\s+ugt\s+i64\s+("
    + SSA
    + r")\s*,\s*("
    + SSA
    + r")"
)
ADD_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*add\s+i64\s+("
    + SSA
    + r")\s*,\s*("
    + SSA
    + r")"
)
BRCOND_RE = re.compile(
    r"^br\s+i1\s+("
    + SSA
    + r")\s*,\s*label\s+("
    + SSA
    + r")\s*,\s*label\s+("
    + SSA
    + r")"
)
LABEL_RE = re.compile(r"^%?([A-Za-z0-9_.$-]+):$")
FOLD_RE = re.compile(r"^%\S+\s*=\s*lshr\s+i32\s+\S+,\s*16$")
COMPLEMENT_RE = re.compile(r"^%\S+\s*=\s*xor\s+i16\s+\S+,\s*-1$")
ADD32_RE = re.compile(r"^%\S+\s*=\s*add\s+i32\s+")

# Positive shape -> (guard need, maximum covered byte offset). The
# two-tier shape uses two start-based guards and is checked
# separately; every shape below uses one constant need.
SHAPES = {
    "parse_eth": (14, 13),
    "parse_vlan": (18, 17),
    "checksum_window": (24, 23),
}
# Two-tier shape -> (sorted guard needs, loads needing only the first
# guard, loads needing the second guard).
TWO_TIER_SHAPE = "parse_trunc"
TWO_TIER_NEEDS = (14, 18)
TWO_TIER_FIRST = (12, 13)
TWO_TIER_SECOND = (16, 17)
CHECKSUM_SHAPE = "checksum_window"
# Negative control: the pre-existing unguarded packet fixture (no new
# files). It must carry packet loads with zero guard patterns.
NEG_SHAPE = "packet_unguarded"


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def build_shape(name):
    """Run the genuine three-step build; return (raw_ir, adapted, image)."""
    source = os.path.join(COMPILE_DIR, name + ".mojo")
    if not os.path.isfile(source):
        raise EnvironmentFailure("missing fixture: %s" % source)
    workdir = tempfile.mkdtemp(prefix="mojo-parse-elf-")
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
            "frontend reported diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    with open(raw_path, "r", encoding="utf-8") as handle:
        raw_ir = handle.read()
    try:
        mode = audit.validate(raw_ir)
    except audit.AuditError as exc:
        raise AssertionError(
            "frozen audit rejected %s: %s" % (source, exc)
        )
    assert mode == "classifier", (
        "%s must validate as the classifier shape, got %r" % (source, mode)
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
    with open(adapted_path, "r", encoding="utf-8") as handle:
        adapted = handle.read()
    with open(object_path, "rb") as handle:
        image = handle.read()
    return raw_ir, adapted, image


_CACHED = {}


def built(name):
    if name not in _CACHED:
        for tool in ("mojo", "llc"):
            if shutil.which(tool) is None:
                raise EnvironmentFailure("%s not found on PATH" % tool)
        if not os.path.isdir(SDK_INCLUDE):
            raise EnvironmentFailure("missing SDK dir: %s" % SDK_INCLUDE)
        if not os.path.isfile(ADAPTER):
            raise EnvironmentFailure("missing adapter: %s" % ADAPTER)
        _CACHED[name] = build_shape(name)
    return _CACHED[name]


def all_shapes():
    return list(SHAPES) + [TWO_TIER_SHAPE, NEG_SHAPE]


def parse_elf(image):
    """Parse headers/sections/symbols; return string-keyed facts."""
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
    ei_class, ei_data = image[4], image[5]
    (e_type, e_machine, _e_version) = struct.unpack_from("<HHI", image, 16)
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, sh_flags, _sh_addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        (sh_link, sh_info, _sh_align, sh_entsize) = struct.unpack_from(
            "<IIQQ", image, off + 40
        )
        sections.append(
            {
                "index": index,
                "name_off": sh_name,
                "type": sh_type,
                "flags": sh_flags,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "info": sh_info,
                "entsize": sh_entsize,
            }
        )
    strtab = sections[e_shstrndx]
    strbase = strtab["offset"]
    for section in sections:
        end = image.index(b"\x00", strbase + section["name_off"])
        section["name"] = image[
            strbase + section["name_off"] : end
        ].decode("ascii")
    symbols = []
    for section in sections:
        if section["name"] != ".symtab":
            continue
        count = section["size"] // 24
        strsec = sections[section["link"]]
        for i in range(count):
            off = section["offset"] + i * 24
            (st_name, st_info, _st_other, st_shndx, _st_value, _st_size) = (
                struct.unpack_from("<IBBHQQ", image, off)
            )
            end = image.index(b"\x00", strsec["offset"] + st_name)
            name = image[strsec["offset"] + st_name : end].decode("ascii")
            symbols.append(
                {"name": name, "type": st_info & 0xF, "shndx": st_shndx}
            )
    return {
        "class": ei_class,
        "data": ei_data,
        "type": e_type,
        "machine": e_machine,
        "sections": sections,
        "symbols": symbols,
        "image": image,
    }


def section_bytes(elf, section):
    return elf["image"][section["offset"] : section["offset"] + section["size"]]


def body_lines(ir_text):
    """Comment-stripped body lines between define and close."""
    lines = []
    in_body = False
    for raw in ir_text.splitlines():
        line = audit.strip_comment(raw).strip()
        if line.startswith("define "):
            in_body = True
            continue
        if line == "}":
            in_body = False
            continue
        if in_body and line and not line.startswith("!"):
            lines.append(line)
    return lines


def packet_loads(lines):
    """Loads fed by the reinterpreted packet address.

    Returns (asm_count, [(ssa, width_bits, const_offset_or_None)]):
    the reinterpretation count plus every load whose pointer operand
    is the reinterpretation result or a constant-indexed GEP rooted
    at it (a variable GEP index reports None).
    """
    roots = set()
    asm_count = 0
    for line in lines:
        match = ASM_RE.match(line)
        if match:
            asm_count += 1
            roots.add("%" + match.group(1))
    gep_index = {}
    changed = True
    while changed:
        changed = False
        for line in lines:
            match = GEP_RE.match(line)
            if not match:
                continue
            _name, base, operands = match.groups()
            if base not in roots:
                continue
            target = "%" + match.group(1)
            if target in roots:
                continue
            roots.add(target)
            changed = True
            parts = [part.strip() for part in operands.split(",")]
            index = None
            if parts:
                atoms = parts[-1].split()
                if len(atoms) == 2 and atoms[1].lstrip("-").isdigit():
                    try:
                        index = int(atoms[1])
                    except ValueError:
                        index = None
            gep_index[target] = index
    loads = []
    for line in lines:
        match = LOAD_RE.match(line)
        if match and "%" + match.group(3).lstrip("%") in roots:
            width = int(match.group(2)[1:])
            operand = "%" + match.group(3).lstrip("%")
            loads.append((match.group(1), width, gep_index.get(operand, 0)))
    return asm_count, loads


def const_guards(lines):
    """Start-based guards: (need, cond_ssa, true_label) per guard."""
    adds = {}
    for line in lines:
        match = ADD_RE.match(line)
        if match:
            _name, left, right = match.groups()
            for token in (left, right):
                if token.lstrip("-").isdigit():
                    adds["%" + match.group(1)] = int(token)
    guards = []
    for line in lines:
        match = ICMP_RE.match(line)
        if match and "%" + match.group(2).lstrip("%") in adds:
            guards.append(
                (adds["%" + match.group(2).lstrip("%")], match.group(1), None)
            )
    branches = {}
    for line in lines:
        match = BRCOND_RE.match(line)
        if match:
            branches[match.group(1).lstrip("%")] = match.group(2)
    resolved = []
    for need, cond, _ in guards:
        resolved.append((need, cond, branches.get(cond)))
    return resolved


def guard_returns_drop(lines, cond, true_label):
    """The guard's tripped branch must return XDP_DROP (1)."""
    assert cond is not None and true_label is not None, (
        "guard compare has no conditional branch"
    )
    blocks = {}
    current = None
    for line in lines:
        match = LABEL_RE.match(line)
        if match:
            current = match.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    target = true_label.lstrip("%")
    assert target in blocks, "guard target block %%%s missing" % target
    assert len(blocks[target]) == 1 and blocks[target][0].startswith("br "), (
        "guard block %%%s must only forward, got %r" % (target, blocks[target])
    )
    dest = blocks[target][0].split()[-1].lstrip("%")
    assert dest in blocks, "guard exit block %%%s missing" % dest
    for line in blocks[dest]:
        if line.startswith("%") and " phi " in line:
            assert ("[ 1, %%%s ]" % target) in line, (
                "guard exit must return 1 on the tripped path: %r" % line
            )
            return
    raise AssertionError("guard exit block %%%s has no phi" % dest)


def test_entry_signatures():
    for name in all_shapes():
        raw_ir, _, _ = built(name)
        defines = [
            line.strip()
            for line in raw_ir.splitlines()
            if line.strip().startswith("define ")
        ]
        assert len(defines) == 1, "%s: %d defines" % (name, len(defines))
        assert DEFINE_RE.match(defines[0]), (
            "%s: entry is not i32 @xdp_entry(ptr...): %r" % (name, defines[0])
        )


def test_machine_and_layout():
    for name in all_shapes():
        _, _, image = built(name)
        elf = parse_elf(image)
        assert elf["class"] == 2, "%s: not 64-bit" % name
        assert elf["data"] == 1, "%s: not little-endian" % name
        assert elf["type"] == ET_REL, "%s: not relocatable" % name
        assert elf["machine"] == EM_BPF, "%s: not EM_BPF" % name


def test_single_entrypoint():
    for name in all_shapes():
        _, _, image = built(name)
        elf = parse_elf(image)
        by_name = {s["name"]: s for s in elf["sections"]}
        assert "xdp" in by_name, "%s: missing xdp section" % name
        assert "license" in by_name, "%s: missing license section" % name
        executable = [
            s
            for s in elf["sections"]
            if s["flags"] & SHF_EXECINSTR and s["size"] > 0
        ]
        assert [s["name"] for s in executable] == ["xdp"], (
            "%s: executable sections must be [xdp], got %r"
            % (name, [s["name"] for s in executable])
        )
        xdp = by_name["xdp"]
        assert xdp["size"] > 0 and xdp["size"] % 8 == 0, (
            "%s: bad xdp size %d" % (name, xdp["size"])
        )
        funcs = [
            s
            for s in elf["symbols"]
            if s["type"] == 2 and s["shndx"] != SHN_UNDEF
        ]
        assert [(f["name"], f["shndx"]) for f in funcs] == [
            ("xdp_entry", xdp["index"])
        ], "%s: expected only xdp_entry, got %r" % (name, funcs)
        assert section_bytes(elf, by_name["license"]) == LICENSE_BYTES, (
            "%s: license bytes mismatch" % name
        )


def test_no_runtime_calls():
    for name in all_shapes():
        _, _, image = built(name)
        elf = parse_elf(image)
        by_name = {s["name"]: s for s in elf["sections"]}
        code = section_bytes(elf, by_name["xdp"])
        opcodes = [code[i] for i in range(0, len(code), 8)]
        assert BPF_OP_CALL not in opcodes, "%s: call present" % name
        assert BPF_OP_EXIT in opcodes, "%s: no exit" % name
        undefined = [
            s["name"] for s in elf["symbols"] if s["shndx"] == SHN_UNDEF
        ]
        undefined = [sym for sym in undefined if sym]
        assert not undefined, "%s: undefined %s" % (name, undefined)
        for section in elf["sections"]:
            if section["type"] in (SHT_REL, SHT_RELA):
                assert section["info"] != by_name["xdp"]["index"], (
                    "%s: %s relocates xdp" % (name, section["name"])
                )


def test_guarded_loads():
    for name, (need, maxoff) in sorted(SHAPES.items()):
        _, adapted, _ = built(name)
        lines = body_lines(adapted)
        asm_count, loads = packet_loads(lines)
        assert asm_count == 1, "%s: %d reinterprets" % (name, asm_count)
        assert loads, "%s: no packet loads found" % name
        for _ssa, width, offset in loads:
            assert offset is not None, "%s: variable packet offset" % name
            assert 0 <= offset and offset + width // 8 <= need, (
                "%s: load at %d width %d exceeds guard need %d"
                % (name, offset, width // 8, need)
            )
        assert max(off for _, _, off in loads) == maxoff, (
            "%s: expected a load at %d" % (name, maxoff)
        )
        guards = const_guards(lines)
        assert len(guards) == 1, "%s: %d start guards" % (name, len(guards))
        found, cond, true_label = guards[0]
        assert found == need, "%s: guard need %d" % (name, found)
        guard_returns_drop(lines, cond, true_label)


def test_two_tier_guard():
    name = TWO_TIER_SHAPE
    _, adapted, _ = built(name)
    lines = body_lines(adapted)
    asm_count, loads = packet_loads(lines)
    assert asm_count == 1, "%s: %d reinterprets" % (name, asm_count)
    assert loads, "%s: no packet loads found" % name
    offsets = sorted(off for _, _, off in loads)
    assert all(off is not None for _, _, off in loads), (
        "%s: variable packet offset" % name
    )
    for _ssa, width, offset in loads:
        assert width == 8, "%s: expected byte loads, got %d" % (name, width)
    assert offsets == sorted(TWO_TIER_FIRST + TWO_TIER_SECOND), (
        "%s: expected loads at %r, got %r"
        % (name, sorted(TWO_TIER_FIRST + TWO_TIER_SECOND), offsets)
    )
    guards = const_guards(lines)
    needs = sorted(need for need, _, _ in guards)
    assert needs == sorted(TWO_TIER_NEEDS), (
        "%s: expected guard needs %r, got %r"
        % (name, sorted(TWO_TIER_NEEDS), needs)
    )
    for need, cond, true_label in guards:
        guard_returns_drop(lines, cond, true_label)
    # The second guard is load-bearing: the bytes-16-17 loads fit only
    # under the 18-byte need, while the bytes-12-13 loads fit under 14.
    first_need, second_need = TWO_TIER_NEEDS
    for offset in TWO_TIER_FIRST:
        assert offset + 1 <= first_need, (
            "%s: load at %d exceeds the first guard" % (name, offset)
        )
    for offset in TWO_TIER_SECOND:
        assert offset + 1 > first_need, (
            "%s: load at %d fits under the first guard" % (name, offset)
        )
        assert offset + 1 <= second_need, (
            "%s: load at %d exceeds the second guard" % (name, offset)
        )


def test_checksum_arithmetic_present():
    _, adapted, _ = built(CHECKSUM_SHAPE)
    lines = body_lines(adapted)
    adds = [line for line in lines if ADD32_RE.match(line)]
    folds = [line for line in lines if FOLD_RE.match(line)]
    complements = [line for line in lines if COMPLEMENT_RE.match(line)]
    assert len(adds) >= 4, (
        "%s: expected accumulation adds, got %d" % (CHECKSUM_SHAPE, len(adds))
    )
    assert len(folds) >= 2, (
        "%s: expected two carry folds, got %d"
        % (CHECKSUM_SHAPE, len(folds))
    )
    assert len(complements) >= 1, (
        "%s: expected the final complement" % CHECKSUM_SHAPE
    )


def test_unguarded_has_loads_but_no_guard():
    _, adapted, _ = built(NEG_SHAPE)
    lines = body_lines(adapted)
    asm_count, loads = packet_loads(lines)
    assert asm_count == 1, "%s: %d reinterprets" % (NEG_SHAPE, asm_count)
    assert loads, "%s: negative must still carry packet loads" % NEG_SHAPE
    assert not const_guards(lines), "%s: negative must lack guards" % NEG_SHAPE


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
    print("parse struct: object layout and guard coverage checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
