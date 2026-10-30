# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built tracepoint counter object.

Builds ``examples/tracepoint_counter/counter.mojo`` through the
genuine pipeline (``mojo build --emit llvm`` with the packaged SDK
on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and asserts the resulting object
is a conventional BPF relocatable for one tracepoint program:
EM_BPF machine type, exactly one executable section
(``tracepoint/syscalls/sys_enter_getpid``) holding exactly one
function (``trace_entry``), the exact license bytes, helper calls
[1, 14, 1, 2] in order (filter lookup, current-PID/TID, count
lookup, count update), the qualified add-immediate multiset
[-16, -4, -4, -4, 1], three map relocations against the ``.maps``
symbol, a 32-byte all-zero ``.maps`` section, and map BTF
describing a two-entry array map with u32 keys and u64 values.
The BTF blob is compared byte-for-byte against the adapter's
fixed two-entry block and cross-checked against ``bpftool btf
dump`` plus the public map-spec readers.

Also covers the TGID mutant
(``examples/tracepoint_counter/counter_tgid_mutated.mojo``): same
section, calls, immediates, map, and BTF, but different program
bytes (arithmetic shift instead of the low-32 mask), so the
mutant is proven shape-clean yet behaviorally distinct.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool`` on
PATH. A missing tool is reported as an environment failure; a
failing frontend, adapter, or backend step is a proof failure.
Neither ever passes.

Runnable directly (``python3 tests/elf/test_tracepoint_struct.py``)
or under any ``test_``-style runner. Standard library only.
"""

import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import mojo_ir_adapter as adapter  # noqa: E402
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
from mojobpf.inspect import (  # noqa: E402
    object_map_names,
    object_map_specs,
)

COUNTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "counter.mojo"
)
MUTANT_SOURCE = os.path.join(
    REPO_ROOT,
    "examples",
    "tracepoint_counter",
    "counter_tgid_mutated.mojo",
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Independent direct-path pins for the committed counter. The
# build-driver suite pins the same bytes through build_project;
# both paths must agree.
TRACEPOINT_RAW_HASH = (
    "0a7cbc6a1bae8aaf2c14792e1659700b3102040d1ed81c6f941c1adeeddfe9c7"
)
TRACEPOINT_ADAPTED_HASH = (
    "689cd2079b109b9448f9e9ea543c6c077abe32b3f1185c2e69999573dadad4fe"
)
TRACEPOINT_OBJECT_HASH = (
    "b687af78c3056e2299929cd635044875f8369f9ca6e27f626c4f55c4def8b67a"
)
MUTANT_OBJECT_HASH = (
    "05414e1da026919dd91d69485992533f87eb4c7ce16b167b73f3a94c001eae5c"
)

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_REL = 9
SHN_UNDEF = 0
STB_GLOBAL = 1
STT_OBJECT = 1
STT_FUNC = 2
BPF_OP_ADD_IMM = 0x07
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
R_BPF_64_64 = 1
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
TRACEPOINT_SECTION = "tracepoint/syscalls/sys_enter_getpid"
ENTRY_SYMBOL = "trace_entry"
MAP_SYMBOL = "mojobpf_map0"
MAP_SECTION_SIZE = 32
EXPECTED_CALLS = [1, 14, 1, 2]
EXPECTED_IMMS = [-16, -4, -4, -4, 1]


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


def check_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def build_object(source):
    """Build one source through the genuine pipeline.

    Returns (raw_ir, adapted_ir, image). The frontend must be
    silent on stderr; any nonzero step is a proof failure.
    """
    workdir = tempfile.mkdtemp(prefix="mojo-tracepoint-")
    raw_path = os.path.join(workdir, "raw.ll")
    adapted_path = os.path.join(workdir, "adapted.ll")
    object_path = os.path.join(workdir, "prog.o")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS,
            "-I", SDK_INCLUDE, "-o", raw_path, source,
        ]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "frontend failed for %s: %s" % (source, proc.stderr[-2000:])
        )
    if proc.stderr != "":
        raise AssertionError(
            "frontend stderr must be empty, got %r" % proc.stderr[:500]
        )
    proc = run_step(
        [
            sys.executable, ADAPTER,
            "--input", raw_path, "--output", adapted_path,
        ]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "adapter failed for %s: %s%s"
            % (source, proc.stdout[-1000:], proc.stderr[-1000:])
        )
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
            adapted_path, "-o", object_path,
        ]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "backend failed for %s: %s" % (source, proc.stderr[-2000:])
        )
    with open(raw_path, "r", encoding="utf-8") as handle:
        raw_ir = handle.read()
    with open(adapted_path, "r", encoding="utf-8") as handle:
        adapted_ir = handle.read()
    with open(object_path, "rb") as handle:
        image = handle.read()
    return raw_ir, adapted_ir, image, object_path


def parse_elf(image):
    """Parse headers/sections/relocations/symbols; return facts."""
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
    (e_type, e_machine, _e_version) = struct.unpack_from("<HHI", image, 16)
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
        "<HHH", image, 58
    )
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, sh_flags, _addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        sections.append(
            {
                "index": index,
                "name_off": sh_name,
                "type": sh_type,
                "flags": sh_flags,
                "offset": sh_offset,
                "size": sh_size,
            }
        )
    strtab = sections[e_shstrndx]
    blob = image[strtab["offset"]:strtab["offset"] + strtab["size"]]
    for section in sections:
        end = blob.index(b"\x00", section["name_off"])
        section["name"] = blob[
            section["name_off"]:end
        ].decode("ascii")
    symbols = []
    for section in sections:
        if section["name"] != ".symtab":
            continue
        count = section["size"] // 24
        link_off = (
            e_shoff + section["index"] * e_shentsize + 40
        )
        (link,) = struct.unpack_from("<I", image, link_off)
        strsec = sections[link]
        strblob = image[
            strsec["offset"]:strsec["offset"] + strsec["size"]
        ]
        for ordinal in range(count):
            off = section["offset"] + ordinal * 24
            (st_name, st_info, _other, st_shndx, _v, _s) = (
                struct.unpack_from("<IBBHQQ", image, off)
            )
            end = strblob.index(b"\x00", st_name)
            symbols.append(
                {
                    "name": strblob[st_name:end].decode("ascii"),
                    "bind": st_info >> 4,
                    "type": st_info & 0xF,
                    "shndx": st_shndx,
                }
            )
    relocations = []
    for section in sections:
        if section["type"] != SHT_REL:
            continue
        count = section["size"] // 16
        link_off = (
            e_shoff + section["index"] * e_shentsize + 40
        )
        (link,) = struct.unpack_from("<I", image, link_off)
        for ordinal in range(count):
            off = section["offset"] + ordinal * 16
            (r_offset, r_info) = struct.unpack_from("<QQ", image, off)
            relocations.append(
                {
                    "section": section["name"],
                    "offset": r_offset,
                    "sym": r_info >> 32,
                    "type": r_info & 0xFFFFFFFF,
                    "symtab_link": link,
                }
            )
    return {
        "type": e_type,
        "machine": e_machine,
        "sections": sections,
        "symbols": symbols,
        "relocations": relocations,
    }


def section_bytes(image, section):
    return image[section["offset"]:section["offset"] + section["size"]]


def decode_insns(code):
    """Decode raw code bytes into (opcode, dst, src, off, imm)."""
    if len(code) % 8 != 0:
        raise AssertionError("code size is not a whole insn count")
    insns = []
    for off in range(0, len(code), 8):
        opcode = code[off]
        regs = code[off + 1]
        (jump,) = struct.unpack_from("<h", code, off + 2)
        (imm,) = struct.unpack_from("<i", code, off + 4)
        insns.append((opcode, regs & 0xF, regs >> 4, jump, imm))
    return insns


def assemble_btf(directives):
    """Assemble fixed-block directives to section bytes (test only)."""
    blob = bytearray()
    for directive in directives:
        parts = directive.split(None, 1)
        op = parts[0]
        if op == ".section":
            continue
        arg = parts[1]
        if op == ".short":
            blob += struct.pack("<H", int(arg))
        elif op == ".byte":
            blob += struct.pack("<B", int(arg))
        elif op == ".long":
            if arg.lstrip("-").isdigit():
                blob += struct.pack("<i", int(arg))
            else:
                blob += b"\x00\x00\x00\x00"
        elif op == ".ascii":
            assert arg.startswith('"') and arg.endswith('"')
            blob += arg[1:-1].encode("ascii")
        else:
            raise AssertionError("unknown directive %r" % (directive,))
    return bytes(blob)


def test_tracepoint_object_matches_pins():
    check_tools("mojo", "llc")
    raw_ir, adapted_ir, image, _ = build_object(COUNTER_SOURCE)
    assert adapter.validate(raw_ir) == "tracepoint"
    for label, text, want in (
        ("raw IR", raw_ir, TRACEPOINT_RAW_HASH),
        ("adapted IR", adapted_ir, TRACEPOINT_ADAPTED_HASH),
    ):
        observed = hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert observed == want, (
            "%s mismatch: observed %s expected %s"
            % (label, observed, want)
        )
    observed = hashlib.sha256(image).hexdigest()
    assert observed == TRACEPOINT_OBJECT_HASH, (
        "object mismatch: observed %s expected %s"
        % (observed, TRACEPOINT_OBJECT_HASH)
    )
    assert (
        'section "%s"' % TRACEPOINT_SECTION
    ) in adapted_ir
    print("PASS direct-path bytes match the pipeline pins")


def test_tracepoint_program_layout():
    check_tools("mojo", "llc")
    _, _, image, _ = build_object(COUNTER_SOURCE)
    elf = parse_elf(image)
    assert elf["type"] == ET_REL, "object must be relocatable"
    assert elf["machine"] == EM_BPF, "object must target EM_BPF"
    by_name = {s["name"]: s for s in elf["sections"]}
    for required in (TRACEPOINT_SECTION, "license", ".maps", ".BTF"):
        assert required in by_name, "missing %s section" % required
    executable = [
        s["name"] for s in elf["sections"]
        if s["flags"] & SHF_EXECINSTR and s["size"] > 0
    ]
    assert executable == [TRACEPOINT_SECTION], (
        "exactly one nonempty executable section expected, got %r"
        % executable
    )
    assert section_bytes(image, by_name["license"]) == LICENSE_BYTES, (
        "license section bytes mismatch"
    )
    funcs = [
        s for s in elf["symbols"]
        if s["type"] == STT_FUNC and s["shndx"] != SHN_UNDEF
    ]
    assert [(s["name"], s["bind"]) for s in funcs] == [
        (ENTRY_SYMBOL, STB_GLOBAL)
    ], "one global function expected: %r" % (funcs,)
    code = section_bytes(image, by_name[TRACEPOINT_SECTION])
    insns = decode_insns(code)
    helper_ids = [
        imm for opcode, _, _, _, imm in insns if opcode == BPF_OP_CALL
    ]
    assert helper_ids == EXPECTED_CALLS, (
        "expected calls %r, got %r" % (EXPECTED_CALLS, helper_ids)
    )
    assert insns[-1][0] == BPF_OP_EXIT, "program must end in exit"
    imms = sorted(
        imm for opcode, _, _, _, imm in insns
        if opcode == BPF_OP_ADD_IMM
    )
    assert imms == EXPECTED_IMMS, (
        "expected add immediates %r, got %r" % (EXPECTED_IMMS, imms)
    )
    maps = [
        s for s in elf["symbols"]
        if s["name"] == MAP_SYMBOL and s["type"] == STT_OBJECT
    ]
    assert len(maps) == 1, "one map object symbol expected"
    rel_section = ".rel" + TRACEPOINT_SECTION
    hits = [
        r for r in elf["relocations"] if r["section"] == rel_section
    ]
    assert len(hits) == 3, (
        "three map relocations expected, got %r" % (hits,)
    )
    for rel in hits:
        assert rel["type"] == R_BPF_64_64, rel
        target = elf["symbols"][rel["sym"]]
        assert target["name"] == MAP_SYMBOL, target
    assert section_bytes(image, by_name[".maps"]) == (
        b"\x00" * MAP_SECTION_SIZE
    ), ".maps must be 32 zero bytes"
    print(
        "PASS calls [1, 14, 1, 2], imms [-16, -4, -4, -4, 1], "
        "3 map relocations"
    )


def test_tracepoint_map_btf():
    check_tools("mojo", "llc", "bpftool")
    _, _, image, object_path = build_object(COUNTER_SOURCE)
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    want = assemble_btf(adapter.BTF_ASM_LINES_TWO)
    got = section_bytes(image, by_name[".BTF"])
    assert got == want, (
        ".BTF bytes differ from the adapter two-entry block "
        "(%d vs %d bytes)" % (len(got), len(want))
    )
    proc = run_step(
        ["bpftool", "btf", "dump", "file", object_path, "format", "raw"]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "bpftool btf dump failed: %s" % proc.stderr[-1000:]
        )
    dump = proc.stdout
    assert "STRUCT 'mojobpf_map_def'" in dump, dump[:500]
    assert "VAR 'mojobpf_map0'" in dump, dump[-500:]
    assert dump.count("nr_elems=2") == 2, dump
    assert dump.count("nr_elems=4") == 1, dump
    assert dump.count("nr_elems=8") == 1, dump
    assert object_map_specs(object_path) == ((MAP_SYMBOL, 2, 2),)
    assert object_map_names(object_path) == (MAP_SYMBOL,)
    print("PASS two-entry array BTF (u32 key, u64 value)")


def test_tracepoint_mutant_shares_shape():
    check_tools("mojo", "llc")
    base_raw, _, base_image, _ = build_object(COUNTER_SOURCE)
    mut_raw, mut_adapted, mut_image, _ = build_object(MUTANT_SOURCE)
    assert adapter.validate(mut_raw) == "tracepoint"
    assert "ashr i64" in mut_raw, "mutant must shift the helper word"
    assert "and i64" in base_raw, "base must mask the helper word"
    assert mut_image != base_image, "mutant bytes must differ"
    observed = hashlib.sha256(mut_image).hexdigest()
    assert observed == MUTANT_OBJECT_HASH, (
        "mutant object mismatch: observed %s expected %s"
        % (observed, MUTANT_OBJECT_HASH)
    )
    elf = parse_elf(mut_image)
    by_name = {s["name"]: s for s in elf["sections"]}
    assert TRACEPOINT_SECTION in by_name
    insns = decode_insns(
        section_bytes(mut_image, by_name[TRACEPOINT_SECTION])
    )
    helper_ids = [
        imm for opcode, _, _, _, imm in insns if opcode == BPF_OP_CALL
    ]
    assert helper_ids == EXPECTED_CALLS, helper_ids
    imms = sorted(
        imm for opcode, _, _, _, imm in insns
        if opcode == BPF_OP_ADD_IMM
    )
    assert imms == EXPECTED_IMMS, imms
    want = assemble_btf(adapter.BTF_ASM_LINES_TWO)
    assert section_bytes(mut_image, by_name[".BTF"]) == want
    print("PASS TGID mutant: same shape, distinct bytes")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    try:
        check_tools("mojo", "llc", "bpftool")
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE: %s" % exc)
        return 3
    for path in (COUNTER_SOURCE, MUTANT_SOURCE):
        if not os.path.isfile(path):
            print("ENVIRONMENT FAILURE: missing source %s" % path)
            return 3
    failures = 0
    for name in (
        "test_tracepoint_object_matches_pins",
        "test_tracepoint_program_layout",
        "test_tracepoint_map_btf",
        "test_tracepoint_mutant_shares_shape",
    ):
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 3
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("tracepoint structure: shape, calls, BTF, mutant")
    return 0


if __name__ == "__main__":
    sys.exit(main())
