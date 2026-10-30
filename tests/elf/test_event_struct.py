# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built ring-buffer event objects.

Builds ``examples/tracepoint_events/emitter.mojo`` (and the small,
TGID-mutant, and version-mutant siblings) through the genuine
pipeline (``mojo build --emit llvm`` with the packaged SDK on the
import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and asserts each resulting object
is a conventional BPF relocatable for one tracepoint program:
EM_BPF machine type, exactly one executable section
(``tracepoint/syscalls/sys_enter_getpid``) holding exactly one
function (``trace_entry``), the exact license bytes, helper calls
[1, 14, 1, 2, 8, 5, 14, 130, 1, 1, 2] in order (the success and
failure updates share one tail-merged call instruction), the
qualified add-immediate multiset, eight map relocations (seven
against the array state map, one against the ring-buffer map), a
48-byte all-zero ``.maps`` section, and map BTF describing the
four-entry array map plus the ring-buffer map. The BTF blob is
compared byte-for-byte against the adapter's fixed two-map block
and cross-checked against ``bpftool btf dump`` plus the public
map-spec readers.

Also proves the 32-byte record layout five ways: the ABI record
row, the SDK comptime constants, the independent Python decoder
constants, the C reference struct (host facts, BPF-target LLVM
type, and BTF field offsets), the Mojo layout probe (size,
alignment, and a byte-exact dump), and the encoder's adapted-IR
stores (seven word stores through the eight slot views covering
exactly bytes 0 through 31). The backend must also keep the
program frameless (empty MIR stack), since any spill could
collide with the fixed slots; the build's spill gate enforces
the same property on the driver path.

The TGID and version mutants share the section, calls,
immediates, maps, and BTF shape with distinct program bytes, so
each mutant is proven shape-clean yet behaviorally distinct.

Requires a working Mojo compiler, LLVM ``llc``, ``clang``, and
``bpftool`` on PATH. A missing tool is reported as an
environment failure; a failing frontend, adapter, or backend
step is a proof failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_event_struct.py``)
or under any ``test_``-style runner. Standard library only.
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
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import mojo_ir_adapter as adapter  # noqa: E402
import audit as audit_rules  # noqa: E402
from mojobpf import events as event_decoder  # noqa: E402
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
from mojobpf.inspect import (  # noqa: E402
    object_map_names,
    object_map_specs,
)

EVENT_DIR = os.path.join(REPO_ROOT, "examples", "tracepoint_events")
EMITTER_SOURCE = os.path.join(EVENT_DIR, "emitter.mojo")
SMALL_SOURCE = os.path.join(EVENT_DIR, "emitter_small.mojo")
TGID_SOURCE = os.path.join(EVENT_DIR, "emitter_tgid_mutated.mojo")
V2_SOURCE = os.path.join(EVENT_DIR, "emitter_v2_mutated.mojo")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
SDK_EVENTS = os.path.join(SDK_INCLUDE, "mojobpf", "events.mojo")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
ABI_RECORD = os.path.join(REPO_ROOT, "tests", "elf", "abi_layouts.json")
EVENT_PROBE = os.path.join(
    REPO_ROOT, "tests", "elf", "event_layouts_probe.mojo"
)
C_FIXTURE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "event_record.c"
)

# Independent direct-path pins for the committed emitter family.
# The build-driver suite pins the same bytes through
# build_project; both paths must agree.
EMITTER_RAW_HASH = (
    "1839440caeb6fd6b680aeeffc3e83b8c5843928bd370949c36522e080df2c69b"
)
EMITTER_ADAPTED_HASH = (
    "6f18b33e74e6bab2405a0727ad84d735499ff3a45a2c7fcebbc3f0236f673835"
)
EMITTER_OBJECT_HASH = (
    "dbddc75dabe4198107eca403a37bfa04934932c6cfe011ca5f46ca6df67b8770"
)
SMALL_RAW_HASH = (
    "3ceb19693fb0674655a443867396118d464752e66e94176a00047a34234f4f3c"
)
SMALL_ADAPTED_HASH = (
    "fd9b886305f7299b4b28dad24aa7fc2f90b2fa63b37409ae4e08fff092841711"
)
SMALL_OBJECT_HASH = (
    "09be1aaef6eff3d30d8957c9edf11e8487b441c469243bf019b9a3125575920b"
)
TGID_OBJECT_HASH = (
    "e5ecb288b6a3404d0bb26c429540a7b726a0affc3681eeba6a90e47b2830e6ec"
)
V2_OBJECT_HASH = (
    "0f7d4112cb4b6e47fa076ef069de71f824b73a00d5a5b6de0bd1897686354449"
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
RING_SYMBOL = "mojobpf_map1"
MAP_SECTION_SIZE = 48
RING_SIZE_LARGE = 131072
RING_SIZE_SMALL = 4096
# Object-level call order: the success and failure updates share
# one tail-merged call instruction, so the object carries eleven
# calls for the twelve IR-level helper calls.
EXPECTED_CALLS = [1, 14, 1, 2, 8, 5, 14, 130, 1, 1, 2]
EXPECTED_IMMS = [
    -64, -64, -62, -60, -56, -52, -48, -40,
    -16, -16, -16,
    -4, -4, -4, -4, -4, -4, -4,
    1, 1, 1,
]
# Record field (offset, width) pairs from the ABI record row, in
# field order: exactly bytes 0 through 31, no gaps, no overlap.
EXPECTED_COVERAGE = (
    (0, 2), (2, 2), (4, 4), (8, 4), (12, 4), (16, 8), (24, 8),
)


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

    Returns (raw_ir, adapted_ir, image, object_path). The frontend
    must be silent on stderr; any nonzero step is a proof failure.
    """
    workdir = tempfile.mkdtemp(prefix="mojo-events-")
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


def test_event_objects_match_pins():
    check_tools("mojo", "llc")
    for source, raw_hash, adapted_hash, object_hash in (
        (EMITTER_SOURCE, EMITTER_RAW_HASH, EMITTER_ADAPTED_HASH,
         EMITTER_OBJECT_HASH),
        (SMALL_SOURCE, SMALL_RAW_HASH, SMALL_ADAPTED_HASH,
         SMALL_OBJECT_HASH),
    ):
        raw_ir, adapted_ir, image, _ = build_object(source)
        assert adapter.validate(raw_ir) == "event"
        for label, text, want in (
            ("raw IR", raw_ir, raw_hash),
            ("adapted IR", adapted_ir, adapted_hash),
        ):
            observed = hashlib.sha256(text.encode("utf-8")).hexdigest()
            assert observed == want, (
                "%s %s mismatch: observed %s expected %s"
                % (source, label, observed, want)
            )
        observed = hashlib.sha256(image).hexdigest()
        assert observed == object_hash, (
            "%s object mismatch: observed %s expected %s"
            % (source, observed, object_hash)
        )
        assert (
            'section "%s"' % TRACEPOINT_SECTION
        ) in adapted_ir
    print("PASS direct-path bytes match the pipeline pins")


def check_program_layout(image, object_path):
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
    for symbol in (MAP_SYMBOL, RING_SYMBOL):
        matches = [
            s for s in elf["symbols"]
            if s["name"] == symbol and s["type"] == STT_OBJECT
        ]
        assert len(matches) == 1, "one %s symbol expected" % symbol
    rel_section = ".rel" + TRACEPOINT_SECTION
    hits = [
        r for r in elf["relocations"] if r["section"] == rel_section
    ]
    assert len(hits) == 8, (
        "eight map relocations expected, got %r" % (hits,)
    )
    targets = []
    for rel in hits:
        assert rel["type"] == R_BPF_64_64, rel
        targets.append(elf["symbols"][rel["sym"]]["name"])
    assert sorted(targets) == sorted([MAP_SYMBOL] * 7 + [RING_SYMBOL]), (
        "seven state-map plus one ring-buffer relocation expected, "
        "got %r" % (targets,)
    )
    assert section_bytes(image, by_name[".maps"]) == (
        b"\x00" * MAP_SECTION_SIZE
    ), ".maps must be 48 zero bytes"
    specs = dict(
        (name, (map_type, entries))
        for name, map_type, entries in object_map_specs(object_path)
    )
    assert specs[MAP_SYMBOL][0] == 2, specs
    assert specs[RING_SYMBOL][0] == 27, specs


def test_event_program_layout():
    check_tools("mojo", "llc")
    for source in (EMITTER_SOURCE, SMALL_SOURCE):
        _, _, image, object_path = build_object(source)
        check_program_layout(image, object_path)
    print(
        "PASS calls [1, 14, 1, 2, 8, 5, 14, 130, 1, 1, 2], "
        "21 add immediates, 7+1 map relocations"
    )


def check_map_btf(image, object_path, ring_size):
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    want = assemble_btf(
        adapter.btf_event_directives(
            array_entries=4, ring_size=ring_size
        )
    )
    got = section_bytes(image, by_name[".BTF"])
    assert got == want, (
        ".BTF bytes differ from the adapter two-map block "
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
    assert "STRUCT 'mojobpf_ringbuf_def'" in dump, dump[:1000]
    assert "VAR 'mojobpf_map0'" in dump, dump[-500:]
    assert "VAR 'mojobpf_map1'" in dump, dump[-500:]

    def bound_count(nelems):
        return len(
            re.findall(r"nr_elems=%d\b" % nelems, dump)
        )

    assert bound_count(2) == 1, dump
    assert bound_count(4) == 2, dump
    assert bound_count(8) == 1, dump
    assert bound_count(27) == 1, dump
    assert bound_count(ring_size) == 1, dump
    assert object_map_specs(object_path) == (
        (MAP_SYMBOL, 2, 4),
        (RING_SYMBOL, 27, ring_size),
    )
    assert object_map_names(object_path) == (MAP_SYMBOL, RING_SYMBOL)


def test_event_map_btf():
    check_tools("mojo", "llc", "bpftool")
    _, _, image, object_path = build_object(EMITTER_SOURCE)
    check_map_btf(image, object_path, RING_SIZE_LARGE)
    _, _, small_image, small_path = build_object(SMALL_SOURCE)
    check_map_btf(small_image, small_path, RING_SIZE_SMALL)
    print("PASS array-plus-ringbuf BTF in both ring sizes")


def load_abi_event_row():
    with open(ABI_RECORD, "r", encoding="utf-8") as handle:
        record = json.load(handle)
    return record["structs"]["event_record"]


def sdk_comptime_constants():
    found = {}
    pattern = re.compile(r"^comptime\s+(\w+)\s*=\s*(\d+)\s*$")
    with open(SDK_EVENTS, "r", encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            match = pattern.match(line.strip())
            if match:
                found[match.group(1)] = int(match.group(2))
    return found


def run_facts(binary_argv, workdir, label):
    proc = run_step(binary_argv)
    if proc.returncode != 0:
        raise AssertionError(
            "%s failed: %s" % (label, proc.stderr[-2000:])
        )
    if proc.stderr != "":
        raise AssertionError(
            "%s stderr must be empty, got %r"
            % (label, proc.stderr[:500])
        )
    return proc.stdout


def test_event_record_layout_proof():
    check_tools("mojo", "llc", "clang", "bpftool")
    row = load_abi_event_row()
    assert row["size"] == 32, row
    assert row["align"] == 8, row
    widths = {"u16": 2, "u32": 4, "u64": 8}
    coverage = tuple(
        (field["offset"], widths[field["type"]])
        for _, field in sorted(
            row["fields"].items(), key=lambda item: item[1]["offset"]
        )
    )
    assert coverage == EXPECTED_COVERAGE, coverage
    covered = [False] * 32
    for offset, width in coverage:
        for byte in range(offset, offset + width):
            assert not covered[byte], "overlap at %d" % byte
            covered[byte] = True
    assert all(covered), "record has an unmapped byte"
    consts = sdk_comptime_constants()
    assert consts["EVENT_RECORD_VERSION"] == 1, consts
    assert consts["EVENT_RECORD_SIZE"] == 32, consts
    for name, field in row["fields"].items():
        key = "EVENT_OFF_" + name.upper()
        assert consts[key] == field["offset"], (key, consts)
    assert event_decoder.EVENT_RECORD_VERSION == 1
    assert event_decoder.EVENT_RECORD_SIZE == 32
    for name, field in row["fields"].items():
        key = "EVENT_OFF_" + name.upper()
        assert getattr(event_decoder, key) == field["offset"], key
    workdir = tempfile.mkdtemp(prefix="mojo-event-layout-")
    c_binary = os.path.join(workdir, "event_record")
    proc = run_step(["cc", "-O2", "-o", c_binary, C_FIXTURE])
    if proc.returncode != 0:
        raise AssertionError(
            "C fixture build failed: %s" % proc.stderr[-2000:]
        )
    c_facts = run_facts([c_binary], workdir, "C fixture").splitlines()
    assert "SIZE event_record 32" in c_facts, c_facts
    assert "ALIGN event_record 8" in c_facts, c_facts
    c_dump = [
        line for line in c_facts if line.startswith("EDUMP event_record ")
    ]
    assert len(c_dump) == 1, c_facts
    assert [int(v) for v in c_dump[0].split()[2:]] == [
        1, 0, 32, 0,
        17, 17, 17, 17, 34, 34, 34, 34, 51, 51, 51, 51,
        68, 68, 68, 68, 68, 68, 68, 68,
        85, 85, 85, 85, 85, 85, 85, 85,
    ], c_dump
    probe_binary = os.path.join(workdir, "event_layouts_probe")
    proc = run_step(
        [
            "mojo", "build", "-I", SDK_INCLUDE,
            "-o", probe_binary, EVENT_PROBE,
        ]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "Mojo probe build failed: %s" % proc.stderr[-2000:]
        )
    if proc.stderr != "":
        raise AssertionError(
            "Mojo probe stderr must be empty, got %r"
            % proc.stderr[:500]
        )
    mojo_facts = run_facts(
        [probe_binary], workdir, "Mojo probe"
    ).splitlines()
    assert "SIZE event_record 32" in mojo_facts, mojo_facts
    assert "ALIGN event_record 8" in mojo_facts, mojo_facts
    mojo_dump = [
        line for line in mojo_facts
        if line.startswith("EDUMP event_record ")
    ]
    assert mojo_dump == c_dump, (mojo_dump, c_dump)
    bpf_ll = os.path.join(workdir, "event_record.bpf.ll")
    proc = run_step(
        [
            "clang", "--target=bpf", "-DBPF_TYPE_EMIT", "-S",
            "-emit-llvm", "-o", bpf_ll, C_FIXTURE,
        ]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "BPF IR leg failed: %s" % proc.stderr[-2000:]
        )
    with open(bpf_ll, "r", encoding="utf-8") as handle:
        bpf_ir = handle.read()
    match = re.search(
        r"%struct\.event_record\s*=\s*type\s*\{\s*([^{}]+)\}", bpf_ir
    )
    assert match, "no event_record type in BPF IR"
    members = [part.strip() for part in match.group(1).split(",")]
    assert members == [
        "i16", "i16", "i32", "i32", "i32", "i64", "i64",
    ], members
    bpf_obj = os.path.join(workdir, "event_record.bpf.o")
    proc = run_step(
        [
            "clang", "--target=bpf", "-O2", "-g", "-DBPF_TYPE_EMIT",
            "-c", C_FIXTURE, "-o", bpf_obj,
        ]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "BTF leg failed: %s" % proc.stderr[-2000:]
        )
    proc = run_step(
        ["bpftool", "btf", "dump", "file", bpf_obj, "format", "raw"]
    )
    if proc.returncode != 0:
        raise AssertionError(
            "bpftool btf dump failed: %s" % proc.stderr[-1000:]
        )
    offsets = {}
    for line in proc.stdout.splitlines():
        member = re.match(
            r"\s*'(\w+)' type_id=\d+ bits_offset=(\d+)", line
        )
        if member:
            offsets[member.group(1)] = int(member.group(2)) // 8
    for name, field in row["fields"].items():
        assert offsets.get(name) == field["offset"], offsets
    print("PASS record layout: five legs agree byte-exact")


STORE_RE = re.compile(r"^\s*store\s+(i\d+)\s+(\S+),\s+ptr\s+(%\S+)")


def test_event_encoder_store_coverage():
    check_tools("mojo", "llc")
    _, adapted_ir, _, _ = build_object(EMITTER_SOURCE)
    views = {}
    for line in adapted_ir.splitlines():
        stripped = line.strip()
        for shape, regex in (
            ("eventslot", adapter.EVENTSLOT_CALL_RE),
            ("eventslotN", adapter.EVENTSLOTN_CALL_RE),
        ):
            match = regex.match(stripped)
            if match:
                if shape == "eventslot":
                    views[match.group(1)] = 64
                else:
                    views[match.group(1)] = int(match.group(2))
    assert sorted(views.values()) == [
        40, 48, 52, 56, 60, 62, 64, 64,
    ], views
    output_data = None
    for line in adapted_ir.splitlines():
        match = audit_rules.LOWERED_OUTPUT_RE.match(line.strip())
        if match:
            assert output_data is None, "two output calls"
            output_data = match.group(3)
    assert output_data is not None, "no lowered output call"
    assert views.get(output_data) == 64, (
        "output data must be a base view, got %r" % output_data
    )
    stores = {}
    for line in adapted_ir.splitlines():
        match = STORE_RE.match(line)
        if not match:
            continue
        width = int(match.group(1)[1:]) // 8
        target = match.group(3).rstrip(",").lstrip("%")
        if target not in views:
            continue
        stores.setdefault(target, []).append(width)
    assert len(stores) == 7, (
        "seven views must feed stores, got %r" % (stores,)
    )
    assert output_data not in stores, (
        "the output base view must feed no store"
    )
    covered = [False] * 32
    for target, widths in stores.items():
        assert len(widths) == 1, (target, widths)
        offset = 64 - views[target]
        for byte in range(offset, offset + widths[0]):
            assert not covered[byte], "overlap at %d" % byte
            covered[byte] = True
    assert all(covered), "encoder leaves a byte uninitialized"
    by_offset = sorted(
        (64 - views[target], widths[0])
        for target, widths in stores.items()
    )
    assert tuple(by_offset) == EXPECTED_COVERAGE, by_offset
    print("PASS encoder stores cover exactly bytes 0..31")


def test_event_backend_frameless():
    check_tools("mojo", "llc")
    workdir = tempfile.mkdtemp(prefix="mojo-event-mir-")
    for source in (EMITTER_SOURCE, SMALL_SOURCE):
        raw_path = os.path.join(workdir, "raw.ll")
        adapted_path = os.path.join(workdir, "adapted.ll")
        mir_path = os.path.join(workdir, "prog.mir")
        proc = run_step(
            [
                "mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS,
                "-I", SDK_INCLUDE, "-o", raw_path, source,
            ]
        )
        assert proc.returncode == 0, proc.stderr[-1000:]
        proc = run_step(
            [
                sys.executable, ADAPTER,
                "--input", raw_path, "--output", adapted_path,
            ]
        )
        assert proc.returncode == 0, proc.stderr[-1000:]
        proc = run_step(
            [
                "llc", "-mtriple=bpfel", "-mcpu=v3",
                "-stop-after=prologepilog", adapted_path,
                "-o", mir_path,
            ]
        )
        assert proc.returncode == 0, proc.stderr[-1000:]
        with open(mir_path, "r", encoding="utf-8") as handle:
            mir = handle.read()
        assert "fixedStack:      []" in mir, "backend frame present"
        assert re.search(r"^stack:\s*\[\]", mir, re.M), (
            "backend spill slots present"
        )
    print("PASS backend keeps both emitters frameless")


def filter_operand_op(raw_ir):
    """Operation defining the value the filter compares.

    The filter comparison is the second integer comparison of the
    entry block (after the filter lookup's null check); its
    second operand is the masked thread ID in the base program
    and the shifted word in the TGID mutant. Returns ``"and"`` or
    ``"ashr"`` from the operand's defining line.
    """
    icmps = []
    defs = {}
    for line in raw_ir.splitlines():
        stripped = line.strip()
        match = re.match(r"^%(\S+)\s*=\s*(.*)$", stripped)
        if match:
            defs[match.group(1)] = match.group(2)
            if match.group(2).startswith("icmp eq i64"):
                icmps.append(match.group(2))
    assert len(icmps) >= 2, "filter comparison missing"
    compared = icmps[1].rsplit(" ", 1)[1].lstrip("%")
    assert compared in defs, "filter operand undefined"
    defining = defs[compared]
    if defining.startswith("and i64"):
        return "and"
    if defining.startswith("ashr i64"):
        return "ashr"
    raise AssertionError(
        "filter operand has unexpected form %r" % (defining,)
    )


def check_mutant_shape(source, object_hash, base_image):
    raw_ir, _, image, object_path = build_object(source)
    assert adapter.validate(raw_ir) == "event"
    assert image != base_image, "mutant bytes must differ"
    observed = hashlib.sha256(image).hexdigest()
    assert observed == object_hash, (
        "mutant object mismatch: observed %s expected %s"
        % (observed, object_hash)
    )
    check_program_layout(image, object_path)
    return raw_ir


def test_event_mutants_share_shape():
    check_tools("mojo", "llc")
    base_raw, _, base_image, _ = build_object(EMITTER_SOURCE)
    assert filter_operand_op(base_raw) == "and", (
        "base must compare the masked thread ID"
    )
    assert "store i16 1" in base_raw, "base must stamp version 1"
    tgid_raw = check_mutant_shape(
        TGID_SOURCE, TGID_OBJECT_HASH, base_image
    )
    assert filter_operand_op(tgid_raw) == "ashr", (
        "TGID mutant must compare the shifted word"
    )
    v2_raw = check_mutant_shape(V2_SOURCE, V2_OBJECT_HASH, base_image)
    assert "store i16 2" in v2_raw, "v2 mutant must stamp version 2"
    assert filter_operand_op(v2_raw) == "and", (
        "v2 mutant must keep the base filter"
    )
    print("PASS mutants: same shape, distinct bytes")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    try:
        check_tools("mojo", "llc", "clang", "bpftool")
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE: %s" % exc)
        return 3
    for path in (
        EMITTER_SOURCE, SMALL_SOURCE, TGID_SOURCE, V2_SOURCE,
        SDK_EVENTS, ABI_RECORD, EVENT_PROBE, C_FIXTURE,
    ):
        if not os.path.isfile(path):
            print("ENVIRONMENT FAILURE: missing source %s" % path)
            return 3
    failures = 0
    for name in (
        "test_event_objects_match_pins",
        "test_event_program_layout",
        "test_event_map_btf",
        "test_event_record_layout_proof",
        "test_event_encoder_store_coverage",
        "test_event_backend_frameless",
        "test_event_mutants_share_shape",
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
    print("event structure: shape, calls, BTF, layout, mutants")
    return 0


if __name__ == "__main__":
    sys.exit(main())

