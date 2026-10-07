# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built combined packet workload.

Builds ``examples/packet_counter/packet_counter.mojo`` through the
genuine pipeline (``mojo build --emit llvm`` with the packaged SDK
on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and asserts the combined contract
the kernel suite relies on:

* the audit validates the program as the ``combined`` count
  vector, and the adapted IR carries the four lowered helper calls
  (lookup, update, lookup, update) with no remaining reserved
  references and the two-entry map block;
* the two-entry BTF block differs from the one-entry block in
  exactly the ``max_entries`` array bound;
* the object is a conventional BPF relocatable whose ``xdp`` code
  holds exactly helper calls [1, 2, 1, 2] plus an exit, whose
  ``.maps`` section is 32 zero bytes, whose four code relocations
  all target the single map symbol, and whose BTF describes the
  two-entry array (u32 key, u64 value), cross-checked against
  unmodified ``bpftool``;
* the backend allocates no stack frame for the adapted IR and the
  ``xdp`` section carries exactly the qualified combined
  add-immediate multiset (the spill-gate conjuncts, tied to the
  build driver's pinned constant);
* only helpers 1 and 2 are lowered and no unqualified map kind is
  emitted anywhere in the image;
* the byte-sum mutant's object carries one more constant increment
  than the qualified shape, pinning why the build driver refuses
  to publish it (the driver half lives in
  ``tests/compile/test_build_pipeline.py``).

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool`` on
PATH. A missing tool is reported as an environment failure; a
failing frontend, adapter, or backend step is a proof failure.
Neither ever passes.

Runnable directly (``python3 tests/elf/test_combined_struct.py``)
or under any ``test_``-style runner. Standard library only.
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
COMBINED_SOURCE = os.path.join(
    REPO_ROOT, "examples", "packet_counter", "packet_counter.mojo"
)
BYTESUM_MUTATED_SOURCE = os.path.join(
    REPO_ROOT, "examples", "packet_counter",
    "packet_counter_bytesum_mutated.mojo",
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
import audit  # noqa: E402
import mojo_ir_adapter as adapter  # noqa: E402
from mojobpf.build import QUALIFIED_COMBINED_ADD_IMMS  # noqa: E402

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_REL = 9
SHT_RELA = 4
SHN_UNDEF = 0
STB_GLOBAL = 1
STT_OBJECT = 1
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
BPF_OP_ADD64RI = 0x07
R_BPF_64_64 = 1
R_BPF_64_NODYLD32 = 4
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
MAP_SYMBOL = "mojobpf_map0"
MAP_SECTION_SIZE = 32
BTF_SECTION_SIZE = 397

JAL_RE = re.compile(r"^\s*JAL (\d+),\s*csr,\s*(.*)$")


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


def build_shape(source, prefix):
    """Run the genuine three-step build; return (raw, adapted, image)."""
    check_tools("mojo", "llc")
    if not os.path.isfile(source):
        raise EnvironmentFailure("missing source: %s" % source)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK dir: %s" % SDK_INCLUDE)
    if not os.path.isfile(ADAPTER):
        raise EnvironmentFailure("missing adapter: %s" % ADAPTER)
    workdir = tempfile.mkdtemp(prefix=prefix)
    raw_path = os.path.join(workdir, "shape.ll")
    adapted_path = os.path.join(workdir, "shape.bpf.ll")
    object_path = os.path.join(workdir, "shape.bpf.o")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm", "-I", SDK_INCLUDE,
            "-o", raw_path, source,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend reported diagnostics for %s:\n%s"
            % (source, proc.stderr)
        )
    with open(raw_path, "r", encoding="utf-8") as handle:
        raw_ir = handle.read()
    try:
        mode = audit.validate(raw_ir)
    except audit.AuditError as exc:
        raise AssertionError(
            "audit rejected %s: %s" % (source, exc)
        )
    assert mode == "combined", (
        "%s must validate as the combined shape, got %r" % (source, mode)
    )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path,
         "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
            adapted_path, "-o", object_path,
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


def built(source=None, prefix="mojo-combined-"):
    key = source or COMBINED_SOURCE
    if key not in _CACHED:
        _CACHED[key] = build_shape(key, prefix)
    return _CACHED[key]


def parse_elf(image):
    """Parse headers/sections/relocations/symbols; return facts."""
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
    (e_type, e_machine, _e_version) = struct.unpack_from("<HHI", image, 16)
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, sh_flags, _sh_addr, sh_offset, sh_size) = (
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
        link = _section_link(image, e_shoff, e_shentsize, section["index"])
        strsec = sections[link]
        strblob = image[strsec["offset"]:strsec["offset"] + strsec["size"]]
        for ordinal in range(count):
            off = section["offset"] + ordinal * 24
            (st_name, st_info, _other, st_shndx, _value, _size) = (
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
        if section["type"] == SHT_REL:
            count = section["size"] // 16
            for ordinal in range(count):
                off = section["offset"] + ordinal * 16
                (r_offset, r_info) = struct.unpack_from("<QQ", image, off)
                relocations.append(
                    {
                        "target": _rel_target(image, e_shoff, e_shentsize,
                                              section["index"]),
                        "offset": r_offset,
                        "sym": r_info >> 32,
                        "type": r_info & 0xFFFFFFFF,
                    }
                )
        elif section["type"] == SHT_RELA:
            count = section["size"] // 24
            for ordinal in range(count):
                off = section["offset"] + ordinal * 24
                (r_offset, r_info, _add) = struct.unpack_from(
                    "<QQq", image, off
                )
                relocations.append(
                    {
                        "target": _rel_target(image, e_shoff, e_shentsize,
                                              section["index"]),
                        "offset": r_offset,
                        "sym": r_info >> 32,
                        "type": r_info & 0xFFFFFFFF,
                    }
                )
    return {
        "type": e_type,
        "machine": e_machine,
        "sections": sections,
        "symbols": symbols,
        "relocations": relocations,
    }


def _section_link(image, e_shoff, e_shentsize, index):
    off = e_shoff + index * e_shentsize
    return struct.unpack_from("<I", image, off + 40)[0]


def _rel_target(image, e_shoff, e_shentsize, index):
    off = e_shoff + index * e_shentsize
    return struct.unpack_from("<I", image, off + 44)[0]


def section_bytes(image, section):
    return bytes(image[section["offset"]:section["offset"] + section["size"]])


def decode_insns(code):
    """Decode raw xdp bytes into (opcode, dst, src, off, imm) tuples."""
    assert len(code) % 8 == 0, "xdp code is not an insn multiple"
    insns = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        regs = code[offset + 1]
        (off,) = struct.unpack_from("<h", code, offset + 2)
        (imm,) = struct.unpack_from("<i", code, offset + 4)
        insns.append((opcode, regs & 0xF, regs >> 4, off, imm))
        if opcode == 0x18:
            offset += 16
        else:
            offset += 8
    return insns


def parse_btf(blob):
    """Parse a .BTF section; return records with names resolved."""
    (magic, version, _flags, hdr_len) = struct.unpack_from("<HBBI", blob, 0)
    (type_off, type_len, str_off, str_len) = struct.unpack_from(
        "<IIII", blob, 8
    )
    assert magic == 0xEB9F, "bad BTF magic %#x" % magic
    assert version == 1, "bad BTF version %d" % version
    assert hdr_len == 24 and type_off == 0, "unexpected BTF header layout"
    assert str_off == type_len, "unexpected BTF string offset"
    assert len(blob) == 24 + type_len + str_len, "BTF size mismatch"
    strings = blob[24 + type_len:]

    def string_at(off):
        end = strings.index(b"\x00", off)
        return strings[off:end].decode("ascii")

    records = []
    pos = 24
    end = 24 + type_len
    while pos < end:
        (name_off, info, size_or_type) = struct.unpack_from(
            "<III", blob, pos
        )
        kind = (info >> 24) & 0xF
        vlen = info & 0xFFFF
        pos += 12
        if kind == 1:  # INT
            (data,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            payload = {"bits": data & 0xFFFFFF, "size": size_or_type}
        elif kind == 2:  # PTR
            payload = {"target": size_or_type}
        elif kind == 3:  # ARRAY
            (elem, index, nelems) = struct.unpack_from("<III", blob, pos)
            pos += 12
            payload = {"elem": elem, "index": index, "nelems": nelems}
        elif kind == 4:  # STRUCT
            members = []
            for _ in range(vlen):
                (m_name, m_type, m_off) = struct.unpack_from(
                    "<III", blob, pos
                )
                pos += 12
                members.append((string_at(m_name), m_type, m_off))
            payload = {"size": size_or_type, "members": members}
        elif kind == 14:  # VAR
            (linkage,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            payload = {"target": size_or_type, "linkage": linkage}
        elif kind == 15:  # DATASEC
            entries = []
            for _ in range(vlen):
                (e_type, e_off, e_size) = struct.unpack_from(
                    "<III", blob, pos
                )
                pos += 12
                entries.append((e_type, e_off, e_size))
            payload = {"size": size_or_type, "entries": entries}
        else:
            raise AssertionError("unexpected BTF kind %d" % kind)
        records.append(
            {"name": string_at(name_off), "kind": kind, "payload": payload}
        )
    assert pos == end, "BTF type section has trailing bytes"
    return records


def dump_mir(adapted_text):
    check_tools("llc")
    workdir = tempfile.mkdtemp(prefix="mojo-combined-mir-")
    ll_path = os.path.join(workdir, "adapted.ll")
    mir_path = os.path.join(workdir, "out.mir")
    with open(ll_path, "w", encoding="utf-8") as handle:
        handle.write(adapted_text)
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3",
            "-stop-after=prologepilog", "-o", mir_path, ll_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(mir_path):
        raise AssertionError(
            "llc MIR dump failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(mir_path, "r", encoding="utf-8") as handle:
        return handle.read()


def test_combined_validates_and_lowers_four_calls():
    _, adapted, _ = built()
    lowered = [
        line.strip()
        for line in adapted.splitlines()
        if "inttoptr" in line
    ]
    assert len(lowered) == 4, (
        "expected exactly four lowered helper calls, got %r" % lowered
    )
    assert audit.LOWERED_LOOKUP_RE.match(lowered[0]), lowered[0]
    assert audit.LOWERED_UPDATE_RE.match(lowered[1]), lowered[1]
    assert audit.LOWERED_LOOKUP_RE.match(lowered[2]), lowered[2]
    assert audit.LOWERED_UPDATE_RE.match(lowered[3]), lowered[3]
    for reserved in audit.RESERVED_NAMES:
        assert reserved not in adapted, (
            "lowered IR still references %s" % reserved
        )
    assert '"call 1"' not in adapted and '"call 2"' not in adapted, (
        "lowered IR still invokes helpers through assembly"
    )
    assert "[3 x ptr]" in adapted, "combined mode must pin map+license+entry"
    assert 'section ".maps"' in adapted, "adapted IR must carry .maps"
    assert ".BTF" in adapted, "adapted IR must carry .BTF"
    print("PASS lowered callees: lookup/update/lookup/update")


def test_two_entry_btf_differs_by_one_word():
    one = adapter.BTF_ASM_LINES
    two = adapter.BTF_ASM_LINES_TWO
    assert len(one) == 97 and len(two) == 97
    diffs = [i for i, (a, b) in enumerate(zip(one, two)) if a != b]
    assert diffs == [adapter.BTF_ENTRIES_INDEX], diffs
    assert one[adapter.BTF_ENTRIES_INDEX] == ".long 1"
    assert two[adapter.BTF_ENTRIES_INDEX] == ".long 2"
    # The emitter generalizes to any declared count now (3 and 4
    # entries are proven shapes), so the fail-loud boundary moved
    # to unrepresentable values: a zero count and a foreign type.
    block3 = adapter.btf_block(entries=3)
    assert ".long 3" in block3.replace("\\22", '"')
    for bad in ({"entries": 0}, {"map_type": 5}):
        try:
            adapter.btf_block(**bad)
        except adapter.AdapterError as exc:
            assert exc.code == "MBPF301", (bad, exc.code)
        else:
            raise AssertionError("btf_block accepted %r" % (bad,))
    print("PASS two-entry BTF flips exactly the max_entries bound")


def test_combined_object_helpers_and_layout():
    _, _, image = built()
    elf = parse_elf(image)
    assert elf["type"] == ET_REL, "object must be relocatable"
    assert elf["machine"] == EM_BPF, "object must target EM_BPF"
    by_name = {s["name"]: s for s in elf["sections"]}
    for required in ("xdp", "license", ".maps", ".BTF"):
        assert required in by_name, "missing %s section" % required
    assert by_name["xdp"]["flags"] & SHF_EXECINSTR, "xdp must be executable"
    assert section_bytes(image, by_name["license"]) == LICENSE_BYTES, (
        "license section bytes mismatch"
    )
    insns = decode_insns(section_bytes(image, by_name["xdp"]))
    helper_ids = [imm for opcode, _, _, _, imm in insns
                  if opcode == BPF_OP_CALL]
    assert helper_ids == [1, 2, 1, 2], (
        "expected [lookup, update, lookup, update], got %r" % helper_ids
    )
    for opcode, _dst, src, off, _imm in insns:
        if opcode == BPF_OP_CALL:
            assert src == 0 and off == 0, (
                "helper call encoding is not src=0/off=0"
            )
    assert any(opcode == BPF_OP_EXIT for opcode, _, _, _, _ in insns), (
        "xdp code has no exit instruction"
    )
    undefined = [s["name"] for s in elf["symbols"] if s["shndx"] == SHN_UNDEF]
    undefined = [name for name in undefined if name]
    assert not undefined, "undefined symbols: %s" % ", ".join(undefined)
    print("PASS object: calls [1, 2, 1, 2] with conformant encoding")


def test_combined_map_section_and_relocations():
    _, _, image = built()
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    maps = by_name[".maps"]
    assert maps["size"] == MAP_SECTION_SIZE, (
        ".maps size %d, expected %d" % (maps["size"], MAP_SECTION_SIZE)
    )
    assert section_bytes(image, maps) == bytes(MAP_SECTION_SIZE), (
        ".maps must be all zero bytes (values live in BTF)"
    )
    matches = [s for s in elf["symbols"] if s["name"] == MAP_SYMBOL]
    assert len(matches) == 1, "expected one %s symbol" % MAP_SYMBOL
    sym = matches[0]
    assert sym["type"] == STT_OBJECT and sym["shndx"] == maps["index"], (
        "%s must be an object in .maps" % MAP_SYMBOL
    )
    assert sym["bind"] == STB_GLOBAL, "%s must be global" % MAP_SYMBOL
    xdp = by_name["xdp"]
    btf = by_name[".BTF"]
    map_relocs = [
        r
        for r in elf["relocations"]
        if r["target"] == xdp["index"]
        and elf["symbols"][r["sym"]]["name"] == MAP_SYMBOL
    ]
    assert len(map_relocs) == 4, (
        "expected four xdp relocations against %s, got %d"
        % (MAP_SYMBOL, len(map_relocs))
    )
    for reloc in map_relocs:
        assert reloc["type"] == R_BPF_64_64, (
            "map relocation must be R_BPF_64_64, got %d" % reloc["type"]
        )
    btf_relocs = [
        r
        for r in elf["relocations"]
        if r["target"] == btf["index"]
        and elf["symbols"][r["sym"]]["name"] == MAP_SYMBOL
    ]
    assert len(btf_relocs) == 1 and btf_relocs[0]["type"] == (
        R_BPF_64_NODYLD32
    ), "expected one R_BPF_64_NODYLD32 .BTF relocation, got %r" % btf_relocs
    print("PASS map section: 4 code relocs + 1 BTF reloc")


def test_combined_btf_two_entries():
    _, _, image = built()
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    blob = section_bytes(image, by_name[".BTF"])
    assert len(blob) == BTF_SECTION_SIZE, (
        ".BTF size %d, expected %d" % (len(blob), BTF_SECTION_SIZE)
    )
    records = parse_btf(blob)
    kinds = [r["kind"] for r in records]
    assert kinds == [2, 1, 3, 1, 2, 3, 2, 3, 2, 3, 4, 14, 15], (
        "unexpected BTF record kinds %r" % kinds
    )
    dims = [records[i]["payload"]["nelems"] for i in (2, 5, 7, 9)]
    assert dims == [2, 4, 8, 2], (
        "expected map attrs [type=2, key=4, value=8, entries=2], got %r"
        % dims
    )
    struct_rec = records[10]
    assert struct_rec["name"] == "mojobpf_map_def", "unexpected STRUCT name"
    assert struct_rec["payload"]["size"] == MAP_SECTION_SIZE, (
        "STRUCT size must match .maps"
    )
    members = struct_rec["payload"]["members"]
    assert [(m[0], m[2]) for m in members] == [
        ("type", 0),
        ("key_size", 64),
        ("value_size", 128),
        ("max_entries", 192),
    ], "unexpected STRUCT members %r" % (members,)
    var_rec = records[11]
    assert var_rec["name"] == MAP_SYMBOL and var_rec["payload"] == {
        "target": 11,
        "linkage": 1,
    }, "unexpected VAR record %r" % (var_rec,)
    datasec = records[12]
    assert datasec["name"] == ".maps", "expected DATASEC '.maps'"
    assert datasec["payload"]["entries"] == [(12, 0, MAP_SECTION_SIZE)], (
        "unexpected DATASEC entries %r" % (datasec["payload"]["entries"],)
    )
    check_tools("bpftool")
    workdir = tempfile.mkdtemp(prefix="mojo-combined-btf-")
    object_path = os.path.join(workdir, "combined.bpf.o")
    with open(object_path, "wb") as handle:
        handle.write(image)
    proc = run_step(["bpftool", "btf", "dump", "file", object_path])
    assert proc.returncode == 0, "bpftool btf dump failed:\n%s" % proc.stderr
    assert "VAR '%s'" % MAP_SYMBOL in proc.stdout, (
        "bpftool dump lacks the map VAR:\n%s" % proc.stdout
    )
    assert "nr_elems=2" in proc.stdout, (
        "bpftool dump lacks the two-entry bound:\n%s" % proc.stdout
    )
    print("PASS BTF: two-entry array accepted by bpftool")


def test_combined_mir_frameless_and_immediates():
    _, adapted, image = built()
    mir = dump_mir(adapted)
    jals = [
        JAL_RE.match(line)
        for line in mir.splitlines()
        if line.strip().startswith("JAL ")
    ]
    assert len(jals) == 4 and all(jals), (
        "expected exactly four lowered JAL calls"
    )
    ids = [match.group(1) for match in jals]
    assert ids == ["1", "2", "1", "2"], ids
    for match in jals:
        assert re.search(r"implicit-def (dead )?\$r0", match.group(2)), (
            "each call must define its r0 result: %s" % match.group(0)
        )
    assert re.search(r"^fixedStack:\s*\[\]", mir, re.M), (
        "expected no fixed frame objects"
    )
    assert re.search(r"^stack:\s*\[\]", mir, re.M), (
        "expected no managed spill slots"
    )
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    imms = sorted(
        imm
        for opcode, _, _, _, imm in decode_insns(
            section_bytes(image, by_name["xdp"])
        )
        if opcode == BPF_OP_ADD64RI
    )
    assert imms == [-16, -16, -4, -4, -4, -4, 1, 15], (
        "unexpected add-immediate set: %r" % (imms,)
    )
    assert list(QUALIFIED_COMBINED_ADD_IMMS) == imms, (
        "spill-gate constant drifted from the proven object"
    )
    print("PASS MIR: JAL 1/2/1/2 with csr, r0 results, empty frame")


def test_no_foreign_helper_or_map_kind_emitted():
    _, adapted, image = built()
    lowered = re.findall(r"inttoptr \(i64 (\d+) to ptr\)", adapted)
    assert lowered == ["1", "2", "1", "2"], (
        "only helpers 1 and 2 may be lowered, got %r" % lowered
    )
    text = image.decode("latin-1")
    for kind in ("percpu", "PERCPU", "lru_hash", "array_of_maps",
                 "hash_of_maps", "prog_array", "LRU", "HASH"):
        assert kind not in text, (
            "unqualified map kind %r must not appear in the image" % kind
        )
    print("PASS no foreign helper or map kind emitted")


def test_bytesum_mutant_immediates_differ():
    _, _, image = built(BYTESUM_MUTATED_SOURCE, "mojo-combined-mut-")
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    imms = sorted(
        imm
        for opcode, _, _, _, imm in decode_insns(
            section_bytes(image, by_name["xdp"])
        )
        if opcode == BPF_OP_ADD64RI
    )
    assert imms == [-16, -16, -4, -4, -4, -4, 1, 1, 15], (
        "byte-sum mutant must carry the extra +1 increment, got %r"
        % (imms,)
    )
    assert imms != list(QUALIFIED_COMBINED_ADD_IMMS)
    print("PASS byte-sum mutant leaves the qualified shape: %r" % (imms,))


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
    print("combined structure: mode, layout, BTF and spill checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
