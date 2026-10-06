# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built map round-trip object.

Builds ``tests/compile/map_roundtrip.mojo`` through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import path ->
``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel -mcpu=v3``) and
asserts the resulting object is a conventional BPF relocatable using one
helper-based map round trip: EM_BPF machine type, exactly one executable
section holding exactly one function (``xdp_entry``), the exact license
bytes, exactly one ``call 1`` (lookup) and one ``call 2`` (update), two
map relocations against the ``.maps`` symbol, a 32-byte all-zero ``.maps``
section, and map BTF describing a one-entry array map with u32 keys and
u64 values. The BTF blob is parsed with a minimal pure-Python reader and
cross-checked against ``bpftool btf dump``.

Also covers the compile-time negative: ``tests/compile/map_nomap.mojo``
passes the Mojo frontend but must be rejected by the adapter, which is
the first layer that pairs helper calls with their map reference. And it
locks the classifier program's adapted IR hash so adapter evolution
cannot silently change the classifier pipeline.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool`` on PATH.
A missing tool or a failing build step is reported as an environment
failure with a nonzero exit status, never as a pass.

Runnable directly (``python3 tests/elf/test_map_btf.py``) or under any
``test_``-style runner. Standard library only.
"""

import hashlib
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
ROUNDTRIP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)
NOMAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "map_nomap.mojo")
CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Adapted-IR hash of the packet-classifier program. The adapter must keep
# producing byte-identical output for that input (classifier mode).
CLASSIFIER_RAW_HASH = (
    "bb330f62183c6234f028d2e50540246bba6aaccb6ec535fbd8a0389226baf7c8"
)
CLASSIFIER_ADAPTED_HASH = (
    "eeed2b55c0b4bd4332ee93a5e17ee4ac60760c3607a688aad35fd042fe7795e8"
)

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_REL = 9
SHT_RELA = 4
SHN_UNDEF = 0
STB_GLOBAL = 1
STT_OBJECT = 1
STT_FUNC = 2
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
R_BPF_64_64 = 1
R_BPF_64_NODYLD32 = 4
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
MAP_SYMBOL = "mojobpf_map0"
MAP_SECTION_SIZE = 32
# Fixed adapter-emitted blob: 24-byte header + 276 type bytes + 97 string
# bytes describing the one-entry array map (u32 key, u64 value).
BTF_SECTION_SIZE = 397

DEFINE_RE = re.compile(r"^define\s+\S+\s+i32\s+@xdp_entry\(ptr[^)]*\)")
LOOKUP_RE = re.compile(r'call i64 asm sideeffect "call 1", ')
UPDATE_RE = re.compile(r'call i64 asm sideeffect "call 2", ')


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


def mojo_emit(source, raw_path):
    proc = run_step(
        [
            "mojo",
            "build",
            "--emit",
            "llvm",
            "-I",
            SDK_INCLUDE,
            "-o",
            raw_path,
            source,
        ]
    )
    return proc


def build_object(source=None):
    """Run the genuine three-step build; return (raw_ir, image)."""
    check_tools("mojo", "llc")
    source = source or ROUNDTRIP_SOURCE
    for path in (source, ADAPTER):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    workdir = tempfile.mkdtemp(prefix="mojo-map-elf-")
    raw_path = os.path.join(workdir, "map_roundtrip.ll")
    adapted_path = os.path.join(workdir, "map_roundtrip.bpf.ll")
    object_path = os.path.join(workdir, "map_roundtrip.bpf.o")
    proc = mojo_emit(source, raw_path)
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise EnvironmentFailure(
            "mojo build --emit llvm failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr or "warning:" in proc.stderr:
        raise EnvironmentFailure(
            "mojo build reported diagnostics:\n%s" % proc.stderr
        )
    proc = run_step(
        [
            sys.executable,
            ADAPTER,
            "--input",
            raw_path,
            "--output",
            adapted_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise EnvironmentFailure(
            "adapter failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
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
        raise EnvironmentFailure(
            "llc failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(raw_path, "r", encoding="utf-8") as handle:
        raw_ir = handle.read()
    with open(object_path, "rb") as handle:
        image = handle.read()
    return raw_ir, image


_CACHED = {}


def built():
    if "build" not in _CACHED:
        _CACHED["build"] = build_object()
    return _CACHED["build"]


def parse_elf(image):
    """Parse headers/sections/relocations/symbols; return string-keyed facts."""
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
    ei_class, ei_data = image[4], image[5]
    (e_type, e_machine, e_version) = struct.unpack_from("<HHI", image, 16)
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        (sh_link, sh_info, sh_addralign, sh_entsize) = struct.unpack_from(
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
            (st_name, st_info, st_other, st_shndx, st_value, st_size) = (
                struct.unpack_from("<IBBHQQ", image, off)
            )
            end = image.index(b"\x00", strsec["offset"] + st_name)
            name = image[strsec["offset"] + st_name : end].decode("ascii")
            symbols.append(
                {
                    "name": name,
                    "bind": st_info >> 4,
                    "type": st_info & 0xF,
                    "shndx": st_shndx,
                    "value": st_value,
                    "size": st_size,
                }
            )
    relocations = []
    for section in sections:
        if section["type"] == SHT_REL:
            count = section["size"] // 16
            for i in range(count):
                off = section["offset"] + i * 16
                (r_offset, r_info) = struct.unpack_from("<QQ", image, off)
                relocations.append(
                    {
                        "section": section["name"],
                        "target": section["info"],
                        "offset": r_offset,
                        "sym": r_info >> 32,
                        "type": r_info & 0xFFFFFFFF,
                    }
                )
        elif section["type"] == SHT_RELA:
            count = section["size"] // 24
            for i in range(count):
                off = section["offset"] + i * 24
                (r_offset, r_info, _) = struct.unpack_from("<QQq", image, off)
                relocations.append(
                    {
                        "section": section["name"],
                        "target": section["info"],
                        "offset": r_offset,
                        "sym": r_info >> 32,
                        "type": r_info & 0xFFFFFFFF,
                    }
                )
    return {
        "class": ei_class,
        "data": ei_data,
        "type": e_type,
        "machine": e_machine,
        "sections": sections,
        "symbols": symbols,
        "relocations": relocations,
        "image": image,
    }


def section_bytes(elf, section):
    return elf["image"][section["offset"] : section["offset"] + section["size"]]


def parse_btf(blob):
    """Parse a .BTF section; return (records, strings) with names resolved."""
    (magic, version, flags, hdr_len) = struct.unpack_from("<HBBI", blob, 0)
    (type_off, type_len, str_off, str_len) = struct.unpack_from("<IIII", blob, 8)
    assert magic == 0xEB9F, "bad BTF magic %#x" % magic
    assert version == 1, "bad BTF version %d" % version
    assert hdr_len == 24 and type_off == 0, "unexpected BTF header layout"
    assert str_off == type_len, "unexpected BTF string offset"
    assert len(blob) == 24 + type_len + str_len, "BTF size mismatch"
    strings = blob[24 + type_len :]
    assert len(strings) == str_len and strings[0:1] == b"\x00"

    def string_at(off):
        end = strings.index(b"\x00", off)
        return strings[off:end].decode("ascii")

    records = []
    pos = 24
    end = 24 + type_len
    while pos < end:
        (name_off, info, size_or_type) = struct.unpack_from("<III", blob, pos)
        kind = (info >> 24) & 0xF
        vlen = info & 0xFFFF
        pos += 12
        if kind == 1:  # INT
            (data,) = struct.unpack_from("<I", blob, pos)
            pos += 4
            payload = {"bits": data & 0xFFFFFF, "size": size_or_type}
        elif kind in (2, 12):  # PTR, FUNC
            payload = {"target": size_or_type}
        elif kind == 3:  # ARRAY
            (elem, index, nelems) = struct.unpack_from("<III", blob, pos)
            pos += 12
            payload = {"elem": elem, "index": index, "nelems": nelems}
        elif kind in (4, 5):  # STRUCT, UNION
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
    return records, strings


def test_entry_signature():
    raw_ir, _ = built()
    defines = [
        line.strip()
        for line in raw_ir.splitlines()
        if line.strip().startswith("define ")
    ]
    assert len(defines) == 1, "expected one define, got %d" % len(defines)
    assert DEFINE_RE.match(defines[0]), (
        "entry signature is not i32 @xdp_entry(ptr...): %r" % defines[0]
    )
    assert len(LOOKUP_RE.findall(raw_ir)) == 1, "expected one lookup call"
    assert len(UPDATE_RE.findall(raw_ir)) == 1, "expected one update call"


def test_machine_and_layout():
    _, image = built()
    elf = parse_elf(image)
    assert elf["class"] == 2, "not a 64-bit object"
    assert elf["data"] == 1, "not little-endian"
    assert elf["type"] == ET_REL, "not a relocatable object"
    assert elf["machine"] == EM_BPF, (
        "machine type %d is not EM_BPF (%d)" % (elf["machine"], EM_BPF)
    )


def test_single_entrypoint():
    _, image = built()
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    for required in ("xdp", "license", ".maps", ".BTF"):
        assert required in by_name, "missing %s section" % required
    executable = [
        s
        for s in elf["sections"]
        if s["flags"] & SHF_EXECINSTR and s["size"] > 0
    ]
    assert [s["name"] for s in executable] == ["xdp"], (
        "non-empty executable sections must be exactly [xdp], got %r"
        % [s["name"] for s in executable]
    )
    xdp = by_name["xdp"]
    assert xdp["size"] > 0 and xdp["size"] % 8 == 0, (
        "xdp section size %d is not a positive insn multiple" % xdp["size"]
    )
    funcs = [
        s for s in elf["symbols"] if s["type"] == STT_FUNC and s["shndx"] != 0
    ]
    assert [(f["name"], f["shndx"]) for f in funcs] == [
        ("xdp_entry", xdp["index"])
    ], "expected only xdp_entry as a defined function, got %r"
    assert section_bytes(elf, by_name["license"]) == LICENSE_BYTES, (
        "license section bytes mismatch"
    )
    undefined = [s["name"] for s in elf["symbols"] if s["shndx"] == SHN_UNDEF]
    undefined = [name for name in undefined if name]
    assert not undefined, "undefined symbols: %s" % ", ".join(undefined)


def test_helper_calls_present():
    _, image = built()
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    code = section_bytes(elf, by_name["xdp"])
    assert len(code) % 8 == 0, "xdp code is not an insn multiple"
    helper_ids = []
    saw_exit = False
    for off in range(0, len(code), 8):
        opcode = code[off]
        if opcode == BPF_OP_CALL:
            (imm,) = struct.unpack_from("<i", code, off + 4)
            helper_ids.append(imm)
        elif opcode == BPF_OP_EXIT:
            saw_exit = True
    assert helper_ids == [1, 2], (
        "expected exactly [lookup, update] helper calls, got %r" % helper_ids
    )
    assert saw_exit, "xdp code has no exit instruction"


def test_map_section_and_relocations():
    _, image = built()
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    maps = by_name[".maps"]
    assert maps["size"] == MAP_SECTION_SIZE, (
        ".maps size %d, expected %d" % (maps["size"], MAP_SECTION_SIZE)
    )
    assert section_bytes(elf, maps) == bytes(MAP_SECTION_SIZE), (
        ".maps must be all zero bytes (values live in BTF)"
    )
    matches = [s for s in elf["symbols"] if s["name"] == MAP_SYMBOL]
    assert len(matches) == 1, "expected one %s symbol" % MAP_SYMBOL
    sym = matches[0]
    assert sym["type"] == STT_OBJECT and sym["shndx"] == maps["index"], (
        "%s must be an object in .maps" % MAP_SYMBOL
    )
    assert sym["bind"] == STB_GLOBAL, (
        "%s must be a global symbol (mirrors the reference)" % MAP_SYMBOL
    )
    xdp = by_name["xdp"]
    btf = by_name[".BTF"]
    map_relocs = [
        r
        for r in elf["relocations"]
        if r["target"] == xdp["index"]
        and elf["symbols"][r["sym"]]["name"] == MAP_SYMBOL
    ]
    assert len(map_relocs) == 2, (
        "expected two xdp relocations against %s, got %d"
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


def test_map_btf():
    raw_ir, image = built()
    del raw_ir
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    blob = section_bytes(elf, by_name[".BTF"])
    assert len(blob) == BTF_SECTION_SIZE, (
        ".BTF size %d, expected %d" % (len(blob), BTF_SECTION_SIZE)
    )
    records, _ = parse_btf(blob)
    kinds = [r["kind"] for r in records]
    # PTR, INT, ARRAY, INT, PTR, ARRAY, PTR, ARRAY, PTR, ARRAY, STRUCT,
    # VAR, DATASEC: the standard integer-attribute map layout.
    assert kinds == [2, 1, 3, 1, 2, 3, 2, 3, 2, 3, 4, 14, 15], (
        "unexpected BTF record kinds %r" % kinds
    )
    assert records[1]["name"] == "int", "expected INT 'int'"
    assert records[3]["name"] == "__ARRAY_SIZE_TYPE__", (
        "expected INT '__ARRAY_SIZE_TYPE__'"
    )
    dims = [records[i]["payload"]["nelems"] for i in (2, 5, 7, 9)]
    assert dims == [2, 4, 8, 1], (
        "expected map attrs [type=2, key=4, value=8, entries=1], got %r"
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
    workdir = tempfile.mkdtemp(prefix="mojo-map-btf-")
    object_path = os.path.join(workdir, "map_roundtrip.bpf.o")
    with open(object_path, "wb") as handle:
        handle.write(image)
    proc = run_step(["bpftool", "btf", "dump", "file", object_path])
    assert proc.returncode == 0, "bpftool btf dump failed:\n%s" % proc.stderr
    assert "VAR '%s'" % MAP_SYMBOL in proc.stdout, (
        "bpftool dump lacks the map VAR:\n%s" % proc.stdout
    )
    assert "DATASEC '.maps'" in proc.stdout, (
        "bpftool dump lacks DATASEC '.maps':\n%s" % proc.stdout
    )


def test_missing_map_rejected_by_adapter():
    """Missing map reference: first rejecting layer is the adapter."""
    check_tools("mojo")
    if not os.path.isfile(NOMAP_SOURCE):
        raise EnvironmentFailure("missing fixture: %s" % NOMAP_SOURCE)
    workdir = tempfile.mkdtemp(prefix="mojo-map-nomap-")
    raw_path = os.path.join(workdir, "map_nomap.ll")
    adapted_path = os.path.join(workdir, "map_nomap.bpf.ll")
    proc = mojo_emit(NOMAP_SOURCE, raw_path)
    assert proc.returncode == 0 and os.path.isfile(raw_path), (
        "the Mojo frontend must accept the fixture (rejection belongs "
        "to the adapter), got exit %d:\n%s\n%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
    proc = run_step(
        [
            sys.executable,
            ADAPTER,
            "--input",
            raw_path,
            "--output",
            adapted_path,
        ]
    )
    assert proc.returncode == 1, (
        "adapter must reject the missing-map input with exit 1, got %d"
        % proc.returncode
    )
    assert "rejected" in proc.stderr, (
        "adapter must report a rejection, got:\n%s" % proc.stderr
    )
    assert not os.path.isfile(adapted_path), (
        "adapter must not emit output for rejected input"
    )


def test_classifier_pipeline_stable():
    """The classifier program must adapt to its exact recorded hashes."""
    check_tools("mojo", "llc")
    workdir = tempfile.mkdtemp(prefix="mojo-map-regress-")
    raw_path = os.path.join(workdir, "xdp_pass.ll")
    adapted_path = os.path.join(workdir, "xdp_pass.bpf.ll")
    proc = mojo_emit(CLASSIFIER_SOURCE, raw_path)
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise EnvironmentFailure(
            "mojo build --emit llvm failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            sys.executable,
            ADAPTER,
            "--input",
            raw_path,
            "--output",
            adapted_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise EnvironmentFailure(
            "adapter failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(raw_path, "rb") as handle:
        raw_hash = hashlib.sha256(handle.read()).hexdigest()
    with open(adapted_path, "rb") as handle:
        adapted_hash = hashlib.sha256(handle.read()).hexdigest()
    assert raw_hash == CLASSIFIER_RAW_HASH, (
        "classifier frontend output drifted: %s" % raw_hash
    )
    assert adapted_hash == CLASSIFIER_ADAPTED_HASH, (
        "classifier adapted output drifted: %s" % adapted_hash
    )


def main():
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
    print("map object: helper, relocation and BTF checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
