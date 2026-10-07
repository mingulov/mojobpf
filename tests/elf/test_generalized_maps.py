# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structure proof for the generalized map shapes.

Builds every map count family (read-modify-write pairs,
deletions) over every supported entry count (1 to 4) in both map
kinds (array, per-CPU array) plus the per-CPU combined workload
through the genuine frontend and adapter, then proves the
structural contract per shape: the audit family, the exact
helper-call bytes, the BTF map attributes (kind and count), the
map-section layout and relocation counts, the add-immediate
multiset the spill gate enforces, and bpftool acceptance of the
emitted BTF. Array and per-CPU objects for the same shape must
differ only in the BTF type word: the kind tag emits no code.
There is no iteration family: the kernel offers no from-program
map-iteration helper. Genuine-frontend negatives (out-of-range
key, mixed handles, from-program iteration attempt) pin their
refusal codes here too.

Needs the Mojo compiler, LLVM llc, and bpftool on PATH; missing
tools are an environment failure, never a pass.

Runnable directly (``python3 tests/elf/test_generalized_maps.py``)
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
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import audit  # noqa: E402
import mojo_ir_adapter as adapter  # noqa: E402
from mojobpf.build import QUALIFIED_SHAPE_IMMS  # noqa: E402

COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
SDK_INCLUDE = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)
MAP_SYMBOL = "mojobpf_map0"

ET_REL = 1
EM_BPF = 247
SHT_REL = 9
SHT_RELA = 4
R_BPF_64_64 = 1

BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
BPF_OP_ADD64_IMM = 0x07
BPF_OP_LD_IMM64 = 0x18

# (shape name, source file, family, entries, kind, helper calls).
# Array and per-CPU rows share code shapes; only the BTF kind word
# and the kind tags differ.
SHAPES = (
    ("rmw2", "maps_rmw2.mojo", "map", 2, "array", (1, 2, 1, 2)),
    ("rmw3", "maps_rmw3.mojo", "map", 3, "array", (1, 2, 1, 2, 1, 2)),
    (
        "rmw4", "maps_rmw4.mojo", "map", 4, "array",
        (1, 2, 1, 2, 1, 2, 1, 2),
    ),
    ("del1", "maps_delete1.mojo", "delete", 1, "array", (3,)),
    ("del2", "maps_delete2.mojo", "delete", 2, "array", (3, 3)),
    ("del3", "maps_delete3.mojo", "delete", 3, "array", (3, 3, 3)),
    ("del4", "maps_delete4.mojo", "delete", 4, "array", (3, 3, 3, 3)),
    ("pcpu_rmw1", "percpu_rmw1.mojo", "map", 1, "percpu_array", (1, 2)),
    (
        "pcpu_rmw2", "percpu_rmw2.mojo", "map", 2, "percpu_array",
        (1, 2, 1, 2),
    ),
    (
        "pcpu_rmw3", "percpu_rmw3.mojo", "map", 3, "percpu_array",
        (1, 2, 1, 2, 1, 2),
    ),
    (
        "pcpu_rmw4", "percpu_rmw4.mojo", "map", 4, "percpu_array",
        (1, 2, 1, 2, 1, 2, 1, 2),
    ),
    ("pcpu_del1", "percpu_delete1.mojo", "delete", 1, "percpu_array", (3,)),
    (
        "pcpu_del2", "percpu_delete2.mojo", "delete", 2, "percpu_array",
        (3, 3),
    ),
    (
        "pcpu_del3", "percpu_delete3.mojo", "delete", 3, "percpu_array",
        (3, 3, 3),
    ),
    (
        "pcpu_del4", "percpu_delete4.mojo", "delete", 4, "percpu_array",
        (3, 3, 3, 3),
    ),
    (
        "pcpu_comb", "percpu_combined.mojo", "combined", 2,
        "percpu_array", (1, 2, 1, 2),
    ),
)

KIND_IDS = {"array": 2, "percpu_array": 6}


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def mojo_emit(source):
    check_tools("mojo")
    workdir = tempfile.mkdtemp(prefix="mojo-genmaps-")
    out_path = os.path.join(workdir, "raw.ll")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm", "-I", SDK_INCLUDE,
            "-o", out_path, source,
        ]
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "mojo emit failed for %s:\n%s" % (source, proc.stderr)
        )
    if proc.stderr.strip():
        raise AssertionError(
            "mojo emit diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    with open(out_path, "r", encoding="utf-8") as handle:
        return handle.read()


def build_object(adapted):
    check_tools("llc")
    workdir = tempfile.mkdtemp(prefix="mojo-genmaps-")
    ll_path = os.path.join(workdir, "adapted.bpf.ll")
    obj_path = os.path.join(workdir, "shape.bpf.o")
    with open(ll_path, "w", encoding="utf-8") as handle:
        handle.write(adapted)
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
            ll_path, "-o", obj_path,
        ]
    )
    if proc.returncode != 0:
        raise EnvironmentFailure("llc failed:\n%s" % proc.stderr)
    with open(obj_path, "rb") as handle:
        return handle.read()


_BUILT = {}


def built(name):
    if name not in _BUILT:
        row = [row for row in SHAPES if row[0] == name][0]
        source = os.path.join(COMPILE_DIR, row[1])
        raw = mojo_emit(source)
        program = audit.scan(raw)
        assert (program.family, program.entries, program.percpu) == (
            row[2], row[3], row[4] == "percpu_array",
        ), (name, program.family, program.entries, program.percpu)
        adapted = adapter.adapt(raw)
        image = build_object(adapted)
        _BUILT[name] = (raw, adapted, image)
    return _BUILT[name]


def parse_elf(image):
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
        (sh_name, sh_type, _flags, _addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        sections.append(
            {
                "index": index,
                "name_off": sh_name,
                "type": sh_type,
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
            (st_name, _info, _other, st_shndx, _value, _size) = (
                struct.unpack_from("<IBBHQQ", image, off)
            )
            end = strblob.index(b"\x00", st_name)
            symbols.append(
                {
                    "name": strblob[st_name:end].decode("ascii"),
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
                        "target": _rel_target(
                            image, e_shoff, e_shentsize, section["index"]
                        ),
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
                        "target": _rel_target(
                            image, e_shoff, e_shentsize, section["index"]
                        ),
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
    (link,) = struct.unpack_from(
        "<I", image, e_shoff + index * e_shentsize + 40
    )
    return link


def _section_info(image, e_shoff, e_shentsize, index):
    (info,) = struct.unpack_from(
        "<I", image, e_shoff + index * e_shentsize + 44
    )
    return info


def _rel_target(image, e_shoff, e_shentsize, index):
    return _section_info(image, e_shoff, e_shentsize, index)


def section_bytes(image, section):
    return image[section["offset"]:section["offset"] + section["size"]]


def xdp_code(image):
    elf = parse_elf(image)
    by_name = {section["name"]: section for section in elf["sections"]}
    return section_bytes(image, by_name["xdp"])


def helper_calls(code):
    """Return the helper IDs of every call in xdp code."""
    found = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        if opcode == BPF_OP_CALL:
            (imm,) = struct.unpack_from("<i", code, offset + 4)
            found.append(imm)
        if opcode == BPF_OP_LD_IMM64:
            offset += 16
        else:
            offset += 8
    return found


def add_immediates(code):
    """Return the sorted 64-bit add immediates of xdp code."""
    found = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        if opcode == BPF_OP_ADD64_IMM:
            (imm,) = struct.unpack_from("<i", code, offset + 4)
            found.append(imm)
        if opcode == BPF_OP_LD_IMM64:
            offset += 16
        else:
            offset += 8
    return sorted(found)


def parse_btf(blob):
    """Parse a .BTF blob; return (kinds, array_dims) in order."""
    (magic, version, _flags, hdr_len) = struct.unpack_from("<HBBI", blob, 0)
    assert magic == 0xEB9F and version == 1 and hdr_len == 24
    (type_off, type_len, str_off, str_len) = struct.unpack_from(
        "<IIII", blob, 8
    )
    assert type_off == 0 and str_off == type_len
    assert len(blob) == 24 + type_len + str_len
    kinds = []
    dims = []
    pos, end = 24, 24 + type_len
    while pos < end:
        (name_off, info, size_or_type) = struct.unpack_from(
            "<III", blob, pos
        )
        kind = (info >> 24) & 0xF
        vlen = info & 0xFFFF
        pos += 12
        kinds.append(kind)
        if kind == 1:
            pos += 4
        elif kind in (2, 12):
            pass
        elif kind == 3:
            (_elem, _index, nelems) = struct.unpack_from(
                "<III", blob, pos
            )
            pos += 12
            dims.append(nelems)
        elif kind in (4, 5):
            pos += 12 * vlen
        elif kind == 14:
            pos += 4
        elif kind == 15:
            pos += 12 * vlen
        else:
            raise AssertionError("unexpected BTF kind %d" % kind)
    assert pos == end
    return kinds, dims


EXPECTED_BTF_KINDS = [2, 1, 3, 1, 2, 3, 2, 3, 2, 3, 4, 14, 15]


def test_audit_families_cover_shapes():
    for name, _source, family, entries, kind, _calls in SHAPES:
        built(name)
    print("PASS audit families: %d shapes" % len(SHAPES))


def test_helper_call_bytes_per_shape():
    for name, _source, _family, _entries, _kind, want in SHAPES:
        _raw, _adapted, image = built(name)
        calls = helper_calls(xdp_code(image))
        assert tuple(calls) == tuple(want), (
            "%s: expected helper calls %r, got %r" % (name, want, calls)
        )
    print("PASS helper call bytes for %d shapes" % len(SHAPES))


def test_no_foreign_helpers_per_shape():
    for name, _source, _family, _entries, _kind, want in SHAPES:
        _raw, _adapted, image = built(name)
        code = xdp_code(image)
        offset = 0
        while offset < len(code):
            opcode = code[offset]
            if opcode == BPF_OP_CALL:
                (imm,) = struct.unpack_from("<i", code, offset + 4)
                assert imm in (1, 2, 3), (
                    "%s: foreign helper id %d" % (name, imm)
                )
            assert opcode != 0x8D, "%s: pseudo-call present" % name
            if opcode == BPF_OP_LD_IMM64:
                offset += 16
            else:
                offset += 8
        assert helper_calls(code) == list(want), name
    print("PASS no foreign helpers in %d shapes" % len(SHAPES))


def test_btf_dims_per_shape():
    for name, _source, _family, entries, kind, _calls in SHAPES:
        _raw, _adapted, image = built(name)
        elf = parse_elf(image)
        by_name = {
            section["name"]: section for section in elf["sections"]
        }
        blob = section_bytes(image, by_name[".BTF"])
        kinds, dims = parse_btf(blob)
        assert kinds == EXPECTED_BTF_KINDS, (name, kinds)
        assert dims == [KIND_IDS[kind], 4, 8, entries], (
            "%s: expected BTF dims %r, got %r"
            % (name, [KIND_IDS[kind], 4, 8, entries], dims)
        )
    print("PASS BTF dims for %d shapes" % len(SHAPES))


def test_kind_is_one_btf_word():
    # The array and per-CPU objects for the same shape differ only
    # in the BTF type word: same sections, same code, same map
    # layout, one word apart in the type section.
    pairs = [
        ("rmw2", "pcpu_rmw2"),
        ("rmw3", "pcpu_rmw3"),
        ("rmw4", "pcpu_rmw4"),
        ("del1", "pcpu_del1"),
        ("del2", "pcpu_del2"),
        ("del3", "pcpu_del3"),
        ("del4", "pcpu_del4"),
    ]
    for array_name, pcpu_name in pairs:
        _raw, _adapted, array_image = built(array_name)
        _praw, _padapted, pcpu_image = built(pcpu_name)
        assert xdp_code(array_image) == xdp_code(pcpu_image), (
            "%s/%s: kind tag changed code" % (array_name, pcpu_name)
        )
        array_elf = parse_elf(array_image)
        pcpu_elf = parse_elf(pcpu_image)
        array_by_name = {
            section["name"]: section
            for section in array_elf["sections"]
        }
        pcpu_by_name = {
            section["name"]: section
            for section in pcpu_elf["sections"]
        }
        array_blob = section_bytes(array_image, array_by_name[".BTF"])
        pcpu_blob = section_bytes(pcpu_image, pcpu_by_name[".BTF"])
        _kinds, array_dims = parse_btf(array_blob)
        _kinds, pcpu_dims = parse_btf(pcpu_blob)
        assert array_dims[0] == 2 and pcpu_dims[0] == 6
        assert array_dims[1:] == pcpu_dims[1:], (array_name, pcpu_name)
        assert len(array_blob) == len(pcpu_blob)
        diffs = [
            index
            for index, (left, right) in enumerate(
                zip(array_blob, pcpu_blob)
            )
            if left != right
        ]
        assert diffs == [72], (array_name, pcpu_name, diffs)
    print("PASS kind is one BTF word in %d pairs" % len(pairs))


def test_map_section_and_relocations_per_shape():
    # One map-address load per helper call; one code relocation
    # per load; the .maps section stays 32 zero bytes.
    want_loads = {
        "map": lambda entries: 2 * entries,
        "combined": lambda entries: 4,
        "delete": lambda entries: entries,
    }
    for name, _source, family, entries, _kind, _calls in SHAPES:
        _raw, adapted, image = built(name)
        loads = adapted.count("r0 = mojobpf_map0 ll")
        assert loads == want_loads[family](entries), (
            "%s: expected %d map loads, got %d"
            % (name, want_loads[family](entries), loads)
        )
        elf = parse_elf(image)
        by_name = {
            section["name"]: section for section in elf["sections"]
        }
        maps = section_bytes(image, by_name[".maps"])
        assert maps == b"\x00" * 32, "%s: .maps not zero" % name
        sym_names = [symbol["name"] for symbol in elf["symbols"]]
        assert MAP_SYMBOL in sym_names, name
        xdp_index = by_name["xdp"]["index"]
        xdp_relocs = [
            entry
            for entry in elf["relocations"]
            if entry["target"] == xdp_index
        ]
        assert len(xdp_relocs) == loads, (
            "%s: expected %d xdp relocations, got %d"
            % (name, loads, len(xdp_relocs))
        )
        for entry in xdp_relocs:
            assert entry["type"] == R_BPF_64_64, (name, entry)
    print("PASS map sections and relocations for %d shapes" % len(SHAPES))


def test_immediates_match_gate_table():
    for name, _source, family, entries, _kind, _calls in SHAPES:
        _raw, _adapted, image = built(name)
        imms = add_immediates(xdp_code(image))
        want = list(QUALIFIED_SHAPE_IMMS[(family, entries)])
        assert imms == want, (
            "%s: xdp immediates %r, gate wants %r" % (name, imms, want)
        )
    print("PASS immediates match the gate table")


def test_mir_frameless_per_shape():
    check_tools("llc")
    for name, _source, _family, _entries, _kind, _calls in SHAPES:
        _raw, adapted, _image = built(name)
        workdir = tempfile.mkdtemp(prefix="mojo-genmaps-mir-")
        ll_path = os.path.join(workdir, "adapted.bpf.ll")
        mir_path = os.path.join(workdir, "shape.mir")
        with open(ll_path, "w", encoding="utf-8") as handle:
            handle.write(adapted)
        proc = run_step(
            [
                "llc", "-mtriple=bpfel", "-mcpu=v3",
                "-stop-after=prologepilog", ll_path, "-o", mir_path,
            ]
        )
        assert proc.returncode == 0, (
            "%s: MIR dump failed:\n%s" % (name, proc.stderr)
        )
        with open(mir_path, "r", encoding="utf-8") as handle:
            mir = handle.read()
        assert re.search(r"^fixedStack:\s*\[\]", mir, re.M), (
            "%s: backend placed fixed stack slots" % name
        )
        assert re.search(r"^stack:\s*\[\]", mir, re.M), (
            "%s: backend placed stack slots" % name
        )
    print("PASS MIR frameless for %d shapes" % len(SHAPES))


def test_bpftool_accepts_btf_per_shape():
    check_tools("bpftool")
    for name, _source, _family, _entries, _kind, _calls in SHAPES:
        _raw, _adapted, image = built(name)
        workdir = tempfile.mkdtemp(prefix="mojo-genmaps-btf-")
        object_path = os.path.join(workdir, "shape.bpf.o")
        with open(object_path, "wb") as handle:
            handle.write(image)
        proc = run_step(
            ["bpftool", "btf", "dump", "file", object_path]
        )
        assert proc.returncode == 0, (
            "%s: bpftool btf dump failed:\n%s" % (name, proc.stderr)
        )
        assert "VAR '%s'" % MAP_SYMBOL in proc.stdout, (
            "%s: bpftool dump lacks the map VAR" % name
        )
        assert "DATASEC '.maps'" in proc.stdout, (
            "%s: bpftool dump lacks DATASEC '.maps'" % name
        )
    print("PASS bpftool accepts BTF for %d shapes" % len(SHAPES))


def test_object_layout_per_shape():
    for name, _source, _family, _entries, _kind, _calls in SHAPES:
        _raw, _adapted, image = built(name)
        elf = parse_elf(image)
        assert elf["type"] == ET_REL, "%s: not relocatable" % name
        assert elf["machine"] == EM_BPF, "%s: not EM_BPF" % name
        names = {section["name"] for section in elf["sections"]}
        for section in (".maps", ".BTF", "license", "xdp"):
            assert section in names, (name, section)
    print("PASS object layouts for %d shapes" % len(SHAPES))


def check_negative(name, code):
    check_tools("mojo")
    source = os.path.join(COMPILE_DIR, name + ".mojo")
    raw = mojo_emit(source)
    try:
        adapter.adapt(raw)
    except adapter.AdapterError as exc:
        assert exc.code == code, (name, exc.code, exc)
    else:
        raise AssertionError(
            "%s adapted but must be refused with %s" % (name, code)
        )


def test_oob_key_refused():
    check_negative("maps_oob_key", "MBPF307")
    print("PASS oob key refused with MBPF307")


def test_mixed_kind_refused():
    check_negative("maps_mixed_kind", "MBPF307")
    print("PASS mixed kind refused with MBPF307")


def test_getnext_attempt_refused():
    check_negative("maps_getnext_attempt", "MBPF303")
    print("PASS from-program get-next-key refused with MBPF303")


def main():
    names = sorted(k for k in globals() if k.startswith("test_"))
    failures = 0
    for name in names:
        try:
            globals()[name]()
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        except EnvironmentFailure as exc:
            print("ENVFAIL %s: %s" % (name, exc))
            failures += 1
    if failures:
        return 1
    print("generalized map structures: %d checks passed" % len(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
