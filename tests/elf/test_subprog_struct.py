# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built subprogram-call objects.

Builds ``examples/subprog_call/decision.mojo`` (callee defined
first) and ``tests/compile/subprog_entry_first.mojo``
(entrypoint defined first) through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import
path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and asserts each resulting
object is a conventional BPF relocatable for one XDP program
with one static subprogram: EM_BPF machine type, exactly two
executable sections (``.text`` holding the 40-byte callee,
``xdp`` holding the 72-byte entrypoint), the exact license
bytes, exactly one static call (opcode ``0x85`` with source
register 1 and immediate ``-1``) plus one relocation of type
``R_BPF_64_32`` against the callee symbol, and no map or BTF
sections (the call shape rides the classifier path).

Also proves the profile gate at the object layer: the objects
inspect clean under ``linux-bpfel-v3-subprog`` (with the
subprogram observations recorded) and are refused under the
base profile with MBPF406 (``.text``) plus MBPF407 (the static
call), so a call program can never reach the kernel through a
profile that does not admit the shape.

Requires a working Mojo compiler and LLVM ``llc`` on PATH. A
missing tool is reported as an environment failure; a failing
frontend, adapter, or backend step is a proof failure. Neither
ever passes.

Runnable directly (``python3 tests/elf/test_subprog_struct.py``)
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
from mojobpf.inspect import inspect_object  # noqa: E402

DECISION_SOURCE = os.path.join(
    REPO_ROOT, "examples", "subprog_call", "decision.mojo"
)
ENTRY_FIRST_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_entry_first.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

BASE_PROFILE = "linux-bpfel-v3"
SUBPROG_PROFILE = "linux-bpfel-v3-subprog"

# Independent direct-path pins for the committed call family. The
# kernel suite pins the same object bytes through its own staged
# builds; both paths must agree.
DECISION_RAW_HASH = (
    "d19d7ebe2fb5fafbf3a7449b3a2bfc8eeafb248733082b70056d99ff317528f3"
)
DECISION_ADAPTED_HASH = (
    "2d04c4c138a6f4ff5d62ceed85f69830096e1d3f3792345d690914ec56ae9270"
)
DECISION_OBJECT_HASH = (
    "6bc42a7e1cbd90befb7f01a2a4a2a4d0442561792f46248cce9afb3e404b8b56"
)
ENTRY_FIRST_RAW_HASH = (
    "cb29b3e324b7ec9f556726f9dad49b191a06419e0311902bd8389ef26e20c0c3"
)
ENTRY_FIRST_ADAPTED_HASH = (
    "5d0453b132a0abc163976566ee04b207fc68758770077cde80f023deb7720141"
)
ENTRY_FIRST_OBJECT_HASH = (
    "c62683ac82ac5f62cf704f9e921855d218459e663bff1a504b2b887d1d583115"
)

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_REL = 9
STB_GLOBAL = 1
STT_FUNC = 2
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
R_BPF_64_32 = 10
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
TEXT_SIZE = 40
XDP_SIZE = 72
CALL_OFFSET = 0x38

_BUILT = {}


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
    workdir = tempfile.mkdtemp(prefix="mojo-subprog-")
    raw_path = os.path.join(workdir, "raw.ll")
    adapted_path = os.path.join(workdir, "adapted.ll")
    object_path = os.path.join(workdir, "prog.o")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm",
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


def built(tag, source):
    if tag not in _BUILT:
        assert adapter.validate(
            build_object(source)[0]
        ) == "subprog", tag
        _BUILT[tag] = build_object(source)
    return _BUILT[tag]


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
            (st_name, st_info, _other, st_shndx, _v, st_size) = (
                struct.unpack_from("<IBBHQQ", image, off)
            )
            end = strblob.index(b"\x00", st_name)
            symbols.append(
                {
                    "ordinal": ordinal,
                    "name": strblob[st_name:end].decode("ascii"),
                    "bind": st_info >> 4,
                    "type": st_info & 0xF,
                    "shndx": st_shndx,
                    "size": st_size,
                }
            )
    relocations = []
    for section in sections:
        if section["type"] != SHT_REL:
            continue
        count = section["size"] // 16
        for ordinal in range(count):
            off = section["offset"] + ordinal * 16
            (r_offset, r_info) = struct.unpack_from("<QQ", image, off)
            relocations.append(
                {
                    "section": section["name"],
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


def _check_hashes(tag, source, raw_hash, adapted_hash, object_hash):
    check_tools("mojo", "llc")
    raw_ir, adapted_ir, image, _path = built(tag, source)
    assert hashlib.sha256(raw_ir.encode("utf-8")).hexdigest() == (
        raw_hash
    ), tag
    assert hashlib.sha256(adapted_ir.encode("utf-8")).hexdigest() == (
        adapted_hash
    ), tag
    assert hashlib.sha256(image).hexdigest() == object_hash, tag


def test_decision_hashes():
    _check_hashes(
        "decision", DECISION_SOURCE, DECISION_RAW_HASH,
        DECISION_ADAPTED_HASH, DECISION_OBJECT_HASH,
    )


def test_entry_first_hashes():
    _check_hashes(
        "entry_first", ENTRY_FIRST_SOURCE, ENTRY_FIRST_RAW_HASH,
        ENTRY_FIRST_ADAPTED_HASH, ENTRY_FIRST_OBJECT_HASH,
    )


def _check_shape(tag, source, callee, entry_section="xdp"):
    check_tools("mojo", "llc")
    _raw, _adapted, image, _path = built(tag, source)
    elf = parse_elf(image)
    assert elf["type"] == ET_REL, tag
    assert elf["machine"] == EM_BPF, tag
    by_name = {s["name"]: s for s in elf["sections"]}
    executable = sorted(
        s["name"]
        for s in elf["sections"]
        if s["flags"] & SHF_EXECINSTR and s["size"] > 0
    )
    assert executable == [".text", entry_section], (tag, executable)
    assert by_name[".text"]["size"] == TEXT_SIZE, tag
    assert by_name[entry_section]["size"] == XDP_SIZE, tag
    assert by_name["license"]["size"] == len(LICENSE_BYTES), tag
    blob = image[
        by_name["license"]["offset"]:
        by_name["license"]["offset"] + by_name["license"]["size"]
    ]
    assert blob == LICENSE_BYTES, tag
    funcs = {
        sym["name"]: sym
        for sym in elf["symbols"]
        if sym["type"] == STT_FUNC and sym["bind"] == STB_GLOBAL
    }
    assert sorted(funcs) == sorted(["xdp_entry", callee]), (
        tag,
        sorted(funcs),
    )
    assert funcs[callee]["size"] == TEXT_SIZE, tag
    assert funcs["xdp_entry"]["size"] == XDP_SIZE, tag
    assert funcs[callee]["shndx"] == by_name[".text"]["index"], tag
    assert funcs["xdp_entry"]["shndx"] == (
        by_name[entry_section]["index"]
    ), tag
    for name in by_name:
        assert "maps" not in name and "BTF" not in name, (tag, name)
    return elf, image


def test_decision_elf_shape():
    _check_shape("decision", DECISION_SOURCE, "decide")


def test_entry_first_elf_shape():
    _check_shape("entry_first", ENTRY_FIRST_SOURCE, "classify")


def _check_call_encoding(tag, source, callee):
    check_tools("mojo", "llc")
    elf, image = _check_shape(tag, source, callee)
    by_name = {s["name"]: s for s in elf["sections"]}
    text = by_name[".text"]
    code = image[text["offset"]:text["offset"] + text["size"]]
    assert len(code) == TEXT_SIZE, tag
    assert BPF_OP_CALL.to_bytes(1, "little") not in (
        code[0::8]
    ), (tag, "callee must carry no call")
    assert code[-8] == BPF_OP_EXIT, tag
    xdp = by_name["xdp"]
    body = image[xdp["offset"]:xdp["offset"] + xdp["size"]]
    calls = [
        off
        for off in range(0, len(body), 8)
        if body[off] == BPF_OP_CALL
    ]
    assert calls == [CALL_OFFSET], (tag, calls)
    src = (body[CALL_OFFSET + 1] >> 4) & 0xF
    (imm,) = struct.unpack_from("<i", body, CALL_OFFSET + 4)
    assert src == 1, (tag, src)
    assert imm == -1, (tag, imm)
    assert body[-8] == BPF_OP_EXIT, tag
    rels = [
        rel
        for rel in elf["relocations"]
        if rel["section"] == ".relxdp"
    ]
    assert len(rels) == 1, (tag, rels)
    assert rels[0]["offset"] == CALL_OFFSET, (tag, rels)
    assert rels[0]["type"] == R_BPF_64_32, (tag, rels)
    target = elf["symbols"][rels[0]["sym"]]
    assert target["name"] == callee, (tag, target)


def test_decision_call_encoding():
    _check_call_encoding("decision", DECISION_SOURCE, "decide")


def test_entry_first_call_encoding():
    _check_call_encoding("entry_first", ENTRY_FIRST_SOURCE, "classify")


def _check_profile_gating(tag, source):
    check_tools("mojo", "llc")
    _raw, _adapted, _image, object_path = built(tag, source)
    report = inspect_object(object_path, SUBPROG_PROFILE)
    assert report.ok, (
        tag,
        report.structural + report.unsupported + report.license,
    )
    notes = [item.explanation for item in report.observations]
    assert any("call instructions: 1" in note for note in notes), notes
    assert any("subprogram calls: 1" in note for note in notes), notes
    assert any(
        "subprogram section .text holds %d bytes" % TEXT_SIZE in note
        for note in notes
    ), notes
    report = inspect_object(object_path, BASE_PROFILE)
    assert not report.ok, tag
    codes = sorted(item.code for item in report.unsupported)
    assert codes == ["MBPF406", "MBPF407"], (tag, codes)


def test_decision_profile_gating():
    _check_profile_gating("decision", DECISION_SOURCE)


def test_entry_first_profile_gating():
    _check_profile_gating("entry_first", ENTRY_FIRST_SOURCE)


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
    print("subprogram structure: both orders pinned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
