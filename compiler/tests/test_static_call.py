# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-CALLS/pseudo/static-call: BPF_PSEUDO_CALL value and static-call emission.

BPF_PSEUDO_CALL is the UAPI value 1 carried in
the src_reg of a 0x85 call insn; the imm is a
relocation placeholder (-1) resolved by an
R_BPF_64_32 (type 10) relocation against the
defined callee. The production parsed-route
build of the committed subprog example emits
exactly one static call at 0x38. Admission is
exactly one profile: subprog_supported is True
only on linux-bpfel-v3-subprog. The 0x8D
encoding is refused everywhere (existing
artifact-contract probe, cited here). This suite
pins the UAPI value, the production-route
encoding, the admission view, and the inspect
gate on the production object.

Requires a working Mojo compiler and LLVM ``llc``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 compiler/tests/test_static_call.py``) or
under any ``test_``-style runner. Standard library only.
"""
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
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import (  # noqa: E402
    BuildRequest,
    build_project,
)
from mojobpf.capabilities import (  # noqa: E402
    SUPPORTED_PROFILE_IDS,
    lookup_profile,
)
from mojobpf.elf_reader import (  # noqa: E402
    parse_elf,
    section_bytes,
)
from mojobpf.inspect import (  # noqa: E402
    inspect_object,
)

EXAMPLE_DIR = os.path.join(
    REPO_ROOT, "examples", "subprog_call"
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")
PIXI_BIN = os.path.join(REPO_ROOT, ".pixi", "envs", "default", "bin")
UAPI_HEADER = "/usr/include/linux/bpf.h"

BASE_PROFILE = "linux-bpfel-v3"
SUBPROG_PROFILE = "linux-bpfel-v3-subprog"

BPF_PSEUDO_CALL = 1
BPF_OP_CALL = 0x85
BPF_OP_REFUSED_PSEUDO = 0x8D
R_BPF_64_32 = 10
SHT_REL = 9
STT_FUNC = 2
CALL_OFFSET = 0x38
CALLEE = "decide"

DESCRIPTOR_PATHS = (
    os.path.join(REPO_ROOT, "compiler", "admission.json"),
    os.path.join(
        REPO_ROOT, "src", "mojobpf", "resources", "adapter",
        "admission.json",
    ),
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
        found = shutil.which(tool) or os.path.join(PIXI_BIN, tool)
        if not (shutil.which(tool) or os.path.isfile(found)):
            raise EnvironmentFailure("%s not found" % tool)


def build_production():
    """Build the committed example via the production route.

    Returns the object bytes. The parsed route is
    asserted on the evidence transforms.
    """
    check_tools("mojo", "llc")
    for path in (
            os.path.join(EXAMPLE_DIR, "decision.mojo"),
            os.path.join(EXAMPLE_DIR, "mojobpf.toml"),
            SERVICE, LOCKFILE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    parent = tempfile.mkdtemp(prefix="mojo-static-prod-")
    try:
        project = os.path.join(parent, "proj")
        os.makedirs(project)
        for name in ("decision.mojo", "mojobpf.toml"):
            shutil.copyfile(
                os.path.join(EXAMPLE_DIR, name),
                os.path.join(project, name),
            )
        manifest_path = os.path.join(project, "mojobpf.toml")
        out_dir = os.path.join(parent, "out")
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=SERVICE,
                search_paths=(PIXI_BIN,),
                timeout_s=600,
                lockfile_path=LOCKFILE,
            )
        )
        assert result.success is True, (
            [str(item) for item in result.diagnostics],
        )
        with open(
            os.path.join(out_dir, "subprog_decision.evidence.json"),
            encoding="utf-8",
        ) as handle:
            evidence = json.load(handle)
        assert "ir-adapter(parsed)" in evidence["transforms"], (
            evidence["transforms"]
        )
        objects = sorted(
            entry for entry in os.listdir(out_dir)
            if entry.endswith(".bpf.o")
        )
        assert len(objects) == 1, objects
        with open(os.path.join(out_dir, objects[0]), "rb") as handle:
            return handle.read()
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def decode_calls(code):
    """Decode (offset, src, imm) for every 0x85 insn."""
    calls = []
    for off in range(0, len(code), 8):
        if code[off] != BPF_OP_CALL:
            continue
        (imm,) = struct.unpack_from("<i", code, off + 4)
        calls.append((off, (code[off + 1] >> 4) & 0xF, imm))
    return calls


def read_relxdp(image):
    """Read .relxdp entries + symtab names from the image.

    Returns (relocs, symbols) with relocs as (offset,
    type, sym_ordinal) and symbols as (name, type,
    shndx) indexed by ordinal.
    """
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
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
            (index, sh_name, sh_type, sh_offset, sh_size)
        )
    strsec = sections[e_shstrndx]
    blob = image[strsec[3]:strsec[3] + strsec[4]]

    def section_name(section):
        end = blob.index(b"\x00", section[1])
        return blob[section[1]:end].decode("ascii")

    named = {section_name(s): s for s in sections}
    symtab = named[".symtab"]
    (link,) = struct.unpack_from(
        "<I", image, e_shoff + symtab[0] * e_shentsize + 40
    )
    strblob_sec = sections[link]
    strblob = image[
        strblob_sec[3]:strblob_sec[3] + strblob_sec[4]
    ]
    symbols = []
    for ordinal in range(symtab[4] // 24):
        off = symtab[3] + ordinal * 24
        (st_name, st_info, _other, st_shndx, _v, _s) = (
            struct.unpack_from("<IBBHQQ", image, off)
        )
        end = strblob.index(b"\x00", st_name)
        symbols.append(
            (strblob[st_name:end].decode("ascii"),
             st_info & 0xF, st_shndx)
        )
    relocs = []
    for section in sections:
        if section[2] != SHT_REL:
            continue
        if section_name(section) != ".relxdp":
            continue
        for ordinal in range(section[4] // 16):
            off = section[3] + ordinal * 16
            (r_offset, r_info) = struct.unpack_from(
                "<QQ", image, off
            )
            relocs.append(
                (r_offset, r_info & 0xFFFFFFFF, r_info >> 32)
            )
    text_index = named[".text"][0]
    return relocs, symbols, text_index


def check_encoding(calls, relocs, symbols, text_index, source):
    """One static call at 0x38 with a type-10 callee reloc."""
    assert [off for off, _, _ in calls] == [CALL_OFFSET], (
        source, calls)
    _off, src, imm = calls[0]
    assert (src, imm) == (BPF_PSEUDO_CALL, -1), (
        source, src, imm)
    assert len(relocs) == 1, (source, relocs)
    rel_off, rel_type, rel_sym = relocs[0]
    assert (rel_off, rel_type) == (CALL_OFFSET, R_BPF_64_32), (
        source, relocs)
    name, sym_type, sym_shndx = symbols[rel_sym]
    assert name == CALLEE, (source, name)
    assert sym_type == STT_FUNC, (source, sym_type)
    assert sym_shndx == text_index, (source, sym_shndx)


def check_admission(descriptor_paths, profiles):
    """subprog_supported is True on exactly -subprog."""
    assert profiles, "profile walk must stay populated"
    assert SUBPROG_PROFILE in profiles, profiles
    for profile_id in profiles:
        supported = lookup_profile(profile_id).subprog_supported
        assert supported == (profile_id == SUBPROG_PROFILE), (
            profile_id, supported)
    for path in descriptor_paths:
        with open(path, encoding="utf-8") as handle:
            descriptor = json.load(handle)
        entries = descriptor["profiles"]
        assert set(entries) == set(profiles), (path, entries)
        for profile_id, entry in sorted(entries.items()):
            assert entry["subprog_supported"] == (
                profile_id == SUBPROG_PROFILE), (
                path, profile_id, entry)


def program_code(image, section="xdp"):
    elf = parse_elf(image, "built")
    sections = [s for s in elf.sections if s.name == section]
    assert len(sections) == 1, [s.name for s in elf.sections]
    return section_bytes(elf, sections[0])


def test_bpf_pseudo_call_value():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r"#define\s+BPF_PSEUDO_CALL\s+(\d+)", text)
    assert match, "UAPI BPF_PSEUDO_CALL missing"
    assert int(match.group(1)) == BPF_PSEUDO_CALL, match.group(1)
    assert BPF_OP_CALL == 0x85, hex(BPF_OP_CALL)
    assert BPF_OP_REFUSED_PSEUDO != BPF_OP_CALL
    code = program_code(build_production())
    assert BPF_OP_REFUSED_PSEUDO.to_bytes(1, "little") not in (
        code[0::8]
    ), "production object must not carry 0x8D"


def test_static_call_encoding():
    image = build_production()
    calls = decode_calls(program_code(image))
    relocs, symbols, text_index = read_relxdp(image)
    check_encoding(calls, relocs, symbols, text_index, "decision")


def test_subprog_admission():
    check_admission(DESCRIPTOR_PATHS, SUPPORTED_PROFILE_IDS)


def test_production_inspect_gate():
    image = build_production()
    parent = tempfile.mkdtemp(prefix="mojo-static-gate-")
    try:
        object_path = os.path.join(parent, "prod.o")
        with open(object_path, "wb") as handle:
            handle.write(image)
        report = inspect_object(object_path, SUBPROG_PROFILE)
        assert report.ok, (
            report.structural + report.unsupported + report.license
        )
        notes = [item.explanation for item in report.observations]
        assert any(
            "subprogram calls: 1" in note for note in notes
        ), notes
        report = inspect_object(object_path, BASE_PROFILE)
        assert not report.ok, BASE_PROFILE
        codes = sorted(item.code for item in report.unsupported)
        assert codes == ["MBPF406", "MBPF407"], codes
    finally:
        shutil.rmtree(parent, ignore_errors=True)


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
    print("static call: value and emission checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
