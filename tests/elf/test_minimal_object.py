# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built XDP object.

Builds ``examples/xdp_pass/xdp_pass.mojo`` through the genuine pipeline
(``mojo build --emit llvm`` -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and asserts the resulting object is a
minimal single-entrypoint BPF relocatable: EM_BPF machine type, exactly one
executable section holding exactly one function (``xdp_entry``), the exact
license bytes, no call instructions, no code relocations, and no undefined
symbols. The test also asserts the raw frontend IR declares the expected
``i32 @xdp_entry(ptr)`` entry signature.

Requires a working Mojo compiler and LLVM ``llc`` on PATH (for example the
project pixi environment plus system LLVM). A missing tool is reported
as an environment failure; a failing frontend, adapter, or backend step
is a proof failure. Neither ever passes.

The closing tests cross-check the two production ELF readers
(``mojobpf.inspect`` and ``mojobpf.verify``) against the
independent local parse below: one genuine capture must yield one
agreed section set and license payload on all three, and every
corrupt capture must be rejected by both production readers, so
there is no second oracle with its own edge-case opinions. Those
two tests import the production package as their subject; every
other test here stays standard-library-only.

Runnable directly (``python3 tests/elf/test_minimal_object.py``) or under
any ``test_``-style runner. Standard library only.
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
EXAMPLE_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_REL = 9
SHT_RELA = 4
SHN_UNDEF = 0
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"

DEFINE_RE = re.compile(r"^define\s+\S+\s+i32\s+@xdp_entry\(ptr[^)]*\)")


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def run_step(argv, timeout=600):
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    return proc


def build_object():
    """Run the genuine three-step build; return (raw_ir, object_bytes)."""
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (EXAMPLE_SOURCE, ADAPTER):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    workdir = tempfile.mkdtemp(prefix="mojo-xdp-elf-")
    raw_path = os.path.join(workdir, "xdp_pass.ll")
    adapted_path = os.path.join(workdir, "xdp_pass.bpf.ll")
    object_path = os.path.join(workdir, "xdp_pass.bpf.o")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", "-o", raw_path, EXAMPLE_SOURCE]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend reported diagnostics:\n%s" % proc.stderr
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
        raise AssertionError(
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
        raise AssertionError(
            "backend failed (exit %d):\n%s\n%s"
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
    """Parse headers/sections/symbols; return a dict of string-keyed facts."""
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
                    "type": st_info & 0xF,
                    "shndx": st_shndx,
                    "value": st_value,
                    "size": st_size,
                }
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
    assert "xdp" in by_name, "missing xdp section"
    assert "license" in by_name, "missing license section"
    executable = [
        s
        for s in elf["sections"]
        if s["flags"] & SHF_EXECINSTR and s["size"] > 0
    ]
    assert [s["name"] for s in executable] == ["xdp"], (
        "non-empty executable sections must be exactly [xdp], got %r"
        % [s["name"] for s in executable]
    )
    for section in elf["sections"]:
        if section["flags"] & SHF_EXECINSTR and section["size"] == 0:
            assert section["name"] == ".text", (
                "unexpected empty executable section %r"
                % section["name"]
            )
    xdp = by_name["xdp"]
    assert xdp["size"] > 0 and xdp["size"] % 8 == 0, (
        "xdp section size %d is not a positive insn multiple" % xdp["size"]
    )
    funcs = [
        s for s in elf["symbols"] if s["type"] == 2 and s["shndx"] != SHN_UNDEF
    ]
    assert [(f["name"], f["shndx"]) for f in funcs] == [
        ("xdp_entry", xdp["index"])
    ], "expected only xdp_entry as a defined function, got %r"
    assert section_bytes(elf, by_name["license"]) == LICENSE_BYTES, (
        "license section bytes mismatch"
    )


def test_no_runtime_calls():
    _, image = built()
    elf = parse_elf(image)
    by_name = {s["name"]: s for s in elf["sections"]}
    code = section_bytes(elf, by_name["xdp"])
    opcodes = [code[i] for i in range(0, len(code), 8)]
    assert BPF_OP_CALL not in opcodes, "xdp code contains a call instruction"
    assert BPF_OP_EXIT in opcodes, "xdp code has no exit instruction"
    undefined = [s["name"] for s in elf["symbols"] if s["shndx"] == SHN_UNDEF]
    undefined = [name for name in undefined if name]
    assert not undefined, "undefined symbols: %s" % ", ".join(undefined)
    for section in elf["sections"]:
        if section["type"] in (SHT_REL, SHT_RELA):
            assert section["info"] != by_name["xdp"]["index"], (
                "%s relocates the xdp section" % section["name"]
            )


def _production_readers():
    """Import the two production ELF readers as test subjects."""
    src = os.path.join(REPO_ROOT, "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    from mojobpf import inspect as inspect_module
    from mojobpf import verify as verify_module

    return inspect_module, verify_module


def test_shared_reader_agrees_on_genuine_object():
    inspect_module, verify_module = _production_readers()
    _, image = built()
    oracle = parse_elf(image)
    expected = tuple(s["name"] for s in oracle["sections"])
    assert "license" in expected, "genuine object must carry license"
    tmpdir = tempfile.mkdtemp(prefix="shared-reader-")
    try:
        path = os.path.join(tmpdir, "genuine.o")
        with open(path, "wb") as handle:
            handle.write(image)
        observed = inspect_module.object_section_names(path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    assert observed == expected, (observed, expected)
    names, license_out = verify_module.read_elf_sections_bytes(image)
    assert tuple(names) == expected, (names, expected)
    by_name = {s["name"]: s for s in oracle["sections"]}
    assert license_out == section_bytes(oracle, by_name["license"]), (
        "verify must report the oracle's license payload"
    )


def test_shared_reader_agrees_on_corrupt_captures():
    inspect_module, verify_module = _production_readers()
    _, image = built()
    e_shoff = struct.unpack_from("<Q", image, 40)[0]
    e_shnum = struct.unpack_from("<H", image, 60)[0]
    assert e_shoff and e_shnum, "genuine object must carry sections"
    mutations = {
        "empty": b"",
        "truncated-header": image[:32],
        "bad-magic": b"BAD!" + image[4:],
        "bad-class": image[:4] + b"\x01" + image[5:],
        "truncated-section-table": image[: e_shoff + 32],
        "section-table-past-end": (
            image[:40] + struct.pack("<Q", len(image) + 64) + image[48:]
        ),
        "bad-section-name-index": (
            image[:62] + struct.pack("<H", e_shnum + 5) + image[64:]
        ),
    }
    tmpdir = tempfile.mkdtemp(prefix="shared-reader-")
    try:
        for label, mutated in mutations.items():
            path = os.path.join(tmpdir, "corrupt.o")
            with open(path, "wb") as handle:
                handle.write(mutated)
            try:
                inspect_module.object_section_names(path)
            except inspect_module.InspectionError:
                pass
            else:
                raise AssertionError(
                    "inspect accepted corrupt capture %r" % label
                )
            try:
                verify_module.read_elf_sections_bytes(mutated)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    "verify accepted corrupt capture %r" % label
                )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_verify_reproduces_base_ei_version_rejection():
    # Base-behavior preservation (not a new rule): before the
    # shared reader, verification rejected EI_VERSION != 1 while
    # inspection accepted it. The shared container decode follows
    # inspection (no EI_VERSION opinion); the verify path keeps
    # its historical rejection with its historical message, so
    # the report matches base exactly (empty sections, no
    # license/BTF, disabled automatic BTF requirement, a parse
    # error, schema 2).
    inspect_module, verify_module = _production_readers()
    _, image = built()
    assert image[6] == 1, "genuine object must carry EI_VERSION=1"
    mutated = image[:6] + b"\x02" + image[7:]
    try:
        verify_module.read_elf_sections_bytes(mutated)
    except ValueError as exc:
        assert str(exc) == "not a 64-bit little-endian ELF file", (
            str(exc)
        )
    else:
        raise AssertionError("verify accepted EI_VERSION=2")
    tmpdir = tempfile.mkdtemp(prefix="shared-reader-ei-")
    try:
        path = os.path.join(tmpdir, "ei2.o")
        with open(path, "wb") as handle:
            handle.write(mutated)
        observed = inspect_module.object_section_names(path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    oracle = parse_elf(image)
    expected = tuple(s["name"] for s in oracle["sections"])
    assert tuple(observed) == expected, (observed, expected)


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
    print("minimal object: EM_BPF single-entrypoint checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
