# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Artifact-contract checks for built objects.

Builds the canonical programs through the genuine pipeline and
inspects them with ``mojobpf.inspect`` (clean reports, observed
helper IDs, verified license declarations), and exercises every
inspection finding against synthetic byte-level fixtures (corrupt
input, unknown external symbols, license payload defects, profile
violations). A final test proves stable evidence bytes across two
real builds in different directories.

Synthetic-fixture tests need only Python. Real-build tests require
``mojo`` and ``llc`` on PATH plus ``MODULAR_HOME`` (for example the
project pixi environment); missing tools are reported as an
environment failure, never a pass.

Runnable directly (``python3 tests/elf/test_artifact_contract.py``)
or under any ``test_``-style runner. Standard library only.
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import evidence as evidence_module  # noqa: E402
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.build import BuildRequest, build_project  # noqa: E402
from mojobpf.manifest import lookup_profile, parse_manifest  # noqa: E402
from mojobpf.toolchain import ToolchainConfig, probe_toolchain  # noqa: E402

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
MAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "map_roundtrip.mojo")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
SDK_DIR = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")

APACHE = "Apache-2.0 WITH LLVM-exception"
APACHE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
PROFILE = "linux-bpfel-v3"

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
STT_FUNC = 2
SHN_UNDEF = 0

BANNED_ACCEPTANCE_PHRASES = (
    "will load",
    "accepted by",
    "admitted by",
    "safe to load",
    "loadable",
    "kernel will",
    "verifier will",
)


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def _codes(report):
    return (
        [item.code for item in report.structural],
        [item.code for item in report.unsupported],
        [item.code for item in report.license],
    )


def _observations(report):
    return [item.explanation for item in report.observations]


class ElfBuilder:
    """Minimal 64-bit little-endian relocatable object builder."""

    def __init__(self, machine=EM_BPF, objtype=ET_REL):
        self.machine = machine
        self.objtype = objtype
        self.sections = []
        self.symbols = []

    def add_section(self, name, sectype, flags, content, link=0,
                    info=0, align=1, entsize=0):
        """Append a section; return its index (null section is 0)."""
        self.sections.append(
            {
                "name": name,
                "type": sectype,
                "flags": flags,
                "content": bytes(content),
                "link": link,
                "info": info,
                "align": align,
                "entsize": entsize,
            }
        )
        return len(self.sections)

    def add_symbol(self, name, symtype, shndx, value=0, size=0):
        self.symbols.append(
            {
                "name": name,
                "type": symtype,
                "shndx": shndx,
                "value": value,
                "size": size,
            }
        )

    def build(self):
        sections = list(self.sections)
        names = [entry["name"] for entry in sections]
        strtab = b"\x00"
        name_offs = []
        for name in names:
            name_offs.append(len(strtab))
            strtab += name.encode("ascii") + b"\x00"
        symtab_bytes = b""
        symstr = b"\x00"
        sym_offs = []
        if self.symbols:
            for symbol in self.symbols:
                sym_offs.append(len(symstr))
                symstr += symbol["name"].encode("ascii") + b"\x00"
            order = [None] + list(self.symbols)
            for position, symbol in enumerate(order):
                if symbol is None:
                    symtab_bytes += b"\x00" * 24
                    continue
                info = 0x10 | (symbol["type"] & 0xF)
                symtab_bytes += struct.pack(
                    "<IBBHQQ",
                    sym_offs[position - 1],
                    info,
                    0,
                    symbol["shndx"],
                    symbol["value"],
                    symbol["size"],
                )
            symtab_index = len(sections) + 1
            strtab_index = len(sections) + 2
            sections.append(
                {
                    "name": ".symtab",
                    "type": SHT_SYMTAB,
                    "flags": 0,
                    "content": symtab_bytes,
                    "link": strtab_index,
                    "info": 1,
                    "align": 8,
                    "entsize": 24,
                }
            )
            sections.append(
                {
                    "name": ".strtab",
                    "type": SHT_STRTAB,
                    "flags": 0,
                    "content": symstr,
                    "link": 0,
                    "info": 0,
                    "align": 1,
                    "entsize": 0,
                }
            )
            name_offs.append(len(strtab))
            strtab += b".symtab\x00"
            name_offs.append(len(strtab))
            strtab += b".strtab\x00"
        fix = len(strtab)
        strtab += b".shstrtab\x00"
        sections.append(
            {
                "name": ".shstrtab",
                "type": SHT_STRTAB,
                "flags": 0,
                "content": strtab,
                "link": 0,
                "info": 0,
                "align": 1,
                "entsize": 0,
            }
        )
        image = bytearray(b"\x00" * 64)
        offset = 64
        blobs = []
        for entry in sections:
            align = entry["align"] or 1
            pad = (-offset) % align
            offset += pad
            blobs.append(offset)
            offset += len(entry["content"])
        shoff = offset + ((-offset) % 8)
        image += b"\x00" * (shoff - len(image))
        for entry, at in zip(sections, blobs):
            image[at:at + len(entry["content"])] = entry["content"]
        table = bytearray()
        table += b"\x00" * 64
        for position, entry in enumerate(sections):
            if entry["name"] == ".shstrtab":
                name_off = fix
            else:
                name_off = name_offs[position]
            table += struct.pack(
                "<IIQQQQIIQQ",
                name_off,
                entry["type"],
                entry["flags"],
                0,
                blobs[position],
                len(entry["content"]),
                entry["link"],
                entry["info"],
                entry["align"],
                entry["entsize"],
            )
        image += table
        ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
        header = ident
        header += struct.pack("<HHI", self.objtype, self.machine, 1)
        header += struct.pack("<Q", 0)
        header += struct.pack("<Q", 0)
        header += struct.pack("<Q", shoff)
        header += struct.pack("<I", 0)
        header += struct.pack("<HHHHHH", 64, 0, 0, 64, len(sections) + 1,
                              len(sections))
        assert len(header) == 64, len(header)
        image[0:64] = header
        return bytes(image)


def _exit_code():
    return bytes([0x95, 0, 0, 0, 0, 0, 0, 0])


def _call_code(helper_id, src=0):
    return (
        bytes([0x85, (src << 4) & 0xF0, 0, 0])
        + struct.pack("<i", helper_id)
    )


def _clean_builder(license_bytes=APACHE_BYTES, code=None):
    builder = ElfBuilder()
    xdp = builder.add_section(
        "xdp", SHT_PROGBITS, SHF_EXECINSTR,
        _exit_code() if code is None else code, align=8,
    )
    builder.add_section(
        "license", SHT_PROGBITS, 0, license_bytes, align=1
    )
    builder.add_symbol("xdp_entry", STT_FUNC, xdp, size=8)
    return builder


def _write_temp_image(content):
    fd, path = tempfile.mkstemp(prefix="mojobpf-elf-", suffix=".bpf.o")
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
    return path


def _local_sections(image):
    """Read (name, offset, size) rows with an independent mini-parse."""
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    rows = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, _type, _flags, _addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        rows.append((sh_name, sh_offset, sh_size))
    strbase = rows[e_shstrndx][1]
    result = []
    for sh_name, sh_offset, sh_size in rows:
        end = image.index(b"\x00", strbase + sh_name)
        name = image[strbase + sh_name:end].decode("ascii")
        result.append({"name": name, "offset": sh_offset, "size": sh_size})
    return result


def test_synthetic_clean_inspects_clean():
    path = _write_temp_image(_clean_builder().build())
    try:
        report = inspect_module.inspect_object(path, PROFILE)
    finally:
        os.remove(path)
    assert report.ok is True, report.to_dict()
    assert _codes(report) == ([], [], [])
    assert report.license == ()
    notes = _observations(report)
    assert any("xdp" in note and "license" in note for note in notes), notes
    assert any(repr(APACHE_BYTES) in note for note in notes), notes
    assert any("helper IDs observed: (none)" in note for note in notes)
    assert any("xdp_entry" in note for note in notes), notes
    assert any("call instructions: 0" in note for note in notes)


def test_corrupt_inputs_rejected():
    clean = _clean_builder().build()
    cases = [
        (b"", "MBPF401"),
        (b"not an elf object at all....................", "MBPF401"),
        (b"\x7fELF" + b"\x00" * 60, "MBPF401"),
        (clean[:40], "MBPF401"),
    ]
    for index, (content, code) in enumerate(cases):
        path = _write_temp_image(content)
        try:
            report = inspect_module.inspect_object(path, PROFILE)
        finally:
            os.remove(path)
        assert report.ok is False, index
        structural, _, _ = _codes(report)
        assert structural == [code], (index, structural)
    # Section table running past the end.
    bad = bytearray(clean)
    bad[60:62] = struct.pack("<H", 60)
    path = _write_temp_image(bytes(bad))
    try:
        report = inspect_module.inspect_object(path, PROFILE)
    finally:
        os.remove(path)
    assert _codes(report)[0] == ["MBPF402"]
    # Section-name table index out of range.
    bad = bytearray(clean)
    bad[62:64] = struct.pack("<H", 60)
    path = _write_temp_image(bytes(bad))
    try:
        report = inspect_module.inspect_object(path, PROFILE)
    finally:
        os.remove(path)
    assert _codes(report)[0] == ["MBPF402"]
    # Symbol name offset past the string table end.
    builder = _clean_builder()
    image = bytearray(builder.build())
    sym = next(
        entry for entry in _local_sections(image)
        if entry["name"] == ".symtab"
    )
    image[sym["offset"] + 24:sym["offset"] + 28] = struct.pack("<I", 9999)
    path = _write_temp_image(bytes(image))
    try:
        report = inspect_module.inspect_object(path, PROFILE)
    finally:
        os.remove(path)
    assert _codes(report)[0] == ["MBPF402"]


def _inspect_bytes(content):
    path = _write_temp_image(content)
    try:
        return inspect_module.inspect_object(path, PROFILE)
    finally:
        os.remove(path)


def _verify_bytes(content, source=APACHE, kernel=APACHE):
    path = _write_temp_image(content)
    try:
        return inspect_module.verify_object(path, PROFILE, source, kernel)
    finally:
        os.remove(path)


def test_missing_file_raises():
    missing = os.path.join(
        tempfile.gettempdir(), "mojobpf-no-such-object.bpf.o"
    )
    if os.path.exists(missing):
        os.remove(missing)
    for func in (
        lambda: inspect_module.inspect_object(missing, PROFILE),
        lambda: inspect_module.verify_object(
            missing, PROFILE, APACHE, APACHE
        ),
    ):
        try:
            func()
        except inspect_module.InspectionError as exc:
            assert exc.diagnostic.code == "MBPF401", exc.diagnostic
            assert exc.diagnostic.stage == "inspect.object"
        else:
            raise AssertionError("expected MBPF401 for a missing file")
    validated = inspect_module.validate_declaration_pair(APACHE, APACHE)
    try:
        inspect_module.check_object_license(missing, validated)
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF401", exc.diagnostic
    else:
        raise AssertionError("expected MBPF401 for a missing file")


def test_missing_and_extra_license():
    builder = ElfBuilder()
    builder.add_section(
        "xdp", SHT_PROGBITS, SHF_EXECINSTR, _exit_code(), align=8
    )
    report = _inspect_bytes(builder.build())
    assert report.ok is False
    assert _codes(report)[0] == ["MBPF403"]
    assert "missing license" in report.structural[0].explanation

    builder = _clean_builder()
    builder.add_section(
        "license", SHT_PROGBITS, 0, APACHE_BYTES, align=1
    )
    report = _inspect_bytes(builder.build())
    assert _codes(report)[0] == ["MBPF403"]
    assert "conflicting" in report.structural[0].explanation
    verified = _verify_bytes(builder.build())
    assert "MBPF705" in _codes(verified)[2]


def test_malformed_license_payloads():
    for payload in (
        b"",
        b"Apache-2.0 WITH LLVM-exception",
        b"MIT\x00extra\x00",
        b"\xff\xfe\x00",
    ):
        report = _inspect_bytes(_clean_builder(payload).build())
        assert _codes(report)[0] == ["MBPF403"], payload
        verified = _verify_bytes(_clean_builder(payload).build())
        assert "MBPF705" in _codes(verified)[2], payload


def test_license_value_mismatch():
    image = _clean_builder(b"MIT\x00").build()
    validated = inspect_module.validate_declaration_pair(APACHE, APACHE)
    path = _write_temp_image(image)
    try:
        try:
            inspect_module.check_object_license(path, validated)
        except inspect_module.InspectionError as exc:
            assert exc.diagnostic.code == "MBPF705", exc.diagnostic
            assert exc.diagnostic.stage == "inspect.license"
        else:
            raise AssertionError("expected MBPF705 for MIT bytes")
    finally:
        os.remove(path)
    verified = _verify_bytes(image)
    assert _codes(verified)[2] == ["MBPF705"]
    good = _clean_builder().build()
    path = _write_temp_image(good)
    try:
        assert inspect_module.check_object_license(path, validated) == (
            APACHE_BYTES
        )
    finally:
        os.remove(path)
    try:
        inspect_module.check_object_license(path, APACHE)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError for a raw declaration")


def test_unknown_external_symbols():
    builder = _clean_builder()
    builder.add_symbol("helper_x", 0, SHN_UNDEF)
    builder.add_symbol("another_ext", 0, SHN_UNDEF)
    report = _inspect_bytes(builder.build())
    assert _codes(report)[0] == ["MBPF404"]
    explanation = report.structural[0].explanation
    assert "helper_x" in explanation and "another_ext" in explanation


def test_unsupported_section_machine_and_type():
    builder = ElfBuilder()
    builder.add_section(
        "tracepoint/x", SHT_PROGBITS, SHF_EXECINSTR, _exit_code(),
        align=8,
    )
    builder.add_section(
        "license", SHT_PROGBITS, 0, APACHE_BYTES, align=1
    )
    report = _inspect_bytes(builder.build())
    assert _codes(report)[1] == ["MBPF406"]
    verified = _verify_bytes(builder.build())
    assert "MBPF706" in _codes(verified)[2]

    builder = ElfBuilder(machine=62)
    builder.add_section(
        "xdp", SHT_PROGBITS, SHF_EXECINSTR,
        _call_code(7) + _exit_code(), align=8,
    )
    builder.add_section(
        "license", SHT_PROGBITS, 0, APACHE_BYTES, align=1
    )
    report = _inspect_bytes(builder.build())
    # Non-BPF bytes are not decoded as BPF: only the machine finding.
    assert _codes(report) == ([], ["MBPF406"], [])

    builder = ElfBuilder(objtype=2)
    builder.add_section(
        "xdp", SHT_PROGBITS, SHF_EXECINSTR, _exit_code(), align=8
    )
    builder.add_section(
        "license", SHT_PROGBITS, 0, APACHE_BYTES, align=1
    )
    report = _inspect_bytes(builder.build())
    assert _codes(report)[1] == ["MBPF406"]


def test_unsupported_calls():
    code = _call_code(1) + _call_code(2) + _exit_code()
    report = _inspect_bytes(_clean_builder(code=code).build())
    assert _codes(report) == ([], [], [])
    notes = _observations(report)
    assert any("helper IDs observed: 1, 2" in note for note in notes)
    assert any("call instructions: 2" in note for note in notes)

    report = _inspect_bytes(
        _clean_builder(code=_call_code(7) + _exit_code()).build()
    )
    assert _codes(report)[1] == ["MBPF407"]
    assert "7" in report.unsupported[0].explanation

    pseudo = bytes([0x8D, 0x10, 0, 0, 1, 0, 0, 0]) + _exit_code()
    report = _inspect_bytes(_clean_builder(code=pseudo).build())
    assert _codes(report)[1] == ["MBPF407"]

    odd = _call_code(1, src=1) + _exit_code()
    report = _inspect_bytes(_clean_builder(code=odd).build())
    assert _codes(report)[1] == ["MBPF407"]


def test_license_layer_agrees_on_helper7_object():
    image = _clean_builder(code=_call_code(7) + _exit_code()).build()
    report = _inspect_bytes(image)
    assert _codes(report)[1] == ["MBPF407"]
    verified = _verify_bytes(image)
    structural, unsupported, licensed = _codes(verified)
    assert structural == []
    assert unsupported == ["MBPF407"]
    assert licensed == ["MBPF706"]


def test_reloc_and_consistency_findings():
    builder = _clean_builder()
    builder.add_section(
        ".maps", SHT_PROGBITS, 0, b"\x00" * 32, align=8
    )
    report = _inspect_bytes(builder.build())
    assert _codes(report)[0] == ["MBPF405"]

    builder = _clean_builder()
    builder.add_section(".BTF", SHT_PROGBITS, 0, b"\x00" * 8, align=1)
    report = _inspect_bytes(builder.build())
    assert _codes(report)[0] == ["MBPF405"]

    builder = _clean_builder()
    builder.add_section(
        ".rela.xdp", SHT_RELA, 0, struct.pack("<QQq", 0, 1, 0),
        link=0, info=99, align=8, entsize=24,
    )
    report = _inspect_bytes(builder.build())
    assert _codes(report)[0] == ["MBPF405"]

    builder = _clean_builder()
    builder.add_section(
        ".rela.xdp", SHT_RELA, 0, struct.pack("<QQq", 999, 1, 0),
        link=0, info=1, align=8, entsize=24,
    )
    report = _inspect_bytes(builder.build())
    assert _codes(report)[0] == ["MBPF405"]

    builder = _clean_builder()
    report = _inspect_bytes(builder.build())
    assert _codes(report) == ([], [], [])
    builder = ElfBuilder()
    builder.add_section(
        "xdp", SHT_PROGBITS, SHF_EXECINSTR, b"\x95" * 10, align=1
    )
    builder.add_section(
        "license", SHT_PROGBITS, 0, APACHE_BYTES, align=1
    )
    report = _inspect_bytes(builder.build())
    assert _codes(report)[0] == ["MBPF405"]

    wide = bytes([0x18, 0, 0, 0, 0, 0, 0, 0])
    report = _inspect_bytes(_clean_builder(code=wide).build())
    assert _codes(report)[0] == ["MBPF405"]


def test_btfext_rejected():
    builder = _clean_builder()
    builder.add_section(".BTF.ext", SHT_PROGBITS, 0, b"\x00" * 8, align=1)
    report = _inspect_bytes(builder.build())
    assert _codes(report)[1] == ["MBPF407"]


def test_verify_rejects_bad_declarations():
    image = _clean_builder().build()
    verified = _verify_bytes(image, APACHE, "GPL")
    assert _codes(verified)[2] == ["MBPF704"]
    dual = "GPL-2.0-only OR MIT"
    verified = _verify_bytes(image, dual, dual)
    assert _codes(verified)[2] == ["MBPF703"]
    verified = _verify_bytes(image, "MIT OR", "MIT")
    assert _codes(verified)[2] == ["MBPF701"]


def test_reports_claim_no_kernel_acceptance():
    clean = _verify_bytes(_clean_builder().build())
    dirty = _verify_bytes(
        _clean_builder(code=_call_code(7) + _exit_code()).build()
    )
    for report in (clean, dirty):
        assert report.ok in (True, False)
        text = json.dumps(report.to_dict())
        for phrase in BANNED_ACCEPTANCE_PHRASES:
            assert phrase not in text, phrase


def test_unknown_profile_rejected():
    image = _clean_builder().build()
    path = _write_temp_image(image)
    try:
        for func in (
            lambda: inspect_module.inspect_object(path, "no-such"),
            lambda: inspect_module.verify_object(
                path, "no-such", APACHE, APACHE
            ),
        ):
            try:
                func()
            except Exception as exc:  # noqa: BLE001 - carrier varies
                assert exc.diagnostic.code == "MBPF101", exc.diagnostic
            else:
                raise AssertionError("expected MBPF101")
        profile = lookup_profile(PROFILE)
        report = inspect_module.inspect_object(path, profile)
        assert report.ok is True
    finally:
        os.remove(path)


def test_empty_exec_section_observed():
    builder = _clean_builder()
    builder.add_section(".text", SHT_PROGBITS, SHF_EXECINSTR, b"", align=1)
    report = _inspect_bytes(builder.build())
    assert _codes(report) == ([], [], [])
    assert any(".text" in note for note in _observations(report))


def _require_tools():
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    if not os.environ.get("MODULAR_HOME"):
        raise EnvironmentFailure("MODULAR_HOME is not set")
    for path in (CLASSIFIER_SOURCE, MAP_SOURCE, ADAPTER, SERVICE, SDK_DIR):
        if not os.path.exists(path):
            raise EnvironmentFailure("missing repo path: %s" % path)
    found = shutil.which("mojo")
    assert found is not None
    return os.path.dirname(found)


def _run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def _build_uncached(source, with_sdk):
    workdir = tempfile.mkdtemp(prefix="mojobpf-contract-")
    try:
        raw_path = os.path.join(workdir, "prog.ll")
        adapted_path = os.path.join(workdir, "prog.bpf.ll")
        object_path = os.path.join(workdir, "prog.bpf.o")
        frontend = ["mojo", "build", "--emit", "llvm"]
        if with_sdk:
            frontend += ["-I", SDK_DIR]
        frontend += ["-o", raw_path, source]
        proc = _run_step(frontend)
        if proc.returncode != 0 or not os.path.isfile(raw_path):
            raise AssertionError(
                "frontend failed (exit %d):\n%s\n%s"
                % (proc.returncode, proc.stdout, proc.stderr)
            )
        if "error:" in proc.stderr.lower():
            raise AssertionError(
                "frontend reported diagnostics:\n%s" % proc.stderr
            )
        proc = _run_step(
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
        proc = _run_step(
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
        with open(object_path, "rb") as handle:
            return handle.read()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


_CACHED = {}


def _build_image(source, with_sdk):
    _require_tools()
    key = (source, with_sdk)
    if key not in _CACHED:
        _CACHED[key] = _build_uncached(source, with_sdk)
    return _CACHED[key]


def _inspect_image(image):
    path = _write_temp_image(image)
    try:
        return inspect_module.inspect_object(path, PROFILE)
    finally:
        os.remove(path)


def _verify_image(image, source=APACHE, kernel=APACHE):
    path = _write_temp_image(image)
    try:
        return inspect_module.verify_object(path, PROFILE, source, kernel)
    finally:
        os.remove(path)


def test_canonical_classifier_inspects_clean():
    image = _build_image(CLASSIFIER_SOURCE, False)
    report = _inspect_image(image)
    assert report.ok is True, report.to_dict()
    assert _codes(report) == ([], [], [])
    notes = _observations(report)
    assert any(repr(APACHE_BYTES) in note for note in notes), notes
    assert any("helper IDs observed: (none)" in note for note in notes)
    assert any("xdp_entry" in note for note in notes), notes


def test_canonical_map_inspects_clean():
    image = _build_image(MAP_SOURCE, True)
    report = _inspect_image(image)
    assert report.ok is True, report.to_dict()
    assert _codes(report) == ([], [], [])
    notes = _observations(report)
    assert any("helper IDs observed: 1, 2" in note for note in notes)
    assert any("call instructions: 2" in note for note in notes)
    assert any(
        ".maps present: True, .BTF present: True" in note for note in notes
    ), notes


def test_canonical_verify_with_project_declaration():
    for source, with_sdk in (
        (CLASSIFIER_SOURCE, False),
        (MAP_SOURCE, True),
    ):
        verified = _verify_image(_build_image(source, with_sdk))
        assert verified.ok is True, verified.to_dict()
        assert _codes(verified) == ([], [], [])


def test_helper7_patched_canonical_object():
    image = _build_image(MAP_SOURCE, True)
    rows = _local_sections(image)
    xdp = next(entry for entry in rows if entry["name"] == "xdp")
    code = image[xdp["offset"]:xdp["offset"] + xdp["size"]]
    pattern = bytes([0x85, 0, 0, 0, 1, 0, 0, 0])
    assert code.count(pattern) == 1, "expected one helper-1 call"
    patched = (
        image[:xdp["offset"]]
        + code.replace(pattern, bytes([0x85, 0, 0, 0, 7, 0, 0, 0]))
        + image[xdp["offset"] + xdp["size"]:]
    )
    report = _inspect_image(patched)
    assert _codes(report)[1] == ["MBPF407"]
    assert any(
        "helper IDs observed: 2, 7" in note
        for note in _observations(report)
    )
    verified = _verify_image(patched)
    structural, unsupported, licensed = _codes(verified)
    assert structural == []
    assert unsupported == ["MBPF407"]
    assert licensed == ["MBPF706"]


def test_license_terminator_patched_canonical_object():
    image = _build_image(CLASSIFIER_SOURCE, False)
    assert image.count(APACHE_BYTES) == 1
    patched = image.replace(APACHE_BYTES, APACHE_BYTES[:-1] + b"A")
    report = _inspect_image(patched)
    assert _codes(report)[0] == ["MBPF403"]
    assert "NUL" in report.structural[0].explanation
    verified = _verify_image(patched)
    assert _codes(verified)[2] == ["MBPF705"]
    validated = inspect_module.validate_declaration_pair(APACHE, APACHE)
    path = _write_temp_image(patched)
    try:
        try:
            inspect_module.check_object_license(path, validated)
        except inspect_module.InspectionError as exc:
            assert exc.diagnostic.code == "MBPF705", exc.diagnostic
        else:
            raise AssertionError("expected MBPF705 for flipped bytes")
    finally:
        os.remove(path)


def test_evidence_byte_stable_across_build_dirs():
    bindir = _require_tools()
    blobs = []
    manifest_text = (
        "schema_version = 1\n"
        "[project]\n"
        'name = "demo"\n'
        "[target]\n"
        'profile = "linux-bpfel-v3"\n'
        "[artifact]\n"
        'name = "demo"\n'
        'source_license = "Apache-2.0 WITH LLVM-exception"\n'
        'kernel_license = "Apache-2.0 WITH LLVM-exception"\n'
        "[[programs]]\n"
        'source = "prog.mojo"\n'
        'entry = "xdp_entry"\n'
        'program_type = "xdp"\n'
        'section = "xdp"\n'
    )
    with open(CLASSIFIER_SOURCE, "rb") as handle:
        program_bytes = handle.read()
    for _ in range(2):
        parent = tempfile.mkdtemp(prefix="mojobpf-evidence-")
        try:
            project = os.path.join(parent, "proj")
            os.makedirs(project)
            manifest_path = os.path.join(project, "mojobpf.toml")
            with open(manifest_path, "w", encoding="utf-8") as handle:
                handle.write(manifest_text)
            with open(
                os.path.join(project, "prog.mojo"), "wb"
            ) as handle:
                handle.write(program_bytes)
            out_dir = os.path.join(parent, "out")
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=SERVICE,
                    search_paths=(bindir,),
                    timeout_s=600,
                )
            )
            assert result.success is True, result.diagnostics
            manifest = parse_manifest(manifest_path)
            toolchain = probe_toolchain(
                ToolchainConfig(search_paths=(bindir,))
            )
            evidence = evidence_module.evidence_from_build(
                result,
                manifest,
                project_dir=project,
                out_dir=out_dir,
                transforms=(
                    "frontend:mojo-llvm",
                    "adapter:service-v1",
                    "backend:llc-bpfel-v3",
                ),
                flags=("mojo:--emit=llvm", "llc:-mcpu=v3"),
                toolchain=toolchain,
            )
            raw = evidence_module.dumps_evidence(evidence)
            assert parent.encode() not in raw
            blobs.append(raw)
        finally:
            shutil.rmtree(parent, ignore_errors=True)
    assert blobs[0] == blobs[1]
    doc = json.loads(blobs[0].decode("ascii"))
    assert doc["outputs"] == [
        {
            "path": "demo.bpf.o",
            "sha256": doc["outputs"][0]["sha256"],
            "size": doc["outputs"][0]["size"],
        }
    ]
    assert doc["success"] is True


def test_canonical_reports_claim_no_kernel_acceptance():
    for source, with_sdk in (
        (CLASSIFIER_SOURCE, False),
        (MAP_SOURCE, True),
    ):
        verified = _verify_image(_build_image(source, with_sdk))
        text = json.dumps(verified.to_dict())
        for phrase in BANNED_ACCEPTANCE_PHRASES:
            assert phrase not in text, phrase


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
    print("artifact contract: inspection and license checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
