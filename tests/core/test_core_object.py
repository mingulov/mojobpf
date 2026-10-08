# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built CO-RE relocation probe.

Builds ``tests/core/core_read.mojo`` through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import
path -> ``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel
-mcpu=v3``) and asserts the resulting object is a conventional BPF
relocatable carrying exactly the two pinned relocation records:
EM_BPF machine type, exactly one executable section holding
exactly one function (``xdp_entry``), the exact license bytes,
exactly one ``call 1`` (lookup) and no other helper call, one map
relocation against the ``.maps`` symbol, a 32-byte all-zero
``.maps`` section, map BTF describing a one-entry array map with
u32 keys and a 4096-byte value, ``.BTF.ext`` records for exactly
one ``task_struct.pid`` byte-offset access plus one
``task_struct.scx`` existence check, and a genuine conditional
branch on the existence result (the null check plus the exists
guard, pinned by opcode, offset, and skip distance, with the
exists arm folding ``0x10000`` into the observation word).

The relocation content is resolved with the independent reader
(``tests/core/btfext_reader.py``, which shares no code with the
product parser) and cross-checked against ``bpftool btf dump``
(field/type IDs, member offsets, sizes). A third leg, the
loader's load transcript (``LIBBPF_DEBUG=1`` output captured
and retained by the kernel suite
``tests/kernel/test_core_layouts.py`` for audit), carries no
per-relocation lines, so no relocation assertion is made on
it; the in-kernel proof is the lane-correct observed word, not
a transcript comparison. The reader's isolation (standard
library only, no product or test imports) is asserted here, in
a fresh subprocess.

Also locks the adapted-IR hash and the ``xdp`` section bytes so
adapter or backend evolution cannot silently change the core
pipeline, pins the spill-gate immediates, proves
``verify_object`` accepts the object under the CO-RE profile
while the base profile refuses its ``.BTF.ext`` with
``MBPF407``, and proves the CO-RE profile refuses hostile
``.BTF.ext`` content (an unsupported kind, zero records, a
corrupt magic, a relocated instruction offset, a trailing
relocation group, a truncated record) with distinct
diagnostics. The independent reader proves the same trailing
and truncation cases from its side (it parses every group to
the end of the blob instead of stopping after the first), and
proves unterminated strings raise ``ReaderError`` (never a bare
``ValueError``) and negative member indices refuse instead of
wrapping.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool`` on
PATH. A missing tool is reported as an environment failure; a
failing frontend, adapter, or backend step is a proof failure.
Neither ever passes.

Runnable directly (``python3 tests/core/test_core_object.py``) or
under any ``test_``-style runner. Standard library only.
"""

import hashlib
import importlib.util
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

from mojobpf.inspect import verify_object  # noqa: E402

CORE_SOURCE = os.path.join(REPO_ROOT, "tests", "core", "core_read.mojo")
READER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "btfext_reader.py"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Adapted-IR hash of the core relocation probe. The adapter must
# keep producing byte-identical output for that input (core mode).
CORE_ADAPTED_HASH = (
    "cf58d7d2dcbdefe4aff7b0cbeefd32111583a5f2b42476f086b71a7b5187e26e"
)
# Compiled ``xdp`` section bytes of the probe (144 bytes). The
# pinned backend must keep producing byte-identical code.
CORE_XDP_HASH = (
    "81b2ef48788106cd82a5337743601ef3b02122f3d12bd7a974fb76f13c9ed162"
)

EM_BPF = 247
BPF_OP_CALL = 0x85
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
MAP_SYMBOL = "mojobpf_map0"
MAP_SECTION_SIZE = 32
CORE_PROFILE = "linux-bpfel-v3-core"
BASE_PROFILE = "linux-bpfel-v3"


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


def build_core_object(workdir):
    raw_path = os.path.join(workdir, "core.raw.ll")
    adapted_path = os.path.join(workdir, "core.bpf.ll")
    obj_path = os.path.join(workdir, "core.bpf.o")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", "-I", SDK_INCLUDE,
         "-o", raw_path, CORE_SOURCE]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for core_read.mojo (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path,
         "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for the core program (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         adapted_path, "-o", obj_path]
    )
    if proc.returncode != 0 or not os.path.isfile(obj_path):
        raise AssertionError(
            "backend failed for the core program (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    return raw_path, adapted_path, obj_path


def load_reader():
    spec = importlib.util.spec_from_file_location(
        "core_btfext_reader", READER_SOURCE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_sections(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise AssertionError("not an ELF file")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise AssertionError("not a 64-bit little-endian ELF")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_BPF:
        raise AssertionError("machine %d, expected EM_BPF" % machine)
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        fields = struct.unpack_from("<IIQQQQIIQQ", data, base)
        headers.append(fields)
    strtab = headers[shstrndx]
    sections = {}
    for fields in headers:
        end = data.index(b"\0", strtab[4] + fields[0])
        name = data[strtab[4] + fields[0] : end].decode("ascii")
        sections[name] = bytes(data[fields[4] : fields[4] + fields[5]])
    return sections


def test_reader_isolation():
    with open(READER_SOURCE, "r", encoding="utf-8") as handle:
        source = handle.read()
    imports = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith(
            "from "
        ):
            imports.append(stripped)
    assert sorted(imports) == ["import struct", "import sys"], imports
    probe = (
        "import sys; sys.path.insert(0, %r); "
        "import btfext_reader as _r; "
        "mods = sorted(m for m in sys.modules "
        "if m.split('.')[0] in "
        "('mojobpf', 'audit', 'build', 'inspect', 'test')); "
        "print('LEAKED:' + ','.join(mods) if mods else 'ISOLATED')"
        % os.path.dirname(READER_SOURCE)
    )
    proc = run_step([sys.executable, "-c", probe])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ISOLATED", proc.stdout
    print("PASS reader isolation (stdlib only, no product imports)")


def test_core_object_structure():
    check_tools("mojo", "llc", "bpftool")
    workdir = tempfile.mkdtemp(prefix="core-object-")
    _raw, adapted_path, obj_path = build_core_object(workdir)
    with open(adapted_path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assert digest == CORE_ADAPTED_HASH, (
        "adapted IR drifted: %s" % digest
    )
    with open(obj_path, "rb") as handle:
        data = handle.read()
    sections = read_sections(data)
    assert "xdp" in sections, sorted(sections)
    assert sections["license"] == LICENSE_BYTES
    assert len(sections[".maps"]) == MAP_SECTION_SIZE
    assert sections[".maps"] == bytes(MAP_SECTION_SIZE)
    assert ".BTF" in sections and ".BTF.ext" in sections
    code = sections["xdp"]
    assert len(code) == 144, len(code)
    assert hashlib.sha256(code).hexdigest() == CORE_XDP_HASH
    calls = []
    imms = []
    condjumps = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        if opcode == 0x18:
            offset += 16
            continue
        if opcode == BPF_OP_CALL:
            (imm,) = struct.unpack_from("<i", code, offset + 4)
            calls.append(imm)
        if opcode == 0x07:
            (imm,) = struct.unpack_from("<i", code, offset + 4)
            imms.append(imm)
        if (opcode & 0x07) == 0x05 and opcode not in (0x05, 0x85, 0x95):
            (skip,) = struct.unpack_from("<h", code, offset + 2)
            condjumps.append((64, opcode, offset, skip))
        if (opcode & 0x07) == 0x06:
            (skip,) = struct.unpack_from("<h", code, offset + 2)
            condjumps.append((32, opcode, offset, skip))
        offset += 8
    assert calls == [1], calls
    assert sorted(imms) == [-4], imms
    # The guard: exactly two conditional jumps -- the 64-bit null
    # check on the lookup result plus the 32-bit exists guard that
    # skips the single exists-arm OR when the field is absent. An
    # unguarded probe (packed bit, no branch) carries only the
    # null check and fails here.
    assert condjumps == [(64, 0x15, 88, 5), (32, 0x16, 120, 1)], (
        condjumps
    )
    guard_at = condjumps[1][2]
    assert code[guard_at + 8] == 0x44, code[guard_at + 8 : guard_at + 16]
    (arm_imm,) = struct.unpack_from("<i", code, guard_at + 12)
    assert arm_imm == 0x10000, arm_imm
    assert code[guard_at + 16] == 0x95, "guard must skip to exit"
    print("PASS core object structure (pins hold)")


def test_core_relocations_independent():
    check_tools("mojo", "llc", "bpftool")
    workdir = tempfile.mkdtemp(prefix="core-relocs-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    reader = load_reader()
    with open(obj_path, "rb") as handle:
        result = reader.read_relocations(handle.read())
    relocs = result["relocations"]
    assert len(relocs) == 2, relocs
    first, second = relocs
    assert first["section"] == "xdp", first
    assert first["type"] == "task_struct", first
    assert (first["kind"], first["kind_name"]) == (
        0, "FIELD_BYTE_OFFSET",
    ), first
    assert first["access"] == "0:1", first
    assert first["member"] == "pid", first
    assert first["local_byte_offset"] == 32, first
    assert first["local_size"] == 4, first
    assert first["insn_off"] == 96, first
    assert second["section"] == "xdp", second
    assert second["type"] == "task_struct", second
    assert (second["kind"], second["kind_name"]) == (
        2, "FIELD_EXISTS",
    ), second
    assert second["access"] == "0:4", second
    assert second["member"] == "scx", second
    assert second["insn_off"] == 112, second
    # bpftool cross-check: the same type IDs, member offsets,
    # and map value bound from the reference implementation.
    proc = run_step(
        ["bpftool", "btf", "dump", "file", obj_path, "format", "raw"]
    )
    assert proc.returncode == 0, proc.stderr
    dump = proc.stdout
    task = re.search(
        r"\[(\d+)\] STRUCT 'task_struct' size=(\d+) vlen=(\d+)", dump
    )
    assert task is not None, dump[:500]
    assert int(task.group(1)) == first["type_id"], dump[:500]
    assert int(task.group(2)) == 312, dump[:500]
    pid = re.search(r"'pid' type_id=(\d+) bits_offset=(\d+)", dump)
    assert pid is not None, dump[:500]
    assert int(pid.group(2)) == 256, dump[:500]
    assert re.search(r"'scx' type_id=(\d+) bits_offset=(\d+)", dump), (
        dump[:500]
    )
    bound = re.search(
        r"nr_elems=4096", dump
    )
    assert bound is not None, dump[:500]
    print("PASS core relocations (reader + bpftool agree)")


def test_core_profile_verdicts():
    check_tools("mojo", "llc", "bpftool")
    workdir = tempfile.mkdtemp(prefix="core-verdicts-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    apache = "Apache-2.0 WITH LLVM-exception"
    report = verify_object(obj_path, CORE_PROFILE, apache, apache)
    assert report.ok, (
        report.structural + report.unsupported + report.license
    )
    base = verify_object(obj_path, BASE_PROFILE, apache, apache)
    assert base.ok is False, "base profile accepted .BTF.ext"
    codes = [item.code for item in base.unsupported]
    assert codes == ["MBPF407"], codes
    print("PASS core profile verdicts (core ok, base MBPF407)")


def _ext_file_range(data):
    """Return the file (offset, size) of the ``.BTF.ext`` section."""
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        headers.append(struct.unpack_from("<IIQQQQIIQQ", data, base))
    strtab = headers[shstrndx]
    for fields in headers:
        end = data.index(b"\0", strtab[4] + fields[0])
        name = data[strtab[4] + fields[0] : end].decode("ascii")
        if name == ".BTF.ext":
            return fields[4], fields[5]
    raise AssertionError("object has no .BTF.ext section")


def _mutate_ext(obj_path, workdir, tag, edit):
    """Copy the genuine object with one ``.BTF.ext`` byte edit."""
    with open(obj_path, "rb") as handle:
        image = bytearray(handle.read())
    offset, size = _ext_file_range(image)
    blob = bytearray(image[offset : offset + size])
    edit(blob)
    assert len(blob) == size, (tag, len(blob), size)
    image[offset : offset + size] = blob
    mutated = os.path.join(workdir, "core_%s.bpf.o" % tag)
    with open(mutated, "wb") as handle:
        handle.write(bytes(image))
    return mutated


def _patch_kind_99(blob):
    (magic, version, _flags, hdr_len) = struct.unpack_from(
        "<HBBI", blob, 0
    )
    assert (magic, version, hdr_len) == (0xEB9F, 1, 32)
    (_foff, _flen, _loff, _llen, coff, _clen) = struct.unpack_from(
        "<IIIIII", blob, 8
    )
    core = hdr_len + coff
    (record_size,) = struct.unpack_from("<I", blob, core)
    assert record_size == 16, record_size
    (_sec, num_info) = struct.unpack_from("<II", blob, core + 4)
    assert num_info == 2, num_info
    kind_at = core + 4 + 8 + 16 + 12
    (kind,) = struct.unpack_from("<I", blob, kind_at)
    assert kind == 2, kind
    struct.pack_into("<I", blob, kind_at, 99)


def _patch_zero_records(blob):
    (magic, version, _flags, hdr_len) = struct.unpack_from(
        "<HBBI", blob, 0
    )
    assert (magic, version, hdr_len) == (0xEB9F, 1, 32)
    (foff, flen, loff, llen, coff, _clen) = struct.unpack_from(
        "<IIIIII", blob, 8
    )
    core = hdr_len + coff
    (_sec, num_info) = struct.unpack_from("<II", blob, core + 4)
    assert num_info == 2, num_info
    struct.pack_into("<I", blob, core + 8, 0)
    struct.pack_into("<I", blob, 28, 12)
    tail = hdr_len + coff + 12
    for index in range(tail, len(blob)):
        blob[index] = 0
    assert (foff, flen, loff, llen) == (0, 20, 20, 28)


def _patch_corrupt_magic(blob):
    assert blob[0:2] == b"\x9f\xeb", blob[0:4]
    blob[0:2] = b"\x00\x00"


def _patch_insn_off_144(blob):
    (magic, version, _flags, hdr_len) = struct.unpack_from(
        "<HBBI", blob, 0
    )
    assert (magic, version, hdr_len) == (0xEB9F, 1, 32)
    (_foff, _flen, _loff, _llen, coff, _clen) = struct.unpack_from(
        "<IIIIII", blob, 8
    )
    core = hdr_len + coff
    (record_size,) = struct.unpack_from("<I", blob, core)
    assert record_size == 16, record_size
    (_sec, num_info) = struct.unpack_from("<II", blob, core + 4)
    assert num_info == 2, num_info
    off_at = core + 4 + 8
    (insn_off,) = struct.unpack_from("<I", blob, off_at)
    assert insn_off == 96, insn_off
    struct.pack_into("<I", blob, off_at, 144)


def _ext_shdr_offset(data):
    """Return the file offset of the ``.BTF.ext`` section header."""
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        headers.append(
            (base, struct.unpack_from("<IIQQQQIIQQ", data, base))
        )
    strtab = headers[shstrndx][1]
    for base, fields in headers:
        end = data.index(b"\0", strtab[4] + fields[0])
        name = data[strtab[4] + fields[0] : end].decode("ascii")
        if name == ".BTF.ext":
            return base
    raise AssertionError("object has no .BTF.ext section")


def _extend_ext(obj_path, workdir, tag, new_blob):
    """Copy the object with longer ``.BTF.ext`` section bytes.

    The replacement blob is appended at end of file (padded to
    8) and the section header is repointed at it, so no other
    header or byte moves.
    """
    with open(obj_path, "rb") as handle:
        image = bytearray(handle.read())
    shdr_at = _ext_shdr_offset(image)
    new_off = (len(image) + 7) // 8 * 8
    image += b"\0" * (new_off - len(image))
    image += bytes(new_blob)
    struct.pack_into("<Q", image, shdr_at + 24, new_off)
    struct.pack_into("<Q", image, shdr_at + 32, len(new_blob))
    grown = os.path.join(workdir, "core_%s.bpf.o" % tag)
    with open(grown, "wb") as handle:
        handle.write(bytes(image))
    return grown


def _genuine_core_layout(blob):
    """Pin the genuine core table layout; return its facts.

    Returns (core_off, clen, sec_off, rec0, rec1) where each rec
    is (insn_off, type_id, acc_off, kind). Backend drift fails
    the assertions instead of testing dead bytes.
    """
    (magic, version, _flags, hdr_len) = struct.unpack_from(
        "<HBBI", blob, 0
    )
    assert (magic, version, hdr_len) == (0xEB9F, 1, 32)
    (foff, flen, loff, llen, coff, clen) = struct.unpack_from(
        "<IIIIII", blob, 8
    )
    assert (foff, flen, loff, llen, coff) == (0, 20, 20, 28, 48)
    core = hdr_len + coff
    (record_size,) = struct.unpack_from("<I", blob, core)
    assert record_size == 16, record_size
    (sec_off, num_info) = struct.unpack_from("<II", blob, core + 4)
    assert num_info == 2, num_info
    rec0 = struct.unpack_from("<IIII", blob, core + 12)
    rec1 = struct.unpack_from("<IIII", blob, core + 28)
    assert (rec0[0], rec0[3]) == (96, 0), rec0
    assert (rec1[0], rec1[3]) == (112, 2), rec1
    assert len(blob) == core + clen, (len(blob), core, clen)
    return core, clen, sec_off, rec0, rec1


def _build_trailing_blob(blob):
    """Genuine ``.BTF.ext`` bytes plus a second relocation group."""
    _core, clen, sec_off, rec0, _rec1 = _genuine_core_layout(blob)
    group = struct.pack("<II", sec_off, 1) + struct.pack(
        "<IIII", 200, rec0[1], rec0[2], 0
    )
    grown = bytearray(bytes(blob) + group)
    struct.pack_into("<I", grown, 28, clen + len(group))
    return bytes(grown)


def _patch_truncate_record(blob):
    (magic, version, _flags, hdr_len) = struct.unpack_from(
        "<HBBI", blob, 0
    )
    assert (magic, version, hdr_len) == (0xEB9F, 1, 32)
    (_foff, _flen, _loff, _llen, coff, _clen) = struct.unpack_from(
        "<IIIIII", blob, 8
    )
    core = hdr_len + coff
    (_sec, num_info) = struct.unpack_from("<II", blob, core + 4)
    assert num_info == 2, num_info
    struct.pack_into("<I", blob, 28, 36)
    tail = hdr_len + coff + 36
    for index in range(tail, len(blob)):
        blob[index] = 0


def test_core_btfext_negatives_refused():
    # Presence is never acceptance: an unsupported relocation
    # kind, a valid header with zero records, a corrupt magic,
    # and a relocated instruction offset each fail under the
    # CO-RE profile with their own diagnostic. Pre-patch
    # assertions pin the genuine layout so backend drift fails
    # loudly instead of testing dead bytes.
    check_tools("mojo", "llc", "bpftool")
    workdir = tempfile.mkdtemp(prefix="core-negatives-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    apache = "Apache-2.0 WITH LLVM-exception"
    kind = _mutate_ext(obj_path, workdir, "kind99", _patch_kind_99)
    report = verify_object(kind, CORE_PROFILE, apache, apache)
    assert report.ok is False, "kind-99 relocations accepted"
    assert [item.code for item in report.unsupported] == ["MBPF407"]
    assert "kind 99" in report.unsupported[0].explanation, (
        report.unsupported[0].explanation
    )
    zero = _mutate_ext(obj_path, workdir, "zerorec", _patch_zero_records)
    report = verify_object(zero, CORE_PROFILE, apache, apache)
    assert report.ok is False, "zero-record .BTF.ext accepted"
    assert [item.code for item in report.unsupported] == ["MBPF407"]
    assert "no CO-RE relocation records" in (
        report.unsupported[0].explanation
    ), report.unsupported[0].explanation
    corrupt = _mutate_ext(
        obj_path, workdir, "badmagic", _patch_corrupt_magic
    )
    report = verify_object(corrupt, CORE_PROFILE, apache, apache)
    assert report.ok is False, "corrupt-magic .BTF.ext accepted"
    assert [item.code for item in report.structural] == ["MBPF402"]
    assert "bad .BTF.ext header" in report.structural[0].explanation, (
        report.structural[0].explanation
    )
    moved = _mutate_ext(obj_path, workdir, "insn144", _patch_insn_off_144)
    report = verify_object(moved, CORE_PROFILE, apache, apache)
    assert report.ok is False, "moved insn offset accepted"
    assert [item.code for item in report.unsupported] == ["MBPF407"]
    assert "insn offset 144" in report.unsupported[0].explanation, (
        report.unsupported[0].explanation
    )
    print("PASS core .BTF.ext negatives refused (distinct codes)")


def test_reader_parses_trailing_group():
    # The reader resolves every relocation group to the end of
    # the blob: a second group carrying one more record reads
    # as three relocations (previously the reader stopped
    # after the first group and the trailing record vanished).
    check_tools("mojo", "llc")
    workdir = tempfile.mkdtemp(prefix="core-trailing-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    with open(obj_path, "rb") as handle:
        image = handle.read()
    sections = read_sections(image)
    grown = _build_trailing_blob(bytearray(sections[".BTF.ext"]))
    trailing = _extend_ext(obj_path, workdir, "trailing", grown)
    reader = load_reader()
    with open(trailing, "rb") as handle:
        result = reader.read_relocations(handle.read())
    assert [item["insn_off"] for item in result["relocations"]] == [
        96, 112, 200,
    ], result["relocations"]
    with open(obj_path, "rb") as handle:
        genuine = reader.read_relocations(handle.read())
    assert [item["insn_off"] for item in genuine["relocations"]] == [
        96, 112,
    ], genuine["relocations"]
    print("PASS reader parses the trailing group (3 relocations)")


def test_trailing_group_refused_by_gate():
    # The gate parses to the end too, then fails closed: three
    # relocation shapes are not the pinned two (MBPF407).
    check_tools("mojo", "llc")
    workdir = tempfile.mkdtemp(prefix="core-trailing-gate-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    with open(obj_path, "rb") as handle:
        image = handle.read()
    sections = read_sections(image)
    grown = _build_trailing_blob(bytearray(sections[".BTF.ext"]))
    trailing = _extend_ext(obj_path, workdir, "trailing", grown)
    apache = "Apache-2.0 WITH LLVM-exception"
    report = verify_object(trailing, CORE_PROFILE, apache, apache)
    assert report.ok is False, "trailing group accepted"
    assert [item.code for item in report.unsupported] == ["MBPF407"]
    assert "insn offset 200" in report.unsupported[0].explanation, (
        report.unsupported[0].explanation
    )
    print("PASS trailing group refused by the gate (MBPF407)")


def test_truncated_record_refused_both_sides():
    # A group cut mid-record fails on both sides: the reader
    # raises ReaderError and the gate reports MBPF402.
    check_tools("mojo", "llc")
    workdir = tempfile.mkdtemp(prefix="core-trunc-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    truncated = _mutate_ext(
        obj_path, workdir, "trunc", _patch_truncate_record
    )
    reader = load_reader()
    with open(truncated, "rb") as handle:
        image = handle.read()
    try:
        reader.read_relocations(image)
    except reader.ReaderError as exc:
        assert "truncated" in str(exc), exc
    else:
        raise AssertionError("truncated record parsed")
    apache = "Apache-2.0 WITH LLVM-exception"
    report = verify_object(truncated, CORE_PROFILE, apache, apache)
    assert report.ok is False, "truncated record accepted"
    assert [item.code for item in report.structural] == ["MBPF402"]
    assert "truncated .BTF.ext record" in (
        report.structural[0].explanation
    ), report.structural[0].explanation
    print("PASS truncated record refused (reader + MBPF402)")


def test_reader_missing_terminator_refused():
    # Unterminated strings raise ReaderError, never a bare
    # ValueError from the byte search.
    reader = load_reader()
    blob = struct.pack(
        "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, 0, 0, 3
    ) + b"abc"
    try:
        reader.Btf(blob).string(0)
    except Exception as exc:
        assert type(exc) is reader.ReaderError, type(exc)
        assert "no terminator" in str(exc), exc
    else:
        raise AssertionError("unterminated .BTF string parsed")
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[6] = 1
    struct.pack_into("<H", header, 18, 247)
    struct.pack_into("<Q", header, 40, 64)
    struct.pack_into("<HHH", header, 58, 64, 1, 0)
    shdr = struct.pack(
        "<IIQQQQIIQQ", 0, 3, 0, 0, 128, 4, 0, 0, 1, 0
    )
    image = bytes(header) + shdr + b"name"
    try:
        reader.read_sections(image)
    except Exception as exc:
        assert type(exc) is reader.ReaderError, type(exc)
        assert "no terminator" in str(exc), exc
    else:
        raise AssertionError("unterminated section name parsed")
    print("PASS missing terminators raise ReaderError")


def test_reader_negative_member_refused():
    # A negative member index refuses instead of wrapping to
    # the last member; the genuine 0:1 accessor still resolves.
    check_tools("mojo", "llc")
    workdir = tempfile.mkdtemp(prefix="core-negidx-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    reader = load_reader()
    with open(obj_path, "rb") as handle:
        image = handle.read()
    sections = reader.read_sections(image)
    btf = reader.Btf(sections[".BTF"])
    result = reader.read_relocations(image)
    type_id = result["relocations"][0]["type_id"]
    try:
        reader._resolve_member(btf, type_id, [0, -1])
    except reader.ReaderError as exc:
        assert "out of range" in str(exc), exc
    else:
        raise AssertionError("member -1 wrapped")
    facts = reader._resolve_member(btf, type_id, [0, 1])
    assert facts["member"] == "pid", facts
    print("PASS negative member index refused (0:1 resolves)")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    for name in names:
        try:
            globals()[name]()
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
    print("core object: structure, relocations, and verdicts hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
