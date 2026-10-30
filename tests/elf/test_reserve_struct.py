# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built ring-reservation objects.

Builds ``tests/compile/reserve_submit.mojo`` (and the small-ring
submitter plus the discarder) through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import
path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and asserts each resulting
object is a conventional BPF relocatable for one tracepoint
program: EM_BPF machine type, exactly one executable section
(``tracepoint/syscalls/sys_enter_getpid``) holding exactly one
function (``trace_entry``), the exact license bytes, helper
calls [1, 14, 1, 2, 8, 5, 14, 131, 132, 1, 1, 2] (submitter) or
[1, 14, 1, 2, 8, 5, 14, 131, 133, 1, 1, 2] (discarder) in order
(the released/success and failure updates share one
tail-merged call instruction), the qualified add-immediate
multiset (pair slots plus the three pair increments, with no
scratch-buffer offsets: the record lives in the
kernel-provided reservation, not on the stack), eight map
relocations (seven against the array state map, one against the
ring-buffer map), a 48-byte all-zero ``.maps`` section, and map
BTF describing the four-entry array map plus the ring-buffer
map. The BTF blob is compared byte-for-byte against the
copy-output emitter's BTF for the same ring size (the map
contract is unchanged; only the publication path differs) and
cross-checked against the public map-spec readers.

Also proves the reservation encoder covers the 32-byte record:
the adapted IR carries seven word stores through the record
reinterpretation and its six GEPs covering exactly bytes 0
through 31 with no gaps and no overlap, all before the single
terminus. The backend must also keep the program frameless
(empty MIR stack); the build's spill gate enforces the same
property on the driver path.

Requires a working Mojo compiler, LLVM ``llc``, and ``bpftool``
on PATH. A missing tool is reported as an environment failure;
a failing frontend, adapter, or backend step is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_reserve_struct.py``)
or under any ``test_``-style runner. Standard library only.
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
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import mojo_ir_adapter as adapter  # noqa: E402
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
from mojobpf.inspect import inspect_object, object_map_specs  # noqa: E402

SUBMIT_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_submit.mojo"
)
SMALL_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_submit_small.mojo"
)
DISCARD_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "reserve_discard.mojo"
)
EVENT_EMITTER = os.path.join(
    REPO_ROOT, "examples", "tracepoint_events", "emitter.mojo"
)
EVENT_SMALL = os.path.join(
    REPO_ROOT, "examples", "tracepoint_events", "emitter_small.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Independent direct-path pins for the committed reservation
# family. The kernel suite pins the same object bytes through
# its own staged builds; both paths must agree.
SUBMIT_RAW_HASH = (
    "702f0670a95c843c0cd51cc6c1a63ad78140129100112300b1218a087d74dfe1"
)
SUBMIT_ADAPTED_HASH = (
    "1d61b140f4fa27a491cc1bee9cf75ae00ea502a43c8167336afb76dc32159183"
)
SUBMIT_OBJECT_HASH = (
    "d82c1a48ae3388b9ced69062977e1e772dc8523699775e902559bfba89314780"
)
SMALL_RAW_HASH = (
    "7779b500b6710639056f7d61f5871f56801a2513a132c31736a82676f7cf40ae"
)
SMALL_ADAPTED_HASH = (
    "9589691e9996391e1499e3d36967e49497747c596499890d5dd9c1db6e539c80"
)
SMALL_OBJECT_HASH = (
    "5c024e7d8dbd178e778b21911a849eab1625f79be0ade2dae28c715eac08d700"
)
DISCARD_RAW_HASH = (
    "cdab9016be4a546ed8d3b3db8eec6617f7aea061f62136405cdb2e8888843afa"
)
DISCARD_ADAPTED_HASH = (
    "1a578e7fd66eb403bc8d7cc67d004cf60efcef67b1153824002803e0b944e05d"
)
DISCARD_OBJECT_HASH = (
    "ae9750d2089524e2d37651d70d13c9c454375854780296c6f40be1c711f185cd"
)

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_REL = 9
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
# Object-level call orders: the two accounting arms share one
# tail-merged update, so each object carries twelve static
# calls for the thirteen IR-level helper calls.
SUBMIT_CALLS = [1, 14, 1, 2, 8, 5, 14, 131, 132, 1, 1, 2]
DISCARD_CALLS = [1, 14, 1, 2, 8, 5, 14, 131, 133, 1, 1, 2]
EXPECTED_IMMS = [
    -16, -16, -16,
    -4, -4, -4, -4, -4, -4, -4,
    1, 1, 1,
]
# Record field (offset, width) pairs from the ABI record row, in
# field order: exactly bytes 0 through 31, no gaps, no overlap.
EXPECTED_COVERAGE = (
    (0, 2), (2, 2), (4, 4), (8, 4), (12, 4), (16, 8), (24, 8),
)
GEP_RE = re.compile(
    r"^%(\S+)\s*=\s*getelementptr\s+inbounds\s+i8,\s*ptr\s+"
    r"%(\S+),\s*i32\s+(\d+)$"
)
STORE_RE = re.compile(
    r"^store\s+(i16|i32|i64)\s+\S+,\s*ptr\s+%(\S+?)(,|$)"
)
WIDTH_BYTES = {"i16": 2, "i32": 4, "i64": 8}

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
    workdir = tempfile.mkdtemp(prefix="mojo-reserve-")
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


def built(tag, source):
    if tag not in _BUILT:
        assert adapter.validate(
            build_object(source)[0]
        ) == "reserve", tag
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


def test_reserve_objects_match_pins():
    check_tools("mojo", "llc")
    cases = (
        ("submit", SUBMIT_SOURCE,
         SUBMIT_RAW_HASH, SUBMIT_ADAPTED_HASH, SUBMIT_OBJECT_HASH),
        ("small", SMALL_SOURCE,
         SMALL_RAW_HASH, SMALL_ADAPTED_HASH, SMALL_OBJECT_HASH),
        ("discard", DISCARD_SOURCE,
         DISCARD_RAW_HASH, DISCARD_ADAPTED_HASH, DISCARD_OBJECT_HASH),
    )
    for tag, source, raw_hash, adapted_hash, object_hash in cases:
        raw_ir, adapted_ir, image, _path = built(tag, source)
        observed = hashlib.sha256(raw_ir.encode("utf-8")).hexdigest()
        assert observed == raw_hash, (tag, observed)
        observed = hashlib.sha256(adapted_ir.encode("utf-8")).hexdigest()
        assert observed == adapted_hash, (tag, observed)
        observed = hashlib.sha256(image).hexdigest()
        assert observed == object_hash, (tag, observed)
        print("PASS reserve %s bytes match raw/adapted/object pins" % tag)


def check_program_layout(tag, want_calls):
    _raw_ir, _adapted_ir, image, _path = built(
        tag,
        {"submit": SUBMIT_SOURCE,
         "small": SMALL_SOURCE,
         "discard": DISCARD_SOURCE}[tag],
    )
    facts = parse_elf(image)
    assert facts["type"] == ET_REL, facts["type"]
    assert facts["machine"] == EM_BPF, facts["machine"]
    by_name = {section["name"]: section for section in facts["sections"]}
    assert TRACEPOINT_SECTION in by_name, sorted(by_name)
    exec_sections = [
        section for section in facts["sections"]
        if section["flags"] & SHF_EXECINSTR and section["size"] > 0
    ]
    assert len(exec_sections) == 1, (
        [section["name"] for section in exec_sections]
    )
    assert exec_sections[0]["name"] == TRACEPOINT_SECTION
    code = section_bytes(image, exec_sections[0])
    insns = decode_insns(code)
    calls = [
        imm for opcode, _dst, _src, _off, imm in insns
        if opcode == BPF_OP_CALL
    ]
    assert calls == want_calls, (tag, calls)
    imms = sorted(
        imm for opcode, _dst, _src, _off, imm in insns
        if opcode == BPF_OP_ADD_IMM
    )
    assert imms == EXPECTED_IMMS, (tag, imms)
    assert any(
        opcode == BPF_OP_EXIT for opcode, _, _, _, _ in insns
    ), (tag, "no exit instruction")
    funcs = [
        symbol for symbol in facts["symbols"]
        if symbol["type"] == STT_FUNC and symbol["bind"] == STB_GLOBAL
    ]
    assert len(funcs) == 1, funcs
    assert funcs[0]["name"] == ENTRY_SYMBOL, funcs
    license_section = by_name.get("license")
    assert license_section is not None, sorted(by_name)
    assert section_bytes(image, license_section) == LICENSE_BYTES
    maps_section = by_name.get(".maps")
    assert maps_section is not None, sorted(by_name)
    assert maps_section["size"] == MAP_SECTION_SIZE, maps_section
    assert section_bytes(image, maps_section) == bytes(MAP_SECTION_SIZE)
    prog_relocs = [
        reloc for reloc in facts["relocations"]
        if reloc["section"] == ".rel" + TRACEPOINT_SECTION
    ]
    assert len(prog_relocs) == 8, (tag, prog_relocs)
    names = sorted(
        facts["symbols"][reloc["sym"]]["name"] for reloc in prog_relocs
    )
    assert names == [MAP_SYMBOL] * 7 + [RING_SYMBOL], (tag, names)
    for reloc in prog_relocs:
        assert reloc["type"] == R_BPF_64_64, (tag, reloc)
    print("PASS reserve %s layout: calls %s" % (tag, calls))


def test_reserve_program_layout():
    check_tools("mojo", "llc", "bpftool")
    check_program_layout("submit", SUBMIT_CALLS)
    check_program_layout("small", SUBMIT_CALLS)
    check_program_layout("discard", DISCARD_CALLS)


def test_reserve_map_btf_matches_event_pair():
    check_tools("mojo", "llc", "bpftool")
    pairs = (
        ("submit", SUBMIT_SOURCE, EVENT_EMITTER, RING_SIZE_LARGE),
        ("small", SMALL_SOURCE, EVENT_SMALL, RING_SIZE_SMALL),
        ("discard", DISCARD_SOURCE, EVENT_EMITTER, RING_SIZE_LARGE),
    )
    for tag, source, event_source, ring_size in pairs:
        _raw, _adapted, image, path = built(tag, source)
        event_raw, event_adapted, event_image, _event = build_object(
            event_source
        )
        assert adapter.validate(event_raw) == "event"
        del event_adapted
        facts = parse_elf(image)
        event_facts = parse_elf(event_image)
        by_name = {
            section["name"]: section for section in facts["sections"]
        }
        event_by_name = {
            section["name"]: section
            for section in event_facts["sections"]
        }
        assert ".BTF" in by_name, sorted(by_name)
        assert section_bytes(image, by_name[".BTF"]) == section_bytes(
            event_image, event_by_name[".BTF"]
        ), (tag, "map BTF differs from the copy-output pair")
        specs = object_map_specs(path)
        assert specs == (
            (MAP_SYMBOL, 2, 4),
            (RING_SYMBOL, 27, ring_size),
        ), (tag, specs)
        print(
            "PASS reserve %s BTF equals the event pair (%d-byte ring)"
            % (tag, ring_size)
        )


def check_encoder_coverage(tag, terminus_name):
    _raw_ir, adapted_ir, _image, _path = built(
        tag,
        {"submit": SUBMIT_SOURCE,
         "small": SMALL_SOURCE,
         "discard": DISCARD_SOURCE}[tag],
    )
    lines = adapted_ir.splitlines()
    reserve_result = None
    terminus_lineno = None
    for lineno, line in enumerate(lines):
        if "inttoptr (i64 131 to ptr)" in line:
            reserve_result = line.split("%", 1)[1].split()[0]
        if terminus_name in line:
            terminus_lineno = lineno
    assert reserve_result is not None, tag
    assert terminus_lineno is not None, tag
    reinterp = None
    for line in lines:
        if line.strip().endswith("(i64 %%%s)" % reserve_result):
            stripped = line.strip()
            if 'call ptr asm "", "=r,0"' in stripped:
                reinterp = stripped.split("%", 1)[1].split()[0]
    assert reinterp is not None, tag
    geps = {}
    for lineno, line in enumerate(lines):
        matched = GEP_RE.match(line.strip())
        if matched is None or matched.group(2) != reinterp:
            continue
        assert lineno < terminus_lineno, (tag, line)
        geps[matched.group(1)] = int(matched.group(3))
    covered = []
    for lineno, line in enumerate(lines):
        matched = STORE_RE.match(line.strip())
        if matched is None:
            continue
        width, dest = matched.group(1), matched.group(2)
        if dest == reinterp:
            offset = 0
        elif dest in geps:
            offset = geps[dest]
        else:
            continue
        assert lineno < terminus_lineno, (tag, line)
        covered.append((offset, WIDTH_BYTES[width]))
    assert tuple(sorted(covered)) == EXPECTED_COVERAGE, (tag, covered)
    assert '"r0 = r10' not in adapted_ir or "r0 += -64" not in adapted_ir, (
        tag, "reservation object must not prepare the scratch event slot"
    )
    print(
        "PASS reserve %s encoder covers bytes 0..31 before the terminus"
        % tag
    )


def test_reserve_encoder_store_coverage():
    check_tools("mojo", "llc")
    check_encoder_coverage("submit", "inttoptr (i64 132 to ptr)")
    check_encoder_coverage("small", "inttoptr (i64 132 to ptr)")
    check_encoder_coverage("discard", "inttoptr (i64 133 to ptr)")


def test_reserve_inspect_profile_gating():
    check_tools("mojo", "llc")
    for tag in ("submit", "small", "discard"):
        _raw_ir, _adapted_ir, _image, path = built(
            tag,
            {"submit": SUBMIT_SOURCE,
             "small": SMALL_SOURCE,
             "discard": DISCARD_SOURCE}[tag],
        )
        clean = inspect_object(path, "linux-bpfel-v3-reserve")
        assert clean.ok is True, (tag, clean.unsupported)
        assert list(clean.unsupported) == [], (tag, clean.unsupported)
        report = inspect_object(path, "linux-bpfel-v3")
        assert report.ok is False, tag
        codes = [finding.code for finding in report.unsupported]
        assert codes == ["MBPF407", "MBPF407"], (tag, codes)
        helpers = sorted(
            "131" in finding.explanation or "132" in finding.explanation
            or "133" in finding.explanation
            for finding in report.unsupported
        )
        assert helpers == [True, True], (
            tag, [finding.explanation for finding in report.unsupported]
        )
        print(
            "PASS reserve %s inspects clean under reserve, "
            "MBPF407 under base" % tag
        )


def test_reserve_backend_frameless():
    check_tools("mojo", "llc")
    for tag in ("submit", "small", "discard"):
        _raw_ir, adapted_ir, _image, _path = built(
            tag,
            {"submit": SUBMIT_SOURCE,
             "small": SMALL_SOURCE,
             "discard": DISCARD_SOURCE}[tag],
        )
        workdir = tempfile.mkdtemp(prefix="mojo-reserve-mir-")
        adapted_path = os.path.join(workdir, "adapted.ll")
        mir_path = os.path.join(workdir, "prog.mir")
        with open(adapted_path, "w", encoding="utf-8") as handle:
            handle.write(adapted_ir)
        proc = run_step(
            [
                "llc", "-mtriple=bpfel", "-mcpu=v3",
                "-stop-after=prologepilog",
                adapted_path, "-o", mir_path,
            ]
        )
        if proc.returncode != 0:
            raise AssertionError(
                "MIR dump failed for %s: %s" % (tag, proc.stderr[-2000:])
            )
        with open(mir_path, "r", encoding="utf-8") as handle:
            mir = handle.read()
        assert re.search(r"^fixedStack:\s*\[\]", mir, re.M), tag
        assert re.search(r"^stack:\s*\[\]", mir, re.M), tag
        print("PASS reserve %s backend keeps the empty frame" % tag)


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
    print("reserve structure: pins, layout, BTF, encoder, frameless")
    return 0


if __name__ == "__main__":
    sys.exit(main())
