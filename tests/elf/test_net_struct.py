# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built socket/tc classifier objects.

Builds ``examples/socket_classifier/socket.mojo`` and
``examples/tc_classifier/tc.mojo`` through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import path
-> ``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel
-mcpu=v3``) and asserts each resulting object is a conventional
mapless BPF relocatable for one program: EM_BPF machine type,
exactly one executable section (``socket`` / ``classifier``)
holding exactly one function (``socket_entry`` / ``tc_entry``),
the exact license bytes, no call instructions, no code
relocations, no undefined symbols, and no map or BTF sections.

Profile gating is pinned in both directions: each object verifies
under ``linux-bpfel-v3-net`` and is refused with ``MBPF406``
under every other registered profile.

Requires a working Mojo compiler and LLVM ``llc`` on PATH. A
missing tool is reported as an environment failure; a failing
frontend, adapter, or backend step is a proof failure. Neither
ever passes.

Runnable directly (``python3 tests/elf/test_net_struct.py``)
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
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
from mojobpf.inspect import verify_object  # noqa: E402
from mojobpf.manifest import SUPPORTED_PROFILE_IDS  # noqa: E402

SOCKET_SOURCE = os.path.join(
    REPO_ROOT, "examples", "socket_classifier", "socket.mojo"
)
TC_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tc_classifier", "tc.mojo"
)
STORE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "tc_store.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Independent direct-path pins for the committed classifiers,
# observed from genuine pipeline builds whose layout and profile
# gating the suites below prove.
SOCKET_RAW_HASH = (
    "daac962acc76c45f62dad247458511f66b41258b556f18352917648041e3a7f3"
)
SOCKET_ADAPTED_HASH = (
    "54df07f234cacb904214c1ce56e653476cbb984c06595cc6747c671e1ab24d43"
)
SOCKET_OBJECT_HASH = (
    "3ccabbc6f28dbe3e5315476fc815db59b73e7ee270f958ca7e9ff7a2f3e007be"
)
TC_RAW_HASH = (
    "34cab219c5f973048329809a11154ebab84260a00a0a804090a3c66c830507aa"
)
TC_ADAPTED_HASH = (
    "376a0892b3e38f3861e39fa49e5ac979c964f588fd4b4e37e665f78c50da0adf"
)
TC_OBJECT_HASH = (
    "19d605af318d1200d12dc7861c36720006f0e86afbfc01162efe891df5241a34"
)
STORE_RAW_HASH = (
    "bd21502f8072979fd19bd365d08bb0b30fd0c5e7b1261158735d174955460f55"
)
STORE_ADAPTED_HASH = (
    "df5cf094e32620a412846c6c0ff1b173f398426989d1831f4638fa06109fedff"
)
STORE_OBJECT_HASH = (
    "2d805f5e55b512ba81bc8af5e5c2e7cea2109b824156843672e2b9064bcc2825"
)

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHN_UNDEF = 0
STB_GLOBAL = 1
STT_FUNC = 2
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
NET_PROFILE = "linux-bpfel-v3-net"

PROGRAMS = (
    (SOCKET_SOURCE, "socket", "socket_entry", "socket", "skb", [26]),
    (TC_SOURCE, "tc", "tc_entry", "classifier", "classifier", []),
    (STORE_SOURCE, "store", "tc_entry", "classifier", "skb", [9]),
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
    workdir = tempfile.mkdtemp(prefix="mojo-net-")
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
        (
            sh_name, sh_type, sh_flags, _addr,
            sh_offset, sh_size, _link, sh_info,
        ) = struct.unpack_from("<IIQQQQII", image, off)
        sections.append(
            {
                "index": index,
                "name_off": sh_name,
                "type": sh_type,
                "flags": sh_flags,
                "offset": sh_offset,
                "size": sh_size,
                "info": sh_info,
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
        if section["type"] != 9:  # SHT_REL
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


def program_checks(image, label, section, entry, calls_want):
    """Shared layout assertions for one mapless net program."""
    elf = parse_elf(image)
    assert elf["type"] == ET_REL, "object must be relocatable"
    assert elf["machine"] == EM_BPF, "object must target EM_BPF"
    by_name = {s["name"]: s for s in elf["sections"]}
    for required in (section, "license"):
        assert required in by_name, "missing %s section" % required
    for absent in (".maps", ".BTF"):
        assert absent not in by_name, (
            "mapless object must not carry %s" % absent
        )
    executable = [
        s["name"] for s in elf["sections"]
        if s["flags"] & SHF_EXECINSTR and s["size"] > 0
    ]
    assert executable == [section], (
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
        (entry, STB_GLOBAL)
    ], "one global function expected: %r" % (funcs,)
    undefined = [
        s["name"] for s in elf["symbols"]
        if s["shndx"] == SHN_UNDEF and s["name"]
    ]
    assert undefined == [], "no undefined symbols expected: %r" % undefined
    for rel_section in elf["sections"]:
        if rel_section["type"] in (9, 4):  # SHT_REL, SHT_RELA
            assert rel_section["info"] != by_name[section]["index"], (
                "%s relocates the program section" % rel_section["name"]
            )
    code = section_bytes(image, by_name[section])
    assert len(code) > 0, "program section must be nonempty"
    insns = decode_insns(code)
    calls = [
        imm for opcode, _, _, _, imm in insns if opcode == BPF_OP_CALL
    ]
    assert calls == calls_want, (
        "helper calls %r expected, got %r" % (calls_want, calls)
    )
    assert insns[-1][0] == BPF_OP_EXIT, "program must end in exit"


def test_net_objects_match_pins():
    check_tools("mojo", "llc")
    for source, label, entry, section, mode, _calls in PROGRAMS:
        raw_ir, adapted_ir, image, _ = build_object(source)
        assert adapter.validate(raw_ir) == mode, label
        assert ('section "%s"' % section) in adapted_ir, label
        assert ("ptr @%s" % entry) in adapted_ir, label
    print("PASS all net programs validate with their sections")


def test_net_object_hashes_pinned():
    check_tools("mojo", "llc")
    pins = {
        SOCKET_SOURCE: (SOCKET_RAW_HASH, SOCKET_ADAPTED_HASH,
                        SOCKET_OBJECT_HASH),
        TC_SOURCE: (TC_RAW_HASH, TC_ADAPTED_HASH, TC_OBJECT_HASH),
        STORE_SOURCE: (STORE_RAW_HASH, STORE_ADAPTED_HASH,
                       STORE_OBJECT_HASH),
    }
    for source, _label, _entry, _section, _mode, _calls in PROGRAMS:
        raw_ir, adapted_ir, image, _ = build_object(source)
        want_raw, want_adapted, want_object = pins[source]
        for text_label, text, want in (
            ("raw IR", raw_ir, want_raw),
            ("adapted IR", adapted_ir, want_adapted),
        ):
            observed = hashlib.sha256(text.encode("utf-8")).hexdigest()
            assert observed == want, (
                "%s %s mismatch: observed %s expected %s"
                % (source, text_label, observed, want)
            )
        observed = hashlib.sha256(image).hexdigest()
        assert observed == want_object, (
            "%s object mismatch: observed %s expected %s"
            % (source, observed, want_object)
        )
    print("PASS direct-path bytes match the net pins")


def test_net_program_layout():
    check_tools("mojo", "llc")
    for source, label, entry, section, _mode, calls in PROGRAMS:
        _, _, image, _ = build_object(source)
        program_checks(image, label, section, entry, calls)
        print(
            "PASS %s layout: one %s function, calls %r"
            % (label, entry, calls)
        )


def test_net_profile_gating():
    check_tools("mojo", "llc")
    for source, label, entry, section, _mode, _calls in PROGRAMS:
        _, _, _, object_path = build_object(source)
        report = verify_object(
            object_path,
            NET_PROFILE,
            "Apache-2.0 WITH LLVM-exception",
            "Apache-2.0 WITH LLVM-exception",
        )
        assert report.ok, (
            "%s object must verify under the net profile: %r"
            % (label, [d.code for d in report.unsupported])
        )
        for profile in SUPPORTED_PROFILE_IDS:
            if profile == NET_PROFILE:
                continue
            refused = verify_object(
                object_path,
                profile,
                "Apache-2.0 WITH LLVM-exception",
                "Apache-2.0 WITH LLVM-exception",
            )
            assert refused.ok is False, (label, profile)
            codes = [d.code for d in refused.unsupported]
            assert "MBPF406" in codes, (label, profile, codes)
        print("PASS %s object gated to the net profile" % label)


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    try:
        check_tools("mojo", "llc")
    except EnvironmentFailure as exc:
        print("ENVIRONMENT FAILURE: %s" % exc)
        return 3
    for path in (SOCKET_SOURCE, TC_SOURCE):
        if not os.path.isfile(path):
            print("ENVIRONMENT FAILURE: missing source %s" % path)
            return 3
    failures = 0
    for name in (
        "test_net_objects_match_pins",
        "test_net_object_hashes_pinned",
        "test_net_program_layout",
        "test_net_profile_gating",
    ):
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 3
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
    if failures:
        print("net struct: %d failures" % failures)
        return 1
    print("net struct: 4 checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
