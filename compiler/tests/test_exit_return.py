# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-CALLS/exit/return: BPF_EXIT opcode and return emission.

BPF_EXIT is the class-0x90 return operation;
emitted returns encode as opcode 0x95
(BPF_JMP|BPF_EXIT) with zero regs/offset/imm
(the canonical shape the cost model accepts).
Every production program terminates in exactly
one trailing 0x95: map route 22 insns with the
exit at index 21, core route 15 insns with the
exit at index 14. This suite pins the opcode,
the encoding shape, and the trailing-singleton
emission on production parsed-route builds.

Requires a working Mojo compiler and LLVM ``llc``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 compiler/tests/test_exit_return.py``) or
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
from mojobpf.elf_reader import (  # noqa: E402
    parse_elf,
    section_bytes,
)

ROUNDTRIP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)
CORE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "core_read.mojo"
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")
PIXI_BIN = os.path.join(REPO_ROOT, ".pixi", "envs", "default", "bin")
UAPI_HEADER = "/usr/include/linux/bpf.h"

BASE_PROFILE = "linux-bpfel-v3"
CORE_PROFILE = "linux-bpfel-v3-core"

BPF_EXIT_CLASS = 0x90
BPF_JMP_CLASS = 0x05
BPF_OP_EXIT = 0x95


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


def manifest_text(profile, core, source, value_type, max_entries):
    return (
        "schema_version = 1\n"
        "\n"
        "[project]\n"
        'name = "exitret-proof"\n'
        "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "exitret_probe"\n'
        'source_license = "Apache-2.0 WITH LLVM-exception"\n'
        'kernel_license = "Apache-2.0 WITH LLVM-exception"\n'
        "\n"
        "[[programs]]\n"
        'source = "%s"\n' % source
        + 'entry = "xdp_entry"\n'
        'program_type = "xdp"\n'
        'section = "xdp"\n'
        "[[maps]]\n"
        'name = "mojobpf_map0"\n'
        'map_type = "array"\n'
        'key_type = "u32"\n'
        'value_type = "%s"\n' % value_type
        + "max_entries = %d\n" % max_entries
    )


def build_object(source, profile, core, value_type, max_entries):
    """Build through the production route; return image bytes."""
    check_tools("mojo", "llc")
    for path in (source, SERVICE, LOCKFILE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    parent = tempfile.mkdtemp(prefix="mojo-exitret-prod-")
    try:
        project = os.path.join(parent, "proj")
        os.makedirs(project)
        staged = os.path.join(
            project, os.path.basename(source)
        )
        shutil.copyfile(source, staged)
        manifest_path = os.path.join(project, "mojobpf.toml")
        with open(manifest_path, "w", encoding="utf-8") as handle:
            handle.write(
                manifest_text(
                    profile, core, os.path.basename(source),
                    value_type, max_entries,
                )
            )
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
            os.path.join(out_dir, "exitret_probe.evidence.json"),
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


def decode_insns(code):
    """Decode raw code bytes into (opcode, dst, src, off, imm)."""
    insns = []
    for off in range(0, len(code), 8):
        opcode = code[off]
        regs = code[off + 1]
        (jump,) = struct.unpack_from("<h", code, off + 2)
        (imm,) = struct.unpack_from("<i", code, off + 4)
        insns.append((opcode, regs & 0xF, regs >> 4, jump, imm))
    return insns


def program_insns(image, section="xdp"):
    elf = parse_elf(image, "built")
    sections = [s for s in elf.sections if s.name == section]
    assert len(sections) == 1, [s.name for s in elf.sections]
    return decode_insns(section_bytes(elf, sections[0]))


def check_encoding(exits, source):
    """Every emitted exit is the canonical all-zero shape."""
    assert exits, (source, "no exits emitted at all")
    for index, _opcode, dst, src, off, imm in exits:
        assert (dst, src, off, imm) == (0, 0, 0, 0), (
            source, index, dst, src, off, imm)


def check_singleton(insns, source, want_total):
    """Exactly one exit, trailing, with the pinned insn count."""
    exits = [
        (index, opcode, dst, src, off, imm)
        for index, (opcode, dst, src, off, imm) in enumerate(insns)
        if opcode == BPF_OP_EXIT
    ]
    assert len(insns) == want_total, (source, len(insns))
    assert len(exits) == 1, (source, len(exits))
    assert exits[0][0] == want_total - 1, (source, exits[0][0])
    return exits


PRODUCTION_BUILDS = (
    # (source, profile, core, value_type, max_entries, want_total)
    (ROUNDTRIP_SOURCE, BASE_PROFILE, False, "u64", 1, 22),
    (CORE_SOURCE, CORE_PROFILE, True, "bytes4096", 1, 15),
)


def test_bpf_exit_opcode():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r"#define\s+BPF_EXIT\s+(0x[0-9a-fA-F]+)", text)
    assert match, "UAPI BPF_EXIT missing"
    assert int(match.group(1), 16) == BPF_EXIT_CLASS, match.group(1)
    assert BPF_EXIT_CLASS | BPF_JMP_CLASS == BPF_OP_EXIT, (
        hex(BPF_EXIT_CLASS), hex(BPF_JMP_CLASS))


def test_exit_encoding_shape():
    for source, profile, core, value_type, max_entries, _ in (
            PRODUCTION_BUILDS):
        insns = program_insns(build_object(
            source, profile, core, value_type, max_entries))
        check_encoding(
            [
                (index, opcode, dst, src, off, imm)
                for index, (opcode, dst, src, off, imm)
                in enumerate(insns)
                if opcode == BPF_OP_EXIT
            ],
            source,
        )


def test_trailing_singleton_exit():
    for source, profile, core, value_type, max_entries, want in (
            PRODUCTION_BUILDS):
        check_singleton(
            program_insns(build_object(
                source, profile, core, value_type, max_entries)),
            source, want,
        )


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
    print("exit return: opcode and emission checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
