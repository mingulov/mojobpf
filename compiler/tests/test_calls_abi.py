# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-CALLS/call/helper-abi: BPF_CALL opcode and helper-call emission.

BPF_CALL is the class-0x80 call operation; emitted
helper calls encode as opcode 0x85 (BPF_JMP|BPF_CALL)
with the helper ID in the 32-bit immediate and zero
regs/offset. The 12 helpers admitted across the
profile union (seven in base/core/hash/lru/subprog/
uprobe, plus 9/26 in -net, plus 131/132/133 in
-reserve) have lowering + emission proof
(reconciled in the leaf packet, review-verified).
This suite pins the opcode, the encoding shape, and
the representative emission (map route calls [1, 2],
core route calls [1]) on production parsed-route
builds. Register ABI roles are carried from
F-ISA/registers/v3, not re-pinned.

Requires a working Mojo compiler and LLVM ``llc``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 compiler/tests/test_calls_abi.py``) or
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

BPF_CALL_CLASS = 0x80
BPF_JMP_CLASS = 0x05
BPF_OP_CALL = 0x85

# The 12 helper IDs admitted across the profile
# union, reconciled to existing emission proof in
# the leaf packet.
ADMITTED_TWELVE = (1, 2, 3, 5, 8, 9, 14, 26, 130, 131, 132, 133)


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
        'name = "callabi-proof"\n'
        "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "callabi_probe"\n'
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
    parent = tempfile.mkdtemp(prefix="mojo-callabi-prod-")
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
            os.path.join(out_dir, "callabi_probe.evidence.json"),
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


def program_calls(image, section="xdp"):
    elf = parse_elf(image, "built")
    sections = [s for s in elf.sections if s.name == section]
    assert len(sections) == 1, [s.name for s in elf.sections]
    return [
        (opcode, dst, src, off, imm)
        for opcode, dst, src, off, imm in decode_insns(
            section_bytes(elf, sections[0]))
        if opcode == BPF_OP_CALL
    ]


PRODUCTION_BUILDS = (
    # (source, profile, core, value_type, max_entries, want_calls)
    (ROUNDTRIP_SOURCE, BASE_PROFILE, False, "u64", 1, [1, 2]),
    (CORE_SOURCE, CORE_PROFILE, True, "bytes4096", 1, [1]),
)


def test_bpf_call_opcode():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r"#define\s+BPF_CALL\s+(0x[0-9a-fA-F]+)", text)
    assert match, "UAPI BPF_CALL missing"
    assert int(match.group(1), 16) == BPF_CALL_CLASS, match.group(1)
    assert BPF_CALL_CLASS | BPF_JMP_CLASS == BPF_OP_CALL, (
        hex(BPF_CALL_CLASS), hex(BPF_JMP_CLASS))


def test_call_encoding_shape():
    for source, profile, core, value_type, max_entries, _ in (
            PRODUCTION_BUILDS):
        calls = program_calls(build_object(
            source, profile, core, value_type, max_entries))
        assert calls, (source, "no calls emitted at all")
        for _opcode, dst, src, off, imm in calls:
            assert (dst, src, off) == (0, 0, 0), (
                source, dst, src, off)
            assert imm in ADMITTED_TWELVE, (source, imm)


def test_emitted_call_immediates():
    for source, profile, core, value_type, max_entries, want in (
            PRODUCTION_BUILDS):
        calls = program_calls(build_object(
            source, profile, core, value_type, max_entries))
        assert [imm for _, _, _, _, imm in calls] == want, (
            source, calls)


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
    print("call abi: opcode and emission checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
