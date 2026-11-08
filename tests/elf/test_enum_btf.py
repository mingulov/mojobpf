# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""BTF enum/union: UNION-positive, ENUMs refused.

UNION (kind 5) decodes in our reader (member list, same
rule as STRUCT) but is never emitted; ENUM (6) and
ENUM64 (19) are neither emitted nor decoded (MBPF402
"unexpected BTF kind N" — correct fail-closed behavior
for a reader whose contract is our own objects). This
suite pins the UAPI kind numbers, the UNION decode rule,
the two ENUM rejections with exact messages, and the
emitter absence for all three on the production map +
core routes (build_project, parsed route asserted),
cross-checked with bpftool.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_enum_btf.py``) or
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
    ElfError,
    parse_elf,
    section_bytes,
)
from mojobpf.inspect import _parse_btf_types  # noqa: E402

ROUNDTRIP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)
CORE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "core_read.mojo"
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")
PIXI_BIN = os.path.join(REPO_ROOT, ".pixi", "envs", "default", "bin")
UAPI_HEADER = "/usr/include/linux/btf.h"

BASE_PROFILE = "linux-bpfel-v3"
CORE_PROFILE = "linux-bpfel-v3-core"

ENUM_KINDS = {
    "BTF_KIND_UNION": 5,
    "BTF_KIND_ENUM": 6,
    "BTF_KIND_ENUM64": 19,
}


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
        'name = "enum-proof"\n'
        "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "enum_probe"\n'
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
    parent = tempfile.mkdtemp(prefix="mojo-enum-prod-")
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
            os.path.join(out_dir, "enum_probe.evidence.json"),
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


def _blob(types, strings):
    header = struct.pack(
        "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types),
        len(types), len(strings),
    )
    return header + types + strings


def union_blob():
    """Synthetic .BTF: INT + UNION 'u' with members a/b."""
    strings = b"\x00int\x00u\x00a\x00b\x00"
    types = b"".join([
        struct.pack("<III", 1, (1 << 24) | 0, 4),
        struct.pack("<I", 0x20),
        struct.pack("<III", 5, (5 << 24) | 2, 4),
        struct.pack("<III", 7, 1, 0),
        struct.pack("<III", 9, 1, 0),
    ])
    return _blob(types, strings)


def enum_blob():
    """Synthetic .BTF: well-formed ENUM 'e' with A=0, B=1."""
    strings = b"\x00e\x00A\x00B\x00"
    types = struct.pack("<III", 1, (6 << 24) | 2, 4)
    types += struct.pack("<Ii", 3, 0)
    types += struct.pack("<Ii", 5, 1)
    return _blob(types, strings)


def enum64_blob():
    """Synthetic .BTF: well-formed ENUM64 'big' with BIG=1<<32."""
    strings = b"\x00big\x00BIG\x00"
    types = struct.pack("<III", 1, (19 << 24) | 1, 8)
    types += struct.pack("<III", 5, 0, 1)
    return _blob(types, strings)


def test_enum_uapi_kinds():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    for name, want in sorted(ENUM_KINDS.items()):
        match = re.search(r"%s\s*=\s*(\d+)" % name, text)
        assert match, "UAPI kind missing: %s" % name
        assert int(match.group(1)) == want, (name, match.group(1))


def test_union_decode():
    records, _strings = _parse_btf_types(union_blob(), "synthetic")
    assert records == [
        ("int", 1, 4),
        ("u", 5, [("a", 1, 0), ("b", 1, 0)]),
    ], records


def _assert_rejected(blob, kind):
    try:
        _parse_btf_types(blob, "synthetic")
    except ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert str(exc) == "unexpected BTF kind %d" % kind, str(exc)
    else:
        raise AssertionError(
            "kind-%d blob must raise MBPF402" % kind)


def test_enum_rejected():
    _assert_rejected(enum_blob(), 6)


def test_enum64_rejected():
    _assert_rejected(enum64_blob(), 19)


def _btf_kinds(image):
    elf = parse_elf(image, "built")
    sections = [s for s in elf.sections if s.name == ".BTF"]
    assert len(sections) == 1, [s.name for s in elf.sections]
    records, _strings = _parse_btf_types(
        section_bytes(elf, sections[0]), "built")
    return sorted(kind for _name, kind, _payload in records)


PRODUCTION_BUILDS = (
    # (source, profile, core, value_type, max_entries)
    (ROUNDTRIP_SOURCE, BASE_PROFILE, False, "u64", 1),
    (CORE_SOURCE, CORE_PROFILE, True, "bytes4096", 1),
)


def test_routes_emit_no_enum_union():
    for source, profile, core, value_type, max_entries in (
            PRODUCTION_BUILDS):
        kinds = _btf_kinds(build_object(
            source, profile, core, value_type, max_entries))
        assert kinds, source
        for kind in sorted(ENUM_KINDS.values()):
            assert kind not in kinds, (source, kinds)


def test_bpftool_cross_check_has_no_enum_union():
    check_tools("bpftool")
    for source, profile, core, value_type, max_entries in (
            PRODUCTION_BUILDS):
        image = build_object(
            source, profile, core, value_type, max_entries)
        workdir = tempfile.mkdtemp(prefix="mojo-enum-xcheck-")
        try:
            path = os.path.join(workdir, "probe.bpf.o")
            with open(path, "wb") as handle:
                handle.write(image)
            proc = run_step(["bpftool", "btf", "dump", "file", path])
            assert proc.returncode == 0, proc.stderr
            for word in ("UNION", "ENUM", "ENUM64"):
                assert word not in proc.stdout, (source, proc.stdout)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


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
    print("enum BTF: decode, rejection and absence checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
