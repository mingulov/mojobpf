# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""BTF modifiers/qualifiers: refusal on both sides.

Our toolchain neither emits BTF kinds 8/9/10/11
(TYPEDEF/VOLATILE/CONST/RESTRICT) nor decodes them:
the inspector rejects them with MBPF402
("unexpected BTF kind N"), which is correct
fail-closed behavior for a reader whose contract is
our own objects. This suite pins the UAPI kind
numbers, the per-kind rejection with exact messages,
and the emitter absence on the map + core routes over
the production build (build_project, parsed route
asserted), cross-checked with bpftool.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_modifier_btf.py``) or
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

MODIFIER_KINDS = {
    "BTF_KIND_TYPEDEF": 8,
    "BTF_KIND_VOLATILE": 9,
    "BTF_KIND_CONST": 10,
    "BTF_KIND_RESTRICT": 11,
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
        'name = "modifier-proof"\n'
        "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "modifier_probe"\n'
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
    """Build through the production route; return image bytes.

    Uses build_project (route-selected like release builds)
    and asserts the parsed route ran, so the absence proof
    covers the production emitter, not just Lane-A.
    """
    check_tools("mojo", "llc")
    for path in (source, SERVICE, LOCKFILE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    parent = tempfile.mkdtemp(prefix="mojo-mod-prod-")
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
            os.path.join(out_dir, "modifier_probe.evidence.json"),
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


def modifier_blob(kind):
    """Synthetic .BTF: INT + one KIND record pointing at it.

    VOLATILE/CONST/RESTRICT are unnamed (name_off 0), as the
    kernel validator requires; TYPEDEF keeps its name.
    """
    strings = b"\x00int\x00mod\x00"
    name_off = 5 if kind == 8 else 0
    types = b"".join([
        struct.pack("<III", 1, (1 << 24) | 0, 4),
        struct.pack("<I", 0x20),
        struct.pack("<III", name_off, (kind << 24) | 0, 1),
    ])
    header = struct.pack(
        "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types),
        len(types), len(strings),
    )
    return header + types + strings


def test_modifier_uapi_kinds():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    for name, want in sorted(MODIFIER_KINDS.items()):
        match = re.search(r"%s\s*=\s*(\d+)" % name, text)
        assert match, "UAPI kind missing: %s" % name
        assert int(match.group(1)) == want, (name, match.group(1))


def _assert_rejected(kind):
    try:
        _parse_btf_types(modifier_blob(kind), "synthetic")
    except ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert str(exc) == "unexpected BTF kind %d" % kind, str(exc)
    else:
        raise AssertionError(
            "kind-%d blob must raise MBPF402" % kind)


def test_typedef_rejected():
    _assert_rejected(8)


def test_volatile_rejected():
    _assert_rejected(9)


def test_const_rejected():
    _assert_rejected(10)


def test_restrict_rejected():
    _assert_rejected(11)


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


def test_routes_emit_no_modifiers():
    for source, profile, core, value_type, max_entries in (
            PRODUCTION_BUILDS):
        kinds = _btf_kinds(build_object(
            source, profile, core, value_type, max_entries))
        assert kinds, source
        for kind in sorted(MODIFIER_KINDS.values()):
            assert kind not in kinds, (source, kinds)


def test_bpftool_cross_check_has_no_modifiers():
    check_tools("bpftool")
    for source, profile, core, value_type, max_entries in (
            PRODUCTION_BUILDS):
        image = build_object(
            source, profile, core, value_type, max_entries)
        workdir = tempfile.mkdtemp(prefix="mojo-mod-xcheck-")
        try:
            path = os.path.join(workdir, "probe.bpf.o")
            with open(path, "wb") as handle:
                handle.write(image)
            proc = run_step(["bpftool", "btf", "dump", "file", path])
            assert proc.returncode == 0, proc.stderr
            for word in ("TYPEDEF", "VOLATILE", "CONST", "RESTRICT"):
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
    print("modifier BTF: rejection and absence checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
