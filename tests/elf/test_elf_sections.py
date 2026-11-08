# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""ELF data sections: libbpf section-name convention.

libbpf 1.7.0 collects maps, rodata, kconfig, ksyms
and BTF payload sections by fixed ELF section names
(`.BTF`, `.BTF.ext`, `.maps`, `.rodata`, `.kconfig`,
`.ksyms`); our production objects use exactly those
standard names, so unmodified libbpf collects them.
This suite pins the six spellings, the emitter
section sets on the production map route (`.maps` +
`.BTF`, no `.BTF.ext`) and core route (`.maps` +
`.BTF` + `.BTF.ext`), the documented absences
(`.rodata`/`.kconfig`/`.ksyms` on both routes), and
the inspect-gate agreement on both production
builds.

Requires a working Mojo compiler and LLVM ``llc``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_elf_sections.py``) or
under any ``test_``-style runner. Standard library only.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.build import (  # noqa: E402
    BuildRequest,
    build_project,
)
from mojobpf.elf_reader import (  # noqa: E402
    parse_elf,
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

BASE_PROFILE = "linux-bpfel-v3"
CORE_PROFILE = "linux-bpfel-v3-core"

# Fixed section names libbpf 1.7.0 collects by (staged
# source: src/btf.h BTF_ELF_SEC/BTF_EXT_ELF_SEC/
# MAPS_ELF_SEC, src/libbpf.c RODATA_SEC/KCONFIG_SEC/
# KSYMS_SEC; review-verified against the lock hashes).
LIBBPF_DATA_SECTIONS = {
    "BTF_ELF_SEC": ".BTF",
    "BTF_EXT_ELF_SEC": ".BTF.ext",
    "MAPS_ELF_SEC": ".maps",
    "RODATA_SEC": ".rodata",
    "KCONFIG_SEC": ".kconfig",
    "KSYMS_SEC": ".ksyms",
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
        'name = "elfsec-proof"\n'
        "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "elfsec_probe"\n'
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
    parent = tempfile.mkdtemp(prefix="mojo-elfsec-prod-")
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
            os.path.join(out_dir, "elfsec_probe.evidence.json"),
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


def _section_names(image):
    elf = parse_elf(image, "built")
    return sorted(s.name for s in elf.sections)


PRODUCTION_BUILDS = (
    # (source, profile, core, value_type, max_entries)
    (ROUNDTRIP_SOURCE, BASE_PROFILE, False, "u64", 1),
    (CORE_SOURCE, CORE_PROFILE, True, "bytes4096", 1),
)


def test_libbpf_section_spellings():
    assert LIBBPF_DATA_SECTIONS == {
        "BTF_ELF_SEC": ".BTF",
        "BTF_EXT_ELF_SEC": ".BTF.ext",
        "MAPS_ELF_SEC": ".maps",
        "RODATA_SEC": ".rodata",
        "KCONFIG_SEC": ".kconfig",
        "KSYMS_SEC": ".ksyms",
    }, LIBBPF_DATA_SECTIONS


def test_map_build_section_set():
    source, profile, core, value_type, max_entries = PRODUCTION_BUILDS[0]
    names = _section_names(build_object(
        source, profile, core, value_type, max_entries))
    assert ".maps" in names, names
    assert ".BTF" in names, names
    assert ".BTF.ext" not in names, names
    for absent in (".rodata", ".kconfig", ".ksyms"):
        assert absent not in names, (source, names)


def test_core_build_section_set():
    source, profile, core, value_type, max_entries = PRODUCTION_BUILDS[1]
    names = _section_names(build_object(
        source, profile, core, value_type, max_entries))
    assert ".maps" in names, names
    assert ".BTF" in names, names
    assert ".BTF.ext" in names, names
    for absent in (".rodata", ".kconfig", ".ksyms"):
        assert absent not in names, (source, names)


def _inspect_notes(image, profile):
    handle, path = tempfile.mkstemp(prefix="mojo-elfsec-gate-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(image)
        report = inspect_module.inspect_object(path, profile)
        assert report.ok is True, report.to_dict()
        return [item.explanation for item in report.observations]
    finally:
        os.remove(path)


def test_inspect_gates_agree():
    for source, profile, core, value_type, max_entries in (
            PRODUCTION_BUILDS):
        notes = _inspect_notes(
            build_object(
                source, profile, core, value_type, max_entries),
            profile,
        )
        assert any(
            "map metadata: .maps present: True, .BTF present: True"
            in note for note in notes
        ), (source, notes)


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
    print("elf sections: spelling and section-set checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
