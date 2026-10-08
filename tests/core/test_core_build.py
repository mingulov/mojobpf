# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Core driver path: the manifest/profile/build vocabulary proves out.

Builds ``tests/core/core_read.mojo`` through the genuine driver
(``build_project`` with the pinned toolchain lockfile and the
in-tree adapter service) under the CO-RE capability profile and
asserts the full route accepts it: the manifest vocabulary
(``core = true``, the ``bytes4096`` map value), the profile
metadata, the spill gate, the map reconciliation, and the
CO-RE-flag/object agreement all pass, and the published object
carries exactly the two pinned relocation records (checked with
the independent reader).

Negative proofs pin the exact refusal at each layer: the
``bytes4096`` value on the base profile (manifest vocabulary),
``core = true`` on the base profile (profile support), a core
program under ``core = false`` and a non-core program under
``core = true`` (flag/object agreement, both directions), and a
core program with the wrong declared value size (value
reconciliation).

Requires the pinned toolchain (mojo, llc) on PATH. A missing
tool is an environment failure; a failing step is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/core/test_core_build.py``) or
under any ``test_``-style runner. Standard library only.
"""

import importlib.util
import os
import shutil
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import BuildRequest, build_project  # noqa: E402

CORE_SOURCE = os.path.join(REPO_ROOT, "tests", "core", "core_read.mojo")
READER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "btfext_reader.py"
)
ADAPTER = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")
PIXI_BIN = os.path.join(REPO_ROOT, ".pixi", "envs", "default", "bin")
MAP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)

CORE_PROFILE = "linux-bpfel-v3-core"
BASE_PROFILE = "linux-bpfel-v3"


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools():
    for tool in ("mojo", "llc"):
        found = shutil.which(tool) or os.path.join(PIXI_BIN, tool)
        if not (shutil.which(tool) or os.path.isfile(found)):
            raise EnvironmentFailure("%s not found" % tool)


def load_reader():
    spec = importlib.util.spec_from_file_location(
        "core_btfext_reader_build", READER_SOURCE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest_text(profile, core, source, value_type="bytes4096"):
    return (
        "schema_version = 1\n"
        "\n"
        "[project]\n"
        'name = "core-proof"\n'
        "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "core_read"\n'
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
        + "max_entries = 1\n"
    )


def run_build(tree_source, profile, core, value_type="bytes4096"):
    parent = tempfile.mkdtemp(prefix="mojobpf-core-build-")
    try:
        project = os.path.join(parent, "proj")
        os.makedirs(project)
        staged = os.path.join(
            project, os.path.basename(tree_source)
        )
        shutil.copyfile(tree_source, staged)
        manifest_path = os.path.join(project, "mojobpf.toml")
        with open(manifest_path, "w", encoding="utf-8") as handle:
            handle.write(
                manifest_text(
                    profile, core, os.path.basename(tree_source),
                    value_type,
                )
            )
        out_dir = os.path.join(parent, "out")
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=ADAPTER,
                search_paths=(PIXI_BIN,),
                timeout_s=600,
                lockfile_path=LOCKFILE,
            )
        )
        objects = []
        if os.path.isdir(out_dir):
            for entry in sorted(os.listdir(out_dir)):
                if entry.endswith(".bpf.o"):
                    with open(
                        os.path.join(out_dir, entry), "rb"
                    ) as handle:
                        objects.append(handle.read())
        return result, objects
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def assert_failure(result, code, label):
    assert result.success is False, (label, result.success)
    codes = [item.code for item in result.diagnostics]
    assert code in codes, (label, codes)


def test_core_builds_under_core_profile():
    check_tools()
    result, objects = run_build(CORE_SOURCE, CORE_PROFILE, True)
    assert result.success is True, (
        [str(item) for item in result.diagnostics],
    )
    assert len(objects) == 1, len(objects)
    reader = load_reader()
    resolved = reader.read_relocations(objects[0])
    relocs = resolved["relocations"]
    assert len(relocs) == 2, relocs
    assert (
        relocs[0]["type"],
        relocs[0]["kind_name"],
        relocs[0]["member"],
    ) == ("task_struct", "FIELD_BYTE_OFFSET", "pid"), relocs
    assert (
        relocs[1]["type"],
        relocs[1]["kind_name"],
        relocs[1]["member"],
    ) == ("task_struct", "FIELD_EXISTS", "scx"), relocs
    assert result.provenance.profile_id == CORE_PROFILE, (
        result.provenance
    )
    print("PASS core driver build (profile, gates, relocations)")


def test_bytes_value_refused_on_base_profile():
    check_tools()
    result, _objects = run_build(CORE_SOURCE, BASE_PROFILE, False,
                                 value_type="bytes4096")
    assert_failure(result, "MBPF205", "bytes4096 on base profile")
    print("PASS bytes4096 refused on base profile (MBPF205)")


def test_core_flag_refused_on_base_profile():
    check_tools()
    result, _objects = run_build(CORE_SOURCE, BASE_PROFILE, True,
                                 value_type="u64")
    assert_failure(result, "MBPF211", "core=true on base profile")
    print("PASS core=true refused on base profile (MBPF211)")


def test_unrequested_relocations_refused():
    check_tools()
    result, _objects = run_build(CORE_SOURCE, CORE_PROFILE, False)
    assert_failure(result, "MBPF216", "core program, core=false")
    print("PASS unrequested relocations refused (MBPF216)")


def test_requested_but_absent_refused():
    check_tools()
    result, _objects = run_build(MAP_SOURCE, CORE_PROFILE, True,
                                 value_type="u64")
    assert_failure(result, "MBPF216", "map program, core=true")
    print("PASS requested-but-absent relocations refused (MBPF216)")


def test_wrong_value_size_refused():
    check_tools()
    result, _objects = run_build(CORE_SOURCE, CORE_PROFILE, True,
                                 value_type="u64")
    assert_failure(result, "MBPF216", "core program, u64 value")
    print("PASS wrong core value size refused (MBPF216)")


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
    print("core build: driver path proves out with exact refusals")
    return 0


if __name__ == "__main__":
    sys.exit(main())
