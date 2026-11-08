# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-BTF/flags/btf-opts: BTF_F_* display flags have no carrier.

Four UAPI bits (COMPACT, NONAME, PTR_RAW, ZERO)
are display options for the bpf_snprintf_btf (149) /
bpf_seq_printf_btf (150) helpers. Claim: neither
helper is admitted by any MojoBPF profile, no
product code references the flags or the helpers,
and no emitted object calls them — the flags are
never set, forwarded, or consumed anywhere in our
toolchain. This suite pins the UAPI bits against
the installed header and proves the no-carrier
surface over the registry, the product tree, and
production builds.

Surface scoping: flag-macro needles walk
src/compiler/tests/ci; helper-name needles walk
src/compiler only — tests/ hold a recorded kernel
helper-table pin (inventory fixture) and tools/
holds the family-mapping table, both observation,
not toolchain surface.

Lane note: this suite builds through the production
route, so it lives in tests/elf (compiler lane);
the guarded unit lane refuses compiler execution.
"""
import json
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import capabilities as capabilities_module  # noqa: E402
from mojobpf import helpers as helpers_module  # noqa: E402
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.build import (  # noqa: E402
    BuildRequest,
    build_project,
)

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
UAPI_HEADER = "/usr/include/linux/bpf.h"

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

# Owned display-option bits, pinned here and verified
# against the installed header below.
BTF_FLAGS = {
    "BTF_F_COMPACT": 0,
    "BTF_F_NONAME": 1,
    "BTF_F_PTR_RAW": 2,
    "BTF_F_ZERO": 3,
}

# Helpers that consume the flags. Neither may be
# admitted, referenced, or emitted.
FLAG_HELPERS = {
    149: "bpf_snprintf_btf",
    150: "bpf_seq_printf_btf",
}


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools(*tools):
    for tool in tools:
        found = shutil.which(tool) or os.path.join(PIXI_BIN, tool)
        if not (shutil.which(tool) or os.path.isfile(found)):
            raise EnvironmentFailure("%s not found" % tool)


def test_btf_flags_uapi_bits():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    for name, bit in sorted(BTF_FLAGS.items()):
        match = re.search(
            r"%s\s*=\s*\(1ULL\s*<<\s*(\d+)\)" % name, text)
        assert match, "UAPI macro missing: %s" % name
        assert int(match.group(1)) == bit, (name, match.group(1))


DESCRIPTOR_PATHS = (
    os.path.join("compiler", "admission.json"),
    os.path.join("src", "mojobpf", "resources", "adapter",
                 "admission.json"),
)


def test_registry_admits_no_flag_helpers():
    for helper_id, name in sorted(FLAG_HELPERS.items()):
        assert helpers_module.lookup_helper(helper_id) is None, (
            helper_id, name)
    profiles = capabilities_module.SUPPORTED_PROFILE_IDS
    assert profiles, "profile walk must stay populated"
    for profile_id in profiles:
        # Truthful admission view (descriptor-backed,
        # inheritance included) — not the
        # introducing-only legacy spelling.
        admitted = capabilities_module.helpers_for_profile(
            profile_id)
        for helper_id in FLAG_HELPERS:
            assert helper_id not in admitted, (
                profile_id, helper_id, admitted)
    for rel in DESCRIPTOR_PATHS:
        with open(os.path.join(REPO_ROOT, rel),
                  encoding="utf-8") as handle:
            descriptor = json.load(handle)
        seen = set()
        for profile_id, entry in sorted(
                descriptor["profiles"].items()):
            seen.add(profile_id)
            for helper_id in FLAG_HELPERS:
                assert helper_id not in entry["helper_ids"], (
                    rel, profile_id, helper_id)
        assert seen == set(profiles), (rel, seen)


WALK_ROOTS = ["src", "compiler", "tests", "ci"]
WALK_EXTENSIONS = (".py", ".txt", ".mojo", ".cpp", ".h", ".c")
WALK_ALLOWED = {
    os.path.join("tests", "elf", "test_btf_flags.py"),
    os.path.join("tests", "negative", "btf", "flags",
                 "btf_flags.txt"),
}
HELPER_NEEDLES = [
    "bpf_snprintf_btf",
    "snprintf_btf",
    "bpf_seq_printf_btf",
    "seq_printf_btf",
]
HELPER_WALK_ROOTS = ["src", "compiler"]


def _walk_files(roots):
    for root in roots:
        for current, _dirs, files in os.walk(
                os.path.join(REPO_ROOT, root)):
            for name in sorted(files):
                if not name.endswith(WALK_EXTENSIONS):
                    continue
                path = os.path.join(current, name)
                rel = os.path.relpath(path, REPO_ROOT)
                if rel in WALK_ALLOWED:
                    continue
                with open(path, encoding="utf-8",
                          errors="replace") as handle:
                    yield rel, handle.read()


def _flag_patterns():
    return [
        re.compile(r"\b%s\b" % re.escape(needle))
        for needle in BTF_FLAGS
    ]


def _helper_patterns():
    # Both spellings: the unprefixed needle alone
    # cannot match inside `bpf_`-prefixed names (no
    # word boundary after `_`), so the prefixed forms
    # are pinned explicitly.
    return [
        re.compile(r"\b%s\b" % re.escape(needle))
        for needle in HELPER_NEEDLES
    ]


def test_no_btf_flag_macros_in_tree():
    hits = []
    for rel, text in _walk_files(WALK_ROOTS):
        for needle, pattern in zip(BTF_FLAGS, _flag_patterns()):
            if pattern.search(text):
                hits.append((rel, needle))
    assert hits == [], hits


def test_no_flag_helper_surface_in_tree():
    hits = []
    for rel, text in _walk_files(HELPER_WALK_ROOTS):
        for needle, pattern in zip(
                HELPER_NEEDLES, _helper_patterns()):
            if pattern.search(text):
                hits.append((rel, needle))
    assert hits == [], hits


def test_matcher_catches_snprintf_call():
    # Retained mutation: snprintf-shaped call sites must
    # match even though no such site exists in the tree.
    # Real call shapes carry the `bpf_` prefix.
    for call, want in (
            ("r = bpf_snprintf_btf(dst, s, p, d, f);",
             ["bpf_snprintf_btf"]),
            ("r = bpf_seq_printf_btf(m, d, f);",
             ["bpf_seq_printf_btf"]),
            ("emit_call(149, [dst, fmt]);// snprintf_btf",
             ["snprintf_btf"]),
            ("emit_call(150, [m]);// seq_printf_btf",
             ["seq_printf_btf"])):
        matched = [
            needle for needle, pattern in zip(
                HELPER_NEEDLES, _helper_patterns())
            if pattern.search(call)
        ]
        assert matched == want, (call, matched)
    flagged = "flags = BTF_F_ZERO | BTF_F_COMPACT;"
    matched_flags = [
        needle for needle, pattern in zip(
            BTF_FLAGS, _flag_patterns())
        if pattern.search(flagged)
    ]
    assert sorted(matched_flags) == [
        "BTF_F_COMPACT", "BTF_F_ZERO"], matched_flags


def manifest_text(profile, core, source, value_type, max_entries):
    return (
        "schema_version = 1\n"
        "\n"
        "[project]\n"
        'name = "btfopt-proof"\n'
        "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "btfopt_probe"\n'
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
    parent = tempfile.mkdtemp(prefix="mojo-btfopt-prod-")
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
            os.path.join(out_dir, "btfopt_probe.evidence.json"),
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


PRODUCTION_BUILDS = (
    # (source, profile, core, value_type, max_entries)
    (ROUNDTRIP_SOURCE, BASE_PROFILE, False, "u64", 1),
    (CORE_SOURCE, CORE_PROFILE, True, "bytes4096", 1),
)


def _observed_helper_ids(image, profile):
    handle, path = tempfile.mkstemp(prefix="mojo-btfopt-gate-")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(image)
        report = inspect_module.inspect_object(path, profile)
        assert report.ok is True, report.to_dict()
        for item in report.observations:
            match = re.search(
                r"helper IDs observed: ([0-9, ()none]+)",
                item.explanation)
            if match:
                text = match.group(1).strip()
                if text == "(none)":
                    return []
                return [int(part) for part in text.split(", ")]
        raise AssertionError("no helper-ID observation: %s" % (
            [item.explanation for item in report.observations],))
    finally:
        os.remove(path)


def test_emitted_calls_carry_no_flag_helpers():
    for source, profile, core, value_type, max_entries in (
            PRODUCTION_BUILDS):
        observed = _observed_helper_ids(
            build_object(
                source, profile, core, value_type, max_entries),
            profile,
        )
        assert observed, (source, "no calls observed at all")
        for helper_id in FLAG_HELPERS:
            assert helper_id not in observed, (source, observed)


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
    print("btf flags: pins and no-carrier checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
