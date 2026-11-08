# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-CALLS/pseudo/func: BPF_PSEUDO_FUNC value and its qualified refusal.

BPF_PSEUDO_FUNC is the UAPI value 4 carried in
the src_reg of a 0x18 wide load whose imm is a
function reference. The value has no carrier in
this toolchain: the pinned backend never writes
a kinded 0x18 word, every 0x18 pair in the
production map/core/subprog objects has src=0,
the name has zero tree surface in src/compiler,
and the cost collector refuses src=4 with
``unsupported-code-reference``. This suite pins
the UAPI value, the production absence, the
zero surface, and the cost refusal.

Requires a working Mojo compiler and LLVM ``llc``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 compiler/tests/test_pseudo_func.py``) or
under any ``test_``-style runner. Standard library only.
"""
import hashlib
import importlib.util
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
from mojobpf.validation.models import (  # noqa: E402
    canonical_json,
)

ROUNDTRIP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)
CORE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "core_read.mojo"
)
EXAMPLE_DIR = os.path.join(
    REPO_ROOT, "examples", "subprog_call"
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")
PIXI_BIN = os.path.join(REPO_ROOT, ".pixi", "envs", "default", "bin")
UAPI_HEADER = "/usr/include/linux/bpf.h"
COLLECT_PATH = os.path.join(
    REPO_ROOT, "tests", "codegen_cost", "collect.py"
)

BASE_PROFILE = "linux-bpfel-v3"
CORE_PROFILE = "linux-bpfel-v3-core"

BPF_PSEUDO_FUNC = 4
BPF_OP_LD_IMM64 = 0x18

WALK_ROOTS = ["src", "compiler"]
WALK_EXTENSIONS = (".py", ".txt", ".mojo", ".cpp", ".h", ".c")
WALK_ALLOWED = {
    os.path.join("compiler", "tests", "test_pseudo_func.py"),
    os.path.join("tests", "negative", "calls",
                 "pseudo_func.txt"),
}
# Substring needles (stronger than word-boundary:
# they also catch bpf_-prefixed spellings).
WALK_NEEDLES = ("PSEUDO_FUNC", "pseudo_func")

MINIMUM_METRICS = [
    "elf_bytes", "section_file_bytes", "section_logical_bytes",
    "executable_bytes", "reachable_slots", "reachable_bytes",
    "reachable_subprograms", "call_depth",
]


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


def manifest_text(name, profile, core, source, value_type,
                  max_entries):
    return (
        "schema_version = 1\n"
        "\n"
        "[project]\n"
        'name = "%s"\n' % name
        + "\n"
        "[target]\n"
        'profile = "%s"\n' % profile
        + "core = %s\n" % ("true" if core else "false")
        + "\n"
        "[artifact]\n"
        'name = "%s_probe"\n' % name
        + 'source_license = "Apache-2.0 WITH LLVM-exception"\n'
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


def build_manifest(name, source, profile, core, value_type,
                   max_entries):
    """Build a generated manifest via the production route."""
    check_tools("mojo", "llc")
    for path in (source, SERVICE, LOCKFILE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    parent = tempfile.mkdtemp(prefix="mojo-pseudofunc-prod-")
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
                    name, profile, core,
                    os.path.basename(source), value_type,
                    max_entries,
                )
            )
        return _build_project(manifest_path, parent,
                              "%s_probe" % name)
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def build_example():
    """Build the committed subprog example via production route."""
    check_tools("mojo", "llc")
    for path in (
            os.path.join(EXAMPLE_DIR, "decision.mojo"),
            os.path.join(EXAMPLE_DIR, "mojobpf.toml"),
            SERVICE, LOCKFILE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    parent = tempfile.mkdtemp(prefix="mojo-pseudofunc-prod-")
    try:
        project = os.path.join(parent, "proj")
        os.makedirs(project)
        for name in ("decision.mojo", "mojobpf.toml"):
            shutil.copyfile(
                os.path.join(EXAMPLE_DIR, name),
                os.path.join(project, name),
            )
        return _build_project(
            os.path.join(project, "mojobpf.toml"), parent,
            "subprog_decision",
        )
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def _build_project(manifest_path, parent, artifact):
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
        os.path.join(out_dir, artifact + ".evidence.json"),
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


def wide_srcs(image, section="xdp"):
    """Src nibble of every 0x18 pair in the section."""
    elf = parse_elf(image, "built")
    sections = [s for s in elf.sections if s.name == section]
    assert len(sections) == 1, [s.name for s in elf.sections]
    code = section_bytes(elf, sections[0])
    srcs = []
    for off in range(0, len(code), 8):
        if code[off] == BPF_OP_LD_IMM64:
            srcs.append((code[off + 1] >> 4) & 0xF)
    return srcs


PRODUCTION_BUILDS = (
    # (tag, thunk, want_pairs)
    ("map", lambda: build_manifest(
        "pseudofunc-map", ROUNDTRIP_SOURCE, BASE_PROFILE,
        False, "u64", 1), 2),
    ("core", lambda: build_manifest(
        "pseudofunc-core", CORE_SOURCE, CORE_PROFILE,
        True, "bytes4096", 1), 1),
    ("subprog", build_example, 0),
)


def check_absence(tag, image, want_pairs):
    srcs = wide_srcs(image)
    assert len(srcs) == want_pairs, (tag, len(srcs))
    assert not [src for src in srcs if src != 0], (tag, srcs)


def check_surface(roots, allowed):
    """No PSEUDO_FUNC spelling under the roots."""
    hits = []
    for root in roots:
        base = (root if os.path.isabs(root)
                else os.path.join(REPO_ROOT, root))
        for current, _dirs, files in os.walk(base):
            for name in sorted(files):
                if not name.endswith(WALK_EXTENSIONS):
                    continue
                path = os.path.join(current, name)
                rel = os.path.relpath(path, REPO_ROOT)
                if rel in allowed:
                    continue
                with open(path, encoding="utf-8",
                          errors="replace") as handle:
                    text = handle.read()
                for needle in WALK_NEEDLES:
                    if needle in text:
                        hits.append((rel, needle))
    assert not hits, hits


def collector():
    assert os.path.isfile(COLLECT_PATH), (
        "the object cost collector is not implemented")
    name = "object_cost_collector_pseudo_func"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, COLLECT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def synthetic_elf(code):
    """Minimal ELF with one xdp section + main symbol."""
    sections = [("xdp", 1, 6, code)]
    rows = [("", 0, 0, b"", 0, 0, 0)]
    rows.extend(
        (name, kind, flags, data, 0, 0, 0)
        for name, kind, flags, data in sections
    )
    strings = bytearray(b"\0")
    entries = bytearray(24)
    offset = len(strings)
    strings.extend(b"main\0")
    entries.extend(
        struct.pack("<IBBHQQ", offset, 0x12, 0, 1, 0, 24)
    )
    index = len(rows)
    rows.append((".symtab0", 2, 0, bytes(entries),
                 index + 1, 1, 24))
    rows.append((".strtab0", 3, 0, bytes(strings), 0, 0, 0))
    names = bytearray(b"\0")
    offsets = [0]
    for name, *_ in rows[1:]:
        offsets.append(len(names))
        names.extend(name.encode("ascii") + b"\0")
    offsets.append(len(names))
    names.extend(b".shstrtab\0")
    name_index = len(rows)
    rows.append((".shstrtab", 3, 0, bytes(names), 0, 0, 0))
    image = bytearray(64)
    headers = []
    for ordinal, (_, kind, flags, data, link, info,
                   stride) in enumerate(rows):
        location = len(image) if ordinal else 0
        image.extend(data)
        headers.append(struct.pack(
            "<IIQQQQIIQQ", offsets[ordinal], kind, flags, 0,
            location, len(data), link, info, 1, stride))
    while len(image) % 8:
        image.append(0)
    section_offset = len(image)
    image.extend(b"".join(headers))
    image[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH", image, 16, 1, 247, 1, 0, 0,
        section_offset, 0, 64, 0, 0, 64, len(rows),
        name_index)
    return bytes(image)


EXIT_CODE = bytes.fromhex("95 00 00 00 00 00 00 00")


def wide_code(src):
    return (bytes([BPF_OP_LD_IMM64, src << 4, 0, 0,
                   0x29, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            + EXIT_CODE)


def collect_image(module, image, case_id):
    semantic = {"oracle_version": 1, "domain": "pseudo-func",
                "observable": "wide-load pseudo-source gate"}
    case = {
        "case_id": case_id, "family": "accounting-control",
        "producer": "synthetic", "route": "synthetic",
        "profile": "linux-bpfel-v3",
        "entry": {"section": "xdp", "symbol": "main"},
        "source_refs": ["compiler/tests/test_pseudo_func.py"],
        "corpus_ref": None,
        "oracle_ref": "compiler/tests/test_pseudo_func.py",
        "semantic_contract": semantic,
        "semantic_contract_sha256": hashlib.sha256(
            canonical_json(semantic)).hexdigest(),
        "object_sha256": hashlib.sha256(image).hexdigest(),
        "measurement_scope": "object",
        "required_metrics": list(MINIMUM_METRICS),
        "status": "ready", "pending_reason": None,
        "prerequisites": [],
    }
    raw = canonical_json({
        "schema_version": 1,
        "metrics": [{"name": name, "unit": unit}
                    for name, unit in
                    module.METRIC_UNITS.items()],
        "cases": [case],
    })
    bound = module.load_cases(raw)["cases"][0]
    return module.collect_object(
        image, case=bound, provenance=None)


def test_bpf_pseudo_func_value():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r"#define\s+BPF_PSEUDO_FUNC\s+(\d+)", text)
    assert match, "UAPI BPF_PSEUDO_FUNC missing"
    assert int(match.group(1)) == BPF_PSEUDO_FUNC, match.group(1)


def test_no_kinded_wide_load_in_production():
    for tag, thunk, want_pairs in PRODUCTION_BUILDS:
        check_absence(tag, thunk(), want_pairs)


def test_zero_tree_surface():
    check_surface(WALK_ROOTS, WALK_ALLOWED)


def test_cost_refuses_pseudo_func():
    module = collector()
    baseline = collect_image(
        module, synthetic_elf(wide_code(0)),
        "control.pseudo-func.baseline")
    assert baseline["complete"] is True, baseline["issues"]
    refused = collect_image(
        module, synthetic_elf(wide_code(BPF_PSEUDO_FUNC)),
        "control.pseudo-func.refused")
    assert refused["complete"] is False, refused
    codes = {entry["code"] for entry in refused["issues"]}
    assert "unsupported-code-reference" in codes, (
        refused["issues"])
    assert any("pseudo sources" in entry["explanation"]
               for entry in refused["issues"]), refused["issues"]


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
    print("pseudo func: value and refusal checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
