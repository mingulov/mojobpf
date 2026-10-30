# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Mutation sensitivity: the suites detect action and relocation defects.

Proves that the project's acceptance checks catch real defects
instead of passing vacuously, and that built objects stay
standalone standard ELF: the sidecar-free load proof below shows a
published object inspects, verifies, and dumps through stock
readers from a directory containing only itself. Each mutation is
shown to fail its suite before the fix and pass after the revert:

* Action mutation: ``classifier_mutated.mojo`` differs from the
  packet-classifier demo by exactly the inverted bit test, and both
  objects build through the genuine pipeline. The differential
  suite (``tests/differential/test_packets.py``, invoked unmodified
  as a subprocess) fails against a probe carrying the same one-line
  flip with exactly the predicted mismatch count, and passes
  against the committed probe. The kernel accounting suite proves
  the same mutant fails in-guest and the base passes.
* Map-relocation mutation: the counter object must carry exactly
  two ``R_BPF_64_64`` relocations against the declared map at its
  two map-address loads. Zeroing one relocation entry in a copy
  fails that structural check while the map BTF still dumps cleanly
  (proving the failure is relocation-specific, not wholesale
  corruption); restoring the 16 bytes passes again. The kernel
  accounting suite proves the corrupted object then fails to load
  in-guest while the intact object loads and runs.

Requires a working Mojo compiler, LLVM ``llc``, Clang's BPF backend
inputs excluded (no C here), and ``bpftool`` on PATH. A missing
tool is an environment failure; any other failure is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_mutations.py``) or under
any ``test_``-style runner. Standard library only.
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CLASSIFIER_DIR = os.path.join(REPO_ROOT, "examples", "packet_classifier")
COUNTER_DIR = os.path.join(REPO_ROOT, "examples", "xdp_counter")
CLASSIFIER_SOURCE = os.path.join(CLASSIFIER_DIR, "classifier.mojo")
CLASSIFIER_MUTATED = os.path.join(CLASSIFIER_DIR, "classifier_mutated.mojo")
COUNTER_SOURCE = os.path.join(COUNTER_DIR, "counter.mojo")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
PACKETS_SUITE = os.path.join(
    REPO_ROOT, "tests", "differential", "test_packets.py"
)
PROBE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "differential", "packets_probe.mojo"
)
SPEC_MANIFEST = os.path.join(CLASSIFIER_DIR, "corpus", "manifest.json")
SEEDED_MANIFEST = os.path.join(
    REPO_ROOT, "tests", "differential", "seeded_manifest.json"
)
REGRESSION_MANIFEST = os.path.join(
    REPO_ROOT, "tests", "differential", "packets_regressions",
    "manifest.json",
)

sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
import audit  # noqa: E402

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

SHT_REL = 9
R_BPF_64_64 = 1
BPF_OP_LD_IMM64 = 0x18
MAP_SYMBOL = "mojobpf_map0"
MUTATION_LINE = "if (eth_last & 1) == 1:"
MUTATED_LINE = "if (eth_last & 1) == 0:"
PROBE_NEEDLE = "& 1) == 1"
PROBE_MUTANT = "& 1) == 0"


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def run_step(argv, timeout=900):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        cwd=REPO_ROOT,
    )


def check_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def build_object(source, workdir, name):
    """Run the genuine three-step build; return (raw_ir, object_path)."""
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS, "-I", SDK_INCLUDE,
         "-o", raw_path, source]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    with open(raw_path, "r", encoding="utf-8") as handle:
        raw_ir = handle.read()
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         adapted_path, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return raw_ir, object_path


_CACHED = {}


def built(name, source):
    if name not in _CACHED:
        check_tools("mojo", "llc")
        workdir = tempfile.mkdtemp(prefix="mojo-mutations-")
        _CACHED[name] = build_object(source, workdir, name) + (workdir,)
    return _CACHED[name]


def expected_mutant_mismatches():
    """Long frames across the three manifests (the flip hits each)."""
    total = 0
    with open(SPEC_MANIFEST, "r", encoding="utf-8") as handle:
        for entry in json.load(handle)["frames"]:
            total += entry["length"] >= 15
    with open(SEEDED_MANIFEST, "r", encoding="utf-8") as handle:
        for entry in json.load(handle)["frames"]:
            total += entry["length"] >= 15
    with open(REGRESSION_MANIFEST, "r", encoding="utf-8") as handle:
        for entry in json.load(handle)["frames"]:
            total += entry["length"] >= 15
    return total


def parse_elf(image):
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, _fl, _ad, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        (sh_link,) = struct.unpack_from("<I", image, off + 40)
        sections.append(
            {
                "name_off": sh_name,
                "type": sh_type,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
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
        if section["type"] != 2:  # SHT_SYMTAB
            continue
        strsec = sections[section["link"]]
        strblob = image[
            strsec["offset"]:strsec["offset"] + strsec["size"]
        ]
        for ordinal in range(section["size"] // 24):
            off = section["offset"] + ordinal * 24
            (st_name,) = struct.unpack_from("<I", image, off)
            end = strblob.index(b"\x00", st_name)
            symbols.append(strblob[st_name:end].decode("ascii"))
    return {"sections": sections, "symbols": symbols}


def check_map_relocations(image):
    """Pin the counter's two map relocations; return reloc file offsets."""
    elf = parse_elf(image)
    by_name = {section["name"]: section for section in elf["sections"]}
    assert ".relxdp" in by_name, "object lacks .relxdp"
    assert "xdp" in by_name, "object lacks xdp code"
    relsec = by_name[".relxdp"]
    assert relsec["type"] == SHT_REL, ".relxdp is not a REL section"
    assert relsec["size"] == 32, (
        ".relxdp must hold exactly two entries, got %d bytes"
        % relsec["size"]
    )
    code = by_name["xdp"]
    code_bytes = bytes(
        image[code["offset"]:code["offset"] + code["size"]]
    )
    hits = []
    for ordinal in range(2):
        off = relsec["offset"] + ordinal * 16
        (r_offset, r_info) = struct.unpack_from("<QQ", image, off)
        r_type = r_info & 0xFFFFFFFF
        r_sym = r_info >> 32
        assert r_type == R_BPF_64_64, (
            "relocation %d must be R_BPF_64_64, got %d" % (ordinal, r_type)
        )
        assert elf["symbols"][r_sym] == MAP_SYMBOL, (
            "relocation %d must target %s" % (ordinal, MAP_SYMBOL)
        )
        assert r_offset + 16 <= len(code_bytes), (
            "relocation %d points outside xdp code" % ordinal
        )
        assert code_bytes[r_offset] == BPF_OP_LD_IMM64, (
            "relocation %d must sit on a map-address load" % ordinal
        )
        hits.append(off)
    assert hits[0] != hits[1], "relocations must be distinct entries"
    return hits


def test_action_mutant_is_one_line():
    with open(CLASSIFIER_SOURCE, "r", encoding="utf-8") as handle:
        base = [
            line for line in handle.read().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    with open(CLASSIFIER_MUTATED, "r", encoding="utf-8") as handle:
        mutant = [
            line for line in handle.read().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    diff = [
        (index, old, new)
        for index, (old, new) in enumerate(zip(base, mutant))
        if old != new
    ]
    assert len(base) == len(mutant), "mutant changed the code line count"
    assert len(diff) == 1, (
        "mutant must differ by exactly one line, got %d" % len(diff)
    )
    _, old, new = diff[0]
    assert old.strip() == MUTATION_LINE, "unexpected base line: %r" % old
    assert new.strip() == MUTATED_LINE, "unexpected mutant line: %r" % new
    print("PASS classifier mutant differs by exactly the bit-test line")


def test_action_mutant_builds_and_differs():
    base_ir, base_obj = built("classifier", CLASSIFIER_SOURCE)[:2]
    mut_ir, mut_obj = built("classifier_mut", CLASSIFIER_MUTATED)[:2]
    assert audit.validate(base_ir) == "classifier"
    assert audit.validate(mut_ir) == "classifier"
    with open(base_obj, "rb") as handle:
        base_image = handle.read()
    with open(mut_obj, "rb") as handle:
        mut_image = handle.read()
    assert base_image != mut_image, "mutant object must differ from base"
    print("PASS base and mutant objects build and differ")


def test_differential_suite_detects_action_mutation():
    with open(PROBE_SOURCE, "r", encoding="utf-8") as handle:
        probe = handle.read()
    assert probe.count(PROBE_NEEDLE) == 1, (
        "probe must carry the bit test exactly once"
    )
    workdir = tempfile.mkdtemp(prefix="mojo-mutations-probe-")
    mutant_probe = os.path.join(workdir, "probe_mutated.mojo")
    with open(mutant_probe, "w", encoding="utf-8") as handle:
        handle.write(probe.replace(PROBE_NEEDLE, PROBE_MUTANT))
    expected = expected_mutant_mismatches()
    assert expected > 0
    proc = run_step(
        [sys.executable, PACKETS_SUITE, "--probe-source", mutant_probe]
    )
    assert proc.returncode == 1, (
        "differential suite must fail on the mutant, got exit %d:\n%s\n%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
    mismatches = [
        line for line in proc.stdout.splitlines()
        if line.startswith("MISMATCH ")
    ]
    assert len(mismatches) == expected, (
        "expected %d MISMATCH lines, got %d" % (expected, len(mismatches))
    )
    assert "%d mismatches of" % expected in proc.stdout
    print(
        "PASS differential suite fails on the mutant "
        "(%d/%d mismatches)" % (expected, expected)
    )


def test_differential_suite_passes_on_revert():
    proc = run_step([sys.executable, PACKETS_SUITE])
    assert proc.returncode == 0, (
        "differential suite must pass on revert, got exit %d:\n%s\n%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
    assert "match the oracle" in proc.stdout
    print("PASS differential suite passes again on revert")


def test_relocation_mutation_detected_and_reverted():
    check_tools("bpftool")
    _, counter_obj = built("counter", COUNTER_SOURCE)[:2]
    with open(counter_obj, "rb") as handle:
        image = handle.read()
    hits = check_map_relocations(image)
    print(
        "PASS intact counter carries two %s relocations" % MAP_SYMBOL
    )
    workdir = tempfile.mkdtemp(prefix="mojo-mutations-corrupt-")
    corrupt = bytearray(image)
    first = hits[0]
    corrupt[first:first + 16] = b"\x00" * 16
    diff = [i for i in range(len(image)) if corrupt[i] != image[i]]
    span = set(range(first, first + 16))
    assert diff and all(i in span for i in diff), (
        "corruption must change only relocation bytes, changed %r" % (diff,)
    )
    try:
        check_map_relocations(bytes(corrupt))
    except AssertionError as exc:
        print("PASS relocation check fails on the mutant (%s)" % exc)
    else:
        raise AssertionError("relocation check passed on corrupted bytes")
    corrupt_path = os.path.join(workdir, "counter_corrupt.bpf.o")
    with open(corrupt_path, "wb") as handle:
        handle.write(bytes(corrupt))
    proc = run_step(["bpftool", "btf", "dump", "file", corrupt_path])
    assert proc.returncode == 0, (
        "map BTF must still dump on the mutant:\n%s\n%s"
        % (proc.stdout, proc.stderr)
    )
    assert MAP_SYMBOL in proc.stdout
    print("PASS map BTF still dumps on the mutant (failure is specific)")
    reverted = bytearray(corrupt)
    reverted[first:first + 16] = image[first:first + 16]
    assert bytes(reverted) == image, "revert must restore every byte"
    check_map_relocations(bytes(reverted))
    print("PASS relocation check passes again on revert")


def test_standalone_object_without_sidecars():
    check_tools("bpftool")
    _, counter_obj = built("counter", COUNTER_SOURCE)[:2]
    workdir = tempfile.mkdtemp(prefix="mojo-mutations-lone-")
    try:
        with open(counter_obj, "rb") as handle:
            image = handle.read()
        lone = os.path.join(workdir, "counter.bpf.o")
        with open(lone, "wb") as handle:
            handle.write(image)
        assert os.listdir(workdir) == ["counter.bpf.o"]
        # Stock readers judge the object alone: no sidecar is
        # present, none is read, and none is created.
        report = inspect_module.inspect_object(lone, "linux-bpfel-v3")
        assert [item.code for item in report.structural] == []
        assert [item.code for item in report.unsupported] == []
        verified = inspect_module.verify_object(
            lone,
            "linux-bpfel-v3",
            "Apache-2.0 WITH LLVM-exception",
            "Apache-2.0 WITH LLVM-exception",
        )
        assert [item.code for item in verified.structural] == []
        assert [item.code for item in verified.unsupported] == []
        assert [item.code for item in verified.license] == []
        proc = run_step(["bpftool", "btf", "dump", "file", lone])
        assert proc.returncode == 0, (
            "stock bpftool must dump the lone object:\n%s\n%s"
            % (proc.stdout, proc.stderr)
        )
        assert MAP_SYMBOL in proc.stdout
        assert os.listdir(workdir) == ["counter.bpf.o"]
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    print("PASS lone object inspects, verifies and dumps cleanly")


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
    print("mutations: action and relocation defects detected, reverts green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
