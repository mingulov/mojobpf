# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Differential proof for the packet corpus.

Runs the full packet corpus (the 33-frame fixed corpus from
``examples/packet_classifier/corpus/``, 32 deterministic seeded
frames, and 3 minimized regressions) through the native Mojo probe
(``tests/differential/packets_probe.mojo``, plain ``mojo build`` on
the host) and predicts every probe line with an independent integer
oracle that is mechanically distinct from the Mojo under test: the
length guard is a host ``len()`` comparison (never the
data_end-minus-data arithmetic the SDK performs), the bit test is a
modulo (never the mask-and-compare the programs spell), and the
running count and byte total are Python big-integer accumulations.
A shared masking, guard, or wrapping misunderstanding therefore
cannot hide: the two sides share only the input bytes.

Coverage: every fixed-corpus frame (lengths 14 through 1500, tested
byte across 0/1/2/255, 16 drops / 17 passes / 9,590 bytes); seeded
frames with boundary lengths plus adversary-chosen payload bytes
from a hand-rolled deterministic generator (seed 20261007, pinned
hashes in ``tests/differential/seeded_manifest.json`` so generator
drift fails loudly); and minimized regressions reproduced
byte-identically by the suite's own minimizer. The probe runs on
the build host and uses host heap scratch buffers; it is test glue,
not kernel code. Kernel behavior of the same rule is proven
in-guest by the kernel accounting suite.

The suite also builds the independent C reference
(``tests/reference_c/xdp_counter_ref.bpf.c``) with the pinned Clang
and pins its structure: a conventional relocatable object with the
exact license bytes, one program whose only helper calls are the
two map lookups and two map updates, whose only reported actions
are 1 and 2, whose four code relocations all target the declared
map, and whose BTF describes the two-entry array. The C program's
in-kernel behavior is compared separately by the accounting suite.

``--probe-source PATH`` substitutes a different probe (the mutation
suite uses this to prove the differential comparison detects a
flipped bit test); the default is the committed probe. Any oracle
mismatch exits 1 with MISMATCH lines; nothing here ever passes on
a missing tool (environment failures exit 2) or a shortfall.

Runnable directly (``python3 tests/differential/test_packets.py``)
or under any ``test_``-style runner. Standard library only.
"""

import argparse
import hashlib
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
CORPUS_DIR = os.path.join(
    REPO_ROOT, "examples", "packet_classifier", "corpus"
)
SPEC_MANIFEST = os.path.join(CORPUS_DIR, "manifest.json")
PROBE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "differential", "packets_probe.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
C_SOURCE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "xdp_counter_ref.bpf.c"
)
SEEDED_MANIFEST = os.path.join(
    REPO_ROOT, "tests", "differential", "seeded_manifest.json"
)
REGRESSION_DIR = os.path.join(
    REPO_ROOT, "tests", "differential", "packets_regressions"
)

SEED = 20261007
LCG_A = 1103515245
LCG_C = 12345
LCG_M = 0x80000000
N_SEEDED = 32
SEEDED_FIXED_LENGTHS = (14, 15, 16)
SEEDED_MIN_LENGTH = 17
SEEDED_MAX_LENGTH = 1500

HEADER = bytes(
    [0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02, 0x08, 0x00]
)

EM_BPF = 247
ET_REL = 1
SHT_REL = 9
R_BPF_64_64 = 1
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
BPF_ALU64_MOV_IMM = 0xB4
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
C_MAP_SYMBOL = "counter_maps"


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


def lcg_next(state):
    return (LCG_A * state + LCG_C) % LCG_M


def generate_seeded():
    """Deterministically build the 32 seeded (name, bytes) frames.

    A hand-rolled generator (no stdlib random) so the bytes are
    identical on every interpreter: three fixed boundary lengths
    first, then lengths across the full envelope, a chosen byte 14
    on every long frame, and generator-chosen fill in every other
    payload byte (the rule must ignore those bytes).
    """
    frames = []
    state = SEED

    def take_byte():
        nonlocal state
        state = lcg_next(state)
        return (state >> 16) & 0xFF

    for index in range(N_SEEDED):
        if index < len(SEEDED_FIXED_LENGTHS):
            length = SEEDED_FIXED_LENGTHS[index]
        else:
            state = lcg_next(state)
            length = SEEDED_MIN_LENGTH + (
                state % (SEEDED_MAX_LENGTH - SEEDED_MIN_LENGTH + 1)
            )
        frame = bytearray(length)
        frame[:14] = HEADER
        if length >= 15:
            frame[14] = take_byte()
            for pos in range(15, length):
                frame[pos] = take_byte()
        name = "s%02d_%04d.bin" % (index, length)
        frames.append((name, bytes(frame)))
    return frames


def action_oracle(frame):
    """Independent rule prediction (modulo, never masking)."""
    if len(frame) < 15:
        return 2
    if (frame[14] % 2) == 1:
        return 1
    return 2


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def load_spec_corpus():
    """Read and verify the fixed corpus; return [(name, bytes)]."""
    if not os.path.isfile(SPEC_MANIFEST):
        raise EnvironmentFailure("missing manifest: %s" % SPEC_MANIFEST)
    with open(SPEC_MANIFEST, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["totals"] == {
        "invocations": 33,
        "drops": 16,
        "passes": 17,
        "bytes": 9590,
    }, "spec manifest totals changed: %r" % (manifest["totals"],)
    frames = []
    for entry in manifest["frames"]:
        path = os.path.join(CORPUS_DIR, entry["file"])
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing frame: %s" % path)
        with open(path, "rb") as handle:
            raw = handle.read()
        assert len(raw) == entry["length"], (
            "%s: length %d, manifest says %d"
            % (entry["file"], len(raw), entry["length"])
        )
        assert sha256_bytes(raw) == entry["sha256"], (
            "%s: bytes do not match the manifest hash" % entry["file"]
        )
        assert action_oracle(raw) == entry["action"], (
            "%s: oracle says %d, manifest says %d"
            % (entry["file"], action_oracle(raw), entry["action"])
        )
        frames.append((entry["file"], raw))
    assert len(frames) == 33, "spec corpus holds %d frames" % len(frames)
    drops = sum(1 for _, raw in frames if action_oracle(raw) == 1)
    total = sum(len(raw) for _, raw in frames)
    assert (drops, total) == (16, 9590), (drops, total)
    return frames


def load_seeded_frames(workdir):
    """Regenerate seeded frames; verify against the pinned manifest."""
    if not os.path.isfile(SEEDED_MANIFEST):
        raise EnvironmentFailure("missing manifest: %s" % SEEDED_MANIFEST)
    with open(SEEDED_MANIFEST, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert manifest["seed"] == SEED, "seeded manifest seed changed"
    assert manifest["count"] == N_SEEDED, "seeded manifest count changed"
    generated = generate_seeded()
    pinned = {entry["name"]: entry for entry in manifest["frames"]}
    assert len(pinned) == N_SEEDED, "seeded manifest holds %d" % len(pinned)
    frames = []
    for name, raw in generated:
        assert name in pinned, "generated frame %s is not pinned" % name
        entry = pinned[name]
        assert len(raw) == entry["length"], (
            "%s: length %d, manifest says %d"
            % (name, len(raw), entry["length"])
        )
        assert sha256_bytes(raw) == entry["sha256"], (
            "%s: regenerated bytes do not match the pinned hash" % name
        )
        assert action_oracle(raw) == entry["action"], (
            "%s: oracle says %d, manifest says %d"
            % (name, action_oracle(raw), entry["action"])
        )
        path = os.path.join(workdir, name)
        with open(path, "wb") as handle:
            handle.write(raw)
        frames.append((name, raw))
    assert len({name for name, _ in generated}) == N_SEEDED
    return frames


def minimize(frame):
    """Shrink a frame to its minimal same-verdict form.

    Long frames shrink to the 15-byte header-plus-tested-byte form;
    short frames shrink to the 14-byte header. The oracle verdict
    must survive minimization or the minimizer itself is wrong.
    """
    action = action_oracle(frame)
    if len(frame) < 15:
        minimal = HEADER
    else:
        minimal = HEADER + bytes([frame[14]])
    assert action_oracle(minimal) == action, (
        "minimizer changed the verdict for a %d-byte frame" % len(frame)
    )
    assert len(minimal) <= len(frame)
    return minimal


def load_regressions():
    """Read committed regressions; each must equal minimize(parent).

    The manifest maps every regression file to its seeded parent;
    the parents regenerate deterministically, so this check proves
    the minimizer reproduces the committed minima byte-identically.
    """
    manifest_path = os.path.join(REGRESSION_DIR, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise EnvironmentFailure("missing manifest: %s" % manifest_path)
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    by_name = dict(generate_seeded())
    frames = []
    for entry in manifest["frames"]:
        parent = by_name.get(entry["parent"])
        assert parent is not None, (
            "regression parent missing: %s" % entry["parent"]
        )
        expected = minimize(parent)
        path = os.path.join(REGRESSION_DIR, entry["file"])
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing regression: %s" % path)
        with open(path, "rb") as handle:
            raw = handle.read()
        assert raw == expected, (
            "%s: committed bytes differ from minimize(%s)"
            % (entry["file"], entry["parent"])
        )
        assert sha256_bytes(raw) == entry["sha256"]
        assert action_oracle(raw) == entry["action"]
        frames.append((entry["file"], raw))
    assert frames, "no regressions pinned"
    return frames


def build_probe(probe_source, workdir):
    if shutil.which("mojo") is None:
        raise EnvironmentFailure("mojo not found on PATH")
    if not os.path.isfile(probe_source):
        raise EnvironmentFailure("missing probe: %s" % probe_source)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK dir: %s" % SDK_INCLUDE)
    binary = os.path.join(workdir, "packets_probe")
    proc = run_step(
        ["mojo", "build", "-I", SDK_INCLUDE, "-o", binary, probe_source]
    )
    if proc.returncode != 0 or not os.path.isfile(binary):
        raise AssertionError(
            "probe build failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "probe build reported diagnostics:\n%s" % proc.stderr
        )
    return binary


def run_probe(binary, paths):
    """Run the probe over paths; return {path: (action, count, bytes)}."""
    proc = run_step([binary] + list(paths))
    if proc.returncode != 0:
        raise AssertionError(
            "probe exited %d:\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    results = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        assert parts and parts[0] == "FRAME", (
            "unexpected probe line: %r" % line
        )
        assert len(parts) == 5, "malformed probe line: %r" % line
        _, path, action, count, cumbytes = parts
        assert path not in results, "probe repeated %s" % path
        results[path] = (int(action), int(count), int(cumbytes))
    missing = [path for path in paths if path not in results]
    assert not missing, "probe skipped %d frame(s)" % len(missing)
    return results


def check_corpus(tag, frames, staged_paths, results):
    """Compare every probe line with the oracle; return mismatches."""
    mismatches = []
    count = 0
    cumbytes = 0
    for (name, raw), path in zip(frames, staged_paths):
        count += 1
        cumbytes += len(raw)
        expected = (action_oracle(raw), count, cumbytes)
        observed = results[path]
        if observed != expected:
            mismatches.append(
                "MISMATCH %s %s: probe=%r oracle=%r"
                % (tag, name, observed, expected)
            )
    return mismatches, len(frames)


_CACHED = {}


def executed(probe_source=None):
    """Build the probe once; run the whole corpus; cache the outcome."""
    key = probe_source or PROBE_SOURCE
    if key not in _CACHED:
        workdir = tempfile.mkdtemp(prefix="mojo-packets-")
        spec = load_spec_corpus()
        seeded = load_seeded_frames(workdir)
        regressions = load_regressions()
        staged = []
        for name, raw in seeded:
            staged.append(os.path.join(workdir, name))
        reg_staged = []
        for name, raw in regressions:
            path = os.path.join(workdir, name)
            with open(path, "wb") as handle:
                handle.write(raw)
            reg_staged.append(path)
        spec_paths = [os.path.join(CORPUS_DIR, name) for name, _ in spec]
        binary = build_probe(key, workdir)
        mismatches = []
        total = 0
        for tag, frames, paths in (
            ("spec", spec, spec_paths),
            ("seeded", seeded, staged),
            ("regression", regressions, reg_staged),
        ):
            # Running totals restart per group: each group is an
            # independent differential run over shared probe lines.
            group_results = run_probe(binary, paths)
            found, count = check_corpus(tag, frames, paths, group_results)
            mismatches.extend(found)
            total += count
        _CACHED[key] = {
            "probe": key,
            "binary": binary,
            "mismatches": mismatches,
            "total": total,
            "spec": len(spec),
            "seeded": len(seeded),
            "regressions": len(regressions),
        }
    return _CACHED[key]


def parse_elf(image):
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
    (e_type, e_machine, _e_version) = struct.unpack_from("<HHI", image, 16)
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, _flags, _addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        (sh_link, sh_info) = struct.unpack_from("<II", image, off + 40)
        sections.append(
            {
                "index": index,
                "name_off": sh_name,
                "type": sh_type,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
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
        if section["type"] != 2:  # SHT_SYMTAB
            continue
        count = section["size"] // 24
        strsec = sections[section["link"]]
        strblob = image[
            strsec["offset"]:strsec["offset"] + strsec["size"]
        ]
        for ordinal in range(count):
            off = section["offset"] + ordinal * 24
            (st_name,) = struct.unpack_from("<I", image, off)
            end = strblob.index(b"\x00", st_name)
            symbols.append(strblob[st_name:end].decode("ascii"))
    return {"type": e_type, "machine": e_machine,
            "sections": sections, "symbols": symbols}


def section_bytes(image, section):
    return bytes(image[section["offset"]:section["offset"] + section["size"]])


def build_c_reference(workdir):
    if shutil.which("clang") is None:
        raise EnvironmentFailure("clang not found on PATH")
    if not os.path.isfile(C_SOURCE):
        raise EnvironmentFailure("missing C source: %s" % C_SOURCE)
    object_path = os.path.join(workdir, "xdp_counter_ref.bpf.o")
    proc = run_step(
        ["clang", "--target=bpf", "-O2", "-g", "-c",
         C_SOURCE, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "C reference build failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if "warning:" in proc.stderr.lower() or "error:" in proc.stderr.lower():
        raise AssertionError(
            "C reference build reported diagnostics:\n%s" % proc.stderr
        )
    with open(object_path, "rb") as handle:
        return object_path, handle.read()


def check_c_structure(image):
    """Pin the C reference's structure; return a fact summary."""
    elf = parse_elf(image)
    assert elf["type"] == ET_REL, "C object must be relocatable"
    assert elf["machine"] == EM_BPF, "C object must be EM_BPF"
    by_name = {section["name"]: section for section in elf["sections"]}
    for name in ("xdp", ".maps", ".BTF", "license", ".relxdp"):
        assert name in by_name, "C object lacks %s" % name
    assert section_bytes(image, by_name["license"]) == LICENSE_BYTES
    code = section_bytes(image, by_name["xdp"])
    assert len(code) % 8 == 0 and code, "xdp code is not whole insns"
    helpers = []
    exits = 0
    actions = set()
    for off in range(0, len(code), 8):
        opcode = code[off]
        if opcode == BPF_OP_CALL:
            (imm,) = struct.unpack_from("<i", code, off + 4)
            helpers.append(imm)
        elif opcode == BPF_OP_EXIT:
            exits += 1
        elif opcode == BPF_ALU64_MOV_IMM and (code[off + 1] & 0x0F) == 6:
            (imm,) = struct.unpack_from("<i", code, off + 4)
            actions.add(imm)
    assert helpers == [1, 1, 2, 2], (
        "C helpers must be two lookups then two updates, got %r" % helpers
    )
    assert exits == 1, "C program must hold exactly one exit"
    assert actions == {1, 2}, (
        "C action register must spell exactly {1, 2}, got %r" % (actions,)
    )
    relsec = by_name[".relxdp"]
    rels = section_bytes(image, relsec)
    assert len(rels) % 16 == 0
    entries = []
    for off in range(0, len(rels), 16):
        (_r_offset, r_info) = struct.unpack_from("<QQ", rels, off)
        entries.append((r_info & 0xFFFFFFFF, r_info >> 32))
    names = [
        elf["symbols"][sym] for (_typ, sym) in entries
    ]
    assert len(entries) == 4, (
        "C object must carry 4 code relocations, got %d" % len(entries)
    )
    assert all(typ == R_BPF_64_64 for typ, _ in entries), entries
    assert all(name == C_MAP_SYMBOL for name in names), names
    return {"helpers": helpers, "actions": sorted(actions)}


def check_c_btf(object_path):
    if shutil.which("bpftool") is None:
        raise EnvironmentFailure("bpftool not found on PATH")
    proc = run_step(["bpftool", "btf", "dump", "file", object_path])
    assert proc.returncode == 0, (
        "bpftool rejected the C BTF:\n%s\n%s" % (proc.stdout, proc.stderr)
    )
    for token in (
        "STRUCT 'counter_map_def'",
        "'type'",
        "'max_entries'",
        "'key'",
        "'value'",
        "VAR 'counter_maps'",
        "DATASEC '.maps'",
    ):
        assert token in proc.stdout, "C BTF lacks %s" % token
    struct = re.search(
        r"STRUCT 'counter_map_def'.*?"
        r"'type' type_id=(\d+).*?'max_entries' type_id=(\d+)",
        proc.stdout, re.DOTALL,
    )
    assert struct, "C BTF lacks the typed map-definition struct"
    assert struct.group(1) == struct.group(2), (
        "type and max_entries must share one array type, got %s and %s"
        % (struct.group(1), struct.group(2))
    )
    shared = re.search(
        r"\[%s\] PTR '\(anon\)' type_id=(\d+)" % struct.group(1),
        proc.stdout,
    )
    assert shared, "C BTF lacks the shared map-field pointer"
    array = re.search(
        r"\[%s\] ARRAY '\(anon\)' type_id=\d+ index_type_id=\d+ "
        r"nr_elems=(\d+)" % shared.group(1),
        proc.stdout,
    )
    assert array and array.group(1) == "2", (
        "C BTF must pin the array kind and the two entries"
    )


def test_probe_matches_oracle_on_spec_corpus():
    run = executed()
    spec_bad = [line for line in run["mismatches"] if "MISMATCH spec" in line]
    assert not spec_bad, "\n".join(spec_bad)
    assert run["spec"] == 33
    print("PASS spec corpus: 33/33 probe lines match the oracle")


def test_probe_matches_oracle_on_seeded_frames():
    run = executed()
    seeded_bad = [
        line for line in run["mismatches"] if "MISMATCH seeded" in line
    ]
    assert not seeded_bad, "\n".join(seeded_bad)
    assert run["seeded"] == N_SEEDED
    print(
        "PASS seeded corpus: %d/%d probe lines match the oracle"
        % (N_SEEDED, N_SEEDED)
    )


def test_probe_matches_oracle_on_regressions():
    run = executed()
    reg_bad = [
        line for line in run["mismatches"]
        if "MISMATCH regression" in line
    ]
    assert not reg_bad, "\n".join(reg_bad)
    assert run["regressions"] >= 1
    print(
        "PASS regressions: %d/%d probe lines match the oracle"
        % (run["regressions"], run["regressions"])
    )


def test_minimizer_self_check():
    long = HEADER + bytes([7]) + bytes(85)
    assert minimize(long) == HEADER + bytes([7])
    assert minimize(HEADER) == HEADER
    assert minimize(bytes(14)) == HEADER
    print("PASS minimizer shrinks synthetic frames to the pinned minima")


def test_c_reference_structure():
    workdir = tempfile.mkdtemp(prefix="mojo-packets-c-")
    object_path, image = build_c_reference(workdir)
    facts = check_c_structure(image)
    check_c_btf(object_path)
    assert facts == {"helpers": [1, 1, 2, 2], "actions": [1, 2]}
    print("PASS C reference structure pinned (helpers/actions/relocs/BTF)")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Differential proof for the packet corpus."
    )
    parser.add_argument(
        "--probe-source", default=PROBE_SOURCE,
        help="probe Mojo source (default: the committed probe)",
    )
    args = parser.parse_args(argv)
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    names = sorted(k for k in globals() if k.startswith("test_"))
    if args.probe_source != PROBE_SOURCE:
        try:
            run = executed(args.probe_source)
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE: %s" % exc)
            return 2
        for line in run["mismatches"]:
            print(line)
        print(
            "packets differential (%s): %d mismatches of %d lines"
            % (args.probe_source, len(run["mismatches"]), run["total"])
        )
        return 1 if run["mismatches"] else 0
    failures = 0
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
    run = executed()
    print(
        "packets differential: %d/%d probe lines match the oracle "
        "(spec %d, seeded %d, regressions %d)"
        % (run["total"], run["total"], run["spec"],
           run["seeded"], run["regressions"])
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
