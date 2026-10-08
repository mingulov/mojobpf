# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Contract checks for the array map SDK slice.

Builds ``tests/compile/maps_roundtrip_named.mojo`` through the genuine
pipeline (``mojo build --emit llvm`` with the packaged SDK on the
import path -> ``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel
-mcpu=v3``) and asserts the map contract the kernel suites rely on:

* the named-flags spelling (``BPF_ANY``) lowers to the exact canonical
  map shape: the frozen audit validates both sources as the ``map``
  count vector, and the adapted IR is byte-identical modulo the
  module-identity comment lines;
* the named object is a conventional BPF relocatable whose ``xdp``
  code holds exactly one lookup call (helper 1) and one update call
  (helper 2) plus an exit, whose ``.maps``/``.BTF`` bytes equal the
  canonical object's (one-entry array, u32 key, u64 value), and whose
  map BTF dump is accepted by unmodified ``bpftool``;
* exactly one map symbol is declared and no other map kind is
  emitted anywhere in the image;
* the out-of-bounds fixture keeps the identical declared layout but
  differs in code bytes, pinning the mismatch the kernel loader
  rejects (the loader half of that proof lives in
  ``tests/kernel/test_array_maps.py``);
* every genuine-frontend negative is refused by the adapter with its
  exact named code: nonzero update flags (``MBPF314``), delete and
  iteration-step attempts (``MBPF303``), and a lone key-1 slot
  outside the combined shape (``MBPF307``, naming the combined
  count vector key 1 belongs to). Unsupported map kinds (hash,
  LRU, map-in-map, ``PROG_ARRAY``) are refused earlier, at manifest
  validation with ``MBPF205`` (see ``tests/unit/test_manifest.py``).

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool`` on PATH.
A missing tool is reported as an environment failure; a failing
frontend, adapter, or backend step is a proof failure. Neither ever
passes.

Runnable directly (``python3 tests/elf/test_map_contract.py``) or under
any ``test_``-style runner. Standard library only.
"""

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
COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
import audit  # noqa: E402

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
STB_GLOBAL = 1
STT_OBJECT = 1
BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
MAP_SYMBOL = "mojobpf_map0"

NAMED_SHAPE = "maps_roundtrip_named"
CANONICAL_SHAPE = "map_roundtrip"
OOB_SHAPE = "map_oob"

# Negative fixture -> exact audit code. Each source passes the Mojo
# frontend; the adapter must refuse it with exit 1, no output, and the
# named code on stderr.
NEGATIVES = {
    "maps_update_noexist": "MBPF314",
    "maps_update_exist": "MBPF314",
    "maps_hash_noexist": "MBPF314",
    "maps_delete_attempt": "MBPF303",
    "maps_nextkey_attempt": "MBPF303",
    "maps_getnext_attempt": "MBPF303",
    "maps_nonzero_key": "MBPF307",
}

IDENTITY_LINES = ("; ModuleID = ", "source_filename = ")


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
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def mojo_emit(source, raw_path):
    return run_step(
        [
            "mojo",
            "build",
            "--emit",
            "llvm",
            "-I",
            SDK_INCLUDE,
            "-o",
            raw_path,
            source,
        ]
    )


def build_shape(name):
    """Run the genuine three-step build; return (raw_ir, adapted, image)."""
    source = os.path.join(COMPILE_DIR, name + ".mojo")
    if not os.path.isfile(source):
        raise EnvironmentFailure("missing fixture: %s" % source)
    workdir = tempfile.mkdtemp(prefix="mojo-map-contract-")
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = mojo_emit(source, raw_path)
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend reported diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    with open(raw_path, "r", encoding="utf-8") as handle:
        raw_ir = handle.read()
    try:
        mode = audit.validate(raw_ir)
    except audit.AuditError as exc:
        raise AssertionError(
            "frozen audit rejected %s: %s" % (source, exc)
        )
    assert mode == "map", (
        "%s must validate as the map shape, got %r" % (source, mode)
    )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            adapted_path,
            "-o",
            object_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    with open(adapted_path, "r", encoding="utf-8") as handle:
        adapted = handle.read()
    with open(object_path, "rb") as handle:
        image = handle.read()
    return raw_ir, adapted, image


_CACHED = {}


def built(name):
    if name not in _CACHED:
        check_tools("mojo", "llc")
        if not os.path.isdir(SDK_INCLUDE):
            raise EnvironmentFailure("missing SDK dir: %s" % SDK_INCLUDE)
        if not os.path.isfile(ADAPTER):
            raise EnvironmentFailure("missing adapter: %s" % ADAPTER)
        _CACHED[name] = build_shape(name)
    return _CACHED[name]


def strip_identity(text):
    """Drop module-identity comment lines (source file names)."""
    kept = []
    for line in text.splitlines():
        if line.startswith(IDENTITY_LINES):
            continue
        kept.append(line)
    return "\n".join(kept) + "\n"


def parse_elf(image):
    """Parse headers/sections/symbols; return string-keyed facts."""
    if image[:4] != b"\x7fELF":
        raise AssertionError("missing ELF magic")
    (e_type, e_machine, _e_version) = struct.unpack_from("<HHI", image, 16)
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, sh_type, sh_flags, _sh_addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        (sh_link,) = struct.unpack_from("<I", image, off + 40)
        sections.append(
            {
                "index": index,
                "name_off": sh_name,
                "type": sh_type,
                "flags": sh_flags,
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
        count = section["size"] // 24
        strsec = sections[section["link"]]
        strblob = image[
            strsec["offset"]:strsec["offset"] + strsec["size"]
        ]
        for ordinal in range(count):
            off = section["offset"] + ordinal * 24
            (st_name, st_info, _other, st_shndx, _value, _size) = (
                struct.unpack_from("<IBBHQQ", image, off)
            )
            end = strblob.index(b"\x00", st_name)
            symbols.append(
                {
                    "name": strblob[st_name:end].decode("ascii"),
                    "bind": st_info >> 4,
                    "type": st_info & 0xF,
                    "shndx": st_shndx,
                }
            )
    return {
        "type": e_type,
        "machine": e_machine,
        "sections": sections,
        "symbols": symbols,
    }


def section_bytes(image, section):
    return bytes(image[section["offset"]:section["offset"] + section["size"]])


def helper_calls(code):
    """Return the helper IDs of every call in xdp code."""
    found = []
    for off in range(0, len(code), 8):
        opcode = code[off]
        if opcode == BPF_OP_CALL:
            (imm,) = struct.unpack_from("<i", code, off + 4)
            found.append(imm)
    return found


def check_negative(name, code):
    """Pin one genuine-frontend refusal to its exact audit code."""
    check_tools("mojo")
    source = os.path.join(COMPILE_DIR, name + ".mojo")
    if not os.path.isfile(source):
        raise EnvironmentFailure("missing fixture: %s" % source)
    workdir = tempfile.mkdtemp(prefix="mojo-map-neg-")
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    proc = mojo_emit(source, raw_path)
    assert proc.returncode == 0 and os.path.isfile(raw_path), (
        "the Mojo frontend must accept %s (rejection belongs to the "
        "adapter), got exit %d:\n%s\n%s"
        % (source, proc.returncode, proc.stdout, proc.stderr)
    )
    proc = run_step(
        [
            sys.executable,
            ADAPTER,
            "--input",
            raw_path,
            "--output",
            adapted_path,
        ]
    )
    assert proc.returncode == 1, (
        "%s: adapter must reject with exit 1, got %d"
        % (name, proc.returncode)
    )
    assert "[%s]" % code in (proc.stderr or ""), (
        "%s: adapter must report [%s], got:\n%s" % (name, code, proc.stderr)
    )
    assert not os.path.isfile(adapted_path), (
        "%s: adapter must not emit output for rejected input" % name
    )


def test_named_spelling_matches_canonical():
    _, named_adapted, _ = built(NAMED_SHAPE)
    _, canonical_adapted, _ = built(CANONICAL_SHAPE)
    assert strip_identity(named_adapted) == strip_identity(
        canonical_adapted
    ), "named-flags IR must match the canonical map IR"
    assert "inttoptr (i64 1 to ptr)" in named_adapted, (
        "named build must lower the lookup call"
    )
    assert "inttoptr (i64 2 to ptr)" in named_adapted, (
        "named build must lower the update call"
    )
    assert "__mojobpf_" not in named_adapted, (
        "no pseudo-call reference may survive lowering"
    )


def test_named_object_helpers_and_layout():
    _, _, image = built(NAMED_SHAPE)
    elf = parse_elf(image)
    assert elf["type"] == ET_REL, "object must be relocatable"
    assert elf["machine"] == EM_BPF, "object must target EM_BPF"
    by_name = {s["name"]: s for s in elf["sections"]}
    assert "xdp" in by_name, "missing xdp section"
    assert "license" in by_name, "missing license section"
    assert ".maps" in by_name, "missing .maps section"
    assert ".BTF" in by_name, "missing .BTF section"
    assert by_name["xdp"]["flags"] & SHF_EXECINSTR, "xdp must be executable"
    assert LICENSE_BYTES in section_bytes(image, by_name["license"]), (
        "license bytes must be exact"
    )
    code = section_bytes(image, by_name["xdp"])
    assert helper_calls(code) == [1, 2], (
        "expected exactly [lookup, update] helper calls, got %r"
        % helper_calls(code)
    )
    assert BPF_OP_EXIT in code, "xdp code has no exit instruction"


def test_single_map_symbol_and_shared_declaration():
    _, _, named_image = built(NAMED_SHAPE)
    _, _, canonical_image = built(CANONICAL_SHAPE)
    named = parse_elf(named_image)
    canonical = parse_elf(canonical_image)
    for label, elf, image in (
        ("named", named, named_image),
        ("canonical", canonical, canonical_image),
    ):
        matches = [s for s in elf["symbols"] if s["name"] == MAP_SYMBOL]
        assert len(matches) == 1, (
            "%s: expected one %s symbol" % (label, MAP_SYMBOL)
        )
        sym = matches[0]
        by_name = {s["name"]: s for s in elf["sections"]}
        maps = by_name[".maps"]
        assert sym["type"] == STT_OBJECT and sym["shndx"] == maps["index"], (
            "%s: %s must be an object in .maps" % (label, MAP_SYMBOL)
        )
        assert sym["bind"] == STB_GLOBAL, (
            "%s: %s must be global" % (label, MAP_SYMBOL)
        )
        others = [
            s
            for s in elf["symbols"]
            if s["name"].startswith("mojobpf_map") and s["name"] != MAP_SYMBOL
        ]
        assert not others, (
            "%s: unexpected extra map symbols %r" % (label, others)
        )
    named_sections = {s["name"]: s for s in named["sections"]}
    canonical_sections = {s["name"]: s for s in canonical["sections"]}
    for section in (".maps", ".BTF"):
        assert section_bytes(named_image, named_sections[section]) == (
            section_bytes(canonical_image, canonical_sections[section])
        ), "%s bytes must match the canonical declaration" % section


def test_btf_accepted_by_bpftool():
    check_tools("bpftool")
    _, _, image = built(NAMED_SHAPE)
    workdir = tempfile.mkdtemp(prefix="mojo-map-contract-btf-")
    object_path = os.path.join(workdir, "maps_named.bpf.o")
    with open(object_path, "wb") as handle:
        handle.write(image)
    proc = run_step(["bpftool", "btf", "dump", "file", object_path])
    assert proc.returncode == 0, "bpftool btf dump failed:\n%s" % proc.stderr
    assert "VAR '%s'" % MAP_SYMBOL in proc.stdout, (
        "bpftool dump lacks the map VAR:\n%s" % proc.stdout
    )
    assert "DATASEC '.maps'" in proc.stdout, (
        "bpftool dump lacks DATASEC '.maps':\n%s" % proc.stdout
    )


def test_oob_keeps_layout_but_differs_in_code():
    _, _, oob_image = built(OOB_SHAPE)
    _, _, canonical_image = built(CANONICAL_SHAPE)
    oob = parse_elf(oob_image)
    canonical = parse_elf(canonical_image)
    oob_sections = {s["name"]: s for s in oob["sections"]}
    canonical_sections = {s["name"]: s for s in canonical["sections"]}
    for section in (".maps", ".BTF"):
        assert section_bytes(oob_image, oob_sections[section]) == (
            section_bytes(canonical_image, canonical_sections[section])
        ), "oob %s must keep the declared layout" % section
    oob_code = section_bytes(oob_image, oob_sections["xdp"])
    canonical_code = section_bytes(
        canonical_image, canonical_sections["xdp"]
    )
    assert oob_code != canonical_code, (
        "oob code must differ from the in-bounds access"
    )
    assert helper_calls(oob_code) == [1, 2], (
        "oob object must keep the [lookup, update] call shape, got %r"
        % helper_calls(oob_code)
    )


def test_no_foreign_helper_or_map_kind_emitted():
    _, adapted, image = built(NAMED_SHAPE)
    lowered = re.findall(
        r"inttoptr \(i64 (\d+) to ptr\)", adapted
    )
    assert lowered == ["1", "2"], (
        "the one-entry round-trip shape lowers helpers 1 and 2, "
        "got %r" % lowered
    )
    text = image.decode("latin-1")
    for kind in ("percpu", "PERCPU", "lru_hash", "array_of_maps",
                 "hash_of_maps", "prog_array", "LRU", "HASH"):
        assert kind not in text, (
            "unqualified map kind %r must not appear in the image" % kind
        )


def test_update_noexist_refused():
    check_negative("maps_update_noexist", NEGATIVES["maps_update_noexist"])


def test_update_exist_refused():
    check_negative("maps_update_exist", NEGATIVES["maps_update_exist"])


def test_hash_update_noexist_refused():
    check_negative("maps_hash_noexist", NEGATIVES["maps_hash_noexist"])


def test_delete_attempt_refused():
    check_negative("maps_delete_attempt", NEGATIVES["maps_delete_attempt"])


def test_nextkey_attempt_refused():
    check_negative("maps_nextkey_attempt", NEGATIVES["maps_nextkey_attempt"])


def test_getnext_attempt_refused():
    check_negative("maps_getnext_attempt", NEGATIVES["maps_getnext_attempt"])


def test_nonzero_key_refused():
    check_negative("maps_nonzero_key", NEGATIVES["maps_nonzero_key"])


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
    print("map contract: named spelling, layout and refusal checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
