# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/mem/pseudo-imm64: pseudo-reference encoding pins (ISA-01).

Oracle pseudo-reference emission (pinned llc 22.1.8, recorded at
RED, verified by decoding before pinning): every map/data/ksym
reference shape lowers to the 0x18 pair with src_reg 0 plus an
R_BPF_64_64 relocation — the pseudo kind is a loader rewrite.
The NO-PSEUDO-SRC pin guards that llc never writes a kinded
word on v3. Audit companions pin the existing input-global and
producer-model rules. See the leaf packet for the frozen vector
list.
"""
import struct

import pytest

from test_isa_cpu import (
    check_cpu,
    llc,
)
from test_target_model import (
    ROOT,
    module,
    refusal,
)

PSEUDO_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "pseudo" / "oracle-pseudo.ll"

R_BPF_64_64 = 1

# Pinned oracle pseudo words + reloc tuples, one entry per corpus
# function index (observed at RED, decode-verified by hand: the
# 0x18 pair shape, consumer words, and (offset, type, symbol)
# relocation records).
FUNC_WORDS = {
    # callarg: key slot [r10-8] = 0, key pointer into r2,
    # relocated ld_imm64 into r1 (slot 4), call 1.
    "pseudo_fd_callarg": [439, 4294449787, 41663,
                          18446744039349813767, 280, 0,
                          4294967429, 149],
    # direct: relocated ld_imm64 (slot 0) + LDXDW [r1+0].
    "pseudo_fd_direct": [280, 0, 4217, 149],
    # field: relocated ld_imm64 (slot 0) + LDXDW [r1+16];
    # the GEP offset lives in the consumer, not the pair.
    "pseudo_field_offset": [280, 0, 1052793, 149],
    # data: same pair shape against the .data global.
    "pseudo_data": [280, 0, 4217, 149],
    # ksym: same pair shape against the .ksyms extern.
    "pseudo_ksym": [280, 0, 4217, 149],
}
# Per-function (slot, reloc type, symbol) tuples: every pair
# site carries exactly one R_BPF_64_64 against its global.
FUNC_RELOCS = {
    "pseudo_fd_callarg": [(4, 1, "map0")],
    "pseudo_fd_direct": [(0, 1, "map0")],
    "pseudo_field_offset": [(0, 1, "mapstruct")],
    "pseudo_data": [(0, 1, "gvar")],
    "pseudo_ksym": [(0, 1, "ksym0")],
}
FUNC_ORDER = list(FUNC_WORDS)


def _oracle_pseudo_object(tmp_path):
    out = tmp_path / "pseudo.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  PSEUDO_CORPUS, "-o", out])
    assert result.returncode == 0, result.stderr
    return out


def _elf_sections(path):
    with open(path, "rb") as handle:
        data = handle.read()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    sections = {}
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        sections[data[base + row[0]:end].decode()] = row
    return data, sections


def _section_words(path, section):
    data, sections = _elf_sections(path)
    row = sections[section]
    text = data[row[4]:row[4] + row[5]]
    assert len(text) % 8 == 0
    return [word for (word,) in struct.iter_unpack("<Q", text)]


def _relocs(path, rel_section):
    # Elf64_Rel entries (r_offset u64, r_info u64) resolved
    # against .symtab/.strtab: (offset, type, symbol) tuples.
    data, sections = _elf_sections(path)
    row = sections[rel_section]
    blob = data[row[4]:row[4] + row[5]]
    assert len(blob) % 16 == 0
    symtab = sections[".symtab"]
    strtab = sections[".strtab"]
    syms = data[symtab[4]:symtab[4] + symtab[5]]
    strings = data[strtab[4]:strtab[4] + strtab[5]]
    assert len(syms) % 24 == 0
    entries = []
    for index in range(len(syms) // 24):
        st_name = struct.unpack_from("<I", syms, index * 24)[0]
        end = strings.index(b"\x00", st_name)
        entries.append(strings[st_name:end].decode())
    relocs = []
    for (offset, info) in struct.iter_unpack("<QQ", blob):
        relocs.append((offset, info & 0xFFFFFFFF,
                       entries[info >> 32]))
    return relocs


def _split_funcs(words):
    funcs, current = [], []
    for word in words:
        current.append(word)
        if word & 0xFF == 0x95:
            funcs.append(current)
            current = []
    assert not current, "trailing words after the last exit"
    return funcs


def _func_relocs(words, relocs):
    # Attribute each .text relocation to its function by byte
    # offset: per-function (slot, type, symbol) tuples.
    bounds, start = [], 0
    for func in _split_funcs(words):
        bounds.append((start, start + len(func) * 8))
        start += len(func) * 8
    grouped = [[] for _ in bounds]
    for offset, rtype, sym in relocs:
        for index, (low, high) in enumerate(bounds):
            if low <= offset < high:
                grouped[index].append(((offset - low) // 8,
                                       rtype, sym))
                break
        else:
            raise AssertionError(
                "relocation outside .text functions: %r"
                % ((offset, rtype, sym),))
    return grouped


@pytest.mark.parametrize("name", FUNC_ORDER)
def test_pseudo_oracle_emission(tmp_path, name):
    obj = _oracle_pseudo_object(tmp_path)
    words = _section_words(obj, ".text")
    funcs = _split_funcs(words)
    assert len(funcs) == 5, "corpus function count moved"
    index = FUNC_ORDER.index(name)
    assert funcs[index][-1] == 0x95
    pairs = [slot for slot, word in enumerate(funcs[index])
             if word & 0xFF == 0x18]
    assert pairs, "pseudo shape %s must carry an ld_imm64 pair" % name
    assert funcs[index] == FUNC_WORDS[name]
    relocs = _func_relocs(
        words, _relocs(obj, ".rel.text"))
    assert relocs[index] == FUNC_RELOCS[name]
    assert pairs == [slot for slot, _, _ in relocs[index]], (
        "every pair site in %s must be relocated" % name)


def test_pseudo_oracle_no_pseudo_src(tmp_path):
    # The pseudo kind is a loader rewrite: llc must not write a
    # kinded 0x18 word on v3. Re-verified at RED; a kinded word
    # here would pin instead and force a packet amendment.
    words = _section_words(_oracle_pseudo_object(tmp_path),
                           ".text")
    assert not [word for word in words
                if word & 0xFF == 0x18 and (word >> 12) & 0xF]


def test_pseudo_admit_baseline(tmp_path):
    # The bare scaffold must be admitted: without this anchor,
    # every refusal below could be blamed on broken scaffolding.
    result, report = check_cpu(tmp_path, module(), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


@pytest.mark.parametrize("declaration,code,message", [
    ('@m = dso_local global i64 0, section ".maps", align 8\n',
     "MBPF309", "input globals/aliases/ifuncs"),
    ('@g = dso_local global i64 42, section ".data", align 8\n',
     "MBPF309", "input globals/aliases/ifuncs"),
    ('@k = external dso_local global i64, section ".ksyms", align 8\n',
     "MBPF309", "input globals/aliases/ifuncs"),
    ("declare i64 @llvm.bpf.pseudo(i64, i64)\n",
     "MBPF319", "frozen producer model"),
    ("declare i64 @some_helper(i64)\n",
     "MBPF303", "unreserved declaration"),
])
def test_pseudo_refused_input_shapes(tmp_path, declaration, code,
                                     message):
    result, report = check_cpu(
        tmp_path, module(declarations=declaration), "v3")
    refusal(result, report, code)
    assert message in report["diagnostics"][0]["explanation"]
