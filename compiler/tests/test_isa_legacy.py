# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/legacy/refusal: cBPF loads are absent and stay absent.

Legacy loads (LD_ABS/LD_IND/LD_LEN/LDX_MSH) have no lowering
rule and no llc selection path on the v3 XDP profile: the
pinned backend emits zero legacy-mode words for every
committed corpus (absence guard), and both lanes' XDP
verifiers reject hand-assembled legacy words (live Q legs in
kernel-isa-legacy). This suite pins the UAPI modes, the
word recognizer, the per-corpus zero counts, and the four
committed probe words. See the leaf packet for the frozen
vector list.
"""
import struct

from test_isa_cpu import (
    llc,
)
from test_target_model import (
    CASES,
    ROOT,
    digest,
    run,
)

LEGACY_FIX = ROOT / "tests" / "fixtures" / "isa" / "legacy"
ISA_FIX = ROOT / "tests" / "fixtures" / "isa"

# UAPI modes from the installed linux/bpf_common.h
# (BPF_ABS 0x20, BPF_IND 0x40, BPF_LEN 0x80, BPF_MSH 0xA0).
MODE_ABS = 0x20
MODE_IND = 0x40
MODE_LEN = 0x80
MODE_MSH = 0xA0

CLASS_LD = 0x00
CLASS_LDX = 0x01

# The four committed probe words (xdp section, first slot).
PROBE_WORDS = {
    "legacy_abs.s": 0x20,
    "legacy_ind.s": 0x800006040,
    "legacy_len.s": 0x80,
    "legacy_msh.s": 0xB1,
}


def _legacy_words(words):
    """Slots carrying a legacy cBPF load mode."""
    found = []
    for index, word in enumerate(words):
        opcode = word & 0xFF
        insn_class, mode = opcode & 0x07, opcode & 0xE0
        if insn_class == CLASS_LD and mode in (MODE_ABS, MODE_IND,
                                              MODE_LEN):
            found.append((index, word))
        elif insn_class == CLASS_LDX and mode == MODE_MSH:
            found.append((index, word))
    return found


def tool(name):
    import shutil
    executable = shutil.which(name)
    assert (executable
            and digest(executable) == CASES["tools"][name]), (
        "unadmitted backend tool: %s" % name)
    return executable


def _sections(path):
    data = path.read_bytes()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    sections = []
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        sections.append((data[base + row[0]:end].decode(),
                         row[2], row[4], row[5]))
    return data, sections


def _section_words(path, section):
    data, sections = _sections(path)
    for name, _, offset, size in sections:
        if name == section:
            text = data[offset:offset + size]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError("%s section missing" % section)


SHF_EXECINSTR = 0x4


def _exec_section_words(path):
    """(name, words) for every executable section carrying bytes."""
    data, sections = _sections(path)
    found = []
    for name, flags, offset, size in sections:
        if flags & SHF_EXECINSTR and size:
            text = data[offset:offset + size]
            assert len(text) % 8 == 0, name
            found.append(
                (name, [word for (word,) in struct.iter_unpack(
                    "<Q", text)]))
    return found


def test_legacy_uapi_modes():
    assert (MODE_ABS, MODE_IND, MODE_LEN, MODE_MSH) == (
        0x20, 0x40, 0x80, 0xA0)
    for name, word in sorted(PROBE_WORDS.items()):
        opcode = word & 0xFF
        if name in ("legacy_abs.s", "legacy_ind.s", "legacy_len.s"):
            assert opcode & 0x07 == CLASS_LD, (name, hex(word))
        else:
            assert opcode & 0x07 == CLASS_LDX, (name, hex(word))
    assert PROBE_WORDS["legacy_abs.s"] & 0xE0 == MODE_ABS
    assert PROBE_WORDS["legacy_ind.s"] & 0xE0 == MODE_IND
    assert PROBE_WORDS["legacy_len.s"] & 0xE0 == MODE_LEN
    assert PROBE_WORDS["legacy_msh.s"] & 0xE0 == MODE_MSH


def test_legacy_recognizer():
    flagged = [0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58,
               0x80, 0x88, 0xA1, 0xA9, 0xB1, 0xB9]
    words = [(code | (slot << 8)) for slot, code in enumerate(flagged)]
    assert [slot for slot, _ in _legacy_words(words)] == list(
        range(len(flagged)))
    neighbors = [0x18, 0xDB, 0xC3, 0xDC, 0xD4, 0x05, 0x15, 0x1D,
                 0x95, 0x85, 0x61, 0x79, 0xB7, 0xBF]
    assert _legacy_words(neighbors) == []


# Corpora excluded from the absence guard: each is rejected
# before emission (no bytes exist to scan), pinned by the
# named test. Any other llc failure is a guard failure.
EXCLUDED_CORPORA = {
    "regs/oracle-sixargs.ll":
        "llc rejects stack arguments before emission "
        "(pinned by test_regs_oracle_sixargs_rejected)",
}


def test_legacy_absent_all_corpora(tmp_path):
    corpora = sorted(ISA_FIX.glob("*/*.ll"))
    assert len(corpora) >= 10, (
        "corpus glob must stay populated, got %d" % len(corpora))
    excluded = sorted(
        str(path.relative_to(ISA_FIX)) for path in corpora
        if str(path.relative_to(ISA_FIX)) in EXCLUDED_CORPORA)
    assert excluded == sorted(EXCLUDED_CORPORA), (
        "exclusion list drifted: glob has %r, list pins %r"
        % (excluded, sorted(EXCLUDED_CORPORA),)
    )
    for corpus in corpora:
        if str(corpus.relative_to(ISA_FIX)) in EXCLUDED_CORPORA:
            continue
        out = tmp_path / (corpus.stem + ".o")
        result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                      str(corpus), "-o", str(out)])
        assert result.returncode == 0, (corpus, result.stderr)
        exec_sections = _exec_section_words(out)
        scanned = sum(len(words) for _, words in exec_sections)
        assert scanned >= 1, (
            "corpus %s scanned zero executable words" % corpus.name)
        found = [(section, slot, word)
                 for section, words in exec_sections
                 for slot, word in _legacy_words(words)]
        assert found == [], (
            "corpus %s must carry zero legacy-mode words, got %r"
            % (corpus.name, [(section, slot, hex(word))
                             for section, slot, word in found],)
        )


def test_legacy_probe_words_flagged(tmp_path):
    for name, want in sorted(PROBE_WORDS.items()):
        out = tmp_path / (name + ".o")
        result = run([tool("clang"), "--target=bpf", "-mcpu=v3",
                      "-c", str(LEGACY_FIX / name), "-o", str(out)])
        assert result.returncode == 0, (name, result.stderr)
        words = _section_words(out, "xdp")
        assert words[0] == want, (name, hex(words[0]))
        assert words[1:] == [0x95], (name, words[1:])
        assert _legacy_words(words) == [(0, want)], name
