# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/jmp/cond: conditional jumps characterize the Jcc surface.

Oracle pins cover the per-condition emission cells (K/X, 64/32),
the boundary survivors (JLE32-K/JSGE32-K/JSLE32-K), the dodge
demos (imm-rewrite, register materialization, sign-flip), and
the JSET-absence shapes. Structural asserts pin the tiny-diamond
shape (one Jcc + two exits each), Jcc-target landing, the
35-opcode coverage set, and the absences (JSET x4, JA32,
64-bit GE/LE-K, JGE32-K). Admission companions pin the 20 icmp
flavors. See the leaf packet for the frozen vector list.
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
)

JCC_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "jcc" / "oracle-jcc.ll"

FUNC_WORDS = {
    "jcc_jeqk_64": [
        0x700020115, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jeqk_32": [
        0x700020116, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jeqx_64": [
        0x2211D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jeqx_32": [
        0x2211E, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jnek_64": [
        0x700020155, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jnek_32": [
        0x700020156, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jnex_64": [
        0x2215D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jnex_32": [
        0x2215E, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jgtk_64": [
        0x6400020125, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jgtk_32": [
        0x6400020126, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jgtx_64": [
        0x2212D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jgtx_32": [
        0x2212E, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jgek_64": [
        0x6300020125, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jgek_32": [
        0x6300020126, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jgex_64": [
        0x2213D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jgex_32": [
        0x2213E, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jltk_64": [
        0xC8000201A5, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jltk_32": [
        0xC8000201A6, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jltx_64": [
        0x221AD, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jltx_32": [
        0x221AE, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jlek_64": [
        0xC9000201A5, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jlek_32": [
        0xC9000201A6, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jlex_64": [
        0x221BD, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jlex_32": [
        0x221BE, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jsgtk_64": [
        0xFFFFFFFF00020165, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jsgtk_32": [
        0xFFFFFFFF00020166, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jsgtx_64": [
        0x2216D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jsgtx_32": [
        0x2216E, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jsgek_64": [
        0xFFFFFFFF00020165, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jsgek_32": [
        0xFFFFFFFF00020166, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jsgex_64": [
        0x2217D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jsgex_32": [
        0x2217E, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jsltk_64": [
        0x201C5, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jsltk_32": [
        0x201C6, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jsltx_64": [
        0x221CD, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jsltx_32": [
        0x221CE, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jslek_64": [
        0x201C5, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jslek_32": [
        0x201C6, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jcc_jslex_64": [
        0x221DD, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jcc_jslex_32": [
        0x221DE, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jle32_k": [
        0xFFFFFFFF000201B6, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jsge32_k": [
        0x8000000000020176, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jsle32_k": [
        0x7FFFFFFF000201D6, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "dodge_ge64": [
        0x7FFFFFFF00000218, 0xFFFFFFFF00000000, 0x2212D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "dodge_le64": [
        0x218, 0x100000000, 0x221AD, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "dodge_sge64": [
        0x7FFFFFFF00000218, 0xFFFFFFFF00000000, 0x2216D, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "dodge_sle64": [
        0x8000000000000218, 0x0, 0x221CD, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "dodge_ge32": [
        0x201C6, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
    "jset_abs_x64": [
        0x215F, 0x20115, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jset_abs_k64": [
        0x300000157, 0x20155, 0x1000000B7, 0x95, 0x2000000B7, 0x95,
    ],
    "jset_abs_x32": [
        0x215C, 0x20116, 0x1000000B4, 0x95, 0x2000000B4, 0x95,
    ],
}


def _section_words(path, section):
    data = path.read_bytes()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        if data[base + row[0]:end] == section.encode():
            text = data[row[4]:row[4] + row[5]]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError("%s section missing" % section)


def _oracle_functions(tmp_path):
    out = tmp_path / "oracle-jcc.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  str(JCC_CORPUS), "-o", str(out)])
    assert result.returncode == 0, result.stderr
    words = _section_words(out, ".text")
    funcs, cur = [], []
    for word in words:
        cur.append(word)
        if word & 0xFF == 0x95:
            funcs.append(cur)
            cur = []
    assert not cur and len(funcs) % 2 == 0
    return [funcs[index] + funcs[index + 1]
            for index in range(0, len(funcs), 2)]


def _signed_off(word):
    off = (word >> 16) & 0xFFFF
    return off - 0x10000 if off >= 0x8000 else off


def test_jcc_oracle_emission(tmp_path):
    funcs = _oracle_functions(tmp_path)
    assert len(funcs) == len(FUNC_WORDS) == 51
    for name, words in zip(FUNC_WORDS, funcs):
        assert words == FUNC_WORDS[name], name


def _jump_words(words):
    return [(index, word) for index, word in enumerate(words)
            if word & 0xFF not in (0x85, 0x95)
            and word & 0x07 in (0x05, 0x06)]


def test_jcc_shape_and_targets(tmp_path):
    funcs = _oracle_functions(tmp_path)
    assert sum(len(words) for words in funcs) == 266
    for name, words in zip(FUNC_WORDS, funcs):
        jumps = _jump_words(words)
        assert len(jumps) == 1, (name, jumps)
        (slot, word), = jumps
        target = slot + _signed_off(word) + 1
        assert 0 <= target < len(words), (name, slot, target)
        assert [word for word in words if word & 0xFF == 0x95] == [
            0x95, 0x95], name


COVERAGE_35 = {
    0x15, 0x16, 0x1D, 0x1E, 0x25, 0x26, 0x2D, 0x2E, 0x3D, 0x3E,
    0x55, 0x56, 0x5D, 0x5E, 0x65, 0x66, 0x6D, 0x6E, 0x76, 0x7D,
    0x7E, 0xA5, 0xA6, 0xAD, 0xAE, 0xB6, 0xBD, 0xBE, 0xC5, 0xC6,
    0xCD, 0xCE, 0xD6, 0xDD, 0xDE,
}

ABSENT_OPS = {
    # JSET x4: the backend lowers and+compare to AND + JEQ/JNE.
    0x45, 0x4D, 0x46, 0x4E,
    # 64-bit GE/LE-K: imm-rewrite or register materialization wins.
    0x35, 0xB5, 0x75, 0xD5,
    # JGE32-K: imm-rewrite, or the sign-flip at INT32_MIN.
    0x36,
    # JA32: needs >32767 slots (unobservable in-slice).
    0x06,
}


def test_jcc_opcode_coverage(tmp_path):
    funcs = _oracle_functions(tmp_path)
    seen = {word & 0xFF for words in funcs for _, word in
            _jump_words(words)}
    assert seen == COVERAGE_35, (
        "observed %r" % (sorted("0x%02X" % op for op in seen),)
    )


def test_jcc_absences(tmp_path):
    funcs = _oracle_functions(tmp_path)
    for name, words in zip(FUNC_WORDS, funcs):
        for index, word in enumerate(words):
            assert word & 0xFF not in ABSENT_OPS, (
                name, index, hex(word))


COND_NIBBLES = {
    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0xA, 0xB, 0xC, 0xD,
}


def test_jcc_class_rules(tmp_path):
    # BPF_JCOND/BPF_JMP32: every jump word decodes under the
    # class/op/K-X rule (class 0x05 = 64-bit, 0x06 = 32-bit;
    # condition nibble; bit 3 = X source).
    funcs = _oracle_functions(tmp_path)
    for name, words in zip(FUNC_WORDS, funcs):
        for index, word in _jump_words(words):
            op = word & 0xFF
            assert op & 0x07 in (0x05, 0x06), (name, hex(word))
            assert (op >> 4) & 0xF in COND_NIBBLES, (name, hex(word))
            target = index + _signed_off(word) + 1
            assert 0 <= target < len(words), (name, index)


ICMP_FLAVORS = [
    "eq", "ne", "ugt", "uge", "ult", "ule",
    "sgt", "sge", "slt", "sle",
]


def _flavor_body(pred, width):
    return (
        "entry:\n"
        "  %%c = icmp %s i%d 1, 2\n" % (pred, width) +
        "  br i1 %c, label %yes, label %no\n"
        "yes:\n"
        "  ret i32 1\n"
        "no:\n"
        "  ret i32 2\n"
    )


@pytest.mark.parametrize("pred", ICMP_FLAVORS)
@pytest.mark.parametrize("width", [64, 32])
def test_jcc_admitted_flavors(tmp_path, pred, width):
    result, report = check_cpu(
        tmp_path, module(_flavor_body(pred, width)), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report is not None and report["ok"] is True
