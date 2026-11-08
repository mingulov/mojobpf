# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/misc/endian: bswap refuses, the BPF_END surface pins.

The audit refuses the bswap intrinsic (the `nocallback`
attribute is outside the frozen producer model -> exit 4,
MBPF319 at entry AND subprogram sites); no admitted Mojo
emits BPF_END. Oracle pins cover the llc emission cells
(bswap x 16/32/64 used, unused x3 eliminated), the
TO_BE-always rule on bpfel, and the hand-asm TO_LE word.
Structural asserts pin one-BPF_END-word functions with
width immediates and trailing exits (zero END words for
unused). See the leaf packet for the frozen vector list.
"""
import struct

from test_isa_cpu import (
    check_cpu,
    llc,
)
from test_parsed_lowering import (
    ENTRY_CALL_BODY,
    lower,
    subprog_module,
    subprog_spec,
)
from test_target_model import (
    CASES,
    ROOT,
    digest,
    module,
    refusal,
    run,
)

ENDIAN_FIX = ROOT / "tests" / "fixtures" / "isa" / "endian"
ENDIAN_CORPUS = ENDIAN_FIX / "oracle-endian.ll"
ENDIAN_ASM = ENDIAN_FIX / "oracle-endian-run.s"

FUNC_NAMES = [
    "bswap_16_used", "bswap_32_used", "bswap_64_used",
    "bswap_16_unused", "bswap_32_unused", "bswap_64_unused",
]

UNUSED_FUNCS = (
    "bswap_16_unused", "bswap_32_unused", "bswap_64_unused",
)

# Exact words per function, observed at RED, decode-verified
# (one BPF_END|TO_BE word each for used: opcode 0xDC, width
# imm, regs value, exit-trailing; mov + exit for unused).
FUNC_WORDS = {
    "bswap_16_used": [0x10BC, 0x10000000DC, 0x95],
    "bswap_32_used": [0x10BC, 0x20000000DC, 0x95],
    "bswap_64_used": [0x10BF, 0x40000000DC, 0x95],
    "bswap_16_unused": [0x7000000B4, 0x95],
    "bswap_32_unused": [0x7000000B4, 0x95],
    "bswap_64_unused": [0x7000000B4, 0x95],
}

# Hand-asm TO_LE oracle words (xdp section), observed at RED,
# decode-verified (bounds check, u16 load at +14, le16, exit;
# fallback mov + exit).
ASM_WORDS = [
    0x1679, 0x41279, 0x63BF, 0x1000000307, 0x3232D,
    0xE6069, 0x10000000D4, 0x95, 0xB7, 0x95,
]

# BPF_END width immediates (bytes-to-swap operand size).
END_WIDTHS = {16, 32, 64}


def tool(name):
    import shutil
    executable = shutil.which(name)
    assert (executable
            and digest(executable) == CASES["tools"][name]), (
        "unadmitted backend tool: %s" % name)
    return executable


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
    out = tmp_path / "oracle-endian.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  str(ENDIAN_CORPUS), "-o", str(out)])
    assert result.returncode == 0, result.stderr
    words = _section_words(out, ".text")
    funcs, cur = [], []
    for word in words:
        cur.append(word)
        if word & 0xFF == 0x95:
            funcs.append(cur)
            cur = []
    assert not cur
    return funcs


def _asm_words(tmp_path):
    out = tmp_path / "oracle-endian-asm.o"
    result = run([tool("clang"), "--target=bpf", "-mcpu=v3",
                  "-c", str(ENDIAN_ASM), "-o", str(out)])
    assert result.returncode == 0, result.stderr
    return _section_words(out, "xdp")


def _endian_words(words):
    return [(index, word) for index, word in enumerate(words)
            if word & 0xFF in (0xDC, 0xD4)]


def test_endian_oracle_emission(tmp_path):
    funcs = _oracle_functions(tmp_path)
    assert len(funcs) == len(FUNC_NAMES) == 6
    for name, words in zip(FUNC_NAMES, funcs):
        assert words == FUNC_WORDS[name], name


def test_endian_shape_and_imm(tmp_path):
    funcs = _oracle_functions(tmp_path)
    for name, words in zip(FUNC_NAMES, funcs):
        assert words == FUNC_WORDS[name], name
        found = _endian_words(words)
        if name in UNUSED_FUNCS:
            assert found == [], (name, found)
        else:
            assert len(found) == 1, (name, found)
            imm = (found[0][1] >> 32) & 0xFFFFFFFF
            assert imm in END_WIDTHS, (name, hex(imm))
            assert found[0][1] & 0xFF == 0xDC, (name, hex(found[0][1]))
        assert words[-1] == 0x95, name


def test_endian_tobe_rule(tmp_path):
    # llc selects TO_BE (opcode 0xDC) on every observed bpfel
    # emission; TO_LE (0xD4) rides the hand-asm oracle. No
    # broader selection claim (bpfeb unobserved).
    funcs = _oracle_functions(tmp_path)
    for name, words in zip(FUNC_NAMES, funcs):
        assert words == FUNC_WORDS[name], name
        for _, word in _endian_words(words):
            assert word & 0xFF == 0xDC, (name, hex(word))


def test_endian_tole_asm_words(tmp_path):
    words = _asm_words(tmp_path)
    assert words == ASM_WORDS


def test_endian_tole_asm_decode(tmp_path):
    words = _asm_words(tmp_path)
    assert words == ASM_WORDS
    found = _endian_words(words)
    assert len(found) == 1, found
    slot, word = found[0]
    assert word & 0xFF == 0xD4, hex(word)
    assert (word >> 32) & 0xFFFFFFFF == 16, hex(word)


BSWAP_BODY = (
    "entry:\n"
    "  %v = call i32 @llvm.bswap.i32(i32 305419896)\n"
    "  ret i32 %v\n"
)

BSWAP_DECLS = "declare i32 @llvm.bswap.i32(i32)\n"

# bswap refuses under the frozen-producer-model attribute gate
# (observed at RED), identically at both sites.
REFUSED_CODE = "MBPF319"
REFUSED_ATTRIBUTE = "nocallback"


def test_endian_refused_entry(tmp_path):
    result, report = check_cpu(
        tmp_path, module(BSWAP_BODY, declarations=BSWAP_DECLS), "v3")
    refusal(result, report, REFUSED_CODE)
    assert REFUSED_ATTRIBUTE in report["diagnostics"][0]["explanation"]


def test_endian_refused_subprog(tmp_path):
    # Same face in the bound callee: the attribute check
    # precedes site-specific machinery (observed at RED).
    callee = ("entry:\n"
              "  %v = call i32 @llvm.bswap.i32(i32 305419896)\n"
              "  %t = zext i32 %v to i64\n"
              "  ret i64 %t\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY)
                      + BSWAP_DECLS)
    result, report, _ = lower(tmp_path, source, subprog_spec())
    refusal(result, report, REFUSED_CODE)
    assert REFUSED_ATTRIBUTE in report["diagnostics"][0]["explanation"]


def test_endian_admitted_companion(tmp_path):
    # Plain ALU on the same constant admits: the MBPF319
    # refusal keys on the intrinsic, not the shape.
    body = (
        "entry:\n"
        "  %v = add i32 305419896, 1\n"
        "  ret i32 %v\n"
    )
    result, report = check_cpu(tmp_path, module(body), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report is not None and report["ok"] is True
