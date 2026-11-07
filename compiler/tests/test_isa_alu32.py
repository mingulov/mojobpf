# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/alu/alu32: 32-bit ALU admission + oracle pins (ISA-01).

Oracle ALU32 emission words per op (pinned llc 22.1.8, recorded at
RED, verified by decoding before pinning), checked-division
admission at {8,16,32,64} bits at both audit sites, and refusal
companions for every non-admitted div/rem shape. See the leaf
packet for the frozen vector list.
"""
import struct

import pytest

from test_isa_cpu import (
    check_cpu,
    llc,
)
from test_parsed_lowering import (
    ENTRY_CALL_BODY,
    lower,
    lower_success,
    subprog_module,
    subprog_spec,
)
from test_target_model import (
    ROOT,
    module,
    refusal,
)

ALU32_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "alu32" / "oracle-alu32.ll"

# Pinned oracle emission words (observed at RED, decode-verified by
# hand: mov32 r0,r1 prologue per func, op word, exit; regs bytes
# checked dst/src, immediates checked).
OP_WORDS = {
    "add-k": [429496729604],   # ADD32 K r0, 100
    "add-x": [8204],           # ADD32 X r0, r2
    # sub-k: no 0x14 word; see test_alu32_oracle_sub_k_canon.
    # sub-x twice: sub_x plus urem_k7's final word (same encoding).
    "sub-x": [8220, 8220],     # SUB32 X r0, r2
    "mul-k": [429496729636],   # MUL32 K r0, 100
    "mul-x": [8236],           # MUL32 X r0, r2
    "and-k": [1030792151124],  # AND32 K r0, 240
    "and-x": [8284],           # AND32 X r0, r2
    "or-k": [64424509508],     # OR32 K r0, 15
    "or-x": [8268],            # OR32 X r0, r2
    "xor-k": [1095216660644],  # XOR32 K r0, 255
    "xor-x": [8364],           # XOR32 X r0, r2
    "lsh-k": [12884901988],    # LSH32 K r0, 3
    "rsh-k": [21474836596],    # RSH32 K r0, 5
    "arsh-k": [30064771268],   # ARSH32 K r0, 7
    "neg": [132],              # NEG32 r0 (of moved r1)
    "div-x": [8252],           # DIV32 X r0, r2 (selected, audit-refused)
    "mod-x": [8348],           # MOD32 X r0, r2 (selected, audit-refused)
}

# Reduced div/mod sequences, one exact word list per corpus function
# (functions split on exit words, in corpus order; decode-verified:
# div_k/mod_k/urem_k7 are magic-multiply sequences, udiv_k8 a
# shift, udiv_kmax a compare — JEQ32 K r1, max, +1 selecting
# between MOV32 K r0, 1 and MOV32 K r0, 0).
REDUCED_WORDS = {
    "div_k": [4284, 4294967412, 3513665538872049703,
              146028888183, 149],
    "mod_k": [4284, 4294967668, 3513665538872049959,
              146028888439, 180388626724, 4124, 149],
    "udiv_k8": [4284, 12884902004, 149],
    "udiv_kmax": [4294967476, 18446744069414650134, 180, 149],
    "urem_k7": [4284, 444, 2635249155227779367, 137438953847,
                700, 4636, 4294967924, 4620, 8589935220,
                30064771620, 8220, 149],
}


def _section_words(object_path, section):
    data = object_path.read_bytes()
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
    raise AssertionError(
        "%s section missing in %s" % (section, object_path))


def _oracle_alu32_object(tmp_path):
    out = tmp_path / "alu32.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  ALU32_CORPUS, "-o", out])
    assert result.returncode == 0, result.stderr
    return _section_words(out, ".text")


def _split_funcs(words):
    # The corpus emits each function as op words terminated by one
    # exit word (0x95), in corpus order; split there so reduced
    # sequences pin per function.
    funcs, current = [], []
    for word in words:
        current.append(word)
        if word & 0xFF == 0x95:
            funcs.append(current)
            current = []
    assert not current, "trailing words after the last exit"
    return funcs


@pytest.mark.parametrize("op,form,opcode,regs,imm", [
    ("add", "k", 0x04, 0x00, 100), ("add", "x", 0x0C, 0x20, 0),
    ("sub", "x", 0x1C, 0x20, 0),
    ("mul", "k", 0x24, 0x00, 100), ("mul", "x", 0x2C, 0x20, 0),
    ("and", "k", 0x54, 0x00, 240), ("and", "x", 0x5C, 0x20, 0),
    ("or", "k", 0x44, 0x00, 15), ("or", "x", 0x4C, 0x20, 0),
    ("xor", "k", 0xA4, 0x00, 255), ("xor", "x", 0xAC, 0x20, 0),
    ("lsh", "k", 0x64, 0x00, 3), ("rsh", "k", 0x74, 0x00, 5),
    ("arsh", "k", 0xC4, 0x00, 7),
])
def test_alu32_oracle_emission(tmp_path, op, form, opcode, regs, imm):
    # The regs byte is part of the pin: the reduced div/mod sequences
    # reuse ADD32-X/SUB32-X opcodes with other register pairs.
    words = [word for word in _oracle_alu32_object(tmp_path)
             if word & 0xFF == opcode
             and (word >> 8) & 0xFF == regs
             and (word >> 32) & 0xFFFFFFFF == imm & 0xFFFFFFFF]
    assert len(words) >= 1, "no %s-%s word" % (op, form)
    key = "%s-%s" % (op, form)
    assert words == OP_WORDS[key]


def test_alu32_oracle_sub_k_canon(tmp_path):
    # Pinned llc canonicalizes `sub %x, C` to ADD K -C; no 0x14 word
    # is emitted. The SUB-K operation pin is therefore the exact
    # canonical word.
    words = _oracle_alu32_object(tmp_path)
    assert not [word for word in words if word & 0xFF == 0x14]
    canon = [word for word in words
             if word & 0xFF == 0x04
             and (word >> 32) == 0xFFFFFF9C]
    assert canon == [18446743644212822020]  # ADD32 K r0, -100


def test_alu32_oracle_neg(tmp_path):
    words = [word for word in _oracle_alu32_object(tmp_path)
             if word & 0xFF == 0x84]
    assert len(words) >= 1
    assert words == OP_WORDS["neg"]


def test_alu32_oracle_mov(tmp_path):
    # mov32 r0, r1 prologues: 23 (udiv_kmax optimizes to a compare
    # sequence with no prologue), plus urem_k7's two internal moves
    # (mov32 r1, r0; mov32 r2, r0).
    words = [word for word in _oracle_alu32_object(tmp_path)
             if word & 0xFF == 0xBC]
    assert len(words) == 25
    assert sorted(words) == [0x01BC, 0x02BC] + [0x10BC] * 23


@pytest.mark.parametrize("op,opcode", [("div", 0x3C), ("mod", 0x9C)])
def test_alu32_oracle_divmod_x_shape(tmp_path, op, opcode):
    words = [word for word in _oracle_alu32_object(tmp_path)
             if word & 0xFF == opcode
             and (word >> 8) & 0xFF == 0x20]
    assert len(words) >= 1
    assert words == OP_WORDS["%s-x" % op]


def test_alu32_oracle_no_div_k(tmp_path):
    # No constant divisor in the corpus selects a DIV32/MOD32 K word:
    # every admitted K shape reduces (magic sequence, shift, or
    # compare). Re-verified at RED; a K word here would pin instead.
    words = _oracle_alu32_object(tmp_path)
    assert not [word for word in words if word & 0xFF in (0x34, 0x94)]


@pytest.mark.parametrize("name,index", [
    ("div_k", 6), ("mod_k", 7), ("udiv_k8", 10),
    ("udiv_kmax", 11), ("urem_k7", 12),
])
def test_alu32_oracle_div_k_reduced(tmp_path, name, index):
    funcs = _split_funcs(_oracle_alu32_object(tmp_path))
    assert len(funcs) == 24, "corpus function count moved"
    # Anchor: function 0 must be add_k (mov32, ADD32 K 100, exit),
    # proving llc emits in corpus order.
    assert funcs[0][0] == 0x10BC and funcs[0][-1] == 0x95
    assert funcs[index] == REDUCED_WORDS[name]


@pytest.mark.parametrize("op,width,divisor", [
    ("udiv", 32, 42), ("urem", 32, 42),
    ("udiv", 16, 42), ("urem", 16, 42),
    ("udiv", 8, 7), ("urem", 8, 7),
    ("udiv", 32, 4294967295),
])
def test_alu32_admit_div_k_nonzero(tmp_path, op, width, divisor):
    # Admission is about the IR shape (provably cannot trap), not the
    # selected encoding: constant divisors reduce, large-K included.
    if width == 32:
        tail = " ret i32 %x\n"
    else:
        tail = " %%z = zext i%d %%x to i32\n ret i32 %%z\n" % width
    text = module("entry:\n %%x = %s i%d 100, %d\n%s"
                  % (op, width, divisor, tail))
    result, report = check_cpu(tmp_path, text, "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


@pytest.mark.parametrize("snippet,message", [
    ("entry:\n %x = udiv i32 100, 0\n ret i32 %x\n",
     "unchecked division"),
    ("entry:\n %x = urem i32 100, 0\n ret i32 %x\n",
     "unchecked division"),
    ("entry:\n %a = add i32 100, 1\n %x = udiv i32 100, %a\n ret i32 %x\n",
     "unchecked division"),
    ("entry:\n %a = add i32 100, 1\n %x = urem i32 100, %a\n ret i32 %x\n",
     "unchecked division"),
    ("entry:\n %x = sdiv i32 100, 42\n ret i32 %x\n",
     "unchecked division"),
    ("entry:\n %x = srem i32 100, 42\n ret i32 %x\n",
     "unchecked division"),
    ("entry:\n %x = sdiv i16 100, 42\n %z = zext i16 %x to i32\n ret i32 %z\n",
     "unchecked division"),
    ("entry:\n %x = udiv i1 1, 1\n %z = zext i1 %x to i32\n ret i32 %z\n",
     "8/16/32/64-bit"),
    ("entry:\n %x = urem i1 1, 1\n %z = zext i1 %x to i32\n ret i32 %z\n",
     "8/16/32/64-bit"),
    ("entry:\n %a = add i32 100, 1\n %x = shl i32 100, %a\n ret i32 %x\n",
     "shift count"),
])
def test_alu32_refused_div_shapes(tmp_path, snippet, message):
    result, report = check_cpu(tmp_path, module(snippet), "v3")
    refusal(result, report, "MBPF319")
    assert message in report["diagnostics"][0]["explanation"]


def test_alu32_admit_div_k_nonzero_subprog(tmp_path):
    # Subprogram audit site: checked 32-bit division in the callee
    # lowers (shared helper — both sites move together). The callee
    # keeps its (i64)->i64 shape; the 32-bit division sits inside.
    callee = ("entry:\n %t = trunc i64 %n to i32\n"
              " %q = udiv i32 %t, 42\n %r = urem i32 %q, 7\n"
              " %z = zext i32 %r to i64\n ret i64 %z\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    lower_success(result, report, output)
    assert "udiv i32" in output.read_text()


def test_alu32_refused_div_x_subprog(tmp_path):
    # Subprogram audit site: X-form 32-bit division is refused
    # identically.
    callee = ("entry:\n %t = trunc i64 %n to i32\n"
              " %a = add i32 %t, 1\n %q = udiv i32 %t, %a\n"
              " %z = zext i32 %q to i64\n ret i64 %z\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, "MBPF319")
    assert "unchecked division" in report["diagnostics"][0]["explanation"]
