# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/alu/logic64: 64-bit logic/shift pins + shift companions (ISA-01).

Oracle K/X emission words per op (pinned llc 22.1.8, recorded at RED,
verified by decoding before pinning), MOV64 selection pins, and the
existing shift-count rule pinned at both audit sites. See the leaf
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

LOGIC_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "logic" / "oracle-logic64.ll"

# Pinned oracle emission words (observed at RED, decode-verified by
# hand: mov r0,r1 prologue per func, op word, exit; regs bytes
# checked dst/src, immediates checked).
OP_WORDS = {
    "and-k": [1030792151127],  # AND64 K r0, 240
    "and-x": [8287],           # AND64 X r0, r2
    "or-k": [64424509511],     # OR64 K r0, 15
    "or-x": [8271],            # OR64 X r0, r2
    "xor-k": [1095216660647],  # XOR64 K r0, 255
    "xor-x": [8367],           # XOR64 X r0, r2
    "shl-k": [12884901991],    # LSH64 K r0, 3
    "lshr-k": [21474836599],   # RSH64 K r0, 5
    "ashr-k": [30064771271],   # ARSH64 K r0, 7
    "shl-x": [8303],           # LSH64 X r0, r2 (selected, audit-refused)
    "lshr-x": [8319],          # RSH64 X r0, r2 (selected, audit-refused)
    "ashr-x": [8399],          # ARSH64 X r0, r2 (selected, audit-refused)
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


def _oracle_logic_object(tmp_path):
    out = tmp_path / "logic64.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  LOGIC_CORPUS, "-o", out])
    assert result.returncode == 0, result.stderr
    return _section_words(out, ".text")


@pytest.mark.parametrize("op,form,opcode,imm", [
    ("and", "k", 0x57, 240), ("and", "x", 0x5F, 0),
    ("or", "k", 0x47, 15), ("or", "x", 0x4F, 0),
    ("xor", "k", 0xA7, 255), ("xor", "x", 0xAF, 0),
    ("shl", "k", 0x67, 3), ("lshr", "k", 0x77, 5),
    ("ashr", "k", 0xC7, 7),
])
def test_logic64_oracle_emission(tmp_path, op, form, opcode, imm):
    words = [word for word in _oracle_logic_object(tmp_path)
             if word & 0xFF == opcode
             and (word >> 32) & 0xFFFFFFFF == imm & 0xFFFFFFFF]
    assert len(words) >= 1, "no %s-%s word" % (op, form)
    key = "%s-%s" % (op, form)
    assert words == OP_WORDS[key]


def test_logic64_oracle_mov(tmp_path):
    # Every corpus function opens with mov64 r0, r1 (the param move).
    words = [word for word in _oracle_logic_object(tmp_path)
             if word & 0xFF == 0xBF]
    assert len(words) == 12, "one prologue mov per corpus function"
    assert words == [4287] * 12  # MOV64 r0, r1


@pytest.mark.parametrize("op,opcode", [("shl", 0x6F), ("lshr", 0x7F),
                                       ("ashr", 0xCF)])
def test_logic64_oracle_shift_x_shape(tmp_path, op, opcode):
    # The oracle selects X-form shifts; the audit refuses them and no
    # route object emits them.
    words = [word for word in _oracle_logic_object(tmp_path)
             if word & 0xFF == opcode]
    assert len(words) >= 1
    assert words == OP_WORDS["%s-x" % op]


@pytest.mark.parametrize("snippet", [
    "entry:\n %a = add i64 100, 1\n %x = and i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %a = add i64 100, 1\n %x = or i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %a = add i64 100, 1\n %x = xor i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %x = shl i64 100, 3\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %x = lshr i64 100, 5\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %x = ashr i64 100, 7\n %t = trunc i64 %x to i32\n ret i32 %t\n",
])
def test_logic64_admitted_shapes(tmp_path, snippet):
    result, report = check_cpu(tmp_path, module(snippet), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


@pytest.mark.parametrize("snippet", [
    "entry:\n %x = shl i64 100, 64\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %a = add i64 100, 1\n %x = shl i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %a = add i64 100, 1\n %x = lshr i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %a = add i64 100, 1\n %x = ashr i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %x = lshr i64 100, 128\n %t = trunc i64 %x to i32\n ret i32 %t\n",
    "entry:\n %x = shl i32 100, 40\n ret i32 %x\n",
])
def test_logic64_refused_shift_shapes(tmp_path, snippet):
    result, report = check_cpu(tmp_path, module(snippet), "v3")
    refusal(result, report, "MBPF319")
    assert "shift count" in report["diagnostics"][0]["explanation"]


def test_logic64_admit_or_x_subprog(tmp_path):
    # Subprogram audit site: admitted logic in the callee lowers.
    callee = ("entry:\n %a = add i64 %n, 1\n"
              " %x = or i64 %n, %a\n ret i64 %x\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    lower_success(result, report, output)
    assert "or i64" in output.read_text()


def test_logic64_refused_shl_x_subprog(tmp_path):
    # Subprogram audit site: X-form shift refused identically.
    callee = ("entry:\n %a = add i64 %n, 1\n"
              " %x = shl i64 %n, %a\n ret i64 %x\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, "MBPF319")
    assert "shift count" in report["diagnostics"][0]["explanation"]
