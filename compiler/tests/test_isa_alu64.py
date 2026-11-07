# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/alu/arith64: 64-bit ALU admission + oracle pins (ISA-01).

Oracle K/X emission words per op (pinned llc 22.1.8, recorded at RED,
verified by decoding before pinning), checked-division admission at
both audit sites, and refusal companions for every non-admitted
div/rem shape. See the leaf packet for the frozen vector list.
"""
import struct

import pytest

from test_isa_cpu import (
    check_cpu,
    llc,
    lower_tool,
    run,
    spec,
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

ALU_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "alu" / "oracle-alu64.ll"
ALU_LARGEK_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "alu" / "oracle-alu64-largek.ll"

# Pinned oracle emission words (observed at RED, decode-verified by
# hand: mov r0,r1 prologue per func, op word, exit; regs bytes
# checked dst/src, immediates checked).
OP_WORDS = {
    "add-k": [429496729607],   # ADD64 K r0, 100
    "add-x": [8207],           # ADD64 X r0, r2
    # sub-k: no 0x17 word; see test_alu64_oracle_sub_k_canon.
    "sub-x": [8223],           # SUB64 X r0, r2
    "mul-k": [429496729639],   # MUL64 K r0, 100
    "mul-x": [8239],           # MUL64 X r0, r2
    "div-k": [180388626487],   # DIV64 K r0, 42
    "mod-k": [180388626583],   # MOD64 K r0, 42
    "neg": [135],              # NEG64 r0 (of moved r1)
    "div-x": [8255],           # DIV64 X r0, r2 (selected, audit-refused)
    "mod-x": [8351],           # MOD64 X r0, r2 (selected, audit-refused)
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


def _alu64_words(words):
    return [word for word in words if word & 0x07 == 0x07]


def _oracle_alu_object(tmp_path, corpus=ALU_CORPUS):
    out = tmp_path / "alu64.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  corpus, "-o", out])
    assert result.returncode == 0, result.stderr
    return _section_words(out, ".text")


@pytest.mark.parametrize("op,form,opcode,imm", [
    ("add", "k", 0x07, 100), ("add", "x", 0x0F, 0),
    ("sub", "x", 0x1F, 0),
    ("mul", "k", 0x27, 100), ("mul", "x", 0x2F, 0),
    ("div", "k", 0x37, 42), ("mod", "k", 0x97, 42),
])
def test_alu64_oracle_emission(tmp_path, op, form, opcode, imm):
    words = [word for word in _oracle_alu_object(tmp_path)
             if word & 0xFF == opcode
             and (word >> 32) & 0xFFFFFFFF == imm & 0xFFFFFFFF]
    assert len(words) >= 1, "no %s-%s word" % (op, form)
    key = "%s-%s" % (op, form)
    assert words == OP_WORDS[key]


def test_alu64_oracle_sub_k_canon(tmp_path):
    # Pinned llc canonicalizes `sub %x, C` to ADD K -C (observed for
    # C in {1, 100, 2147483647}); no 0x17 word is emitted. The SUB-K
    # operation pin is therefore the exact canonical word.
    words = _oracle_alu_object(tmp_path)
    assert not [word for word in words if word & 0xFF == 0x17]
    canon = [word for word in words
             if word & 0xFF == 0x07
             and (word >> 32) == 0xFFFFFF9C]
    assert canon == [18446743644212822023]  # ADD64 K r0, -100


def test_alu64_oracle_neg(tmp_path):
    words = [word for word in _oracle_alu_object(tmp_path)
             if word & 0xFF == 0x87]
    assert len(words) >= 1
    assert words == OP_WORDS["neg"]


@pytest.mark.parametrize("op,opcode", [("div", 0x3F), ("mod", 0x9F)])
def test_alu64_oracle_divmod_x_shape(tmp_path, op, opcode):
    words = [word for word in _oracle_alu_object(tmp_path)
             if word & 0xFF == opcode]
    assert len(words) >= 1
    assert words == OP_WORDS["%s-x" % op]


@pytest.mark.parametrize("op,opcode", [("udiv", 0x3F), ("urem", 0x9F)])
def test_alu64_oracle_largek_selects_x(tmp_path, op, opcode):
    # Divisors past the 32-bit immediate field are admitted (provably
    # nonzero) but selected to register-materialized X-form: ld_imm64
    # r1, 0xFFFFFFFF (two slots) then DIV/MOD64 X r0, r1.
    words = _oracle_alu_object(tmp_path, ALU_LARGEK_CORPUS)
    materialized = [word for word in words if word & 0xFF == 0x18]
    assert materialized == [18446744069414584600,
                            18446744069414584600]
    found = [word for word in words if word & 0xFF == opcode]
    expected = [4159] if op == "udiv" else [4255]
    assert found == expected


@pytest.mark.parametrize("op", ["udiv", "urem"])
def test_alu64_admit_div_k_large(tmp_path, op):
    # Large nonzero constants are admitted: admission is about the
    # IR shape (provably cannot trap), not the selected encoding.
    text = module("entry:\n %%x = %s i64 100, 4294967295\n"
                  " %%t = trunc i64 %%x to i32\n ret i32 %%t\n" % op)
    result, report = check_cpu(tmp_path, text, "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


def test_alu64_admit_div_k_nonzero(tmp_path):
    text = module("entry:\n %x = udiv i64 100, 42\n %t = trunc i64 %x to i32\n ret i32 %t\n")
    result, report = check_cpu(tmp_path, text, "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


def test_alu64_admit_mod_k_nonzero(tmp_path):
    text = module("entry:\n %x = urem i64 100, 42\n %t = trunc i64 %x to i32\n ret i32 %t\n")
    result, report = check_cpu(tmp_path, text, "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


@pytest.mark.parametrize("snippet,code,message", [
    ("entry:\n %x = udiv i64 100, 0\n %t = trunc i64 %x to i32\n ret i32 %t\n",
     "MBPF319", "unchecked division"),
    ("entry:\n %x = urem i64 100, 0\n %t = trunc i64 %x to i32\n ret i32 %t\n",
     "MBPF319", "unchecked division"),
    ("entry:\n %a = add i64 100, 1\n %x = udiv i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
     "MBPF319", "unchecked division"),
    ("entry:\n %a = add i64 100, 1\n %x = urem i64 100, %a\n %t = trunc i64 %x to i32\n ret i32 %t\n",
     "MBPF319", "unchecked division"),
    ("entry:\n %x = sdiv i64 100, 42\n %t = trunc i64 %x to i32\n ret i32 %t\n",
     "MBPF319", "unchecked division"),
    ("entry:\n %x = srem i64 100, 42\n %t = trunc i64 %x to i32\n ret i32 %t\n",
     "MBPF319", "unchecked division"),
    # F-ISA/alu/alu32 flips: udiv/urem i32 with a nonzero constant
    # divisor are admitted now (see test_alu32_admit_div_k_nonzero);
    # the signed/variable i32 shapes stay refused under the
    # established unchecked explanation.
    ("entry:\n %x = sdiv i32 100, 42\n ret i32 %x\n",
     "MBPF319", "unchecked division"),
    ("entry:\n %a = add i32 100, 1\n %x = udiv i32 100, %a\n ret i32 %x\n",
     "MBPF319", "unchecked division"),
])
def test_alu64_refused_div_shapes(tmp_path, snippet, code, message):
    result, report = check_cpu(tmp_path, module(snippet), "v3")
    refusal(result, report, code)
    assert message in report["diagnostics"][0]["explanation"]


def test_alu64_admit_div_k_nonzero_subprog(tmp_path):
    # Subprogram audit site: checked division in the callee lowers.
    callee = ("entry:\n %q = udiv i64 %n, 42\n"
              " %r = urem i64 %q, 7\n ret i64 %r\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    lower_success(result, report, output)
    assert "udiv i64" in output.read_text()


def test_alu64_refused_div_x_subprog(tmp_path):
    # Subprogram audit site: X-form division is refused identically.
    callee = ("entry:\n %a = add i64 %n, 1\n"
              " %q = udiv i64 %n, %a\n ret i64 %q\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, "MBPF319")
    assert "unchecked division" in report["diagnostics"][0]["explanation"]
