# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/jmp/uncond: JA/RET emission + jump-rule pins (ISA-01).

Oracle unconditional-jump emission (pinned llc 22.1.8, recorded
at RED, verified by decoding before pinning): JA words with
verified pc+off+1 targets, single trailing exits, plus the two
audited-out shapes (loop back-edge, switch chain) pinned for
the record. Audit companions pin the existing no-loop,
finite-subset, and block-limit rules. Jcc words appear only as
layout context and belong to the cond leaf. The admitted-MoJo
diamond exhibit pins the Amendment A2 negative finding (0 JA
by backend call-merging). See the leaf packet for the frozen
vector list.
"""
import struct
import subprocess
import sys

import pytest

from test_isa_cpu import (
    check_cpu,
    llc,
)
from test_target_model import (
    ROOT,
    capture,
    module,
    refusal,
)

JMP_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "jmp" / "oracle-jmp.ll"
JMP_EXHIBIT = ROOT / "tests" / "fixtures" / "isa" / "jmp" / "jmp_minimal.mojo"
JMP_ADAPTER = ROOT / "compiler" / "mojo_ir_adapter.py"

# Pinned oracle jump words, one entry per corpus function
# (observed at RED, decode-verified by hand: JA targets land
# on join work, exits trail).
FUNC_WORDS = {
    # join: JNE over the yes arm (add), JA+1 at slot 3 onto
    # the join (+100) over the no arm (mul), single exit.
    "jmp_join": [4287, 131157, 4294967303, 65541, 12884901927,
                 429496729607, 149],
    # nested: JNE dispatch, c arm (add) JA+3 at slot 4 to the
    # exit, b arm (mul), d arm (sub) JA+1 at slot 6 to the
    # exit, single exit. (Jcc words are cond-leaf context.)
    "jmp_nested": [4287, 196693, 262741, 8207, 196613, 8239,
                   65541, 8223, 149],
    # loop shape: the audited-out form — conditional back-edge
    # (JLT-reg -2) onto the add, single exit.
    "jmp_loop_shape": [183, 4294967303, 4294840493, 149],
}
FUNC_ORDER = list(FUNC_WORDS)

# switch shape: the audited-out form — JEQ-imm chain with four
# exits and no JA (llc expands, never a jump table).
SWITCH_WORDS = [12885295381, 8590131477, 4295360853, 42949673143,
                149, 85899346103, 149, 128849019063, 149,
                171798692023, 149]

DIAMOND_BODY = """entry:
  %c = icmp eq i64 1, 2
  br i1 %c, label %yes, label %no
yes:
  br label %join
no:
  br label %join
join:
  ret i32 2
"""

LOOP_BODY = """entry:
  br label %head
head:
  %i = phi i64 [ 0, %entry ], [ %next, %head ]
  %next = add i64 %i, 1
  %c = icmp ult i64 %next, 10
  br i1 %c, label %head, label %done
done:
  ret i32 2
"""

SWITCH_BODY = """entry:
  switch i32 1, label %dflt [ i32 1, label %one
                              i32 2, label %two ]
one:
  ret i32 1
two:
  ret i32 1
dflt:
  ret i32 2
"""


def _chain_body(count):
    lines = ["entry:", "  br label %b0"]
    for index in range(count):
        lines.append("b%d:" % index)
        lines.append("  %%c%d = icmp eq i32 %d, -1" % (index, index))
        nxt = "b%d" % (index + 1) if index + 1 < count else "done"
        lines.append("  br i1 %%c%d, label %%done, label %%%s"
                     % (index, nxt))
    lines.append("done:")
    lines.append("  ret i32 2")
    return "\n".join(lines) + "\n"


def _oracle_jmp_object(tmp_path):
    out = tmp_path / "jmp.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  JMP_CORPUS, "-o", out])
    assert result.returncode == 0, result.stderr
    return out


def _section_words(path, section):
    with open(path, "rb") as handle:
        data = handle.read()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        if data[base + row[0]:end].decode() == section:
            text = data[row[4]:row[4] + row[5]]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError("missing section %s" % section)


def _split_funcs(words):
    funcs, current = [], []
    for word in words:
        current.append(word)
        if word & 0xFF == 0x95:
            funcs.append(current)
            current = []
    assert not current, "trailing words after the last exit"
    return funcs


def _check_ja_targets(name, func):
    for slot, word in enumerate(func):
        if word & 0xFF == 0x05:
            target = slot + ((word >> 16) & 0xFFFF) + 1
            assert 0 <= target < len(func), (
                "%s: JA at %d lands outside at %d"
                % (name, slot, target))


@pytest.mark.parametrize("name", FUNC_ORDER)
def test_jmp_oracle_emission(tmp_path, name):
    words = _section_words(_oracle_jmp_object(tmp_path), ".text")
    funcs = _split_funcs(words)
    assert len(funcs) == 7, "corpus exit-chunk count moved"
    index = FUNC_ORDER.index(name)
    assert funcs[index] == FUNC_WORDS[name]


def test_jmp_oracle_switch_emission(tmp_path):
    words = _section_words(_oracle_jmp_object(tmp_path), ".text")
    funcs = _split_funcs(words)
    assert len(funcs) == 7, "corpus exit-chunk count moved"
    assert funcs[3] + funcs[4] + funcs[5] + funcs[6] == SWITCH_WORDS


@pytest.mark.parametrize("name", FUNC_ORDER)
def test_jmp_oracle_shape(tmp_path, name):
    func = FUNC_WORDS[name]
    assert func, "pin %s before shape checks" % name
    assert func[-1] == 0x95
    assert [word for word in func if word & 0xFF == 0x95] == [0x95], (
        "%s must carry exactly one trailing exit" % name)
    _check_ja_targets(name, func)


def test_jmp_oracle_switch_shape(tmp_path):
    words = _section_words(_oracle_jmp_object(tmp_path), ".text")
    assert words[-len(SWITCH_WORDS):] == SWITCH_WORDS
    assert [word for word in SWITCH_WORDS
            if word & 0xFF == 0x95], "switch shape must exit"
    assert not [word for word in SWITCH_WORDS
                if word & 0xFF == 0x05], (
        "switch lowers to a Jcc chain without JA")


def test_jmp_admit_diamond(tmp_path):
    result, report = check_cpu(tmp_path, module(DIAMOND_BODY), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


def test_jmp_admit_128_blocks(tmp_path):
    result, report = check_cpu(tmp_path, module(_chain_body(126)),
                               "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


@pytest.mark.parametrize("body,code,message", [
    (LOOP_BODY, "MBPF319", "cyclic CFG is outside the admitted no-loop slice"),
    (SWITCH_BODY, "MBPF319", "instruction is outside the finite source subset"),
    ("CHAIN127", "MBPF320", "basic-block analysis budget exhausted"),
])
def test_jmp_refused_jump_shapes(tmp_path, body, code, message):
    text = module(_chain_body(127)) if body == "CHAIN127" else module(body)
    result, report = check_cpu(tmp_path, text, "v3")
    refusal(result, report, code)
    assert message in report["diagnostics"][0]["explanation"]


def _exhibit_words(tmp_path):
    raw = capture(tmp_path, JMP_EXHIBIT, "llvm")
    adapted = tmp_path / "exhibit.bpf.ll"
    proc = subprocess.run(
        [sys.executable, str(JMP_ADAPTER), "--input", str(raw),
         "--output", str(adapted)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = tmp_path / "exhibit.o"
    result = llc(["-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
                  str(adapted), "-o", str(out)])
    assert result.returncode == 0, result.stderr
    return _section_words(out, "xdp")


def test_jmp_mojo_exhibit_no_ja(tmp_path):
    words = _exhibit_words(tmp_path)
    assert len(words) > 8, "exhibit object vacuous"
    assert [word for word in words if word & 0xFF == 0x85], (
        "merged subprogram call missing")
    assert words[-1] == 0x95
    assert [word for word in words if word & 0xFF == 0x95] == [0x95]
    assert not [word for word in words if word & 0xFF == 0x05], (
        "Amendment A2: the admitted Mojo diamond stays JA-free "
        "(backend merges the two call sites); a JA here reopens "
        "the amendment")
