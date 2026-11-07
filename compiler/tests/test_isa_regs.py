# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/registers/v3: register roles + call-convention pins (ISA-01).

Oracle register-allocation words (pinned llc 22.1.8, recorded at
RED, verified by decoding before pinning): r1-r5 arguments, r0
return, r6-r9 callee-saved, r10 frame slots, and the local-call
sequence. Audit companions pin the existing single-arg rules, and
the oracle's own 6-argument rejection pins the upstream boundary.
See the leaf packet for the frozen vector list.
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
    subprog_module,
    subprog_spec,
)
from test_target_model import (
    ROOT,
    module,
    refusal,
    spec,
)

REGS_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "regs" / "oracle-regs.ll"
SIXARGS_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "regs" / "oracle-sixargs.ll"

# Pinned oracle role words (observed at RED, decode-verified by
# hand: regs bytes checked dst/src, offsets/immediates checked).
FIVE_ARGS_WORDS = [4287, 8207, 12303, 16399, 20495, 149]
CALLER_SAVED_WORDS = [22207, 18367, 14527, 10687,
                      18446744069414588549, 36879, 32783,
                      28687, 24591, 149]
SPILL_WORDS = [3675001, 4294457979, 3150713, 4293933691,
               2626425, 4293409403, 2102137, 4292885115,
               1578617, 1054585, 530553, 6521, 8639,
               18446744069414588549, 36879, 32783, 28687,
               24591, 4292911481, 4111, 4293435769, 4111,
               4293960057, 4111, 4294484345, 4111, 149]
CALLEE_WORDS = [4287, 180388626487, 149]
CALL_SEQ_WORDS = [30064771511, 18446744069414588549, 149]


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


def _oracle_regs_object(tmp_path):
    out = tmp_path / "regs.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  REGS_CORPUS, "-o", out])
    assert result.returncode == 0, result.stderr
    return _section_words(out, ".text")


def _split_funcs(words):
    funcs, current = [], []
    for word in words:
        current.append(word)
        if word & 0xFF == 0x95:
            funcs.append(current)
            current = []
    assert not current, "trailing words after the last exit"
    return funcs


def test_regs_oracle_five_args(tmp_path):
    funcs = _split_funcs(_oracle_regs_object(tmp_path))
    assert len(funcs) == 5, "corpus function count moved"
    assert funcs[0][0] == 0x10BF and funcs[0][-1] == 0x95
    assert funcs[0] == FIVE_ARGS_WORDS


def test_regs_oracle_caller_saved(tmp_path):
    funcs = _split_funcs(_oracle_regs_object(tmp_path))
    assert funcs[1] == CALLER_SAVED_WORDS


def test_regs_oracle_spill_slots(tmp_path):
    funcs = _split_funcs(_oracle_regs_object(tmp_path))
    assert funcs[2] == SPILL_WORDS


def test_regs_oracle_callee(tmp_path):
    funcs = _split_funcs(_oracle_regs_object(tmp_path))
    assert funcs[3] == CALLEE_WORDS


def test_regs_oracle_call_seq(tmp_path):
    funcs = _split_funcs(_oracle_regs_object(tmp_path))
    assert funcs[4] == CALL_SEQ_WORDS


def _r10_violation(word):
    # r10 is the read-only frame pointer: it appears only as the
    # memory base (STX low nibble / LDX high nibble), never as a
    # written destination or a value source.
    opcode = word & 0xFF
    low, high = (word >> 8) & 0xF, (word >> 12) & 0xF
    klass = opcode & 0x07
    if klass == 0x03:  # STX: value nibble must not be r10
        return high == 0xA
    if klass == 0x02:  # ST: no value register at all
        return high != 0x0
    if klass == 0x01:  # LDX: dst nibble must not be r10
        return low == 0xA
    if klass == 0x00:  # LD: dst nibble must not be r10
        return low == 0xA
    return low == 0xA or high == 0xA


def test_regs_oracle_r10_never_dst(tmp_path):
    words = _oracle_regs_object(tmp_path)
    assert words, "oracle object must not be empty"
    bad = [word for word in words if _r10_violation(word)]
    assert not bad, [hex(word) for word in bad]


def test_regs_oracle_sixargs_rejected(tmp_path):
    out = tmp_path / "sixargs.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  SIXARGS_CORPUS, "-o", out])
    assert result.returncode != 0, "llc must reject stack arguments"
    assert "stack arguments are not supported" in result.stderr


def test_regs_refused_two_arg_entry(tmp_path):
    text = module("entry:\n %t = trunc i64 %n to i32\n ret i32 %t\n",
                  header="i32 @xdp_entry(ptr noundef %ctx, i64 noundef %n)")
    result, report = check_cpu(tmp_path, text, "v3")
    refusal(result, report, "MBPF302")
    assert "C-ABI i32(AS0 pointer)" in report["diagnostics"][0]["explanation"]


def test_regs_refused_zero_arg_entry(tmp_path):
    text = module("entry:\n ret i32 2\n",
                  header="i32 @xdp_entry()")
    result, report = check_cpu(tmp_path, text, "v3")
    refusal(result, report, "MBPF302")
    assert "C-ABI i32(AS0 pointer)" in report["diagnostics"][0]["explanation"]


TWO_ARG_CALL_BODY = ("entry:\n  %v = tail call i64 @decide(i64 7, i64 8)\n"
                       "  %t = trunc i64 %v to i32\n  ret i32 %t\n")


def test_regs_refused_two_arg_subprog(tmp_path):
    callee = ("entry:\n %s = add i64 %n, %m\n ret i64 %s\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(
        callee, TWO_ARG_CALL_BODY,
        callee_param="i64 noundef %n, i64 noundef %m"))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, "MBPF302")
    assert "(i64)->i64" in report["diagnostics"][0]["explanation"]


def test_regs_refused_mangled_subprog(tmp_path):
    callee = "entry:\n %q = udiv i64 %n, 42\n ret i64 %q\n"
    body = subprog_module(callee, ENTRY_CALL_BODY)
    body = body.replace("@decide", '@"decide::helper"')
    source = tmp_path / "input.ll"
    source.write_text(body)
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, "MBPF302")
    assert "plain C identifier" in report["diagnostics"][0]["explanation"]


def test_regs_internal_linkage_subprog(tmp_path):
    # Pinned at RED: internal-linkage callees are refused (the
    # admitted slice needs dso_local definitions).
    callee = "entry:\n %q = udiv i64 %n, 42\n ret i64 %q\n"
    body = subprog_module(callee, ENTRY_CALL_BODY)
    body = body.replace("define dso_local i64 @decide(",
                        "define internal i64 @decide(")
    source = tmp_path / "input.ll"
    source.write_text(body)
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, "MBPF302")
    assert "(i64)->i64" in report["diagnostics"][0]["explanation"]
