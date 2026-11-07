# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/mem/load-store: memory selection + contract pins (ISA-01).

Oracle load/store emission words (pinned llc 22.1.8, recorded at
RED, verified by decoding before pinning), the MEMSX/ST absence
pins, and audit companions for the existing load/store/contract
rules. The companions mutate a genuine-shape scaffold in memory
(the scaffold text mirrors mojo-emitted IR; the baseline
admission test proves the scaffold itself is valid). See the leaf
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
    subprog_module,
    subprog_spec,
)
from test_target_model import (
    ROOT,
    module,
    refusal,
)

MEM_CORPUS = ROOT / "tests" / "fixtures" / "isa" / "mem" / "oracle-mem.ll"

# Pinned oracle memory words, one list per corpus function index
# (observed at RED, decode-verified by hand: class/mode/size,
# regs bytes, offsets/immediates checked).
FUNC_WORDS = {
    "ld_b_off": [921713, 149],
    "ld_h": [921705, 149],
    "ld_w": [266337, 149],
    "ld_dw": [4217, 149],
    "ld_sx_b": [921713, 240518168679, 240518168775, 149],
    "ld_sx_h": [921705, 206158430311, 206158430407, 149],
    "ld_sx_w": [266337, 137438953575, 137438953671, 149],
    "st_b": [8563, 149],
    "st_h": [270699, 149],
    "st_w": [270691, 149],
    "st_dw": [8571, 149],
    "st_imm_w": [180388627124, 270691, 149],
    "st_imm_dw": [30064771767, 8571, 149],
    # ld_imm64: 0x18 low word (0x89abcdef) + high word
    # (0x01234567); the 0x00 "opcode" is the high half.
    "ld_imm64": [9920249030594527256, 81985526906748928, 149],
    # alloca_use: the slot store survives while the reload is
    # forwarded (backend quirk, pinned as observed).
    "alloca_use": [4287, 4294445691, 4294967303, 149],
}
FUNC_ORDER = list(FUNC_WORDS)


# Genuine-shape entry scaffold (bounds edge + ctx words + one
# packet byte load), mirroring mojo-emitted IR. The baseline test
# proves it is admitted; companions mutate exactly one shape.
SCAFFOLD_BODY = """entry:
  %2 = load i32, ptr %ctx, align 4
  %3 = zext i32 %2 to i64
  %4 = getelementptr inbounds i32, ptr %ctx, i32 1
  %5 = load i32, ptr %4, align 4
  %6 = add i64 %3, 24
  %7 = zext i32 %5 to i64
  %8 = icmp ugt i64 %6, %7
  br i1 %8, label %9, label %10

9:
  br label %18

10:
  %11 = call ptr asm "", "=r,0"(i64 %3)
  %12 = getelementptr inbounds i8, ptr %11, i32 14
  %13 = load i8, ptr %12, align 1
  %14 = zext i8 %13 to i64
  %15 = add i64 %14, 5
  %16 = icmp ugt i64 %15, 10
  %17 = select i1 %16, i32 1, i32 2
  br label %18

18:
  %19 = phi i32 [ %17, %10 ], [ 2, %9 ]
  ret i32 %19
"""


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


def _oracle_mem_object(tmp_path):
    out = tmp_path / "mem.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  MEM_CORPUS, "-o", out])
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


@pytest.mark.parametrize("name", FUNC_ORDER)
def test_mem_oracle_emission(tmp_path, name):
    funcs = _split_funcs(_oracle_mem_object(tmp_path))
    assert len(funcs) == 15, "corpus function count moved"
    assert funcs[0][0] & 0xFF == 0x71 and funcs[0][-1] == 0x95
    assert funcs[FUNC_ORDER.index(name)] == FUNC_WORDS[name]


def test_mem_oracle_no_memsx(tmp_path):
    # Sign extension on v3 lowers to LDX + shifts (MEMSX selects
    # only on v4+). Re-verified at RED; a MEMSX word here would
    # pin instead.
    words = _oracle_mem_object(tmp_path)
    assert not [word for word in words
                if word & 0xFF in (0x81, 0x89, 0x91)]


def test_mem_oracle_no_st(tmp_path):
    # Immediate stores expand to MOV-K + STX (no ST word for any
    # probed width/sign). Re-verified at RED; an ST word here
    # would pin instead.
    words = _oracle_mem_object(tmp_path)
    assert not [word for word in words
                if word & 0xFF in (0x62, 0x6A, 0x72, 0x7A)]


def _mutate_scaffold(find, replace):
    assert SCAFFOLD_BODY.count(find) == 1, (find, SCAFFOLD_BODY)
    return module(SCAFFOLD_BODY.replace(find, replace, 1))


def test_mem_admit_baseline(tmp_path):
    # The scaffold itself must be admitted: without this anchor,
    # every refusal below could be blamed on broken scaffolding.
    result, report = check_cpu(tmp_path, module(SCAFFOLD_BODY), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


def test_mem_admit_sext(tmp_path):
    text = _mutate_scaffold("%14 = zext i8 %13 to i64",
                            "%14 = sext i8 %13 to i64")
    result, report = check_cpu(tmp_path, text, "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


@pytest.mark.parametrize("find,replace,code,message", [
    ("%13 = load i8, ptr %12, align 1\n  %14 = zext i8 %13 to i64",
     "%13 = load i32, ptr %12, align 4\n  %14 = zext i32 %13 to i64",
     "MBPF317", "packet load exceeds the admitted byte access"),
    ("%13 = load i8, ptr %12, align 1",
     "%13 = load i8, ptr %12, align 4",
     "MBPF319", "alignment/volatile/atomic contract"),
    ("%13 = load i8, ptr %12, align 1",
     "%13 = load i8, ptr %12, align 8",
     "MBPF319", "alignment/volatile/atomic contract"),
    ("%13 = load i8, ptr %12, align 1",
     "%13 = load volatile i8, ptr %12, align 1",
     "MBPF319", "alignment/volatile/atomic contract"),
    ("%2 = load i32, ptr %ctx, align 4\n  %3 = zext i32 %2 to i64",
     "%2 = load i16, ptr %ctx, align 2\n  %3 = zext i16 %2 to i64",
     "MBPF317", "context loads must read the two aligned u32"),
    ("%14 = zext i8 %13 to i64",
     "%14 = zext i8 %13 to i64\n  %qb = getelementptr inbounds i8, ptr %11, i32 15\n  store i8 %13, ptr %qb, align 1",
     "MBPF314", "store exceeds or escapes its proved scratch/map cell"),
    ("%2 = load i32, ptr %ctx, align 4",
     "%slot = alloca i64, align 8\n  %2 = load i32, ptr %ctx, align 4",
     "MBPF310", "user stack allocations are outside the shared-cell slice"),
])
def test_mem_refused_entry_shapes(tmp_path, find, replace, code, message):
    result, report = check_cpu(tmp_path, _mutate_scaffold(find, replace), "v3")
    refusal(result, report, code)
    assert message in report["diagnostics"][0]["explanation"]


@pytest.mark.parametrize("callee,code,message", [
    ("entry:\n %v = load i64, ptr null, align 8\n ret i64 %v\n",
     "MBPF303", "must not load"),
    ("entry:\n store i64 %n, ptr null, align 8\n ret i64 %n\n",
     "MBPF316", "must not store"),
    ("entry:\n %slot = alloca i64, align 8\n ret i64 %n\n",
     "MBPF310", "user stack allocations are outside the shared-cell slice"),
])
def test_mem_refused_subprog_shapes(tmp_path, callee, code, message):
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, output = lower(tmp_path, source, subprog_spec())
    refusal(result, report, code)
    assert message in report["diagnostics"][0]["explanation"]
