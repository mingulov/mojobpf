# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/atomic/ops: atomicrmw/cmpxchg refuse, the STX|ATOMIC surface pins.

The audit refuses every atomic construct (fence/atomicrmw ->
exit 4, MBPF319 at entries and MBPF304 in subprograms;
cmpxchg -> exit 4, MBPF305 first-and-only); no admitted Mojo
emits atomics. Oracle pins cover the llc emission cells (rmw
add/sub/and/or/xor/xchg x 64/32, cmpxchg x 64/32/weak,
nofetch x2, monotonic x2), the ordering-boundary FETCH rule
(seq_cst FETCH / monotonic bare, usedness irrelevant), and
the hand-asm bare-XADD + LOAD_ACQ + STORE_REL words.
Structural asserts pin one-STX|ATOMIC-word functions with
UAPI immediates and trailing exits. See the leaf packet for
the frozen vector list and the crash set.
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
    CASES,
    ROOT,
    digest,
    module,
    refusal,
    run,
)

ATOMIC_FIX = ROOT / "tests" / "fixtures" / "isa" / "atomic"
ATOMIC_CORPUS = ATOMIC_FIX / "oracle-atomic.ll"
ATOMIC_ASM = ATOMIC_FIX / "oracle-atomic.s"

FUNC_NAMES = [
    "rmw_add_64", "rmw_add_32",
    "rmw_sub_64", "rmw_sub_32",
    "rmw_and_64", "rmw_and_32",
    "rmw_or_64", "rmw_or_32",
    "rmw_xor_64", "rmw_xor_32",
    "rmw_xchg_64", "rmw_xchg_32",
    "cmpxchg_64", "cmpxchg_32", "cmpxchg_weak",
    "nofetch_add_64", "nofetch_xchg_32",
    "monotonic_add_64_used", "monotonic_add_64_unused",
]

# Functions selecting bare XADD (monotonic ordering); every
# other corpus function selects FETCH (seq_cst ordering).
MONOTONIC_FUNCS = (
    "monotonic_add_64_used", "monotonic_add_64_unused",
)

# Exact words per function, observed at RED, decode-verified
# (one STX|ATOMIC word each: class 0xDB/0xC3, UAPI imm, regs
# ptr/value, exit-trailing).
FUNC_WORDS = {
    "rmw_add_64": [0x5000000B7, 0x1000001DB, 0x95],
    "rmw_add_32": [0x5000000B4, 0x1000001C3, 0x95],
    "rmw_sub_64": [0x5000000B7, 0x87, 0x1000001DB, 0x95],
    "rmw_sub_32": [0x5000000B4, 0x84, 0x1000001C3, 0x95],
    "rmw_and_64": [0x5000000B7, 0x51000001DB, 0x95],
    "rmw_and_32": [0x5000000B4, 0x51000001C3, 0x95],
    "rmw_or_64": [0x5000000B7, 0x41000001DB, 0x95],
    "rmw_or_32": [0x5000000B4, 0x41000001C3, 0x95],
    "rmw_xor_64": [0x5000000B7, 0xA1000001DB, 0x95],
    "rmw_xor_32": [0x5000000B4, 0xA1000001C3, 0x95],
    "rmw_xchg_64": [0x5000000B7, 0xE1000001DB, 0x95],
    "rmw_xchg_32": [0x5000000B4, 0xE1000001C3, 0x95],
    "cmpxchg_64": [0x2000002B7, 0x1000000B7, 0xF1000021DB, 0x95],
    "cmpxchg_32": [0x2000002B4, 0x1000000B4, 0xF1000021C3, 0x95],
    "cmpxchg_weak": [0x2000002B7, 0x1000000B7, 0xF1000021DB, 0x95],
    "nofetch_add_64": [0x5000002B7, 0x1000021DB, 0x7000000B4, 0x95],
    "nofetch_xchg_32": [0x5000002B4, 0xE1000021C3, 0x7000000B4, 0x95],
    "monotonic_add_64_used": [0x5000000B7, 0x1DB, 0x95],
    "monotonic_add_64_unused": [0x5000002B7, 0x21DB, 0x7000000B4, 0x95],
}

# Hand-asm corpus words (bare XADD + LOAD_ACQ + STORE_REL +
# exit), observed at RED, decode-verified.
ASM_WORDS = [0x21DB, 0x100000010DB, 0x110000021DB, 0x95]

# UAPI STX|ATOMIC immediates (linux/bpf.h): op | FETCH, plus
# the bare and acq/rel forms.
UAPI_IMM = {
    0x00, 0x01, 0x40, 0x41, 0x50, 0x51, 0xA0, 0xA1,
    0xE1, 0xF1, 0x100, 0x110,
}


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
    out = tmp_path / "oracle-atomic.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  str(ATOMIC_CORPUS), "-o", str(out)])
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
    out = tmp_path / "oracle-atomic-asm.o"
    result = run([tool("clang"), "--target=bpf", "-mcpu=v3",
                  "-c", str(ATOMIC_ASM), "-o", str(out)])
    assert result.returncode == 0, result.stderr
    return _section_words(out, ".text")


def _atomic_words(words):
    return [(index, word) for index, word in enumerate(words)
            if word & 0xFF in (0xDB, 0xC3)]


def test_atomic_oracle_emission(tmp_path):
    funcs = _oracle_functions(tmp_path)
    assert len(funcs) == len(FUNC_NAMES) == 19
    for name, words in zip(FUNC_NAMES, funcs):
        assert words == FUNC_WORDS[name], name


def test_atomic_shape_and_imm(tmp_path):
    funcs = _oracle_functions(tmp_path)
    for name, words in zip(FUNC_NAMES, funcs):
        found = _atomic_words(words)
        assert len(found) == 1, (name, found)
        assert words[-1] == 0x95, name
        imm = (found[0][1] >> 32) & 0xFFFFFFFF
        assert imm in UAPI_IMM, (name, hex(imm))
        width = 64 if "64" in name or "weak" in name else 32
        want = 0xDB if width == 64 else 0xC3
        assert found[0][1] & 0xFF == want, (name, hex(found[0][1]))


def test_atomic_fetch_rule(tmp_path):
    # FETCH rule: ordering is the boundary (seq_cst selects
    # FETCH, monotonic selects bare XADD), usedness is
    # irrelevant. Bare hand-asm forms ride the hand-asm
    # oracle; other orderings are unobserved (non-claim).
    funcs = _oracle_functions(tmp_path)
    for name, words in zip(FUNC_NAMES, funcs):
        assert words == FUNC_WORDS[name], name
        for _, word in _atomic_words(words):
            imm = (word >> 32) & 0xFFFFFFFF
            if name in MONOTONIC_FUNCS:
                assert imm == 0x00, (name, hex(imm))
                assert word & 0xFF == 0xDB, (name, hex(word))
            else:
                assert imm & 0x01, (name, hex(imm))


def test_atomic_weak_equals_strong(tmp_path):
    funcs = _oracle_functions(tmp_path)
    by_name = dict(zip(FUNC_NAMES, funcs))
    weak = [word for _, word in
            _atomic_words(by_name["cmpxchg_weak"])]
    strong = [word for _, word in
              _atomic_words(by_name["cmpxchg_64"])]
    assert len(weak) == len(strong) == 1
    assert (weak[0] & 0xFFFFFFFF00000000) == (
        strong[0] & 0xFFFFFFFF00000000)


def test_atomic_asm_words(tmp_path):
    words = _asm_words(tmp_path)
    assert words == ASM_WORDS


def test_atomic_acqrel_decode(tmp_path):
    words = _asm_words(tmp_path)
    assert words == ASM_WORDS
    _, bare = _atomic_words(words)[0]
    assert bare == 0x21DB, hex(bare)
    imms = [(word >> 32) & 0xFFFFFFFF
            for _, word in _atomic_words(words)]
    assert 0x100 in imms and 0x110 in imms, [hex(i) for i in imms]


REFUSED_BODIES = {
    "fence_seq_cst": (
        "entry:\n"
        "  fence seq_cst\n"
        "  ret i32 1\n"
    ),
    "rmw_add_seq_cst": (
        "entry:\n"
        "  %v = atomicrmw add ptr %ctx, i64 5 seq_cst\n"
        "  %t = trunc i64 %v to i32\n"
        "  ret i32 %t\n"
    ),
    "rmw_xchg_monotonic": (
        "entry:\n"
        "  %v = atomicrmw xchg ptr %ctx, i64 5 monotonic\n"
        "  %t = trunc i64 %v to i32\n"
        "  ret i32 %t\n"
    ),
}

CMPXCHG_BODY = (
    "entry:\n"
    "  %r = cmpxchg ptr %ctx, i64 1, i64 2 seq_cst seq_cst\n"
    "  %v = extractvalue { i64, i1 } %r, 0\n"
    "  %t = trunc i64 %v to i32\n"
    "  ret i32 %t\n"
)

# Entry-site atomic constructs refuse under the finite-source-subset
# gate (observed at RED), not the subprogram MBPF304 site.
REFUSED_CODE = "MBPF319"
REFUSED_MESSAGE = "instruction is outside the finite source subset"


@pytest.mark.parametrize("shape", sorted(REFUSED_BODIES))
def test_atomic_refused_shapes(tmp_path, shape):
    result, report = check_cpu(
        tmp_path, module(REFUSED_BODIES[shape]), "v3")
    refusal(result, report, REFUSED_CODE)
    assert REFUSED_MESSAGE in report["diagnostics"][0]["explanation"]


def test_atomic_cmpxchg_aggregate_face(tmp_path):
    # cmpxchg never reaches an atomicity check: its {i64, i1}
    # result refuses as aggregate-typed (first and only
    # diagnostic), at the entry site ...
    result, report = check_cpu(tmp_path, module(CMPXCHG_BODY), "v3")
    refusal(result, report, "MBPF305")
    assert len(report["diagnostics"]) == 1
    assert "aggregate" in report["diagnostics"][0]["explanation"]


def test_atomic_cmpxchg_subprog_aggregate_face(tmp_path):
    # ... and at the subprogram site alike.
    callee = ("entry:\n"
              "  %r = cmpxchg ptr null, i64 1, i64 2 seq_cst seq_cst\n"
              "  %v = extractvalue { i64, i1 } %r, 0\n"
              "  ret i64 %v\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, _ = lower(tmp_path, source, subprog_spec())
    refusal(result, report, "MBPF305")
    assert len(report["diagnostics"]) == 1


# Subprogram face, observed at RED (Audit.cpp:957 site).
SUBPROG_REFUSED_CODE = "MBPF304"
SUBPROG_REFUSED_MESSAGE = "atomic or varargs machinery is outside the slice"


def test_atomic_refused_subprog_shape(tmp_path):
    # The Audit.cpp:957 MBPF304 site is subprogram-scoped: an
    # atomicrmw in the bound callee names it.
    callee = ("entry:\n"
              "  %v = atomicrmw add ptr null, i64 5 seq_cst\n"
              "  ret i64 %v\n")
    source = tmp_path / "input.ll"
    source.write_text(subprog_module(callee, ENTRY_CALL_BODY))
    result, report, _ = lower(tmp_path, source, subprog_spec())
    refusal(result, report, SUBPROG_REFUSED_CODE)
    assert SUBPROG_REFUSED_MESSAGE in report["diagnostics"][0][
        "explanation"]


def test_atomic_admitted_companion(tmp_path):
    # Pointer arithmetic without atomicity admits: the MBPF319
    # refusal keys on the atomic instruction, not the pointer
    # operand (and the operand-free fence vector agrees).
    body = (
        "entry:\n"
        "  %p1 = getelementptr inbounds i32, ptr %ctx, i32 1\n"
        "  ret i32 2\n"
    )
    result, report = check_cpu(tmp_path, module(body), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report is not None and report["ok"] is True
