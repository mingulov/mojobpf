# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Lowering proof: helper calls reach the backend as ordinary calls.

Builds the canonical map program through the genuine frontend and
adapter, then proves the lowered contract at three levels: the
adapted IR carries exactly the two ``inttoptr(ID)`` callees with no
remaining reserved references; the final object issues exactly
``call 1`` then ``call 2`` with conformant encoding; and the backend
machine IR shows ordinary call lowering (caller-saved clobbers,
arguments in r1..rN, result in r0, no compiler-placed stack). The
same three levels then cover the tracepoint event emitter: twelve
lowered callees in source order (helpers 1, 14, 1, 2, 8, 5, 14,
130, 1, 2, 1, 2), eleven object calls after backend tail-merging
of the two accounting arms, and twelve MIR calls with an empty
frame. A final test proves one-lane integer vectors scalarize to
plain BPF arithmetic. Needs the Mojo compiler and LLVM llc on
PATH; missing tools are an environment failure, never a pass.

Runnable directly (``python3 tests/ir/test_helper_lowering.py``) or
under any ``test_``-style runner. Standard library only.
"""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))

import audit  # noqa: E402
import mojo_ir_adapter as adapter  # noqa: E402

MAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile",
                          "map_roundtrip.mojo")
DELETE_SOURCE = os.path.join(REPO_ROOT, "tests", "compile",
                             "maps_delete1.mojo")
GETNEXT_ATTEMPT_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "maps_getnext_attempt.mojo"
)
EVENT_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_events", "emitter.mojo"
)
# The twelve lowered emitter callees in source order: filter
# lookup, filter PID/TID, sequence pair, CPU, clock, record
# PID/TID, ring-buffer output, then the success and failure
# accounting pairs.
EVENT_LOWERED = (
    audit.LOWERED_LOOKUP_RE,
    audit.LOWERED_PID_RE,
    audit.LOWERED_LOOKUP_RE,
    audit.LOWERED_UPDATE_RE,
    audit.LOWERED_CPU_RE,
    audit.LOWERED_KTIME_RE,
    audit.LOWERED_PID_RE,
    audit.LOWERED_OUTPUT_RE,
    audit.LOWERED_LOOKUP_RE,
    audit.LOWERED_UPDATE_RE,
    audit.LOWERED_LOOKUP_RE,
    audit.LOWERED_UPDATE_RE,
)
EVENT_HELPER_IDS = (1, 14, 1, 2, 8, 5, 14, 130, 1, 2, 1, 2)
# The backend tail-merges the two accounting arms' shared update
# epilogue, so the object carries eleven static calls: the
# straight-line prefix through the output call plus lookup,
# lookup, update.
EVENT_OBJECT_CALLS = (1, 14, 1, 2, 8, 5, 14, 130, 1, 1, 2)
ONELANE_FIXTURE = os.path.join(
    REPO_ROOT, "tests", "compile", "unsupported", "onelane_vector_ok.ll"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources",
                           "sdk")

BPF_OP_CALL = 0x85
BPF_OP_EXIT = 0x95
BPF_OP_ADD64RI = 0x07
BPF_OP_MOV64 = 0xBF

JAL_RE = re.compile(r"^\s*JAL (\d+),\s*csr,\s*(.*)$")
IMPLICIT_RE = re.compile(r"implicit(?:-def)?\s+(?:killed\s+)?\$r(\d+)")


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def mojo_emit(source):
    check_tools("mojo")
    workdir = tempfile.mkdtemp(prefix="lowering-proof-")
    out_path = os.path.join(workdir, "raw.ll")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm", "-I", SDK_INCLUDE,
            "-o", out_path, source,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(out_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    with open(out_path, "r", encoding="utf-8") as handle:
        return handle.read()


def run_llc(adapted_text, extra_args=()):
    check_tools("llc")
    workdir = tempfile.mkdtemp(prefix="lowering-proof-")
    ll_path = os.path.join(workdir, "adapted.ll")
    with open(ll_path, "w", encoding="utf-8") as handle:
        handle.write(adapted_text)
    return workdir, ll_path


def build_object(adapted_text):
    workdir, ll_path = run_llc(adapted_text)
    obj_path = os.path.join(workdir, "out.bpf.o")
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
            ll_path, "-o", obj_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(obj_path):
        raise AssertionError(
            "llc failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(obj_path, "rb") as handle:
        return handle.read()


def dump_mir(adapted_text):
    workdir, ll_path = run_llc(adapted_text)
    mir_path = os.path.join(workdir, "out.mir")
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3",
            "-stop-after=prologepilog", "-o", mir_path, ll_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(mir_path):
        raise AssertionError(
            "llc MIR dump failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(mir_path, "r", encoding="utf-8") as handle:
        return handle.read()


def section_bytes(image, wanted):
    """Return the bytes of one ELF section by name (minimal parser)."""
    (magic, klass, data, _ver, _abi) = struct.unpack_from(
        "4sBBBB", image, 0
    )
    assert magic == b"\x7fELF" and klass == 2 and data == 1, (
        "not a little-endian 64-bit ELF object"
    )
    (
        _phoff, e_shoff, _flags, _ehsize, _phentsize, _phnum,
        e_shentsize, e_shnum, e_shstrndx,
    ) = struct.unpack_from("<QQIHHHHHH", image, 0x20)
    str_off = e_shoff + e_shstrndx * e_shentsize
    (str_sec_off,) = struct.unpack_from("<Q", image, str_off + 0x18)
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (name, _, _, _, sec_off, size) = struct.unpack_from(
            "<IIQQQQ", image, off
        )
        end = image.index(b"\x00", str_sec_off + name)
        section = image[str_sec_off + name:end].decode("ascii")
        if section == wanted:
            return image[sec_off:sec_off + size]
    raise AssertionError("missing %s section" % wanted)


def decode_insns(code):
    """Decode raw xdp bytes into (opcode, dst, src, off, imm) tuples."""
    assert len(code) % 8 == 0, "xdp code is not an insn multiple"
    insns = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        regs = code[offset + 1]
        (off,) = struct.unpack_from("<h", code, offset + 2)
        (imm,) = struct.unpack_from("<i", code, offset + 4)
        insns.append((opcode, regs & 0xF, regs >> 4, off, imm))
        # A 64-bit immediate load occupies two slots.
        if opcode == 0x18:
            offset += 16
        else:
            offset += 8
    return insns


_BUILT = {}


def built():
    if "adapted" not in _BUILT:
        raw = mojo_emit(MAP_SOURCE)
        assert adapter.validate(raw) == "map"
        _BUILT["raw"] = raw
        _BUILT["adapted"] = adapter.adapt(raw)
    return _BUILT["raw"], _BUILT["adapted"]


def test_lowered_callee_lines():
    raw, adapted = built()
    lowered = [
        line.strip()
        for line in adapted.splitlines()
        if "inttoptr" in line
    ]
    assert len(lowered) == 2, (
        "expected exactly two lowered helper calls, got %r" % lowered
    )
    assert audit.LOWERED_LOOKUP_RE.match(lowered[0]), lowered[0]
    assert audit.LOWERED_UPDATE_RE.match(lowered[1]), lowered[1]
    # The argument SSA values survive lowering unchanged.
    assert "(i64 %3, ptr %2)" in lowered[0], lowered[0]
    assert "(i64 %13, ptr %12, ptr %8, i64 0)" in lowered[1], lowered[1]
    for reserved in audit.RESERVED_NAMES:
        assert reserved not in adapted, (
            "lowered IR still references %s" % reserved
        )
    assert '"call 1"' not in adapted and '"call 2"' not in adapted, (
        "lowered IR still invokes helpers through assembly"
    )
    print("PASS lowered callees: %s" % lowered)


def test_backend_conformance_bytes():
    _, adapted = built()
    code = section_bytes(build_object(adapted), "xdp")
    calls = [
        (off, imm)
        for opcode, dst, src, off, imm in decode_insns(code)
        if opcode == BPF_OP_CALL
    ]
    assert [imm for _, imm in calls] == [1, 2], (
        "expected exactly [lookup, update] helper calls, got %r"
        % (calls,)
    )
    for opcode, dst, src, off, imm in decode_insns(code):
        if opcode == BPF_OP_CALL:
            assert src == 0 and off == 0, (
                "helper call encoding is not src=0/off=0: %r"
                % ((opcode, dst, src, off, imm),)
            )
    assert any(
        opcode == BPF_OP_EXIT for opcode, _, _, _, _ in decode_insns(code)
    ), "xdp code has no exit instruction"
    print("PASS backend calls: %s" % (calls,))


def _lowered_fixture(source, want_id, want_shape):
    raw = mojo_emit(source)
    assert adapter.validate(raw) == "map"
    adapted = adapter.adapt(raw)
    lowered = [
        line.strip()
        for line in adapted.splitlines()
        if "inttoptr" in line
    ]
    assert len(lowered) == 1, (
        "expected exactly one lowered helper call, got %r" % lowered
    )
    assert want_shape.match(lowered[0]), lowered[0]
    for reserved in audit.RESERVED_NAMES:
        assert reserved not in adapted, (
            "lowered IR still references %s" % reserved
        )
    code = section_bytes(build_object(adapted), "xdp")
    calls = [
        imm
        for opcode, _dst, _src, _off, imm in decode_insns(code)
        if opcode == BPF_OP_CALL
    ]
    assert calls == [want_id], (
        "expected exactly [helper %d], got %r" % (want_id, calls)
    )
    return lowered


def test_delete_lowers_to_helper_3():
    lowered = _lowered_fixture(
        DELETE_SOURCE, 3, audit.LOWERED_DELETE_RE
    )
    print("PASS lowered delete callee: %s" % lowered)


def test_from_bpf_getnext_refused():
    # The kernel offers no from-program map-iteration helper, so
    # the long-spelled attempt never reaches lowering: the audit
    # refuses its unreserved direct call with MBPF303.
    raw = mojo_emit(GETNEXT_ATTEMPT_SOURCE)
    try:
        adapter.adapt(raw)
    except adapter.AdapterError as exc:
        assert exc.code == "MBPF303", exc.code
        assert "__mojobpf_get_next_key_v1" in exc.explanation, exc
    else:
        raise AssertionError(
            "from-program get-next-key adapted but must be refused"
        )
    print("PASS from-program get-next-key refused with MBPF303")


def test_stack_immediates_are_slots_and_increment():
    # Every 64-bit add-immediate in the qualified map object is one
    # of the two audited stack-slot offsets (-4 key, -16 value) or
    # the round-trip increment (+1) from the Mojo source. Combined
    # with the audit (no alloca) and the MIR check below (no
    # compiler-placed frame), no other stack traffic can collide
    # with the fixed slots in this program.
    _, adapted = built()
    code = section_bytes(build_object(adapted), "xdp")
    imms = sorted(
        imm
        for opcode, _, _, _, imm in decode_insns(code)
        if opcode == BPF_OP_ADD64RI
    )
    assert imms == [-16, -4, -4, 1], (
        "unexpected add-immediate set (slots plus increment): %r"
        % (imms,)
    )
    print("PASS stack immediates: %s" % (imms,))


def test_mir_call_model():
    _, adapted = built()
    mir = dump_mir(adapted)
    jals = [
        JAL_RE.match(line)
        for line in mir.splitlines()
        if line.strip().startswith("JAL ")
    ]
    assert len(jals) == 2 and all(jals), (
        "expected exactly two lowered JAL calls"
    )
    first_id, first_tail = jals[0].group(1), jals[0].group(2)
    second_id, second_tail = jals[1].group(1), jals[1].group(2)
    assert (first_id, second_id) == ("1", "2"), (first_id, second_id)
    # Arguments arrive in r1..rN and the result returns through r0;
    # the csr regmask carries the caller-saved clobbers.
    first_regs = IMPLICIT_RE.findall(first_tail)
    assert "1" in first_regs and "2" in first_regs, first_tail
    assert "implicit-def $r0" in first_tail, first_tail
    second_regs = IMPLICIT_RE.findall(second_tail)
    for reg in ("1", "2", "3", "4"):
        assert reg in second_regs, second_tail
    assert re.search(r"implicit-def (dead )?\$r0", second_tail), (
        "update result must be defined (dead: unused): %s" % second_tail
    )
    body = mir.split("body:")[1]
    assert re.search(r"^fixedStack:\s*\[\]", mir, re.M), (
        "expected no fixed frame objects"
    )
    assert re.search(r"^stack:\s*\[\]", mir, re.M), (
        "expected no managed spill slots"
    )
    assert not re.search(r"\$r(6|7|8|9|10)\s*=", body), (
        "callee-saved or frame registers must not be written"
    )
    assert not re.search(r"implicit-def \$r[6789]\b", body), (
        "callee-saved registers must not be clobbered"
    )
    print("PASS MIR: JAL 1/2 with csr, r0 result, empty frame")


def built_event():
    if "event_adapted" not in _BUILT:
        raw = mojo_emit(EVENT_SOURCE)
        assert adapter.validate(raw) == "event"
        _BUILT["event_raw"] = raw
        _BUILT["event_adapted"] = adapter.adapt(raw)
    return _BUILT["event_raw"], _BUILT["event_adapted"]


def test_event_lowered_callee_lines():
    _, adapted = built_event()
    lowered = [
        line.strip()
        for line in adapted.splitlines()
        if "inttoptr" in line
    ]
    assert len(lowered) == 12, (
        "expected exactly twelve lowered helper calls, got %r"
        % (lowered,)
    )
    for line, shape in zip(lowered, EVENT_LOWERED):
        assert shape.match(line), line
    for reserved in audit.RESERVED_NAMES:
        assert reserved not in adapted, (
            "lowered IR still references %s" % reserved
        )
    print("PASS event lowered callees: %d in source order" % len(lowered))


def test_event_backend_conformance_bytes():
    _, adapted = built_event()
    code = section_bytes(
        build_object(adapted), "tracepoint/syscalls/sys_enter_getpid"
    )
    insns = decode_insns(code)
    calls = [imm for opcode, _, _, _, imm in insns
             if opcode == BPF_OP_CALL]
    assert calls == list(EVENT_OBJECT_CALLS), (
        "expected object calls %r, got %r" % (EVENT_OBJECT_CALLS, calls)
    )
    for opcode, _dst, src, off, imm in insns:
        if opcode == BPF_OP_CALL:
            assert src == 0 and off == 0, (
                "helper call encoding is not src=0/off=0: %r"
                % ((opcode, _dst, src, off, imm),)
            )
    assert any(
        opcode == BPF_OP_EXIT for opcode, _, _, _, _ in insns
    ), "tracepoint code has no exit instruction"
    print("PASS event backend calls: %s" % (calls,))


def test_event_mir_call_model():
    _, adapted = built_event()
    mir = dump_mir(adapted)
    jals = [
        JAL_RE.match(line)
        for line in mir.splitlines()
        if line.strip().startswith("JAL ")
    ]
    assert len(jals) == 12 and all(jals), (
        "expected exactly twelve lowered JAL calls, got %d"
        % len(jals)
    )
    ids = tuple(match.group(1) for match in jals)
    assert ids == tuple(str(n) for n in EVENT_HELPER_IDS), ids
    for match, want in zip(jals, EVENT_HELPER_IDS):
        tail = match.group(2)
        if want in (14, 5, 8):
            regs = IMPLICIT_RE.findall(tail)
            for reg in ("1", "2", "3", "4", "5"):
                assert reg not in regs, tail
        elif want == 130:
            regs = IMPLICIT_RE.findall(tail)
            for reg in ("1", "2", "3"):
                assert reg in regs, tail
        elif want == 1:
            regs = IMPLICIT_RE.findall(tail)
            assert "1" in regs and "2" in regs, tail
        else:
            regs = IMPLICIT_RE.findall(tail)
            for reg in ("1", "2", "3", "4"):
                assert reg in regs, tail
        assert re.search(r"implicit-def (dead )?\$r0", tail), (
            "helper %d result must be defined: %s" % (want, tail)
        )
    assert re.search(r"^fixedStack:\s*\[\]", mir, re.M), (
        "expected no fixed frame objects"
    )
    assert re.search(r"^stack:\s*\[\]", mir, re.M), (
        "expected no managed spill slots"
    )
    print("PASS event MIR: twelve JALs with csr, r0 results, empty frame")


def test_onelane_scalarization():
    with open(ONELANE_FIXTURE, "r", encoding="utf-8") as handle:
        fixture = handle.read()
    assert adapter.validate(fixture) == "classifier"
    code = section_bytes(build_object(adapter.adapt(fixture)), "xdp")
    insns = decode_insns(code)
    assert [opcode for opcode, _, _, _, _ in insns] == [
        0x79, 0x04, 0x95,
    ], ["0x%02x" % opcode for opcode, _, _, _, _ in insns]
    assert insns[1][4] == 41, (
        "expected the scalarized +41 add-immediate, got %r"
        % (insns[1],)
    )
    print("PASS one-lane add scalarized to w0 += 41")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    for name in names:
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("helper lowering: adapted IR, object bytes, MIR, scalar proof")
    return 0


if __name__ == "__main__":
    sys.exit(main())
