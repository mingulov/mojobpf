# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Language-subset gates: positives validate, negatives fail precisely.

Drives the frozen IR audit (``compiler/audit.py``) over genuine
frontend output for every fixture in this directory, plus the two
source-level negatives the frontend itself refuses. Each negative
names its rejecting layer and its exact evidence:

* source: the Mojo frontend exits nonzero (dynamic stack sizes and
  pointer/integer erasure are not expressible; the audit fixtures
  ``dynamic_alloca.ll`` and ``ptrtoint_op.ll`` pin the matching
  preflight codes for IR that carries those shapes anyway);
* preflight: the audit rejects with its exact ``MBPF3xx`` code at
  stage ``adapter.audit`` (escaping pointers, unqualified helpers);
* backend: ``llc`` refuses to emit an object for the excessive-frame
  program (its error names the BPF stack limit);
* kernel: the verifier rejects the out-of-bounds store object at
  load; that path is covered by the guest suite in
  ``tests/verifier/``, never here, so the layers stay distinct.

Positive programs must validate with their expected mode
(``classifier`` or ``map``) and satisfy their shape assertions: the
plain helper leaves no call behind, the stack array leaves no
``alloca`` behind, and the loop programs keep real loop structure in
the emitted IR.

Requires the working Mojo compiler and LLVM ``llc`` on PATH. A
missing tool is reported as an environment failure; a wrong verdict
is a proof failure. Neither ever passes.

Runnable directly (``python3
tests/compile/subset/test_subset_audit.py``) or under any
``test_``-style runner. Standard library only.
"""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import audit
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

SUBSET_DIR = os.path.dirname(os.path.abspath(__file__))
COMPILE_DIR = os.path.dirname(SUBSET_DIR)
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
SDK_INCLUDE = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)
UNSUPPORTED_DIR = os.path.join(COMPILE_DIR, "unsupported")

STAGE = "adapter.audit"

# Fixture stem -> expected audit mode. The excessive-frame program
# validates here on purpose: the audit sees no stack allocation (the
# frame pressure comes from carried SSA values), so the backend is
# its first rejecting layer. The out-of-bounds store validates as a
# map program: only the kernel verifier knows the map value size.
EXPECTED_MODES = {
    "subset_loop_sum": "classifier",
    "subset_call_inline": "classifier",
    "subset_stack_array": "classifier",
    "subset_casts": "classifier",
    "subset_checked_arith": "classifier",
    "subset_loop_pressure": "classifier",
    "subset_deep_stack": "classifier",
    "subset_oob_store": "map",
}

# Fixture stem -> (expected code, explanation substring).
EXPECTED_REJECTIONS = {
    "subset_escape_value": (
        "MBPF314",
        "must come from the prepared value slot",
    ),
    "subset_bad_helper": (
        "MBPF306",
        "never inline assembly",
    ),
}

# A stack allocation whose size is a runtime value. The frontend only
# accepts a compile-time count, so this source must fail before any
# IR exists.
DYNAMIC_STACK_SOURCE = """\
from std.memory import unsafe_stack_allocation
from mojobpf.packet import (
    GUARD_ACTION, XDP_DROP, XDP_PASS, XdpCtx, load_u8,
    packet_addr, packet_base, packet_len, packet_short,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var n = Int(packet_len(pkt) & 63) + 1
    var slot = unsafe_stack_allocation[n, UInt8]()
    slot[unsafe_offset=0] = load_u8(base, 14)
    if slot[unsafe_offset=0] == 1:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
"""

DYNAMIC_STACK_ERROR = "cannot use a dynamic value in a parameter list"

# Reinterpreting a packet pointer as an integer. The frontend rejects
# the type mismatch, so no erasure reaches the audit.
PTR_ERASE_SOURCE = """\
from mojobpf.packet import (
    GUARD_ACTION, XDP_DROP, XDP_PASS, XdpCtx,
    packet_addr, packet_base, packet_short,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var bits = rebind[Int64](base)
    if bits == 0:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
"""

PTR_ERASE_ERROR = (
    "rebind input type '!kgen.pointer<none>' does not match "
    "result type '!kgen.scalar<si64>'"
)

BACKEND_STACK_ERROR = "BPF stack limit is exceeded"

# The kernel stack budget in bytes. The within-budget loop program
# must use some stack (proving real spill pressure) without reaching
# this limit; the excessive program must be refused for exceeding it.
STACK_BUDGET = 512

CALL_RE = re.compile(r"(^|\s)call\b")
LABEL_DEF_RE = re.compile(r"^[A-Za-z0-9_.$-]+:$")


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools():
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (ADAPTER, SDK_INCLUDE):
        if not os.path.exists(path):
            raise EnvironmentFailure("missing repo path: %s" % path)


def mojo_emit(source, extra_args=()):
    """Compile one Mojo source to LLVM IR text (frontend only)."""
    if shutil.which("mojo") is None:
        raise EnvironmentFailure("mojo compiler not found on PATH")
    workdir = tempfile.mkdtemp(prefix="subset-audit-")
    out_path = os.path.join(workdir, "out.ll")
    argv = (
        ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS]
        + list(extra_args)
        + ["-I", SDK_INCLUDE, "-o", out_path, source]
    )
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )
    return proc, out_path


def emit_fixture(stem):
    """Emit IR for a subset fixture; fail loudly on frontend trouble."""
    source = os.path.join(SUBSET_DIR, stem + ".mojo")
    if not os.path.isfile(source):
        raise EnvironmentFailure("missing fixture: %s" % source)
    proc, out_path = mojo_emit(source)
    if proc.returncode != 0 or not os.path.isfile(out_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    lowered = proc.stderr.lower()
    if "error:" in lowered or "warning:" in lowered:
        raise AssertionError(
            "frontend diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    with open(out_path, "r", encoding="utf-8") as handle:
        return handle.read()


def emit_inline_source(source_text, name):
    """Emit IR for inline Mojo source; return (proc, ir or None)."""
    workdir = tempfile.mkdtemp(prefix="subset-inline-")
    source = os.path.join(workdir, name + ".mojo")
    with open(source, "w", encoding="utf-8") as handle:
        handle.write(source_text)
    proc, out_path = mojo_emit(source)
    if proc.returncode != 0 or not os.path.isfile(out_path):
        return proc, None
    with open(out_path, "r", encoding="utf-8") as handle:
        return proc, handle.read()


def read_unsupported(name):
    path = os.path.join(UNSUPPORTED_DIR, name)
    if not os.path.isfile(path):
        raise AssertionError("missing audit fixture: %s" % path)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def assert_rejected(text, code, stage, excerpt=None):
    try:
        audit.validate(text)
    except audit.AuditError as exc:
        assert exc.code == code, (
            "expected code %s, got %s (%s)" % (code, exc.code, exc)
        )
        assert exc.stage == stage, (
            "expected stage %s, got %s" % (stage, exc.stage)
        )
        if excerpt is not None:
            assert excerpt in exc.explanation, (
                "explanation %r must contain %r"
                % (exc.explanation, excerpt)
            )
        return exc
    raise AssertionError(
        "audit accepted input it must reject with %s" % code
    )


def format_case_result(text):
    """Short per-fixture audit summary for the direct-run log."""
    try:
        return "validates (%s)" % audit.validate(text)
    except audit.AuditError as exc:
        return "rejected %s/%s" % (exc.code, exc.stage)


def test_positive_programs_validate():
    check_tools()
    for stem in sorted(EXPECTED_MODES):
        mode = audit.validate(emit_fixture(stem))
        assert mode == EXPECTED_MODES[stem], (
            "%s validated as %s, expected %s"
            % (stem, mode, EXPECTED_MODES[stem])
        )
        print("PASS %s validates (%s)" % (stem, mode))


def test_positive_shapes():
    """Each positive keeps the IR shape its case promises."""
    check_tools()
    inline = emit_fixture("subset_call_inline")
    defines = [
        line for line in inline.splitlines() if line.startswith("define ")
    ]
    assert len(defines) == 1, (
        "inlined helper must leave exactly one definition, got %d"
        % len(defines)
    )
    calls = [
        line.strip()
        for line in inline.splitlines()
        if CALL_RE.search(line.strip())
    ]
    assert len(calls) == 1, (
        "inlined helper must leave exactly the reinterpretation "
        "call, got %d: %r" % (len(calls), calls)
    )
    print("PASS call-inline leaves a single call: %r" % (calls[0][:60],))
    stacked = emit_fixture("subset_stack_array")
    allocas = [line for line in stacked.splitlines() if "alloca" in line]
    assert not allocas, (
        "initialized stack array must promote to SSA, found: %r"
        % (allocas[:2],)
    )
    print("PASS stack-array promotes with no alloca")
    for stem in ("subset_loop_sum", "subset_loop_pressure"):
        text = emit_fixture(stem)
        labels = set()
        for raw in text.splitlines():
            line = audit.strip_comment(raw).strip()
            if LABEL_DEF_RE.match(line):
                labels.add(line[:-1])
        assert len(labels) > 2, (
            "%s must keep loop structure, found %d labels"
            % (stem, len(labels))
        )
        assert "phi " in text, "%s must keep phi nodes" % stem
        print("PASS %s keeps a loop (%d labels)" % (stem, len(labels)))
    casts = emit_fixture("subset_casts")
    assert "zext" in casts and "trunc" in casts, (
        "casts program must narrow and widen explicitly"
    )
    print("PASS casts program carries trunc+zext")
    checked = emit_fixture("subset_checked_arith")
    assert "mul " in checked, (
        "checked program must multiply in a narrow type"
    )
    print("PASS checked program carries narrow multiply")


def test_preflight_negatives_rejected():
    check_tools()
    for stem in sorted(EXPECTED_REJECTIONS):
        code, excerpt = EXPECTED_REJECTIONS[stem]
        exc = assert_rejected(emit_fixture(stem), code, STAGE, excerpt)
        print("PASS %s -> %s (%s)" % (stem, exc.code, exc.location))


def test_dynamic_stack_rejected_at_source():
    """Runtime stack sizes fail in the frontend, not downstream."""
    check_tools()
    proc, ir_text = emit_inline_source(
        DYNAMIC_STACK_SOURCE, "dynamic_stack"
    )
    assert proc.returncode != 0, (
        "frontend must reject a runtime stack size"
    )
    assert ir_text is None, "rejected source must emit no IR"
    assert DYNAMIC_STACK_ERROR in (proc.stderr or ""), (
        "frontend must name the dynamic count, got:\n%s"
        % (proc.stderr or "")[-800:]
    )
    print("PASS dynamic stack rejected at source")
    exc = assert_rejected(
        read_unsupported("dynamic_alloca.ll"), "MBPF310", STAGE
    )
    print("PASS dynamic-alloca IR pinned %s" % exc.code)


def test_ptr_erase_rejected_at_source():
    """Pointer/integer erasure fails in the frontend type check."""
    check_tools()
    proc, ir_text = emit_inline_source(PTR_ERASE_SOURCE, "ptr_erase")
    assert proc.returncode != 0, (
        "frontend must reject pointer/integer erasure"
    )
    assert ir_text is None, "rejected source must emit no IR"
    assert PTR_ERASE_ERROR in (proc.stderr or ""), (
        "frontend must name the type mismatch, got:\n%s"
        % (proc.stderr or "")[-800:]
    )
    print("PASS pointer erasure rejected at source")
    exc = assert_rejected(
        read_unsupported("ptrtoint_op.ll"), "MBPF311", STAGE
    )
    print("PASS ptrtoint IR pinned %s" % exc.code)


def adapt_fixture(stem, workdir):
    """Run the genuine adapter CLI over a fixture; return adapted IR."""
    raw_path = os.path.join(workdir, stem + ".ll")
    adapted_path = os.path.join(workdir, stem + ".bpf.ll")
    with open(raw_path, "w", encoding="utf-8") as handle:
        handle.write(emit_fixture(stem))
    proc = subprocess.run(
        [sys.executable, ADAPTER, "--input", raw_path,
         "--output", adapted_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (stem, proc.returncode, proc.stdout, proc.stderr)
        )
    return adapted_path


def run_llc(adapted_path, object_path):
    return subprocess.run(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            adapted_path,
            "-o",
            object_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )


def test_deep_stack_refused_by_backend():
    """The excessive frame passes the audit but llc refuses to emit."""
    check_tools()
    workdir = tempfile.mkdtemp(prefix="subset-deep-")
    adapted_path = adapt_fixture("subset_deep_stack", workdir)
    object_path = os.path.join(workdir, "deep.bpf.o")
    proc = run_llc(adapted_path, object_path)
    assert proc.returncode != 0, (
        "backend must refuse the excessive frame"
    )
    assert BACKEND_STACK_ERROR in (proc.stderr or ""), (
        "backend must name the stack limit, got:\n%s"
        % (proc.stderr or "")[-800:]
    )
    assert not os.path.isfile(object_path), (
        "refused backend run must emit no object"
    )
    print(
        "PASS deep stack refused by backend (exit %d)" % proc.returncode
    )


def bpf_max_stack_depth(object_path):
    """Deepest r10-relative access in the xdp section (bytes).

    Decodes the section bytes directly so the bound does not depend
    on a disassembler: any store to ``DST=r10`` with a negative
    offset contributes its depth.
    """
    with open(object_path, "rb") as handle:
        image = handle.read()
    if image[0:4] != b"\x7fELF" or len(image) < 64:
        raise AssertionError("not a 64-bit ELF object")
    _e_type, _e_machine, _e_version = struct.unpack_from(
        "<HHI", image, 16
    )
    e_shoff, _e_flags = struct.unpack_from("<QI", image, 40)
    (
        _e_ehsize,
        _e_phentsize,
        _e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHHHHH", image, 52)
    if e_shentsize < 64 or e_shnum == 0:
        raise AssertionError("ELF has no section table")
    headers = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        headers.append(struct.unpack_from("<IIQQQQIIQQ", image, off))
    strtab = headers[e_shstrndx]
    str_base, str_size = strtab[4], strtab[5]
    names = {}
    for index, header in enumerate(headers):
        begin = str_base + header[0]
        end = image.index(b"\x00", begin, str_base + str_size)
        names[image[begin:end].decode("ascii")] = index
    if "xdp" not in names:
        raise AssertionError("object has no xdp section")
    section = headers[names["xdp"]]
    code = image[section[4] : section[4] + section[5]]
    if len(code) % 8 != 0:
        raise AssertionError("xdp section is not whole instructions")
    deepest = 0
    for pos in range(0, len(code), 8):
        opcode, regs, offset = struct.unpack_from("<BBh", code, pos)
        op_class = opcode & 0x07
        if op_class not in (0x02, 0x03):
            continue
        if (regs & 0x0F) != 10 or offset >= 0:
            continue
        deepest = max(deepest, -offset)
    return deepest


def test_loop_pressure_frame_within_budget():
    """The 40-carried loop spills for real but stays legal."""
    check_tools()
    workdir = tempfile.mkdtemp(prefix="subset-pressure-")
    adapted_path = adapt_fixture("subset_loop_pressure", workdir)
    object_path = os.path.join(workdir, "pressure.bpf.o")
    proc = run_llc(adapted_path, object_path)
    assert proc.returncode == 0 and os.path.isfile(object_path), (
        "backend must accept the within-budget frame (exit %d):\n%s"
        % (proc.returncode, proc.stderr)
    )
    depth = bpf_max_stack_depth(object_path)
    assert 0 < depth <= STACK_BUDGET, (
        "within-budget frame must spill without reaching %d, "
        "measured %d" % (STACK_BUDGET, depth)
    )
    print("PASS loop pressure spills to depth %d" % depth)


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
    print("subset audit: all gate verdicts match their layers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
