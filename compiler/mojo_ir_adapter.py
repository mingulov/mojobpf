# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Retarget genuine Mojo-emitted host IR to little-endian BPF.

Pipeline position: ``mojo build --emit llvm`` (raw host IR) -> this adapter
-> ``llc -mtriple=bpfel -mcpu=v3 -filetype=obj`` (BPF object). The adapter
input must be real frontend output; the raw file is preserved alongside the
adapted file so reviewers can diff them.

All checks live in ``compiler/audit.py``; this module owns only the
enumerated transform below and delegates every validation to it. The
transform makes exactly these edits, each by exact match on known
lines (any mismatch fails loudly, so a reviewer can enumerate every
possible edit; there is no pattern rewriting):

1. host ``target datalayout`` -> the little-endian BPF data layout;
2. host ``target triple`` -> ``bpfel-unknown-none``;
3. the ``@xdp_entry`` definition line gains ``section "xdp"``;
4. the entrypoint ``attributes #0`` line (host ``target-cpu``/
   ``target-features``) -> ``attributes #0 = { "target-cpu"="v3" }``;
5. for each of the two admitted helper pseudo-calls (map mode only),
   the callee operand alone is replaced with the ordinary BPF
   helper-call representation: ``@__mojobpf_lookup_v1`` becomes
   ``inttoptr (i64 1 to ptr)`` and ``@__mojobpf_update_v1`` becomes
   ``inttoptr (i64 2 to ptr)``. Function type, argument SSA values,
   result, and position are preserved;
6. the two now-unreferenced reserved helper declarations are
   removed;
7. appended: for the classifier shape, a ``license`` section global
   declaring the project license plus the ``llvm.compiler.used``
   marker that keeps it (both mirror what Clang emits for a
   section-attributed license global); for the map shape, the same
   license global with a three-entry used marker, plus the standard
   ``.maps`` global for the one-entry array map and the 97-line
   ``.BTF`` assembler block describing it (both mirror the bytes of
   a Clang-built reference object; the independent map/BTF checks
   live in ``tests/elf/test_map_btf.py``).

Outside edits 1-7 the instruction graph is byte-identical; the
adapter re-verifies this after transforming (post-lowering audit)
and rejects its own output on any other drift. The lookup and
update operations are explicitly selected in Mojo (the SDK wrappers
call the reserved declarations); the adapter introduces only their
BPF ABI representation, the register effects ordinary call
lowering provides, and declared metadata. It invents no lookups,
increments, conditions, retries, replacement results, or
application algorithms.

The admitted program shapes are the classifier (one tied
register-reinterpretation cast, nothing else) and the map round
trip (one reinterpretation, two map-address loads, two key-slot and
one value-slot preparations, one lookup call, one update call).
Anything else — including helper invocations through inline
assembly, which cannot model the call contract — is rejected.
Production use of any broader transform must move to LLVM APIs;
this exact-match adapter is deliberately limited to the two known
single-entrypoint shapes.
"""

import argparse
import os
import sys


def _load_audit():
    """Import the sibling audit module under its canonical name.

    Plain ``import audit`` works when this directory is on ``sys.path``
    (command-line use, test runners); otherwise the module is loaded
    from this file's directory and registered as ``audit`` so every
    importer shares one module object either way.
    """
    try:
        import audit as audit_module

        return audit_module
    except ImportError:
        pass
    import importlib.util

    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "audit.py")
    spec = importlib.util.spec_from_file_location("audit", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load audit module: %s" % path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit"] = module
    spec.loader.exec_module(module)
    return module


audit = _load_audit()

# Rejections carry the audit's stable MBPF3xx codes; the historical
# AdapterError name stays as an alias for existing callers.
AdapterError = audit.AuditError

# Validation shapes shared with the audit (single definitions live
# in audit.py; the names below keep working for existing importers).
ASM_CALL_RE = audit.ASM_CALL_RE
MAPADDR_CALL_RE = audit.MAPADDR_CALL_RE
KEYSLOT_CALL_RE = audit.KEYSLOT_CALL_RE
VALSLOT_CALL_RE = audit.VALSLOT_CALL_RE
LOOKUP_CALL_RE = audit.LOOKUP_CALL_RE
UPDATE_CALL_RE = audit.UPDATE_CALL_RE
ASM_SHAPES = audit.ASM_SHAPES
CLASSIFIER_COUNTS = audit.CLASSIFIER_COUNTS
MAP_COUNTS = audit.MAP_COUNTS
DEFINE_RE = audit.DEFINE_RE

HOST_DATALAYOUT = (
    'target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-'
    'i128:128-f80:128-n8:16:32:64-S128"'
)
BPF_DATALAYOUT = (
    'target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"'
)
HOST_TRIPLE = 'target triple = "x86_64-unknown-linux-gnu"'
BPF_TRIPLE = 'target triple = "bpfel-unknown-none"'
ENTRY_DEFINE = "define dso_local i32 @xdp_entry(ptr noundef %0) #0 {"
ENTRY_DEFINE_SECTIONED = (
    'define dso_local i32 @xdp_entry(ptr noundef %0) #0 section "xdp" {'
)
HOST_ATTRS = (
    'attributes #0 = { "target-cpu"="znver4" "target-features"="+adx,+aes,'
    "+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,"
    "+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,"
    "+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,"
    "+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,"
    "+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,"
    "+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,"
    '+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }'
)
BPF_ATTRS = 'attributes #0 = { "target-cpu"="v3" }'
LICENSE_BLOCK = (
    '@_license = dso_local global [31 x i8] '
    'c"Apache-2.0 WITH LLVM-exception\\00", section "license", align 1\n'
    "@llvm.compiler.used = appending global [2 x ptr] "
    '[ptr @_license, ptr @xdp_entry], section "llvm.metadata"'
)
MAP_LICENSE_BLOCK = (
    '@_license = dso_local global [31 x i8] '
    'c"Apache-2.0 WITH LLVM-exception\\00", section "license", align 1\n'
    "@llvm.compiler.used = appending global [3 x ptr] "
    '[ptr @_license, ptr @xdp_entry, ptr @mojobpf_map0], '
    'section "llvm.metadata"'
)
MAP_BLOCK = (
    "%struct.mojobpf_map_def = type { ptr, ptr, ptr, ptr }\n"
    "@mojobpf_map0 = global %struct.mojobpf_map_def zeroinitializer, "
    'section ".maps", align 8'
)
# Fixed .BTF assembler block: 24-byte header, 13 type records (integer
# attributes type=2, key=4, value=8, entries=1, then the map struct, var
# and datasec), and the string table. The datasec entry references the
# map symbol so the assembler emits the standard BTF relocation.
BTF_ASM_LINES = (
    '.section .BTF,"",@progbits',
    '.short 60319',
    '.byte 1',
    '.byte 0',
    '.long 24',
    '.long 0',
    '.long 276',
    '.long 276',
    '.long 97',
    '.long 0',
    '.long 33554432',
    '.long 3',
    '.long 1',
    '.long 16777216',
    '.long 4',
    '.long 16777248',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    '.long 2',
    '.long 5',
    '.long 16777216',
    '.long 4',
    '.long 32',
    '.long 0',
    '.long 33554432',
    '.long 6',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    '.long 4',
    '.long 0',
    '.long 33554432',
    '.long 8',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    '.long 8',
    '.long 0',
    '.long 33554432',
    '.long 10',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    '.long 1',
    '.long 25',
    '.long 67108868',
    '.long 32',
    '.long 41',
    '.long 1',
    '.long 0',
    '.long 46',
    '.long 5',
    '.long 64',
    '.long 55',
    '.long 7',
    '.long 128',
    '.long 66',
    '.long 9',
    '.long 192',
    '.long 78',
    '.long 234881024',
    '.long 11',
    '.long 1',
    '.long 91',
    '.long 251658241',
    '.long 0',
    '.long 12',
    '.long mojobpf_map0',
    '.long 32',
    '.byte 0',
    '.ascii "int"',
    '.byte 0',
    '.ascii "__ARRAY_SIZE_TYPE__"',
    '.byte 0',
    '.ascii "mojobpf_map_def"',
    '.byte 0',
    '.ascii "type"',
    '.byte 0',
    '.ascii "key_size"',
    '.byte 0',
    '.ascii "value_size"',
    '.byte 0',
    '.ascii "max_entries"',
    '.byte 0',
    '.ascii "mojobpf_map0"',
    '.byte 0',
    '.ascii ".maps"',
    '.byte 0',
)

REPLACEMENTS = (
    (HOST_DATALAYOUT, BPF_DATALAYOUT),
    (HOST_TRIPLE, BPF_TRIPLE),
    (ENTRY_DEFINE, ENTRY_DEFINE_SECTIONED),
    (HOST_ATTRS, BPF_ATTRS),
)

RESERVED_CALLEES = (
    ("lookup", "@" + audit.LOOKUP_NAME),
    ("update", "@" + audit.UPDATE_NAME),
)


def strip_comment(line):
    """Cut an LLVM ``;`` comment, keeping quoted strings intact."""
    return audit.strip_comment(line)


def match_shape(line):
    """Return the admitted call-shape name for a line, or None."""
    return audit.match_shape(line)


def count_shapes(text):
    """Count admitted call shapes per body line (validate semantics)."""
    counts = {name: 0 for name, _ in ASM_SHAPES}
    for raw in text.splitlines():
        line = audit.strip_comment(raw).strip()
        if audit.CALL_DETECT_RE.search(line):
            shape = audit.match_shape(line)
            if shape is not None:
                counts[shape] += 1
    return counts


def validate(text):
    """Audit raw frontend IR; return ``"classifier"`` or ``"map"``.

    Raises AdapterError (the audit rejection, carrying its stable
    MBPF3xx code) naming the first violated check.
    """
    return audit.validate(text)


def btf_block():
    """Render the fixed .BTF assembler block as IR module-asm lines."""
    lines = []
    for directive in BTF_ASM_LINES:
        escaped = directive.replace('"', "\\22")
        lines.append('module asm "\\09%s"' % escaped)
    return "\n".join(lines)


def _fail(message):
    return AdapterError(
        audit.CODE_FALLBACK,
        message,
        location=None,
        remedy="report this adapter failure as a bug",
    )


def _lower_helper_calls(text, raw_lines, program):
    """Substitute the two helper callees; drop their declarations.

    Returns (lowered text, {raw call line: lowered call line}).
    """
    dropped = {"lookup": 0, "update": 0}
    kept = []
    for raw in text.splitlines(keepends=True):
        stripped = audit.strip_comment(raw).strip()
        if stripped == audit.LOOKUP_DECL_LINE:
            dropped["lookup"] += 1
            continue
        if stripped == audit.UPDATE_DECL_LINE:
            dropped["update"] += 1
            continue
        kept.append(raw)
    if dropped != {"lookup": 1, "update": 1}:
        raise _fail(
            "expected exactly one of each reserved declaration, "
            "found %r" % (dropped,)
        )
    text = "".join(kept)
    lowered = {}
    for shape, callee in RESERVED_CALLEES:
        found = text.count(callee)
        if found != 1:
            raise _fail(
                "expected exactly one %s call site, found %d"
                % (shape, found)
            )
        text = text.replace(callee, audit.LOWERED_CALLEE[shape])
    for lineno, shape, _ in program.calls:
        if shape in ("lookup", "update"):
            raw_line = audit.strip_comment(
                raw_lines[lineno - 1]
            ).strip()
            lowered[raw_line] = raw_line.replace(
                "@__mojobpf_%s_v1"
                % ("lookup" if shape == "lookup" else "update"),
                audit.LOWERED_CALLEE[shape],
            )
    if len(lowered) != 2:
        raise _fail(
            "expected two lowered helper call lines, found %d"
            % len(lowered)
        )
    return text, lowered


def adapt(text):
    """Apply the enumerated transform; audit the lowered result."""
    program = audit.scan(text)
    mode = program.mode
    raw_lines = text.splitlines()
    for old, new in REPLACEMENTS:
        found = text.count(old)
        if found != 1:
            raise _fail(
                "expected exactly one occurrence of %r, found %d"
                % (old[:72], found)
            )
        text = text.replace(old, new)
    if "@_license" in text or "@llvm.compiler.used" in text:
        raise _fail("input already contains license metadata")
    lowered = {}
    if mode == "map":
        text, lowered = _lower_helper_calls(text, raw_lines, program)
    else:
        for _, callee in RESERVED_CALLEES:
            if callee in text:
                raise _fail(
                    "classifier input references %s" % callee
                )
    raw_body = audit.body_lines("\n".join(raw_lines))
    if mode == "map":
        block = MAP_LICENSE_BLOCK + "\n" + MAP_BLOCK + "\n\n" + btf_block()
        markers = (
            MAP_LICENSE_BLOCK,
            MAP_BLOCK,
            'module asm "\\09.section .BTF,\\22\\22,@progbits"',
            'module asm "\\09.ascii \\22.maps\\22"',
        )
    else:
        block = LICENSE_BLOCK
        markers = (LICENSE_BLOCK,)
    text = text.rstrip("\n") + "\n\n" + block + "\n"
    for marker in (
        (BPF_DATALAYOUT, BPF_TRIPLE, ENTRY_DEFINE_SECTIONED, BPF_ATTRS)
        + markers
    ):
        if marker not in text:
            raise _fail("postcondition failed for %r" % marker[:48])
    audit.audit_post(text, mode)
    audit.check_graph_preserved(
        raw_body, audit.body_lines(text), lowered
    )
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Retarget genuine Mojo host IR to BPF (exact-match)."
    )
    parser.add_argument("--input", required=True, help="raw Mojo IR file")
    parser.add_argument("--output", required=True, help="adapted IR file")
    args = parser.parse_args(argv)
    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            raw = handle.read()
        validate(raw)
        adapted = adapt(raw)
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(adapted)
    except OSError as exc:
        sys.stderr.write("adapter I/O error: %s\n" % exc)
        return 1
    except AdapterError as exc:
        sys.stderr.write("adapter rejected input: %s\n" % exc)
        return 1
    if count_shapes(raw)["lookup"] == 1:
        sys.stderr.write(
            "adapted %s -> %s (metadata retarget, 2 helper calls "
            "lowered, map+BTF appended)\n" % (args.input, args.output)
        )
    else:
        sys.stderr.write(
            "adapted %s -> %s (metadata retarget, license "
            "appended)\n" % (args.input, args.output)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
