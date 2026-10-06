# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Retarget genuine Mojo-emitted host IR to little-endian BPF.

Pipeline position: ``mojo build --emit llvm`` (raw host IR) -> this adapter
-> ``llc -mtriple=bpfel -mcpu=v3 -filetype=obj`` (BPF object). The adapter
input must be real frontend output; the raw file is preserved alongside the
adapted file so reviewers can diff them.

The adapter makes exactly four line replacements plus one appended metadata
block, each by exact match on a known line (any mismatch fails loudly, so a
reviewer can enumerate every possible edit; there is no pattern rewriting):

1. host ``target datalayout`` -> the little-endian BPF data layout;
2. host ``target triple`` -> ``bpfel-unknown-none``;
3. the ``@xdp_entry`` definition line gains ``section "xdp"``;
4. the entrypoint ``attributes #0`` line (host ``target-cpu``/``target-features``)
   -> ``attributes #0 = { "target-cpu"="v3" }``;
5. appended: for the classifier shape, a ``license`` section global declaring
   the project license plus the ``llvm.compiler.used`` marker that keeps it
   (both mirror what Clang emits for a section-attributed license global);
   for the map shape, the same license global with a three-entry used
   marker, plus the standard ``.maps`` global for the one-entry array map
   and the 97-line ``.BTF`` assembler block describing it (both mirror the
   bytes of a Clang-built reference object; see the map/BTF report).

No body instruction is added, removed, or substituted: every adapted body
line is byte-identical to the frontend output. Before transforming, the
adapter validates the restricted program shape and rejects anything outside
it (extra definitions, globals, runtime calls, intrinsics, unwinding,
floating-point or vector types, address spaces, and inline assembly other
than the six known exact shapes below). The admitted assembly shapes are:

- ``empty``: the register reinterpretation cast (empty template, exactly
  ``=r,r``, i64 operand);
- ``mapaddr``: load of the map address (``r0 = mojobpf_map0 ll`` output);
- ``keyslot``: key scratch-slot init (exactly ``r10 - 4``, u32 zero);
- ``valslot``: value scratch-slot address (exactly ``r10 - 16``);
- ``lookup``: helper 1 call with fixed argument/result registers;
- ``update``: helper 2 call with fixed argument/result registers.

Exactly two count vectors validate: the classifier (one ``empty``, nothing
else) and the map round trip (one ``empty``, two ``mapaddr``, two
``keyslot``, one ``valslot``, one ``lookup``, one ``update``). Any other
combination, including a helper call without its map reference, is
rejected. Production use of any broader transform must move to LLVM APIs;
this exact-match adapter is deliberately limited to the two known
single-entrypoint shapes.
"""

import argparse
import re
import sys

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

# The only calls admitted in the entry body, each one exact shape:
# an empty-template inline assembly register reinterpretation of an i64
# address to a pointer (template empty, constraints exactly "=r,r");
# the map address load; the key/value scratch-slot preparations; and the
# two reviewed helper calls (lookup is helper 1, update is helper 2) with
# fixed argument/result registers and full caller-saved clobbers.
ASM_CALL_RE = re.compile(
    r"^%\S+\s*=\s*call\s+ptr\s+asm\s+\"\",\s*\"=r,r\"\(i64\s+%\S+\)$"
)
MAPADDR_CALL_RE = re.compile(
    r"^%\S+\s*=\s*call\s+i64\s+asm\s+sideeffect\s+"
    r"\"r0 = mojobpf_map0 ll\",\s*\"=\{r0\}\"\(\)$"
)
KEYSLOT_CALL_RE = re.compile(
    r"^%\S+\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -4\\0A\*\(u32 \*\)\(r0 \+ 0\) = r1\",\s*"
    r"\"=\{r0\},\{r1\},~\{memory\}\"\(i32 0\)$"
)
VALSLOT_CALL_RE = re.compile(
    r"^%\S+\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -16\",\s*\"=\{r0\}\"\(\)$"
)
LOOKUP_CALL_RE = re.compile(
    r"^%\S+\s*=\s*call\s+i64\s+asm\s+sideeffect\s+\"call 1\",\s*"
    r"\"=\{r0\},\{r1\},\{r2\},~\{r3\},~\{r4\},~\{r5\}\""
    r"\(i64\s+%\S+,\s+ptr\s+%\S+\)$"
)
UPDATE_CALL_RE = re.compile(
    r"^%\S+\s*=\s*call\s+i64\s+asm\s+sideeffect\s+\"call 2\",\s*"
    r"\"=\{r0\},\{r1\},\{r2\},\{r3\},\{r4\},~\{r5\}\""
    r"\(i64\s+%\S+,\s+ptr\s+%\S+,\s+ptr\s+%\S+,\s+i64 0\)$"
)
ASM_SHAPES = (
    ("empty", ASM_CALL_RE),
    ("mapaddr", MAPADDR_CALL_RE),
    ("keyslot", KEYSLOT_CALL_RE),
    ("valslot", VALSLOT_CALL_RE),
    ("lookup", LOOKUP_CALL_RE),
    ("update", UPDATE_CALL_RE),
)
# The only two admitted shape count vectors, keyed by shape name above.
CLASSIFIER_COUNTS = {
    "empty": 1,
    "mapaddr": 0,
    "keyslot": 0,
    "valslot": 0,
    "lookup": 0,
    "update": 0,
}
MAP_COUNTS = {
    "empty": 1,
    "mapaddr": 2,
    "keyslot": 2,
    "valslot": 1,
    "lookup": 1,
    "update": 1,
}
DEFINE_RE = re.compile(r"^define\s+\S+\s+i32\s+@xdp_entry\(ptr[^)]*\)")
GLOBAL_RE = re.compile(r"^@\S+\s*=")
FORBIDDEN_RES = (
    re.compile(r"\bcallbr\b"),
    re.compile(r"\binvoke\b|\blandingpad\b|\bresume\b|\bpersonality\b"),
    re.compile(r"\bcatchpad\b|\bcleanuppad\b|\bcatchret\b|\bcleanupret\b"),
    re.compile(
        r"\bfloat\b|\bdouble\b|\bhalf\b|\bfp128\b|\bx86_fp80\b|\bppc_fp80\b"
    ),
    re.compile(r"\bfadd\b|\bfsub\b|\bfmul\b|\bfdiv\b|\bfrem\b|\bfcmp\b"),
    re.compile(r"<\d+\s+x\s+"),
    re.compile(r"\baddrspace\b"),
)


class AdapterError(Exception):
    """The input IR falls outside the restricted adapter shape."""


def strip_comment(line):
    """Cut an LLVM ``;`` comment, keeping quoted strings intact."""
    in_string = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and in_string:
            index += 2
            continue
        if char == '"':
            in_string = not in_string
        elif char == ";" and not in_string:
            return line[:index]
        index += 1
    return line


def match_shape(line):
    """Return the admitted assembly shape name for a call line, or None."""
    for name, pattern in ASM_SHAPES:
        if pattern.match(line):
            return name
    return None


def count_shapes(text):
    """Count admitted assembly shapes per body line (validate semantics)."""
    counts = {name: 0 for name, _ in ASM_SHAPES}
    for raw in text.splitlines():
        line = strip_comment(raw).strip()
        if re.search(r"(^|\s)call\b", line):
            shape = match_shape(line)
            if shape is not None:
                counts[shape] += 1
    return counts


def validate(text):
    """Reject any input outside the two restricted single-entry shapes."""
    defines = 0
    counts = {name: 0 for name, _ in ASM_SHAPES}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw).strip()
        if not line or line.startswith("!"):
            continue
        if line.startswith("define "):
            defines += 1
            if not DEFINE_RE.match(line):
                raise AdapterError(
                    "line %d: unexpected definition (only i32 "
                    "@xdp_entry(ptr...) allowed): %r" % (lineno, raw.strip())
                )
            continue
        if GLOBAL_RE.match(line):
            raise AdapterError(
                "line %d: input must not define globals: %r"
                % (lineno, raw.strip())
            )
        if line.startswith("declare "):
            raise AdapterError(
                "line %d: input must not declare externals: %r"
                % (lineno, raw.strip())
            )
        if line.startswith("module asm"):
            raise AdapterError(
                "line %d: module-level assembly is not allowed: %r"
                % (lineno, raw.strip())
            )
        if re.search(r"(^|\s)call\b", line):
            shape = match_shape(line)
            if shape is not None:
                counts[shape] += 1
                continue
            raise AdapterError(
                "line %d: only the known assembly shapes are allowed: %r"
                % (lineno, raw.strip())
            )
        if "asm" in line:
            raise AdapterError(
                "line %d: inline assembly outside the known call shapes "
                "is not allowed: %r" % (lineno, raw.strip())
            )
        if "llvm." in line:
            raise AdapterError(
                "line %d: intrinsic or llvm-namespaced reference: %r"
                % (lineno, raw.strip())
            )
        for forbidden in FORBIDDEN_RES:
            if forbidden.search(line):
                raise AdapterError(
                    "line %d: forbidden construct %r in: %r"
                    % (lineno, forbidden.pattern, raw.strip())
                )
    if defines != 1:
        raise AdapterError(
            "expected exactly one @xdp_entry definition, found %d" % defines
        )
    if counts != CLASSIFIER_COUNTS and counts != MAP_COUNTS:
        raise AdapterError(
            "unexpected assembly shape counts %r "
            "(classifier allows %r, map allows %r)"
            % (counts, CLASSIFIER_COUNTS, MAP_COUNTS)
        )


def btf_block():
    """Render the fixed .BTF assembler block as IR module-asm lines."""
    lines = []
    for directive in BTF_ASM_LINES:
        escaped = directive.replace('"', "\\22")
        lines.append('module asm "\\09%s"' % escaped)
    return "\n".join(lines)


def adapt(text):
    """Apply the four exact-match replacements and append metadata."""
    for old, new in REPLACEMENTS:
        found = text.count(old)
        if found != 1:
            raise AdapterError(
                "expected exactly one occurrence of %r, found %d"
                % (old[:72], found)
            )
        text = text.replace(old, new)
    if "@_license" in text or "@llvm.compiler.used" in text:
        raise AdapterError("input already contains license metadata")
    counts = count_shapes(text)
    is_map = counts["lookup"] == 1
    if is_map:
        if counts != MAP_COUNTS:
            raise AdapterError(
                "map mode needs shape counts %r, found %r"
                % (MAP_COUNTS, counts)
            )
        block = MAP_LICENSE_BLOCK + "\n" + MAP_BLOCK + "\n\n" + btf_block()
        markers = (
            MAP_LICENSE_BLOCK,
            MAP_BLOCK,
            'module asm "\\09.section .BTF,\\22\\22,@progbits"',
            'module asm "\\09.ascii \\22.maps\\22"',
        )
    else:
        if counts != CLASSIFIER_COUNTS:
            raise AdapterError(
                "classifier mode needs shape counts %r, found %r"
                % (CLASSIFIER_COUNTS, counts)
            )
        block = LICENSE_BLOCK
        markers = (LICENSE_BLOCK,)
    text = text.rstrip("\n") + "\n\n" + block + "\n"
    for marker in (
        (BPF_DATALAYOUT, BPF_TRIPLE, ENTRY_DEFINE_SECTIONED, BPF_ATTRS)
        + markers
    ):
        if marker not in text:
            raise AdapterError("postcondition failed for %r" % marker[:48])
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
    mode = "map+BTF" if count_shapes(raw)["lookup"] == 1 else "license"
    sys.stderr.write(
        "adapted %s -> %s (4 replacements, %s appended)\n"
        % (args.input, args.output, mode)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
