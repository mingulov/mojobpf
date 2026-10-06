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
5. appended: a ``license`` section global declaring the project license plus
   the ``llvm.compiler.used`` marker that keeps it (both mirror what Clang
   emits for a section-attributed license global).

No body instruction is added, removed, or substituted: every adapted body
line is byte-identical to the frontend output. Before transforming, the
adapter validates the restricted program shape and rejects anything outside
it (extra definitions, globals, runtime calls, intrinsics, unwinding,
floating-point or vector types, address spaces, inline assembly other than
the single known empty-template register reinterpretation). Production
use of any broader transform must move to LLVM APIs; this exact-match
adapter is deliberately limited to the known single-entrypoint shape.
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

REPLACEMENTS = (
    (HOST_DATALAYOUT, BPF_DATALAYOUT),
    (HOST_TRIPLE, BPF_TRIPLE),
    (ENTRY_DEFINE, ENTRY_DEFINE_SECTIONED),
    (HOST_ATTRS, BPF_ATTRS),
)

# The only call admitted in the entry body: an empty-template inline
# assembly register reinterpretation of an i64 address to a pointer. The
# template must be empty and the constraints exactly "=r,r" (single output
# register, single input register, no memory or target operands).
ASM_CALL_RE = re.compile(
    r"^%\S+\s*=\s*call\s+ptr\s+asm\s+\"\",\s*\"=r,r\"\(i64\s+%\S+\)$"
)
DEFINE_RE = re.compile(r"^define\s+\S+\s+i32\s+@xdp_entry\(ptr[^)]*\)")
GLOBAL_RE = re.compile(r"^@\S+\s*=")
FORBIDDEN_RES = (
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


def validate(text):
    """Reject any input outside the restricted single-entry shape."""
    defines = 0
    asm_calls = 0
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
        if re.search(r"(^|\s)call\b", line):
            if ASM_CALL_RE.match(line):
                asm_calls += 1
                continue
            raise AdapterError(
                "line %d: only the known empty-asm call is allowed: %r"
                % (lineno, raw.strip())
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
    if asm_calls != 1:
        raise AdapterError(
            "expected exactly one empty-asm cast call, found %d" % asm_calls
        )


def adapt(text):
    """Apply the four exact-match replacements and append the license."""
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
    text = text.rstrip("\n") + "\n\n" + LICENSE_BLOCK + "\n"
    for marker in (BPF_DATALAYOUT, BPF_TRIPLE, ENTRY_DEFINE_SECTIONED,
                   BPF_ATTRS, LICENSE_BLOCK):
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
    sys.stderr.write(
        "adapted %s -> %s (4 replacements, license appended)\n"
        % (args.input, args.output)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
