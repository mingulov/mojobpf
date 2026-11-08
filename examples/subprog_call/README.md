<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Subprogram-call decision example

`decision.mojo` is a Mojo-authored XDP program that classifies
packets through one static subprogram call: frames of at least
15 bytes with bit 0 of byte 14 set return `XDP_DROP` (1),
everything else returns `XDP_PASS` (2). Frames shorter than 15
bytes take the pass path through the explicit bounds check. The
bit test itself lives in the `decide` subprogram, so every
full-size frame's action is computed through the call: a
`pkt_drop.bin` frame (byte 14 = `0x01`) returns exactly 1, a
`pkt_pass.bin` frame (byte 14 = `0x00`) returns exactly 2, and
the 10-byte `pkt_short.bin` frame returns exactly 2.

`decision_mutated.mojo` is the call-free inverted mutant: the
same rule with the bit test flipped inline and no call at all,
so the two full-size fixtures swap their actions (drop returns
2, pass returns 1). It builds under the base profile and proves
the suites notice when the call disappears.

`mojobpf.toml` declares the decision program under the
subprogram capability profile (`linux-bpfel-v3-subprog`) with
no maps: the call shape needs no map or helper vocabulary.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mkdir -p out
mojo build --emit llvm \
    --target-cpu znver4 \
    --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves \
    -I src/mojobpf/resources/sdk \
    -o out/decision.ll examples/subprog_call/decision.mojo
python3 compiler/mojo_ir_adapter.py --input out/decision.ll \
    --output out/decision.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/decision.bpf.ll \
    -o out/decision.bpf.o
```

The `--target-cpu`/`--target-features` pair pins the frontend to
the frozen producer shape the exact-match adapter expects (the
same flags the `mojobpf build` route passes); without it the
frontend emits the build machine's CPU and the adapter refuses
the IR.

or through the installed CLI, which uses its packaged adapter by
default:

```bash
mojobpf build \
    --manifest examples/subprog_call/mojobpf.toml \
    --out-dir out/subprog-call \
    --lockfile toolchains.lock.json
```

The adapter retargets module metadata, sections the entrypoint,
and appends the license; the subprogram definition and its call
site pass through byte-identical, and the backend lowers the
static call itself. The resulting object (the callee in `.text`,
the entrypoint in `xdp`, one `R_BPF_64_32` relocation) loads
with unmodified libbpf/bpftool.

## Call discipline

The example demonstrates the only admitted BPF-to-BPF call
shape: exactly one callee per program, spelled `@export` +
`@no_inline` with a C ABI and the fixed one-argument scalar
signature `(UInt64) -> UInt64`, called from an XDP classifier
entrypoint in either definition order. The callee body is pure
scalar arithmetic with no calls of its own. A second callee, any
other arity or argument type, recursion, an indirect call, a
call inside the callee, a call under `trace_entry`, and map or
helper calls alongside the callee are all refused before the
backend runs; under profiles without the subprogram capability
the object is refused at inspection instead. See
`docs/supported-subset.md` (subprogram section) for the exact
codes.

## Measured behavior

In a disposable guest on each supported kernel lane, the base
board is drop/pass/short = 1/2/2 with distinct actions across
the two full-size fixtures, the rebuilt mutant boards 2/1/2, and
the entry-first twin matches the base rule — so the callee
executes and computes an input-dependent result through the
call. The verifier log of a successful load shows the
subprogram (`func#0`/`func#1` with the relocated call and
caller/callee frames). Every load reports `cleanup_ok`, both
pins are absent afterwards, and the final program/map listing
carries none of our names. The kernel suite proving this is
`tests/kernel/test_subprog_calls.py` (eleven tests: fixture
bytes, base, mutant, second order, stale, verifier log,
callee null-load, FD lifecycle, provenance, object hashes,
license).
