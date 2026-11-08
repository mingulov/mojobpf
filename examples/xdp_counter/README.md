<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# XDP counter example

`counter.mojo` is a Mojo-authored XDP program that counts
invocations: on every execution it adds one to entry 0 of the
single-entry array map and returns `2` (`XDP_PASS`). On a lookup
miss it returns `2` without touching the map. With the value
initialized to N by userspace, K sequential invocations observe
exactly N + K.

`counter_mutated.mojo` returns `1` instead of `2` (same counting,
different action) and `counter_slot_mutated.mojo` adds two per
invocation instead of one (same action, different count); both exist
for behavior-change proofs.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mkdir -p out
mojo build --emit llvm \
    --target-cpu znver4 \
    --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves \
    -I src/mojobpf/resources/sdk \
    -o out/counter.ll examples/xdp_counter/counter.mojo
python3 compiler/mojo_ir_adapter.py --input out/counter.ll \
    --output out/counter.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/counter.bpf.ll \
    -o out/counter.bpf.o
```

The `--target-cpu`/`--target-features` pair pins the frontend to
the frozen producer shape the exact-match adapter expects (the
same flags the `mojobpf build` route passes); without it the
frontend emits the build machine's CPU and the adapter refuses
the IR.

The adapter retargets module metadata, lowers the two helper
pseudo-calls to their standard BPF helper-call encoding, and appends
the standard map declaration with map BTF; every other body
instruction in the adapted IR is byte-identical to the frontend
output. The resulting object loads with unmodified libbpf/bpftool.

## Scope

This program counts invocations unconditionally: its action is a
constant pass and it never inspects packet bytes. It stays as
subset documentation for the single-entry map shape (one address
reinterpretation, one read-modify-write pair, no cross-call packet
values). The packet workload whole — content action plus both
counters in one program — is the `packet_counter` example,
admitted under the combined count vector; partial combined forms
that match neither vector stay refused with named diagnostics
under `tests/compile/counter_*_attempt.mojo`. Content actions
without a map are demonstrated by the `packet_classifier` example
instead. The kernel suite runs this counter over that example's
shared packet corpus (`examples/packet_classifier/corpus/`) with
per-invocation map reads and a nonzero userspace initialization,
so every accumulated value is checked exactly.
