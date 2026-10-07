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
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/counter.ll examples/xdp_counter/counter.mojo
python3 compiler/mojo_ir_adapter.py --input out/counter.ll \
    --output out/counter.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/counter.bpf.ll \
    -o out/counter.bpf.o
```

The adapter retargets module metadata, lowers the two helper
pseudo-calls to their standard BPF helper-call encoding, and appends
the standard map declaration with map BTF; every other body
instruction in the adapted IR is byte-identical to the frontend
output. The resulting object loads with unmodified libbpf/bpftool.

## Scope

This program counts invocations unconditionally: its action is a
constant pass and it never inspects packet bytes. Combining the
classifier rule with map counting in one program is refused by the
IR audit, as are packet-derived map values; the closest combined
forms are committed as refused reproducers under
`tests/compile/counter_*_attempt.mojo` with their exact diagnostic
codes. Packet-content actions are demonstrated by the
`packet_classifier` example instead. The kernel suite runs this
counter over that example's shared packet corpus
(`examples/packet_classifier/corpus/`) with per-invocation map reads
and a nonzero userspace initialization, so every accumulated value
is checked exactly.
