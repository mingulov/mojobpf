<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Packet counter example

`packet_counter.mojo` is a Mojo-authored XDP program combining the
packet workload in one program: it returns the classifier action
(`1`, `XDP_DROP`, when the frame holds at least 15 bytes and bit 0
of byte 14 is set, else `2`, `XDP_PASS`), adds one to entry 0, and
adds the frame length to entry 1 of the two-entry array map on
every invocation. Frames shorter than 15 bytes return `2` without
touching packet bytes; short frames are ordinary traffic under this
rule, so the short-input action is `XDP_PASS`, not the SDK's
fail-closed guard idiom.

Counting is unconditional: both map pairs run on every path that
reaches them, including the drop path. On a lookup miss the program
returns the content action without counting that entry (an in-range
array lookup never misses; the checks satisfy the kernel verifier).

`packet_counter_bit_mutated.mojo` inverts the bit test (same
counting, flipped actions) and
`packet_counter_bytesum_mutated.mojo` accumulates one per invocation
into entry 1 instead of the frame length (same action, wrong byte
sum); both exist for behavior-change proofs.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/packet_counter.ll examples/packet_counter/packet_counter.mojo
python3 compiler/mojo_ir_adapter.py --input out/packet_counter.ll \
    --output out/packet_counter.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/packet_counter.bpf.ll \
    -o out/packet_counter.bpf.o
```

The adapter retargets module metadata, lowers the four helper
pseudo-calls to their standard BPF helper-call encoding, and appends
the standard two-entry map declaration with map BTF; every other
body instruction in the adapted IR is byte-identical to the frontend
output. The resulting object loads with unmodified libbpf/bpftool.

## Scope

This program is the packet workload whole: content action plus both
counters in one Mojo program, proven over the shared packet corpus
(`examples/packet_classifier/corpus/`) with per-invocation map reads
and nonzero userspace initializations, so every action and every
accumulated value is checked exactly. The split demos stay as subset
documentation: `packet_classifier` classifies without a map and
`xdp_counter` counts invocations without inspecting bytes.
