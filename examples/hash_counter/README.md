<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Hash counter example

`counter.mojo` is a Mojo-authored XDP program that counts
invocations through a hash map: on every execution it adds one to
the value stored under key 0 of the single-entry hash map and
returns `2` (`XDP_PASS`). On a lookup miss (key 0 absent) it
returns `2` without touching the map. With the value initialized
to N by userspace, K sequential invocations observe exactly N +
K; on a fresh map every key misses until an update creates it,
so the program never inserts entries by itself.

`mojobpf.toml` declares the counter shape under the hash
capability profile (`linux-bpfel-v3-hash`): key 0 holds the
invocation count as a `u64`.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/hash.ll examples/hash_counter/counter.mojo
python3 compiler/mojo_ir_adapter.py --input out/hash.ll \
    --output out/hash.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/hash.bpf.ll \
    -o out/hash.bpf.o
```

or through the installed CLI, which uses its packaged adapter by
default:

```bash
mojobpf build \
    --manifest examples/hash_counter/mojobpf.toml \
    --out-dir out/hash_counter \
    --lockfile toolchains.lock.json
```

The adapter retargets module metadata, lowers the two helper
pseudo-calls to their standard BPF helper-call encoding, and
appends the standard hash map declaration with map BTF; every
other body instruction in the adapted IR is byte-identical to the
frontend output. The resulting object loads with unmodified
libbpf/bpftool.

## Scope

This program counts invocations unconditionally: its action is a
constant pass and it never inspects packet bytes. It stays as
subset documentation for the single-entry hash shape (one address
reinterpretation, one read-modify-write pair, one hash tag per map
load, no cross-call packet values). Multi-entry hash shapes (up to
4 entries) and hash deletion probes build the same way; the
kernel suite proves insert, lookup, update, delete, and
userspace-driven iteration at 4 entries with exact bytes,
an independent consumer proves 2-entry read-modify-write,
this 1-entry shape is a load/unload proof, and structural
proofs cover every count at all 24 shapes. The
update flag stays `BPF_ANY` (create-or-replace);
`BPF_NOEXIST`/`BPF_EXIST` spellings are refused before the kernel,
and there is no from-program key-iteration spelling (userspace
walks live maps with the `bpf()` get-next-key command).
