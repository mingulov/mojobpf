<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Uprobe counter example

`counter.mojo` is a Mojo-authored uprobe program that counts calls
carrying one argument value: on every hit of the uprobe it is
attached to, it reads the probed call's first argument from the
pinned x86-64 register word, compares it against the expected
value in entry 0 of the two-entry array map, and adds one to the
counter in entry 1 only on a match, returning `0`. On a lookup
miss or an argument mismatch it returns `0` without touching the
counter. With entry 0 holding an expected argument and entry 1
starting at 0, exactly the calls carrying that argument are
counted.

`counter_inverted_mutated.mojo` counts the calls whose argument
differs from the expected value instead (same shape, different
behavior) and exists for behavior-change proofs. `mojobpf.toml`
declares the filter shape: entry 0 is the expected argument as a
`u64`, entry 1 is the counter.

`target.c` is the suite-owned test executable the probe attaches
to: it calls `probe_target(value)` N times (each call reporting
its argument over a FIFO oracle channel) and also carries the
never-called `probe_never_called` symbol for the zero-hit
negative. It builds non-PIE so its symbol addresses are fixed:

```bash
cc -no-pie -fno-pie -O2 -o uprobe_target target.c
```

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/uprobe.ll examples/uprobe_counter/counter.mojo
python3 compiler/mojo_ir_adapter.py --input out/uprobe.ll \
    --output out/uprobe.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/uprobe.bpf.ll \
    -o out/uprobe.bpf.o
```

or through the build driver:

```bash
python3 -m mojobpf.cli build \
    --manifest examples/uprobe_counter/mojobpf.toml \
    --out-dir out/uprobe \
    --adapter compiler/adapter_service.py \
    --lockfile toolchains.lock.json
```

The adapter retargets module metadata, lowers the three helper
pseudo-calls (two lookups, one update) to their standard BPF
helper-call encoding, and appends the standard map declaration
with map BTF; every other body instruction in the adapted IR is
byte-identical to the frontend output. The resulting object loads
with unmodified libbpf/bpftool under program type `kprobe`.

## Scope

The program reads exactly one context word: `pt_regs` word 14
(`rdi` at byte 112), the first function-argument register under
the System V ABI on x86-64. The uprobe fires at function entry,
so the register still holds the caller's first argument. Any
other context access — another word, another width, a second
read, or a context write — is refused before code generation.
Register extraction is architecture-specific and explicit: x86-64
is proven, AArch64 register extraction is not claimed, and a
tracepoint is never presented as a portable uprobe.

The object carries no attach target (the section is the bare
`uprobe` name). The loader attaches it at load time to one symbol
of the suite-owned test executable built from `target.c`, never
to a system binary. One build holds one uprobe program; one
binary, one symbol. Multi-probe graphs, mixed uprobe/XDP builds,
and wider register or symbol vocabularies are unproven and
refused.

## Measured behavior

In a disposable guest on each supported kernel lane (x86-64,
`v6.12` and `v6.6`), with the expected argument 41: N=1000 calls
carrying 41 are counted exactly 1000 with every oracle word equal
to 41; M=500 calls carrying 43 leave the counter at 0 with every
oracle word equal to 43; the inverted mutant counts exactly the
500 mismatching calls; the reloaded base object counts exactly
1000 again; and a probe attached to the never-called symbol
observes 0 while the workload's 1000 calls proceed normally. A
guest without the tracefs uprobe interface reports an explicit
environment-capability failure instead of passing; an out-of-range
probe offset fails the perf open loudly; and an out-of-bounds
context mutant that clears host inspection is rejected by the
kernel verifier with `dereference of modified ctx ptr R1
off=112000 disallowed`. The kernel suite proving this is
`tests/kernel/test_uprobe_register.py`.
