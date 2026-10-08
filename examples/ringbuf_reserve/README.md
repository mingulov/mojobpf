<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Ring-buffer reservation example

`emitter.mojo` is a Mojo-authored tracepoint program that emits one
32-byte event record per `getpid` call from one thread through an
explicit ring-buffer reservation: on every
`syscalls:sys_enter_getpid` event it compares the low 32 bits of
the helper-14 word (the TID) against the filter in entry 0 of the
four-entry array map and returns `0` on a mismatch without
reserving anything. On a match it takes the next per-run sequence
number from entry 1, reads the CPU number and the monotonic clock
plus the PID/TID identity word, reserves a 32-byte record with
the ring-buffer reserve helper 131, stamps the record (version
`1`, size `32`, TGID, TID, CPU, sequence, monotonic nanoseconds)
directly into the reservation with one word store per field, and
publishes exactly that record with the ring-buffer submit helper
132. A null reservation (ring full) increments the
failed-reservation count in entry 3 and publishes nothing; a
submitted reservation increments the successful-output count in
entry 2. With entry 0 holding a monitored TID and entries 1-3
starting at 0, the producer side reconciles attempted =
successful + failed, and the drained records reconcile received =
successful with the failures visible as sequence gaps.

`mojobpf.toml` declares the reservation shape under the
reservation capability profile (`linux-bpfel-v3-reserve`):
four-entry array plus the 128 KiB ring, with helpers 131 and 132
admitted alongside the base helper set.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/reserve.ll examples/ringbuf_reserve/emitter.mojo
python3 compiler/mojo_ir_adapter.py --input out/reserve.ll \
    --output out/reserve.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/reserve.bpf.ll \
    -o out/reserve.bpf.o
```

or through the build driver:

```bash
python3 -m mojobpf.cli build \
    --manifest examples/ringbuf_reserve/mojobpf.toml \
    --out-dir out/ringbuf-reserve \
    --adapter compiler/adapter_service.py \
    --lockfile toolchains.lock.json
```

The adapter retargets module metadata, lowers the thirteen helper
pseudo-calls (four lookups, three updates, two PID/TID, one clock,
one CPU, one ring-buffer reserve, one ring-buffer submit) to their
standard BPF helper-call encoding, and appends the standard map
declarations with map BTF for both maps; every other body
instruction in the adapted IR is byte-identical to the frontend
output. The resulting object loads with unmodified libbpf/bpftool.

## Reserve vs copy-output

Each reservation program commits to exactly one terminus: a
submit program (reserve, fill, then submit — this example)
publishes its record, while a discard program (reserve, fill,
then discard) releases its reservation unpublished via the
discard terminus (helper 133). The terminus is fixed per
program, never chosen per event: a program containing both
termini, even in mutually exclusive branches, is refused
(MBPF307). Use the explicit reservation path when the fill
logic needs the record address; use copy-output (helper 130,
the `tracepoint_events` example) when every event publishes
unconditionally from a fixed scratch buffer. The submit and
copy-output paths publish the identical 32-byte record and
reconcile identically (`attempted=successful+failed`,
`received=successful`); on the discard path `received=0`
while entry 2 counts the released reservations. The paths
differ only in where the record is staged (kernel-provided
reservation vs program scratch) and in the failure signal
(null reservation vs nonzero status).

## Scope

The filter uses the low 32 bits of the helper-14 word only; both
sides observe the initial PID namespace, where the helper result
and `gettid()` agree. The program reads no tracepoint context
payload fields — the context pointer is accepted but unused, and
any use is refused before code generation — and attaches only to
`syscalls:sys_enter_getpid`. A program holds at most one live
reservation and one terminus: two reserves, two termini, a mixed
terminus, or any use after the terminus is refused before the
kernel sees the program, and the kernel verifier independently
rejects the same shapes.

## Measured behavior

In a disposable guest on each supported kernel lane, the producer
side reconciles attempted = successful + failed on every path.
On the submit path the drained records reconcile received =
successful: a healthy consumer drains the full workload with
zero loss and contiguous sequences (every reserve published
exactly once). On the discard path received = 0 while entry 2
counts the released reservations: a discard emitter drains zero
records while its counters prove every attempt ran (every
reserve discarded published nothing). A
stopped consumer on the one-page ring observes nonzero explicit
loss with the drained records forming the exact successful
prefix. The four adversarial interleavings (double submit,
submit-then-discard, discard-then-submit, use-after-discard) are
all rejected at load while the well-formed control loads and
unloads cleanly. The kernel suite proving this is
`tests/kernel/test_ringbuf_reserve.py` (six tests: submit,
discard, saturation, adversarial, residue, license).
