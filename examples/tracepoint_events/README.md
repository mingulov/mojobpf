<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Tracepoint events example

`emitter.mojo` is a Mojo-authored tracepoint program that emits one
32-byte event record per `getpid` call from one thread: on every
`syscalls:sys_enter_getpid` event it compares the low 32 bits of
the helper-14 word (the TID) against the filter in entry 0 of the
four-entry array map and returns `0` on a mismatch without
emitting anything. On a match it takes the next per-run sequence
number from entry 1, stamps the record (version `1`, size `32`,
TGID, TID, CPU, sequence, monotonic nanoseconds), initializes
every byte, and emits it through the ring-buffer map with the
copy-output helper 130. A zero status increments the
successful-output count in entry 2; a nonzero status increments
the failed-output count in entry 3. With entry 0 holding a
monitored TID and entries 1-3 starting at 0, the producer side
reconciles attempted = successful + failed, and the drained
records reconcile received = successful with the failures visible
as sequence gaps.

`emitter_small.mojo` is the same program against the one-page
saturation ring (4096 bytes); `emitter.mojo` uses the healthy
128 KiB ring. `emitter_tgid_mutated.mojo` compares the high 32
bits (the TGID) instead of the low 32 bits (same shape, emits
nothing) and exists for behavior-change proofs.
`emitter_v2_mutated.mojo` stamps version `2` on every record
(same shape, undecodable) and exists for decoder-liveness proofs.
`mojobpf.toml` declares the healthy shape (four-entry array plus
the 128 KiB ring); `mojobpf-small.toml` declares the saturation
shape (four-entry array plus the one-page ring).

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/events.ll examples/tracepoint_events/emitter.mojo
python3 compiler/mojo_ir_adapter.py --input out/events.ll \
    --output out/events.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/events.bpf.ll \
    -o out/events.bpf.o
```

or through the build driver:

```bash
python3 -m mojobpf.cli build \
    --manifest examples/tracepoint_events/mojobpf.toml \
    --out-dir out/tracepoint-events \
    --adapter compiler/adapter_service.py \
    --lockfile toolchains.lock.json
```

The adapter retargets module metadata, lowers the eleven helper
pseudo-calls (four lookups, three updates, one PID/TID, one clock,
one CPU, one ring-buffer output) to their standard BPF helper-call
encoding, and appends the standard map declarations with map BTF
for both maps; every other body instruction in the adapted IR is
byte-identical to the frontend output. The resulting object loads
with unmodified libbpf/bpftool.

## Scope

The filter uses the low 32 bits of the helper-14 word only; both
sides observe the initial PID namespace, where the helper result
and `gettid()` agree. The program reads no tracepoint context
payload fields — the context pointer is accepted but unused, and
any use is refused before code generation — and attaches only to
`syscalls:sys_enter_getpid`. Only the copy-output helper is
supported: reserve/submit/discard spellings are refused.

## Measured behavior

In a disposable guest on each supported kernel lane, the producer
side reconciles attempted = successful + failed and the drained
records reconcile received = successful on every run: a healthy
consumer drains the full workload with zero loss and contiguous
sequences; a stopped consumer on the one-page ring observes
nonzero explicit loss with the drained records forming the exact
successful prefix; killing the consumer mid-drain loses no kernel
records and resumes at the exact byte offset; a TGID mutant emits
nothing while the reloaded base still emits exactly; version-2
records are produced but rejected by the decoder; and an
independent C control producer validates the observer. The kernel
suite proving this is `tests/kernel/test_tracepoint_events.py`
(six tests: control, healthy, saturation, crash, mutant-plus-stale,
version gate). The loss accounting above is what the suite checks
on the forced saturation run with a stopped consumer.
