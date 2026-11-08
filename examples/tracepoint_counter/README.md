<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Tracepoint counter example

`counter.mojo` is a Mojo-authored tracepoint program that counts
`getpid` calls from one thread: on every
`syscalls:sys_enter_getpid` event it compares the low 32 bits of
the helper-14 word (the TID) against the filter in entry 0 of the
two-entry array map and adds one to the counter in entry 1 only
on a match, returning `0`. On a lookup miss or a filter mismatch
it returns `0` without touching the counter. With entry 0 holding
a monitored TID and entry 1 starting at 0, exactly the monitored
thread's `getpid` calls are counted; every other thread's calls,
including background system activity, are rejected by the filter.

`counter_tgid_mutated.mojo` compares the high 32 bits (the TGID)
instead of the low 32 bits (same shape, different behavior) and
exists for behavior-change proofs. `mojobpf.toml` declares the
filter shape: entry 0 is the monitored TID as a zero-extended
`u64`, entry 1 is the counter.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mkdir -p out
mojo build --emit llvm \
    --target-cpu znver4 \
    --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves \
    -I src/mojobpf/resources/sdk \
    -o out/trace.ll examples/tracepoint_counter/counter.mojo
python3 compiler/mojo_ir_adapter.py --input out/trace.ll \
    --output out/trace.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/trace.bpf.ll \
    -o out/trace.bpf.o
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
    --manifest examples/tracepoint_counter/mojobpf.toml \
    --out-dir out/tracepoint \
    --lockfile toolchains.lock.json
```

The adapter retargets module metadata, lowers the four helper
pseudo-calls (two lookups, one update, one PID/TID call) to their
standard BPF helper-call encoding, and appends the standard map
declaration with map BTF; every other body instruction in the
adapted IR is byte-identical to the frontend output. The resulting
object loads with unmodified libbpf/bpftool.

## Scope

The filter uses the low 32 bits of the helper-14 word only; the
high 32 bits (the TGID) are never compared, so a thread is never
confused with its thread group. Both sides observe the initial PID
namespace, where the helper result and `gettid()` agree. The
program reads no tracepoint context payload fields — the context
pointer is accepted but unused, and any use is refused before code
generation — and attaches only to `syscalls:sys_enter_getpid`;
other events, other filters, and per-CPU counting are unproven.

## Measured behavior

In a disposable guest on each supported kernel lane, a raw-`getpid`
workload over a handshake (no fixed sleeps) observes exactly
N=10000 counts for the monitored thread and 0 for two excluded
threads issuing 1000 calls each; with the monitored thread idle
the excluded phase observes 0; a filter naming TID 2147483647
(which no thread holds) observes 0 as a controlled mismatch; a
TGID-confused mutant observes 0 while the reloaded base still
observes N; and attaching to a missing event reports an explicit
environment-capability failure instead of passing. The kernel
suite proving this is
`tests/kernel/test_tracepoint_counter.py` (five tests: excluded,
exact, unavailability, wrong-filter, mutant-plus-stale).
