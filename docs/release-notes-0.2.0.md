<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.2.0 release notes

MojoBPF compiles Mojo-authored Linux eBPF programs into
conventional `EM_BPF` ELF objects loadable by unmodified
`bpftool`/libbpf. This release adds a proven tracing slice —
an exact tracepoint counter plus fixed-record ring-buffer
event output with loss accounting — on top of the 0.1.0 XDP
slice. It remains a narrow, proven slice, not a general eBPF
toolchain.

## What is included

* Everything in 0.1.0, unchanged in behavior: the validated
  XDP pipeline, SDK surface 1.0 as a frozen subset, the
  two-lane matrix, and all prior kernel proofs (all XDP
  object pins reproduce byte-identically).
* The tracepoint counter: a Mojo-authored TID-filtered exact
  counter on `syscalls:sys_enter_getpid` (N=10000 exact,
  excluded-thread zeros, bogus-filter and TGID-mutant
  mismatch controls, missing-event environment failure).
* The fixed-record event emitter: 32-byte little-endian
  version-1 records through the copy-output path with an
  independent tool-side decoder, exact accounting
  (attempted = successful + failed, received = successful),
  stopped-consumer explicit loss, and SIGKILL-between-batches
  consumer-crash resumption at the exact byte offset.
* Lifecycle and licensing proofs: classified attach failures
  with no residue, exact process-exit counts, mid-run
  interruption (signal/kill) with strict 0 < frozen < N,
  clean repeated runs, fail-safe map/event preflights, and
  helper license enforcement (MBPF709) agreeing with the
  kernel verifier — without ever rewriting an artifact's
  license declaration.
* SDK surface 1.1 (`mojobpf.events` added; the 1.0 surface
  is frozen and enforced as an unchanged subset) and tool
  0.2.0. Manifest schema 1, license-mapping version 1,
  evidence schema v4, and cache key v4 are unchanged.
* The tracing suites are wired into the two-lane VM matrix
  (16 suites x 2 lanes on the same bits, missing lane/suite
  fails loudly, never skips).

## Verification

The release board — unit, structural contract, packaging
(including the independent external-consumer canary),
reproducibility, and the full two-lane matrix including
tracing — is recorded in
[`docs/evidence-0.2.0.md`](evidence-0.2.0.md) with the
toolchain pins, object hashes, and rerun commands. The
[quickstart](quickstart.md) was executed verbatim from a
fresh environment; its outputs are transcribed from that
run. Nothing in this release is claimed without a runnable
test or an observed run behind it.

## Limitations

This release explicitly does not support CO-RE, tracing
beyond the proven counter and emitter shapes (other events,
other filters, context payload reads, per-CPU counting, and
reserve/submit/discard output are refused or unclaimed),
multi-program objects, map kinds beyond
`ARRAY`/`PERCPU_ARRAY`/`RINGBUF` (1–4 entries for arrays,
`u32` keys, `u64` values, ring sizes 4096/131072), helpers
beyond the audited per-shape sets, or host architectures
beyond x86-64. The bounded-loop subset case verifies on
6.12 but is rejected by the 6.6 verifier (a pinned
per-lane verdict, not a skip); the arena map type is
available on 6.12 and refused by fail-safe preflight on 6.6
(a pinned per-lane split, not a skip). The IR audit's two
analysis boundaries — fail-open on constant-expression
store operands, untainted comparison predicates by design —
are disclosed in the architecture document. All details and
proof pointers live in [`docs/compatibility.md`](compatibility.md).

## License

First-party material is **Apache-2.0 WITH LLVM-exception**
(see `LICENSE` and `THIRD_PARTY_NOTICES.md`, both shipped in
the wheel). Dependencies and user-authored BPF programs keep
their own licensing. An ELF license declaration must
accurately reflect its program and is never rewritten to
gain kernel API access. See [`docs/licensing.md`](licensing.md)
for the enforced declaration behavior.
