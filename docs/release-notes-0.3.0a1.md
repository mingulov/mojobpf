<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.3.0a1 release notes

Alpha preview. MojoBPF compiles Mojo-authored Linux eBPF
programs into conventional `EM_BPF` ELF objects loadable by
unmodified `bpftool`/libbpf. This alpha adds three proven
breadth slices — socket/TC networking programs, LRU hash
maps, and the skb accessor helpers — on top of the 0.2.0
tracing slice, plus the joint libbpf-mojo stack proof and a
revision-2 capability registry. It remains a narrow, proven
slice, not a general eBPF toolchain.

## What is included

* Everything in 0.2.0, unchanged in behavior: the validated
  XDP pipeline, the tracepoint counter and fixed-record
  event emitter, the two-lane matrix, and all prior kernel
  proofs. The quickstart XDP counter object reproduces
  byte-identically (`b2679151…`).
* Breadth 1, networking (`linux-bpfel-v3-net` profile):
  socket-filter programs with verdicts from live `AF_PACKET`
  attach, TC classifier programs with verdicts through
  test-run, TC packet-store bytes observed out, and map
  readback through skb-load plus update — 12/12 in both
  lanes on the same bits.
* Breadth 2, LRU (`linux-bpfel-v3-lru` profile): `LRU_HASH`
  maps with `u32` keys and `u64` values, one-entry
  lifecycle shapes, exact quiesced counts, miss/delete/
  iteration semantics, and a pigeonhole eviction leg proving
  the LRU victim — 17/17 in both lanes on the same bits.
* Breadth 3, skb helpers: helpers 9 (`skb_load_bytes`) and
  26 (`skb_store_bytes`) audited to genuine emission
  spellings with initialized keyslots, proven through the
  breadth-1 legs.
* The joint stack: Mojo userspace through libbpf-mojo
  (`Object` open/load, `lookup_u64`/`update_u64`,
  `test_run`) initializes map key 0 to 41, the genuine Mojo
  kernel program observes and increments to 42, and
  mutant/stale legs fail exactly — 8/8 in the 6.12, 6.6,
  and joint-only 7.x lanes (see
  [pair-matrix-0.3.0a1.md](pair-matrix-0.3.0a1.md)).
* Capability registry revision 2: 47 records proven by the
  alpha evidence flip to IMPLEMENTED/tested through a
  curated flip table; the registry validates byte-identical
  against freshly downloaded pinned upstream sources.
* Five independent external consumers (base, hash, reserve,
  subprog, uprobe) build their own sources through the
  installed tool only and observe exact kernel results in
  both lanes.
* SDK surface 1.7 (the 1.0–1.6 surfaces are frozen and
  enforced as unchanged subsets) and tool 0.3.0a1.
  Manifest schema 1, license-mapping version 1, evidence
  schema v4, and cache key v4 are unchanged.

## Verification

The release board — unit, compiler (with the four
pre-existing reds and their pristine-base reproduction),
the full two-lane matrix, the joint-only 7.x lane, and the
registry byte-identity proof — is recorded in
[`docs/evidence-0.3.0a1.md`](evidence-0.3.0a1.md) with the
toolchain pins, object hashes, and rerun commands. The
[quickstart](quickstart.md) was executed verbatim from a
fresh environment; its outputs are transcribed from that
run. Nothing in this release is claimed without a runnable
test or an observed run behind it.

## Limitations

This alpha explicitly does not support CO-RE beyond the
proven `task_struct.pid` relocation slice, tcx programs,
XDP attach (objects load and run under test-run only;
attachment stays out), LPM-trie maps, 7.x beyond the
joint-only lane (no 7.x full matrix ran), tracing beyond
the proven counter/emitter/reservation/uprobe shapes,
multi-program objects, map kinds beyond
`ARRAY`/`PERCPU_ARRAY`/`RINGBUF`/`HASH`/`LRU_HASH` (1–4
entries for arrays and hashes, `u32` keys, `u64` values,
ring sizes 4096/131072, one-entry LRU lifecycle shapes),
helpers beyond the audited per-shape sets, or host
architectures beyond x86-64. The bounded-loop subset case
verifies on 6.12 but is rejected by the 6.6 verifier (a
pinned per-lane verdict, not a skip); the arena map type is
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
