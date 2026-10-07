<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.1.0 release notes

MojoBPF compiles Mojo-authored Linux eBPF programs into
conventional `EM_BPF` ELF objects loadable by unmodified
`bpftool`/libbpf. This is the first release: a narrow, proven
XDP slice — not a general eBPF toolchain.

## What is included

* The validated pipeline: Mojo source → Mojo 1.1.0 frontend
  IR → exact-match adapter → LLVM `llc` (`bpfel`, `v3`) →
  standard ELF. The kernel-side algorithm always originates
  in Mojo source; every body instruction in the adapted IR is
  byte-identical to the frontend output
  (`docs/architecture.md`).
* The versioned Mojo SDK surface 1.0 (`mojobpf.packet`,
  `mojobpf.parse`, `mojobpf.checksum`, `mojobpf.helpers`,
  `mojobpf.maps`): bounds-checked packet access, Ethernet
  parsing with one optional VLAN tag, checksums, map
  lookup/update/delete wrappers, and array/per-CPU-array maps
  with 1–4 entries (`docs/sdk.md`).
* The installable `mojobpf` tool 0.1.0
  (`doctor`/`build`/`check`/`inspect`/`verify --kernel`),
  installing offline from a standard wheel with no
  repository paths (`docs/install.md`).
* Three Mojo demo programs, a 68-frame packet corpus with an
  independent C reference workload, and per-frame in-kernel
  accounting proofs (`examples/`,
  `tests/kernel/test_xdp_accounting.py`).
* The two-lane VM matrix (guest kernels 6.12 and 6.6, pinned
  by hash) proving every guest-backed suite on the same
  bits, with owned-resource cleanup proofs and reproducible
  builds (`ci/`, `docs/compatibility.md`).

## Verification

The release board — unit, structural contract, packaging
(including the independent external-consumer canary),
reproducibility, and the full two-lane matrix — is recorded
in [`docs/evidence-0.1.0.md`](evidence-0.1.0.md) with the
toolchain pins, object hashes, and rerun commands. The
[quickstart](quickstart.md) was executed verbatim from a
fresh environment; its outputs are transcribed from that
run. Nothing in this release is claimed without a runnable
test or an observed run behind it.

## Limitations

This release explicitly does not support CO-RE, tracing
programs, multi-program objects, map kinds beyond
`ARRAY`/`PERCPU_ARRAY` (1–4 entries, `u32` keys, `u64`
values), helpers beyond lookup/update/delete, or host
architectures beyond x86-64. The bounded-loop subset case
verifies on 6.12 but is rejected by the 6.6 verifier (a
pinned per-lane verdict, not a skip). The IR audit's two
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
