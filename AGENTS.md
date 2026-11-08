<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Contributing to MojoBPF

## Project contract

Use **MojoBPF** for the project and `mojobpf` for the repository and CLI. The first-party default is `Apache-2.0 WITH LLVM-exception`. Preserve the exact license text and third-party notices.

The product compiles actual Mojo-authored Linux eBPF programs into conventional `EM_BPF` ELF objects loadable by unmodified supported libbpf/bpftool. The kernel-side algorithm must originate in Mojo. Source-to-C translation, hidden C implementations, custom interpreters and runtime stubs do not meet this contract.

This tree ships a 6-verb CLI (`mojobpf build/check/doctor/inspect/verify/test`), a versioned Mojo SDK surface, 8 supported target profiles, and 12 examples. Update public status and supported capabilities only as real functionality is verified; supported means observed in the release test runs, never merely untested.

## Work and layout

Read the README and relevant contributor contracts. Inspect Git state, worktrees and existing changes before editing; preserve unrelated work. Keep focused changes and commits. Public documentation and all required build/test inputs must be usable from a standalone clone or source archive with declared dependencies.

Layout:

- `tests/probes/`, `tests/reference_c/`, `tests/harness/`: tool discovery, independent C controls and standard loader/test-run helpers.
- `tests/compile/`, `tests/ir/`, `tests/elf/`, `tests/kernel/`: source, ABI, artifact and real behavior proofs.
- `src/mojobpf/`: Python 3.11+ build driver, manifest, diagnostics, inspection and provenance.
- `src/mojobpf/resources/sdk/mojobpf/`: packaged Mojo SDK source.
- `compiler/`: small matching-LLVM C++ adapter plus the exact-match Python adapter it mirrors.
- `examples/`, `docs/`, `schemas/`, `ci/`: reproducible examples, public contracts, versioned metadata and qualified test environments.

Do not expand the CLI, SDK, or profile surface without the proofs below. External applications consume an installed package through public interfaces and have independent repositories. Keep their logic out of compiler internals.

## Change and proof contract

1. Prove every behavior change RED-first: a failing test names the defect before the fix, and the fix turns it green without weakening the test.
2. Run the affected lanes before finishing: host unit, compiler, and packaging lanes via `ci/test_lanes.py`, and every guest-backed suite the change can reach via `ci/run_vm_tests.py` on the pinned lanes. A new red blocks the change.
3. Claim only what passes on the current tree. Unsupported is stated unsupported. A skipped, unavailable, or unrun check is never counted as a pass, and a kernel is claimed only by a full matrix pass on that kernel.
4. Keep kernel loads inside disposable guests. Build, check, and inspect stay unprivileged; nothing in this repository loads programs on the build host.

A compiler target listing, disassembly, constant return or successful load alone is insufficient proof of behavior.

## Compiler and SDK invariants

Mojo 1.1.0 is the pinned compiler (see `toolchains.lock.json` and `docs/compatibility.md`); anything else needs its own qualification run. Use official Mojo syntax guidance where available, then compile against the pinned version. An agent skill is not a product dependency or a source of kernel support guarantees.

Build/test hosts are x86-64 Linux with little-endian BPF; `linux-bpfel-v3` is the base profile with seven capability profiles beside it (see `docs/compatibility.md`). Candidate guest kernels are pinned by hash in `ci/kernels.lock.json`; no kernel is supported until the release matrix proves it.

Preserve source semantics, verifier-relevant pointers and ABI layouts. Do not blindly replace a host target triple, erase error paths or use regex rewriting as the production IR transform. Reject unsupported reachable runtime, allocation, exception, floating-point, vector and indirect-call behavior explicitly. Supported fixed-width integer scalars must not be rejected merely for their one-lane SIMD representation.

Keep nullable map access checked, packet bounds explicit, records and padding initialized, and map/BTF/decoder layouts independently verified. Map BTF is an early requirement; source-line metadata and CO-RE are separate capabilities.

## Verification, evidence and licensing

Distinguish source rejection, object/loader failure, verifier rejection, unavailable environment and incorrect runtime behavior. Keep source/import/toolchain/SDK/object hashes and actual command records. A successful compilation, kernel admission and matching oracle are distinct assertions. Mandatory unavailable tests cannot pass a gate.

Use structural checks plus independent runtime oracles. Privileged load/test-run steps run only inside disposable KVM guests driven by the pinned lanes; never attach to the interface carrying an SSH session or remove unrelated BPF resources. Register owned-resource cleanup, retain interruption evidence, and record the exact lane, kernel, and suite verdict for every guest claim.

The toolchain license, dependency licenses, BPF source grants and ELF kernel license string are distinct. Never substitute `GPL` to unlock helpers. Record upstream URLs, exact revisions, hashes, modifications and applicable notices for bundled material. New license grants and publication require maintainer authorization.

For setup/documentation changes, verify links, scope, provenance and whitespace. For compiler/SDK changes, run the affected compile, IR, ELF, verifier and semantic tests and report their practical limits. Document only observed support.
