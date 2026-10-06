<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Contributing to MojoBPF

## Project contract

Use **MojoBPF** for the project and `mojobpf` for the repository and CLI. The first-party default is `Apache-2.0 WITH LLVM-exception`. Preserve the exact license text and third-party notices.

The product compiles actual Mojo-authored Linux eBPF programs into conventional `EM_BPF` ELF objects loadable by unmodified supported libbpf/bpftool. The kernel-side algorithm must originate in Mojo. Source-to-C translation, hidden C implementations, custom interpreters and runtime stubs do not meet this contract.

The repository currently contains setup documentation and licensing only. No build/test wrappers, SDK or CLI exist yet. Update public status and supported capabilities as real functionality is verified.

## Work and layout

Read the README and relevant contributor contracts. Inspect Git state, worktrees and existing changes before editing; preserve unrelated work. Keep focused changes and commits. Public documentation and all required build/test inputs must be usable from a standalone clone or source archive with declared dependencies.

Create files when their deliverable needs them:

- `tests/probes/`, `tests/reference_c/`, `tests/harness/`: tool discovery, independent C controls and standard loader/test-run helpers.
- `tests/compile/`, `tests/ir/`, `tests/elf/`, `tests/kernel/`: source, ABI, artifact and real behavior proofs.
- `src/mojobpf/`: Python 3.11+ build driver, manifest, diagnostics, inspection and provenance.
- `src/mojobpf/resources/sdk/mojobpf/`: packaged Mojo SDK source.
- `compiler/`: small matching-LLVM C++ adapter only if demonstrated necessary.
- `examples/`, `docs/`, `schemas/`, `ci/`: reproducible examples, public contracts, versioned metadata and qualified test environments.

Do not generate a large empty API or test tree before feasibility. External applications consume an installed package through public interfaces and have independent repositories. Keep their logic out of compiler internals.

## First feasibility contract

1. Inventory actual Mojo/LLVM/libbpf/bpftool versions, hashes, flags and kernel capabilities.
2. Execute an independent C XDP control in the designated disposable VM and observe `XDP_PASS` (2). A permission failure must be classified as an environment failure.
3. Obtain genuine Mojo IR with an understood exported ABI and tested target/data-layout model.
4. Execute a context-taking Mojo XDP program with two packet inputs producing independently expected different actions. Source changes must alter rebuilt behavior; stale objects must fail the test.
5. Initialize a one-element array map with u32 key/u64 value to 41, let Mojo perform a checked helper lookup and update, and independently read 42. Validate standard map BTF and relocations.
6. Reproduce from clean inputs and document the smallest justified route: native target, genuine-IR adapter or bounded compiler patch.

Do not expand the SDK/CLI before that contract passes. A compiler target listing, disassembly, constant return or successful load alone is insufficient.

## Compiler and SDK invariants

Mojo 1.1.0 is the first compiler candidate, not a compatibility claim. Pin the actual working compiler/stdlib/backend combination and inspect its documented flags. Use official Mojo syntax guidance where available, then compile against the selected version. An agent skill is not a product dependency or a source of kernel support guarantees.

Start with x86-64 build/test hosts and little-endian BPF; `linux-bpfel-v3` is a candidate profile. Linux 6.6 and 6.12 are initial test-family candidates. Exact kernels/configurations, feature probes and real executions decide supported profiles.

Preserve source semantics, verifier-relevant pointers and ABI layouts. Do not blindly replace a host target triple, erase error paths or use regex rewriting as the production IR transform. Reject unsupported reachable runtime, allocation, exception, floating-point, vector and indirect-call behavior explicitly. Supported fixed-width integer scalars must not be rejected merely for their one-lane SIMD representation.

Keep nullable map access checked, packet bounds explicit, records and padding initialized, and map/BTF/decoder layouts independently verified. Map BTF is an early requirement; source-line metadata and CO-RE are separate capabilities.

## Verification, evidence and licensing

Distinguish source rejection, object/loader failure, verifier rejection, unavailable environment and incorrect runtime behavior. Keep source/import/toolchain/SDK/object hashes and actual command records. A successful compilation, kernel admission and matching oracle are distinct assertions. Mandatory unavailable tests cannot pass a gate.

Use structural checks plus independent runtime oracles. The first XDP corpus uses test-run with repeat 1; privileged operations belong in an approved disposable VM. Build, check and inspect stay unprivileged. Register owned-resource cleanup, retain interruption evidence and never attach to the interface carrying an SSH session or remove unrelated BPF resources.

The toolchain license, dependency licenses, BPF source grants and ELF kernel license string are distinct. Never substitute `GPL` to unlock helpers. Record upstream URLs, exact revisions, hashes, modifications and applicable notices for bundled material. New license grants and publication require maintainer authorization.

For setup/documentation changes, verify links, scope, provenance and whitespace. For compiler/SDK changes, run the affected compile, IR, ELF, verifier and semantic tests and report their practical limits. Document only observed support.
