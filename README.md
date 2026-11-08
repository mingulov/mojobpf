<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF

Linux eBPF programs written in Mojo.

MojoBPF is an independent toolchain and SDK project intended to compile Mojo-authored kernel programs into standard BPF ELF objects usable with existing Linux loaders.

**Status:** 0.3.0a1. MojoBPF compiles Mojo-authored XDP, tracepoint, socket-filter, TC classifier, and uprobe programs into standard BPF ELF objects through a validated pipeline, with kernel behavior proofs behind every supported shape. This tree supports 8 target profiles: `linux-bpfel-v3` (base) plus `linux-bpfel-v3-core`, `linux-bpfel-v3-hash`, `linux-bpfel-v3-lru`, `linux-bpfel-v3-net`, `linux-bpfel-v3-reserve`, `linux-bpfel-v3-subprog`, and `linux-bpfel-v3-uprobe`. Per-CPU-hash maps are implemented in-tree but unclaimed: `linux-bpfel-v3-percpu-hash` is not supported in this release (see [compatibility](docs/compatibility.md)). The installable 6-verb CLI (`mojobpf build/check/doctor/inspect/verify/test`), the versioned SDK surface (1.8, eight Mojo modules), and 12 examples ship with clean-install and compatibility proofs; the SDK remains the proven slices, not a complete standard library. No kernel is claimed by this tree: each candidate lane (6.6, 6.12, 7.0.14, 7.2, 7.4-rc1, all KVM) is claimed only by a full 41-suite matrix pass, which is pending. The historical 0.3.0a1 alpha matrix (28 suites, software emulation, 6.12 + 6.6) does not qualify the current tree.

Start with the [quickstart](docs/quickstart.md) (reference walkthrough; the installed end-to-end re-proof on the current tree is pending the release matrix), then see [docs/architecture.md](docs/architecture.md) for the validated pipeline, the pinned toolchain, and the [explicit non-claims](docs/architecture.md#explicit-non-claims) bounding this result. See [docs/install.md](docs/install.md) for installation, [docs/sdk.md](docs/sdk.md) for the versioned SDK surface, [docs/compatibility.md](docs/compatibility.md) for supported profiles and limitations, [docs/licensing.md](docs/licensing.md) for license behavior, [docs/artifact-format.md](docs/artifact-format.md) for the emitted layouts, [docs/diagnostics.md](docs/diagnostics.md) for the diagnostic catalog, and [docs/release-notes-0.3.0a1.md](docs/release-notes-0.3.0a1.md) with its [evidence record](docs/evidence-0.3.0a1.md) for the historical alpha summary.

The build driver is Python, with a small exact-match LLVM adapter that lowers helper calls and retargets module metadata. The kernel-side algorithm remains Mojo. C reference programs and a minimal loader/test harness establish independent controls.

See [AGENTS.md](AGENTS.md) for contribution and verification requirements.

First-party material uses **Apache-2.0 WITH LLVM-exception**; see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Dependencies and user-authored BPF programs retain their own licensing. An ELF license declaration must accurately reflect its program and must not be changed automatically to gain kernel API access.

MojoBPF is an independent open-source project and is not affiliated with or endorsed by Modular, Inc.

MAX® and Mojo® are trademarks of Modular, Inc. used under license. Attribution follows [Modular's policy](https://www.modular.com/legal/trademark).
