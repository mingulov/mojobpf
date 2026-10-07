<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF

Linux eBPF programs written in Mojo.

MojoBPF is an independent toolchain and SDK project intended to compile Mojo-authored kernel programs into standard BPF ELF objects usable with existing Linux loaders.

**Status:** restricted feasibility implementation. Two Mojo-authored XDP programs (a packet classifier and a helper/map round trip) compile to standard BPF ELF objects through a validated pipeline, with kernel behavior proofs. A bounds-checked packet-access SDK slice (context handle, guarded byte/half/word loads, cursor) ships with per-shape kernel behavior proofs. A parsing and checksum SDK slice (Ethernet field accessors with an optional single VLAN tag, incremental ones-complement checksums over bounded windows) ships with per-shape kernel behavior proofs against an independent model. An array map SDK slice (named update flags, documented mutation semantics, exact-count kernel proofs, per-CPU decoding validated against live kernel maps) ships with lifecycle, refusal, and layout-contract proofs. Scalar boundary behavior (endian conversions, guard edges, boundary frames) ships with in-kernel proofs plus an exhaustive host differential against an independent integer model, and ABI layout records checked across Mojo, C, and LLVM legs. Three Mojo demo programs (an SDK-built packet classifier, an invocation counter, and a combined packet counter joining content actions with both map counters in one program) ship with a 68-frame packet corpus, an independent C reference workload, per-frame in-kernel accounting proofs against an independent oracle, a host differential proof over the whole corpus, and mutation-sensitivity plus sidecar-less-load proofs. An installable CLI (`mojobpf doctor/build/inspect`) and the versioned SDK surface ship with clean-install and compatibility proofs; the SDK remains the proven slices (no complete standard library), and the supported profile stays narrow.

See [docs/architecture.md](docs/architecture.md) for the validated pipeline, the pinned toolchain, and the [explicit non-claims](docs/architecture.md#explicit-non-claims) bounding this result. See [docs/install.md](docs/install.md) for installation and [docs/sdk.md](docs/sdk.md) for the versioned SDK surface.

The planned build driver uses Python, with a small LLVM adapter only if required. The kernel-side algorithm remains Mojo. C reference programs and a minimal loader/test harness establish independent controls.

See [AGENTS.md](AGENTS.md) for contribution and verification requirements. Source and test directories will be introduced with working experiments and their acceptance checks.

First-party material uses **Apache-2.0 WITH LLVM-exception**; see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Dependencies and user-authored BPF programs retain their own licensing. An ELF license declaration must accurately reflect its program and must not be changed automatically to gain kernel API access.

MojoBPF is an independent open-source project and is not affiliated with or endorsed by Modular, Inc.

MAX® and Mojo® are trademarks of Modular, Inc. used under license. Attribution follows [Modular's policy](https://www.modular.com/legal/trademark).
