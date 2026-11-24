<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF

Linux eBPF programs written in Mojo.

MojoBPF is an independent toolchain and SDK project intended to compile Mojo-authored kernel programs into standard BPF ELF objects usable with existing Linux loaders.

**Status:** 1.0.1. MojoBPF compiles Mojo-authored XDP, tracepoint, socket-filter, TC classifier, and uprobe programs into standard BPF ELF objects through a validated pipeline, with kernel behavior proofs behind every supported shape. This tree supports 8 target profiles: `linux-bpfel-v3` (base) plus `linux-bpfel-v3-core`, `linux-bpfel-v3-hash`, `linux-bpfel-v3-lru`, `linux-bpfel-v3-net`, `linux-bpfel-v3-reserve`, `linux-bpfel-v3-subprog`, and `linux-bpfel-v3-uprobe`. Per-CPU-hash maps are implemented in-tree but unclaimed: `linux-bpfel-v3-percpu-hash` is not supported in this release (see [compatibility](docs/compatibility.md)). The installable 6-verb CLI (`mojobpf build/check/doctor/inspect/verify/test`), the versioned SDK surface (1.8, eight Mojo modules), and 12 examples ship with clean-install and compatibility proofs; the SDK remains the proven slices, not a complete standard library. Two guest kernels run green on the 1.0.1 board (6.6.0 and 6.12.0, both KVM): the 28-suite gating scope passes on each lane (56/56 cells; see the [evidence record](docs/evidence-1.0.1.md), board commit 330226e, see [compatibility](docs/compatibility.md)). [TBD: scope/claim sentence pending O-2 owner words.] The historical 1.0.0 matrix (197/205 cells, five lanes; see the [1.0.0 release notes](docs/release-notes-1.0.0.md) and [evidence record](docs/evidence-1.0.0.md)) and the 0.3.0a1 alpha matrix do not qualify the current tree.

Start with the [quickstart](docs/quickstart.md) (reference walkthrough, executed verbatim against the release wheel), then see [docs/architecture.md](docs/architecture.md) for the validated pipeline, the pinned toolchain, and the [explicit non-claims](docs/architecture.md#explicit-non-claims) bounding this result. See [docs/install.md](docs/install.md) for installation, [docs/sdk.md](docs/sdk.md) for the versioned SDK surface, [docs/compatibility.md](docs/compatibility.md) for supported profiles and limitations, [docs/licensing.md](docs/licensing.md) for license behavior, [docs/artifact-format.md](docs/artifact-format.md) for the emitted layouts, [docs/diagnostics.md](docs/diagnostics.md) for the diagnostic catalog, and the [evidence record](docs/evidence-1.0.1.md) for the current release ([1.0.1 notes](docs/release-notes-1.0.1.md); [1.0.0 notes](docs/release-notes-1.0.0.md) with its [evidence record](docs/evidence-1.0.0.md), and [0.3.0a1 notes](docs/release-notes-0.3.0a1.md), are historical).

## Obtain

```bash
git clone https://github.com/mingulov/mojobpf.git
```

Release assets (wheel, source archive, checksums) publish with
the `v1.0.1` GitHub Release at release time; until then, build
from the checkout above ([installation](docs/install.md)).

The build driver is Python, with a small exact-match LLVM adapter that lowers helper calls and retargets module metadata. The kernel-side algorithm remains Mojo. C reference programs and a minimal loader/test harness establish independent controls.

See [AGENTS.md](AGENTS.md) for contribution and verification requirements.

First-party material uses **Apache-2.0 WITH LLVM-exception**; see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Dependencies and user-authored BPF programs retain their own licensing. An ELF license declaration must accurately reflect its program and must not be changed automatically to gain kernel API access.

MojoBPF is an independent open-source project and is not affiliated with or endorsed by Modular, Inc.

MAX® and Mojo® are trademarks of Modular, Inc. used under license. Attribution follows [Modular's policy](https://www.modular.com/legal/trademark).
