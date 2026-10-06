<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF

Linux eBPF programs written in Mojo.

MojoBPF is an independent toolchain and SDK project intended to compile Mojo-authored kernel programs into standard BPF ELF objects usable with existing Linux loaders.

**Status:** initial repository setup. There is no implemented compiler pipeline, installable CLI, supported SDK or validated kernel profile yet.

The first development milestone is a small feasibility proof: actual Mojo code must execute an input-dependent XDP program in Linux and update a map through a helper, with independent expected results. Compiler target semantics, the entry ABI, runtime absence and map metadata must all be demonstrated before expanding the SDK.

The planned build driver uses Python, with a small LLVM adapter only if required. The kernel-side algorithm remains Mojo. C reference programs and a minimal loader/test harness establish independent controls.

See [AGENTS.md](AGENTS.md) for contribution and verification requirements. Source and test directories will be introduced with working experiments and their acceptance checks.

First-party material uses **Apache-2.0 WITH LLVM-exception**; see [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Dependencies and user-authored BPF programs retain their own licensing. An ELF license declaration must accurately reflect its program and must not be changed automatically to gain kernel API access.

MojoBPF is an independent open-source project and is not affiliated with or endorsed by Modular, Inc.

MAX® and Mojo® are trademarks of Modular, Inc. used under license. Attribution follows [Modular's policy](https://www.modular.com/legal/trademark).
