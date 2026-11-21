<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Third-party provenance

The first-party project license is **Apache-2.0 WITH LLVM-exception**. [LICENSE](LICENSE) preserves the complete license text obtained from Modular's official repository, including its original notices and exceptions.

| Item | Provenance |
|---|---|
| File | `LICENSE` |
| Upstream | [modular/modular](https://github.com/modular/modular) |
| Revision | `85356f6562ed57bab8762fde38448ba5b50b69c9` |
| Exact source | [LICENSE at that revision](https://raw.githubusercontent.com/modular/modular/85356f6562ed57bab8762fde38448ba5b50b69c9/LICENSE) |
| SHA-256 | `077ecef8fc610215df3319c555c2fa1b4d28df60ee67a72946b9338cbc90a8a0` (of the upstream bytes) |
| Modifications | 223-byte MojoBPF wrapper prefix (project license declaration); the upstream text follows verbatim from offset 223 |

This revision identifies the copied license text; it is not a selected compiler dependency. No third-party implementation code or compiler binaries are currently bundled.

| Item | Provenance |
|---|---|
| File | `capabilities/api-rows.json` |
| Upstream | [mingulov/libbpf-mojo](https://github.com/mingulov/libbpf-mojo) (`docs/api-coverage.json`) |
| Revision | `cc4b03d8eec3a16a336f261801deeaf6b4fdbc2f` |
| SHA-256 | `3ee5cad59c1bbf4f724c8fa67671e6f6e956f036b561f83657f5987e29561c16` (of the upstream bytes) |
| License | `Apache-2.0 WITH LLVM-exception` (same first-party grant; stamped in the extract header) |
| Modifications | Filtered to the 356 `function:` rows sorted by ID, plus the provenance header; row values verbatim, re-serialized with sorted keys |

Regenerate with `docs/coverage-ledger.md` after any upstream repin; the ledger header binds the extract content, revision, and upstream digest, while the suite and ritual bind the file bytes.

When dependencies or derived files are added, record their source URL, exact revision, hash, license, modifications and required notices. Preserve any original per-file terms. The toolchain's first-party license does not determine the license of user-authored BPF programs or authorize changing their ELF license declaration.
