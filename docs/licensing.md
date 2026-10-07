<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF licensing (0.1.0)

How licenses flow through the tool: what the project itself
uses, what user programs must declare, and what the emitted
object carries. The tool enforces every rule below with a
named diagnostic; nothing is advisory prose.

## Project license

First-party material uses **Apache-2.0 WITH LLVM-exception**.
The complete license text is preserved byte-exact in
[`LICENSE`](../LICENSE), copied without modification from
`modular/modular` at revision
`85356f6562ed57bab8762fde38448ba5b50b69c9` (SHA-256
`077ecef8fc610215df3319c555c2fa1b4d28df60ee67a72946b9338cbc90a8a0`;
see [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md) for
the provenance record). Every first-party source file carries
an `SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception`
header or an equivalent license field (JSON documents use a
top-level `license` field or an SPDX `$comment` marker).

No third-party implementation code or compiler binaries are
bundled in this release. The wheel ships the tool modules, the
Mojo SDK sources, the adapter scripts, and the license texts
only
(`tests/packaging/test_wheel_contents.py::test_no_bundled_compiler`).

MojoBPF is an independent open-source project and is not
affiliated with or endorsed by Modular, Inc. MAX® and Mojo®
are trademarks of Modular, Inc. used under license.
Attribution follows [Modular's
policy](https://www.modular.com/legal/trademark).

## User programs: declared grants

A build manifest declares two licenses per artifact:

* `source_license`: the SPDX expression granting the program
  sources. Every program source must carry a matching SPDX
  header; a missing header fails the build with `MBPF707`
  and a disagreeing header with `MBPF702`.
* `kernel_license`: the loader-facing declaration string the
  object will carry (see below).

The declared `(source, kernel)` pair must appear in the
versioned mapping table (`LICENSE_MAPPING_VERSION = 1`), which
currently qualifies exactly one pair: `Apache-2.0 WITH
LLVM-exception` with itself. Every other pair — including
MIT, GPL, and dual-licensed arrangements — is rejected with
`MBPF703`/`MBPF704` until its own reviewed mapping lands.

```text
MBPF707 (inspect.license/error): program source '.../counter.mojo'
carries no SPDX header; ...; remedy: add an
'SPDX-License-Identifier: ...' header line
```

(The line above is the actual diagnostic a headerless source
produces; only the working path is shortened.)

## Emitted objects: declaration bytes

The adapter writes the validated kernel declaration into the
ELF `license` section verbatim, NUL-terminated
(`Apache-2.0 WITH LLVM-exception\0` in this release). The
pre-publication gate compares the final payload against the
validated declaration byte for byte:

* missing, extra, conflicting, or unterminated payloads fail
  inspection with `MBPF403`;
* payloads differing from the validated declaration fail the
  gate with `MBPF705`;
* an unknown helper ID, program type, or kfunc use fails
  closed with `MBPF706`, since the supported profile holds
  no GPL-restricted helper and no new licensing requirement
  may slip in unreviewed.

The declaration is derived from the validated manifest value
without substitution: the tool never rewrites it — to `GPL`
or anything else — to gain kernel API access
(`tests/elf/test_artifact_contract.py`,
`tests/unit/test_artifact_publication.py::test_requires_gpl_unknown_inputs`).

## Three surfaces, never confused

Source grants, dependency terms, and the kernel declaration
are distinct. The SDK and standard-library grants are
recorded separately with hashes in the evidence sidecar and
are never flattened into one convenient expression; the
kernel declaration string affects loader eligibility but
creates no license grant. See the module contract in
`src/mojobpf/inspect.py` and the
[artifact format](artifact-format.md) for the sidecar layout.
