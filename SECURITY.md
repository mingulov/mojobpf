<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Security Policy

## Supported Versions

Only the latest `1.x` release is supported with security fixes.
Alpha and pre-release versions (`0.x`, including release candidates)
are not supported; upgrade to the latest `1.x` release.

| Version    | Supported |
|------------|-----------|
| latest 1.x | yes       |
| older      | no        |

## Reporting a Vulnerability

Report vulnerabilities through GitHub private vulnerability
reporting: open the repository's **Security** tab, then
**Advisories**, then **Report a vulnerability**. This is the only
supported reporting channel; there is no security contact email.

Include in the report:

- The affected version and how it was installed (wheel, source
  archive, or checkout).
- Steps to reproduce, with the smallest `.mojo` program,
  `mojobpf.toml`, or command line that triggers the issue.
- The impact you see or suspect (incorrect compiled output,
  verifier rejection of valid programs, unsafe diagnostics, or
  anything else).

Do not open a public issue for a suspected vulnerability, and do
not attach exploit material to a public thread.

## What Happens Next

A maintainer confirms receipt, reproduces the report against the
latest supported release, and works toward a fix in a private
advisory. When the fix ships, the advisory is published with
credit to the reporter unless anonymity is requested.

Out of scope: vulnerabilities in third-party toolchains (Mojo,
LLVM, bpftool, libbpf, QEMU, virtme-ng) should be reported to
their own upstreams, although a note here helps us track any
effect on MojoBPF.
