<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# External consumer canary

This directory is a small external consumer of MojoBPF, kept local
for canary testing. It owns its manifest (`mojobpf.toml`) and its
Mojo XDP counter source (`canary.mojo`): no compiler internals, no
copied SDK implementation, no path back into the MojoBPF tree.

`canary.mojo` counts invocations: on every run it adds one to entry
0 of the single-entry array map and returns `2` (`XDP_PASS`). With
the value initialized to 41 by userspace, two sequential runs
observe exactly 42 then 43.

The canary suite (`tests/packaging/test_external_consumer.py`)
installs the release-candidate wheel into a fresh virtual
environment, copies this directory to an unrelated working
directory with the MojoBPF tree scrubbed from every search path,
resolves `mojo` from PATH only (an independently installed Mojo
1.1.0, never the checkout's developer environment), builds through
the installed `mojobpf` command, and requires the exact kernel
result through the standard loader/test runner.

The consumer pins its own toolchain: the suite writes a
`toolchains.lock.json` beside the copied manifest from the
PATH-resolved tools, the way a real user pins theirs. No lockfile
is committed here because pins are machine-specific.

## Toolchain pins

The suite resolves mojo and llc without looking at the checkout
tree. When `MOJOBPF_CONSUMER_TOOLCHAIN_BIN` (a tool prefix
directory) and `MOJOBPF_CONSUMER_TOOLCHAIN_LOCK` (pins recorded
out of band) are both set, the suite admits the prefix tools
against those pins before running them, and the lockfile is
labeled admitted. Without both settings the lockfile is labeled
bootstrap: a self-pin is never an independent trust root. Record
pins out of band (version string plus entry and exec hashes) and
keep the pins document with the runner configuration, not in
this project.
