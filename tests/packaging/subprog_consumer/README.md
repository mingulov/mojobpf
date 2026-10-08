<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Subprogram-call subscriber

This directory is a small external consumer of MojoBPF, kept local
for canary testing. It owns its manifest (`mojobpf.toml`) and its
Mojo XDP decision source (`subscriber.mojo`): no compiler
internals, no copied SDK implementation, no path back into the
MojoBPF tree.

`subscriber.mojo` classifies frames through one static subprogram
call: the `select_action` callee drops (returns `1`, `XDP_DROP`)
when bit 1 of byte 14 is set and passes (returns `2`,
`XDP_PASS`) otherwise, with short frames taking the pass path.
A 60-byte frame with byte 14 = `0x02` returns exactly 1; the
same frame with byte 14 = `0x01` or `0x00`, and any 10-byte
frame, return exactly 2.

The subscriber suite
(`tests/packaging/test_subprog_consumer.py`) installs the
release-candidate wheel into a fresh virtual environment, copies
this directory to an unrelated working directory with the
MojoBPF tree scrubbed from every search path, resolves `mojo`
from PATH only (an independently installed Mojo 1.1.0, never
the checkout's developer environment), builds through the
installed `mojobpf` command, and requires the exact kernel
result through the standard loader/test runner.

The consumer pins its own toolchain: the suite writes a
`toolchains.lock.json` beside the copied manifest from the
PATH-resolved tools, the way a real user pins theirs. No lockfile
is committed here because pins are machine-specific.
