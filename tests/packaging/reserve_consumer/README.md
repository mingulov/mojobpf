<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Ring-reservation consumer

A third-party check that the installed `mojobpf` package builds a
ring-reservation program end to end. `emitter.mojo` is the
consumer's own tracepoint emitter: every matching `getpid` call
reserves one 32-byte record, stamps it, and submits it, counting
attempts, submissions, and null reservations in the four-entry
array map. `mojobpf.toml` declares that shape under the public
reservation profile.

Build it with the installed tool and the consumer's own lockfile:

```bash
mojobpf build --manifest mojobpf.toml --out-dir out \
    --lockfile toolchains.lock.json
```

With the filter holding a monitored TID, N monitored calls yield
N submissions and N drained records with contiguous sequences.
The object loads with unmodified libbpf/bpftool.

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
