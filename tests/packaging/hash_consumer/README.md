<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Hash tally consumer

A third-party check that the installed `mojobpf` package builds a
hash-map program end to end. `tally.mojo` is the consumer's own
two-cell tally: every execution adds one to keys 0 and 1 of the
two-entry hash map and returns `XDP_PASS`, skipping keys that are
still absent. `mojobpf.toml` declares that shape under the public
hash profile.

Build it with the installed tool and the consumer's own lockfile:

```bash
mojobpf build --manifest mojobpf.toml --out-dir out \
    --lockfile toolchains.lock.json
```

Seed both cells with 41, run once, and both read 42; run again
and both read 43. The object loads with unmodified libbpf/bpftool.

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
