<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Uprobe subscriber (third party)

A third-party consumer of the installed `mojobpf` package. The
subscriber owns every file in this directory: `subscriber.mojo`
is a uprobe program written against the public SDK surface only,
`consumer_target.c` is the subscriber's own executable carrying
the probe sites, and `mojobpf.toml` is the subscriber's own
manifest. Nothing here is copied from the MojoBPF tree.

## What the probe does

`subscriber.mojo` exports `uprobe_entry`. On every hit of the
uprobe it is attached to, the program reads the probed call's
first argument through the SDK's pinned x86-64 register read
(`mojobpf.uprobe.uprobe_first_arg`), compares it with the watched
value in entry 0 of the two-entry array map, and adds one to the
tally in entry 1 only on a match, returning `0`. Misses and
mismatches return `0` without touching the tally.

The probe reads exactly one context word (`pt_regs` word 14,
`rdi`): any other context access is refused at build time. The
object names no attach target; the subscriber attaches the built
object to `watched_call` in the subscriber's own
`consumer_target` executable at run time, never to a system
binary. AArch64 register extraction is not claimed.

## Build

With the `mojobpf` package installed and `mojo` plus `llc` on
`PATH`, from this directory:

```bash
mojobpf build \
    --manifest mojobpf.toml \
    --out-dir out \
    --lockfile toolchains.lock.json
```

`toolchains.lock.json` is the subscriber's own toolchain pin,
written from the PATH-resolved tools the way any user pins
theirs. The build emits `subscriber_probe.bpf.o` plus a JSON
evidence sidecar recording every stage, and refuses anything
outside the `linux-bpfel-v3-uprobe` profile before publishing.

The probe target builds with the system C compiler:

```bash
cc -no-pie -fno-pie -O2 -o consumer_target consumer_target.c
```

## Run

Initialize map entry 0 with the watched argument and entry 1
with zero, load the object under program type `kprobe`, attach
to `watched_call`, run the target, and read entry 1 back: with
entry 0 holding 97, exactly the calls carrying 97 are tallied.

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
