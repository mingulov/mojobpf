<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.0 release notes

MojoBPF compiles Mojo-authored Linux eBPF programs into
conventional `EM_BPF` ELF objects loadable by unmodified
`bpftool`/libbpf. This is the first stable release: a
6-verb CLI, SDK surface 1.8, eight target profiles, and
twelve examples, proven by a 41-suite matrix on five
KVM guest kernels. It remains a narrow, proven slice, not
a general eBPF toolchain.

## What is included

* The CLI: `build`, `check`, `doctor`, `inspect`, `verify`,
  and `test`. Users write `.mojo` + `mojobpf.toml`, build
  to a standard BPF `.o`, and load with stock tooling.
* SDK surface 1.8: eight Mojo modules (`checksum`, `core`,
  `events`, `helpers`, `maps`, `packet`, `parse`,
  `uprobe`).
* Eight target profiles: `linux-bpfel-v3` base plus
  `-core`, `-hash`, `-lru`, `-net`, `-reserve`,
  `-subprog`, and `-uprobe`.
* Twelve examples: XDP pass/counter, packet
  classifier/counter, hash counter, TC and socket
  classifiers, tracepoint counter/events, uprobe counter,
  ring-buffer reserve, and subprogram call.
* XDP, tracepoint, socket, TC, and uprobe slices with the
  flipped map types (147 records), the qualified exact
  tracepoint counter and fixed-record event emitter with
  loss accounting, lifecycle proofs (classified attach
  failures, exact exit counts, interruption, clean
  repeats, fail-safe preflights), and helper license
  enforcement agreeing with the kernel verifier — without
  ever rewriting an artifact's license declaration.
* Five claimed guest kernels (Ubuntu mainline builds,
  pinned by hash): 6.6.0-060600-generic,
  6.12.0-061200-generic, 7.0.14-070014-generic,
  7.2.0-070200-generic, and 7.4.0-070400rc1-generic. The
  full 41-suite matrix passes on each (197/205 cells;
  joint cells need libbpf-mojo inputs and are labelled
  experimental, 7.x task-struct layouts are 1.x CO-RE
  work — both excluded from claims by ruling, never
  counted pass).

## Verification

The release board — host lanes, the independent
external-consumer canaries, reproducibility, and the
full five-lane KVM matrix — is recorded in
[`docs/evidence-1.0.0.md`](evidence-1.0.0.md) with the
toolchain pins, object hashes, and rerun commands. The
[quickstart](quickstart.md) was executed verbatim from a
fresh environment against the release wheel, including
guest load and packet counting on KVM; its outputs are
transcribed from that run. Nothing in this release is
claimed without a runnable test or an observed run
behind it.

## Limitations

This release explicitly does not support CO-RE beyond
the relocation probe, tail calls and program
composition, helpers beyond the audited per-shape sets,
map kinds beyond the flipped records, full Mojo
userspace (the libbpf-mojo joint slice beyond the
proven operations is labelled experimental), host
architectures beyond x86-64, or performance claims from
TCG runs. Per-lane verdicts are pinned, never skipped:
the `loop-sum` subset case verifies on all lanes
except 6.6, where the verifier rejects the back edge;
7.x kernels refuse short test-run inputs with EINVAL
(XDP below 14 bytes; TC/socket below 34 bytes). All
details and proof pointers live in
[`docs/compatibility.md`](compatibility.md).

## License

First-party material is **Apache-2.0 WITH LLVM-exception**
(see `LICENSE` and `THIRD_PARTY_NOTICES.md`, both shipped in
the wheel). Dependencies and user-authored BPF programs keep
their own licensing. An ELF license declaration must
accurately reflect its program and is never rewritten to
gain kernel API access. See [`docs/licensing.md`](licensing.md)
for the enforced declaration behavior.
