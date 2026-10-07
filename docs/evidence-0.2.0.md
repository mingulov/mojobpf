<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.2.0 evidence summary

The release regression anchor: every suite below ran green on
the release tree. The two-lane matrix ran on commit
`a6e640a6247d0dec8ea978e3b75ab342136b3671` with a clean tree
(the runner refuses dirty trees and re-checks the commit
mid-run); this document, `checksums-0.2.0.md`,
`release-notes-0.2.0.md`, and the quickstart transcription
landed afterwards in the release commit as docs-only
additions no suite executes (4 files; no `.py` under
`tests/`, `src/`, or `ci/` references them, no suite walks
`docs/`, and the only direct doc reads target `sdk.md` and
`supported-subset.md`, untouched by that delta), with the
fast suites re-run on the release commit to confirm.

Release commit: the commit carrying this document (the
docs-only amendment of the matrix commit described above).
Matrix commit: `a6e640a6247d0dec8ea978e3b75ab342136b3671`.

## Anchor board

| Suite | Command | Result |
|---|---|---|
| Unit | `python3 -m pytest tests/unit -q` | 303 passed |
| Structural contract | direct `python3` per file: `tests/ir` (5), `tests/compile` (4), `tests/elf` (12), `tests/verifier/test_subset_doc.py`, `tests/differential` (2) | 24/24 files exit 0 (incl. 50/50 rejection corpus, 68/68 packet differential) |
| Packaging | `tests/packaging/test_wheel_contents.py`, `test_sdk_compat.py`, `test_installed_build.py` direct | 3/3 exit 0 |
| Feasibility reproduction | `python3 tests/probes/run_feasibility.py` | 4 suites green, 6/6 hashes match |
| VM matrix, 6.12 lane | `python3 ci/run_vm_tests.py --out-dir matrix-out --consumer-path <independent-toolchain>` | 16/16 lane-suites pass |
| VM matrix, 6.6 lane | (same run) | 16/16 lane-suites pass |

Matrix total: 32/32 lane-suites pass, 448 `PASS` lines,
0 failures, 0 environment failures. Per-suite passes per
lane: kernel-xdp 5, kernel-map 6, kernel-packet 13,
kernel-parse 8, kernel-array 9, kernel-percpu 17,
kernel-accounting 20, kernel-generalized 17,
kernel-mojopercpu 19, kernel-tracepoint 10, kernel-events 12,
kernel-tracing-lifecycle 20, verifier-subset 16,
verifier-licenses 14, packaging-consumer 10, kernel-cleanup
28.

## Toolchain the anchor ran

* Host/compound tools: Python 3.14.4, pytest 9.0.2, Mojo
  1.1.0 (`8189361e`), LLVM `llc` 21.1.8, `bpftool` 7.7.0
  with libbpf 1.7, virtme-ng 1.41, QEMU 10.2.1.
* Guest lanes (both software-emulated, pinned by hash in
  `ci/kernels.lock.json`): 6.12.0-061200-generic and
  6.6.0-060600-generic (Ubuntu mainline builds).
* The consumer suite in every run resolved Mojo 1.1.0 from
  an independently installed toolchain outside the checkout
  (PATH-only, no checkout-derived paths); every lane-suite
  asserts its guest kernel identity.

## Key release proofs (all observed in the anchor)

* Tracing in the matrix: exact tracepoint counts (N=10000
  plus excluded zeros, bogus-filter and TGID-mutant
  mismatch controls), fixed-record event contents with
  exact accounting (healthy 3000/0, saturation 2000/102/
  1898 with the contiguous 0..101 prefix, crash 2500
  contiguous with failed=0 at offset 80000), and lifecycle
  behavior (classified attach failures, exact exit-500,
  strict 0 < frozen < N interruptions, clean repeats,
  fail-safe preflights, kernel GPL rejection) — all in both
  lanes on the same bits.
* External consumer: own manifest plus own Mojo XDP counter
  built through the installed tool only, exact kernel result
  (action 2, map 41 → 42 → 43) in both lanes; the built
  object (`bd1520ce…`) is byte-identical in both lanes, and
  the canary source differs from every in-tree Mojo source.
* Kernel-version boundaries: the `loop-sum` subset case
  passes with oracle-predicted actions on 6.12 and is
  rejected by the 6.6 verifier with the exact pinned line
  (`back-edge from insn 18 to 19`); the `arena` map type is
  available on 6.12 and refused by fail-safe preflight on
  6.6 — per-lane verdicts, never skips.
* Cleanup and reproducibility: 28 cleanup `PASS` lines from
  13 test methods in both lanes (repeat load/unload leaves
  guest listings byte-identical; timeout/interrupt runs
  reap their process groups with no strays); two-path builds
  produce identical objects equal to the feasibility pins
  (`17570ee7…`/`18f74906…`).
* Quickstart: the documented fresh-environment run built
  the counter (`b26791510be38c737fe52a7236ee4484df2e7dbb4f5fffc007175532c6122a60…`), inspected clean, and passed
  `verify --kernel` (guest load plus unload, no attach).
* Revision equality: the six SDK sources and three adapter
  scripts are byte-identical across the source tree, the
  installed package, and the wheel (9/9 equal; see
  [checksums](checksums-0.2.0.md)).

## Rerunning

From a clean checkout of the tree carrying this document
with the toolchain above on `PATH`:

```bash
python3 -m pytest tests/unit -q
for t in tests/ir/test_*.py tests/compile/test_*.py \
    tests/compile/subset/test_*.py tests/elf/test_*.py \
    tests/verifier/test_subset_doc.py tests/differential/test_*.py \
    tests/packaging/test_wheel_contents.py \
    tests/packaging/test_sdk_compat.py \
    tests/packaging/test_installed_build.py; do
  python3 "$t" || exit 1
done
python3 tests/probes/run_feasibility.py
python3 ci/run_vm_tests.py --out-dir matrix-out \
    --consumer-path <independent-toolchain>
```

Guest-backed suites take tens of minutes under software
emulation. A missing tool, guest image, or lane fails its
run loudly; nothing passes by skipping.
