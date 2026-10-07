<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.1.0 evidence summary

The release regression anchor: every suite below ran green on
the release tree. The two-lane matrix ran on commit
`d769411ecdfce26a7ac778398cc80ca12b890875` with a clean tree
(the runner refuses dirty trees and re-checks the commit
mid-run); this document, `checksums-0.1.0.md`, and one
quickstart wheel-hash line landed afterwards in the release
commit as docs-only additions no suite executes (3 files; no
`.py` under `tests/`, `src/`, or `ci/` references them, no
suite walks `docs/`, and the only direct doc reads target
`sdk.md` and `supported-subset.md`, untouched by that delta),
with the fast suites re-run on the release commit to confirm.

Release commit: `5a63fc7f7b09143ea772f2b1389e3cafeee46e82`.
Matrix commit: `d769411ecdfce26a7ac778398cc80ca12b890875`.

## Anchor board

| Suite | Command | Result |
|---|---|---|
| Unit | `python3 -m pytest tests/unit -q` | 242 passed |
| Structural contract | `python3 -m pytest tests/elf tests/ir tests/compile tests/verifier tests/differential -q` | 305 passed |
| Packaging + canary | `python3 -m pytest tests/packaging -q` (independent Mojo 1.1.0 on `PATH`) | 25 passed (16 packaging + 9 canary) |
| Feasibility reproduction | `python3 tests/probes/run_feasibility.py` | 4 suites green, 6/6 hashes match |
| VM matrix, 6.12 lane | `python3 ci/run_vm_tests.py --out-dir matrix-out --consumer-path <independent-toolchain>` | 12/12 lane-suites pass |
| VM matrix, 6.6 lane | (same run) | 12/12 lane-suites pass |

Matrix total: 24/24 lane-suites pass, 336 `PASS` lines,
0 failures, 0 environment failures. Per-suite passes per
lane: kernel-xdp 5, kernel-map 6, kernel-packet 13,
kernel-parse 8, kernel-array 9, kernel-percpu 17,
kernel-accounting 20, kernel-generalized 17,
kernel-mojopercpu 19, verifier-subset 16,
packaging-consumer 10, kernel-cleanup 28.

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

* External consumer: own manifest plus own Mojo XDP counter
  built through the installed tool only, exact kernel result
  (action 2, map 41 → 42 → 43) in both lanes; the built
  object (`bd1520ce…`) is byte-identical in both lanes, and
  the canary source differs from all 78 in-tree Mojo sources.
* Kernel-version boundary: the `loop-sum` subset case passes
  with oracle-predicted actions on 6.12 and is rejected by
  the 6.6 verifier with the exact pinned line (`back-edge
  from insn 18 to 19`) — a per-lane verdict, never a skip.
* Cleanup and reproducibility: 28 cleanup `PASS` lines from
  13 test methods in both lanes (repeat load/unload leaves
  guest listings
  byte-identical; timeout/interrupt runs reap their process
  groups with no strays); two-path builds produce identical
  objects equal to the feasibility pins
  (`17570ee7…`/`18f74906…`).
* Quickstart: the documented fresh-environment run built
  the counter (`b2679151…`), inspected clean, and passed
  `verify --kernel` (guest load plus unload, no attach).
* Revision equality: the five SDK sources and three adapter
  scripts are byte-identical across the source tree, the
  installed package, and the wheel (8/8 equal; see
  [checksums](checksums-0.1.0.md)).

## Rerunning

From a clean checkout of the release commit with the
toolchain above on `PATH`:

```bash
python3 -m pytest tests/unit -q
python3 -m pytest tests/elf tests/ir tests/compile tests/verifier tests/differential -q
python3 -m pytest tests/packaging -q
python3 tests/probes/run_feasibility.py
python3 ci/run_vm_tests.py --out-dir matrix-out \
    --consumer-path <independent-toolchain>
```

Guest-backed suites take tens of minutes under software
emulation. A missing tool, guest image, or lane fails its
run loudly; nothing passes by skipping.
