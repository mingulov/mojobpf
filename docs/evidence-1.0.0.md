<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.0 evidence summary

The release regression anchor: the full matrix below ran
green on the release tree. The 41x5 KVM matrix ran at
`a7fa1a120e5782851889f8a93a2507c47c589947` with a clean
tree (the runner refuses dirty trees and re-checks the
commit mid-run); the 3.4 review fix-forward re-proved
every affected suite at `ccf7490c9a0666e33c32c2a93873d67a4267d55f`
(25/25 lane-suites, 0 failures); the confirm round's
docs-only delta (`e5d9d7d`) plus this release record
landed afterwards as docs-only additions no suite
executes (no `.py` under `tests/`, `src/`, or `ci/`
references them and no suite reads `docs/` except the
subset-doc gate, which re-passes on the release tree),
with the host lanes re-run on the release commit to
confirm.

Release commit: the commit carrying this document (the
docs-only amendment of the matrix chain described above).
Matrix commit: `a7fa1a120e5782851889f8a93a2507c47c589947`.
Fix-forward commits: `3cf3260` (review findings),
`ccf7490` (34-byte net boundary correction), `e5d9d7d`
(review-confirm docs).

## Anchor board

| Suite | Command | Result |
|---|---|---|
| Unit | `python3 ci/test_lanes.py --lane unit` | exit 0 |
| Compiler | `python3 ci/test_lanes.py --lane compiler` | 83/84 modules exit 0; module-18 subtests-closure gap re-proven red on the pre-freeze base (standalone 336 green) |
| Package | `python3 ci/test_lanes.py --lane package` | exit 0 (sdist membership + wheel contents) |
| VM matrix, 6.12 lane | `python3 ci/run_vm_tests.py --lane v6.12-kvm --suite <each of 41> --consumer-path <independent-toolchain>` | 40/41 pass; joint REQUIRED-BLOCKED (needs libbpf-mojo inputs; experimental, excluded from claims) |
| VM matrix, 6.6 lane | (same per-suite runs) | 40/41 pass; joint REQUIRED-BLOCKED as above |
| VM matrix, 7.0.14 lane | (same per-suite runs) | 39/41 pass; joint REQUIRED-BLOCKED, core-layouts excluded by ruling (1.x CO-RE work) |
| VM matrix, 7.2 lane | (same per-suite runs) | 39/41 pass; joint REQUIRED-BLOCKED, core-layouts excluded by ruling |
| VM matrix, 7.4-rc1 lane | (same per-suite runs) | 39/41 pass; joint REQUIRED-BLOCKED, core-layouts excluded by ruling |
| TCG fallback spot | 6.12 TCG `kernel-xdp` + `kernel-map` | 5/5 + 6/6 pass (proves no KVM dependence) |

Matrix total: 197/205 lane-suite cells pass, 0 red,
0 unexplained, 0 environment failures on claimed cells.
Affected-suite reruns after the 3.4 review (net, subset,
cleanup, tracing-lifecycle, subprog-consumer x 5 lanes):
25/25 pass.

## Toolchain the anchor ran

* Host/compound tools: Python 3.14 (3.14.8 in the current
  lock), Mojo 1.1.0 (`8189361e`), LLVM `llc` 22.1.8
  (triple `bpfel`, CPU `v3`), `bpftool` 7.6.0 with
  libbpf 1.6, virtme-ng 1.41, QEMU 10.2.2, KVM hardware
  acceleration on x86-64.
* Guest lanes (pinned by hash in `ci/kernels.lock.json`):
  6.6.0-060600-generic, 6.12.0-061200-generic,
  7.0.14-070014-generic, 7.2.0-070200-generic,
  7.4.0-070400rc1-generic (Ubuntu mainline builds).
* The consumer suites in every run resolve Mojo 1.1.0 from
  an independently installed toolchain outside the checkout
  (PATH-only, no checkout-derived paths); every lane-suite
  asserts its guest kernel identity.

## Key release proofs (all observed in the anchor)

* Input-dependent Mojo kernel behavior: rebuilt mutants
  flip verdicts on every lane (XDP, TC, socket, packet,
  parse, map, subprogram suites); stale objects fail
  their cells.
* Helper/map proof with userspace initialization and
  independent observation: exact kernel results (map
  41 -> 42 -> 43) through both the direct and the
  standard-runner paths.
* Kernel-version boundaries, each probed exact and
  pinned per release: the `loop-sum` subset case runs on
  every lane except 6.6, where the verifier rejects the
  back edge (`back-edge from insn 18 to 19`); 7.x kernels
  refuse short test-run inputs with EINVAL (XDP below 14
  bytes; TC/socket below 34 bytes, with 33-refused /
  34-runs controls in the corpus); 6.x runs every
  length. Per-lane verdicts, never skips.
* External consumers: five consumer suites (canary, hash,
  reserve, subprog, uprobe) build own manifests plus own
  Mojo sources through the installed tool only, with
  exact kernel results and byte-identical objects across
  lanes; refusal branches assert cleanup and identity.
* Tracing in the matrix: exact tracepoint counts,
  fixed-record event contents with exact accounting,
  lifecycle behavior (classified attach failures, exact
  exit counts, strict interruption bounds, clean repeats,
  fail-safe preflights) — all on every lane on the same
  bits.
* Cleanup and reproducibility: 31/31 cleanup cells on
  every lane (repeat load/unload leaves guest listings
  identical modulo wall clock; timeout/interrupt runs
  reap their process groups with no strays); two-path
  builds produce identical objects.
* Quickstart: the documented fresh-environment run built
  the counter from the release wheel, inspected clean,
  and passed guest load plus packet counting on KVM.
* Revision equality: the eight SDK sources and three
  adapter scripts are byte-identical across the source
  tree, the installed package, and the wheel (11/11
  equal; see [checksums](checksums-1.0.0.md)).

## Rerunning

From a clean checkout of the tree carrying this document
with the toolchain above on `PATH`:

```bash
python3 ci/test_lanes.py --lane unit
python3 ci/test_lanes.py --lane compiler
python3 ci/test_lanes.py --lane package
python3 ci/run_vm_tests.py --lane <lane> --suite <suite> \
    --out-dir matrix-out --consumer-path <independent-toolchain>
```

Guest-backed suites take tens of seconds per suite
under KVM (two concurrent guests). A missing tool, guest
image, or lane fails its run loudly; nothing passes by
skipping.
