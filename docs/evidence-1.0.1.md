<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.1 evidence summary

This page anchors the release matrix: the 28x5 KVM release
board runs at one clean commit (the runner refuses dirty
trees and re-checks the commit mid-run) via per-lane runs
plus a scoped merge (`--expect-lanes` + `--expect-suites`,
exact within the declared scope), targeting 140/140
lane-suites with 0 red, 0 unexplained, and 0 environment
failures on claimed cells. The verdict lines below fill in
when the board lands; until then this page describes the
scope plus prior observations, not a result.

> [TBD: scope/claim sentences pending O-2 owner words. The
> scope numbers below are decided; the verdict lines fill in
> when the release board lands; the sentences that turn them
> into release claims are not written yet.]

Release commit: the commit carrying the merged release board
verdict named below.
Matrix commit: <filled by the release board run>.

Tally arithmetic: 41 registry suites minus `kernel-joint`
(stays excluded, unclaimed) minus `kernel-percpu-hash`
(non-gating exclusion) minus the 11 nightly `kernel-isa-*`
suites = 28 gating suites, including the `kernel-isa-cpu`
ISA smoke; 28 suites x 5 lanes (6.6 + 6.12 + 7.0.14 + 7.2 +
exact 7.4.0-070400rc4) = 140 cells.

## Anchor board

| Suite | Command | Result |
|---|---|---|
| Unit | `pixi run test-unit` | re-run pending post-migration (was 27/27 at 330226e) |
| Compiler | `pixi run test-compiler` | re-run pending post-migration (was 84/84 at 330226e; the 1.0.0 module-18 subtests-closure gap shows no in-lane failure in this cut) |
| Package | `pixi run test-package` | re-run pending post-migration (was 2/2 at 330226e) |
| Smoke | `pixi run test-smoke` | re-run pending post-migration (was 4/4 at 330226e) |
| VM matrix, per lane | `python3 ci/run_vm_tests.py --lane <lane> --suite <each of 28> --out-dir <lane> --consumer-path <independent-toolchain>` | verdict pending the release run (28/28 per lane expected) |
| Scoped merge | `python3 ci/run_vm_tests.py --merge <5 lane reports> --expect-lanes v6.6-kvm,v6.12-kvm,v7.0.14-kvm,v7.2-kvm,v7.4-rc4-kvm --expect-suites <28>` | verdict pending (140/140 expected) |

Merged report sha256:
<filled by the release board run>
(`matrix-report.json` covering the 140 cells above, once run).

Prior observations feeding this board: 6.6 + 6.12 green 56/56
at 330226e; 7.0.14 + 7.2 + 7.4-rc1 green 84/84 + 11 ISA in the
appendix board at 59ec93d; the rc4 lane re-pinned from rc1
with re-observed fixtures.

> [TBD: exact-build rc4 scope sentence pending owner wording
> approval.]

The `kernel-joint` suite stays unclaimed; its historical
workspace receipts are retired, not cited. The 11 nightly
ISA suites report outside the gating tally.

## Toolchain the anchor ran

* Host/compound tools: Python 3.11.17 (canonical lane
  interpreter), Mojo 1.2.0 (`2016d0cd`), LLVM `llc` 22.1.8
  (triple `bpfel`, CPU `v3`), `bpftool` 7.6.0 with
  libbpf 1.6, virtme-ng 1.41, QEMU 10.2.2, KVM hardware
  acceleration on x86-64.
* Guest lanes (pinned by hash in `ci/kernels.lock.json`):
  6.6.0-060600-generic, 6.12.0-061200-generic
  (Ubuntu mainline builds).
* The consumer suites in every run resolve Mojo 1.2.0 from
  an independently installed toolchain outside the checkout
  (PATH-only, no checkout-derived paths); every lane-suite
  asserts its guest kernel identity.

## Key release proofs (observed in the T6 anchor and appendix)

Each claimed shape maps to at least one passing guest
suite plus its consumer canary, on both T6 lanes (and the
same suites on all three appendix lanes), on the same bits;
the release board re-proves every mapping on all five lanes:

* Packet and parse paths: `kernel-xdp`, `kernel-packet`,
  `kernel-parse`, `kernel-net` pass on both lanes.
* Map shapes: `kernel-map`, `kernel-array`, `kernel-hash`,
  `kernel-lru`, `kernel-percpu`, `kernel-ringbuf`,
  `kernel-mojopercpu`, `kernel-generalized`,
  `kernel-accounting` pass on both lanes.
* Programs and control flow: `kernel-subprog`,
  `kernel-events`, `kernel-cleanup`,
  `kernel-tracing-lifecycle`, `kernel-tracepoint`,
  `kernel-uprobe`, `kernel-core-layouts` pass on both
  lanes.
* ISA baseline: the `kernel-isa-cpu` smoke passes on both
  lanes.
* Verifier posture: `verifier-subset` and
  `verifier-licenses` pass on both lanes.
* External consumers: the five consumer suites
  (`packaging-consumer`, `packaging-hash-consumer`,
  `packaging-reserve-consumer`, `packaging-subprog-consumer`,
  `packaging-uprobe-consumer`) build own manifests plus
  own Mojo sources through the installed tool only, with
  exact kernel results through both the direct and the
  standard-runner paths; refusal branches assert cleanup
  and identity.
* Quickstart: the documented fresh-environment run built
  the counter from a clean-clone wheel (object byte-identical
  to the pinned `b74df864`), inspected clean, passed guest
  load/unload on the TCG and KVM lanes, and counted packets
  (3 after three runs, 8 after five more) on KVM — with two
  doc deviations recorded in the T7 rehearsal receipt (cmake
  flag, lockfile bpftool pin), to be removed by the docs
  pass and its final re-run.

## Rerunning

From a clean checkout of the tree carrying this document
with the toolchain above on `PATH`
(`MODULAR_HOME` from the project pixi environment):

```bash
pixi run test-unit
pixi run test-compiler
pixi run test-package
python3 ci/run_vm_tests.py --lane <lane> \
    --suite <s1> --suite <s2> ... --suite <s28> \
    --out-dir lane-<lane> --consumer-path <independent-toolchain>
python3 ci/run_vm_tests.py --merge \
    lane-v6.6-kvm/matrix-report.json \
    lane-v6.12-kvm/matrix-report.json \
    lane-v7.0.14-kvm/matrix-report.json \
    lane-v7.2-kvm/matrix-report.json \
    lane-v7.4-rc4-kvm/matrix-report.json \
    --out-dir board \
    --expect-lanes v6.6-kvm,v6.12-kvm,v7.0.14-kvm,v7.2-kvm,v7.4-rc4-kvm \
    --expect-suites <the 28 gating suites>
```

(One invocation per lane with all 28 `--suite` flags into its
own directory: the merge consumes exactly one report per
lane.)

Guest-backed suites take tens of seconds per suite
under KVM (two concurrent guests). A missing tool, guest
image, or lane fails its run loudly; nothing passes by
skipping.
