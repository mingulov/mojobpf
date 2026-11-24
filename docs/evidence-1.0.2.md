<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.2 evidence summary

The release regression anchor: this cut changes no product
code (supply-chain pins, CI workflows, release tooling,
signing verifiability, version, and records only), so the
28x5 KVM release board stands unchanged at the 1.0.1 board
commit below — no guest re-board. The host lanes re-ran
green on the release tree, including the doc-reading host
tests over the new records.

MojoBPF 1.0.2 qualifies the program and map shapes its
28-suite gating board exercises (stable and preview profiles
alike; only the two stable profiles carry a stability
promise), with the pinned toolchain, on five exact x86-64 KVM
guest builds: `6.6.0-060600-generic`, `6.12.0-061200-generic`,
`7.0.14-070014-generic`, `7.2.0-070200-generic`, and
`7.4.0-070400rc4-generic`; other kernels, including other 7.4
builds, are outside the support claim.
This Beta release qualifies that bounded subset only. The
broader full-support assessment remains on hold: performance
budgets and the remaining capability-inventory work are open,
and no full-support gate has run.

Release commit: the commit carrying this document
(supply-chain/CI/docs/version only; no `src/`, `compiler/`,
or lock changes since the 1.0.1 release commit `807e8ca`).
Matrix commit: `7b0d8b2353eac386ea5485664a875059cc0be9c4`
(unchanged from 1.0.1).

Tally arithmetic: 41 registry suites minus `kernel-joint`
(stays excluded, unclaimed) minus `kernel-percpu-hash`
(non-gating exclusion) minus the 11 nightly `kernel-isa-*`
suites = 28 gating suites, including the `kernel-isa-cpu`
ISA smoke; 28 suites x 5 lanes (6.6 + 6.12 + 7.0.14 + 7.2 +
exact 7.4.0-070400rc4) = 140 cells.

## Anchor board

| Suite | Command | Result |
|---|---|---|
| Unit | `pixi run test-unit` | 27/27 modules exit 0 (TBD nodes) |
| Compiler | `pixi run test-compiler` | 84/84 modules exit 0 (TBD nodes); the 1.0.0 module-18 subtests-closure gap shows no in-lane failure in this cut |
| Package | `pixi run test-package` | 2/2 modules exit 0 (sdist membership + wheel contents) |
| Smoke | `pixi run test-smoke` | 4/4 modules exit 0 (TBD nodes) |
| VM matrix, per lane | `python3 ci/run_vm_tests.py --lane <lane> --suite <each of 28> --out-dir <lane> --consumer-path <independent-toolchain>` | 28/28 pass on each of the 5 lanes, unchanged (run detail in [evidence-1.0.1.md](evidence-1.0.1.md)) |
| Scoped merge | `python3 ci/run_vm_tests.py --merge <5 lane reports> --expect-lanes v6.6-kvm,v6.12-kvm,v7.0.14-kvm,v7.2-kvm,v7.4-rc4-kvm --expect-suites <28>` | exit 0; 140/140 lane-suites passed, unchanged |

Merged report sha256:
`248841386ccc3e3dfad232b9b5ca80a95277f6ef684065bde8dd334a41cc1831`
(`matrix-report.json` covering the 140 cells above;
unchanged from 1.0.1 — no product code change, no guest
re-board).

The 7.4 entry names exactly the `7.4.0-070400rc4-generic`
build pinned by hash in `ci/kernels.lock.json`, the latest
release candidate at cut time. It is not a promise for any
other 7.4 release candidate or for the 7.4 final; each needs
its own qualifying run.

The `kernel-joint` suite stays unclaimed; its earlier results
are retired, not cited. The 11 nightly
ISA suites report outside the gating tally.

## Toolchain the anchor ran

* Host/compound tools: Python 3.11.17 (canonical lane
  interpreter), Mojo 1.2.0 (`2016d0cd`), LLVM `llc` 22.1.8
  (triple `bpfel`, CPU `v3`), `bpftool` 7.6.0 with
  libbpf 1.6, virtme-ng 1.41, QEMU 10.2.2, KVM hardware
  acceleration on x86-64.
* Guest lanes (pinned by hash in `ci/kernels.lock.json`):
  6.6.0-060600-generic, 6.12.0-061200-generic,
  7.0.14-070014-generic, 7.2.0-070200-generic, and the exact
  7.4.0-070400rc4-generic build (Ubuntu mainline builds).
* The consumer suites in every run resolve Mojo 1.2.0 from
  an independently installed toolchain outside the checkout
  (PATH-only, no checkout-derived paths); every lane-suite
  asserts its guest kernel identity.

## Key release proofs (all observed in the anchor)

Each claimed shape maps to at least one passing guest
suite plus, where one exists, its consumer canary, on all
five lanes, on the
same bits (run detail in
[evidence-1.0.1.md](evidence-1.0.1.md)):

* Packet and parse paths: `kernel-xdp`, `kernel-packet`,
  `kernel-parse`, `kernel-net` pass on all five lanes.
* Map shapes: `kernel-map`, `kernel-array`, `kernel-hash`,
  `kernel-lru`, `kernel-percpu`, `kernel-ringbuf`,
  `kernel-mojopercpu`, `kernel-generalized`,
  `kernel-accounting` pass on all five lanes.
* Programs and control flow: `kernel-subprog`,
  `kernel-events`, `kernel-cleanup`,
  `kernel-tracing-lifecycle`, `kernel-tracepoint`,
  `kernel-uprobe`, `kernel-core-layouts` pass on all five
  lanes.
* ISA baseline: the `kernel-isa-cpu` smoke passes on all five
  lanes.
* Verifier posture: `verifier-subset` and
  `verifier-licenses` pass on all five lanes.
* External consumers: the five consumer suites
  (`packaging-consumer`, `packaging-hash-consumer`,
  `packaging-reserve-consumer`, `packaging-subprog-consumer`,
  `packaging-uprobe-consumer`) build own manifests plus
  own Mojo sources through the installed tool only, with
  exact kernel results through both the direct and the
  standard-runner paths; refusal branches assert cleanup
  and identity.
* Quickstart: the 1.0.1 clean-clone rehearsals stand (three
  verbatim passes, zero deviations; no product path
  changed). 1.0.2 re-observed the oracle from the candidate
  wheel: `xdp_counter` builds to `b74df864` (TBD full hash
  at T8), and the transcripts carry the new wheel identity.

## Rerunning

From a clean checkout of the tree carrying this document
with the toolchain above on `PATH`
(`MODULAR_HOME` from the project pixi environment):

```bash
pixi run test-unit
pixi run test-compiler
pixi run test-package
pixi run test-smoke
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
