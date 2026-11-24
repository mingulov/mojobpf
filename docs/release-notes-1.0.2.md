<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.2 release notes

MojoBPF compiles Mojo-authored Linux eBPF programs into
conventional `EM_BPF` ELF objects loadable by unmodified
`bpftool`/libbpf. This is a supply-chain and CI hygiene cut
on the 1.0 line: no product code changes, same CLI, SDK
surface, profile set, and examples, with the guest board
standing unchanged (140/140 cells at the 1.0.1 board
commit) and the host lanes re-run green on the release
commit.

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

The 7.4 entry names exactly the `7.4.0-070400rc4-generic`
build pinned by hash in `ci/kernels.lock.json`, the latest
release candidate at cut time. It is not a promise for any
other 7.4 release candidate or for the 7.4 final; each needs
its own qualifying run.

## Claim set

* 6-verb CLI (`build`, `check`, `doctor`, `inspect`,
  `verify`, `test`); SDK surface 1.8 (eight Mojo modules);
  2 stable target profiles (`linux-bpfel-v3` base plus
  `-hash`) with 6 preview profiles (`-core`, `-lru`, `-net`,
  `-reserve`, `-subprog`, `-uprobe`); 12 examples.
* Guest board: 28 gating suites (41 registry minus
  `kernel-joint`, `kernel-percpu-hash`, and 11 nightly
  `kernel-isa-*`, including the `kernel-isa-cpu` smoke) on
  five lanes — 6.6.0-060600-generic, 6.12.0-061200-generic,
  7.0.14-070014-generic, 7.2.0-070200-generic (KVM finals),
  and the exact 7.4.0-070400rc4-generic build — 140 cells
  green 140/140, unchanged from 1.0.1 (no product code
  change, no guest re-board; see
  [evidence](evidence-1.0.2.md)).
* Capability registry: 147 IMPLEMENTED of 1451 records
  (1304 PLANNED) at the candidate tree.
* Host lanes: unit 27/27 modules (1932 nodes), compiler
  84/84 modules (5133 nodes), package 2/2 modules, smoke 4/4
  modules (79 nodes), re-run green on the release commit
  (see [evidence](evidence-1.0.2.md)).

## What changed in 1.0.2

* All GitHub Action pins move to current releases
  (checkout v7.0.1, upload-artifact v7.0.2,
  download-artifact v8.0.2, attest-build-provenance v4.2.2,
  action-gh-release v3.0.4, codeql upload-sarif v4.39.5),
  still full-SHA pinned, with exact-SHA tests over every
  workflow; Dependabot files update PRs for future bumps.
* The release workflow proves the sdist rebuilds a
  byte-identical wheel, writes a `SHA256SUMS` manifest over
  every attached artifact plus the versioned records, and
  attaches the checksums and evidence records to the draft
  itself.
* Every release ships CycloneDX SBOMs for the wheel and
  the sdist, emitted by the committed stdlib-only
  `ci/release_sbom.py` (no new pinned inputs).
* Signed tags are publicly verifiable: `docs/allowed_signers`
  carries the release principal and key, and RELEASING.md
  documents the signing configuration.
* OpenSSF Scorecard scans every push and pull request and
  uploads SARIF to code scanning (results are not published
  externally).

## Preview set

* Six preview profiles (`-core`, `-lru`, `-net`, `-reserve`,
  `-subprog`, `-uprobe`): present and tested, no stability
  promise; promotion needs a gating board plus a label change.
* The 11 nightly ISA suites: ran green once on the 6.12 KVM
  lane at a pre-release commit (not on the release commit or
  the other lanes); reported outside the claim tally.
* `linux-bpfel-v3-percpu-hash`: implemented in-tree with
  refusal guards; not admitted, not claimed.

## Deferred set

* CO-RE breadth beyond pinned shapes; 7.4 release
  candidates other than the claimed rc4 build, and the 7.4
  final (each needs its own cut to claim).
* AArch64 guest lane; non-x86 hosts; big-endian BPF.
* `mojobpf` lock/init verb; reproducible wheel
  container bytes; `mojobpf-lower` binary distribution.
* Hardware-backed proofs: not claimed;
  hardware-blocked, tracked in 1.x.

## Known issues

* The 1.0.0 module-18 subtests-closure gap shows no in-lane
  failure in this cut (compiler 84/84); kept listed until
  the mechanism is independently closed.
* CI executes the unit lane only on hosted runners
  (compiler/package/VM: NOT RUN until a runner is
  provisioned); see the workflow summary wording.
* No linter is configured (report-only adoption is future
  work; recorded as known debt, not a gate).

## Upgrade notes (vs 1.0.1)

No behavior change: same CLI, SDK, profiles, examples, and
guest qualification. Install the 1.0.2 wheel from the
release page as before. New in this cut: `SHA256SUMS` and
CycloneDX SBOMs ship as release assets; the release tag
verifies against `docs/allowed_signers`; CI adds the
Scorecard scan. The 1.0.1 notes stay the reference for the
guest-board run itself.
