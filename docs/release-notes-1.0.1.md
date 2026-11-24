<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.1 release notes

MojoBPF compiles Mojo-authored Linux eBPF programs into
conventional `EM_BPF` ELF objects loadable by unmodified
`bpftool`/libbpf. This is a bugfix and honesty cut on the 1.0
line: same CLI, SDK surface, profile set, and examples, with the
guest board green on five lanes (140/140 cells) and every
count bound to its scope.

MojoBPF 1.0.1 qualifies the program and map shapes its
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
  green 140/140 at one clean commit (see
  [evidence](evidence-1.0.1.md)).
* Capability registry: 147 IMPLEMENTED of 1451 records
  (1304 PLANNED) at the candidate tree.
* Host lanes: unit 27/27, compiler 84/84, package 2/2,
  smoke 4/4, re-run green on the release commit (see
  [evidence](evidence-1.0.1.md)).

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
* `mojobpf` lock/init verb; SBOM; reproducible wheel
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

## Upgrade notes (vs the v1.0.0 tag tree's actual claims)

The `v1.0.0` tag (cdc9619) notes claim a stable release with
five guest kernels (6.6.0, 6.12.0, 7.0.14, 7.2.0, 7.4.0-rc1),
a 41-suite matrix at 197/205 cells, and "(147 records)"
without a denominator. This cut:

* runs five lanes (6.6.0, 6.12.0, 7.0.14, 7.2.0, exact
  7.4.0-070400rc4) at 140 cells with the 11 nightly ISA suites
  in the appendix;
* binds 147 IMPLEMENTED to 1451 registry records;
* marks itself Beta (the v1.0.0 notes called it "the first
  stable release"; its package classifier said Alpha) with
  this posture paragraph;
* labels six of the eight profiles 1.0.0 called supported
  (`-core`, `-lru`, `-net`, `-reserve`, `-subprog`,
  `-uprobe`) as preview, with no stability promise; only
  `linux-bpfel-v3` and `-hash` are stable;
* requires `bpftool` pins in user lockfiles (builds validate
  it exactly like the compilers) and `MODULAR_HOME` exported
  for the Mojo compiler -- see the quickstart and install
  recipes, both re-executed verbatim for this cut.

Relative to the `v1.0.0` tag this is a correction, not a
narrowing of the kernel claim: the four final kernels 1.0.0
claimed stay claimed and are re-qualified on this tree, and
the 7.4 release-candidate claim moves: `7.4.0-070400rc1` is
no longer claimed, and the exact `7.4.0-070400rc4` build is
claimed instead.
The gating tally is scoped more tightly than 1.0.0's 197/205:
the 11 nightly ISA suites, `kernel-joint`, and
`kernel-percpu-hash` report outside it.
