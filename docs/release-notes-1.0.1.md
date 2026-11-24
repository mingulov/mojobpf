<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.1 release notes

MojoBPF compiles Mojo-authored Linux eBPF programs into
conventional `EM_BPF` ELF objects loadable by unmodified
`bpftool`/libbpf. This is a bugfix and honesty cut on the 1.0
line: same CLI, SDK surface, profiles, and examples, with the
guest board covering five lanes (verdict pending in the
evidence record) and every count bound to its scope.

> [TBD: scope paragraph pending O-2 owner words.]

> [TBD: 7.4 RC correction sentence pending owner wording
> approval.]

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
  (see [evidence](evidence-1.0.1.md) for the merged verdict).
* Capability registry: 147 IMPLEMENTED of 1451 records
  (1304 PLANNED) at the candidate tree.
* Host lanes: unit 27/27, compiler 84/84, package 2/2,
  smoke 4/4, observed at 330226e; re-run pending
  post-migration (see [evidence](evidence-1.0.1.md)).

## Preview set

* Six preview profiles (`-core`, `-lru`, `-net`, `-reserve`,
  `-subprog`, `-uprobe`): present and tested, no stability
  promise; promotion needs a gating board plus a label change.
* The 11 nightly ISA suites: run green in the appendix
  board, reported outside the claim tally.
* `linux-bpfel-v3-percpu-hash`: implemented in-tree with
  refusal guards; not admitted, not claimed.

## Deferred set

* CO-RE breadth beyond pinned shapes; future 7.4 release
  candidates beyond the claimed rc4-exact build (each needs
  its own cut to claim).
* AArch64 guest lane; non-x86 hosts; big-endian BPF.
* `mojobpf` lock/init verb; SBOM; reproducible wheel
  container bytes; `mojobpf-lower` binary distribution.
* F05 hardware-backed proofs: not claimed;
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
* marks itself Beta (was: Production/Stable) with this
  posture paragraph;
* requires `bpftool` pins in user lockfiles (builds validate
  it exactly like the compilers) and `MODULAR_HOME` exported
  for the Mojo compiler -- see the quickstart and install
  recipes, both re-executed verbatim for this cut.

[TBD: the "correction vs narrowing" characterization of the
lane change pending O-2 -- the ruling premise and the tag's
actual five-kernel text are both cited in the check-in
packet.]
