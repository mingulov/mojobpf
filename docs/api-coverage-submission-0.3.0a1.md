<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# API coverage submission 0.3.0a1 (mojobpf → libbpf-mojo)

The mojobpf-side qualified outcomes for the alpha joint
pair, in the shape the library side records coverage:
one row per exercised library operation per target cell,
with the outcome, the evidence reference, and explicit
blockers (none open). This document records the submission;
delivering it to the library side is a separate maintainer
decision, not claimed here.

Pair: mojobpf 0.3.0a1 (matrix commit `15be770…`) ×
libbpf-mojo `cc4b03d8eec3a16a336f261801deeaf6b4fdbc2f`
(nearest tag `v0.2.2`); see
[pair-matrix-0.3.0a1.md](pair-matrix-0.3.0a1.md) for the
pair identity and provenance.

## Exercised operations

The joint driver (`tests/kernel/joint_driver.mojo`) drives
exactly these library operations; nothing else in the alpha
touches the library:

| Operation | Role in the joint proof |
|---|---|
| `libbpf_mojo.object.Object` (open/load) | load the genuine Mojo kernel object into the guest kernel |
| `libbpf_mojo.maps.update_u64` | initialize map key 0 to 41 from userspace |
| `libbpf_mojo.maps.lookup_u64` | read back the kernel-observed value (42 after the run) |
| `libbpf_mojo.program.test_run` | execute the program in-kernel and observe the verdict |

## Qualified outcomes per cell

Each row is one joint case on one target; “qualified”
means the case passed on the first attempt with the staged
bytes verified (see the pair matrix for the byte-binding).
Evidence reference: the lane run id, whose case records
carry the object, source, and transcript hashes.

Target A: `6b3fc81f…` (6.12.0-061200-generic),
run `kernel-joint-v6.12-3781249-1793889403739`.
Target B: `c9e82de8…` (6.6.0-060600-generic),
run `kernel-joint-v6.6-3788895-1793891776854`.
Target C: `f11d6b15…` (7.0.14-070014-generic),
run `kernel-joint-v7.0.14-3789406-1793891930532`.

| Case | Target A | Target B | Target C |
|---|---|---|---|
| `test_guest_provenance` (staged bytes verified, pins absent) | PASS | PASS | PASS |
| `test_joint_baseline_42` (41 → run → 42) | PASS | PASS | PASS |
| `test_joint_cross_check_42` (independent read agrees) | PASS | PASS | PASS |
| `test_joint_driver_mutant_43` (mutant detected) | PASS | PASS | PASS |
| `test_joint_driver_reports_42` (driver reports 42) | PASS | PASS | PASS |
| `test_joint_driver_stale_fails_43` (stale fails exactly) | PASS | PASS | PASS |
| `test_joint_mutation_changes_value` (mutation observed) | PASS | PASS | PASS |
| `test_joint_stale_object_fails` (stale object refused) | PASS | PASS | PASS |

24/24 cells qualified, 0 failed, 0 blocked, 0
environment failures. Blockers: none open on the mojobpf
side for these four operations on these three targets.

## Scope notes for the library side

* The alpha exercises the four operations above only, with
  `u32` keys / `u64` values on `ARRAY` maps and the XDP
  program type. Other operations, widths, map kinds, and
  program types are unproven through mojobpf and must not
  be inferred from these rows.
* Target C (7.x) carries the joint suite alone; no mojobpf
  claim beyond these 8 cells extends to 7.x.
* The guest kernels, runner, and toolchain pins behind
  these outcomes are in
  [evidence-0.3.0a1.md](evidence-0.3.0a1.md).

## Request

Please record the 24 qualified cells above in the
libbpf-mojo API coverage ledger against library revision
`cc4b03d` (nearest tag `v0.2.2`), keyed by the four
operations, with the mojobpf 0.3.0a1 evidence references
(run ids and this document's pair matrix) attached per
cell. No library change is requested; this is a
coverage-recording request only.
