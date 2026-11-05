<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.3.0a1 pair matrix (mojobpf × libbpf-mojo)

Which Mojo userspace library revision the alpha joint proof
ran against, which cells passed, and how the pairing is
identified. Only the pairs below ran; every other
combination is unproven, not supported.

## The qualified pair

| Side | Proven identity |
|---|---|
| mojobpf | 0.3.0a1, matrix commit `15be770c4398b7759dd1df71c0c401257a79b19a` |
| libbpf-mojo | `cc4b03d8eec3a16a336f261801deeaf6b4fdbc2f` (“Match the live tracing fixture to its BTF target”), 15 commits past nearest tag `v0.2.2` (`v0.2.2-15-gcc4b03d`), read-only |

Libbpf-mojo is an independent userspace library under its
own history; MojoBPF consumes it, never vendors it. The
joint suite takes the library through two required
environment variables that are never defaulted:
`MOJOBPF_LIBBPF_MOJO_SRC` (the checkout, using its `src/`)
and `MOJOBPF_LIBBPF_MOJO_LIB` (the built `libbpf_mojo.so`).
A missing variable fails loudly as an environment failure.

## How the lib revision is identified

The joint suite reads the library commit from the checkout
(`git rev-parse HEAD`, refusing to run when unreadable),
stages a `lib_identity.json` (checkout path, commit, `.so`
path) alongside the objects, and the guest re-verifies the
staged bytes: the provenance case passes only when the
guest-reported hashes of every staged file, including the
identity record and the `.so`, match the consumed bytes.
The evidence bundle therefore binds the exact staged
library bytes per run, but it records the identity record
by hash, not by content: the commit string above is
established from the single on-machine library checkout,
which sat at `cc4b03d` with a clean tree, unmoved since
2026-11-01 (checkout reflog), across the joint-proof
qualification and every alpha joint run. No other checkout
existed for the suite to consume.

## Cells

The joint suite (`tests/kernel/test_joint_stack.py`, 8
cases) ran green in three lanes. Each cell is
`<case-id>@<target-fingerprint>`; all 24 cells passed on
the first attempt with zero failures and zero environment
failures.

| Lane | Target fingerprint | Run id | Cells |
|---|---|---|---|
| v6.12-tcg (6.12.0-061200-generic) | `6b3fc81fc4b6c6d584dbb06d5bd64e8efd7a3affeb72973236e6a2ec4954cde2` | `kernel-joint-v6.12-3781249-1793889403739` | 8/8 pass |
| v6.6-tcg (6.6.0-060600-generic) | `c9e82de89ff9a0b84621e2f4b82230f3a96dc60f531e0169ee848fb39b5872e6` | `kernel-joint-v6.6-3788895-1793891776854` | 8/8 pass |
| v7.0.14-tcg (7.0.14-070014-generic, joint-only) | `f11d6b159ac7e44e37ec04f1ddf06774745cd0363e8055f0191e11d9f05d7f4c` | `kernel-joint-v7.0.14-3789406-1793891930532` | 8/8 pass |

The 8 cases per lane: `test_guest_provenance`,
`test_joint_baseline_42`, `test_joint_cross_check_42`,
`test_joint_driver_mutant_43`, `test_joint_driver_reports_42`,
`test_joint_driver_stale_fails_43`,
`test_joint_mutation_changes_value`,
`test_joint_stale_object_fails`.

What the cells prove: Mojo userspace through libbpf-mojo
(`Object` open/load, `lookup_u64`/`update_u64`, `test_run`)
initializes map key 0 to 41, the genuine Mojo kernel
program observes 41 and increments to 42, an independent
cross-check observes the same value, a driver mutant
carrying 43 is detected exactly, and stale objects fail
exactly. The full two-lane matrix (all 28 suites) ran on
6.12 and 6.6 only; 7.x carried the joint suite alone, so
no 7.x claim extends beyond these 8 cells.

## Rerunning the pair

```bash
MOJOBPF_TARGET_LEASE=1 \
MOJOBPF_LIBBPF_MOJO_SRC=<libbpf-mojo at cc4b03d> \
MOJOBPF_LIBBPF_MOJO_LIB=<built libbpf_mojo.so> \
python3 tests/kernel/test_joint_stack.py
```

The suite asserts its guest kernel identity and its staged
bytes; a different library revision, a dirty checkout, or a
missing variable fails loudly. The per-cell outcomes with
evidence references, in the shape the library side records
coverage, are in
[api-coverage-submission-0.3.0a1.md](api-coverage-submission-0.3.0a1.md).
