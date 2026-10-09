<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Migrating suite results to test-contracts-v1

Existing suites report text lines (`PASS ...`, `FAIL ...`,
`ENVIRONMENT FAILURE ...`) and exit codes (0 success, 1 failure,
2 environment failure), which `ci/run_vm_tests.py` folds into a
per-suite `pass`/`fail`/`envfail`/`timeout` outcome. The frozen
`test-contracts-v1`/`suite-result-v1` records replace that text
scraping with structured, hash-bound records. **Only the runner
owner edits `ci/run_vm_tests.py` and the suite wrappers**; this
note maps the old conventions onto the new contracts so wrapper
authors know what the runner will expect.

## Concept mapping

| Old convention | New contract |
|---|---|
| `PASS <name>` line | `CaseResult` with `outcome: PASS`, matching `expected`/`observed`, non-empty `evidence` digests, `CLEAN` cleanup |
| `FAIL <name>` line | `CaseResult` with `outcome: FAIL` and the structured `failure_stage` where the workload actually failed |
| `ENVIRONMENT FAILURE` line | `CaseResult` with `outcome: INFRA_ERROR` or `NOT_RUN` plus the independent `applicability` value (`HARDWARE_MISSING`, `TOOLCHAIN_UNAVAILABLE`, ...) |
| Exit 0 with passes and no failures | Per-cell evidence; the gate still requires every required cell, so one passing suite never implies a passing gate |
| Exit 1 | One or more `FAIL` cells, or a rejected record (wrong hash, duplicate, unplanned case) |
| Exit 2 / `envfail` | Blocked cells (`INFRA_ERROR` finals, unavailable hardware, missing target); reported separately, never green |
| `timeout` outcome | `INFRA_ERROR` at the interrupted stage with preserved partial attempts, never a silent retry |
| Suite log file | `evidence` entries with `path`/`sha256`/`bytes`; raw data must support the verdict without trusting one printed line |

## Rules for wrapper output during migration

1. Keep emitting the current `PASS`/`FAIL` lines until the runner
   owner migrates each wrapper; existing suites keep working
   unchanged (additive only).
2. Never print a bare success line as the only proof of a new
   contract cell: a `PASS` without evidence digests is rejected as
   forged success.
3. Report availability separately from execution. A skipped
   hardware-only case is `HARDWARE_MISSING`/`NOT_RUN`, not a pass
   and not a silent omission.
4. Expected rejections (negative tests) pass only their own denial
   case and carry the stage where the denial happened; they never
   qualify the positive capability.
5. Preserve every attempt, including infrastructure failures and
   retries. A retry adds attempt N+1; resubmitting attempt 1's
   content as a replacement is rejected.
6. Name cleanup residue explicitly. `RESIDUE` fails its cell;
   `NOT_CHECKED` leaves the gate incomplete.

## Consumer acquisition

Standalone consumers (including the userspace library's tests)
import the versioned schema bundle instead of reading this
checkout. From an installed `mojobpf` package or an unpacked
source archive:

```sh
python3 -c "from mojobpf.validation import export_schema_bundle; export_schema_bundle('mojobpf-test-contracts')"
python3 -c "from mojobpf.validation import verify_schema_bundle; print(verify_schema_bundle('mojobpf-test-contracts')['version'])"
```

Verify the bundle manifest before use. The bundle is tests-only
support data; it creates no runtime dependency on this package.
