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
| `PASS <name>` line | `CaseResult` with `outcome: PASS`, matching `expected`/`observed` (including the semantic `value`, e.g. 42), non-empty `evidence` digests, `CLEAN` cleanup |
| `FAIL <name>` line | `CaseResult` with `outcome: FAIL`, the structured `failure_stage` where the workload actually failed, and the semantic `error_class` |
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
   case, and only when the observed outcome and failure stage match
   the plan's expected denial with evidence and clean cleanup; they
   never qualify the positive capability.
5. Preserve every attempt, including infrastructure failures and
   retries. A retry adds attempt N+1; resubmitting attempt 1's
   content as a replacement is rejected.
6. Name cleanup residue explicitly. `RESIDUE` on any preserved
   attempt fails its cell permanently, as does a `NOT_CHECKED`
   earlier attempt: only `FAIL`/`INFRA_ERROR` outcomes with `CLEAN`
   cleanup may retry to `PASS`. A lone `INFRA_ERROR` that never
   reached cleanup stays blocked (incomplete), not failed.
7. Report semantic observations, not just the verdict. A `PASS`
   must observe its full expectation including `value` (a stale 41
   never satisfies an expected 42); failures carry the structured
   `error_class` instead of free-text wording.

## Schema/Python parity boundary

The JSON Schemas pin record shapes, enums, required fields and the
`PASS` outcome/`failure_stage`/evidence/cleanup skeleton, but they
cannot express full `expected`/`observed` equality for arbitrary JSON
values: JSON Schema has no cross-property comparison, so no schema
clause can state "`observed.value` equals `expected.value`" for
per-case payloads. That equality is enforced only by the Python
parser (`CaseResult.from_dict`, `MBPF305`) and the gate
(`aggregate`, `MBPF311`/`MBPF314`).

Concretely, a `PASS` record with expected `value: 42` and observed
`value: 41` is schema-valid but rejected by the parser, and every
comparison uses strict JSON types: boolean `true` never equals
number `1`, including inside nested arrays/objects and in denial
cases. Consumers that validate with the schemas alone must also run
the Python parser (or an equivalent strict comparison) before
trusting a verdict.

## Consumer acquisition

Standalone consumers (including the userspace library's tests)
import the versioned schema bundle instead of reading this
checkout. From an installed `mojobpf` package (schemas ship with
the wheel) or an unpacked source archive:

```sh
python3 -c "from mojobpf.validation import digest_of, export_schema_bundle; print(digest_of(export_schema_bundle('mojobpf-test-contracts')))"
python3 -c "from mojobpf.validation import verify_schema_bundle; print(verify_schema_bundle('mojobpf-test-contracts', '<pinned-manifest-digest>')['version'])"
```

Bootstrap: the publisher runs the export step, prints the canonical
manifest digest, and publishes it with the release. Consumers pin
that published digest independently and pass it to
`verify_schema_bundle`, which requires it — there is no unpinned
mode. The bundle is tests-only support data; it creates no
runtime dependency on this package.
