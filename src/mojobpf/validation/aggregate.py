# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Aggregation of case results into a coverage ledger and gate decision.

:func:`aggregate` implements ``aggregate(plan, results) -> GateDecision``.
It accepts :class:`CaseResult` objects or plain mappings; malformed
records are preserved as rejected attempts and force a non-PASS verdict
rather than raising. Every rejection carries a stable ``MBPF31x`` code:

* ``MBPF310``: unplanned case, unknown target cell, or an attempt
  number beyond the sealed ``expected_attempts``.
* ``MBPF311``: identity or hash mismatch (plan, revisions, source,
  object, consumer, fixture, corpus, run).
* ``MBPF312``: duplicate result for one (case, target, attempt).
* ``MBPF313``: broken attempt chain (retry replaced an earlier attempt).
* ``MBPF314``: inconsistent verdict (PASS on an unavailable cell, or a
  final outcome the evidence cannot support).

Verdict precedence is FAIL, then INCOMPLETE, then PASS. A denial case
passes only its own cell, and only when the observed outcome and
failure stage match the plan's expected denial with evidence and
clean cleanup; it never qualifies the positive case it guards.
Required cells with blocked availability keep the gate non-PASS
without incrementing PASS; required ``NOT_APPLICABLE`` cells keep the
gate incomplete instead of self-excluding, while optional ones are
excluded from the denominator with their IDs recorded. Cleanup
residue on any preserved attempt fails its cell permanently, as does
an unchecked (``NOT_CHECKED``) earlier attempt: only ``FAIL`` or
``INFRA_ERROR`` outcomes with ``CLEAN`` cleanup may retry to PASS.
The ledger records applicable/executed/not-run membership from the
final attempt even for poisoned cells, and blocked cells that ran to
``FAIL`` count as executed and failed as well as blocked.

Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .models import (
    AVAIL_APPLICABLE,
    AVAIL_NOT_APPLICABLE,
    BLOCKED_AVAILABILITY,
    OUTCOME_FAIL,
    OUTCOME_INFRA_ERROR,
    OUTCOME_NOT_RUN,
    OUTCOME_PASS,
    ContractError,
    CaseResult,
    RunPlan,
    SuiteResult,
)

STAGE_AGGREGATE = "validation.aggregate"


def _cell_id(case_id: str, fingerprint: str) -> str:
    return "%s@%s" % (case_id, fingerprint)


@dataclass(frozen=True)
class GateDecision:
    """Aggregation outcome with ledger, reasons and preserved attempts."""

    verdict: str
    ledger: Mapping[str, Any] = field(compare=False)
    reasons: tuple[str, ...] = ()
    rejected: tuple[Mapping[str, Any], ...] = ()
    accepted: tuple[CaseResult, ...] = ()
    suite: SuiteResult | None = field(default=None, compare=False)

    def to_suite_dict(self) -> dict[str, Any]:
        """Return the terminal SuiteResult record for this decision."""
        if self.suite is None:
            raise ContractError(
                "MBPF314",
                "no suite record: aggregation saw no run_id",
                stage=STAGE_AGGREGATE,
            )
        return self.suite.to_dict()


def _reject(
    rejected: list[dict[str, Any]],
    code: str,
    reason: str,
    index: int,
    cell: str | None,
    raw_digest: str | None,
) -> None:
    rejected.append(
        {
            "index": index,
            "cell": cell,
            "code": code,
            "reason": reason,
            "raw_digest": raw_digest,
        }
    )


def _raw_digest(value: Any) -> str | None:
    try:
        from .models import digest_of

        return digest_of(value)
    except Exception:
        return None


def _rejected_digest(entry: Mapping[str, Any]) -> str:
    """Return the suite-binding digest for one rejected attempt.

    Rejected attempts bind their raw record digest, so substituting a
    different rejected record changes the suite. Records with no
    canonical form bind the deterministic rejection entry instead.
    """
    raw = entry.get("raw_digest")
    if isinstance(raw, str):
        return raw
    from .models import digest_of

    return digest_of(
        {
            "index": entry.get("index"),
            "cell": entry.get("cell"),
            "code": entry.get("code"),
            "reason": entry.get("reason"),
        }
    )


def aggregate(
    plan: RunPlan | Mapping[str, Any],
    results: Sequence[CaseResult | Mapping[str, Any]],
) -> GateDecision:
    """Fold results against the plan into a gate decision.

    ``plan`` may be a :class:`RunPlan` or its plain mapping; a malformed
    plan raises :class:`ContractError` because there is no denominator to
    judge against. Every submitted result is preserved: accepted results
    feed the ledger, rejected ones are listed with codes and reasons.
    """
    # Model instances are revalidated through their serialized form so
    # a directly constructed or post-seal mutated object cannot bypass
    # parsing and hash checks.
    checked_plan = (
        RunPlan.from_dict(plan.to_dict())
        if isinstance(plan, RunPlan)
        else RunPlan.from_dict(plan)
    )
    by_case = {case.case_id: case for case in checked_plan.cases}
    expected_cells = checked_plan.cells()
    expected_set = set(expected_cells)
    expected_attempts = {
        cell: by_case[cell[0]].expected_attempts for cell in expected_cells
    }

    rejected: list[dict[str, Any]] = []
    accepted: list[CaseResult] = []
    seen: set[tuple[str, str, int]] = set()
    run_ids: set[str] = set()

    for index, raw in enumerate(results):
        if isinstance(raw, CaseResult):
            try:
                digest = raw.digest()
            except ContractError as exc:
                _reject(
                    rejected,
                    exc.code,
                    "malformed record: %s" % exc.diagnostic.explanation,
                    index,
                    None,
                    None,
                )
                continue
            try:
                result = CaseResult.from_dict(raw.to_dict())
            except ContractError as exc:
                _reject(
                    rejected,
                    exc.code,
                    "malformed record: %s" % exc.diagnostic.explanation,
                    index,
                    None,
                    digest,
                )
                continue
        else:
            digest = _raw_digest(raw)
            try:
                result = CaseResult.from_dict(raw)
            except ContractError as exc:
                _reject(
                    rejected,
                    exc.code,
                    "malformed record: %s" % exc.diagnostic.explanation,
                    index,
                    None,
                    digest,
                )
                continue
        cell = (result.case_id, result.target_fingerprint)
        label = _cell_id(*cell)
        if cell not in expected_set:
            _reject(
                rejected,
                "MBPF310",
                "unplanned cell %s" % label,
                index,
                label,
                digest,
            )
            continue
        key = (result.case_id, result.target_fingerprint, result.attempt)
        if key in seen:
            _reject(
                rejected,
                "MBPF312",
                "duplicate result for %s attempt %d"
                % (label, result.attempt),
                index,
                label,
                digest,
            )
            continue
        seen.add(key)
        case = by_case[result.case_id]
        if result.attempt > case.expected_attempts:
            _reject(
                rejected,
                "MBPF310",
                "%s: unplanned attempt %d beyond sealed expectation %d"
                % (label, result.attempt, case.expected_attempts),
                index,
                label,
                digest,
            )
            continue
        problems: list[str] = []
        if result.plan_hash != checked_plan.plan_hash:
            problems.append("wrong plan_hash")
        for field_name in ("repository_commit", "package", "tool"):
            if (
                result.identities[field_name]
                != checked_plan.revisions[field_name]
            ):
                problems.append("wrong %s" % field_name)
        if result.identities["source_sha256"] != case.source_sha256:
            problems.append("wrong source_sha256")
        if result.identities["object_sha256"] != case.object_sha256:
            problems.append("wrong object_sha256")
        consumer = result.identities["consumer"]
        if (
            consumer["name"],
            consumer["version"],
            consumer["artifact_sha256"],
        ) not in set(case.consumers):
            problems.append(
                "unadmitted consumer %s %s %.12s"
                % (
                    consumer["name"],
                    consumer["version"],
                    consumer["artifact_sha256"],
                )
            )
        if result.identities["workload"]["fixture_id"] != case.fixture_id:
            problems.append("wrong workload fixture_id")
        if (
            result.identities["workload"]["corpus_sha256"]
            != case.corpus_sha256
        ):
            problems.append("wrong workload corpus_sha256")
        if result.required != case.required:
            problems.append("required flag disagrees with plan")
        if result.expected != dict(case.expected):
            problems.append("expected behavior disagrees with plan")
        if problems:
            _reject(
                rejected,
                "MBPF311",
                "%s: %s" % (label, "; ".join(problems)),
                index,
                label,
                digest,
            )
            continue
        if result.outcome == OUTCOME_PASS and (
            result.applicability != AVAIL_APPLICABLE
        ):
            _reject(
                rejected,
                "MBPF314",
                "%s: PASS on %s cell cannot increment PASS"
                % (label, result.applicability),
                index,
                label,
                digest,
            )
            continue
        run_ids.add(result.run_id)
        accepted.append(result)

    if len(run_ids) > 1:
        for result in accepted:
            _reject(
                rejected,
                "MBPF311",
                "%s: mixed run_id %r in one suite"
                % (
                    _cell_id(result.case_id, result.target_fingerprint),
                    result.run_id,
                ),
                -1,
                _cell_id(result.case_id, result.target_fingerprint),
                result.digest(),
            )
        accepted = []
        run_ids = set()

    per_cell: dict[tuple[str, str], list[CaseResult]] = {}
    for result in accepted:
        per_cell.setdefault(
            (result.case_id, result.target_fingerprint), []
        ).append(result)

    # Attempt chains must be contiguous from 1: a retry preserves every
    # earlier attempt, never replaces one.
    for cell in sorted(per_cell):
        attempts = sorted(result.attempt for result in per_cell[cell])
        if attempts != list(range(1, len(attempts) + 1)):
            label = _cell_id(*cell)
            for result in per_cell[cell]:
                _reject(
                    rejected,
                    "MBPF313",
                    "%s: broken attempt chain %s" % (label, attempts),
                    -1,
                    label,
                    result.digest(),
                )
            del per_cell[cell]
    accepted = [item for cell in per_cell.values() for item in cell]

    required_cells = [
        cell for cell in expected_cells if by_case[cell[0]].required
    ]
    buckets: dict[str, list[str]] = {
        "required": [_cell_id(*cell) for cell in required_cells],
        "applicable": [],
        "executed": [],
        "passed": [],
        "failed": [],
        "blocked": [],
        "not_run": [],
    }
    reasons: list[str] = []
    excluded: list[str] = []
    failed_required = False
    incomplete_required = False

    for cell in expected_cells:
        case = by_case[cell[0]]
        label = _cell_id(*cell)
        cell_results = sorted(
            per_cell.get(cell, []), key=lambda item: item.attempt
        )
        if not cell_results:
            if any(
                entry.get("cell") == label
                and entry.get("code") in ("MBPF312", "MBPF313")
                for entry in rejected
            ):
                buckets["failed"].append(label)
                if case.required:
                    failed_required = True
                    reasons.append("%s: rejected attempts" % label)
            else:
                # Missing case or dropped shard: the cell never arrived.
                buckets["not_run"].append(label)
                if case.required:
                    incomplete_required = True
                    reasons.append("%s: missing cell" % label)
                else:
                    reasons.append("%s: missing optional cell" % label)
            continue
        if len(cell_results) < expected_attempts[cell]:
            buckets["not_run"].append(label)
            if case.required:
                incomplete_required = True
                reasons.append(
                    "%s: dropped attempt (%d of %d preserved)"
                    % (label, len(cell_results), expected_attempts[cell])
                )
            else:
                reasons.append(
                    "%s: dropped optional attempt (%d of %d preserved)"
                    % (label, len(cell_results), expected_attempts[cell])
                )
            continue
        dirty = [
            result.attempt
            for result in cell_results
            if result.cleanup["status"] == "RESIDUE"
        ]
        unchecked = [
            result.attempt
            for result in cell_results[:-1]
            if result.cleanup["status"] == "NOT_CHECKED"
        ]
        if dirty or unchecked:
            # Residue on any preserved attempt fails the cell
            # permanently, as does an unchecked earlier attempt: a
            # later passing retry proves neither that residue was
            # cleaned nor that cleanup was ever checked. Only FAIL or
            # INFRA_ERROR outcomes with CLEAN cleanup may retry to
            # PASS. The final attempt's own NOT_CHECKED status keeps
            # its per-outcome meaning below (a lone INFRA_ERROR that
            # never reached cleanup stays blocked, not failed).
            poisoned_final = cell_results[-1]
            if poisoned_final.applicability == AVAIL_APPLICABLE:
                buckets["applicable"].append(label)
            if poisoned_final.outcome in (OUTCOME_PASS, OUTCOME_FAIL):
                buckets["executed"].append(label)
            if poisoned_final.outcome == OUTCOME_NOT_RUN:
                buckets["not_run"].append(label)
            buckets["failed"].append(label)
            poison = []
            if dirty:
                poison.append(
                    "cleanup residue on attempt(s) %s"
                    % ", ".join(str(n) for n in dirty)
                )
            if unchecked:
                poison.append(
                    "cleanup not checked on attempt(s) %s"
                    % ", ".join(str(n) for n in unchecked)
                )
            if case.required:
                failed_required = True
                reasons.append("%s: %s" % (label, "; ".join(poison)))
            else:
                reasons.append(
                    "%s: optional %s" % (label, "; ".join(poison))
                )
            continue
        final = cell_results[-1]
        for earlier in cell_results[:-1]:
            if earlier.outcome != OUTCOME_PASS:
                reasons.append(
                    "%s: attempt %d %s at %s superseded by attempt %d"
                    % (
                        label,
                        earlier.attempt,
                        earlier.outcome,
                        earlier.failure_stage,
                        final.attempt,
                    )
                )
        if final.applicability == AVAIL_NOT_APPLICABLE:
            if case.required:
                buckets["blocked"].append(label)
                if final.outcome == OUTCOME_NOT_RUN:
                    buckets["not_run"].append(label)
                incomplete_required = True
                reasons.append(
                    "%s: required cell reports NOT_APPLICABLE, "
                    "cannot qualify" % label
                )
            else:
                excluded.append(label)
                reasons.append("%s: not applicable, excluded" % label)
            continue
        if final.applicability == AVAIL_APPLICABLE:
            buckets["applicable"].append(label)
        else:
            buckets["blocked"].append(label)
            if final.outcome == OUTCOME_NOT_RUN:
                # Availability and execution are independent
                # dimensions: an unavailable cell that never ran is
                # both blocked and not run.
                buckets["not_run"].append(label)
            if final.outcome == OUTCOME_FAIL:
                # A blocked cell that ran to FAIL is both blocked
                # and failed: it counts as executed and failed while
                # the gate still reports the block. FAIL outranks
                # INCOMPLETE in verdict precedence.
                buckets["executed"].append(label)
                buckets["failed"].append(label)
                if case.required:
                    failed_required = True
                    reasons.append(
                        "%s: %s, failed at %s"
                        % (label, final.applicability,
                           final.failure_stage)
                    )
                else:
                    reasons.append(
                        "%s: optional cell %s, failed at %s"
                        % (label, final.applicability,
                           final.failure_stage)
                    )
                continue
            if case.required:
                blocked_reason = "%s: %s, cannot qualify" % (
                    label,
                    final.applicability,
                )
                if final.applicability in BLOCKED_AVAILABILITY:
                    reasons.append(blocked_reason)
                    incomplete_required = True
                else:  # pragma: no cover - enum is closed above
                    reasons.append(blocked_reason)
                    incomplete_required = True
            else:
                reasons.append(
                    "%s: optional cell %s"
                    % (label, final.applicability)
                )
            continue
        if final.outcome == OUTCOME_NOT_RUN:
            buckets["not_run"].append(label)
            if case.required:
                incomplete_required = True
                reasons.append("%s: not run" % label)
            continue
        if final.outcome == OUTCOME_INFRA_ERROR:
            buckets["blocked"].append(label)
            if case.required:
                incomplete_required = True
                reasons.append("%s: infrastructure failure" % label)
            else:
                reasons.append("%s: optional infrastructure failure" % label)
            continue
        buckets["executed"].append(label)
        if final.outcome == OUTCOME_FAIL:
            if case.expectation == "denial":
                wanted = dict(case.expected)
                if dict(final.observed) != wanted:
                    buckets["failed"].append(label)
                    if case.required:
                        failed_required = True
                    reasons.append(
                        "%s: denial observed %s at %s, expected %s at %s"
                        % (
                            label,
                            final.observed["outcome"],
                            final.failure_stage,
                            wanted["outcome"],
                            wanted["failure_stage"],
                        )
                    )
                    continue
                gaps = []
                if not final.evidence:
                    gaps.append("no evidence")
                if final.cleanup["status"] != "CLEAN":
                    gaps.append(
                        "cleanup %s" % final.cleanup["status"]
                    )
                if gaps:
                    buckets["failed"].append(label)
                    if case.required:
                        failed_required = True
                    reasons.append(
                        "%s: expected denial at %s unproven (%s)"
                        % (label, final.failure_stage, "; ".join(gaps))
                    )
                    continue
                buckets["passed"].append(label)
                reasons.append(
                    "%s: expected denial observed at %s, "
                    "passed only this case"
                    % (label, final.failure_stage)
                )
                continue
            buckets["failed"].append(label)
            if case.required:
                failed_required = True
                reasons.append(
                    "%s: failed at %s"
                    % (label, final.failure_stage)
                )
            else:
                reasons.append(
                    "%s: optional cell failed at %s"
                    % (label, final.failure_stage)
                )
            continue
        # Final outcome is PASS on an applicable cell with clean parse;
        # cleanup status decides whether the pass actually counts. (A
        # denial case never reaches this branch: PASS observations
        # disagree with its planned failure and are rejected.)
        cleanup_status = final.cleanup["status"]
        if cleanup_status == "CLEAN":
            buckets["passed"].append(label)
        elif cleanup_status == "NOT_CHECKED":
            buckets["blocked"].append(label)
            if case.required:
                incomplete_required = True
                reasons.append("%s: cleanup not checked" % label)
            else:
                reasons.append("%s: optional cleanup not checked" % label)
        else:
            buckets["failed"].append(label)
            if case.required:
                failed_required = True
                reasons.append(
                    "%s: cleanup residue %s"
                    % (label, list(final.cleanup["residue"]))
                )
            else:
                reasons.append(
                    "%s: optional cleanup residue" % label
                )

    # Non-required failures stay visible in the ledger without failing the
    # gate; rejected records always fail it.
    if rejected:
        verdict = OUTCOME_FAIL
        reasons.append("%d rejected attempt(s) preserved" % len(rejected))
    elif failed_required:
        verdict = OUTCOME_FAIL
    elif incomplete_required:
        verdict = "INCOMPLETE"
    else:
        verdict = OUTCOME_PASS
    # Denial cells can pass only themselves: a passing denial never moves
    # its guarded positive case out of missing/failed/blocked, because
    # ledger buckets are keyed by the result's own case_id.
    ledger = {
        bucket: {"count": len(cells), "cells": cells}
        for bucket, cells in buckets.items()
    }
    suite: SuiteResult | None = None
    if run_ids:
        (run_id,) = sorted(run_ids)
        suite = SuiteResult(
            run_id=run_id,
            plan_hash=checked_plan.plan_hash,
            result_digests=tuple(item.digest() for item in accepted),
            rejected_digests=tuple(
                _rejected_digest(entry) for entry in rejected
            ),
            attempts_preserved=len(accepted) + len(rejected),
            ledger=ledger,
            decision={"verdict": verdict, "reasons": list(reasons)},
        )
    else:
        reasons.append("no accepted attempts; no run_id to bind")
    return GateDecision(
        verdict=verdict,
        ledger=ledger,
        reasons=tuple(reasons),
        rejected=tuple(rejected),
        accepted=tuple(accepted),
        suite=suite,
    )


def verify_suite_result(
    suite: SuiteResult | Mapping[str, Any],
    plan: RunPlan | Mapping[str, Any],
    results: Sequence[CaseResult | Mapping[str, Any]],
) -> SuiteResult:
    """Verify a terminal suite record against its plan and results.

    Recomputes aggregation from the submitted results and requires the
    stored digests, ledger, verdict and attempt count to match exactly.
    Returns the checked :class:`SuiteResult`.
    """
    checked_suite = (
        SuiteResult.from_dict(suite.to_dict())
        if isinstance(suite, SuiteResult)
        else SuiteResult.from_dict(suite)
    )
    checked_plan = (
        RunPlan.from_dict(plan.to_dict())
        if isinstance(plan, RunPlan)
        else RunPlan.from_dict(plan)
    )
    if checked_suite.plan_hash != checked_plan.plan_hash:
        raise ContractError(
            "MBPF311",
            "suite plan_hash does not match the plan",
            "suite",
            None,
            STAGE_AGGREGATE,
        )
    decision = aggregate(checked_plan, results)
    if decision.suite is None:
        raise ContractError(
            "MBPF314",
            "suite binds no run_id",
            "suite",
            None,
            STAGE_AGGREGATE,
        )
    expected = decision.suite.to_dict()
    actual = checked_suite.to_dict()
    for key in (
        "run_id",
        "result_digests",
        "rejected_digests",
        "attempts_preserved",
        "ledger",
        "decision",
    ):
        if actual[key] != expected[key]:
            raise ContractError(
                "MBPF314",
                "suite %s does not match recomputed aggregation" % key,
                "suite",
                None,
                STAGE_AGGREGATE,
            )
    return checked_suite
