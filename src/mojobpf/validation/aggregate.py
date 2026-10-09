# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Aggregation of case results into a coverage ledger and gate decision.

:func:`aggregate` implements ``aggregate(plan, results) -> GateDecision``.
It accepts :class:`CaseResult` objects or plain mappings; malformed
records are preserved as rejected attempts and force a non-PASS verdict
rather than raising. Every rejection carries a stable ``MBPF31x`` code:

* ``MBPF310``: unplanned case or unknown target cell.
* ``MBPF311``: identity or hash mismatch (plan, revisions, source,
  object, consumer, fixture, run).
* ``MBPF312``: duplicate result for one (case, target, attempt).
* ``MBPF313``: broken attempt chain (retry replaced an earlier attempt).
* ``MBPF314``: inconsistent verdict (PASS on an unavailable cell, or a
  final outcome the evidence cannot support).

Verdict precedence is FAIL, then INCOMPLETE, then PASS. A denial case
passes only its own cell and never qualifies the positive case it
guards. Required cells with blocked availability keep the gate
non-PASS without incrementing PASS; ``NOT_APPLICABLE`` cells are
excluded from the denominator with their IDs recorded.

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
    checked_plan = plan if isinstance(plan, RunPlan) else RunPlan.from_dict(
        plan
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
            result = raw
            digest = raw.digest()
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
        if (consumer["name"], consumer["version"]) not in set(
            case.consumers
        ):
            problems.append(
                "unadmitted consumer %s %s"
                % (consumer["name"], consumer["version"])
            )
        if result.identities["workload"]["fixture_id"] != case.fixture_id:
            problems.append("wrong workload fixture_id")
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
        final = cell_results[-1]
        if final.applicability == AVAIL_NOT_APPLICABLE:
            excluded.append(label)
            reasons.append("%s: not applicable, excluded" % label)
            continue
        if final.applicability == AVAIL_APPLICABLE:
            buckets["applicable"].append(label)
        else:
            buckets["blocked"].append(label)
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
        # cleanup status decides whether the pass actually counts.
        cleanup_status = final.cleanup["status"]
        if cleanup_status == "CLEAN":
            buckets["passed"].append(label)
            if case.expectation == "denial":
                reasons.append(
                    "%s: expected denial passed only this case" % label
                )
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
        suite if isinstance(suite, SuiteResult) else SuiteResult.from_dict(
            suite
        )
    )
    checked_plan = plan if isinstance(plan, RunPlan) else RunPlan.from_dict(
        plan
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
