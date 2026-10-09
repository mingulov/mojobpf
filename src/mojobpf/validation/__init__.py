# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Frozen validation contracts: result, target and fixture records plus aggregation.

This package implements ``test-contracts-v1`` and ``suite-result-v1``:
:func:`plan` builds an immutable :class:`RunPlan` from cases, targets
and revisions, and :func:`aggregate` folds :class:`CaseResult` records
into a :class:`GateDecision` with a full coverage ledger. The JSON
schemas under ``schemas/`` are the frozen cross-consumer contract;
this package is the Python enforcement. Standard library only.
"""

from .aggregate import GateDecision, aggregate
from .models import (
    SUITE_RESULT_VERSION,
    TEST_CONTRACTS_VERSION,
    AVAILABILITY,
    EXECUTION_OUTCOMES,
    FAILURE_STAGES,
    CaseResult,
    ContractError,
    CostRecord,
    Fixture,
    RunPlan,
    RunPlanCase,
    SuiteResult,
    TargetManifest,
    digest_of,
    export_schema_bundle,
    load_schema,
    plan,
    schema_digest,
    verify_schema_bundle,
)

__all__ = [
    "AVAILABILITY",
    "EXECUTION_OUTCOMES",
    "FAILURE_STAGES",
    "SUITE_RESULT_VERSION",
    "TEST_CONTRACTS_VERSION",
    "CaseResult",
    "ContractError",
    "CostRecord",
    "Fixture",
    "GateDecision",
    "RunPlan",
    "RunPlanCase",
    "SuiteResult",
    "TargetManifest",
    "aggregate",
    "digest_of",
    "export_schema_bundle",
    "load_schema",
    "plan",
    "schema_digest",
    "verify_schema_bundle",
]
