from dataclasses import replace

import pytest

from risi.budget import (
    BudgetExhaustedError,
    BudgetLedger,
    BudgetResource,
    ResourceUse,
)
from risi.operator.models import ExecutionLimits


def _limits() -> ExecutionLimits:
    return ExecutionLimits(
        episodes=1,
        retrieval_calls=2,
        logical_steps=3,
        input_bytes=100,
        memory_records=4,
        artifact_bytes=1_000,
    )


def test_ledger_tracks_approved_and_consumed_values_immutably() -> None:
    initial = BudgetLedger(_limits())
    consumed = initial.consume(BudgetResource.EPISODES).consume(
        BudgetResource.RETRIEVAL_CALLS,
        2,
    )

    assert initial.consumed.episodes == 0
    assert consumed.resource_use().to_json()["episodes"] == {
        "approved": 1,
        "consumed": 1,
    }
    assert consumed.resource_use().to_json()["retrieval_calls"] == {
        "approved": 2,
        "consumed": 2,
    }


def test_ledger_fails_closed_before_exceeding_an_approved_limit() -> None:
    full = BudgetLedger(_limits()).consume(BudgetResource.LOGICAL_STEPS, 3)

    with pytest.raises(BudgetExhaustedError) as raised:
        full.consume(BudgetResource.LOGICAL_STEPS)

    assert raised.value.to_json() == {
        "resource": "logical_steps",
        "approved": 3,
        "consumed": 3,
        "requested": 1,
    }
    assert full.consumed.logical_steps == 3


def test_zero_consumption_is_deterministic_and_negative_values_are_rejected() -> None:
    ledger = BudgetLedger(_limits())

    assert ledger.consume(BudgetResource.ARTIFACT_BYTES, 0) == ledger
    with pytest.raises(ValueError, match="nonnegative"):
        ledger.consume(BudgetResource.ARTIFACT_BYTES, -1)


def test_resource_use_parser_is_closed_and_rejects_overconsumption() -> None:
    report = BudgetLedger(_limits()).resource_use()

    assert ResourceUse.from_json(report.to_json()) == report
    with pytest.raises(ValueError, match="field set"):
        ResourceUse.from_json({**report.to_json(), "tokens": {"approved": 1, "consumed": 0}})

    invalid = report.to_json()
    invalid["episodes"] = {"approved": 1, "consumed": 2}
    with pytest.raises(ValueError, match="within"):
        ResourceUse.from_json(invalid)


def test_every_resource_uses_its_manifest_ceiling() -> None:
    limits = replace(_limits(), artifact_bytes=2_000)
    report = BudgetLedger(limits).resource_use().to_json()

    assert set(report) == {resource.value for resource in BudgetResource}
    assert report["artifact_bytes"]["approved"] == 2_000
