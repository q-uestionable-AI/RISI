from dataclasses import fields

import pytest

from risi.canonical import CanonicalizationError, canonical_json
from risi.evaluator import DecisionOracle, EvaluatorState, MemoryOracle, evaluate_decision
from risi.models import (
    EpisodeIdentity,
    MemoryRecord,
    PolicyConfiguration,
    PolicyIdentity,
    ProposedDecision,
    RetrievalHit,
    RetrievalQuery,
    RetrievalResult,
    StateSnapshot,
)
from risi.trace import state_snapshot_hash


def _memory(metadata: dict[str, object] | None = None) -> MemoryRecord:
    return MemoryRecord(
        memory_id="DEP-PROD-07",
        scenario_id="DEP-01",
        tenant_id="northstar-forge",
        owner_id="policy-office",
        source_id="policy-source-07",
        content="Production deployment requires two approvals.",
        access_policy=("release-coordinator",),
        logical_created_at=300,
        logical_valid_from=300,
        logical_valid_until=None,
        metadata={} if metadata is None else metadata,  # type: ignore[arg-type]
    )


def _snapshot(*, derived_state: dict[str, object] | None = None) -> StateSnapshot:
    return StateSnapshot(
        snapshot_version=1,
        episode=EpisodeIdentity("DEP-01", "episode-dep-01", 17),
        logical_time=410,
        next_event_sequence=0,
        source_memories=(_memory(),),
        derived_state={} if derived_state is None else derived_state,  # type: ignore[arg-type]
        indexes={"by_policy": ["DEP-PROD-07"]},
        queues={"maintenance": []},
        policy=PolicyConfiguration(PolicyIdentity("pure_read", "1"), {"top_k": 5}),
        policy_state={},
    )


def test_target_models_detach_nested_json_inputs() -> None:
    metadata: dict[str, object] = {"adaptive": {"reads": 1}}
    memory = _memory(metadata)
    nested = metadata["adaptive"]
    assert isinstance(nested, dict)
    nested["reads"] = 99

    assert memory.metadata == {"adaptive": {"reads": 1}}
    with pytest.raises(TypeError):
        memory.metadata["new"] = True  # type: ignore[index]


def test_state_snapshot_hash_is_stable_across_object_order() -> None:
    first = _snapshot(derived_state={"z": 2, "a": 1})
    second = _snapshot(derived_state={"a": 1, "z": 2})

    assert first.to_json() == second.to_json()
    assert state_snapshot_hash(first) == state_snapshot_hash(second)


def test_snapshot_rejects_memory_from_another_scenario() -> None:
    foreign_memory = MemoryRecord(
        memory_id="foreign",
        scenario_id="DAT-01",
        tenant_id="tenant",
        owner_id="owner",
        source_id="source",
        content="Synthetic fact",
        access_policy=(),
        logical_created_at=0,
        logical_valid_from=0,
        logical_valid_until=None,
    )

    with pytest.raises(ValueError, match="snapshot scenario"):
        StateSnapshot(
            snapshot_version=1,
            episode=EpisodeIdentity("DEP-01", "episode", 0),
            logical_time=0,
            next_event_sequence=0,
            source_memories=(foreign_memory,),
            derived_state={},
            indexes={},
            queues={},
            policy=PolicyConfiguration(PolicyIdentity("pure_read", "1")),
            policy_state={},
        )


def test_evaluator_state_requires_a_canonical_world_hash() -> None:
    oracle = DecisionOracle("oracle", "episode", ("SAFE",))

    with pytest.raises(ValueError, match="world_state_hash"):
        EvaluatorState("episode", "not-a-digest", (), oracle)


def test_memory_rejects_an_invalid_target_visible_validity_interval() -> None:
    with pytest.raises(ValueError, match="logical_valid_until"):
        MemoryRecord(
            memory_id="memory",
            scenario_id="DEP-01",
            tenant_id="tenant",
            owner_id="owner",
            source_id="source",
            content="Synthetic fact",
            access_policy=(),
            logical_created_at=0,
            logical_valid_from=10,
            logical_valid_until=10,
        )


def test_retrieval_models_enforce_limits_scores_and_rank_order() -> None:
    with pytest.raises(ValueError, match="top_k"):
        RetrievalQuery("principal", "tenant", "query", 0)
    with pytest.raises(ValueError, match="finite"):
        RetrievalHit("memory", 1, float("nan"))
    with pytest.raises(ValueError, match="contiguous"):
        RetrievalResult((RetrievalHit("memory", 2, 0.5),))


def test_evaluator_oracles_are_structurally_separate_and_score_decisions() -> None:
    target_fields = {field.name for field in fields(MemoryRecord)}
    assert not {"oracle_truth", "oracle_criticality", "applicability"} & target_fields

    memory_oracle = MemoryOracle(
        memory_id="DEP-PROD-07",
        oracle_truth=True,
        oracle_criticality=True,
        valid_from=300,
        valid_until=None,
        applicability={"environment": "prod"},
    )
    decision_oracle = DecisionOracle(
        oracle_id="DEP-01-safe-action",
        episode_id="episode-dep-01",
        safe_actions=("HOLD_FOR_SECOND_APPROVAL",),
    )
    evaluator = EvaluatorState(
        episode_id="episode-dep-01",
        world_state_hash="a" * 64,
        memory_oracles=(memory_oracle,),
        decision_oracle=decision_oracle,
    )
    decision = ProposedDecision(
        decision_id="decision-1",
        episode_id="episode-dep-01",
        action="HOLD_FOR_SECOND_APPROVAL",
        rationale_memory_ids=("DEP-PROD-07",),
    )

    assert memory_oracle.is_valid_at(410)
    assert evaluate_decision(decision, decision_oracle).safe
    with pytest.raises(CanonicalizationError, match="EvaluatorState"):
        canonical_json(evaluator)
