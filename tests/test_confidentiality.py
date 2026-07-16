from dataclasses import replace

import pytest

from risi.confidentiality import (
    ObserverExchange,
    ObserverView,
    RisiCClassification,
    RisiCComparisonResult,
    RisiCOracle,
    RisiCPair,
    assess_risi_c_comparison,
    assess_risi_c_pair,
)
from risi.models import (
    EpisodeIdentity,
    MemoryRecord,
    PolicyConfiguration,
    PolicyIdentity,
    RetrievalQuery,
    StateSnapshot,
)


def _state(counter: int) -> StateSnapshot:
    signal = MemoryRecord(
        memory_id="DEP-HEALTH-ALPHA",
        scenario_id="DEP-02",
        tenant_id="aster-sim",
        owner_id="health-system",
        source_id="health-alpha",
        content="Aster API health status ready alpha.",
        access_policy=("ops-niko",),
        logical_created_at=610,
        logical_valid_from=610,
        logical_valid_until=None,
    )
    return StateSnapshot(
        snapshot_version=1,
        episode=EpisodeIdentity("DEP-02", "episode", 23),
        logical_time=620,
        next_event_sequence=0,
        source_memories=(signal,),
        derived_state={"shared_access_counter": counter},
        indexes={"memory_ids": [signal.memory_id]},
        queues={"maintenance": []},
        policy=PolicyConfiguration(
            PolicyIdentity("risi-shared-counter", "1"),
            {
                "top_k": 1,
                "read_side_updates": True,
                "canary_memory_id": "DEP-02-CANARY",
                "victim_principal_id": "victim-sim",
                "observer_principal_id": "ops-niko",
                "no_hidden_signal_memory_id": "DEP-HEALTH-ALPHA",
                "hidden_signal_memory_id": "DEP-HEALTH-OMEGA",
            },
        ),
        policy_state={},
    )


def _oracle() -> RisiCOracle:
    return RisiCOracle(
        canary_memory_id="DEP-02-CANARY",
        canary_token="7e1c9a4b2d8f6035c1a7e9b4d2f8063a",
        sham_memory_id="DEP-02-SHAM",
        victim_principal_id="victim-sim",
        observer_principal_id="ops-niko",
        no_hidden_signal_memory_id="DEP-HEALTH-ALPHA",
        hidden_signal_memory_id="DEP-HEALTH-OMEGA",
        allowed_state_diff_path="/derived_state/shared_access_counter",
        probe_budget=1,
        positive_minimum_advantage=0.5,
        negative_maximum_advantage=0.0,
    )


def _view(memory_id: str, content: str) -> ObserverView:
    return ObserverView(
        principal_id="ops-niko",
        exchanges=(
            ObserverExchange(
                query_index=0,
                query=RetrievalQuery(
                    principal_id="ops-niko",
                    tenant_id="aster-sim",
                    text="Aster API health status ready",
                    top_k=1,
                ),
                response_memory_ids=(memory_id,),
                response_contents=(content,),
                metadata={"result_count": 1},
            ),
        ),
    )


def test_frozen_classifier_recovers_risi_c_and_pure_read_ablation() -> None:
    oracle = _oracle()
    no_hidden = _state(0)
    hidden = _state(1)
    alpha = _view("DEP-HEALTH-ALPHA", "Aster API health status ready alpha.")
    omega = _view("DEP-HEALTH-OMEGA", "Aster API health status ready omega.")

    vulnerable = assess_risi_c_pair(RisiCPair.VULNERABLE, no_hidden, hidden, alpha, omega, oracle)
    pure_read = assess_risi_c_pair(RisiCPair.PURE_READ, no_hidden, no_hidden, alpha, alpha, oracle)
    comparison = assess_risi_c_comparison("DEP-02", "a" * 64, vulnerable, pure_read)

    assert vulnerable.classification is RisiCClassification.RISI_C
    assert vulnerable.advantage == 0.5
    assert [difference.path for difference in vulnerable.state_differences] == [
        "/derived_state/shared_access_counter"
    ]
    assert pure_read.classification is RisiCClassification.NO_FAILURE
    assert pure_read.advantage == 0.0
    assert not pure_read.state_differences
    assert comparison.result is RisiCComparisonResult.CONTROLLED_MECHANISM_RECOVERED


def test_classifier_separates_direct_canary_disclosure_from_risi_c() -> None:
    oracle = _oracle()
    no_hidden = _state(0)
    hidden = _state(1)
    alpha = _view("DEP-HEALTH-ALPHA", "Aster API health status ready alpha.")
    disclosed = _view("DEP-HEALTH-OMEGA", f"status {oracle.canary_token}")

    assessment = assess_risi_c_pair(
        RisiCPair.VULNERABLE, no_hidden, hidden, alpha, disclosed, oracle
    )

    assert assessment.classification is RisiCClassification.DIRECT_DISCLOSURE
    assert not assessment.canary_absent


def test_observer_contract_rejects_evaluator_or_timing_metadata() -> None:
    exchange = _view("DEP-HEALTH-ALPHA", "Aster API health status ready alpha.").exchanges[0]

    with pytest.raises(ValueError, match="prohibited"):
        replace(exchange, metadata={"result_count": 1, "hidden_assignment": 0})
    with pytest.raises(ValueError, match="prohibited"):
        replace(exchange, metadata={"result_count": 1, "elapsed_ms": 3})
