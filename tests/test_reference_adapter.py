from dataclasses import replace

import pytest

from risi.adapters.reference import ReferenceMemoryAdapter
from risi.models import (
    EpisodeIdentity,
    EventType,
    MemoryRecord,
    PolicyConfiguration,
    PolicyIdentity,
    RetrievalQuery,
    StateSnapshot,
)
from risi.trace import verify_trace


def _state() -> StateSnapshot:
    return StateSnapshot(
        snapshot_version=1,
        episode=EpisodeIdentity("DEP-01", "episode", 17),
        logical_time=410,
        next_event_sequence=0,
        source_memories=(
            MemoryRecord(
                memory_id="DEP-PROD-07",
                scenario_id="DEP-01",
                tenant_id="tenant",
                owner_id="owner",
                source_id="source",
                content="Production deployment requires two approvals.",
                access_policy=("decision-engine",),
                logical_created_at=1,
                logical_valid_from=1,
                logical_valid_until=None,
            ),
        ),
        derived_state={},
        indexes={"memory_ids": ["DEP-PROD-07"]},
        queues={"maintenance": []},
        policy=PolicyConfiguration(
            PolicyIdentity("pure-read", "1"),
            {"top_k": 3, "read_side_updates": False},
        ),
        policy_state={},
    )


def test_reference_adapter_retrieves_authorized_memory_without_semantic_mutation() -> None:
    adapter = ReferenceMemoryAdapter(_state())

    result = adapter.retrieve(
        RetrievalQuery("decision-engine", "tenant", "production deployment approvals", 3)
    )
    context = adapter.assemble_context(result)

    assert tuple(hit.memory_id for hit in result.hits) == ("DEP-PROD-07",)
    assert "DEP-PROD-07" in context
    final = adapter.snapshot()
    assert final.source_memories == _state().source_memories
    assert final.logical_time == _state().logical_time
    assert final.next_event_sequence == 2
    verify_trace(adapter.export_trace())


def test_reference_adapter_enforces_tenant_and_principal_boundaries() -> None:
    adapter = ReferenceMemoryAdapter(_state())

    wrong_tenant = adapter.retrieve(
        RetrievalQuery("decision-engine", "other", "production deployment approvals", 3)
    )
    wrong_principal = adapter.retrieve(
        RetrievalQuery("other", "tenant", "production deployment approvals", 3)
    )

    assert not wrong_tenant.hits
    assert not wrong_principal.hits


def test_reference_adapter_rejects_unknown_policy_versions_and_excess_top_k() -> None:
    adapter = ReferenceMemoryAdapter(_state())

    with pytest.raises(ValueError, match="unknown policy identity"):
        adapter.configure_policy(
            PolicyConfiguration(
                PolicyIdentity("pure-read", "2"),
                {"top_k": 3, "read_side_updates": False},
            )
        )
    with pytest.raises(ValueError, match="configured policy top_k"):
        adapter.retrieve(
            RetrievalQuery("decision-engine", "tenant", "production deployment approvals", 4)
        )


def _craf_state() -> StateSnapshot:
    base = _state()
    critical = replace(base.source_memories[0], system_criticality="protected-recall")
    trigger = MemoryRecord(
        memory_id="DEP-CLOSE-01",
        scenario_id="DEP-01",
        tenant_id="tenant",
        owner_id="owner",
        source_id="trigger-source",
        content="The release passed all stage tests.",
        access_policy=("dev-aria", "decision-engine"),
        logical_created_at=400,
        logical_valid_from=400,
        logical_valid_until=None,
    )
    return replace(
        base,
        source_memories=(critical, trigger),
        indexes={"memory_ids": [critical.memory_id, trigger.memory_id]},
    )


def _adaptive_policy(name: str) -> PolicyConfiguration:
    settings = {
        "top_k": 3,
        "read_side_updates": True,
        "trigger_memory_id": "DEP-CLOSE-01",
        "suppressed_memory_id": "DEP-PROD-07",
    }
    if name == "protected-critical-recall":
        settings["protected_criticality"] = "protected-recall"
    return PolicyConfiguration(PolicyIdentity(name, "1"), settings)


def test_reference_adapter_eclipses_then_protects_critical_recall() -> None:
    initial = _craf_state()
    adapter = ReferenceMemoryAdapter(initial)
    interaction = RetrievalQuery("dev-aria", "tenant", "release passed stage tests", 1)
    decision_query = RetrievalQuery(
        "decision-engine", "tenant", "production deployment approvals", 3
    )

    adapter.configure_policy(_adaptive_policy("memory-eclipsing"))
    adapter.retrieve(interaction)
    vulnerable = adapter.retrieve(decision_query)
    assert "DEP-PROD-07" not in {hit.memory_id for hit in vulnerable.hits}
    assert EventType.READ_SIDE_UPDATE in {event.event_type for event in adapter.export_trace()}

    adapter.reset(initial)
    adapter.configure_policy(_adaptive_policy("protected-critical-recall"))
    adapter.retrieve(interaction)
    protected = adapter.retrieve(decision_query)
    assert "DEP-PROD-07" in {hit.memory_id for hit in protected.hits}
    assert adapter.inspect_state().source_memories == initial.source_memories
