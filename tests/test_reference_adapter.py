from risi.adapters.reference import ReferenceMemoryAdapter
from risi.models import (
    EpisodeIdentity,
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
        policy=PolicyConfiguration(PolicyIdentity("pure-read", "1")),
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
