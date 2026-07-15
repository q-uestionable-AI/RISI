from dataclasses import replace

import pytest

from risi.adapters.base import MemoryAdapter
from risi.engine import ReferenceEngine
from risi.models import (
    EpisodeIdentity,
    MemoryRecord,
    PolicyConfiguration,
    PolicyIdentity,
    RetrievalQuery,
    RetrievalResult,
    StateSnapshot,
    TraceEvent,
)
from risi.trace import state_snapshot_hash


class _SnapshotAdapter(MemoryAdapter):
    def __init__(self, snapshot: StateSnapshot) -> None:
        self._snapshot = snapshot
        self._trace: tuple[TraceEvent, ...] = ()

    def ingest(self, memory: MemoryRecord) -> MemoryRecord:
        return memory

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        return RetrievalResult((), {"principal_id": query.principal_id})

    def assemble_context(self, result: RetrievalResult) -> str:
        return "\n".join(hit.memory_id for hit in result.hits)

    def configure_policy(self, configuration: PolicyConfiguration) -> None:
        self._snapshot = replace(self._snapshot, policy=configuration)

    def snapshot(self) -> StateSnapshot:
        return self._snapshot

    def reset(self, snapshot: StateSnapshot) -> None:
        self._snapshot = snapshot

    def advance_clock(self, logical_steps: int) -> int:
        if logical_steps <= 0:
            raise ValueError("logical_steps must be positive")
        logical_time = self._snapshot.logical_time + logical_steps
        self._snapshot = replace(self._snapshot, logical_time=logical_time)
        return logical_time

    def run_maintenance(self) -> None:
        return None

    def consolidate(self) -> tuple[str, ...]:
        return ()

    def expire(self) -> tuple[str, ...]:
        return ()

    def export_trace(self) -> tuple[TraceEvent, ...]:
        return self._trace

    def inspect_state(self) -> StateSnapshot:
        return self._snapshot


def _snapshot(episode: EpisodeIdentity) -> StateSnapshot:
    return StateSnapshot(
        snapshot_version=1,
        episode=episode,
        logical_time=0,
        next_event_sequence=0,
        source_memories=(),
        derived_state={},
        indexes={},
        queues={},
        policy=PolicyConfiguration(PolicyIdentity("pure_read", "1")),
        policy_state={},
    )


def test_adapter_reset_restores_exact_snapshot_hash() -> None:
    episode = EpisodeIdentity("DEP-01", "episode-dep-01", 17)
    initial = _snapshot(episode)
    adapter = _SnapshotAdapter(initial)
    engine = ReferenceEngine(adapter, episode)

    expected_hash = state_snapshot_hash(engine.snapshot())
    adapter.advance_clock(4)
    assert state_snapshot_hash(engine.snapshot()) != expected_hash

    engine.reset(initial)
    assert state_snapshot_hash(engine.snapshot()) == expected_hash
    assert adapter.inspect_state() == initial


def test_reference_engine_rejects_cross_episode_state() -> None:
    episode = EpisodeIdentity("DEP-01", "episode-dep-01", 17)
    adapter = _SnapshotAdapter(_snapshot(EpisodeIdentity("DAT-01", "foreign", 17)))
    engine = ReferenceEngine(adapter, episode)

    with pytest.raises(ValueError, match="does not belong"):
        engine.snapshot()
