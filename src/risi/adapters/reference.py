"""Deterministic, model-free reference memory adapter."""

from __future__ import annotations

import re
from dataclasses import replace

from risi.adapters.base import MemoryAdapter
from risi.canonical import JsonObject
from risi.models import (
    EventType,
    EventVisibility,
    MemoryRecord,
    MemoryState,
    PolicyConfiguration,
    RetrievalHit,
    RetrievalQuery,
    RetrievalResult,
    StateSnapshot,
    TraceEvent,
    TraceEventDraft,
)
from risi.trace import create_event, state_snapshot_hash

_TOKEN = re.compile(r"[a-z0-9]+")


class ReferenceMemoryAdapter(MemoryAdapter):
    """Implement deterministic authorized pure-read retrieval with full-state telemetry.

    Args:
        initial_state: Complete initial target state for one episode.
    """

    def __init__(self, initial_state: StateSnapshot) -> None:
        self._state = initial_state
        self._trace: list[TraceEvent] = []
        self._memory_by_id = {memory.memory_id: memory for memory in initial_state.source_memories}

    def ingest(self, memory: MemoryRecord) -> MemoryRecord:
        """Reject writes because the implemented profile is pure-read.

        Args:
            memory: Candidate target-visible memory.

        Raises:
            PermissionError: Always, because local-reference grants no write capability.
        """
        raise PermissionError("the local-reference profile does not grant memory writes")

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        """Return deterministic lexical results from the authorized principal view.

        Args:
            query: Authorized target-visible retrieval request.

        Returns:
            Ranked pure-read retrieval results.
        """
        scored: list[tuple[float, str]] = []
        for memory in self._state.source_memories:
            if not self._is_retrievable(memory, query):
                continue
            score = self._score(query.text, memory.content)
            if score > 0:
                scored.append((score, memory.memory_id))
        scored.sort(key=lambda item: (-item[0], item[1]))
        hits = tuple(
            RetrievalHit(memory_id=memory_id, rank=rank, score=score)
            for rank, (score, memory_id) in enumerate(scored[: query.top_k], start=1)
        )
        result = RetrievalResult(
            hits=hits,
            observations={
                "principal_id": query.principal_id,
                "result_count": len(hits),
                "policy": self._state.policy.identity.name,
            },
        )
        self.record_event(
            EventType.RETRIEVAL_COMPLETED,
            EventVisibility.BOTH,
            {"query": query.to_json(), "result": result.to_json()},
            actor_principal_id=query.principal_id,
        )
        return result

    def assemble_context(self, result: RetrievalResult) -> str:
        """Assemble exact deterministic context from ranked retrieved memories.

        Args:
            result: Ranked retrieval result.

        Returns:
            Newline-separated memory identifiers and content.
        """
        lines = [
            f"[{hit.memory_id}] {self._memory_by_id[hit.memory_id].content}" for hit in result.hits
        ]
        context = "\n".join(lines)
        self.record_event(
            EventType.CONTEXT_ASSEMBLED,
            EventVisibility.BOTH,
            {
                "memory_ids": [hit.memory_id for hit in result.hits],
                "context": context,
            },
        )
        return context

    def configure_policy(self, configuration: PolicyConfiguration) -> None:
        """Set the deterministic policy and record the state transition.

        Args:
            configuration: Approved pure-read policy configuration.

        Raises:
            ValueError: If a non-pure-read policy is requested.
        """
        if configuration.identity.name != "pure-read":
            raise ValueError("reference adapter only implements the pure-read policy")
        before = self._state
        after = replace(
            before,
            policy=configuration,
            next_event_sequence=before.next_event_sequence + 1,
        )
        self._commit_event(
            before,
            after,
            EventType.POLICY_CONFIGURED,
            EventVisibility.EVALUATOR,
            {"policy": configuration.to_json()},
            None,
        )

    def snapshot(self) -> StateSnapshot:
        """Capture complete deterministic target state."""
        return self._state

    def reset(self, snapshot: StateSnapshot) -> None:
        """Restore exact state and begin a new evaluator-controlled trace.

        Args:
            snapshot: Full-state snapshot for the same scenario.
        """
        if snapshot.episode.scenario_id != self._state.episode.scenario_id:
            raise ValueError("reset snapshot belongs to another scenario")
        self._state = snapshot
        self._memory_by_id = {memory.memory_id: memory for memory in snapshot.source_memories}
        self._trace = []

    def advance_clock(self, logical_steps: int) -> int:
        """Advance deterministic time and record the exact state transition.

        Args:
            logical_steps: Positive number of logical steps.

        Returns:
            Updated logical time.
        """
        if logical_steps <= 0:
            raise ValueError("logical_steps must be positive")
        before = self._state
        after = replace(
            before,
            logical_time=before.logical_time + logical_steps,
            next_event_sequence=before.next_event_sequence + 1,
        )
        self._commit_event(
            before,
            after,
            EventType.STATE_HASH,
            EventVisibility.EVALUATOR,
            {"logical_steps": logical_steps},
            None,
        )
        return after.logical_time

    def run_maintenance(self) -> None:
        """Perform no work because maintenance is disabled in the pure-read profile."""

    def consolidate(self) -> tuple[str, ...]:
        """Return no affected memories because consolidation is disabled."""
        return ()

    def expire(self) -> tuple[str, ...]:
        """Return no affected memories because expiry is disabled."""
        return ()

    def export_trace(self) -> tuple[TraceEvent, ...]:
        """Export the ordered tamper-evident trace."""
        return tuple(self._trace)

    def inspect_state(self) -> StateSnapshot:
        """Return evaluator-only complete target state."""
        return self._state

    def record_event(
        self,
        event_type: EventType,
        visibility: EventVisibility,
        payload: JsonObject,
        *,
        actor_principal_id: str | None = None,
    ) -> TraceEvent:
        """Record a trace-only transition while preserving semantic target state.

        Args:
            event_type: Closed event category.
            visibility: Authorized event-observer boundary.
            payload: JSON-compatible event details.
            actor_principal_id: Optional target-visible actor.

        Returns:
            Complete tamper-evident event.
        """
        before = self._state
        after = replace(before, next_event_sequence=before.next_event_sequence + 1)
        return self._commit_event(
            before,
            after,
            event_type,
            visibility,
            payload,
            actor_principal_id,
        )

    def _commit_event(
        self,
        before: StateSnapshot,
        after: StateSnapshot,
        event_type: EventType,
        visibility: EventVisibility,
        payload: JsonObject,
        actor_principal_id: str | None,
    ) -> TraceEvent:
        sequence = before.next_event_sequence
        previous_hash = self._trace[-1].event_hash if self._trace else None
        event = create_event(
            TraceEventDraft(
                event_id=f"{before.episode.episode_id}-event-{sequence:04d}",
                episode_id=before.episode.episode_id,
                sequence=sequence,
                logical_time=after.logical_time,
                event_type=event_type,
                actor_principal_id=actor_principal_id,
                visibility=visibility,
                state_hash_before=state_snapshot_hash(before),
                state_hash_after=state_snapshot_hash(after),
                payload=payload,
            ),
            previous_hash,
        )
        self._state = after
        self._trace.append(event)
        return event

    def _is_retrievable(self, memory: MemoryRecord, query: RetrievalQuery) -> bool:
        return (
            memory.state is MemoryState.CURRENT
            and memory.tenant_id == query.tenant_id
            and query.principal_id in memory.access_policy
            and self._state.logical_time >= memory.logical_valid_from
            and (
                memory.logical_valid_until is None
                or self._state.logical_time < memory.logical_valid_until
            )
        )

    @staticmethod
    def _score(query: str, content: str) -> float:
        query_tokens = set(_TOKEN.findall(query.casefold()))
        content_tokens = set(_TOKEN.findall(content.casefold()))
        if not query_tokens or not content_tokens:
            return 0.0
        overlap = len(query_tokens & content_tokens)
        return round(overlap / len(query_tokens), 12)
