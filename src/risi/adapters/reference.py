"""Deterministic, model-free reference memory adapter."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import cast

from risi.adapters.base import MemoryAdapter
from risi.canonical import JsonObject, JsonValue
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
_SUPPORTED_POLICIES = frozenset({"pure-read", "memory-eclipsing", "protected-critical-recall"})
_PROTECTED_CRITICALITY = "protected-recall"


class ReferenceMemoryAdapter(MemoryAdapter):
    """Implement deterministic authorized reference retrieval with full-state telemetry.

    Args:
        initial_state: Complete initial target state for one episode.
    """

    def __init__(self, initial_state: StateSnapshot) -> None:
        self._state = initial_state
        self._trace: list[TraceEvent] = []
        self._memory_by_id = {memory.memory_id: memory for memory in initial_state.source_memories}
        self._validate_policy_configuration(initial_state.policy)

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
        configured_top_k = self._state.policy.settings.get("top_k")
        if (
            isinstance(configured_top_k, bool)
            or not isinstance(configured_top_k, int)
            or query.top_k > configured_top_k
        ):
            raise ValueError("retrieval query exceeds the configured policy top_k")
        scored: list[tuple[float, str]] = []
        for memory in self._state.source_memories:
            if not self._is_retrievable(memory, query):
                continue
            score = self._score(query.text, memory.content)
            if score > 0:
                scored.append((score, memory.memory_id))
        scored.sort(key=lambda item: (-item[0], item[1]))
        suppressed = self._suppressed_memory_ids()
        protected = frozenset(
            memory_id
            for _, memory_id in scored
            if memory_id in suppressed
            and self._state.policy.identity.name == "protected-critical-recall"
            and self._memory_by_id[memory_id].system_criticality
            == self._state.policy.settings.get("protected_criticality")
        )
        removed = tuple(memory_id for _, memory_id in scored if memory_id in suppressed - protected)
        scored = [item for item in scored if item[1] not in suppressed - protected]
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
        if removed or protected:
            removed_json = cast(list[JsonValue], list(removed))
            protected_json = cast(list[JsonValue], sorted(protected))
            self.record_event(
                EventType.RETRIEVAL_SET_CHANGE,
                EventVisibility.BOTH,
                {
                    "removed_memory_ids": removed_json,
                    "protected_memory_ids": protected_json,
                    "policy": self._state.policy.identity.name,
                },
                actor_principal_id=query.principal_id,
            )
        self._apply_read_side_update(query, tuple(hit.memory_id for hit in hits))
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
            configuration: Approved closed reference-policy configuration.

        Raises:
            ValueError: If an unknown or malformed policy is requested.
        """
        self._validate_policy_configuration(configuration)
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
        """Perform no work because maintenance is disabled in local-reference."""

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

    def _validate_policy_configuration(self, configuration: PolicyConfiguration) -> None:
        name = configuration.identity.name
        if name not in _SUPPORTED_POLICIES or configuration.identity.version != "1":
            raise ValueError("reference adapter received an unknown policy identity")
        if name == "pure-read":
            self._validate_pure_read_policy(configuration)
            return
        self._validate_adaptive_policy(configuration)

    @staticmethod
    def _validate_policy_top_k(configuration: PolicyConfiguration) -> None:
        top_k = configuration.settings["top_k"]
        if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0:
            raise ValueError("reference policy top_k is invalid")

    def _validate_pure_read_policy(self, configuration: PolicyConfiguration) -> None:
        if set(configuration.settings) != {"top_k", "read_side_updates"}:
            raise ValueError("reference policy settings are invalid")
        self._validate_policy_top_k(configuration)
        if configuration.settings["read_side_updates"] is not False:
            raise ValueError("reference policy read-side setting is invalid")

    def _validate_adaptive_policy(self, configuration: PolicyConfiguration) -> None:
        name = configuration.identity.name
        required = {"top_k", "read_side_updates", "trigger_memory_id", "suppressed_memory_id"}
        if name == "protected-critical-recall":
            required.add("protected_criticality")
        if set(configuration.settings) != required:
            raise ValueError("reference policy settings are invalid")
        self._validate_policy_top_k(configuration)
        if configuration.settings["read_side_updates"] is not True:
            raise ValueError("reference policy read-side setting is invalid")
        identifiers: dict[str, str] = {}
        for field_name in ("trigger_memory_id", "suppressed_memory_id"):
            value = configuration.settings[field_name]
            if not isinstance(value, str) or not value:
                raise ValueError(f"adaptive reference policy {field_name} is invalid")
            if value not in self._memory_by_id:
                raise ValueError(f"adaptive reference policy {field_name} is unknown")
            identifiers[field_name] = value
        if identifiers["trigger_memory_id"] == identifiers["suppressed_memory_id"]:
            raise ValueError("adaptive reference trigger and suppressed memory must differ")
        if (
            name == "protected-critical-recall"
            and configuration.settings["protected_criticality"] != _PROTECTED_CRITICALITY
        ):
            raise ValueError("protected reference policy criticality label is invalid")

    def _suppressed_memory_ids(self) -> frozenset[str]:
        raw = self._state.derived_state.get("suppressed_memory_ids", [])
        if not isinstance(raw, (list, tuple)):
            raise TypeError("derived_state.suppressed_memory_ids is invalid")
        values: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                raise TypeError("derived_state.suppressed_memory_ids is invalid")
            values.append(item)
        return frozenset(values)

    def _apply_read_side_update(
        self,
        query: RetrievalQuery,
        retrieved_memory_ids: tuple[str, ...],
    ) -> None:
        policy = self._state.policy
        if policy.identity.name == "pure-read" or not policy.settings.get("read_side_updates"):
            return
        trigger = policy.settings.get("trigger_memory_id")
        suppressed = policy.settings.get("suppressed_memory_id")
        if not isinstance(trigger, str) or not isinstance(suppressed, str):
            raise TypeError("adaptive reference policy identifiers are invalid")
        if trigger not in retrieved_memory_ids or suppressed in self._suppressed_memory_ids():
            return
        prior_count = self._state.policy_state.get("interaction_count", 0)
        if isinstance(prior_count, bool) or not isinstance(prior_count, int):
            raise TypeError("policy_state.interaction_count is invalid")
        interaction_count = prior_count + 1
        before = self._state
        after = replace(
            before,
            derived_state={
                "suppressed_memory_ids": [suppressed],
                "trigger_memory_ids": [trigger],
                "tenant_id": query.tenant_id,
            },
            policy_state={"interaction_count": interaction_count},
            next_event_sequence=before.next_event_sequence + 1,
        )
        self._commit_event(
            before,
            after,
            EventType.READ_SIDE_UPDATE,
            EventVisibility.BOTH,
            {
                "operation": "set_memory_eclipse",
                "trigger_memory_id": trigger,
                "suppressed_memory_id": suppressed,
                "tenant_id": query.tenant_id,
                "interaction_count": interaction_count,
            },
            query.principal_id,
        )

    @staticmethod
    def _score(query: str, content: str) -> float:
        query_tokens = set(_TOKEN.findall(query.casefold()))
        content_tokens = set(_TOKEN.findall(content.casefold()))
        if not query_tokens or not content_tokens:
            return 0.0
        overlap = len(query_tokens & content_tokens)
        return round(overlap / len(query_tokens), 12)
