"""Typed target-visible and trace-boundary models for RISI experiments."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias

from risi.canonical import (
    JsonObject,
    JsonValue,
    freeze_json_object,
    normalize_json_object,
)

EpisodeId: TypeAlias = str
LogicalTime: TypeAlias = int
EventSequence: TypeAlias = int


def _require_nonempty(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _require_nonnegative(value: int, field_name: str) -> None:
    if value < 0:
        raise ValueError(f"{field_name} must be nonnegative")


def _require_unique(values: tuple[str, ...], field_name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must contain unique values")


class EventVisibility(StrEnum):
    """Visibility boundary for an emitted experimental event."""

    ATTACKER = "attacker"
    EVALUATOR = "evaluator"
    BOTH = "both"


class EventType(StrEnum):
    """Closed event vocabulary for deterministic reference experiments."""

    EPISODE_STARTED = "episode_started"
    POLICY_CONFIGURED = "policy_configured"
    MEMORY_INGESTED = "memory_ingested"
    MEMORY_READ = "memory_read"
    READ_SIDE_UPDATE = "read_side_update"
    RETRIEVAL_COMPLETED = "retrieval_completed"
    RETRIEVAL_SET_CHANGE = "retrieval_set_change"
    CONTEXT_ASSEMBLED = "context_assembled"
    CRITICAL_MEMORY_SUPPRESSION = "critical_memory_suppression"
    ADMISSION_DECISION = "admission_decision"
    DEDUPLICATION_DECISION = "deduplication_decision"
    CONSOLIDATION = "consolidation"
    EVICTION = "eviction"
    ARCHIVE = "archive"
    TRIAL_RESET = "trial_reset"
    STATE_HASH = "state_hash"
    INVARIANT_VIOLATION = "invariant_violation"
    DECISION = "decision"
    ORACLE_EVALUATED = "oracle_evaluated"
    EPISODE_COMPLETED = "episode_completed"


class MemoryState(StrEnum):
    """Lifecycle state of a target-visible memory record."""

    CURRENT = "current"
    SUPERSEDED = "superseded"
    HIDDEN = "hidden"
    ARCHIVED = "archived"
    DELETED = "deleted"


@dataclass(frozen=True, slots=True)
class EpisodeIdentity:
    """Identify one deterministic episode.

    Attributes:
        scenario_id: Stable scenario identifier.
        episode_id: Unique identifier for the episode instance.
        seed: Nonnegative deterministic seed.
    """

    scenario_id: str
    episode_id: EpisodeId
    seed: int

    def __post_init__(self) -> None:
        """Validate identity fields."""
        _require_nonempty(self.scenario_id, "scenario_id")
        _require_nonempty(self.episode_id, "episode_id")
        _require_nonnegative(self.seed, "seed")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical JSON-compatible identity representation."""
        return {
            "scenario_id": self.scenario_id,
            "episode_id": self.episode_id,
            "seed": self.seed,
        }


@dataclass(frozen=True, slots=True)
class PolicyIdentity:
    """Identify an immutable policy implementation.

    Attributes:
        name: Stable policy name.
        version: Policy contract or implementation version.
    """

    name: str
    version: str

    def __post_init__(self) -> None:
        """Validate policy identity fields."""
        _require_nonempty(self.name, "policy name")
        _require_nonempty(self.version, "policy version")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical JSON-compatible policy identity."""
        return {"name": self.name, "version": self.version}


@dataclass(frozen=True, slots=True)
class PolicyConfiguration:
    """Contain a policy identity and deterministic target-visible settings.

    Attributes:
        identity: Immutable policy identity.
        settings: JSON-compatible policy settings.
    """

    identity: PolicyIdentity
    settings: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Detach and validate the settings object."""
        object.__setattr__(self, "settings", freeze_json_object(self.settings))

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical JSON-compatible policy configuration."""
        return {
            "name": self.identity.name,
            "version": self.identity.version,
            "settings": normalize_json_object(self.settings),
        }


@dataclass(frozen=True, slots=True)
class MemoryRecord:
    """Represent a target-visible memory item without evaluator-only oracles.

    Attributes:
        memory_id: Stable identifier within the scenario.
        scenario_id: Scenario that owns the record.
        tenant_id: Tenant security boundary.
        owner_id: Principal that owns the record.
        source_id: Source identifier used for provenance.
        content: Synthetic memory content.
        access_policy: Principals or roles authorized to retrieve the record.
        logical_created_at: Deterministic logical creation time.
        logical_valid_from: Inclusive target-visible validity boundary.
        logical_valid_until: Optional exclusive target-visible validity boundary.
        system_criticality: Optional system-visible criticality label.
        state: Current lifecycle state.
        metadata: Target-visible metadata and adaptive fields.
    """

    memory_id: str
    scenario_id: str
    tenant_id: str
    owner_id: str
    source_id: str
    content: str
    access_policy: tuple[str, ...]
    logical_created_at: LogicalTime
    logical_valid_from: LogicalTime
    logical_valid_until: LogicalTime | None
    system_criticality: str | None = None
    state: MemoryState = MemoryState.CURRENT
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate identifiers, logical time, authorization, and metadata."""
        for field_name in ("memory_id", "scenario_id", "tenant_id", "owner_id", "source_id"):
            _require_nonempty(getattr(self, field_name), field_name)
        _require_nonempty(self.content, "content")
        _require_nonnegative(self.logical_created_at, "logical_created_at")
        _require_nonnegative(self.logical_valid_from, "logical_valid_from")
        if self.logical_valid_until is not None and (
            self.logical_valid_until <= self.logical_valid_from
        ):
            raise ValueError("logical_valid_until must be greater than logical_valid_from")
        object.__setattr__(self, "access_policy", tuple(self.access_policy))
        _require_unique(self.access_policy, "access_policy")
        if any(not principal.strip() for principal in self.access_policy):
            raise ValueError("access_policy entries must not be empty")
        object.__setattr__(self, "metadata", freeze_json_object(self.metadata))

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical JSON-compatible target-visible record."""
        return {
            "memory_id": self.memory_id,
            "scenario_id": self.scenario_id,
            "tenant_id": self.tenant_id,
            "owner_id": self.owner_id,
            "source_id": self.source_id,
            "content": self.content,
            "access_policy": list(self.access_policy),
            "logical_created_at": self.logical_created_at,
            "logical_valid_from": self.logical_valid_from,
            "logical_valid_until": self.logical_valid_until,
            "system_criticality": self.system_criticality,
            "state": self.state.value,
            "metadata": normalize_json_object(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class RetrievalQuery:
    """Describe an authorized retrieval request.

    Attributes:
        principal_id: Principal issuing the query.
        tenant_id: Tenant boundary for authorization.
        text: Synthetic query text.
        top_k: Positive maximum number of results requested.
    """

    principal_id: str
    tenant_id: str
    text: str
    top_k: int

    def __post_init__(self) -> None:
        """Validate authorization identifiers and result limit."""
        _require_nonempty(self.principal_id, "principal_id")
        _require_nonempty(self.tenant_id, "tenant_id")
        _require_nonempty(self.text, "text")
        if self.top_k <= 0:
            raise ValueError("top_k must be positive")


@dataclass(frozen=True, slots=True)
class RetrievalHit:
    """Represent one ranked memory result.

    Attributes:
        memory_id: Identifier of the retrieved memory.
        rank: One-based rank in the retrieval result.
        score: Finite backend-defined retrieval score.
    """

    memory_id: str
    rank: int
    score: float

    def __post_init__(self) -> None:
        """Validate the memory identifier, rank, and score."""
        _require_nonempty(self.memory_id, "memory_id")
        if self.rank <= 0:
            raise ValueError("rank must be one-based")
        if not math.isfinite(self.score):
            raise ValueError("score must be finite")


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    """Contain ranked hits and attacker-visible observations.

    Attributes:
        hits: Ranked memory hits available to the caller.
        observations: Metadata legitimately visible to the requesting principal.
    """

    hits: tuple[RetrievalHit, ...]
    observations: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate result ordering and detach observations."""
        object.__setattr__(self, "hits", tuple(self.hits))
        expected_ranks = tuple(range(1, len(self.hits) + 1))
        if tuple(hit.rank for hit in self.hits) != expected_ranks:
            raise ValueError("retrieval hit ranks must be contiguous and one-based")
        _require_unique(tuple(hit.memory_id for hit in self.hits), "retrieval hit memory IDs")
        object.__setattr__(self, "observations", freeze_json_object(self.observations))


@dataclass(frozen=True, slots=True)
class ProposedDecision:
    """Represent a proposed decision that cannot execute an external action.

    Attributes:
        decision_id: Stable decision identifier.
        episode_id: Episode that produced the decision.
        action: Machine-verifiable proposed action code.
        rationale_memory_ids: Target-visible memories cited by the decision.
        parameters: Synthetic structured decision parameters.
    """

    decision_id: str
    episode_id: EpisodeId
    action: str
    rationale_memory_ids: tuple[str, ...] = ()
    parameters: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the proposed decision and detach parameters."""
        _require_nonempty(self.decision_id, "decision_id")
        _require_nonempty(self.episode_id, "episode_id")
        _require_nonempty(self.action, "action")
        object.__setattr__(self, "rationale_memory_ids", tuple(self.rationale_memory_ids))
        _require_unique(self.rationale_memory_ids, "rationale_memory_ids")
        object.__setattr__(self, "parameters", freeze_json_object(self.parameters))

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical JSON-compatible proposed decision."""
        return {
            "decision_id": self.decision_id,
            "episode_id": self.episode_id,
            "action": self.action,
            "rationale_memory_ids": list(self.rationale_memory_ids),
            "parameters": normalize_json_object(self.parameters),
        }


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    """Capture complete deterministic target state for reset and replay.

    Attributes:
        snapshot_version: Snapshot contract version.
        episode: Episode identity associated with the state.
        logical_time: Current deterministic logical time.
        next_event_sequence: Sequence assigned to the next event.
        source_memories: Complete immutable-source memory records.
        derived_state: Adaptive metadata not stored in source records.
        indexes: Complete deterministic retrieval-index state.
        queues: Pending deterministic work queues.
        policy: Active policy configuration.
        policy_state: Complete mutable state owned by the active policy.
    """

    snapshot_version: int
    episode: EpisodeIdentity
    logical_time: LogicalTime
    next_event_sequence: EventSequence
    source_memories: tuple[MemoryRecord, ...]
    derived_state: JsonObject
    indexes: JsonObject
    queues: JsonObject
    policy: PolicyConfiguration
    policy_state: JsonObject

    def __post_init__(self) -> None:
        """Validate snapshot identity, ordering values, memories, and state objects."""
        if self.snapshot_version <= 0:
            raise ValueError("snapshot_version must be positive")
        _require_nonnegative(self.logical_time, "logical_time")
        _require_nonnegative(self.next_event_sequence, "next_event_sequence")
        object.__setattr__(self, "source_memories", tuple(self.source_memories))
        memory_ids = tuple(memory.memory_id for memory in self.source_memories)
        _require_unique(memory_ids, "source memory IDs")
        if any(memory.scenario_id != self.episode.scenario_id for memory in self.source_memories):
            raise ValueError("all source memories must belong to the snapshot scenario")
        for field_name in ("derived_state", "indexes", "queues", "policy_state"):
            object.__setattr__(
                self,
                field_name,
                freeze_json_object(getattr(self, field_name)),
            )

    def to_json(self) -> dict[str, JsonValue]:
        """Return the canonical JSON-compatible full-state representation."""
        return {
            "snapshot_version": self.snapshot_version,
            "episode": self.episode.to_json(),
            "logical_time": self.logical_time,
            "next_event_sequence": self.next_event_sequence,
            "source_memories": [memory.to_json() for memory in self.source_memories],
            "derived_state": normalize_json_object(self.derived_state),
            "indexes": normalize_json_object(self.indexes),
            "queues": normalize_json_object(self.queues),
            "policy": self.policy.to_json(),
            "policy_state": normalize_json_object(self.policy_state),
        }


@dataclass(frozen=True, slots=True)
class TraceEventDraft:
    """Contain event material before hash-chain fields are assigned.

    Attributes:
        event_id: Stable event identifier.
        episode_id: Episode that emitted the event.
        sequence: Zero-based event sequence.
        logical_time: Deterministic event time.
        event_type: Closed event category.
        actor_principal_id: Target-visible actor or ``None`` for system events.
        visibility: Authorized event-observer boundary.
        state_hash_before: State hash immediately before the event.
        state_hash_after: State hash immediately after the event.
        payload: JSON-compatible event details.
    """

    event_id: str
    episode_id: EpisodeId
    sequence: EventSequence
    logical_time: LogicalTime
    event_type: EventType
    actor_principal_id: str | None
    visibility: EventVisibility
    state_hash_before: str
    state_hash_after: str
    payload: JsonObject

    def __post_init__(self) -> None:
        """Validate draft identifiers, ordering values, and payload."""
        _require_nonempty(self.event_id, "event_id")
        _require_nonempty(self.episode_id, "episode_id")
        _require_nonnegative(self.sequence, "sequence")
        _require_nonnegative(self.logical_time, "logical_time")
        if self.actor_principal_id is not None:
            _require_nonempty(self.actor_principal_id, "actor_principal_id")
        object.__setattr__(self, "payload", freeze_json_object(self.payload))


@dataclass(frozen=True, slots=True)
class TraceEvent:
    """Represent one ordered tamper-evident event.

    Attributes:
        event_id: Stable event identifier.
        episode_id: Episode that emitted the event.
        sequence: Zero-based event sequence.
        logical_time: Deterministic event time.
        event_type: Closed event category.
        actor_principal_id: Target-visible actor or ``None`` for system events.
        visibility: Authorized event-observer boundary.
        state_hash_before: State hash immediately before the event.
        state_hash_after: State hash immediately after the event.
        previous_event_hash: Previous event digest or ``None`` for genesis.
        event_hash: Digest of this event's canonical material.
        payload: JSON-compatible event details.
    """

    event_id: str
    episode_id: EpisodeId
    sequence: EventSequence
    logical_time: LogicalTime
    event_type: EventType
    actor_principal_id: str | None
    visibility: EventVisibility
    state_hash_before: str
    state_hash_after: str
    previous_event_hash: str | None
    event_hash: str
    payload: JsonObject

    def __post_init__(self) -> None:
        """Validate basic event values and detach the payload."""
        _require_nonempty(self.event_id, "event_id")
        _require_nonempty(self.episode_id, "episode_id")
        _require_nonnegative(self.sequence, "sequence")
        _require_nonnegative(self.logical_time, "logical_time")
        if self.actor_principal_id is not None:
            _require_nonempty(self.actor_principal_id, "actor_principal_id")
        object.__setattr__(self, "payload", freeze_json_object(self.payload))
