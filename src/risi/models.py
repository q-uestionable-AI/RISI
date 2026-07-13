"""Core target-visible models for the initial RISI scaffold."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class EventVisibility(StrEnum):
    """Visibility boundary for an emitted experimental event."""

    ATTACKER = "attacker"
    EVALUATOR = "evaluator"
    BOTH = "both"


class MemoryState(StrEnum):
    """Lifecycle state of a target-visible memory record."""

    CURRENT = "current"
    SUPERSEDED = "superseded"
    HIDDEN = "hidden"
    ARCHIVED = "archived"
    DELETED = "deleted"


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
        system_criticality: Optional system-visible criticality label.
        state: Current lifecycle state.
        metadata: Target-visible adaptive metadata.
    """

    memory_id: str
    scenario_id: str
    tenant_id: str
    owner_id: str
    source_id: str
    content: str
    access_policy: tuple[str, ...]
    logical_created_at: int
    system_criticality: str | None = None
    state: MemoryState = MemoryState.CURRENT
    metadata: dict[str, JsonValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RetrievalQuery:
    """Describe an authorized retrieval request.

    Attributes:
        principal_id: Principal issuing the query.
        tenant_id: Tenant boundary for authorization.
        text: Synthetic query text.
        top_k: Maximum number of results requested.
    """

    principal_id: str
    tenant_id: str
    text: str
    top_k: int


@dataclass(frozen=True, slots=True)
class RetrievalHit:
    """Represent one ranked memory result.

    Attributes:
        memory_id: Identifier of the retrieved memory.
        rank: One-based rank in the retrieval result.
        score: Backend-defined retrieval score.
    """

    memory_id: str
    rank: int
    score: float


@dataclass(frozen=True, slots=True)
class RetrievalResult:
    """Contain ranked hits and attacker-visible observations.

    Attributes:
        hits: Ranked memory hits available to the caller.
        observations: Metadata legitimately visible to the requesting principal.
    """

    hits: tuple[RetrievalHit, ...]
    observations: dict[str, JsonValue] = field(default_factory=dict)
