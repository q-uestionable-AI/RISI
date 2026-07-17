"""Deterministic resource accounting for guarded reference runs."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from risi.canonical import JsonValue
from risi.operator.models import ExecutionLimits


class BudgetResource(StrEnum):
    """Closed resource vocabulary enforced by the run ledger."""

    EPISODES = "episodes"
    RETRIEVAL_CALLS = "retrieval_calls"
    LOGICAL_STEPS = "logical_steps"
    INPUT_BYTES = "input_bytes"
    MEMORY_RECORDS = "memory_records"
    ARTIFACT_BYTES = "artifact_bytes"


class BudgetExhaustedError(RuntimeError):
    """Raised before a guarded run exceeds an approved resource limit.

    Attributes:
        resource: Resource whose approved ceiling would be exceeded.
        approved: Approved ceiling from the exact run manifest.
        consumed: Amount consumed before the rejected request.
        requested: Additional amount requested by the rejected operation.
    """

    def __init__(
        self,
        resource: BudgetResource,
        *,
        approved: int,
        consumed: int,
        requested: int,
    ) -> None:
        super().__init__(f"approved {resource.value} budget exhausted")
        self.resource = resource
        self.approved = approved
        self.consumed = consumed
        self.requested = requested

    def to_json(self) -> dict[str, JsonValue]:
        """Return the closed machine-readable exhaustion detail."""
        return {
            "resource": self.resource.value,
            "approved": self.approved,
            "consumed": self.consumed,
            "requested": self.requested,
        }


@dataclass(frozen=True, slots=True)
class ResourceConsumption:
    """Contain nonnegative consumed amounts for every bounded resource."""

    episodes: int = 0
    retrieval_calls: int = 0
    logical_steps: int = 0
    input_bytes: int = 0
    memory_records: int = 0
    artifact_bytes: int = 0

    def __post_init__(self) -> None:
        """Reject negative or non-integer resource accounting."""
        for resource in BudgetResource:
            value = getattr(self, resource.value)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{resource.value} consumption must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class BudgetAmount:
    """Pair one approved resource ceiling with its consumed amount."""

    approved: int
    consumed: int

    def __post_init__(self) -> None:
        """Validate one closed resource-use amount."""
        if (
            isinstance(self.approved, bool)
            or not isinstance(self.approved, int)
            or self.approved <= 0
        ):
            raise ValueError("approved resource amount must be a positive integer")
        if (
            isinstance(self.consumed, bool)
            or not isinstance(self.consumed, int)
            or self.consumed < 0
            or self.consumed > self.approved
        ):
            raise ValueError("consumed resource amount must be within the approved ceiling")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the approved and consumed values."""
        return {"approved": self.approved, "consumed": self.consumed}


@dataclass(frozen=True, slots=True)
class ResourceUse:
    """Report approved and consumed amounts for all bounded resources."""

    episodes: BudgetAmount
    retrieval_calls: BudgetAmount
    logical_steps: BudgetAmount
    input_bytes: BudgetAmount
    memory_records: BudgetAmount
    artifact_bytes: BudgetAmount

    def to_json(self) -> dict[str, JsonValue]:
        """Return the closed resource-use representation."""
        return {
            resource.value: getattr(self, resource.value).to_json() for resource in BudgetResource
        }

    @classmethod
    def from_json(cls, value: object) -> ResourceUse:
        """Parse an exact resource-use object from retained evidence.

        Args:
            value: Candidate decoded JSON value.

        Returns:
            Validated immutable resource-use report.

        Raises:
            TypeError: If an approved or consumed amount is not an integer.
            ValueError: If the field set or any amount is invalid.
        """
        if not isinstance(value, dict) or set(value) != {item.value for item in BudgetResource}:
            raise ValueError("resource_use has an invalid field set")
        amounts: dict[str, BudgetAmount] = {}
        for resource in BudgetResource:
            raw = value[resource.value]
            if not isinstance(raw, dict) or set(raw) != {"approved", "consumed"}:
                raise ValueError(f"resource_use.{resource.value} has an invalid field set")
            approved = raw["approved"]
            consumed = raw["consumed"]
            if (
                isinstance(approved, bool)
                or not isinstance(approved, int)
                or isinstance(consumed, bool)
                or not isinstance(consumed, int)
            ):
                raise TypeError(f"resource_use.{resource.value} values must be integers")
            amounts[resource.value] = BudgetAmount(approved, consumed)
        return cls(
            episodes=amounts["episodes"],
            retrieval_calls=amounts["retrieval_calls"],
            logical_steps=amounts["logical_steps"],
            input_bytes=amounts["input_bytes"],
            memory_records=amounts["memory_records"],
            artifact_bytes=amounts["artifact_bytes"],
        )


@dataclass(frozen=True, slots=True)
class BudgetLedger:
    """Track deterministic consumption against one approved manifest limit set."""

    approved: ExecutionLimits
    consumed: ResourceConsumption = ResourceConsumption()

    def consume(self, resource: BudgetResource, amount: int = 1) -> BudgetLedger:
        """Return a ledger with one bounded resource increment applied.

        Args:
            resource: Closed resource to consume.
            amount: Nonnegative deterministic increment.

        Returns:
            New immutable ledger containing the accepted increment.

        Raises:
            ValueError: If the requested amount is not a nonnegative integer.
            BudgetExhaustedError: If the increment would exceed the approved ceiling.
        """
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise ValueError("budget consumption amount must be a nonnegative integer")
        consumed = getattr(self.consumed, resource.value)
        approved = getattr(self.approved, resource.value)
        if consumed + amount > approved:
            raise BudgetExhaustedError(
                resource,
                approved=approved,
                consumed=consumed,
                requested=amount,
            )
        return replace(
            self,
            consumed=replace(self.consumed, **{resource.value: consumed + amount}),
        )

    def resource_use(self) -> ResourceUse:
        """Return approved and consumed values for evidence and results."""

        def amount(resource: BudgetResource) -> BudgetAmount:
            return BudgetAmount(
                getattr(self.approved, resource.value),
                getattr(self.consumed, resource.value),
            )

        return ResourceUse(
            episodes=amount(BudgetResource.EPISODES),
            retrieval_calls=amount(BudgetResource.RETRIEVAL_CALLS),
            logical_steps=amount(BudgetResource.LOGICAL_STEPS),
            input_bytes=amount(BudgetResource.INPUT_BYTES),
            memory_records=amount(BudgetResource.MEMORY_RECORDS),
            artifact_bytes=amount(BudgetResource.ARTIFACT_BYTES),
        )
