"""Replaceable decision-provider boundary for synthetic RISI experiments."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from risi.canonical import JsonObject, JsonValue, freeze_json_object
from risi.models import EpisodeIdentity, ProposedDecision, RetrievalResult
from risi.scenarios import DecisionProtocol, ReferenceRunProtocol, RegionDecisionProtocol


@dataclass(frozen=True, slots=True)
class DecisionRequest:
    """Contain only target-visible material supplied to a decision provider.

    Attributes:
        episode: Deterministic episode identity.
        context: Exact assembled retrieval context.
        retrieval: Target-visible retrieval result.
        facts: Target-visible immutable world facts.
        protocol: Target-visible decision protocol.
    """

    episode: EpisodeIdentity
    context: str
    retrieval: RetrievalResult
    facts: JsonObject
    protocol: DecisionProtocol

    def __post_init__(self) -> None:
        """Detach target-visible world facts."""
        object.__setattr__(self, "facts", freeze_json_object(self.facts))


class DecisionProvider(ABC):
    """Define the boundary implemented by deterministic or inference providers."""

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Return the registered provider identifier."""

    @abstractmethod
    def propose(self, request: DecisionRequest) -> ProposedDecision:
        """Produce a synthetic proposal without executing an external action.

        Args:
            request: Target-visible decision request.

        Returns:
            Machine-verifiable proposed decision.
        """


class DeterministicApprovalProvider(DecisionProvider):
    """Apply the target-visible DEP-01 approval protocol deterministically."""

    @property
    def provider_id(self) -> str:
        """Return the registered provider identifier."""
        return "deterministic-approval"

    def propose(self, request: DecisionRequest) -> ProposedDecision:
        """Propose an action from retrieved policy and target-visible facts.

        Args:
            request: Target-visible decision request.

        Returns:
            Deterministic synthetic action proposal.

        Raises:
            TypeError: If the protocol or configured fact has the wrong type.
        """
        protocol = request.protocol
        if not isinstance(protocol, ReferenceRunProtocol):
            raise TypeError("deterministic approval provider requires an approval protocol")
        approval_count = request.facts.get(protocol.approval_count_fact)
        if isinstance(approval_count, bool) or not isinstance(approval_count, int):
            raise TypeError("approval-count fact must be an integer")
        retrieved_ids = tuple(hit.memory_id for hit in request.retrieval.hits)
        policy_available = protocol.required_memory_id in retrieved_ids
        below_threshold = approval_count < protocol.minimum_approvals
        rationale: tuple[str, ...]
        if policy_available and below_threshold:
            action = protocol.action_if_below
            rationale = (protocol.required_memory_id,)
        else:
            action = protocol.action_if_met
            rationale = ()
        parameters: dict[str, JsonValue] = {
            "approval_count": approval_count,
            "minimum_approvals": protocol.minimum_approvals,
            "policy_available": policy_available,
        }
        return ProposedDecision(
            decision_id=f"{request.episode.episode_id}-decision-0001",
            episode_id=request.episode.episode_id,
            action=action,
            rationale_memory_ids=rationale,
            parameters=parameters,
        )


class DeterministicRegionProvider(DecisionProvider):
    """Apply the target-visible DEP-02 region protocol deterministically."""

    @property
    def provider_id(self) -> str:
        """Return the registered provider identifier."""
        return "deterministic-region"

    def propose(self, request: DecisionRequest) -> ProposedDecision:
        """Propose a synthetic region action from retrieved policy and world facts.

        Args:
            request: Target-visible region decision request.

        Returns:
            Deterministic synthetic region proposal.

        Raises:
            TypeError: If the protocol or required world facts have the wrong type.
        """
        protocol = request.protocol
        if not isinstance(protocol, RegionDecisionProtocol):
            raise TypeError("deterministic region provider requires a region protocol")
        dataset_class = request.facts.get(protocol.dataset_class_fact)
        requested_region = request.facts.get(protocol.requested_region_fact)
        if not isinstance(dataset_class, str) or not isinstance(requested_region, str):
            raise TypeError("region decision facts must be strings")
        retrieved_ids = tuple(hit.memory_id for hit in request.retrieval.hits)
        policy_available = protocol.required_memory_id in retrieved_ids
        prohibited = (
            policy_available
            and dataset_class == protocol.restricted_dataset_class
            and requested_region == protocol.prohibited_region
        )
        action = protocol.action_if_prohibited if prohibited else protocol.action_if_allowed
        rationale = (protocol.required_memory_id,) if policy_available else ()
        parameters: dict[str, JsonValue] = {
            "dataset_class": dataset_class,
            "requested_region": requested_region,
            "prohibited_region": protocol.prohibited_region,
            "policy_available": policy_available,
            "allowed_alternatives": list(protocol.allowed_alternatives),
        }
        return ProposedDecision(
            decision_id=f"{request.episode.episode_id}-decision-0001",
            episode_id=request.episode.episode_id,
            action=action,
            rationale_memory_ids=rationale,
            parameters=parameters,
        )
