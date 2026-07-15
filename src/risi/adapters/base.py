"""Framework-neutral memory-system adapter contract."""

from abc import ABC, abstractmethod

from risi.models import (
    MemoryRecord,
    PolicyConfiguration,
    RetrievalQuery,
    RetrievalResult,
    StateSnapshot,
    TraceEvent,
)


class MemoryAdapter(ABC):
    """Define the complete experimental boundary for a memory backend.

    Target operations use ordinary ingest, retrieve, and context methods. Snapshot, reset, trace,
    and inspection methods belong only to the evaluator harness and must never be surfaced through
    an attacker or target tool interface.
    """

    @abstractmethod
    def ingest(self, memory: MemoryRecord) -> MemoryRecord:
        """Admit a target-visible memory record.

        Args:
            memory: Synthetic record submitted through the ordinary write interface.

        Returns:
            The admitted or normalized target-visible record.
        """

    @abstractmethod
    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        """Retrieve memories through an authorized principal view.

        Args:
            query: Authorized retrieval request.

        Returns:
            Ranked results and caller-visible observations.
        """

    @abstractmethod
    def assemble_context(self, result: RetrievalResult) -> str:
        """Assemble deterministic decision context from retrieval results.

        Args:
            result: Ranked retrieval output.

        Returns:
            Exact context supplied to the decision layer.
        """

    @abstractmethod
    def configure_policy(self, configuration: PolicyConfiguration) -> None:
        """Configure a replaceable deterministic memory-control policy.

        Args:
            configuration: Typed policy identity and target-visible settings.
        """

    @abstractmethod
    def snapshot(self) -> StateSnapshot:
        """Capture complete target state for evaluator-controlled reset and replay."""

    @abstractmethod
    def reset(self, snapshot: StateSnapshot) -> None:
        """Restore complete deterministic target state.

        Args:
            snapshot: Full-state snapshot previously produced by the adapter.
        """

    @abstractmethod
    def advance_clock(self, logical_steps: int) -> int:
        """Advance deterministic logical time.

        Args:
            logical_steps: Positive number of logical steps.

        Returns:
            Updated logical time.
        """

    @abstractmethod
    def run_maintenance(self) -> None:
        """Run deterministic pending maintenance operations."""

    @abstractmethod
    def consolidate(self) -> tuple[str, ...]:
        """Run configured consolidation and return affected memory identifiers."""

    @abstractmethod
    def expire(self) -> tuple[str, ...]:
        """Run configured expiry and return affected memory identifiers."""

    @abstractmethod
    def export_trace(self) -> tuple[TraceEvent, ...]:
        """Export the ordered tamper-evident event trace for evaluator verification."""

    @abstractmethod
    def inspect_state(self) -> StateSnapshot:
        """Return evaluator-only target state that is never exposed to attacker views."""
