"""Deterministic reference-engine composition point."""

from risi.adapters.base import MemoryAdapter
from risi.models import EpisodeIdentity, StateSnapshot


class ReferenceEngine:
    """Bind an adapter to one deterministic episode identity.

    The engine intentionally implements no attack policy, persistence backend, or model behavior.
    It only enforces episode identity around evaluator-controlled snapshots and resets.

    Args:
        adapter: Framework-neutral target memory adapter.
        episode: Immutable identity of the deterministic episode.
    """

    def __init__(self, adapter: MemoryAdapter, episode: EpisodeIdentity) -> None:
        self._adapter = adapter
        self._episode = episode

    @property
    def adapter(self) -> MemoryAdapter:
        """Return the configured memory-system adapter."""
        return self._adapter

    @property
    def episode(self) -> EpisodeIdentity:
        """Return the immutable episode identity."""
        return self._episode

    def snapshot(self) -> StateSnapshot:
        """Capture state and verify that it belongs to this episode.

        Returns:
            Complete deterministic target-state snapshot.

        Raises:
            ValueError: If the adapter returns state for another episode.
        """
        snapshot = self._adapter.snapshot()
        self._require_episode(snapshot)
        return snapshot

    def reset(self, snapshot: StateSnapshot) -> None:
        """Restore state after verifying episode identity.

        Args:
            snapshot: Complete deterministic target state.

        Raises:
            ValueError: If the snapshot belongs to another episode.
        """
        self._require_episode(snapshot)
        self._adapter.reset(snapshot)

    def _require_episode(self, snapshot: StateSnapshot) -> None:
        if snapshot.episode != self._episode:
            raise ValueError("snapshot does not belong to this reference-engine episode")
