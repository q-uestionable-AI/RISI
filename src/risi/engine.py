"""Reference-engine composition point.

The first scaffold intentionally defines no persistence or attack behavior. Later M1 work will add
deterministic policies behind the adapter boundary.
"""

from risi.adapters.base import MemoryAdapter


class ReferenceEngine:
    """Hold the backend adapter used by the future deterministic reference engine."""

    def __init__(self, adapter: MemoryAdapter) -> None:
        self._adapter = adapter

    @property
    def adapter(self) -> MemoryAdapter:
        """Return the configured memory-system adapter."""
        return self._adapter
