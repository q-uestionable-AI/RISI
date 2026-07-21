"""Closed health-sampling contract for isolated campaign targets."""

from __future__ import annotations

from dataclasses import dataclass, field

from risi.canonical import JsonObject, JsonValue, freeze_json_object, normalize_json_object


@dataclass(frozen=True, slots=True)
class HealthSample:
    """Record one engineering-health sample without experimental outcomes."""

    sample_sequence: int
    services: JsonObject
    cpu_percent: float
    memory_bytes: int
    storage_bytes: int
    restart_count: int
    oom_kill_count: int
    firewall_denied_count: int
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate nonnegative, finite engineering measurements."""
        if self.sample_sequence < 0:
            raise ValueError("sample_sequence must be nonnegative")
        if not 0.0 <= self.cpu_percent <= 100.0:
            raise ValueError("cpu_percent must be between zero and one hundred")
        for name in (
            "memory_bytes",
            "storage_bytes",
            "restart_count",
            "oom_kill_count",
            "firewall_denied_count",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        object.__setattr__(self, "services", freeze_json_object(self.services))
        object.__setattr__(self, "metadata", freeze_json_object(self.metadata))

    def to_json(self) -> dict[str, JsonValue]:
        """Return the exact health-sample representation."""
        return {
            "schema_version": 1,
            "sample_sequence": self.sample_sequence,
            "services": normalize_json_object(self.services),
            "cpu_percent": self.cpu_percent,
            "memory_bytes": self.memory_bytes,
            "storage_bytes": self.storage_bytes,
            "restart_count": self.restart_count,
            "oom_kill_count": self.oom_kill_count,
            "firewall_denied_count": self.firewall_denied_count,
            "metadata": normalize_json_object(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class HealthLimits:
    """Define stop ceilings for an E2 validation lifecycle."""

    max_cpu_percent: float
    max_memory_bytes: int
    max_storage_bytes: int
    max_restart_count: int = 0
    max_oom_kill_count: int = 0


def health_stop_reasons(sample: HealthSample, limits: HealthLimits) -> tuple[str, ...]:
    """Return stable stop reasons for one health sample."""
    reasons: list[str] = []
    if sample.cpu_percent > limits.max_cpu_percent:
        reasons.append("cpu_ceiling_exceeded")
    if sample.memory_bytes > limits.max_memory_bytes:
        reasons.append("memory_ceiling_exceeded")
    if sample.storage_bytes > limits.max_storage_bytes:
        reasons.append("storage_ceiling_exceeded")
    if sample.restart_count > limits.max_restart_count:
        reasons.append("service_restart_observed")
    if sample.oom_kill_count > limits.max_oom_kill_count:
        reasons.append("oom_kill_observed")
    unhealthy = sorted(name for name, state in sample.services.items() if state != "healthy")
    reasons.extend(f"service_unhealthy:{name}" for name in unhealthy)
    return tuple(reasons)
