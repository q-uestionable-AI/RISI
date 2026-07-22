"""Deterministic campaign geometry and interval calculations."""

from __future__ import annotations

import math
from dataclasses import dataclass

from risi.canonical import JsonValue

E1_WORLD_COUNT = 330
E1_OBSERVATIONS_PER_WORLD = 22
E1_TOTAL_OBSERVATIONS = 7_260
E1_PRIMARY_POWER = 0.8025


@dataclass(frozen=True, slots=True)
class CampaignGeometry:
    """Describe the immutable primary E1 campaign geometry."""

    world_count: int
    observations_per_world: int
    total_observations: int
    primary_power: float

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable campaign geometry."""
        return {
            "world_count": self.world_count,
            "observations_per_world": self.observations_per_world,
            "total_observations": self.total_observations,
            "primary_power": self.primary_power,
        }


def e1_campaign_geometry() -> CampaignGeometry:
    """Return and internally verify the accepted E1 design geometry."""
    total = E1_WORLD_COUNT * E1_OBSERVATIONS_PER_WORLD
    if total != E1_TOTAL_OBSERVATIONS:
        raise RuntimeError("E1 geometry constants are inconsistent")
    return CampaignGeometry(
        world_count=E1_WORLD_COUNT,
        observations_per_world=E1_OBSERVATIONS_PER_WORLD,
        total_observations=total,
        primary_power=E1_PRIMARY_POWER,
    )


@dataclass(frozen=True, slots=True)
class ProportionInterval:
    """Contain a bounded two-sided Wilson score interval."""

    successes: int
    trials: int
    estimate: float
    lower: float
    upper: float

    def to_json(self) -> dict[str, JsonValue]:
        """Return the interval representation."""
        return {
            "successes": self.successes,
            "trials": self.trials,
            "estimate": self.estimate,
            "lower": self.lower,
            "upper": self.upper,
        }


def wilson_interval(
    successes: int, trials: int, *, z: float = 1.959963984540054
) -> ProportionInterval:
    """Calculate a deterministic two-sided Wilson interval.

    Args:
        successes: Observed binary successes.
        trials: Total binary trials.
        z: Fixed standard-normal quantile; defaults to a 95 percent interval.
    """
    if isinstance(successes, bool) or isinstance(trials, bool):
        raise TypeError("successes and trials must be integers")
    if trials <= 0 or successes < 0 or successes > trials or not math.isfinite(z) or z <= 0:
        raise ValueError("interval inputs are outside their valid ranges")
    estimate = successes / trials
    z_squared = z * z
    denominator = 1 + z_squared / trials
    center = (estimate + z_squared / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(estimate * (1 - estimate) / trials + z_squared / (4 * trials * trials))
        / denominator
    )
    return ProportionInterval(
        successes, trials, estimate, max(0.0, center - margin), min(1.0, center + margin)
    )
