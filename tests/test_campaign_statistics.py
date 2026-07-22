import pytest

from risi.statistics import (
    E1_OBSERVATIONS_PER_WORLD,
    E1_PRIMARY_POWER,
    E1_TOTAL_OBSERVATIONS,
    E1_WORLD_COUNT,
    e1_campaign_geometry,
    wilson_interval,
)


def test_e1_geometry_is_exact_and_self_consistent() -> None:
    geometry = e1_campaign_geometry()

    assert geometry.world_count == E1_WORLD_COUNT == 330
    assert geometry.observations_per_world == E1_OBSERVATIONS_PER_WORLD == 22
    assert geometry.total_observations == E1_TOTAL_OBSERVATIONS == 7_260
    assert geometry.primary_power == E1_PRIMARY_POWER == 0.8025
    assert geometry.world_count * geometry.observations_per_world == geometry.total_observations


def test_wilson_interval_is_bounded_and_deterministic() -> None:
    first = wilson_interval(264, 330)
    second = wilson_interval(264, 330)

    assert first == second
    assert first.estimate == 0.8
    assert 0.0 < first.lower < first.estimate < first.upper < 1.0


def test_wilson_interval_rejects_invalid_counts() -> None:
    with pytest.raises(ValueError):
        wilson_interval(2, 1)
