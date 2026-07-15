import math

import pytest

from risi.canonical import (
    CanonicalizationError,
    canonical_json,
    canonical_json_bytes,
    canonical_sha256,
    normalize_json_value,
)


def test_canonical_json_is_stable_across_mapping_order() -> None:
    first = {"z": [3, 2, 1], "a": {"unicode": "café"}}
    second = {"a": {"unicode": "café"}, "z": (3, 2, 1)}

    assert canonical_json(first) == canonical_json(second)
    assert canonical_json(first) == '{"a":{"unicode":"café"},"z":[3,2,1]}'
    assert canonical_json_bytes(first).decode("utf-8") == canonical_json(first)
    assert canonical_sha256(first) == canonical_sha256(second)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_canonical_json_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(CanonicalizationError, match="finite"):
        canonical_json({"value": value})


def test_canonical_json_rejects_non_string_keys() -> None:
    with pytest.raises(CanonicalizationError, match="keys must be strings"):
        normalize_json_value({1: "ambiguous"})


def test_canonical_json_rejects_arbitrary_objects() -> None:
    with pytest.raises(CanonicalizationError, match="Unsupported"):
        canonical_json(object())
