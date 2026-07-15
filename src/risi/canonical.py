"""Deterministic JSON serialization and hashing helpers."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import TypeAlias, cast

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = (
    JsonScalar | list["JsonValue"] | tuple["JsonValue", ...] | Mapping[str, "JsonValue"]
)
JsonObject: TypeAlias = Mapping[str, JsonValue]
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented as deterministic JSON."""


def normalize_json_value(value: object) -> JsonValue:
    """Return a detached JSON-compatible representation of a value.

    Args:
        value: Candidate value containing only JSON scalars, sequences, and mappings.

    Returns:
        A recursively copied value containing only JSON-compatible built-in types.

    Raises:
        CanonicalizationError: If the value is ambiguous or unsupported.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("JSON numbers must be finite")
        return value
    if isinstance(value, (list, tuple)):
        return [normalize_json_value(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            normalized[key] = normalize_json_value(item)
        return normalized
    raise CanonicalizationError(f"Unsupported JSON value type: {type(value).__name__}")


def normalize_json_object(value: object) -> dict[str, JsonValue]:
    """Return a detached JSON object.

    Args:
        value: Candidate mapping.

    Returns:
        A normalized JSON object.

    Raises:
        CanonicalizationError: If the value is not a JSON object or contains unsupported values.
    """
    normalized = normalize_json_value(value)
    if not isinstance(normalized, dict):
        raise CanonicalizationError("Expected a JSON object")
    return cast(dict[str, JsonValue], normalized)


def freeze_json_value(value: object) -> JsonValue:
    """Return a deeply immutable JSON-compatible value.

    Args:
        value: Candidate JSON-compatible value.

    Returns:
        A value whose arrays are tuples and whose objects are read-only mappings.

    Raises:
        CanonicalizationError: If the value contains unsupported data.
    """
    normalized = normalize_json_value(value)
    if isinstance(normalized, list):
        return tuple(freeze_json_value(item) for item in normalized)
    if isinstance(normalized, dict):
        return MappingProxyType({key: freeze_json_value(item) for key, item in normalized.items()})
    return normalized


def freeze_json_object(value: object) -> JsonObject:
    """Return a deeply immutable JSON object.

    Args:
        value: Candidate JSON mapping.

    Returns:
        Read-only normalized JSON mapping.

    Raises:
        CanonicalizationError: If the value is not a JSON object.
    """
    frozen = freeze_json_value(value)
    if not isinstance(frozen, Mapping):
        raise CanonicalizationError("Expected a JSON object")
    return frozen


def canonical_json(value: object) -> str:
    """Serialize a value to the RISI canonical JSON representation.

    Canonical JSON uses UTF-8-compatible text, sorted object keys, compact separators, and rejects
    non-finite numbers. The contract is intentionally narrower than arbitrary Python serialization.

    Args:
        value: JSON-compatible value to serialize.

    Returns:
        Deterministic JSON text.

    Raises:
        CanonicalizationError: If the value is not supported.
    """
    normalized = normalize_json_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a value to canonical UTF-8 JSON bytes.

    Args:
        value: JSON-compatible value to serialize.

    Returns:
        Deterministic UTF-8 bytes.
    """
    return canonical_json(value).encode("utf-8")


def canonical_sha256(value: object) -> str:
    """Return the hexadecimal SHA-256 digest of canonical JSON.

    Args:
        value: JSON-compatible value to hash.

    Returns:
        A lowercase 64-character hexadecimal digest.
    """
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def is_sha256_digest(value: str) -> bool:
    """Return whether a string is a lowercase SHA-256 digest.

    Args:
        value: Candidate hexadecimal digest.

    Returns:
        ``True`` for exactly 64 lowercase hexadecimal characters.
    """
    return _SHA256_PATTERN.fullmatch(value) is not None
