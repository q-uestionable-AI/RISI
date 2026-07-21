"""Framework-neutral contract for an isolated external knowledge target."""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from risi.canonical import (
    JsonObject,
    JsonValue,
    canonical_sha256,
    freeze_json_object,
    normalize_json_object,
)
from risi.operator.models import ExecutionProfile, OperatorInputError
from risi.transport import CancellationToken


@dataclass(frozen=True, slots=True)
class ExternalTargetManifest:
    """Bind an isolated target to exact transport and service identities."""

    schema_version: int
    target_id: str
    profile: ExecutionProfile
    base_url: str
    server_name: str
    certificate_sha256: str
    ca_certificate_path: str
    api_key_sha256: str
    health_token_sha256: str
    api_paths: JsonObject
    identities: JsonObject
    request_timeout_seconds: int = 10
    automatic_retry_count: int = 0
    indexing_poll_seconds: int = 1
    indexing_timeout_seconds: int = 300
    metadata: JsonObject = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the closed E2 external-target envelope."""
        if self.schema_version != 1:
            raise OperatorInputError("target manifest schema_version must be 1")
        if re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", self.target_id) is None:
            raise OperatorInputError("target_id must be a lowercase registered identifier")
        if self.profile is not ExecutionProfile.ISOLATED_DIFY_KNOWLEDGE:
            raise OperatorInputError("target profile must be isolated-dify-knowledge")
        self._validate_transport_identity()
        self._validate_lifecycle_ceilings()
        object.__setattr__(self, "api_paths", freeze_json_object(self.api_paths))
        object.__setattr__(self, "identities", freeze_json_object(self.identities))
        object.__setattr__(self, "metadata", freeze_json_object(self.metadata))

    def _validate_transport_identity(self) -> None:
        """Validate the frozen HTTPS and credential identities."""
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise OperatorInputError("base_url must be one HTTPS origin")
        guest_ipv4 = self.identities.get("guest_ipv4")
        allowed_hosts = {self.server_name}
        if isinstance(guest_ipv4, str):
            allowed_hosts.add(guest_ipv4)
        if parsed.hostname not in allowed_hosts:
            raise OperatorInputError("base_url host is not the frozen target identity")
        if self.server_name != "risi-dify-e1":
            raise OperatorInputError("server_name is not the frozen E1 target identity")
        for name in ("certificate_sha256", "api_key_sha256", "health_token_sha256"):
            if re.fullmatch(r"[a-f0-9]{64}", getattr(self, name)) is None:
                raise OperatorInputError(f"{name} must be a lowercase SHA-256 digest")
        if not self.ca_certificate_path.strip():
            raise OperatorInputError("ca_certificate_path must not be empty")

    def _validate_lifecycle_ceilings(self) -> None:
        """Validate fixed timeout, polling, and zero-retry ceilings."""
        if self.request_timeout_seconds != 10:
            raise OperatorInputError("request_timeout_seconds must be exactly 10")
        if self.automatic_retry_count != 0:
            raise OperatorInputError("automatic_retry_count must be zero")
        if self.indexing_poll_seconds != 1 or self.indexing_timeout_seconds != 300:
            raise OperatorInputError("indexing polling must be one second with a 300 second limit")

    @property
    def digest(self) -> str:
        """Return the canonical target-manifest digest."""
        return canonical_sha256(self.to_json())

    def to_json(self) -> dict[str, JsonValue]:
        """Return the exact target-manifest representation."""
        return {
            "schema_version": self.schema_version,
            "target_id": self.target_id,
            "profile": self.profile.value,
            "base_url": self.base_url,
            "server_name": self.server_name,
            "certificate_sha256": self.certificate_sha256,
            "ca_certificate_path": self.ca_certificate_path,
            "api_key_sha256": self.api_key_sha256,
            "health_token_sha256": self.health_token_sha256,
            "api_paths": normalize_json_object(self.api_paths),
            "identities": normalize_json_object(self.identities),
            "request_timeout_seconds": self.request_timeout_seconds,
            "automatic_retry_count": self.automatic_retry_count,
            "indexing_poll_seconds": self.indexing_poll_seconds,
            "indexing_timeout_seconds": self.indexing_timeout_seconds,
            "metadata": normalize_json_object(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class TargetCredential:
    """Contain target API and health credentials without a JSON rendering method."""

    target_id: str
    api_key: str = field(repr=False)
    health_token: str = field(repr=False)

    def __post_init__(self) -> None:
        """Validate credential identity without exposing credential material."""
        if (
            not self.target_id.strip()
            or not self.api_key
            or not self.health_token
            or "\r" in self.api_key
            or "\n" in self.api_key
            or "\r" in self.health_token
            or "\n" in self.health_token
        ):
            raise OperatorInputError("target credential is invalid")


def load_target_credential(path: Path, manifest: ExternalTargetManifest) -> TargetCredential:
    """Load fingerprint-bound secrets from an operator-controlled regular file."""
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.is_symlink():
            raise OperatorInputError("credential path must be a regular non-symlink file")
        content = resolved.read_bytes()
    except OSError as exc:
        raise OperatorInputError("cannot read target credential") from exc
    if len(content) > 16_384:
        raise OperatorInputError("target credential file exceeds the size limit")
    try:
        value: Any = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorInputError("target credential is not valid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"target_id", "api_key", "health_token"}:
        raise OperatorInputError("target credential has an invalid field set")
    target_id = value["target_id"]
    api_key = value["api_key"]
    health_token = value["health_token"]
    if not all(isinstance(item, str) for item in (target_id, api_key, health_token)):
        raise OperatorInputError("target credential fields must be strings")
    if target_id != manifest.target_id:
        raise OperatorInputError("target credential is bound to another target")
    credential = TargetCredential(target_id, api_key, health_token)
    if hashlib.sha256(api_key.encode("utf-8")).hexdigest() != manifest.api_key_sha256:
        raise OperatorInputError("target API key fingerprint does not match the manifest")
    if hashlib.sha256(health_token.encode("utf-8")).hexdigest() != manifest.health_token_sha256:
        raise OperatorInputError("target health token fingerprint does not match the manifest")
    return credential


def load_external_target_manifest(path: Path) -> ExternalTargetManifest:
    """Strictly load an external-target manifest."""
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperatorInputError(f"cannot read external target manifest: {exc}") from exc
    required = {
        "schema_version",
        "target_id",
        "profile",
        "base_url",
        "server_name",
        "certificate_sha256",
        "ca_certificate_path",
        "api_key_sha256",
        "health_token_sha256",
        "api_paths",
        "identities",
        "request_timeout_seconds",
        "automatic_retry_count",
        "indexing_poll_seconds",
        "indexing_timeout_seconds",
        "metadata",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OperatorInputError("external target manifest has an invalid field set")
    try:
        profile = ExecutionProfile(value["profile"])
    except (TypeError, ValueError) as exc:
        raise OperatorInputError("external target profile is not implemented") from exc
    for field_name in ("api_paths", "identities", "metadata"):
        if not isinstance(value[field_name], dict):
            raise OperatorInputError(f"{field_name} must be an object")
    integer_fields = (
        "schema_version",
        "request_timeout_seconds",
        "automatic_retry_count",
        "indexing_poll_seconds",
        "indexing_timeout_seconds",
    )
    if any(
        isinstance(value[name], bool) or not isinstance(value[name], int) for name in integer_fields
    ):
        raise OperatorInputError("external target numeric fields must be integers")
    string_fields = (
        "target_id",
        "base_url",
        "server_name",
        "certificate_sha256",
        "ca_certificate_path",
        "api_key_sha256",
        "health_token_sha256",
    )
    if any(not isinstance(value[name], str) for name in string_fields):
        raise OperatorInputError("external target identity fields must be strings")
    return ExternalTargetManifest(
        schema_version=cast(int, value["schema_version"]),
        target_id=cast(str, value["target_id"]),
        profile=profile,
        base_url=cast(str, value["base_url"]),
        server_name=cast(str, value["server_name"]),
        certificate_sha256=cast(str, value["certificate_sha256"]),
        ca_certificate_path=cast(str, value["ca_certificate_path"]),
        api_key_sha256=cast(str, value["api_key_sha256"]),
        health_token_sha256=cast(str, value["health_token_sha256"]),
        api_paths=cast(dict[str, Any], value["api_paths"]),
        identities=cast(dict[str, Any], value["identities"]),
        request_timeout_seconds=cast(int, value["request_timeout_seconds"]),
        automatic_retry_count=cast(int, value["automatic_retry_count"]),
        indexing_poll_seconds=cast(int, value["indexing_poll_seconds"]),
        indexing_timeout_seconds=cast(int, value["indexing_timeout_seconds"]),
        metadata=cast(dict[str, Any], value["metadata"]),
    )


@dataclass(frozen=True, slots=True)
class ExternalRetrievalHit:
    """Represent one ordered Dify segment result."""

    segment_id: str
    document_id: str
    rank: int
    score: float
    content: str

    def to_json(self) -> dict[str, JsonValue]:
        """Return the target-visible retrieval hit."""
        return {
            "segment_id": self.segment_id,
            "document_id": self.document_id,
            "rank": self.rank,
            "score": self.score,
            "content": self.content,
        }


@dataclass(frozen=True, slots=True)
class ExternalRetrievalResult:
    """Contain ordered external-target retrieval hits."""

    hits: tuple[ExternalRetrievalHit, ...]

    def __post_init__(self) -> None:
        """Require contiguous ranks and unique segments."""
        object.__setattr__(self, "hits", tuple(self.hits))
        if tuple(hit.rank for hit in self.hits) != tuple(range(1, len(self.hits) + 1)):
            raise ValueError("external retrieval ranks must be contiguous and one-based")
        if len({hit.segment_id for hit in self.hits}) != len(self.hits):
            raise ValueError("external retrieval segment IDs must be unique")

    def to_json(self) -> dict[str, JsonValue]:
        """Return the ordered retrieval result."""
        return {"hits": [hit.to_json() for hit in self.hits]}


class ExternalKnowledgeAdapter(ABC):
    """Define the ordinary Dify Knowledge API boundary used by a campaign."""

    @abstractmethod
    def list_knowledge_bases(self, cancellation: CancellationToken) -> tuple[JsonObject, ...]:
        """List the complete bounded owner-visible knowledge-base inventory."""

    @abstractmethod
    def create_knowledge_base(self, name: str, cancellation: CancellationToken) -> str:
        """Create one condition knowledge base and return its identifier."""

    @abstractmethod
    def inspect_knowledge_base(
        self, dataset_id: str, cancellation: CancellationToken
    ) -> JsonObject:
        """Inspect one knowledge base through the documented API."""

    @abstractmethod
    def delete_knowledge_base(self, dataset_id: str, cancellation: CancellationToken) -> None:
        """Delete one condition knowledge base as the recorded reset."""

    @abstractmethod
    def create_document(
        self, dataset_id: str, name: str, content: str, cancellation: CancellationToken
    ) -> tuple[str, str]:
        """Create one text document and return document and indexing-batch IDs."""

    @abstractmethod
    def wait_for_indexing(
        self, dataset_id: str, batch_id: str, cancellation: CancellationToken
    ) -> None:
        """Perform planned one-second indexing polling until a terminal result."""

    @abstractmethod
    def inspect_segments(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> tuple[JsonObject, ...]:
        """List indexed segments for one document."""

    @abstractmethod
    def retrieve(
        self, dataset_id: str, query: str, cancellation: CancellationToken
    ) -> ExternalRetrievalResult:
        """Perform one semantic top-five test retrieval."""

    @abstractmethod
    def delete_document(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> None:
        """Delete one document through the documented API."""

    @abstractmethod
    def read_health(self, cancellation: CancellationToken) -> JsonObject:
        """Read the target's allowlisted engineering-health endpoint."""
