"""Dify 1.15 Knowledge API adapter for the isolated E1 target."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, cast

from risi.adapters.external import (
    ExternalKnowledgeAdapter,
    ExternalRetrievalHit,
    ExternalRetrievalResult,
    ExternalTargetManifest,
    TargetCredential,
)
from risi.canonical import JsonObject, freeze_json_object
from risi.transport import AllowedRoute, CancellationToken, HttpsTransport, TransportError

DIFY_API_PATHS = {
    "datasets": "/v1/datasets",
    "dataset": "/v1/datasets/{dataset_id}",
    "create_document_by_text": "/v1/datasets/{dataset_id}/document/create-by-text",
    "indexing_status": "/v1/datasets/{dataset_id}/documents/{batch_id}/indexing-status",
    "documents": "/v1/datasets/{dataset_id}/documents",
    "document": "/v1/datasets/{dataset_id}/documents/{document_id}",
    "segments": "/v1/datasets/{dataset_id}/documents/{document_id}/segments",
    "retrieve": "/v1/datasets/{dataset_id}/retrieve",
    "health": "/healthz",
}

DIFY_ROUTES = (
    AllowedRoute("GET", DIFY_API_PATHS["datasets"]),
    AllowedRoute("POST", DIFY_API_PATHS["datasets"]),
    AllowedRoute("GET", DIFY_API_PATHS["dataset"]),
    AllowedRoute("DELETE", DIFY_API_PATHS["dataset"]),
    AllowedRoute("POST", DIFY_API_PATHS["create_document_by_text"]),
    AllowedRoute("GET", DIFY_API_PATHS["indexing_status"]),
    AllowedRoute("GET", DIFY_API_PATHS["documents"]),
    AllowedRoute("GET", DIFY_API_PATHS["document"]),
    AllowedRoute("DELETE", DIFY_API_PATHS["document"]),
    AllowedRoute("GET", DIFY_API_PATHS["segments"]),
    AllowedRoute("POST", DIFY_API_PATHS["retrieve"]),
    AllowedRoute("GET", DIFY_API_PATHS["health"]),
)

DIFY_IDENTITY = {
    "dify_version": "1.15.0",
    "ollama_model": "nomic-embed-text:v1.5",
    "provider": "langgenius/ollama:1.0.0",
    "embedding_model_provider": "ollama",
}


def _string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise TransportError("malformed_response", f"target response field {field_name} is invalid")
    return value


def _object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TransportError("malformed_response", f"target response field {field_name} is invalid")
    return cast(dict[str, Any], value)


def _array(value: object, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise TransportError("malformed_response", f"target response field {field_name} is invalid")
    return cast(list[Any], value)


def _retrieval_model() -> JsonObject:
    """Return the fixed Dify semantic-retrieval contract."""
    return {
        "search_method": "semantic_search",
        "reranking_enable": False,
        "reranking_mode": None,
        "reranking_model": {"reranking_provider_name": "", "reranking_model_name": ""},
        "weights": None,
        "top_k": 5,
        "score_threshold_enabled": False,
        "score_threshold": None,
    }


class DifyKnowledgeAdapter(ExternalKnowledgeAdapter):
    """Use only the frozen Dify 1.15 Knowledge API surface."""

    def __init__(
        self,
        manifest: ExternalTargetManifest,
        credential: TargetCredential,
        *,
        transport: HttpsTransport | None = None,
    ) -> None:
        """Create an adapter bound to exact target and credential manifests."""
        if credential.target_id != manifest.target_id:
            raise ValueError("credential target does not match target manifest")
        if dict(manifest.api_paths) != DIFY_API_PATHS:
            raise ValueError("target manifest does not contain the frozen Dify API paths")
        identities = dict(manifest.identities)
        for name, expected in DIFY_IDENTITY.items():
            if identities.get(name) != expected:
                raise ValueError(f"target manifest does not identify frozen {name}")
        self._embedding_model = DIFY_IDENTITY["ollama_model"]
        self._embedding_model_provider = DIFY_IDENTITY["embedding_model_provider"]
        self._manifest = manifest
        self._credential = credential
        self._transport = transport or HttpsTransport(
            manifest.base_url,
            manifest.certificate_sha256,
            Path(manifest.ca_certificate_path),
            DIFY_ROUTES,
            timeout_seconds=manifest.request_timeout_seconds,
        )

    @property
    def request_count(self) -> int:
        """Return the number of requests dispatched without retries."""
        return self._transport.request_count

    def _path(self, name: str, **identifiers: str) -> str:
        try:
            return DIFY_API_PATHS[name].format(**identifiers)
        except KeyError as exc:
            raise ValueError("unknown Dify API path") from exc

    def _request(
        self,
        method: str,
        path: str,
        cancellation: CancellationToken,
        *,
        body: JsonObject | None = None,
        query: dict[str, str | int] | None = None,
    ) -> JsonObject:
        return self._transport.request_json(
            method,
            path,
            api_key=self._credential.api_key,
            body=body,
            query=query,
            cancellation=cancellation,
        ).body

    def _request_empty(
        self, method: str, path: str, cancellation: CancellationToken, *, expected_status: int
    ) -> None:
        self._transport.request_empty(
            method,
            path,
            api_key=self._credential.api_key,
            expected_status=expected_status,
            cancellation=cancellation,
        )

    def list_knowledge_bases(self, cancellation: CancellationToken) -> tuple[JsonObject, ...]:
        """List a complete owner-visible inventory up to the fixed isolation ceiling."""
        response = self._request(
            "GET", self._path("datasets"), cancellation, query={"page": 1, "limit": 100}
        )
        datasets = tuple(
            freeze_json_object(_object(item, "data[]"))
            for item in _array(response.get("data"), "data")
        )
        if response.get("has_more") is not False or response.get("total") != len(datasets):
            raise TransportError(
                "inventory_ceiling_exceeded",
                "owner-visible knowledge-base inventory exceeds the closed listing ceiling",
            )
        return datasets

    def create_knowledge_base(self, name: str, cancellation: CancellationToken) -> str:
        """Create one high-quality semantic-vector knowledge base."""
        if not name.strip():
            raise ValueError("knowledge-base name must not be empty")
        response = self._request(
            "POST",
            self._path("datasets"),
            cancellation,
            body={
                "name": name,
                "description": "RISI E1 synthetic condition memory",
                "indexing_technique": "high_quality",
                "permission": "only_me",
                "provider": "vendor",
                "embedding_model": self._embedding_model,
                "embedding_model_provider": self._embedding_model_provider,
                "retrieval_model": _retrieval_model(),
            },
        )
        return _string(response.get("id"), "id")

    def inspect_knowledge_base(
        self, dataset_id: str, cancellation: CancellationToken
    ) -> JsonObject:
        """Inspect one knowledge base."""
        return self._request("GET", self._path("dataset", dataset_id=dataset_id), cancellation)

    def delete_knowledge_base(self, dataset_id: str, cancellation: CancellationToken) -> None:
        """Delete one knowledge base as a reset."""
        self._request_empty(
            "DELETE",
            self._path("dataset", dataset_id=dataset_id),
            cancellation,
            expected_status=204,
        )

    def create_document(
        self, dataset_id: str, name: str, content: str, cancellation: CancellationToken
    ) -> tuple[str, str]:
        """Create one text document with exactly one custom-separated chunk."""
        if not name.strip() or not content.strip() or "␞" in content:
            raise ValueError("document name/content is empty or contains the reserved separator")
        response = self._request(
            "POST",
            self._path("create_document_by_text", dataset_id=dataset_id),
            cancellation,
            body={
                "name": name,
                "text": content,
                "indexing_technique": "high_quality",
                "doc_form": "text_model",
                "doc_language": "English",
                "process_rule": {
                    "mode": "custom",
                    "rules": {
                        "pre_processing_rules": [
                            {"id": "remove_extra_spaces", "enabled": False},
                            {"id": "remove_urls_emails", "enabled": False},
                        ],
                        "segmentation": {
                            "separator": "␞",
                            "max_tokens": 512,
                            "chunk_overlap": 0,
                        },
                    },
                },
            },
        )
        document = _object(response.get("document"), "document")
        return _string(document.get("id"), "document.id"), _string(response.get("batch"), "batch")

    def wait_for_indexing(
        self, dataset_id: str, batch_id: str, cancellation: CancellationToken
    ) -> None:
        """Poll at the planned one-second interval for at most 300 seconds."""
        for poll_index in range(self._manifest.indexing_timeout_seconds):
            response = self._request(
                "GET",
                self._path("indexing_status", dataset_id=dataset_id, batch_id=batch_id),
                cancellation,
            )
            entries = _array(response.get("data"), "data")
            if not entries:
                raise TransportError("malformed_response", "indexing status contains no documents")
            statuses = {
                _string(_object(entry, "data[]").get("indexing_status"), "indexing_status")
                for entry in entries
            }
            if statuses == {"completed"}:
                return
            if statuses & {"error", "paused"}:
                raise TransportError(
                    "indexing_failed", "target indexing reached a terminal failure"
                )
            if not statuses <= {"waiting", "parsing", "cleaning", "splitting", "indexing"}:
                raise TransportError(
                    "malformed_response", "target returned an unknown indexing status"
                )
            if poll_index + 1 < self._manifest.indexing_timeout_seconds:
                time.sleep(self._manifest.indexing_poll_seconds)
        raise TransportError("indexing_timeout", "target indexing exceeded 300 seconds")

    def inspect_segments(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> tuple[JsonObject, ...]:
        """List and validate exactly one enabled chunk for a document."""
        response = self._request(
            "GET",
            self._path("segments", dataset_id=dataset_id, document_id=document_id),
            cancellation,
            query={"page": 1, "limit": 100},
        )
        segments = tuple(
            freeze_json_object(_object(item, "data[]"))
            for item in _array(response.get("data"), "data")
        )
        if response.get("has_more") is not False or response.get("total") != len(segments):
            raise TransportError(
                "chunk_contract_failed", "document segment inventory is incomplete or unbounded"
            )
        enabled = tuple(segment for segment in segments if segment.get("enabled") is True)
        if len(segments) != 1 or len(enabled) != 1:
            raise TransportError("chunk_contract_failed", "document must contain one enabled chunk")
        return segments

    def retrieve(
        self, dataset_id: str, query: str, cancellation: CancellationToken
    ) -> ExternalRetrievalResult:
        """Perform fixed semantic-vector top-five retrieval without threshold or reranking."""
        if not query.strip():
            raise ValueError("retrieval query must not be empty")
        response = self._request(
            "POST",
            self._path("retrieve", dataset_id=dataset_id),
            cancellation,
            body={
                "query": query,
                "retrieval_model": _retrieval_model(),
            },
        )
        hits: list[ExternalRetrievalHit] = []
        for rank, raw in enumerate(_array(response.get("records"), "records"), start=1):
            record = _object(raw, "records[]")
            segment = _object(record.get("segment"), "segment")
            score = record.get("score")
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise TransportError("malformed_response", "retrieval score is invalid")
            hits.append(
                ExternalRetrievalHit(
                    segment_id=_string(segment.get("id"), "segment.id"),
                    document_id=_string(segment.get("document_id"), "segment.document_id"),
                    rank=rank,
                    score=float(score),
                    content=_string(segment.get("content"), "segment.content"),
                )
            )
        if len(hits) > 5:
            raise TransportError("retrieval_contract_failed", "target returned more than five hits")
        return ExternalRetrievalResult(tuple(hits))

    def delete_document(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> None:
        """Delete one document as a recorded reset step."""
        self._request_empty(
            "DELETE",
            self._path("document", dataset_id=dataset_id, document_id=document_id),
            cancellation,
            expected_status=204,
        )

    def read_health(self, cancellation: CancellationToken) -> JsonObject:
        """Read the allowlisted health summary."""
        return self._transport.request_json(
            "GET",
            self._path("health"),
            api_key=self._credential.health_token,
            cancellation=cancellation,
        ).body
