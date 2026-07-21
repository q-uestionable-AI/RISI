import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from risi.adapters.dify import DIFY_API_PATHS, DifyKnowledgeAdapter
from risi.adapters.external import ExternalTargetManifest, TargetCredential
from risi.operator.models import ExecutionProfile
from risi.transport import CancellationToken, TransportError, TransportResponse

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dify"


class FakeTransport:
    def __init__(self, responses: list[dict]) -> None:
        self.responses: Iterator[dict] = iter(responses)
        self.calls: list[dict] = []
        self.request_count = 0

    def request_json(self, method: str, path: str, **kwargs: object) -> TransportResponse:
        self.request_count += 1
        self.calls.append({"method": method, "path": path, **kwargs})
        response = next(self.responses)
        return TransportResponse(200, response)

    def request_empty(self, method: str, path: str, **kwargs: object) -> int:
        self.request_count += 1
        self.calls.append({"method": method, "path": path, **kwargs})
        response = next(self.responses)
        assert response == {"status": 204, "body": b""}
        return 204


def _fixture(name: str) -> dict:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def _target() -> ExternalTargetManifest:
    return ExternalTargetManifest(
        1,
        "risi-dify-e1",
        ExecutionProfile.ISOLATED_DIFY_KNOWLEDGE,
        "https://risi-dify-e1",
        "risi-dify-e1",
        "b" * 64,
        "ca.pem",
        "c" * 64,
        "d" * 64,
        DIFY_API_PATHS,
        {
            "dify_version": "1.15.0",
            "ollama_model": "nomic-embed-text:v1.5",
            "provider": "langgenius/ollama:1.0.0",
            "embedding_model_provider": "ollama",
        },
    )


def _adapter(responses: list[dict]) -> tuple[DifyKnowledgeAdapter, FakeTransport]:
    transport = FakeTransport(responses)
    adapter = DifyKnowledgeAdapter(
        _target(),
        TargetCredential("risi-dify-e1", "synthetic-key", "synthetic-health-token"),
        transport=transport,
    )
    return adapter, transport


def test_create_document_freezes_one_chunk_processing_contract() -> None:
    adapter, transport = _adapter([{"document": {"id": "document-0001"}, "batch": "batch-0001"}])

    document_id, batch_id = adapter.create_document(
        "dataset-0001", "memory-0001", "Synthetic obligation.", CancellationToken()
    )

    assert (document_id, batch_id) == ("document-0001", "batch-0001")
    body = transport.calls[0]["body"]
    segmentation = body["process_rule"]["rules"]["segmentation"]
    assert segmentation == {"separator": "␞", "max_tokens": 512, "chunk_overlap": 0}
    assert all(
        not rule["enabled"] for rule in body["process_rule"]["rules"]["pre_processing_rules"]
    )


def test_create_knowledge_base_binds_model_provider_and_retrieval_contract() -> None:
    adapter, transport = _adapter([{"id": "dataset-0001"}])

    assert adapter.create_knowledge_base("synthetic-memory", CancellationToken()) == "dataset-0001"

    body = transport.calls[0]["body"]
    assert body["embedding_model"] == "nomic-embed-text:v1.5"
    assert body["embedding_model_provider"] == "ollama"
    assert body["retrieval_model"]["search_method"] == "semantic_search"
    assert body["retrieval_model"]["top_k"] == 5
    assert body["retrieval_model"]["reranking_enable"] is False
    assert body["retrieval_model"]["score_threshold_enabled"] is False


def test_adapter_rejects_substituted_model_or_provider_identity() -> None:
    manifest = _target()
    for changed_identity in (
        {"ollama_model": "another-model"},
        {"provider": "another/provider:1.0.0"},
        {"embedding_model_provider": "another-provider"},
    ):
        identities = dict(manifest.identities)
        identities.update(changed_identity)
        changed_manifest = ExternalTargetManifest(
            manifest.schema_version,
            manifest.target_id,
            manifest.profile,
            manifest.base_url,
            manifest.server_name,
            manifest.certificate_sha256,
            manifest.ca_certificate_path,
            manifest.api_key_sha256,
            manifest.health_token_sha256,
            manifest.api_paths,
            identities,
        )

        with pytest.raises(ValueError, match="target manifest does not identify frozen"):
            DifyKnowledgeAdapter(
                changed_manifest,
                TargetCredential("risi-dify-e1", "synthetic-key", "synthetic-health-token"),
                transport=FakeTransport([]),
            )


def test_indexing_completion_and_semantic_top_five_retrieval() -> None:
    adapter, transport = _adapter(
        [_fixture("indexing-completed.json"), _fixture("retrieval-success.json")]
    )
    token = CancellationToken()

    adapter.wait_for_indexing("dataset-0001", "batch-0001", token)
    result = adapter.retrieve("dataset-0001", "What obligation applies?", token)

    assert result.hits[0].segment_id == "segment-0001"
    body = transport.calls[1]["body"]["retrieval_model"]
    assert body["search_method"] == "semantic_search"
    assert body["top_k"] == 5
    assert body["reranking_enable"] is False
    assert body["score_threshold_enabled"] is False
    assert transport.request_count == 2


def test_segment_inventory_requires_exactly_one_enabled_chunk() -> None:
    adapter, _ = _adapter(
        [
            {
                "data": [
                    {"id": "one", "enabled": True},
                    {"id": "two", "enabled": True},
                ],
                "has_more": False,
                "total": 2,
            }
        ]
    )

    with pytest.raises(TransportError) as error:
        adapter.inspect_segments("dataset-0001", "document-0001", CancellationToken())

    assert error.value.code == "chunk_contract_failed"


def test_malformed_retrieval_is_not_retried() -> None:
    adapter, transport = _adapter([{"records": [{"segment": {}, "score": 0.5}]}])

    with pytest.raises(TransportError) as error:
        adapter.retrieve("dataset-0001", "query", CancellationToken())

    assert error.value.code == "malformed_response"
    assert transport.request_count == 1


def test_health_uses_separate_health_token() -> None:
    adapter, transport = _adapter([{"status": "healthy"}])

    assert adapter.read_health(CancellationToken()) == {"status": "healthy"}
    assert transport.calls[0]["api_key"] == "synthetic-health-token"


def test_owner_inventory_is_complete_and_bounded() -> None:
    adapter, transport = _adapter(
        [{"data": [{"id": "dataset-0001"}], "has_more": False, "total": 1}]
    )

    datasets = adapter.list_knowledge_bases(CancellationToken())

    assert datasets == ({"id": "dataset-0001"},)
    assert transport.calls[0]["query"] == {"page": 1, "limit": 100}


def test_delete_operations_require_empty_204_contract() -> None:
    adapter, transport = _adapter([{"status": 204, "body": b""}, {"status": 204, "body": b""}])
    token = CancellationToken()

    adapter.delete_document("dataset-0001", "document-0001", token)
    adapter.delete_knowledge_base("dataset-0001", token)

    assert [call["expected_status"] for call in transport.calls] == [204, 204]
