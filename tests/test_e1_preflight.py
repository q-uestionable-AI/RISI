from collections.abc import Iterator

from risi.adapters.external import (
    ExternalKnowledgeAdapter,
    ExternalRetrievalHit,
    ExternalRetrievalResult,
)
from risi.campaign import run_e2_target_validation
from risi.health import HealthLimits, HealthSample, health_stop_reasons
from risi.statistics import e1_campaign_geometry
from risi.transport import CancellationToken


class ValidationAdapter(ExternalKnowledgeAdapter):
    def __init__(self) -> None:
        self.datasets: dict[str, dict[str, str]] = {}
        self.next_dataset = 0

    def list_knowledge_bases(self, cancellation: CancellationToken) -> tuple[dict, ...]:
        return tuple({"id": dataset_id} for dataset_id in self.datasets)

    def create_knowledge_base(self, name: str, cancellation: CancellationToken) -> str:
        self.next_dataset += 1
        dataset_id = f"dataset-{self.next_dataset:04d}"
        self.datasets[dataset_id] = {}
        return dataset_id

    def inspect_knowledge_base(self, dataset_id: str, cancellation: CancellationToken) -> dict:
        return {"id": dataset_id, "document_count": len(self.datasets[dataset_id])}

    def delete_knowledge_base(self, dataset_id: str, cancellation: CancellationToken) -> None:
        del self.datasets[dataset_id]

    def create_document(
        self, dataset_id: str, name: str, content: str, cancellation: CancellationToken
    ) -> tuple[str, str]:
        document_id = f"{dataset_id}-document-{len(self.datasets[dataset_id]) + 1:03d}"
        self.datasets[dataset_id][document_id] = content
        return document_id, f"batch-{document_id}"

    def wait_for_indexing(
        self, dataset_id: str, batch_id: str, cancellation: CancellationToken
    ) -> None:
        return None

    def inspect_segments(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> tuple[dict, ...]:
        return (
            {
                "id": f"segment-{document_id}",
                "document_id": document_id,
                "content": self.datasets[dataset_id][document_id],
                "enabled": True,
            },
        )

    def retrieve(
        self, dataset_id: str, query: str, cancellation: CancellationToken
    ) -> ExternalRetrievalResult:
        hits = tuple(
            ExternalRetrievalHit(f"segment-{document_id}", document_id, rank, 1.0 / rank, content)
            for rank, (document_id, content) in enumerate(
                list(self.datasets[dataset_id].items())[:5], start=1
            )
        )
        return ExternalRetrievalResult(hits)

    def delete_document(
        self, dataset_id: str, document_id: str, cancellation: CancellationToken
    ) -> None:
        del self.datasets[dataset_id][document_id]

    def read_health(self, cancellation: CancellationToken) -> dict:
        return {"status": "healthy"}


def test_e1_preflight_geometry_and_healthy_sample_pass() -> None:
    geometry = e1_campaign_geometry()
    sample = HealthSample(
        sample_sequence=0,
        services=dict.fromkeys(
            ("api", "worker", "db", "redis", "plugin", "weaviate", "ollama", "nginx"),
            "healthy",
        ),
        cpu_percent=12.5,
        memory_bytes=8_000_000_000,
        storage_bytes=20_000_000_000,
        restart_count=0,
        oom_kill_count=0,
        firewall_denied_count=7,
    )
    limits = HealthLimits(90.0, 32_000_000_000, 256_000_000_000)

    assert geometry.total_observations == 7_260
    assert health_stop_reasons(sample, limits) == ()


def test_health_stop_reasons_are_closed_and_deterministic() -> None:
    sample = HealthSample(
        1,
        {"api": "unhealthy"},
        95.0,
        33,
        257,
        1,
        1,
        0,
    )

    assert health_stop_reasons(sample, HealthLimits(90.0, 32, 256)) == (
        "cpu_ceiling_exceeded",
        "memory_ceiling_exceeded",
        "storage_ceiling_exceeded",
        "service_restart_observed",
        "oom_kill_observed",
        "service_unhealthy:api",
    )


def test_outcome_free_target_validation_matches_full_request_geometry() -> None:
    adapter = ValidationAdapter()
    ticks: Iterator[float] = iter((0.0, 1.0, 11.0, 12.0))

    checks = run_e2_target_validation(adapter, monotonic=lambda: next(ticks))

    assert checks["validation_passed"] is True
    assert checks["targeted_outcomes_evaluated"] is False
    assert checks["dry_run_scenarios"] == 10
    assert checks["dry_run_documents"] == 560
    assert checks["dry_run_retrievals"] == 220
    assert checks["projected_e1_seconds"] == 330.0
    assert not adapter.datasets
