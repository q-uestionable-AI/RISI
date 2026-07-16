"""Guarded application service for deterministic RISI reference runs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from risi.adapters.reference import ReferenceMemoryAdapter
from risi.artifacts import (
    BundleVerification,
    create_evidence_bundle,
    json_bytes,
    json_lines_bytes,
)
from risi.canonical import JsonValue
from risi.decision import DecisionRequest, DeterministicApprovalProvider
from risi.evaluator import DecisionAssessment, evaluate_decision
from risi.models import (
    EpisodeIdentity,
    EventType,
    EventVisibility,
    PolicyConfiguration,
    PolicyIdentity,
    RetrievalQuery,
    RetrievalResult,
    StateSnapshot,
    TraceEvent,
)
from risi.operator.models import ApprovalRecord, CommandResult, ResultStatus, RunManifest
from risi.operator.safety import (
    LOCAL_REFERENCE_POLICY,
    AuthorizationDecision,
    authorize_run,
    resolve_artifact_root,
    resolve_existing_path,
)
from risi.scenarios import SyntheticScenario, load_scenario
from risi.trace import event_to_json, state_snapshot_hash, verify_trace


class SafetyBlockedError(PermissionError):
    """Raised when the safety kernel denies an execution request.

    Args:
        decision: Complete model-independent authorization decision.
    """

    def __init__(self, decision: AuthorizationDecision) -> None:
        super().__init__("run blocked by the safety kernel")
        self.decision = decision


@dataclass(frozen=True, slots=True)
class ValidatedRun:
    """Contain an authorized manifest and its validated synthetic scenario.

    Attributes:
        manifest: Exact authorized run contract.
        approval: Hash-bound approval evidence.
        authorization: Safety-kernel decision.
        scenario_path: Contained, resolved scenario path.
        scenario: Parsed target/evaluator scenario state.
    """

    manifest: RunManifest
    approval: ApprovalRecord
    authorization: AuthorizationDecision
    scenario_path: Path
    scenario: SyntheticScenario

    def to_json(self) -> dict[str, JsonValue]:
        """Return the machine-readable validation summary."""
        return {
            "manifest_sha256": self.manifest.digest,
            "scenario_id": self.scenario.scenario_id,
            "scenario_path": self.manifest.scenario_path,
            "seed": self.manifest.seed,
            "approval": {
                "approved_by": self.approval.approved_by,
                "manifest_sha256": self.approval.manifest_sha256,
            },
            "authorization": self.authorization.to_json(),
        }


@dataclass(frozen=True, slots=True)
class RunExecution:
    """Describe a completed reference run and its evidence anchor.

    Attributes:
        result: Stable operator-facing command result.
        bundle_path: Completed evidence-bundle directory.
        verification: Bundle integrity summary.
    """

    result: CommandResult
    bundle_path: Path
    verification: BundleVerification


@dataclass(frozen=True, slots=True)
class _EvidenceMaterial:
    validated: ValidatedRun
    initial_state: StateSnapshot
    final_state: StateSnapshot
    query: RetrievalQuery
    retrieval: RetrievalResult
    context: str
    decision: dict[str, JsonValue]
    assessment: DecisionAssessment
    events: tuple[TraceEvent, ...]


def capabilities_result() -> CommandResult:
    """Return implemented profiles and hard safety boundaries."""
    profiles: list[JsonValue] = [LOCAL_REFERENCE_POLICY.to_json()]
    future_profiles: list[JsonValue] = [
        {
            "profile": "authorized-local-inference",
            "status": "not-implemented",
            "note": "Reserved for an exact allowlisted local or lab endpoint.",
        }
    ]
    return CommandResult(
        command="capabilities",
        status=ResultStatus.OK,
        data={"profiles": profiles, "future_profiles": future_profiles},
    )


def validate_run(
    manifest: RunManifest,
    approval: ApprovalRecord | None,
    scenario_root: Path,
) -> ValidatedRun:
    """Authorize and validate a run without executing or writing artifacts.

    Args:
        manifest: Requested run contract.
        approval: Hash-bound approval evidence.
        scenario_root: Operator-selected trusted scenario root.

    Returns:
        Authorized and semantically validated run.

    Raises:
        SafetyBlockedError: If the safety kernel denies the request.
        ValueError: If paths or scenario semantics are invalid.
    """
    authorization = authorize_run(manifest, approval)
    if not authorization.allowed:
        raise SafetyBlockedError(authorization)
    if approval is None:
        raise AssertionError("allowed authorization must include approval evidence")
    scenario_path = resolve_existing_path(scenario_root, manifest.scenario_path)
    scenario = load_scenario(
        scenario_path,
        run_id=manifest.run_id,
        seed=manifest.seed,
        max_input_bytes=manifest.limits.input_bytes,
        max_memory_records=manifest.limits.memory_records,
        expected_sha256=manifest.scenario_sha256,
    )
    if scenario.protocol.top_k > manifest.limits.retrieval_calls:
        raise ValueError("scenario top_k exceeds the approved retrieval_calls limit")
    return ValidatedRun(manifest, approval, authorization, scenario_path, scenario)


def run_guarded(
    manifest: RunManifest,
    approval: ApprovalRecord | None,
    scenario_root: Path,
    artifact_root: Path,
) -> RunExecution:
    """Authorize, validate, and execute through one state-changing service entry point.

    Args:
        manifest: Requested run contract.
        approval: Hash-bound approval evidence.
        scenario_root: Operator-selected trusted scenario root.
        artifact_root: Operator-selected artifact directory.

    Returns:
        Completed run result and evidence-bundle integrity anchor.
    """
    validated = validate_run(manifest, approval, scenario_root)
    return _execute_run(validated, artifact_root)


def _execute_run(validated: ValidatedRun, artifact_root: Path) -> RunExecution:
    """Execute one prevalidated pure-read episode and atomically persist its evidence.

    Args:
        validated: Result produced by :func:`validate_run`.
        artifact_root: Operator-selected artifact directory outside the manifest.

    Returns:
        Completed run result and evidence-bundle integrity anchor.
    """
    manifest = validated.manifest
    scenario = validated.scenario
    resolved_artifact_root = resolve_artifact_root(artifact_root)
    episode = EpisodeIdentity(
        scenario_id=scenario.scenario_id,
        episode_id=scenario.evaluator.episode_id,
        seed=manifest.seed,
    )
    memory_ids: list[JsonValue] = [memory.memory_id for memory in scenario.memories]
    memory_ids.sort()
    initial_state = StateSnapshot(
        snapshot_version=1,
        episode=episode,
        logical_time=scenario.logical_time,
        next_event_sequence=0,
        source_memories=scenario.memories,
        derived_state={},
        indexes={"memory_ids": memory_ids},
        queues={"maintenance": []},
        policy=PolicyConfiguration(
            PolicyIdentity("pure-read", "1"),
            {"top_k": scenario.protocol.top_k, "read_side_updates": False},
        ),
        policy_state={},
    )
    adapter = ReferenceMemoryAdapter(initial_state)
    adapter.record_event(
        EventType.EPISODE_STARTED,
        EventVisibility.EVALUATOR,
        {"manifest_sha256": manifest.digest, "profile": manifest.profile.value},
    )
    query = RetrievalQuery(
        principal_id=scenario.protocol.principal_id,
        tenant_id=scenario.protocol.tenant_id,
        text=scenario.protocol.query,
        top_k=scenario.protocol.top_k,
    )
    retrieval = adapter.retrieve(query)
    context = adapter.assemble_context(retrieval)
    provider = DeterministicApprovalProvider()
    if provider.provider_id != manifest.decision_provider:
        raise ValueError("registered decision provider does not match the manifest")
    decision = provider.propose(
        DecisionRequest(
            episode=episode,
            context=context,
            retrieval=retrieval,
            facts=scenario.facts,
            protocol=scenario.protocol,
        )
    )
    adapter.record_event(
        EventType.DECISION,
        EventVisibility.BOTH,
        {"decision": decision.to_json()},
    )
    assessment = evaluate_decision(decision, scenario.evaluator.decision_oracle)
    adapter.record_event(
        EventType.ORACLE_EVALUATED,
        EventVisibility.EVALUATOR,
        {"assessment": assessment.to_json()},
    )
    adapter.record_event(
        EventType.EPISODE_COMPLETED,
        EventVisibility.EVALUATOR,
        {"safe": assessment.safe, "reason_code": assessment.reason_code},
    )
    final_state = adapter.inspect_state()
    events = adapter.export_trace()
    verify_trace(events)
    files = _evidence_files(
        _EvidenceMaterial(
            validated=validated,
            initial_state=initial_state,
            final_state=final_state,
            query=query,
            retrieval=retrieval,
            context=context,
            decision=decision.to_json(),
            assessment=assessment,
            events=events,
        )
    )
    verification = create_evidence_bundle(
        resolved_artifact_root,
        manifest.run_id,
        files,
        max_bytes=manifest.limits.artifact_bytes,
    )
    bundle_path = resolved_artifact_root / manifest.run_id
    result = CommandResult(
        command="run",
        status=ResultStatus.OK,
        run_id=manifest.run_id,
        data={
            "scenario_id": scenario.scenario_id,
            "episode_id": episode.episode_id,
            "safe": assessment.safe,
            "reason_code": assessment.reason_code,
            "bundle_path": str(bundle_path),
            "inventory_sha256": verification.inventory_sha256,
            "bundle_hash": verification.bundle_hash,
            "event_count": len(events),
        },
    )
    return RunExecution(result, bundle_path, verification)


def _evidence_files(material: _EvidenceMaterial) -> dict[str, bytes]:
    manifest = material.validated.manifest
    execution: dict[str, JsonValue] = {
        "schema_version": 1,
        "run_id": manifest.run_id,
        "manifest_sha256": manifest.digest,
        "episode_id": material.validated.scenario.evaluator.episode_id,
        "status": "succeeded",
        "safe": material.assessment.safe,
        "reason_code": material.assessment.reason_code,
        "initial_state_hash": state_snapshot_hash(material.initial_state),
        "final_state_hash": state_snapshot_hash(material.final_state),
        "event_count": len(material.events),
    }
    report = _render_report(execution, material.retrieval, material.decision, material.assessment)
    return {
        "manifest.json": json_bytes(manifest.to_json()),
        "approval.json": json_bytes(material.validated.approval.to_json()),
        "target-scenario.json": json_bytes(material.validated.scenario.target_view()),
        "evaluator/evaluator-state.json": json_bytes(material.validated.scenario.evaluator_view()),
        "initial-state.json": json_bytes(material.initial_state.to_json()),
        "final-state.json": json_bytes(material.final_state.to_json()),
        "events.jsonl": json_lines_bytes(tuple(event_to_json(event) for event in material.events)),
        "retrieval.json": json_bytes(
            {"query": material.query.to_json(), "result": material.retrieval.to_json()}
        ),
        "context.json": json_bytes({"context": material.context}),
        "decision.json": json_bytes(material.decision),
        "evaluator/assessment.json": json_bytes(material.assessment.to_json()),
        "execution.json": json_bytes(execution),
        "report.md": report.encode(),
    }


def _render_report(
    execution: dict[str, JsonValue],
    retrieval: RetrievalResult,
    decision: dict[str, JsonValue],
    assessment: DecisionAssessment,
) -> str:
    retrieved = ", ".join(hit.memory_id for hit in retrieval.hits) or "none"
    outcome = "safe" if assessment.safe else "unsafe"
    return (
        "# RISI reference-run report\n\n"
        f"- Run: `{execution['run_id']}`\n"
        f"- Episode: `{execution['episode_id']}`\n"
        f"- Outcome: **{outcome}** (`{assessment.reason_code}`)\n"
        f"- Retrieved memories: {retrieved}\n"
        f"- Proposed action: `{decision['action']}`\n"
        f"- Events: {execution['event_count']}\n"
        f"- Initial state: `{execution['initial_state_hash']}`\n"
        f"- Final state: `{execution['final_state_hash']}`\n\n"
        "This report describes a synthetic proposal only. No external action was executed.\n"
    )
