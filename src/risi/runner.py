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
from risi.confidentiality import (
    ObserverExchange,
    ObserverView,
    RisiCArm,
    RisiCComparisonAssessment,
    RisiCPair,
    RisiCPairAssessment,
    assess_risi_c_comparison,
    assess_risi_c_pair,
)
from risi.craf import (
    CrafArm,
    CrafAssessment,
    CrafComparisonAssessment,
    CrafTrialEvidence,
    assess_craf_comparison,
    assess_craf_trial,
)
from risi.decision import (
    DecisionProvider,
    DecisionRequest,
    DeterministicApprovalProvider,
    DeterministicObligationProvider,
    DeterministicRegionProvider,
)
from risi.evaluator import DecisionAssessment, MemoryOracle, evaluate_decision
from risi.models import (
    EpisodeIdentity,
    EventType,
    EventVisibility,
    MemoryRecord,
    PolicyConfiguration,
    PolicyIdentity,
    ProposedDecision,
    RetrievalQuery,
    RetrievalResult,
    StateSnapshot,
    TraceEvent,
)
from risi.operator.models import ApprovalRecord, CommandResult, ResultStatus, RunManifest
from risi.operator.safety import (
    CRAF_REFERENCE_POLICY,
    LOCAL_REFERENCE_OBLIGATION_POLICY,
    LOCAL_REFERENCE_POLICY,
    RISI_C_REFERENCE_POLICY,
    AuthorizationDecision,
    authorize_run,
    resolve_artifact_root,
    resolve_existing_path,
)
from risi.scenarios import (
    ObligationDecisionProtocol,
    ReferenceRunProtocol,
    RegionDecisionProtocol,
    SyntheticScenario,
    load_scenario,
)
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


@dataclass(frozen=True, slots=True)
class _CrafArmMaterial:
    arm: CrafArm
    policy: PolicyConfiguration
    final_state: StateSnapshot
    interaction_query: RetrievalQuery
    interaction_retrieval: RetrievalResult
    interaction_context: str
    decision_query: RetrievalQuery
    decision_retrieval: RetrievalResult
    decision_context: str
    decision: ProposedDecision
    decision_assessment: DecisionAssessment
    craf_assessment: CrafAssessment
    events: tuple[TraceEvent, ...]


@dataclass(frozen=True, slots=True)
class _RisiCArmMaterial:
    pair: RisiCPair
    arm: RisiCArm
    policy: PolicyConfiguration
    final_state: StateSnapshot
    victim_query: RetrievalQuery
    victim_retrieval: RetrievalResult
    victim_context: str
    observer_query: RetrievalQuery
    observer_retrieval: RetrievalResult
    observer_view: ObserverView
    decision_query: RetrievalQuery
    decision_retrieval: RetrievalResult
    decision_context: str
    decision: ProposedDecision
    decision_assessment: DecisionAssessment
    events: tuple[TraceEvent, ...]


def capabilities_result() -> CommandResult:
    """Return implemented profiles and hard safety boundaries."""
    profiles: list[JsonValue] = [
        LOCAL_REFERENCE_POLICY.to_json(),
        LOCAL_REFERENCE_OBLIGATION_POLICY.to_json(),
        CRAF_REFERENCE_POLICY.to_json(),
        RISI_C_REFERENCE_POLICY.to_json(),
    ]
    future_profiles: list[JsonValue] = [
        {
            "profile": "authorized-local-inference",
            "status": "not-implemented",
            "note": (
                "Reserved for an exact allowlisted loopback or operator-controlled lab endpoint."
            ),
        },
        {
            "profile": "authorized-remote-inference",
            "status": "not-implemented",
            "note": "Reserved for an exact allowlisted public HTTPS endpoint and model.",
        },
    ]
    return CommandResult(
        command="capabilities",
        status=ResultStatus.OK,
        data={"profiles": profiles, "future_profiles": future_profiles},
    )


def _validate_craf_run_contract(manifest: RunManifest, scenario: SyntheticScenario) -> None:
    if scenario.craf_reference is None:
        raise ValueError("craf-reference policy requires a craf_reference protocol")
    if manifest.limits.episodes < 3:
        raise ValueError("craf-reference requires an episodes limit of at least 3")
    required_retrievals = 3 * (scenario.craf_reference.interaction_count + 1)
    if manifest.limits.retrieval_calls < required_retrievals:
        raise ValueError("craf-reference retrieval_calls limit is too small")
    if scenario.risi_c_reference is not None:
        raise ValueError("craf-reference cannot execute a risi_c_reference protocol")


def _validate_risi_c_run_contract(manifest: RunManifest, scenario: SyntheticScenario) -> None:
    if scenario.risi_c_reference is None or scenario.risi_c_oracle is None:
        raise ValueError("risi-c-reference requires its protocol and evaluator oracle")
    if not isinstance(scenario.protocol, RegionDecisionProtocol):
        raise TypeError("risi-c-reference requires a region decision protocol")
    if scenario.craf_reference is not None:
        raise ValueError("risi-c-reference cannot execute a craf_reference protocol")
    if manifest.limits.episodes < 4:
        raise ValueError("risi-c-reference requires an episodes limit of at least 4")
    if manifest.limits.retrieval_calls < 12:
        raise ValueError("risi-c-reference retrieval_calls limit is too small")


def _validate_pure_read_run_contract(manifest: RunManifest, scenario: SyntheticScenario) -> None:
    if scenario.craf_reference is not None or scenario.risi_c_reference is not None:
        raise ValueError("pure-read policy cannot execute an adaptive reference protocol")
    protocol = scenario.protocol
    if isinstance(protocol, ReferenceRunProtocol):
        expected_provider = DeterministicApprovalProvider().provider_id
    elif isinstance(protocol, ObligationDecisionProtocol):
        expected_provider = DeterministicObligationProvider().provider_id
    else:
        raise TypeError("pure-read policy requires an approval or obligation decision protocol")
    if manifest.decision_provider != expected_provider:
        raise ValueError("pure-read decision provider does not match the scenario protocol")
    if protocol.top_k > manifest.limits.retrieval_calls:
        raise ValueError("scenario top_k exceeds the approved retrieval_calls limit")


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
    if manifest.policy == CRAF_REFERENCE_POLICY.policy:
        _validate_craf_run_contract(manifest, scenario)
    elif manifest.policy == RISI_C_REFERENCE_POLICY.policy:
        _validate_risi_c_run_contract(manifest, scenario)
    else:
        _validate_pure_read_run_contract(manifest, scenario)
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
    if validated.manifest.policy == CRAF_REFERENCE_POLICY.policy:
        return _execute_craf_reference(validated, artifact_root)
    if validated.manifest.policy == RISI_C_REFERENCE_POLICY.policy:
        return _execute_risi_c_reference(validated, artifact_root)
    return _execute_pure_read(validated, artifact_root)


def _execute_pure_read(validated: ValidatedRun, artifact_root: Path) -> RunExecution:
    """Execute the prevalidated pure-read baseline."""
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
    provider: DecisionProvider
    if isinstance(scenario.protocol, ReferenceRunProtocol):
        provider = DeterministicApprovalProvider()
    elif isinstance(scenario.protocol, ObligationDecisionProtocol):
        provider = DeterministicObligationProvider()
    else:
        raise TypeError("validated pure-read run has an unsupported decision protocol")
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


def _execute_craf_reference(validated: ValidatedRun, artifact_root: Path) -> RunExecution:
    """Execute the approved three-arm controlled CRAF reference comparison."""
    manifest = validated.manifest
    scenario = validated.scenario
    interaction = scenario.craf_reference
    if interaction is None:
        raise AssertionError("validated craf-reference run is missing its interaction protocol")
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
    critical_oracle = _critical_oracle(scenario)
    initial_critical = _memory_by_id(initial_state, critical_oracle.memory_id)
    if initial_critical.system_criticality != "protected-recall":
        raise ValueError("craf-reference requires the target-visible protected-recall label")

    adaptive_settings: dict[str, JsonValue] = {
        "top_k": scenario.protocol.top_k,
        "read_side_updates": True,
        "trigger_memory_id": interaction.trigger_memory_id,
        "suppressed_memory_id": scenario.protocol.required_memory_id,
    }
    policies = {
        CrafArm.CONTROL: PolicyConfiguration(
            PolicyIdentity("pure-read", "1"),
            {"top_k": scenario.protocol.top_k, "read_side_updates": False},
        ),
        CrafArm.VULNERABLE: PolicyConfiguration(
            PolicyIdentity("memory-eclipsing", "1"),
            adaptive_settings,
        ),
        CrafArm.PROTECTED: PolicyConfiguration(
            PolicyIdentity("protected-critical-recall", "1"),
            {**adaptive_settings, "protected_criticality": "protected-recall"},
        ),
    }
    arms = tuple(
        _execute_craf_arm(
            validated,
            initial_state,
            arm,
            policies[arm],
            critical_oracle,
            initial_critical,
        )
        for arm in CrafArm
    )
    comparison = assess_craf_comparison(
        scenario.scenario_id,
        state_snapshot_hash(initial_state),
        tuple(arm.craf_assessment for arm in arms),
    )
    files, execution = _craf_evidence_files(validated, initial_state, arms, comparison)
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
            "comparison_result": comparison.result.value,
            "bundle_path": str(bundle_path),
            "inventory_sha256": verification.inventory_sha256,
            "bundle_hash": verification.bundle_hash,
            "event_count": execution["event_count"],
            "arms": execution["arms"],
        },
    )
    return RunExecution(result, bundle_path, verification)


def _execute_craf_arm(
    validated: ValidatedRun,
    initial_state: StateSnapshot,
    arm: CrafArm,
    policy: PolicyConfiguration,
    critical_oracle: MemoryOracle,
    initial_critical: MemoryRecord,
) -> _CrafArmMaterial:
    scenario = validated.scenario
    interaction = scenario.craf_reference
    if interaction is None:
        raise AssertionError("craf-reference interaction is required")
    adapter = ReferenceMemoryAdapter(initial_state)
    adapter.record_event(
        EventType.EPISODE_STARTED,
        EventVisibility.EVALUATOR,
        {
            "arm": arm.value,
            "manifest_sha256": validated.manifest.digest,
            "profile": validated.manifest.profile.value,
        },
    )
    adapter.configure_policy(policy)
    interaction_query = RetrievalQuery(
        principal_id=interaction.principal_id,
        tenant_id=interaction.tenant_id,
        text=interaction.query,
        top_k=interaction.top_k,
    )
    interaction_retrieval = adapter.retrieve(interaction_query)
    interaction_context = adapter.assemble_context(interaction_retrieval)
    if tuple(hit.memory_id for hit in interaction_retrieval.hits) != (
        interaction.trigger_memory_id,
    ):
        raise ValueError("craf-reference interaction did not isolate its truthful trigger")

    decision_query = RetrievalQuery(
        principal_id=scenario.protocol.principal_id,
        tenant_id=scenario.protocol.tenant_id,
        text=scenario.protocol.query,
        top_k=scenario.protocol.top_k,
    )
    decision_retrieval = adapter.retrieve(decision_query)
    decision_context = adapter.assemble_context(decision_retrieval)
    provider = DeterministicApprovalProvider()
    if provider.provider_id != validated.manifest.decision_provider:
        raise ValueError("registered decision provider does not match the manifest")
    decision = provider.propose(
        DecisionRequest(
            episode=initial_state.episode,
            context=decision_context,
            retrieval=decision_retrieval,
            facts=scenario.facts,
            protocol=scenario.protocol,
        )
    )
    adapter.record_event(
        EventType.DECISION,
        EventVisibility.BOTH,
        {"decision": decision.to_json()},
    )
    decision_assessment = evaluate_decision(decision, scenario.evaluator.decision_oracle)
    final_critical = _optional_memory_by_id(adapter.inspect_state(), critical_oracle.memory_id)
    craf_assessment = assess_craf_trial(
        CrafTrialEvidence(
            arm=arm,
            initial_memory=initial_critical,
            final_memory=final_critical,
            oracle=critical_oracle,
            logical_time=adapter.inspect_state().logical_time,
            oracle_applicable=_critical_oracle_applicable(scenario, critical_oracle),
            retrieval_memory_ids=tuple(hit.memory_id for hit in decision_retrieval.hits),
            context_memory_ids=tuple(hit.memory_id for hit in decision_retrieval.hits),
            decision=decision,
            decision_assessment=decision_assessment,
        )
    )
    if craf_assessment.classification.value == "core_craf":
        adapter.record_event(
            EventType.CRITICAL_MEMORY_SUPPRESSION,
            EventVisibility.EVALUATOR,
            {
                "assessment": craf_assessment.to_json(),
                "arm": arm.value,
            },
        )
    adapter.record_event(
        EventType.ORACLE_EVALUATED,
        EventVisibility.EVALUATOR,
        {
            "decision_assessment": decision_assessment.to_json(),
            "craf_assessment": craf_assessment.to_json(),
        },
    )
    adapter.record_event(
        EventType.EPISODE_COMPLETED,
        EventVisibility.EVALUATOR,
        {
            "arm": arm.value,
            "classification": craf_assessment.classification.value,
            "safe": decision_assessment.safe,
        },
    )
    final_state = adapter.inspect_state()
    events = adapter.export_trace()
    verify_trace(events)
    return _CrafArmMaterial(
        arm=arm,
        policy=policy,
        final_state=final_state,
        interaction_query=interaction_query,
        interaction_retrieval=interaction_retrieval,
        interaction_context=interaction_context,
        decision_query=decision_query,
        decision_retrieval=decision_retrieval,
        decision_context=decision_context,
        decision=decision,
        decision_assessment=decision_assessment,
        craf_assessment=craf_assessment,
        events=events,
    )


def _execute_risi_c_reference(validated: ValidatedRun, artifact_root: Path) -> RunExecution:
    """Execute the approved four-arm DEP-02 RISI-C reference comparison."""
    manifest = validated.manifest
    scenario = validated.scenario
    protocol = scenario.risi_c_reference
    oracle = scenario.risi_c_oracle
    if protocol is None or oracle is None:
        raise AssertionError("validated risi-c-reference run is missing its contracts")
    if not isinstance(scenario.protocol, RegionDecisionProtocol):
        raise TypeError("validated risi-c-reference run is missing its region protocol")
    resolved_artifact_root = resolve_artifact_root(artifact_root)
    episode = EpisodeIdentity(
        scenario_id=scenario.scenario_id,
        episode_id=scenario.evaluator.episode_id,
        seed=manifest.seed,
    )
    memory_ids: list[JsonValue] = [memory.memory_id for memory in scenario.memories]
    memory_ids.sort()
    top_k = max(scenario.protocol.top_k, protocol.event_top_k, protocol.observer_top_k)
    initial_state = StateSnapshot(
        snapshot_version=1,
        episode=episode,
        logical_time=scenario.logical_time,
        next_event_sequence=0,
        source_memories=scenario.memories,
        derived_state={"shared_access_counter": 0},
        indexes={"memory_ids": memory_ids},
        queues={"maintenance": []},
        policy=PolicyConfiguration(
            PolicyIdentity("pure-read", "1"),
            {"top_k": top_k, "read_side_updates": False},
        ),
        policy_state={},
    )
    critical_oracle = _critical_oracle(scenario)
    critical_memory = _memory_by_id(initial_state, critical_oracle.memory_id)
    if critical_memory.system_criticality != "protected-recall":
        raise ValueError("risi-c-reference requires the protected-recall decision policy")
    policies = {
        RisiCPair.VULNERABLE: PolicyConfiguration(
            PolicyIdentity("risi-shared-counter", "1"),
            {
                "top_k": top_k,
                "read_side_updates": True,
                "canary_memory_id": oracle.canary_memory_id,
                "victim_principal_id": oracle.victim_principal_id,
                "observer_principal_id": oracle.observer_principal_id,
                "no_hidden_signal_memory_id": oracle.no_hidden_signal_memory_id,
                "hidden_signal_memory_id": oracle.hidden_signal_memory_id,
            },
        ),
        RisiCPair.PURE_READ: PolicyConfiguration(
            PolicyIdentity("pure-read", "1"),
            {"top_k": top_k, "read_side_updates": False},
        ),
    }
    arms = tuple(
        _execute_risi_c_arm(validated, initial_state, pair, arm, policies[pair])
        for pair in RisiCPair
        for arm in RisiCArm
    )
    by_identity = {(material.pair, material.arm): material for material in arms}
    pair_assessments: dict[RisiCPair, RisiCPairAssessment] = {}
    for pair in RisiCPair:
        sham = by_identity[(pair, RisiCArm.SHAM)]
        hidden = by_identity[(pair, RisiCArm.HIDDEN)]
        pair_assessments[pair] = assess_risi_c_pair(
            pair,
            sham.final_state,
            hidden.final_state,
            sham.observer_view,
            hidden.observer_view,
            oracle,
        )
    comparison = assess_risi_c_comparison(
        scenario.scenario_id,
        state_snapshot_hash(initial_state),
        pair_assessments[RisiCPair.VULNERABLE],
        pair_assessments[RisiCPair.PURE_READ],
    )
    files, execution = _risi_c_evidence_files(validated, initial_state, arms, comparison)
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
            "comparison_result": comparison.result.value,
            "bundle_path": str(bundle_path),
            "inventory_sha256": verification.inventory_sha256,
            "bundle_hash": verification.bundle_hash,
            "event_count": execution["event_count"],
            "pairs": execution["pairs"],
        },
    )
    return RunExecution(result, bundle_path, verification)


def _execute_risi_c_arm(
    validated: ValidatedRun,
    initial_state: StateSnapshot,
    pair: RisiCPair,
    arm: RisiCArm,
    policy: PolicyConfiguration,
) -> _RisiCArmMaterial:
    scenario = validated.scenario
    protocol = scenario.risi_c_reference
    oracle = scenario.risi_c_oracle
    if (
        protocol is None
        or oracle is None
        or not isinstance(scenario.protocol, RegionDecisionProtocol)
    ):
        raise AssertionError("risi-c-reference contracts are required")
    adapter = ReferenceMemoryAdapter(initial_state)
    adapter.record_event(
        EventType.EPISODE_STARTED,
        EventVisibility.EVALUATOR,
        {
            "pair": pair.value,
            "arm": arm.value,
            "manifest_sha256": validated.manifest.digest,
            "profile": validated.manifest.profile.value,
        },
    )
    adapter.configure_policy(policy)
    victim_query = RetrievalQuery(
        principal_id=protocol.victim_principal_id,
        tenant_id=protocol.tenant_id,
        text=protocol.hidden_query if arm is RisiCArm.HIDDEN else protocol.sham_query,
        top_k=protocol.event_top_k,
    )
    victim_retrieval = adapter.retrieve(victim_query)
    victim_context = adapter.assemble_context(victim_retrieval)
    expected_victim_memory = (
        oracle.canary_memory_id if arm is RisiCArm.HIDDEN else oracle.sham_memory_id
    )
    if tuple(hit.memory_id for hit in victim_retrieval.hits) != (expected_victim_memory,):
        raise ValueError("risi-c-reference victim event did not isolate its expected memory")

    observer_query = RetrievalQuery(
        principal_id=protocol.observer_principal_id,
        tenant_id=protocol.tenant_id,
        text=protocol.observer_query,
        top_k=protocol.observer_top_k,
    )
    observer_retrieval = adapter.retrieve(observer_query)
    adapter.assemble_context(observer_retrieval)
    observer_ids = tuple(hit.memory_id for hit in observer_retrieval.hits)
    observer_contents = tuple(
        _memory_by_id(adapter.inspect_state(), memory_id).content for memory_id in observer_ids
    )
    observer_view = ObserverView(
        principal_id=protocol.observer_principal_id,
        exchanges=(
            ObserverExchange(
                query_index=0,
                query=observer_query,
                response_memory_ids=observer_ids,
                response_contents=observer_contents,
                metadata={"result_count": len(observer_ids)},
            ),
        ),
    )

    decision_query = RetrievalQuery(
        principal_id=scenario.protocol.principal_id,
        tenant_id=scenario.protocol.tenant_id,
        text=scenario.protocol.query,
        top_k=scenario.protocol.top_k,
    )
    decision_retrieval = adapter.retrieve(decision_query)
    decision_context = adapter.assemble_context(decision_retrieval)
    provider = DeterministicRegionProvider()
    if provider.provider_id != validated.manifest.decision_provider:
        raise ValueError("registered decision provider does not match the manifest")
    decision = provider.propose(
        DecisionRequest(
            episode=initial_state.episode,
            context=decision_context,
            retrieval=decision_retrieval,
            facts=scenario.facts,
            protocol=scenario.protocol,
        )
    )
    adapter.record_event(
        EventType.DECISION,
        EventVisibility.BOTH,
        {"decision": decision.to_json()},
    )
    decision_assessment = evaluate_decision(decision, scenario.evaluator.decision_oracle)
    adapter.record_event(
        EventType.ORACLE_EVALUATED,
        EventVisibility.EVALUATOR,
        {"decision_assessment": decision_assessment.to_json()},
    )
    adapter.record_event(
        EventType.EPISODE_COMPLETED,
        EventVisibility.EVALUATOR,
        {"pair": pair.value, "arm": arm.value, "safe": decision_assessment.safe},
    )
    final_state = adapter.inspect_state()
    if final_state.source_memories != initial_state.source_memories:
        raise ValueError("risi-c-reference changed source memories")
    events = adapter.export_trace()
    verify_trace(events)
    return _RisiCArmMaterial(
        pair=pair,
        arm=arm,
        policy=policy,
        final_state=final_state,
        victim_query=victim_query,
        victim_retrieval=victim_retrieval,
        victim_context=victim_context,
        observer_query=observer_query,
        observer_retrieval=observer_retrieval,
        observer_view=observer_view,
        decision_query=decision_query,
        decision_retrieval=decision_retrieval,
        decision_context=decision_context,
        decision=decision,
        decision_assessment=decision_assessment,
        events=events,
    )


def _critical_oracle(scenario: SyntheticScenario) -> MemoryOracle:
    critical = tuple(
        oracle for oracle in scenario.evaluator.memory_oracles if oracle.oracle_criticality
    )
    if len(critical) != 1:
        raise ValueError("craf-reference requires exactly one evaluator-critical memory")
    return critical[0]


def _critical_oracle_applicable(
    scenario: SyntheticScenario,
    oracle: MemoryOracle,
) -> bool:
    protocol = scenario.protocol
    if isinstance(protocol, RegionDecisionProtocol):
        return (
            oracle.applicability.get("dataset_class")
            == scenario.facts.get(protocol.dataset_class_fact)
            and oracle.applicability.get("prohibited_region") == protocol.prohibited_region
        )
    if isinstance(protocol, ReferenceRunProtocol):
        return (
            oracle.applicability.get("environment") == scenario.facts.get("target_environment")
            and oracle.applicability.get("minimum_approvals") == protocol.minimum_approvals
        )
    raise TypeError("craf-reference requires an approval decision protocol")


def _optional_memory_by_id(state: StateSnapshot, memory_id: str) -> MemoryRecord | None:
    return next((memory for memory in state.source_memories if memory.memory_id == memory_id), None)


def _memory_by_id(state: StateSnapshot, memory_id: str) -> MemoryRecord:
    memory = _optional_memory_by_id(state, memory_id)
    if memory is None:
        raise ValueError("required source memory is missing")
    return memory


def _craf_evidence_files(
    validated: ValidatedRun,
    initial_state: StateSnapshot,
    arms: tuple[_CrafArmMaterial, ...],
    comparison: CrafComparisonAssessment,
) -> tuple[dict[str, bytes], dict[str, JsonValue]]:
    manifest = validated.manifest
    arm_summaries: list[JsonValue] = [
        {
            "arm": arm.arm.value,
            "policy": arm.policy.identity.name,
            "classification": arm.craf_assessment.classification.value,
            "loss_stage": arm.craf_assessment.loss_stage.value,
            "safe": arm.decision_assessment.safe,
            "final_state_hash": state_snapshot_hash(arm.final_state),
            "event_count": len(arm.events),
        }
        for arm in arms
    ]
    execution: dict[str, JsonValue] = {
        "schema_version": 1,
        "run_id": manifest.run_id,
        "scenario_id": validated.scenario.scenario_id,
        "manifest_sha256": manifest.digest,
        "episode_id": validated.scenario.evaluator.episode_id,
        "policy": manifest.policy,
        "status": "succeeded",
        "comparison_result": comparison.result.value,
        "initial_state_hash": state_snapshot_hash(initial_state),
        "event_count": sum(len(arm.events) for arm in arms),
        "arms": arm_summaries,
    }
    files = {
        "manifest.json": json_bytes(manifest.to_json()),
        "approval.json": json_bytes(validated.approval.to_json()),
        "target-scenario.json": json_bytes(validated.scenario.target_view()),
        "evaluator/evaluator-state.json": json_bytes(validated.scenario.evaluator_view()),
        "evaluator/craf-comparison.json": json_bytes(comparison.to_json()),
        "initial-state.json": json_bytes(initial_state.to_json()),
        "execution.json": json_bytes(execution),
    }
    for arm in arms:
        prefix = f"arms/{arm.arm.value}"
        files[f"{prefix}/final-state.json"] = json_bytes(arm.final_state.to_json())
        files[f"{prefix}/events.jsonl"] = json_lines_bytes(
            tuple(event_to_json(event) for event in arm.events)
        )
        files[f"{prefix}/interaction.json"] = json_bytes(
            {
                "query": arm.interaction_query.to_json(),
                "result": arm.interaction_retrieval.to_json(),
                "context": arm.interaction_context,
            }
        )
        files[f"{prefix}/retrieval.json"] = json_bytes(
            {"query": arm.decision_query.to_json(), "result": arm.decision_retrieval.to_json()}
        )
        files[f"{prefix}/context.json"] = json_bytes({"context": arm.decision_context})
        files[f"{prefix}/decision.json"] = json_bytes(arm.decision.to_json())
        files[f"evaluator/arms/{arm.arm.value}/decision-assessment.json"] = json_bytes(
            arm.decision_assessment.to_json()
        )
        files[f"evaluator/arms/{arm.arm.value}/craf-assessment.json"] = json_bytes(
            arm.craf_assessment.to_json()
        )
    files["report.md"] = _render_craf_report(execution, comparison).encode()
    return files, execution


def _risi_c_evidence_files(
    validated: ValidatedRun,
    initial_state: StateSnapshot,
    arms: tuple[_RisiCArmMaterial, ...],
    comparison: RisiCComparisonAssessment,
) -> tuple[dict[str, bytes], dict[str, JsonValue]]:
    manifest = validated.manifest
    pair_assessments = {pair.pair: pair for pair in comparison.pairs}
    pair_summaries: list[JsonValue] = []
    for pair in RisiCPair:
        assessment = pair_assessments[pair]
        arm_summaries: list[JsonValue] = [
            {
                "arm": material.arm.value,
                "safe": material.decision_assessment.safe,
                "final_state_hash": state_snapshot_hash(material.final_state),
                "observer_view_hash": next(
                    arm.observer_view_sha256 for arm in assessment.arms if arm.arm is material.arm
                ),
                "event_count": len(material.events),
            }
            for material in arms
            if material.pair is pair
        ]
        pair_summaries.append(
            {
                "pair": pair.value,
                "classification": assessment.classification.value,
                "advantage": assessment.advantage,
                "sole_mediator": assessment.sole_mediator,
                "arms": arm_summaries,
            }
        )
    execution: dict[str, JsonValue] = {
        "schema_version": 1,
        "run_id": manifest.run_id,
        "scenario_id": validated.scenario.scenario_id,
        "manifest_sha256": manifest.digest,
        "episode_id": validated.scenario.evaluator.episode_id,
        "policy": manifest.policy,
        "status": "succeeded",
        "comparison_result": comparison.result.value,
        "initial_state_hash": state_snapshot_hash(initial_state),
        "event_count": sum(len(arm.events) for arm in arms),
        "pairs": pair_summaries,
    }
    files = {
        "manifest.json": json_bytes(manifest.to_json()),
        "approval.json": json_bytes(validated.approval.to_json()),
        "target-scenario.json": json_bytes(validated.scenario.target_view()),
        "evaluator/evaluator-state.json": json_bytes(validated.scenario.evaluator_view()),
        "evaluator/risi-c-comparison.json": json_bytes(comparison.to_json()),
        "evaluator/initial-state.json": json_bytes(initial_state.to_json()),
        "execution.json": json_bytes(execution),
    }
    for material in arms:
        prefix = f"pairs/{material.pair.value}/arms/{material.arm.value}"
        evaluator_prefix = f"evaluator/{prefix}"
        files[f"{evaluator_prefix}/final-state.json"] = json_bytes(material.final_state.to_json())
        files[f"{evaluator_prefix}/events.jsonl"] = json_lines_bytes(
            tuple(event_to_json(event) for event in material.events)
        )
        files[f"{evaluator_prefix}/victim-event.json"] = json_bytes(
            {
                "query": material.victim_query.to_json(),
                "result": material.victim_retrieval.to_json(),
                "context": material.victim_context,
            }
        )
        files[f"observer/{prefix}/view.json"] = json_bytes(material.observer_view.to_json())
        files[f"target/{prefix}/decision-retrieval.json"] = json_bytes(
            {
                "query": material.decision_query.to_json(),
                "result": material.decision_retrieval.to_json(),
            }
        )
        files[f"target/{prefix}/decision-context.json"] = json_bytes(
            {"context": material.decision_context}
        )
        files[f"target/{prefix}/decision.json"] = json_bytes(material.decision.to_json())
        files[f"{evaluator_prefix}/decision-assessment.json"] = json_bytes(
            material.decision_assessment.to_json()
        )
    files["report.md"] = _render_risi_c_report(execution, comparison).encode()
    return files, execution


def _render_risi_c_report(
    execution: dict[str, JsonValue],
    comparison: RisiCComparisonAssessment,
) -> str:
    lines = [
        "# RISI controlled RISI-C reference report",
        "",
        f"- Run: `{execution['run_id']}`",
        f"- Episode: `{execution['episode_id']}`",
        f"- Result: **{comparison.result.value}**",
        f"- Shared initial state: `{comparison.shared_initial_state_sha256}`",
        f"- Total events: {execution['event_count']}",
        "",
        "## Pairs",
        "",
    ]
    lines.extend(
        f"- `{pair.pair.value}`: `{pair.classification.value}`; "
        f"advantage={pair.advantage:.1f}; sole_mediator={str(pair.sole_mediator).lower()}"
        for pair in comparison.pairs
    )
    lines.extend(
        [
            "",
            "The observer view contains only its own authorized query, response, and result count.",
            "The opaque canary, hidden assignment, traces, full state, and evaluator oracle are",
            "excluded. Wall-clock timing is not part of the observer view or classifier.",
            "This is controlled local mechanism recovery, not an external vulnerability finding.",
            "No deployment or other external action was executed.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_craf_report(
    execution: dict[str, JsonValue],
    comparison: CrafComparisonAssessment,
) -> str:
    lines = [
        "# RISI controlled CRAF reference report",
        "",
        f"- Run: `{execution['run_id']}`",
        f"- Episode: `{execution['episode_id']}`",
        f"- Result: **{comparison.result.value}**",
        f"- Shared initial state: `{comparison.shared_initial_state_sha256}`",
        f"- Total events: {execution['event_count']}",
        "",
        "## Arms",
        "",
    ]
    lines.extend(
        f"- `{arm.arm.value}`: `{arm.classification.value}` at "
        f"`{arm.loss_stage.value}`; safe={str(arm.decision_safe).lower()}"
        for arm in comparison.arms
    )
    lines.extend(
        [
            "",
            "This report records an intentionally controlled synthetic mechanism, not an external",
            "vulnerability finding. No external action was executed.",
            "",
        ]
    )
    return "\n".join(lines)


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
