"""Human-readable and machine-stable command-line interface for RISI."""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

import typer

from risi import __version__
from risi.artifacts import ArtifactError, verify_evidence_bundle
from risi.budget import BudgetExhaustedError
from risi.canonical import canonical_json
from risi.evidence import compare_bundles, inspect_bundle, recover_existing_result
from risi.operator.models import (
    CommandResult,
    OperatorInputError,
    ResultError,
    ResultStatus,
    load_approval_record,
    load_run_manifest,
)
from risi.operator.safety import PathBoundaryError
from risi.replay import read_verified_report, replay_bundle
from risi.runner import (
    SafetyBlockedError,
    capabilities_result,
    run_guarded,
    validate_run,
)

app = typer.Typer(
    help="Agent-operable reference harness for Retrieval-Induced State Interference research.",
    no_args_is_help=True,
)


class ExitCode(IntEnum):
    """Stable process exit codes for autonomous operators."""

    SUCCESS = 0
    INVALID_INPUT = 2
    BLOCKED_BY_POLICY = 3
    INTEGRITY_FAILURE = 4
    EXECUTION_FAILURE = 5
    RESOURCE_EXHAUSTED = 6
    INTERRUPTED = 130


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit


@app.callback()
def main(
    version_requested: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print the installed RISI package version and exit.",
    ),
) -> None:
    """Operate the guarded RISI reference harness."""


def _validate_format(format_name: str) -> None:
    if format_name not in {"text", "json"}:
        raise OperatorInputError("format must be 'text' or 'json'")


def _render_evidence_operation(result: CommandResult) -> str:
    if result.command == "inspect":
        return (
            f"{result.run_id}: evidence inspected\n"
            f"scenario: {result.data['scenario']}\n"
            f"bundle sha256: {result.data['bundle_hash']}"
        )
    differences = result.data["differences"]
    if not isinstance(differences, (list, tuple)):
        raise TypeError("compare differences must be an array")
    return f"equal: {str(result.data['equal']).lower()}\ndifferences: {len(differences)}"


def _render_text(result: CommandResult) -> str:
    if result.status is not ResultStatus.OK:
        rendered = "\n".join(f"{error.code}: {error.message}" for error in result.errors)
    elif result.command == "capabilities":
        rendered = "local-reference: available (network, subprocesses, and credentials denied)"
    elif result.command == "validate":
        rendered = f"{result.run_id}: valid and authorized"
    elif result.command == "run":
        if "comparison_result" in result.data:
            rendered = (
                f"{result.run_id}: completed {result.data['comparison_result']}\n"
                f"evidence: {result.data['bundle_path']}\n"
                f"inventory sha256: {result.data['inventory_sha256']}"
            )
        else:
            rendered = (
                f"{result.run_id}: completed safely={result.data['safe']}\n"
                f"evidence: {result.data['bundle_path']}\n"
                f"inventory sha256: {result.data['inventory_sha256']}"
            )
    elif result.command == "verify":
        rendered = (
            f"{result.run_id}: evidence verified\n"
            f"inventory sha256: {result.data['inventory_sha256']}"
        )
    elif result.command in {"inspect", "compare"}:
        rendered = _render_evidence_operation(result)
    elif result.command == "replay":
        if "comparison_result" in result.data:
            rendered = (
                f"{result.run_id}: replay verified ({result.data['event_count']} events)\n"
                f"comparison: {result.data['comparison_result']}"
            )
        else:
            rendered = (
                f"{result.run_id}: replay verified ({result.data['event_count']} events)\n"
                f"decision: {result.data['decision_action']}\n"
                f"safe: {result.data['safe']}"
            )
    else:
        rendered = canonical_json(result.to_json())
    return rendered


def _emit(result: CommandResult, format_name: str) -> None:
    _validate_format(format_name)
    typer.echo(canonical_json(result.to_json()) if format_name == "json" else _render_text(result))


def _error_result(
    command: str,
    status: ResultStatus,
    code: str,
    message: str,
    *,
    run_id: str | None = None,
) -> CommandResult:
    return CommandResult(
        command=command,
        status=status,
        run_id=run_id,
        errors=(ResultError(code=code, message=message),),
    )


def _emit_blocked(command: str, exc: SafetyBlockedError, format_name: str) -> None:
    result = CommandResult(
        command=command,
        status=ResultStatus.BLOCKED,
        data={"authorization": exc.decision.to_json()},
        errors=tuple(
            ResultError(code=reason, message="denied by the local-reference safety policy")
            for reason in exc.decision.reason_codes
        ),
    )
    _emit(result, format_name)
    raise typer.Exit(ExitCode.BLOCKED_BY_POLICY)


@app.command()
def version() -> None:
    """Print the installed RISI package version."""
    typer.echo(__version__)


@app.command()
def smoke() -> None:
    """Run a deterministic package smoke check."""
    typer.echo("risi smoke: ok")


@app.command("capabilities")
def show_capabilities(
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Show implemented profiles, capabilities, and hard denials."""
    try:
        _emit(capabilities_result(), format_name)
    except OperatorInputError as exc:
        _emit(_error_result("capabilities", ResultStatus.ERROR, "invalid_input", str(exc)), "json")
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc


@app.command("validate")
def validate_command(
    manifest_path: Path = typer.Argument(..., help="Run-manifest JSON path."),
    approval_path: Path = typer.Option(..., "--approval", help="Approval-record JSON path."),
    scenario_root: Path = typer.Option(
        Path("scenarios"), "--scenario-root", help="Trusted scenario root."
    ),
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Authorize and validate a run without executing it or writing artifacts."""
    try:
        _validate_format(format_name)
        manifest = load_run_manifest(manifest_path)
        approval = load_approval_record(approval_path)
        validated = validate_run(manifest, approval, scenario_root)
        _emit(
            CommandResult(
                command="validate",
                status=ResultStatus.OK,
                run_id=manifest.run_id,
                data=validated.to_json(),
            ),
            format_name,
        )
    except SafetyBlockedError as exc:
        _emit_blocked("validate", exc, format_name)
    except (OperatorInputError, PathBoundaryError, ValueError) as exc:
        _emit(
            _error_result("validate", ResultStatus.ERROR, "invalid_input", str(exc)),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc


@app.command("run")
def run_command(
    manifest_path: Path = typer.Argument(..., help="Run-manifest JSON path."),
    approval_path: Path = typer.Option(..., "--approval", help="Approval-record JSON path."),
    scenario_root: Path = typer.Option(
        Path("scenarios"), "--scenario-root", help="Trusted scenario root."
    ),
    artifact_root: Path = typer.Option(
        Path("artifacts"), "--artifact-root", help="Operator-controlled artifact root."
    ),
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Execute one guarded deterministic reference run and write its evidence bundle."""
    manifest = None
    approval = None
    try:
        _validate_format(format_name)
        manifest = load_run_manifest(manifest_path)
        approval = load_approval_record(approval_path)
        execution = run_guarded(manifest, approval, scenario_root, artifact_root)
        _emit(execution.result, format_name)
    except SafetyBlockedError as exc:
        _emit_blocked("run", exc, format_name)
    except BudgetExhaustedError as exc:
        _emit(
            CommandResult(
                command="run",
                status=ResultStatus.RESOURCE_EXHAUSTED,
                run_id=None if manifest is None else manifest.run_id,
                data={"exhaustion": exc.to_json()},
                errors=(
                    ResultError(
                        code="budget_exhausted",
                        message=str(exc),
                        field=f"limits.{exc.resource.value}",
                    ),
                ),
            ),
            format_name,
        )
        raise typer.Exit(ExitCode.RESOURCE_EXHAUSTED) from exc
    except KeyboardInterrupt as exc:
        if manifest is not None and approval is not None:
            try:
                validate_run(manifest, approval, scenario_root)
                recovered = recover_existing_result(artifact_root, manifest)
            except (SafetyBlockedError, ValueError):
                recovered = None
            if recovered is not None:
                _emit(recovered.result, format_name)
                return
        _emit(
            _error_result(
                "run",
                ResultStatus.INTERRUPTED,
                "interrupted",
                "run interrupted before atomic evidence finalization",
                run_id=None if manifest is None else manifest.run_id,
            ),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INTERRUPTED) from exc
    except ArtifactError as exc:
        _emit(
            _error_result("run", ResultStatus.ERROR, "artifact_failure", str(exc)),
            format_name,
        )
        raise typer.Exit(ExitCode.EXECUTION_FAILURE) from exc
    except (OperatorInputError, PathBoundaryError, ValueError) as exc:
        _emit(
            _error_result("run", ResultStatus.ERROR, "invalid_input", str(exc)),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc


@app.command("verify")
def verify_command(
    bundle_path: Path = typer.Argument(..., help="Evidence-bundle directory."),
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Verify an evidence bundle and every inventoried file digest."""
    try:
        _validate_format(format_name)
        verification = verify_evidence_bundle(bundle_path)
        _emit(
            CommandResult(
                command="verify",
                status=ResultStatus.OK,
                run_id=verification.run_id,
                data=verification.to_json(),
            ),
            format_name,
        )
    except OperatorInputError as exc:
        _emit(_error_result("verify", ResultStatus.ERROR, "invalid_input", str(exc)), "json")
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ArtifactError, OSError, ValueError) as exc:
        _emit(
            _error_result("verify", ResultStatus.ERROR, "integrity_failure", str(exc)),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INTEGRITY_FAILURE) from exc


@app.command("inspect")
def inspect_command(
    bundle_path: Path = typer.Argument(..., help="Evidence-bundle directory."),
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Verify and inspect a completed evidence bundle."""
    try:
        _validate_format(format_name)
        summary = inspect_bundle(bundle_path)
        _emit(
            CommandResult(
                command="inspect",
                status=ResultStatus.OK,
                run_id=summary.run_id,
                data=summary.to_json(),
            ),
            format_name,
        )
    except OperatorInputError as exc:
        _emit(_error_result("inspect", ResultStatus.ERROR, "invalid_input", str(exc)), "json")
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ArtifactError, OSError, ValueError) as exc:
        _emit(
            _error_result("inspect", ResultStatus.ERROR, "integrity_failure", str(exc)),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INTEGRITY_FAILURE) from exc


@app.command("compare")
def compare_command(
    bundle_path_a: Path = typer.Argument(..., help="First evidence-bundle directory."),
    bundle_path_b: Path = typer.Argument(..., help="Second evidence-bundle directory."),
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Verify and compare two completed evidence bundles."""
    try:
        _validate_format(format_name)
        comparison = compare_bundles(bundle_path_a, bundle_path_b)
        _emit(
            CommandResult(
                command="compare",
                status=ResultStatus.OK,
                data=comparison.to_json(),
            ),
            format_name,
        )
    except OperatorInputError as exc:
        _emit(_error_result("compare", ResultStatus.ERROR, "invalid_input", str(exc)), "json")
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ArtifactError, OSError, ValueError) as exc:
        _emit(
            _error_result("compare", ResultStatus.ERROR, "integrity_failure", str(exc)),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INTEGRITY_FAILURE) from exc


@app.command("replay")
def replay_command(
    bundle_path: Path = typer.Argument(..., help="Evidence-bundle directory."),
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Perform model-free replay of a verified deterministic evidence bundle."""
    try:
        _validate_format(format_name)
        replay = replay_bundle(bundle_path)
        _emit(
            CommandResult(
                command="replay",
                status=ResultStatus.OK,
                run_id=replay.run_id,
                data=replay.to_json(),
            ),
            format_name,
        )
    except OperatorInputError as exc:
        _emit(_error_result("replay", ResultStatus.ERROR, "invalid_input", str(exc)), "json")
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ArtifactError, OSError, ValueError) as exc:
        _emit(
            _error_result("replay", ResultStatus.ERROR, "integrity_failure", str(exc)),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INTEGRITY_FAILURE) from exc


@app.command("report")
def report_command(
    bundle_path: Path = typer.Argument(..., help="Evidence-bundle directory."),
    format_name: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Read a generated report only after verifying its evidence bundle."""
    try:
        _validate_format(format_name)
        verification, report = read_verified_report(bundle_path)
        if format_name == "text":
            typer.echo(report, nl=False)
            return
        _emit(
            CommandResult(
                command="report",
                status=ResultStatus.OK,
                run_id=verification.run_id,
                data={"report": report, "verification": verification.to_json()},
            ),
            format_name,
        )
    except OperatorInputError as exc:
        _emit(_error_result("report", ResultStatus.ERROR, "invalid_input", str(exc)), "json")
        raise typer.Exit(ExitCode.INVALID_INPUT) from exc
    except (ArtifactError, OSError, ValueError) as exc:
        _emit(
            _error_result("report", ResultStatus.ERROR, "integrity_failure", str(exc)),
            format_name if format_name in {"text", "json"} else "json",
        )
        raise typer.Exit(ExitCode.INTEGRITY_FAILURE) from exc
