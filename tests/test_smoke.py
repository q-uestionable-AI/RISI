import json
import tomllib
from pathlib import Path

from typer.testing import CliRunner

from risi import __version__
from risi.cli import app

PROJECT_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def test_package_version_matches_project_metadata() -> None:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as project_file:
        project = tomllib.load(project_file)

    assert project["project"]["version"] == __version__


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_root_version_option() -> None:
    for option in ("--version", "-V"):
        result = runner.invoke(app, [option])

        assert result.exit_code == 0
        assert result.stdout.strip() == __version__


def test_smoke_command() -> None:
    result = runner.invoke(app, ["smoke"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "risi smoke: ok"


def test_capabilities_expose_closed_dify_profile_and_reserve_inference_profiles() -> None:
    result = runner.invoke(app, ["capabilities", "--format", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    implemented = {profile["profile"]: profile for profile in payload["data"]["profiles"]}
    reserved = {profile["profile"]: profile for profile in payload["data"]["future_profiles"]}
    assert set(implemented) == {"local-reference", "isolated-dify-knowledge"}
    assert implemented["local-reference"]["network"] == "denied"
    assert implemented["local-reference"]["credentials"] == "denied"
    dify = implemented["isolated-dify-knowledge"]
    assert dify["network"] == "one-frozen-target"
    assert dify["credentials"] == "pbkdf2-sha256-verifier-bound-secret-file"
    assert dify["request_timeout_seconds"] == 10
    assert dify["automatic_retry_count"] == 0
    assert set(reserved) == {"authorized-local-inference", "authorized-remote-inference"}
    assert all(profile["status"] == "not-implemented" for profile in reserved.values())
    lifecycle = {item["operation"]: item["disposition"] for item in payload["data"]["lifecycle"]}
    assert lifecycle["inspect"] == "implemented"
    assert lifecycle["compare"] == "implemented"
    assert lifecycle["idempotent-reinvocation"] == "implemented"
    assert lifecycle["status-service"] == "denied"
    assert lifecycle["cancel-command"] == "denied"
    campaign_lifecycle = {
        item["operation"]: item["disposition"] for item in payload["data"]["campaign_lifecycle"]
    }
    assert campaign_lifecycle["status"] == "implemented"
    assert campaign_lifecycle["cancel"] == "implemented"
    assert campaign_lifecycle["execute"] == "implemented"
    assert lifecycle["wall-clock-deadlines"] == "denied"
    assert lifecycle["automatic-retries"] == "denied"
    assert lifecycle["async-jobs"] == "denied"
    assert payload["data"]["automatic_retry_count"] == 0


def test_json_schemas_are_parseable() -> None:
    schema_paths = sorted((PROJECT_ROOT / "schemas").glob("*.schema.json"))

    assert schema_paths
    for schema_path in schema_paths:
        with schema_path.open(encoding="utf-8") as schema_file:
            schema = json.load(schema_file)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
