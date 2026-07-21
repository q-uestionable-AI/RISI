import hashlib
import json
from pathlib import Path

import pytest

from risi.adapters.dify import DIFY_API_PATHS
from risi.adapters.external import ExternalTargetManifest, load_target_credential
from risi.operator.models import ExecutionProfile, OperatorInputError
from risi.transport import AllowedRoute, CancellationToken, HttpsTransport, TransportError


class FakeContext:
    check_hostname = True


class FakeSocket:
    def __init__(self, certificate: bytes) -> None:
        self.certificate = certificate

    def getpeercert(self, *, binary_form: bool) -> bytes:
        assert binary_form
        return self.certificate


class FakeResponse:
    def __init__(self, status: int, content: bytes) -> None:
        self.status = status
        self.content = content

    def getheader(self, name: str):
        return str(len(self.content)) if name == "Content-Length" else None

    def read(self, limit: int) -> bytes:
        return self.content[:limit]


class FakeConnection:
    def __init__(
        self, certificate: bytes, response: FakeResponse, *, connect_error: Exception | None = None
    ) -> None:
        self.sock = FakeSocket(certificate)
        self.response = response
        self.connect_error = connect_error
        self.requests = 0

    def connect(self) -> None:
        if self.connect_error is not None:
            raise self.connect_error

    def request(self, *args, **kwargs) -> None:
        self.requests += 1

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        return None


def _target(
    api_key_sha256: str = "c" * 64,
    health_token_sha256: str = "d" * 64,
) -> ExternalTargetManifest:
    return ExternalTargetManifest(
        schema_version=1,
        target_id="risi-dify-e1",
        profile=ExecutionProfile.ISOLATED_DIFY_KNOWLEDGE,
        base_url="https://risi-dify-e1",
        server_name="risi-dify-e1",
        certificate_sha256="b" * 64,
        ca_certificate_path="ca.pem",
        api_key_sha256=api_key_sha256,
        health_token_sha256=health_token_sha256,
        api_paths=DIFY_API_PATHS,
        identities={"dify_version": "1.15.0"},
    )


def test_target_manifest_freezes_profile_deadline_retry_and_identity() -> None:
    target = _target()

    assert target.profile is ExecutionProfile.ISOLATED_DIFY_KNOWLEDGE
    assert target.request_timeout_seconds == 10
    assert target.automatic_retry_count == 0
    assert target.indexing_poll_seconds == 1
    assert target.indexing_timeout_seconds == 300
    assert len(target.digest) == 64


def test_target_manifest_denies_wrong_host_and_retry() -> None:
    with pytest.raises(OperatorInputError, match="frozen target identity"):
        ExternalTargetManifest(
            **{
                **_target().to_json(),
                "profile": ExecutionProfile.ISOLATED_DIFY_KNOWLEDGE,
                "base_url": "https://other-host",
            }
        )
    with pytest.raises(OperatorInputError, match="zero"):
        ExternalTargetManifest(
            **{
                **_target().to_json(),
                "profile": ExecutionProfile.ISOLATED_DIFY_KNOWLEDGE,
                "automatic_retry_count": 1,
            }
        )


def test_fingerprint_bound_credential_never_renders_secret(tmp_path: Path) -> None:
    secret = {
        "target_id": "risi-dify-e1",
        "api_key": "secret-value-do-not-render",
        "health_token": "health-secret-do-not-render",
    }
    content = json.dumps(secret).encode()
    path = tmp_path / "target-admin.json"
    path.write_bytes(content)
    target = _target(
        hashlib.sha256(secret["api_key"].encode()).hexdigest(),
        hashlib.sha256(secret["health_token"].encode()).hexdigest(),
    )

    credential = load_target_credential(path, target)

    assert credential.api_key == secret["api_key"]
    assert secret["api_key"] not in repr(credential)
    assert credential.health_token == secret["health_token"]
    assert secret["health_token"] not in repr(credential)


@pytest.mark.parametrize(
    ("fingerprint_name", "expected_message"),
    [
        ("api_key_sha256", "API key fingerprint"),
        ("health_token_sha256", "health token fingerprint"),
    ],
)
def test_credential_rejects_individual_secret_fingerprint_mismatch(
    tmp_path: Path, fingerprint_name: str, expected_message: str
) -> None:
    secret = {
        "target_id": "risi-dify-e1",
        "api_key": "synthetic-api-key",
        "health_token": "synthetic-health-token",
    }
    path = tmp_path / "target-admin.json"
    path.write_text(json.dumps(secret), encoding="utf-8")
    fingerprints = {
        "api_key_sha256": hashlib.sha256(secret["api_key"].encode()).hexdigest(),
        "health_token_sha256": hashlib.sha256(secret["health_token"].encode()).hexdigest(),
    }
    fingerprints[fingerprint_name] = "0" * 64
    target = _target(**fingerprints)

    with pytest.raises(OperatorInputError, match=expected_message):
        load_target_credential(path, target)


def test_route_matching_is_closed_and_cancellation_prevents_dispatch() -> None:
    route = AllowedRoute("GET", "/v1/datasets/{dataset_id}")
    assert route.matches("GET", "/v1/datasets/123e4567-e89b-12d3-a456-426614174000")
    assert not route.matches("POST", "/v1/datasets/123e4567-e89b-12d3-a456-426614174000")
    assert not route.matches("GET", "/console/api/datasets/123")

    token = CancellationToken()
    token.cancel()
    with pytest.raises(TransportError, match="before dispatch"):
        token.raise_if_cancelled()


def test_https_transport_rejects_missing_ca(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="CA certificate path"):
        HttpsTransport(
            "https://risi-dify-e1",
            "b" * 64,
            tmp_path / "missing.pem",
            (AllowedRoute("GET", "/healthz"),),
        )


def _transport_with_connection(
    tmp_path: Path, monkeypatch, connection: FakeConnection, certificate: bytes
) -> HttpsTransport:
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text("placeholder", encoding="utf-8")
    monkeypatch.setattr("risi.transport.ssl.create_default_context", lambda **kwargs: FakeContext())
    transport = HttpsTransport(
        "https://risi-dify-e1",
        hashlib.sha256(certificate).hexdigest(),
        ca_path,
        (AllowedRoute("GET", "/healthz"),),
    )
    monkeypatch.setattr(transport, "_connection", lambda: connection)
    return transport


def test_wrong_certificate_stops_before_credential_dispatch(tmp_path: Path, monkeypatch) -> None:
    connection = FakeConnection(b"wrong", FakeResponse(200, b"{}"))
    transport = _transport_with_connection(tmp_path, monkeypatch, connection, b"expected")

    with pytest.raises(TransportError) as error:
        transport.request_json("GET", "/healthz", api_key="do-not-render")

    assert error.value.code == "certificate_mismatch"
    assert connection.requests == 0
    assert transport.request_count == 1
    assert "do-not-render" not in str(error.value)


@pytest.mark.parametrize(
    ("response", "expected_code"),
    [
        (FakeResponse(503, b'{"message":"secret-do-not-render"}'), "service_error"),
        (FakeResponse(200, b"[]"), "malformed_response"),
    ],
)
def test_service_and_malformed_errors_are_never_retried(
    tmp_path: Path, monkeypatch, response: FakeResponse, expected_code: str
) -> None:
    certificate = b"expected"
    connection = FakeConnection(certificate, response)
    transport = _transport_with_connection(tmp_path, monkeypatch, connection, certificate)

    with pytest.raises(TransportError) as error:
        transport.request_json("GET", "/healthz", api_key="do-not-render")

    assert error.value.code == expected_code
    assert connection.requests == 1
    assert transport.request_count == 1
    assert "secret-do-not-render" not in str(error.value)
    assert "do-not-render" not in str(error.value)


def test_timeout_is_one_failed_request_without_retry(tmp_path: Path, monkeypatch) -> None:
    certificate = b"expected"
    connection = FakeConnection(certificate, FakeResponse(200, b"{}"), connect_error=TimeoutError())
    transport = _transport_with_connection(tmp_path, monkeypatch, connection, certificate)

    with pytest.raises(TransportError) as error:
        transport.request_json("GET", "/healthz", api_key="do-not-render")

    assert error.value.code == "transport_failure"
    assert connection.requests == 0
    assert transport.request_count == 1


def test_unlisted_path_is_denied_without_dispatch(tmp_path: Path, monkeypatch) -> None:
    certificate = b"expected"
    connection = FakeConnection(certificate, FakeResponse(200, b"{}"))
    transport = _transport_with_connection(tmp_path, monkeypatch, connection, certificate)

    with pytest.raises(TransportError) as error:
        transport.request_json("GET", "/console/api", api_key="do-not-render")

    assert error.value.code == "path_denied"
    assert connection.requests == 0
    assert transport.request_count == 0


def test_empty_response_contract_accepts_only_exact_status_and_no_body(
    tmp_path: Path, monkeypatch
) -> None:
    certificate = b"expected"
    connection = FakeConnection(certificate, FakeResponse(204, b""))
    transport = _transport_with_connection(tmp_path, monkeypatch, connection, certificate)

    status = transport.request_empty(
        "GET", "/healthz", api_key="synthetic-key", expected_status=204
    )

    assert status == 204
    assert connection.requests == 1


@pytest.mark.parametrize("response", [FakeResponse(200, b""), FakeResponse(204, b"{}")])
def test_empty_response_contract_rejects_wrong_status_or_body(
    tmp_path: Path, monkeypatch, response: FakeResponse
) -> None:
    certificate = b"expected"
    connection = FakeConnection(certificate, response)
    transport = _transport_with_connection(tmp_path, monkeypatch, connection, certificate)

    with pytest.raises(TransportError) as error:
        transport.request_empty("GET", "/healthz", api_key="synthetic-key", expected_status=204)

    assert error.value.code == "malformed_response"
    assert connection.requests == 1
