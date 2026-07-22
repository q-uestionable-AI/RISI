"""Pinned, allowlisted HTTPS transport for isolated external targets."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, cast
from urllib.parse import urlencode, urlsplit

from risi.canonical import JsonObject, freeze_json_object

REQUEST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 4_000_000


class TransportError(RuntimeError):
    """Report a closed, credential-free transport failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class CancellationToken:
    """Provide cooperative cancellation without interrupting an in-flight request."""

    def __init__(self) -> None:
        self._cancelled = threading.Event()

    @property
    def cancelled(self) -> bool:
        """Return whether cancellation has been requested."""
        return self._cancelled.is_set()

    def cancel(self) -> None:
        """Prevent the caller from starting another request."""
        self._cancelled.set()

    def raise_if_cancelled(self) -> None:
        """Reject a new request after cancellation."""
        if self.cancelled:
            raise TransportError("cancelled", "request cancelled before dispatch")


@dataclass(frozen=True, slots=True)
class AllowedRoute:
    """Allow one HTTP method and one exact parameterized path template."""

    method: str
    template: str

    def __post_init__(self) -> None:
        """Validate a closed route declaration."""
        if self.method not in {"GET", "POST", "DELETE"}:
            raise ValueError("route method is not allowed")
        if not self.template.startswith("/") or "?" in self.template:
            raise ValueError("route template must be an absolute path without a query")

    def matches(self, method: str, path: str) -> bool:
        """Return whether the method and path match this template."""
        if method != self.method:
            return False
        expression = re.escape(self.template)
        expression = re.sub(r"\\\{[a-z_]+\\\}", r"[A-Za-z0-9-]+", expression)
        return re.fullmatch(expression, path) is not None


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Contain a validated JSON response without credential material."""

    status: int
    body: JsonObject


class HttpsTransport:
    """Issue one-shot JSON requests to a pinned HTTPS endpoint.

    The transport has no retry loop. It uses normal CA and hostname verification and then checks
    the exact peer-certificate fingerprint before transmitting a credential-bearing request.
    """

    def __init__(
        self,
        base_url: str,
        certificate_sha256: str,
        ca_certificate_path: Path,
        routes: tuple[AllowedRoute, ...],
        *,
        timeout_seconds: int = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Configure the immutable endpoint and allowlist.

        Args:
            base_url: HTTPS origin without a path, query, or fragment.
            certificate_sha256: Lowercase SHA-256 digest of the peer certificate DER bytes.
            ca_certificate_path: Operator-controlled PEM CA certificate path.
            routes: Closed method/path allowlist.
            timeout_seconds: Per-request deadline, fixed at ten seconds by the E2 profile.
        """
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("base_url must be one HTTPS origin")
        if re.fullmatch(r"[a-f0-9]{64}", certificate_sha256) is None:
            raise ValueError("certificate_sha256 must be a lowercase SHA-256 digest")
        if timeout_seconds != REQUEST_TIMEOUT_SECONDS:
            raise ValueError("isolated target request timeout must be exactly ten seconds")
        try:
            ca_path = ca_certificate_path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("CA certificate path does not exist") from exc
        if not ca_path.is_file() or ca_path.is_symlink():
            raise ValueError("CA certificate path must be a regular non-symlink file")
        if not routes or len(routes) != len(set(routes)):
            raise ValueError("routes must contain unique entries")
        self._host = parsed.hostname
        self._port = parsed.port or 443
        self._certificate_sha256 = certificate_sha256
        self._routes = routes
        self._timeout_seconds = timeout_seconds
        self._context = ssl.create_default_context(cafile=str(ca_path))
        self._context.check_hostname = True
        self._request_count = 0

    @property
    def request_count(self) -> int:
        """Return the number of dispatched requests, including failed requests."""
        return self._request_count

    def _validate_route(self, method: str, path: str) -> None:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise TransportError("path_denied", "request path is malformed or not allowlisted")
        if not any(route.matches(method, path) for route in self._routes):
            raise TransportError("path_denied", "request method and path are not allowlisted")

    def _connection(self) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(
            self._host,
            self._port,
            timeout=self._timeout_seconds,
            context=self._context,
        )

    def _verify_peer(self, connection: http.client.HTTPSConnection) -> None:
        connection.connect()
        if connection.sock is None:
            raise TransportError("tls_failure", "HTTPS connection did not expose a peer")
        certificate = connection.sock.getpeercert(binary_form=True)
        if certificate is None:
            raise TransportError("tls_failure", "HTTPS peer did not provide a certificate")
        actual = hashlib.sha256(certificate).hexdigest()
        if actual != self._certificate_sha256:
            connection.close()
            raise TransportError("certificate_mismatch", "HTTPS peer certificate is not pinned")

    def request_json(
        self,
        method: str,
        path: str,
        *,
        api_key: str,
        body: JsonObject | None = None,
        query: dict[str, str | int] | None = None,
        cancellation: CancellationToken | None = None,
    ) -> TransportResponse:
        """Dispatch exactly one allowlisted request and parse one JSON-object response.

        Args:
            method: Uppercase HTTP method.
            path: Exact path without query material.
            api_key: Target API key, used only in the Authorization header.
            body: Optional JSON object request body.
            query: Optional percent-encoded query parameters.
            cancellation: Cooperative cancellation checked before dispatch.

        Returns:
            Validated response status and object body.

        Raises:
            TransportError: If policy, TLS, deadline, status, size, or JSON checks fail.
        """
        status, raw = self._request_bytes(
            method,
            path,
            api_key=api_key,
            body=body,
            query=query,
            cancellation=cancellation,
        )
        try:
            value: Any = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise TransportError("malformed_response", "target returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise TransportError("malformed_response", "target JSON response must be an object")
        return TransportResponse(status, freeze_json_object(cast(dict[str, Any], value)))

    def request_empty(
        self,
        method: str,
        path: str,
        *,
        api_key: str,
        expected_status: int,
        cancellation: CancellationToken | None = None,
    ) -> int:
        """Dispatch one allowlisted request that must return an empty exact-status response."""
        status, raw = self._request_bytes(
            method,
            path,
            api_key=api_key,
            cancellation=cancellation,
        )
        if status != expected_status or raw:
            raise TransportError(
                "malformed_response", "target returned an unexpected empty-response contract"
            )
        return status

    def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        api_key: str,
        body: JsonObject | None = None,
        query: dict[str, str | int] | None = None,
        cancellation: CancellationToken | None = None,
    ) -> tuple[int, bytes]:
        """Dispatch exactly one request and return a bounded successful response body."""
        token = cancellation or CancellationToken()
        token.raise_if_cancelled()
        self._validate_route(method, path)
        if not api_key or "\r" in api_key or "\n" in api_key:
            raise TransportError("credential_invalid", "target credential is invalid")
        target = path if not query else f"{path}?{urlencode(query)}"
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "risi-isolated-dify-knowledge/1",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        connection = self._connection()
        self._request_count += 1
        try:
            self._verify_peer(connection)
            connection.request(method, target, body=payload, headers=headers)
            response = connection.getresponse()
            content_length = response.getheader("Content-Length")
            try:
                if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
                    raise TransportError(
                        "response_too_large", "target response exceeds size ceiling"
                    )
            except ValueError as exc:
                raise TransportError(
                    "malformed_response", "target Content-Length header is invalid"
                ) from exc
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise TransportError("response_too_large", "target response exceeds size ceiling")
            if not 200 <= response.status < 300:
                raise TransportError(
                    "service_error", f"target returned HTTP status {response.status}"
                )
        except (TimeoutError, ssl.SSLError, OSError, http.client.HTTPException) as exc:
            raise TransportError("transport_failure", "target HTTPS request failed") from exc
        else:
            return response.status, raw
        finally:
            connection.close()

    def __enter__(self) -> HttpsTransport:
        """Return this stateless one-shot transport."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Provide context-manager symmetry; each request closes its own connection."""
