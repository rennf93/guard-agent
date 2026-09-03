import asyncio
import gzip
from typing import Any, NoReturn

import httpx

from guard_agent._transport_lifecycle import TransportLifecycleMixin
from guard_agent._version import __version__ as _AGENT_VERSION
from guard_agent.encryption import EncryptionError
from guard_agent.exceptions import PayloadTooLargeError, PermanentClientError
from guard_agent.signing import sign_payload
from guard_agent.utils import (
    RateLimitedError,
    SerializationError,
    parse_retry_after_seconds,
    safe_json_serialize,
    sanitize_headers,
    summarize_response_body,
)

_NON_RETRYABLE_STATUS_CODES = (400, 404, 413, 422)


class TransportResponseMixin:
    logger: Any

    def _log_request_error(self, method: str, url: str, exc: Exception) -> None:
        """Classify and log a request-level exception."""
        if isinstance(exc, EncryptionError):
            label = "Encryption error"
        elif isinstance(exc, httpx.HTTPError):
            label = "HTTP client error"
        elif isinstance(exc, asyncio.TimeoutError):
            label = "Timeout error"
        else:
            label = "Unexpected error"
        self.logger.error(f"{label} for {method} {url}: {type(exc).__name__}: {exc!r}")

    def _handle_200(self, response: httpx.Response) -> dict[str, Any] | bool:
        try:
            json_data = response.json()
        except Exception as exc:
            self.logger.warning(
                f"200 response with unparseable JSON body for {response.url}: "
                f"{type(exc).__name__}: {exc}"
            )
            return False
        if isinstance(json_data, dict):
            success = json_data.get("success")
            errors = json_data.get("errors")
            if success is False or errors:
                self.logger.warning(
                    f"200 response reported partial failure for {response.url}: "
                    f"success={success!r} errors={errors!r}"
                )
            return json_data
        return True

    def _raise_for_permanent_error(self, status_code: int, error_text: str) -> NoReturn:
        if status_code == 413:
            raise PayloadTooLargeError(error_text)
        raise PermanentClientError(status_code, error_text)

    async def _handle_response(self, response: httpx.Response) -> dict[str, Any] | bool:
        """Handle HTTP response with proper error checking."""
        self.logger.debug(f"Response: {response.status_code} for {response.url}")

        if response.status_code == 200:
            return self._handle_200(response)

        elif response.status_code == 201:
            return True

        elif response.status_code == 429:
            retry_after_seconds = parse_retry_after_seconds(
                response.headers.get("Retry-After"), default=60.0
            )
            raise RateLimitedError(retry_after_seconds)

        elif response.status_code in [401, 403]:
            raise Exception(f"Authentication failed: {response.status_code}")

        elif response.status_code in _NON_RETRYABLE_STATUS_CODES:
            error_text = summarize_response_body(response.text)
            self.logger.error(
                f"Permanent client error {response.status_code} for {response.url}: "
                f"{error_text}"
            )
            self._raise_for_permanent_error(response.status_code, error_text)

        elif response.status_code >= 500:
            error_text = summarize_response_body(response.text)
            raise Exception(
                f"Server error {response.status_code} for {response.url}: {error_text}"
            )

        else:
            error_text = summarize_response_body(response.text)
            self.logger.error(
                f"Client error {response.status_code} for {response.url}: {error_text}"
            )
            return False


class TransportDispatchMixin(TransportResponseMixin, TransportLifecycleMixin):
    _ENCRYPTED_ENDPOINTS = ("/api/v1/events", "/api/v1/metrics")

    def _maybe_compress(self, json_text: str) -> tuple[bytes, dict[str, str]]:
        """Return body bytes plus Content-Encoding header when compression applies."""
        raw = json_text.encode("utf-8")
        if (
            not self.config.compression_enabled
            or len(raw) < self.config.compression_threshold
        ):
            return raw, {}
        return gzip.compress(raw), {"Content-Encoding": "gzip"}

    def _redact_sensitive_headers(self, data: dict[str, Any]) -> dict[str, Any]:
        for event in data.get("events", []):
            metadata = event.get("metadata")
            if isinstance(metadata, dict):
                event["metadata"] = sanitize_headers(
                    metadata, self.config.sensitive_headers
                )
        for metric in data.get("metrics", []):
            tags = metric.get("tags")
            if isinstance(tags, dict):
                metric["tags"] = sanitize_headers(tags, self.config.sensitive_headers)
        return data

    def _is_encrypted_target(
        self, method: str, endpoint: str, data: dict[str, Any] | None
    ) -> bool:
        return (
            method == "POST"
            and bool(data)
            and self._encryption_enabled
            and endpoint in self._ENCRYPTED_ENDPOINTS
        )

    async def _make_request(
        self, method: str, endpoint: str, data: dict[str, Any] | None
    ) -> dict[str, Any] | bool:
        """Make HTTP request with proper error handling and optional encryption."""
        await self._ensure_client_for_current_process()

        if not self._client:
            raise Exception("Failed to initialize HTTP client")

        if data:
            data = self._redact_sensitive_headers(data)

        endpoint_base = self.config.endpoint.rstrip("/")
        url = f"{endpoint_base}{endpoint}"
        if self._is_encrypted_target(method, endpoint, data):
            actual_url = f"{endpoint_base}/api/v1/events/encrypted"
        else:
            actual_url = url

        try:
            return await self._dispatch_request(method, endpoint, url, data)
        except Exception as e:
            self._log_request_error(method, actual_url, e)
            raise

    async def _dispatch_request(
        self,
        method: str,
        endpoint: str,
        url: str,
        data: dict[str, Any] | None,
    ) -> dict[str, Any] | bool:
        """Dispatch the HTTP call by method/endpoint without error handling."""
        assert self._client is not None
        if method == "POST" and data:
            if self._is_encrypted_target(method, endpoint, data):
                return await self._post_encrypted(data)
            return await self._post_unencrypted(url, data)
        if method == "GET":
            response = await self._client.get(url)
            return await self._handle_response(response)
        raise ValueError(f"Unsupported method: {method}")

    def _build_encrypted_payload(self, data: dict[str, Any]) -> dict[str, Any]:
        """Serialize events/metrics for encryption."""
        return {
            "events": [
                event.model_dump(mode="json") if hasattr(event, "model_dump") else event
                for event in data.get("events", [])
            ],
            "metrics": [
                metric.model_dump(mode="json")
                if hasattr(metric, "model_dump")
                else metric
                for metric in data.get("metrics", [])
            ],
        }

    async def _post_encrypted(self, data: dict[str, Any]) -> dict[str, Any] | bool:
        """POST an encrypted payload to the dedicated encrypted endpoint."""
        if not self._encryptor:
            raise EncryptionError("Encryptor not initialized")
        assert self._client is not None

        encrypted_payload = self._encryptor.encrypt(self._build_encrypted_payload(data))
        encrypted_data = {
            "encrypted_payload": encrypted_payload,
            "batch_id": data.get("batch_id"),
            "agent_version": _AGENT_VERSION,
            "guard_version": self.config.guard_version,
            "guard_core_version": self.config.guard_core_version,
        }
        encrypted_url = f"{self.config.endpoint.rstrip('/')}/api/v1/events/encrypted"
        try:
            json_data = await safe_json_serialize(encrypted_data)
        except SerializationError as e:
            self.logger.error(
                f"Aborting encrypted POST to {encrypted_url}; "
                f"payload serialization failed and batch retained: {e}"
            )
            self._fire_error_hook("encryption", e, {"endpoint": encrypted_url})
            return False
        body, headers = self._maybe_compress(json_data)
        signature = sign_payload(body, secret=self.config.payload_signing_secret)
        if signature is not None:
            headers["X-Payload-Signature"] = signature
        self.bytes_sent += len(body)
        response = await self._client.post(encrypted_url, content=body, headers=headers)
        return await self._handle_response(response)

    async def _post_unencrypted(
        self, url: str, data: dict[str, Any]
    ) -> dict[str, Any] | bool:
        """POST a plain JSON payload."""
        assert self._client is not None
        try:
            json_data = await safe_json_serialize(data)
        except SerializationError as e:
            self.logger.error(
                f"Aborting POST to {url}; "
                f"payload serialization failed and batch retained: {e}"
            )
            self._fire_error_hook("transport_send", e, {"endpoint": url})
            return False
        body, headers = self._maybe_compress(json_data)
        signature = sign_payload(body, secret=self.config.payload_signing_secret)
        if signature is not None:
            headers["X-Payload-Signature"] = signature
        self.bytes_sent += len(body)
        response = await self._client.post(url, content=body, headers=headers)
        return await self._handle_response(response)
