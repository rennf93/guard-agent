import asyncio
import gzip
import logging
import os
from typing import Any

import httpx

from guard_agent._version import __version__ as _AGENT_VERSION
from guard_agent.encryption import (
    EncryptionConfigError,
    EncryptionError,
    PayloadEncryptor,
    create_encryptor,
)
from guard_agent.exceptions import PermanentClientError
from guard_agent.install_id import resolve_install_id
from guard_agent.models import (
    AgentConfig,
    AgentStatus,
    DynamicRules,
    EventBatch,
    SecurityEvent,
    SecurityMetric,
)
from guard_agent.protocols import TransportProtocol
from guard_agent.signing import sign_payload
from guard_agent.utils import (
    CircuitBreaker,
    RateLimitedError,
    RateLimiter,
    SerializationError,
    calculate_backoff_delay,
    generate_batch_id,
    get_current_timestamp,
    parse_retry_after_seconds,
    safe_json_serialize,
)

_NON_RETRYABLE_STATUS_CODES = (400, 404, 413, 422)

_MAX_RETRY_AFTER_SECONDS = 300.0


class HTTPTransport(TransportProtocol):
    """
    HTTP transport layer for communicating with FastAPI Guard SaaS platform.
    Includes retry logic, circuit breaker, and rate limiting.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

        self._client: httpx.AsyncClient | None = None
        self._pid = os.getpid()
        self._install_id = resolve_install_id(override=config.install_id)

        self._encryptor: PayloadEncryptor | None = None
        self._encryption_enabled = False
        self._init_encryption()

        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5, recovery_timeout=60.0
        )
        self.rate_limiter = RateLimiter(
            max_calls=100,
            time_window=60.0,
        )

        self.requests_sent = 0
        self.requests_failed = 0
        self.bytes_sent = 0

        self._register_fork_hook()

    def _register_fork_hook(self) -> None:
        """Schedule transport reset after fork; no-op on platforms without fork."""
        register_at_fork = getattr(os, "register_at_fork", None)
        if register_at_fork is None:
            return
        try:
            register_at_fork(after_in_child=self._reset_after_fork)
        except Exception as e:
            self.logger.debug(f"register_at_fork unavailable: {e}")

    def _reset_after_fork(self) -> None:
        """Drop transport state inherited from the parent process."""
        self._client = None
        self._pid = os.getpid()
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5, recovery_timeout=60.0
        )
        self.rate_limiter = RateLimiter(max_calls=100, time_window=60.0)
        self.requests_sent = 0
        self.requests_failed = 0
        self.bytes_sent = 0

    async def _ensure_client_for_current_process(self) -> None:
        """Reinitialize the httpx client if the current pid differs from init pid."""
        current_pid = os.getpid()
        if current_pid != self._pid:
            self._reset_after_fork()
        if self._client is None or self._client.is_closed:
            await self.initialize()

    def _maybe_compress(self, json_text: str) -> tuple[bytes, dict[str, str]]:
        """Return body bytes plus Content-Encoding header when compression applies."""
        raw = json_text.encode("utf-8")
        if (
            not self.config.compression_enabled
            or len(raw) < self.config.compression_threshold
        ):
            return raw, {}
        return gzip.compress(raw), {"Content-Encoding": "gzip"}

    def _init_encryption(self) -> None:
        if not self.config.project_encryption_key:
            return

        try:
            self._encryptor = create_encryptor(self.config.project_encryption_key)
            if not self._encryptor or not self._encryptor.verify_key():
                raise EncryptionConfigError(
                    "Encryption round-trip failed at startup;"
                    " refusing plaintext fallback"
                )
            self._encryption_enabled = True
        except EncryptionConfigError:
            raise
        except Exception as exc:
            raise EncryptionConfigError(
                "Encryption round-trip failed at startup; refusing plaintext fallback"
            ) from exc

    async def initialize(self) -> None:
        """Initialize HTTP client."""
        if self._client and not self._client.is_closed:
            return

        try:
            headers = {
                "User-Agent": f"guard-agent/{_AGENT_VERSION}",
                "Content-Type": "application/json",
                "X-API-Key": self.config.api_key,
                "X-Agent-Install-Id": self._install_id,
            }

            if self.config.project_id:
                headers["X-Project-ID"] = self.config.project_id

            self._client = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(
                    timeout=self.config.timeout,
                    connect=10.0,
                    read=self.config.timeout,
                ),
                limits=httpx.Limits(
                    max_connections=10,
                    max_keepalive_connections=5,
                    keepalive_expiry=30.0,
                ),
                follow_redirects=False,
            )

            self.logger.info("HTTP transport initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize HTTP transport: {str(e)}")
            raise

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _fire_error_hook(
        self, stage: str, exc: BaseException, context: dict[str, Any]
    ) -> None:
        hook = self.config.on_error
        if hook is None:
            return
        try:
            hook(stage, exc, context)
        except Exception as hook_error:
            self.logger.error(
                f"on_error hook raised while handling '{stage}': {hook_error}"
            )

    async def send_events(self, events: list[SecurityEvent]) -> bool:
        """Send security events to the SaaS platform.

        Returns False when the batch was not durably accepted. This now
        includes a permanently-rejected batch (non-retryable 4xx) and a 200
        response that reported partial failure; both are surfaced by
        _send_with_retry as a False result so the caller does not treat the
        batch as delivered.
        """
        if not events:
            return True

        try:
            batch = EventBatch(
                project_id=self.config.project_id or "default",
                events=events,
                batch_id=generate_batch_id(),
                created_at=get_current_timestamp(),
                agent_version=_AGENT_VERSION,
                guard_version=self.config.guard_version,
            )

            return await self._send_with_retry(
                "/api/v1/events", batch.model_dump(), "events"
            )

        except Exception as e:
            self.logger.error(f"Failed to send events: {str(e)}")
            self.requests_failed += 1
            return False

    async def send_metrics(self, metrics: list[SecurityMetric]) -> bool:
        """Send metrics to the SaaS platform."""
        if not metrics:
            return True

        try:
            batch = EventBatch(
                project_id=self.config.project_id or "default",
                metrics=metrics,
                batch_id=generate_batch_id(),
                created_at=get_current_timestamp(),
                agent_version=_AGENT_VERSION,
                guard_version=self.config.guard_version,
            )

            return await self._send_with_retry(
                "/api/v1/metrics", batch.model_dump(), "metrics"
            )

        except Exception as e:
            self.logger.error(f"Failed to send metrics: {str(e)}")
            self.requests_failed += 1
            return False

    async def fetch_dynamic_rules(self) -> DynamicRules | None:
        """Fetch dynamic rules from the SaaS platform."""
        try:
            response_data = await self._get_with_retry("/api/v1/rules")

            if response_data:
                return DynamicRules(**response_data)

            return None

        except Exception as e:
            self.logger.error(f"Failed to fetch dynamic rules: {str(e)}")
            return None

    async def send_status(self, status: AgentStatus) -> bool:
        """Send agent status/health information."""
        try:
            return await self._send_with_retry(
                "/api/v1/status", status.model_dump(), "status"
            )

        except Exception as e:
            self.logger.error(f"Failed to send status: {str(e)}")
            return False

    def _evaluate_send_result(self, result: Any, data_type: str) -> bool | None:
        """Return True (accepted), False (partial failure), or None (retry)."""
        if isinstance(result, dict) and (
            result.get("success") is False or result.get("errors")
        ):
            self.logger.warning(
                f"Server acknowledged {data_type} batch with partial failure: "
                f"success={result.get('success')!r} errors={result.get('errors')!r}"
            )
            self.requests_failed += 1
            return False
        if result:
            self.requests_sent += 1
            self.logger.debug(f"Successfully sent {data_type} batch")
            return True
        self.requests_failed += 1
        return None

    async def _sleep_or_record_giveup(self, attempt: int, delay: float) -> bool:
        """Sleep to retry (return True) or record a final failure (return False)."""
        if attempt < self.config.retry_attempts:
            await asyncio.sleep(delay)
            return True
        self.requests_failed += 1
        return False

    async def _send_with_retry(
        self, endpoint: str, data: dict[str, Any], data_type: str
    ) -> bool:
        """Send data with retry logic and circuit breaker."""
        for attempt in range(self.config.retry_attempts + 1):
            try:
                if not await self.rate_limiter.acquire():
                    retry_after = self.rate_limiter.get_retry_after()
                    self.logger.warning(
                        f"Rate limit exceeded, waiting {retry_after:.1f}s"
                    )
                    await asyncio.sleep(retry_after)
                    continue

                result = await self.circuit_breaker.call(
                    self._make_request, "POST", endpoint, data
                )

                outcome = self._evaluate_send_result(result, data_type)
                if outcome is not None:
                    return outcome

            except RateLimitedError as e:
                delay = min(e.retry_after_seconds, _MAX_RETRY_AFTER_SECONDS)
                self.logger.warning(
                    f"Server rate-limited {data_type}; sleeping {delay:.1f}s "
                    f"per Retry-After"
                )
                await self._sleep_or_record_giveup(attempt, delay)
            except PermanentClientError as e:
                self.logger.error(
                    f"Dropping {data_type} batch; non-retryable {e.status_code} "
                    f"response: {e.detail}"
                )
                self.requests_failed += 1
                self._fire_error_hook(
                    "transport_send", e, {"endpoint": endpoint, "data_type": data_type}
                )
                return False
            except Exception as e:
                self.logger.warning(
                    f"Attempt {attempt + 1} failed for {data_type}: {str(e)}"
                )

                delay = calculate_backoff_delay(attempt, self.config.backoff_factor)
                if not await self._sleep_or_record_giveup(attempt, delay):
                    self.logger.error(f"All retry attempts failed for {data_type}")
                    self._fire_error_hook(
                        "transport_send",
                        e,
                        {"endpoint": endpoint, "data_type": data_type},
                    )

        return False

    async def _get_with_retry(self, endpoint: str) -> dict[str, Any] | None:
        """GET request with retry logic and circuit breaker."""
        for attempt in range(self.config.retry_attempts + 1):
            try:
                if not await self.rate_limiter.acquire():
                    retry_after = self.rate_limiter.get_retry_after()
                    await asyncio.sleep(retry_after)
                    continue

                response_data = await self.circuit_breaker.call(
                    self._make_request, "GET", endpoint, None
                )

                if isinstance(response_data, dict):
                    self.requests_sent += 1
                    return response_data
                else:
                    self.requests_failed += 1

            except RateLimitedError as e:
                delay = min(e.retry_after_seconds, _MAX_RETRY_AFTER_SECONDS)
                self.logger.warning(
                    f"Server rate-limited GET {endpoint}; sleeping {delay:.1f}s "
                    f"per Retry-After"
                )
                if attempt < self.config.retry_attempts:
                    await asyncio.sleep(delay)
                else:
                    self.requests_failed += 1
            except Exception as e:
                self.logger.warning(
                    f"GET attempt {attempt + 1} failed for {endpoint}: {str(e)}"
                )

                if attempt < self.config.retry_attempts:
                    delay = calculate_backoff_delay(attempt, self.config.backoff_factor)
                    await asyncio.sleep(delay)
                else:
                    self.requests_failed += 1

        return None

    _ENCRYPTED_ENDPOINTS = ("/api/v1/events", "/api/v1/metrics")

    async def _make_request(
        self, method: str, endpoint: str, data: dict[str, Any] | None
    ) -> dict[str, Any] | bool:
        """Make HTTP request with proper error handling and optional encryption."""
        await self._ensure_client_for_current_process()

        if not self._client:
            raise Exception("Failed to initialize HTTP client")

        endpoint_base = self.config.endpoint.rstrip("/")
        url = f"{endpoint_base}{endpoint}"
        if (
            method == "POST"
            and data
            and self._encryption_enabled
            and endpoint in self._ENCRYPTED_ENDPOINTS
        ):
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
            if self._encryption_enabled and endpoint in self._ENCRYPTED_ENDPOINTS:
                return await self._post_encrypted(data)
            return await self._post_unencrypted(url, data)
        if method == "GET":
            response = await self._client.get(url)
            return await self._handle_response(response)
        raise ValueError(f"Unsupported method: {method}")

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
            error_text = response.text
            self.logger.error(
                f"Permanent client error {response.status_code} for {response.url}: "
                f"{error_text}"
            )
            raise PermanentClientError(response.status_code, error_text)

        elif response.status_code >= 500:
            error_text = response.text
            raise Exception(f"Server error {response.status_code}: {error_text}")

        else:
            error_text = response.text
            self.logger.error(f"Client error {response.status_code}: {error_text}")
            return False

    def get_stats(self) -> dict[str, Any]:
        """Get transport statistics."""
        return {
            "requests_sent": self.requests_sent,
            "requests_failed": self.requests_failed,
            "bytes_sent": self.bytes_sent,
            "circuit_breaker_state": self.circuit_breaker.state,
            "failure_count": self.circuit_breaker.failure_count,
            "session_closed": self._client.is_closed if self._client else True,
        }
