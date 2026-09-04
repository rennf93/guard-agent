import logging
import os
from typing import Any

import httpx

from guard_agent._version import __version__ as _AGENT_VERSION
from guard_agent.encryption import (
    EncryptionConfigError,
    PayloadEncryptor,
    create_encryptor,
)
from guard_agent.models import AgentConfig
from guard_agent.utils import CircuitBreaker, RateLimiter, fire_error_hook


class TransportLifecycleMixin:
    config: AgentConfig
    logger: logging.Logger
    _client: httpx.AsyncClient | None
    _pid: int
    _install_id: str
    _encryptor: PayloadEncryptor | None
    _encryption_enabled: bool
    circuit_breaker: CircuitBreaker
    rate_limiter: RateLimiter
    requests_sent: int
    requests_failed: int
    bytes_sent: int

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
        fire_error_hook(self.config.on_error, self.logger, stage, exc, context)

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
