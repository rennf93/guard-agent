import hashlib
import json
import logging
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from guard_agent.exceptions import PermanentClientError
from guard_agent.models import AgentConfig


class RateLimitedError(Exception):
    """Raised on HTTP 429; carries server-supplied Retry-After in seconds."""

    def __init__(self, retry_after_seconds: float, message: str | None = None):
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            message or f"Rate limited by server, retry after {retry_after_seconds:.1f}s"
        )


def parse_retry_after_seconds(header_value: str | None, default: float = 60.0) -> float:
    """Parse RFC 7231 Retry-After header (integer seconds) into a float."""
    if header_value is None:
        return default
    try:
        value = float(header_value)
    except (TypeError, ValueError):
        return default
    return max(0.0, value)


def generate_batch_id() -> str:
    """Generate a unique batch ID for event batches."""
    timestamp = str(int(time.time() * 1000))
    random_part = uuid.uuid4().hex[:8]
    return f"{timestamp}-{random_part}"


def sanitize_headers(
    headers: dict[str, str], sensitive_headers: list[str]
) -> dict[str, str]:
    """Remove sensitive headers from telemetry data."""
    sanitized = {}
    for key, value in headers.items():
        if key.lower() in [h.lower() for h in sensitive_headers]:
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = value
    return sanitized


def truncate_payload(payload: str, max_size: int) -> str:
    """Truncate payload to maximum size with indicator."""
    if len(payload) <= max_size:
        return payload
    return payload[:max_size] + "...[TRUNCATED]"


def summarize_response_body(text: str, max_length: int = 300) -> str:
    """Collapse an HTTP response body into a bounded, single-line summary.

    Handles HTML/plain-text error pages as well as JSON: whitespace (including
    newlines) is collapsed so one response body can never span more than one
    log line, and the summary is capped at max_length characters with the
    original length noted when truncated.
    """
    collapsed = " ".join(text.split())
    if len(collapsed) <= max_length:
        return collapsed
    return f"{collapsed[:max_length]}... [truncated, {len(text)} chars total]"


def hash_ip(ip: str, salt: str = "") -> str:
    """Hash IP address for privacy-conscious telemetry."""
    combined = f"{ip}{salt}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def get_current_timestamp() -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(timezone.utc)


def calculate_backoff_delay(
    attempt: int, base_delay: float = 1.0, max_delay: float = 60.0
) -> float:
    """Calculate exponential backoff delay."""
    delay = base_delay * float(2**attempt)
    return min(delay, max_delay)


class SerializationError(Exception):
    """Raised when an object cannot be serialized to JSON for transport."""


async def safe_json_serialize(obj: Any) -> str:
    """Serialize object to JSON; raise SerializationError on failure."""
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        logging.warning(f"Failed to serialize object: {str(e)}")
        raise SerializationError(str(e)) from e


async def safe_json_deserialize(json_str: str) -> dict[str, Any] | None:
    """Safely deserialize JSON string with error handling."""
    try:
        result = json.loads(json_str)
        if isinstance(result, dict):
            return result
        return None
    except (TypeError, ValueError, json.JSONDecodeError) as e:
        logging.warning(f"Failed to deserialize JSON: {str(e)}")
        return None


def validate_config(config: AgentConfig) -> list[str]:
    """Validate agent configuration and return list of errors."""
    errors = []

    if not config.api_key or len(config.api_key) < 10:
        errors.append("api_key must be at least 10 characters long")

    if not config.endpoint.startswith(("http://", "https://")):
        errors.append("endpoint must be a valid HTTP/HTTPS URL")

    if config.buffer_size <= 0:
        errors.append("buffer_size must be greater than 0")

    if config.flush_interval <= 0:
        errors.append("flush_interval must be greater than 0")

    if config.timeout <= 0:
        errors.append("timeout must be greater than 0")

    if config.retry_attempts < 0:
        errors.append("retry_attempts cannot be negative")

    if config.backoff_factor <= 0:
        errors.append("backoff_factor must be greater than 0")

    return errors


class RateLimiter:
    """Simple rate limiter for agent operations."""

    def __init__(self, max_calls: int, time_window: float):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls: list[float] = []

    async def acquire(self) -> bool:
        """Check if operation is allowed under rate limit."""
        now = time.time()

        self.calls = [
            call_time for call_time in self.calls if now - call_time < self.time_window
        ]

        if len(self.calls) < self.max_calls:
            self.calls.append(now)
            return True

        return False

    def get_retry_after(self) -> float:
        """Get seconds to wait before next allowed call."""
        if not self.calls:
            return 0.0

        oldest_call = min(self.calls)
        return max(0.0, self.time_window - (time.time() - oldest_call))


class CircuitBreaker:
    """Circuit breaker for transport reliability."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.state = "CLOSED"

    async def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Execute function with circuit breaker protection."""
        if self.state == "OPEN":
            if (
                self.last_failure_time
                and time.time() - self.last_failure_time > self.recovery_timeout
            ):
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except PermanentClientError:
            raise
        except Exception as e:
            await self._on_failure()
            raise e

    async def _on_success(self) -> None:
        """Handle successful operation."""
        self.failure_count = 0
        self.state = "CLOSED"

    async def _on_failure(self) -> None:
        """Handle failed operation."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
