import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

_logger = logging.getLogger(__name__)
_endpoint_suffix_warned = False

KNOWN_EVENT_TYPES = [
    "ip_banned",
    "ip_unbanned",
    "ip_blocked",
    "ip_ban_failed",
    "rate_limited",
    "rate_limit_script_reloaded",
    "suspicious_request",
    "cloud_blocked",
    "country_blocked",
    "penetration_attempt",
    "behavioral_violation",
    "user_agent_blocked",
    "custom_request_check",
    "decorator_violation",
    "decoding_error",
    "detection_engine_callback_error",
    "geo_lookup_failed",
    "https_enforced",
    "pattern_anomaly_slow_execution",
    "pattern_anomaly_timeout",
    "pattern_anomaly_statistical_anomaly",
    "redis_connection",
    "redis_error",
    "dynamic_rule_applied",
    "dynamic_rule_updated",
    "path_excluded",
    "route_unresolved",
    "pattern_detected",
    "pattern_added",
    "pattern_removed",
    "access_denied",
    "authentication_failed",
    "content_filtered",
    "emergency_mode_activated",
    "emergency_mode_block",
    "dynamic_rule_violation",
    "security_bypass",
    "security_headers_applied",
    "csp_violation",
]


class AgentConfig(BaseModel):
    """Agent configuration following SecurityConfig pattern."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    api_key: str = Field(description="Guard Agent API key")
    endpoint: str = Field(
        default="https://api.guard-core.com", description="Agent endpoint URL"
    )
    project_id: str | None = Field(
        default=None, description="Project ID for organization"
    )

    buffer_size: int = Field(default=100, description="Event buffer size")
    flush_interval: int = Field(
        default=30, description="Buffer flush interval in seconds"
    )
    dynamic_rule_interval: int = Field(
        default=300,
        ge=60,
        description="Interval in seconds between dynamic rule polls",
    )
    status_interval: int = Field(
        default=300,
        ge=60,
        description="Interval in seconds between agent status reports",
    )
    high_watermark_ratio: float = Field(
        default=0.8, description="Buffer occupancy ratio that triggers early flush"
    )
    max_concurrent_flushes: int = Field(
        default=1, description="Maximum concurrent early-flush operations"
    )
    buffer_overflow_policy: Literal["drop", "block", "raise"] = Field(
        default="drop",
        description=(
            "Behavior when the in-memory buffer is full. "
            "'drop' (default) silently evicts the oldest entry. "
            "'block' awaits free space, backpressuring the caller. "
            "'raise' throws BufferFullError so callers can react."
        ),
    )

    enable_metrics: bool = Field(default=True, description="Send performance metrics")
    enable_events: bool = Field(default=True, description="Send security events")

    retry_attempts: int = Field(default=3, description="Number of retry attempts")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    backoff_factor: float = Field(default=1.0, description="Backoff factor for retries")

    sensitive_headers: list[str] = Field(
        default_factory=lambda: [
            "authorization",
            "proxy-authorization",
            "cookie",
            "x-api-key",
        ],
        description="Headers to exclude from telemetry",
    )
    max_payload_size: int = Field(
        default=1024, description="Maximum payload size to include in events (bytes)"
    )

    project_encryption_key: str | None = Field(
        default=None,
        description="Project-specific encryption key for secure telemetry transmission",
    )

    guard_version: str | None = Field(
        default=None,
        description=(
            "Version of the framework integration that wraps this agent "
            "(e.g. fastapi-guard middleware version). The framework adapter "
            "sets this at agent init time so the SaaS can attribute telemetry "
            "to the wrapper version rather than just the agent version."
        ),
    )
    guard_core_version: str | None = Field(
        default=None,
        description=(
            "Version of the guard-core library backing this agent's host "
            "framework. guard-core sets this at agent init time so the SaaS "
            "can identify deployments running a vulnerable guard-core release "
            "independently of the wrapper's own version."
        ),
    )

    compression_enabled: bool = Field(
        default=True,
        description=(
            "Gzip-compress outgoing batch bodies above compression_threshold "
            "bytes. Set to False if your ingestion endpoint does not handle "
            "Content-Encoding: gzip request bodies."
        ),
    )
    compression_threshold: int = Field(
        default=1024,
        description="Minimum body size in bytes before gzip compression applies",
    )

    install_id: str | None = Field(
        default=None,
        description="Override agent install ID (auto-generated if not set)",
    )
    payload_signing_secret: str | None = Field(
        default=None,
        description="HMAC-SHA256 secret for X-Payload-Signature header",
    )

    on_error: Callable[[str, BaseException, dict[str, Any]], None] | None = Field(
        default=None,
        description=(
            "Optional best-effort callback invoked when a transport, encryption, "
            "or flush step fails, receiving (stage, exception, context). stage is "
            "one of 'transport_send' / 'encryption' / 'flush_events' / "
            "'flush_metrics'. A callback that raises is caught and logged, "
            "never propagated."
        ),
    )

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        """Validate that endpoint is a valid URL and strip a legacy /api/v1 suffix."""
        if not v:
            raise ValueError("Endpoint URL cannot be empty")

        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Endpoint must be a valid URL with scheme and domain")

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Endpoint URL must use http or https scheme")

        normalized = v.rstrip("/")
        if normalized.endswith("/api/v1"):
            global _endpoint_suffix_warned
            stripped = normalized[: -len("/api/v1")].rstrip("/")
            if not _endpoint_suffix_warned:
                _logger.warning(
                    "Endpoint %r ends with '/api/v1'; transport already appends "
                    "versioned paths. Stripping suffix to %r. Update your config to "
                    "set the bare host (e.g. 'https://api.guard-core.com').",
                    v,
                    stripped,
                )
                _endpoint_suffix_warned = True
            return stripped

        return normalized


class SecurityEvent(BaseModel):
    """Security event model for telemetry."""

    model_config = ConfigDict(extra="allow")

    idempotency_key: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    event_type: str
    ip_address: str = ""
    country: str | None = None
    user_agent: str | None = None
    action_taken: str = ""
    reason: str = ""
    endpoint: str | None = None
    method: str | None = None
    status_code: int | None = None
    response_time: float | None = None
    decorator_type: str | None = None
    rule_type: str | None = None
    pattern_matched: str | None = None
    handler_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityMetric(BaseModel):
    """Performance and usage metrics."""

    timestamp: datetime
    metric_type: Literal[
        "request_count",
        "response_time",
        "error_rate",
        "bandwidth_usage",
        "threat_level",
        "block_rate",
        "cache_hit_rate",
    ]
    value: float
    endpoint: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class DynamicRules(BaseModel):
    """Dynamic rules received from SaaS platform."""

    rule_id: str = Field(default="default-rule", description="Unique rule ID")
    version: int = Field(default=1, description="Rule version number")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Rule creation/update timestamp",
    )
    expires_at: datetime | None = Field(
        default=None, description="Rule expiration time"
    )
    ttl: int = Field(default=300, description="Cache TTL in seconds")

    ip_blacklist: list[str] = Field(default_factory=list, description="IPs to ban")
    ip_whitelist: list[str] = Field(default_factory=list, description="IPs to allow")
    ip_ban_duration: int = Field(default=3600, description="Ban duration in seconds")

    blocked_countries: list[str] = Field(
        default_factory=list, description="Countries to block"
    )
    whitelist_countries: list[str] = Field(
        default_factory=list, description="Countries to allow"
    )

    global_rate_limit: int | None = Field(default=None, description="Global rate limit")
    global_rate_window: int | None = Field(
        default=None, description="Global rate window"
    )
    endpoint_rate_limits: dict[str, tuple[int, int]] = Field(
        default_factory=dict,
        description="Per-endpoint rate limits {endpoint: (requests, window)}",
    )

    blocked_cloud_providers: set[str] = Field(
        default_factory=set, description="Cloud providers to block"
    )

    blocked_user_agents: list[str] = Field(
        default_factory=list, description="User agents to block"
    )

    suspicious_patterns: list[str] = Field(
        default_factory=list, description="Additional suspicious patterns"
    )

    enable_penetration_detection: bool | None = Field(
        default=None, description="Override penetration detection setting"
    )
    enable_ip_banning: bool | None = Field(
        default=None, description="Override IP banning setting"
    )
    enable_rate_limiting: bool | None = Field(
        default=None, description="Override rate limiting setting"
    )
    auto_ban_threshold: int | None = Field(
        default=None, ge=1, description="Override auto-ban threshold setting"
    )
    auto_ban_duration: int | None = Field(
        default=None, ge=1, description="Override auto-ban duration setting"
    )
    enable_rate_limit_auto_ban: bool | None = Field(
        default=None, description="Override rate-limit auto-ban setting"
    )

    emergency_mode: bool = Field(default=False, description="Emergency lockdown mode")
    emergency_whitelist: list[str] = Field(
        default_factory=list, description="Emergency whitelist IPs"
    )
    emergency_whitelist_only: bool = Field(
        default=False, description="Only allow emergency whitelist IPs"
    )
    message: str | None = Field(
        default=None, description="Optional rule message from server"
    )


class AgentStatus(BaseModel):
    """Agent health and status information."""

    timestamp: datetime
    status: Literal["healthy", "degraded", "failed"]
    uptime: float
    events_sent: int
    events_failed: int
    buffer_size: int
    last_flush: datetime | None = None
    errors: list[str] = Field(default_factory=list)


class EventBatch(BaseModel):
    """Batch of events/metrics for efficient transmission."""

    project_id: str
    events: list[SecurityEvent] = Field(default_factory=list)
    metrics: list[SecurityMetric] = Field(default_factory=list)
    batch_id: str
    created_at: datetime
    compressed: bool = Field(default=False)
    agent_version: str | None = Field(default=None, description="Agent version string")
    guard_version: str | None = Field(
        default=None, description="Framework integration version (e.g. fastapi-guard)"
    )
    guard_core_version: str | None = Field(
        default=None, description="guard-core library version backing this agent"
    )
