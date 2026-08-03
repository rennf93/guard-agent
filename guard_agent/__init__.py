"""
Guard Agent — framework-agnostic telemetry agent for the Guard ecosystem.

Provides telemetry capabilities for the Guard adapters (``fastapi-guard``,
``flaskapi-guard``, ``djangoapi-guard``, ``tornadoapi-guard``), enabling
monitoring, analytics, and dynamic rule management through a centralized
management platform.
"""

import logging
from typing import Any, cast

from guard_agent._version import __version__
from guard_agent.buffer import EventBuffer
from guard_agent.client import GuardAgentHandler, SyncGuardAgentHandler, guard_agent
from guard_agent.exceptions import BufferFullError, GuardAgentError
from guard_agent.models import (
    AgentConfig,
    AgentStatus,
    DynamicRules,
    EventBatch,
    SecurityEvent,
    SecurityMetric,
)
from guard_agent.protocols import (
    AgentHandlerProtocol,
    BufferProtocol,
    RedisHandlerProtocol,
    TransportProtocol,
)
from guard_agent.transport import HTTPTransport
from guard_agent.utils import (
    CircuitBreaker,
    RateLimiter,
    generate_batch_id,
    get_current_timestamp,
    hash_ip,
    sanitize_headers,
    setup_agent_logging,
    truncate_payload,
    validate_config,
)

__all__ = [
    "guard_agent",
    "GuardAgentHandler",
    "SyncGuardAgentHandler",
    "AgentConfig",
    "SecurityEvent",
    "SecurityMetric",
    "DynamicRules",
    "AgentStatus",
    "EventBatch",
    "EventBuffer",
    "BufferFullError",
    "GuardAgentError",
    "HTTPTransport",
    "AgentHandlerProtocol",
    "TransportProtocol",
    "BufferProtocol",
    "RedisHandlerProtocol",
    "generate_batch_id",
    "get_current_timestamp",
    "hash_ip",
    "sanitize_headers",
    "truncate_payload",
    "validate_config",
    "setup_agent_logging",
    "RateLimiter",
    "CircuitBreaker",
    "__version__",
]


def _mute_pydantic_plugin_instrumentation() -> None:
    """Opt guard-agent's hot-path telemetry models out of pydantic plugin
    instrumentation (e.g. logfire.instrument_pydantic()).

    SecurityEvent/SecurityMetric are validated per request and EventBatch
    re-validates every buffered event on each flush, so an instrumented host
    app would otherwise emit a span per security event. plugin_settings is
    only read while building a model's validator, hence the forced rebuild.
    Idempotent: guard-core applies the same mute to the same models; setting
    the same plugin_settings and re-rebuilding is harmless.
    """
    try:
        from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric
    except ImportError:
        return
    try:
        for model in (SecurityEvent, SecurityMetric, EventBatch):
            plugin_settings = cast(
                "dict[str, Any]",
                model.model_config.setdefault("plugin_settings", {}),
            )
            plugin_settings["logfire"] = {"record": "off"}
            model.model_rebuild(force=True)
    except Exception:
        logging.getLogger("guard_agent").warning(
            "Could not opt guard-agent telemetry models out of pydantic "
            "plugin instrumentation",
            exc_info=True,
        )


_mute_pydantic_plugin_instrumentation()
