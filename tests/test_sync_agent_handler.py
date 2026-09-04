from __future__ import annotations

import json
import time
from collections.abc import Generator
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_agent.client import GuardAgentHandler, SyncGuardAgentHandler
from guard_agent.models import AgentConfig, DynamicRules, SecurityEvent


@pytest.fixture(autouse=True)
def reset_singletons() -> Generator[None, None, None]:
    GuardAgentHandler._instance = None
    SyncGuardAgentHandler._instance = None
    yield
    sync_instance: SyncGuardAgentHandler | None = SyncGuardAgentHandler._instance
    GuardAgentHandler._instance = None
    SyncGuardAgentHandler._instance = None
    if sync_instance is not None:
        if not sync_instance._loop.is_closed():
            sync_instance._loop.call_soon_threadsafe(sync_instance._loop.stop)
            sync_instance._thread.join(timeout=2)
            sync_instance._loop.close()


@pytest.fixture
def sync_handler(agent_config: AgentConfig) -> SyncGuardAgentHandler:
    return SyncGuardAgentHandler(agent_config)


def test_sync_handler_singleton(agent_config: AgentConfig) -> None:
    h1 = SyncGuardAgentHandler(agent_config)
    h2 = SyncGuardAgentHandler(agent_config)
    assert h1 is h2


def test_sync_handler_stop(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    inner = sync_handler._inner
    inner.transport = AsyncMock()
    inner.buffer = AsyncMock()
    inner.buffer.flush_events_with_keys = AsyncMock(return_value=([], []))
    inner.buffer.flush_metrics_with_keys = AsyncMock(return_value=([], []))
    inner.buffer.stop_auto_flush = AsyncMock()
    inner._running = False

    sync_handler.stop()

    inner.transport.close.assert_awaited_once()


def test_sync_handler_flush_buffer(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    inner = sync_handler._inner
    inner.buffer = AsyncMock()
    inner.transport = AsyncMock()
    inner.buffer.flush_events_with_keys = AsyncMock(return_value=([], []))
    inner.buffer.flush_metrics_with_keys = AsyncMock(return_value=([], []))

    sync_handler.flush_buffer()

    inner.buffer.flush_events_with_keys.assert_awaited_once()


def test_sync_handler_get_dynamic_rules_cached(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    inner = sync_handler._inner
    rules = DynamicRules(ttl=3600, version=1)
    inner._cached_rules = rules
    inner._rules_last_update = time.time()
    inner.transport = AsyncMock()

    result = sync_handler.get_dynamic_rules()

    assert result is rules
    inner.transport.fetch_dynamic_rules.assert_not_awaited()


def test_sync_handler_get_dynamic_rules_none(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    inner = sync_handler._inner
    inner._cached_rules = None
    inner.transport = AsyncMock()
    inner.transport.fetch_dynamic_rules = AsyncMock(return_value=None)

    result = sync_handler.get_dynamic_rules()

    assert result is None


def test_sync_handler_health_check_not_running(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    inner = sync_handler._inner
    inner._running = False

    result = sync_handler.health_check()

    assert result is False


def test_sync_handler_health_check_running(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    inner = sync_handler._inner
    inner._running = True
    inner.buffer = AsyncMock()
    inner.buffer.get_buffer_size = AsyncMock(return_value=1)
    inner.transport = MagicMock()
    inner.transport.get_stats = MagicMock(
        return_value={"circuit_breaker_state": "CLOSED"}
    )
    inner.events_sent = 10
    inner.metrics_sent = 0
    inner.events_failed = 0
    inner.metrics_failed = 0

    result = sync_handler.health_check()

    assert result is True


def test_sync_handler_get_stats(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    inner = sync_handler._inner
    inner.buffer = MagicMock()
    inner.buffer.get_stats = MagicMock(return_value={})
    inner.transport = MagicMock()
    inner.transport.get_stats = MagicMock(return_value={})

    stats = sync_handler.get_stats()

    assert "running" in stats
    assert "events_sent" in stats


def test_sync_handler_redacts_sensitive_headers_before_transport(
    sync_handler: SyncGuardAgentHandler,
    agent_config: AgentConfig,
    mock_client: AsyncMock,
) -> None:
    agent_config.sensitive_headers = ["authorization", "x-custom-secret"]
    inner = sync_handler._inner
    inner.transport._client = mock_client
    event = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        event_type="ip_banned",
        ip_address="192.168.1.1",
        action_taken="banned",
        reason="test",
        metadata={
            "Authorization": "Bearer super-secret-token",
            "X-Custom-Secret": "super-secret-custom",
            "User-Agent": "Mozilla/5.0",
        },
    )

    sync_handler.send_event(event)
    sync_handler.flush_buffer()

    body = mock_client.post.call_args.kwargs["content"]
    payload = json.loads(body)
    metadata = payload["events"][0]["metadata"]
    assert metadata["Authorization"] == "[REDACTED]"
    assert metadata["X-Custom-Secret"] == "[REDACTED]"
    assert metadata["User-Agent"] == "Mozilla/5.0"
    assert "super-secret" not in body.decode()


def test_sync_handler_stop_thread_already_dead(
    sync_handler: SyncGuardAgentHandler,
) -> None:
    from unittest.mock import patch

    inner = sync_handler._inner
    inner.transport = AsyncMock()
    inner.buffer = AsyncMock()
    inner.buffer.flush_events_with_keys = AsyncMock(return_value=([], []))
    inner.buffer.flush_metrics_with_keys = AsyncMock(return_value=([], []))
    inner.buffer.stop_auto_flush = AsyncMock()
    inner._running = False

    with patch.object(sync_handler._thread, "is_alive", return_value=False):
        sync_handler.stop()

    inner.transport.close.assert_awaited_once()
