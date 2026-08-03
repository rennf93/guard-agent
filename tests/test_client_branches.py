from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_agent.client import GuardAgentHandler
from guard_agent.exceptions import PayloadTooLargeError
from guard_agent.models import AgentConfig, SecurityEvent
from guard_agent.transport import HTTPTransport


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    GuardAgentHandler._instance = None
    yield
    GuardAgentHandler._instance = None


@pytest.mark.asyncio
async def test_get_dynamic_rules_returns_none_when_fetch_returns_none(
    agent_config: AgentConfig,
) -> None:
    handler = GuardAgentHandler(agent_config)
    handler.transport = AsyncMock()
    handler.transport.fetch_dynamic_rules.return_value = None

    result = await handler.get_dynamic_rules()

    assert result is None
    assert handler._cached_rules is None
    assert handler.rules_fetched == 0


@pytest.mark.asyncio
async def test_flush_buffer_no_events_no_metrics(agent_config: AgentConfig) -> None:
    handler = GuardAgentHandler(agent_config)
    handler.buffer = AsyncMock()
    handler.transport = AsyncMock()
    handler.buffer.flush_events_with_keys.return_value = ([], [])
    handler.buffer.flush_metrics_with_keys.return_value = ([], [])

    await handler.flush_buffer()

    handler.transport.send_events.assert_not_called()
    handler.transport.send_metrics.assert_not_called()
    assert handler.events_sent == 0
    assert handler.metrics_sent == 0


@pytest.mark.asyncio
async def test_flush_buffer_no_events_with_metrics(agent_config: AgentConfig) -> None:
    handler = GuardAgentHandler(agent_config)
    handler.buffer = AsyncMock()
    handler.transport = AsyncMock()
    handler.buffer.flush_events_with_keys.return_value = ([], [])
    handler.buffer.flush_metrics_with_keys.return_value = ([MagicMock()], ["mk1"])
    handler.transport.send_metrics.return_value = True

    await handler.flush_buffer()

    handler.transport.send_events.assert_not_called()
    handler.transport.send_metrics.assert_called_once()
    assert handler.metrics_sent == 1


@pytest.mark.asyncio
async def test_get_status_failure_rate_below_threshold(
    agent_config: AgentConfig,
) -> None:
    handler = GuardAgentHandler(agent_config)
    handler.buffer = AsyncMock()
    handler.buffer.get_buffer_size.return_value = 1
    handler.buffer.get_stats = MagicMock(return_value={"last_flush_time": None})
    handler.transport = AsyncMock()
    handler.transport.get_stats = MagicMock(
        return_value={"circuit_breaker_state": "CLOSED"}
    )
    handler.events_failed = 1
    handler.metrics_failed = 0
    handler.events_sent = 100
    handler.metrics_sent = 100

    status = await handler.get_status()

    assert status.status == "healthy"
    assert not any("High failure rate" in e for e in status.errors)


@pytest.mark.asyncio
async def test_status_loop_running_false_after_sleep_skips_status(
    agent_config: AgentConfig,
) -> None:
    handler = GuardAgentHandler(agent_config)
    handler._running = True
    handler.transport = AsyncMock()

    call_count = 0

    async def mock_sleep(_: float) -> None:
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            handler._running = False

    with patch("guard_agent.client.asyncio.sleep", side_effect=mock_sleep):
        with patch.object(handler, "get_status", new_callable=AsyncMock) as mock_status:
            await handler._status_loop()
            mock_status.assert_not_called()


@pytest.mark.asyncio
async def test_rules_loop_running_false_after_sleep_skips_rules(
    agent_config: AgentConfig,
) -> None:
    handler = GuardAgentHandler(agent_config)
    handler._running = True

    call_count = 0

    async def mock_sleep(_: float) -> None:
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            handler._running = False

    with patch("guard_agent.client.asyncio.sleep", side_effect=mock_sleep):
        with patch.object(
            handler, "get_dynamic_rules", new_callable=AsyncMock
        ) as mock_rules:
            await handler._rules_loop()
            mock_rules.assert_not_called()


@pytest.mark.asyncio
async def test_health_check_true_when_no_attempts(agent_config: AgentConfig) -> None:
    handler = GuardAgentHandler(agent_config)
    handler._running = True
    handler.buffer = AsyncMock()
    handler.buffer.get_buffer_size = AsyncMock(return_value=1)
    handler.transport = MagicMock()
    handler.transport.get_stats = MagicMock(
        return_value={"circuit_breaker_state": "CLOSED"}
    )
    handler.events_sent = 0
    handler.metrics_sent = 0
    handler.events_failed = 0
    handler.metrics_failed = 0

    result = await handler.health_check()

    assert result is True


@pytest.mark.asyncio
async def test_flush_events_413_drop_does_not_requeue_and_confirms_redis(
    agent_config: AgentConfig,
) -> None:
    from datetime import datetime, timezone

    agent_config.retry_attempts = 0
    transport = HTTPTransport(agent_config)
    transport._client = AsyncMock()

    async def fake_make_request(method, endpoint, data):
        raise PayloadTooLargeError("too big")

    with patch.object(transport, "_make_request", side_effect=fake_make_request):
        handler = GuardAgentHandler(agent_config)
        handler.transport = transport
        handler.buffer = AsyncMock()
        handler.buffer.requeue_events_in_memory = MagicMock()
        handler.buffer.flush_metrics_with_keys.return_value = ([], [])

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="1.1.1.1",
                action_taken="banned",
                reason="x",
            )
        ]
        event_keys = ["ek1"]
        handler.buffer.flush_events_with_keys.return_value = (events, event_keys)

        await handler.flush_buffer()

    handler.buffer.confirm_event_redis_keys.assert_awaited_once_with(event_keys)
    handler.buffer.requeue_events_in_memory.assert_not_called()
    assert handler.events_sent == len(events)
    assert handler.events_failed == 0
    assert handler._events_failure_streak == 0


@pytest.mark.asyncio
async def test_flush_metrics_permanent_rejection_does_not_requeue(
    agent_config: AgentConfig,
) -> None:
    handler = GuardAgentHandler(agent_config)
    handler.buffer = AsyncMock()
    handler.transport = AsyncMock()
    handler.buffer.requeue_metrics_in_memory = MagicMock()
    handler.buffer.flush_events_with_keys.return_value = ([], [])

    metrics = [MagicMock()]
    metric_keys = ["mk1"]
    handler.buffer.flush_metrics_with_keys.return_value = (metrics, metric_keys)
    handler.transport.send_metrics.return_value = True

    await handler.flush_buffer()

    handler.buffer.confirm_metric_redis_keys.assert_awaited_once_with(metric_keys)
    handler.buffer.requeue_metrics_in_memory.assert_not_called()
    assert handler.metrics_sent == len(metrics)
    assert handler.metrics_failed == 0
