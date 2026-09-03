import time
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock

import pytest

from guard_agent.client import GuardAgentHandler
from guard_agent.models import AgentConfig


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    GuardAgentHandler._instance = None
    yield
    GuardAgentHandler._instance = None


class TestPartialFailureBackoff:
    """A quota-exceeded 200 must back off, not retry every flush forever."""

    @pytest.mark.asyncio
    async def test_backs_off_instead_of_retrying_every_flush(
        self, agent_config: AgentConfig
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_events_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_metrics_with_keys.return_value = ([], [])

        events = [MagicMock()]
        handler.buffer.flush_events_with_keys.return_value = (events, ["ek"])
        handler.transport.send_events.return_value = False

        await handler.flush_buffer()
        await handler.flush_buffer()
        await handler.flush_buffer()

        assert handler.transport.send_events.call_count == 1
        assert handler.buffer.flush_events_with_keys.call_count == 1

    @pytest.mark.asyncio
    async def test_condition_logged_once_not_per_flush(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_events_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_metrics_with_keys.return_value = ([], [])

        events = [MagicMock()]
        handler.buffer.flush_events_with_keys.return_value = (events, ["ek"])
        handler.transport.send_events.return_value = False

        for _ in range(5):
            await handler.flush_buffer()

        assert caplog.text.count("Failed to send 1 events") == 1

    @pytest.mark.asyncio
    async def test_success_after_partial_failure_resets_backoff_and_logs_once(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_events_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_metrics_with_keys.return_value = ([], [])

        events = [MagicMock()]
        handler.buffer.flush_events_with_keys.return_value = (events, ["ek"])
        handler.transport.send_events.return_value = False

        await handler.flush_buffer()
        assert handler._events_failure_streak == 1
        assert handler._events_retry_after > 0.0

        handler._events_retry_after = 0.0
        handler.transport.send_events.return_value = True

        await handler.flush_buffer()

        assert handler._events_failure_streak == 0
        assert handler._events_retry_after == 0.0
        assert caplog.text.count("recovered after") == 1

    @pytest.mark.asyncio
    async def test_events_are_preserved_not_dropped_during_backoff(
        self, agent_config: AgentConfig
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_events_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_metrics_with_keys.return_value = ([], [])

        events = [MagicMock()]
        handler.buffer.flush_events_with_keys.return_value = (events, ["ek"])
        handler.transport.send_events.return_value = False

        await handler.flush_buffer()
        handler.buffer.requeue_events_in_memory.assert_called_once_with(events, ["ek"])

        await handler.flush_buffer()
        await handler.flush_buffer()

        handler.buffer.requeue_events_in_memory.assert_called_once()
        handler.buffer.flush_events_with_keys.assert_called_once()
        assert handler.events_failed == len(events)

    @pytest.mark.asyncio
    async def test_backoff_grows_exponentially_and_caps_at_configured_max(
        self, agent_config: AgentConfig
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_events_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_metrics_with_keys.return_value = ([], [])

        events = [MagicMock()]
        handler.buffer.flush_events_with_keys.return_value = (events, ["ek"])
        handler.transport.send_events.return_value = False

        delays = []
        for _ in range(4):
            handler._events_retry_after = 0.0
            before = time.time()
            await handler.flush_buffer()
            delays.append(handler._events_retry_after - before)

        assert delays[0] == pytest.approx(1.0, abs=0.2)
        assert delays[1] == pytest.approx(2.0, abs=0.2)
        assert delays[2] == pytest.approx(4.0, abs=0.2)
        assert delays[3] == pytest.approx(8.0, abs=0.2)

    @pytest.mark.asyncio
    async def test_metrics_partial_failure_also_backs_off(
        self, agent_config: AgentConfig
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_metrics_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_events_with_keys.return_value = ([], [])

        metrics = [MagicMock()]
        handler.buffer.flush_metrics_with_keys.return_value = (metrics, ["mk"])
        handler.transport.send_metrics.return_value = False

        await handler.flush_buffer()
        await handler.flush_buffer()

        assert handler.transport.send_metrics.call_count == 1
        assert handler._metrics_failure_streak == 1

    @pytest.mark.asyncio
    async def test_metrics_recovered_log_and_reset(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_metrics_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_events_with_keys.return_value = ([], [])

        metrics = [MagicMock()]
        handler.buffer.flush_metrics_with_keys.return_value = (metrics, ["mk"])
        handler.transport.send_metrics.return_value = False

        await handler.flush_buffer()
        assert handler._metrics_failure_streak == 1

        handler._metrics_retry_after = 0.0
        handler.transport.send_metrics.return_value = True

        await handler.flush_buffer()

        assert handler._metrics_failure_streak == 0
        assert handler._metrics_retry_after == 0.0
        assert caplog.text.count("recovered after") == 1

    @pytest.mark.asyncio
    async def test_metrics_failure_log_not_repeated_across_consecutive_attempts(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        handler.buffer.requeue_metrics_in_memory = AsyncMock(return_value=[])
        handler.buffer.flush_events_with_keys.return_value = ([], [])

        metrics = [MagicMock()]
        handler.buffer.flush_metrics_with_keys.return_value = (metrics, ["mk"])
        handler.transport.send_metrics.return_value = False

        await handler.flush_buffer()
        handler._metrics_retry_after = 0.0
        await handler.flush_buffer()

        assert handler._metrics_failure_streak == 2
        assert caplog.text.count("Failed to send 1 metrics") == 1
