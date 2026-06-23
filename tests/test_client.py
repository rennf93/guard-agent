import asyncio
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_agent.client import GuardAgentHandler, guard_agent
from guard_agent.models import (
    AgentConfig,
    AgentStatus,
    DynamicRules,
    SecurityEvent,
    SecurityMetric,
)
from guard_agent.protocols import AgentHandlerProtocol


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    """Reset GuardAgentHandler singleton before each test."""
    GuardAgentHandler._instance = None
    yield


class TestGuardAgentHandler:
    """Tests for GuardAgentHandler class."""

    def test_singleton_pattern(self, agent_config: AgentConfig) -> None:
        """Test that GuardAgentHandler follows singleton pattern."""
        handler1 = GuardAgentHandler(agent_config)
        handler2 = GuardAgentHandler(agent_config)

        assert handler1 is handler2

    def test_singleton_reinitialization_updates_config(
        self, agent_config: AgentConfig
    ) -> None:
        """Test that re-initializing the singleton updates the config."""
        handler1 = GuardAgentHandler(agent_config)
        assert handler1.config.buffer_size == 10

        new_config = agent_config.model_copy(update={"buffer_size": 20})
        handler2 = GuardAgentHandler(new_config)

        assert handler1 is handler2
        assert handler1.config.buffer_size == 20

    def test_factory_function(self, agent_config: AgentConfig) -> None:
        """Test the guard_agent factory function returns a singleton."""
        from guard_agent.client import SyncGuardAgentHandler

        handler1 = guard_agent(agent_config)
        handler2 = guard_agent(agent_config)

        assert handler1 is handler2
        assert isinstance(handler1, (GuardAgentHandler, SyncGuardAgentHandler))

    @pytest.mark.asyncio
    async def test_initialize_redis(
        self, agent_config: AgentConfig, mock_redis_handler: AsyncMock
    ) -> None:
        """Test Redis initialization."""
        handler = GuardAgentHandler(agent_config)

        await handler.initialize_redis(mock_redis_handler)

        assert handler.redis_handler is mock_redis_handler

    @pytest.mark.asyncio
    async def test_send_event(self, agent_config: AgentConfig) -> None:
        """Test sending security events."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="192.168.1.1",
            action_taken="banned",
            reason="test",
        )
        await handler.send_event(event)
        handler.buffer.add_event.assert_called_once_with(event)

    @pytest.mark.asyncio
    async def test_send_event_disabled(self, agent_config: AgentConfig) -> None:
        """Test send_event when events are disabled."""
        config = agent_config.model_copy(update={"enable_events": False})
        handler = GuardAgentHandler(config)
        handler.buffer = AsyncMock()
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="1.1.1.1",
            action_taken="block",
            reason="test",
        )

        await handler.send_event(event)
        handler.buffer.add_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_event_buffering_error(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test error handling when buffering an event fails."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.add_event.side_effect = Exception("Buffer is full")
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="1.1.1.1",
            action_taken="block",
            reason="test",
        )

        await handler.send_event(event)
        assert "Failed to buffer event: Buffer is full" in caplog.text

    @pytest.mark.asyncio
    async def test_send_metric(self, agent_config: AgentConfig) -> None:
        """Test sending metrics."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        metric = SecurityMetric(
            timestamp=datetime.now(timezone.utc),
            metric_type="request_count",
            value=42.0,
        )
        await handler.send_metric(metric)
        handler.buffer.add_metric.assert_called_once_with(metric)

    @pytest.mark.asyncio
    async def test_send_metric_disabled(self, agent_config: AgentConfig) -> None:
        """Test send_metric when metrics are disabled."""
        config = agent_config.model_copy(update={"enable_metrics": False})
        handler = GuardAgentHandler(config)
        handler.buffer = AsyncMock()
        metric = SecurityMetric(
            timestamp=datetime.now(timezone.utc), metric_type="request_count", value=1
        )

        await handler.send_metric(metric)
        handler.buffer.add_metric.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_metric_buffering_error(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test error handling when buffering a metric fails."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.add_metric.side_effect = Exception("Buffer is full")
        metric = SecurityMetric(
            timestamp=datetime.now(timezone.utc), metric_type="request_count", value=1
        )

        await handler.send_metric(metric)
        assert "Failed to buffer metric: Buffer is full" in caplog.text

    @pytest.mark.asyncio
    async def test_get_status(self, agent_config: AgentConfig) -> None:
        """Test getting agent status."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.get_buffer_size.return_value = 5
        handler.buffer.get_stats = MagicMock(return_value={"last_flush_time": None})
        handler.transport = AsyncMock()
        handler.transport.get_stats = MagicMock(
            return_value={"circuit_breaker_state": "CLOSED"}
        )

        status = await handler.get_status()

        assert isinstance(status, AgentStatus)
        assert status.status == "healthy"
        assert status.buffer_size == 5

    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, agent_config: AgentConfig) -> None:
        """Test agent start/stop lifecycle."""
        handler = GuardAgentHandler(agent_config)
        handler.transport = AsyncMock()
        handler.buffer = AsyncMock()

        await handler.start()
        assert handler._running is True
        assert handler._flush_task is not None
        assert handler._status_task is not None
        assert handler._rules_task is not None

        transport = handler.transport
        buffer = handler.buffer
        await handler.stop()
        running_after_stop: bool = handler._running
        assert not running_after_stop
        transport.close.assert_called_once()
        buffer.stop_auto_flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_calls_flush(self, agent_config: AgentConfig) -> None:
        """Test that stop() calls flush_buffer()."""
        handler = GuardAgentHandler(agent_config)
        handler.transport = AsyncMock()
        handler.buffer = AsyncMock()

        await handler.start()

        with patch.object(
            handler, "flush_buffer", new_callable=AsyncMock
        ) as mock_flush:
            await handler.stop()
            mock_flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_flush_buffer(self, agent_config: AgentConfig) -> None:
        """Test manual buffer flush."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.transport = AsyncMock()
        test_events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]
        test_metrics = [
            SecurityMetric(
                timestamp=datetime.now(timezone.utc),
                metric_type="request_count",
                value=1.0,
            )
        ]
        handler.buffer.flush_events_with_keys.return_value = (test_events, ["ek1"])
        handler.buffer.flush_metrics_with_keys.return_value = (test_metrics, ["mk1"])
        handler.transport.send_events.return_value = True
        handler.transport.send_metrics.return_value = True

        await handler.flush_buffer()

        handler.buffer.flush_events_with_keys.assert_called_once()
        handler.buffer.flush_metrics_with_keys.assert_called_once()
        handler.transport.send_events.assert_called_once_with(test_events)
        handler.transport.send_metrics.assert_called_once_with(test_metrics)
        handler.buffer.confirm_event_redis_keys.assert_awaited_once_with(["ek1"])
        handler.buffer.confirm_metric_redis_keys.assert_awaited_once_with(["mk1"])
        assert handler.events_sent == 1
        assert handler.metrics_sent == 1

    @pytest.mark.asyncio
    async def test_configuration_validation(self) -> None:
        """Test that invalid configuration raises errors."""
        with pytest.raises(ValueError):
            GuardAgentHandler(AgentConfig(api_key="test-key", endpoint="invalid-url"))

    def test_get_stats(self, agent_config: AgentConfig) -> None:
        """Test getting comprehensive agent statistics."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = MagicMock()
        handler.buffer.get_stats.return_value = {"buffer_items": 5}
        handler.transport = MagicMock()
        handler.transport.get_stats.return_value = {"requests_sent": 10}

        stats = handler.get_stats()

        assert isinstance(stats, dict)
        assert "running" in stats
        assert "uptime" in stats
        assert "events_sent" in stats
        assert "metrics_sent" in stats
        assert "buffer_stats" in stats
        assert "transport_stats" in stats

    @pytest.mark.asyncio
    async def test_start_already_running(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test starting the agent when it's already running."""
        handler = GuardAgentHandler(agent_config)
        handler.transport = AsyncMock()
        handler.buffer = AsyncMock()

        await handler.start()
        assert handler._running is True

        await handler.start()
        assert "Agent is already running" in caplog.text

        await handler.stop()

    @pytest.mark.asyncio
    async def test_start_failure(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test agent start failure."""
        handler = GuardAgentHandler(agent_config)
        handler.transport = AsyncMock()
        handler.transport.initialize.side_effect = Exception("Transport failed")
        handler.buffer = AsyncMock()

        with pytest.raises(Exception, match="Transport failed"):
            await handler.start()

        assert "Failed to start agent: Transport failed" in caplog.text
        assert handler._running is False

    @pytest.mark.asyncio
    async def test_get_dynamic_rules_cached(self, agent_config: AgentConfig) -> None:
        """Test getting dynamic rules from cache."""
        handler = GuardAgentHandler(agent_config)
        cached_rules = DynamicRules(ttl=300)
        handler._cached_rules = cached_rules
        handler._rules_last_update = datetime.now(timezone.utc).timestamp()
        handler.transport = AsyncMock()

        rules = await handler.get_dynamic_rules()

        assert rules is cached_rules
        handler.transport.fetch_dynamic_rules.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_dynamic_rules_expired_cache(
        self, agent_config: AgentConfig
    ) -> None:
        """Test fetching new rules when cache is expired."""
        handler = GuardAgentHandler(agent_config)
        new_rules = DynamicRules(rule_id="new-rules")
        handler.transport = AsyncMock()
        handler.transport.fetch_dynamic_rules.return_value = new_rules

        handler._cached_rules = DynamicRules(ttl=1)
        handler._rules_last_update = datetime.now(timezone.utc).timestamp() - 2

        rules = await handler.get_dynamic_rules()

        assert rules is new_rules
        handler.transport.fetch_dynamic_rules.assert_called_once()
        assert handler.rules_fetched == 1

    @pytest.mark.asyncio
    async def test_get_dynamic_rules_fetch_error(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test handling of fetch error for dynamic rules."""
        handler = GuardAgentHandler(agent_config)
        cached_rules = DynamicRules(ttl=300)
        handler._cached_rules = cached_rules
        handler._rules_last_update = datetime.now(timezone.utc).timestamp()
        handler.transport = AsyncMock()
        handler.transport.fetch_dynamic_rules.side_effect = Exception("Fetch failed")

        handler._rules_last_update = 0

        rules = await handler.get_dynamic_rules()

        assert "Failed to fetch dynamic rules: Fetch failed" in caplog.text
        assert rules is cached_rules

    @pytest.mark.asyncio
    async def test_flush_buffer_send_failure(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test buffer flush when sending events/metrics fails."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.requeue_events_in_memory = MagicMock()
        handler.buffer.requeue_metrics_in_memory = MagicMock()
        handler.transport = AsyncMock()

        test_events = [MagicMock()]
        test_metrics = [MagicMock()]
        handler.buffer.flush_events_with_keys.return_value = (test_events, ["ek"])
        handler.buffer.flush_metrics_with_keys.return_value = (test_metrics, ["mk"])
        handler.transport.send_events.return_value = False
        handler.transport.send_metrics.return_value = False

        await handler.flush_buffer()

        assert handler.events_failed == len(test_events)
        assert handler.metrics_failed == len(test_metrics)
        assert f"Failed to send {len(test_events)} events" in caplog.text
        assert f"Failed to send {len(test_metrics)} metrics" in caplog.text
        handler.buffer.confirm_event_redis_keys.assert_not_awaited()
        handler.buffer.requeue_events_in_memory.assert_called_once_with(
            test_events, ["ek"]
        )
        handler.buffer.requeue_metrics_in_memory.assert_called_once_with(
            test_metrics, ["mk"]
        )

    @pytest.mark.asyncio
    async def test_flush_buffer_exception(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test exception handling during buffer flush."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.flush_events_with_keys.side_effect = Exception("Flush error")

        await handler.flush_buffer()
        assert "Error during buffer flush: Flush error" in caplog.text

    @pytest.mark.asyncio
    async def test_get_status_degraded_circuit_breaker(
        self, agent_config: AgentConfig
    ) -> None:
        """Test degraded status when circuit breaker is open."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.get_buffer_size.return_value = 1
        handler.buffer.get_stats = MagicMock(return_value={"last_flush_time": None})
        handler.transport = AsyncMock()
        handler.transport.get_stats = MagicMock(
            return_value={"circuit_breaker_state": "OPEN"}
        )

        agent_status = await handler.get_status()
        assert agent_status.status == "degraded"
        assert "Transport circuit breaker is open" in agent_status.errors

    @pytest.mark.asyncio
    async def test_get_status_buffer_full(self, agent_config: AgentConfig) -> None:
        """Test degraded status when buffer is nearly full."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.get_buffer_size.return_value = int(
            agent_config.buffer_size * 0.95
        )
        handler.buffer.get_stats = MagicMock(return_value={"last_flush_time": None})
        handler.transport = AsyncMock()
        handler.transport.get_stats = MagicMock(
            return_value={"circuit_breaker_state": "CLOSED"}
        )

        agent_status = await handler.get_status()
        assert agent_status.status == "degraded"
        assert "Buffer nearly full" in agent_status.errors

    @pytest.mark.asyncio
    async def test_get_status_high_failure_rate(
        self, agent_config: AgentConfig
    ) -> None:
        """Test degraded status due to high failure rate."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()
        handler.buffer.get_buffer_size.return_value = 1
        handler.buffer.get_stats = MagicMock(return_value={"last_flush_time": None})
        handler.transport = AsyncMock()
        handler.transport.get_stats = MagicMock(
            return_value={"circuit_breaker_state": "CLOSED"}
        )
        handler.events_failed = 2
        handler.metrics_failed = 1
        handler.events_sent = 5
        handler.metrics_sent = 5

        agent_status = await handler.get_status()
        assert agent_status.status == "degraded"
        assert any("High failure rate" in e for e in agent_status.errors)

    @pytest.mark.asyncio
    async def test_close(self, agent_config: AgentConfig) -> None:
        """Test the close method."""
        handler = GuardAgentHandler(agent_config)
        with patch.object(handler, "stop", new_callable=AsyncMock) as mock_stop:
            await handler.close()
            mock_stop.assert_called_once()

    def test_get_stats_comprehensive(self, agent_config: AgentConfig) -> None:
        """Test get_stats for comprehensive output."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = MagicMock()
        handler.buffer.get_stats.return_value = {"events_buffered": 1}
        handler.transport = MagicMock()
        handler.transport.get_stats.return_value = {"requests_sent": 2}
        handler._cached_rules = DynamicRules()
        handler._rules_last_update = 12345.67

        stats = handler.get_stats()
        assert stats["buffer_stats"] == {"events_buffered": 1}
        assert stats["transport_stats"] == {"requests_sent": 2}
        assert stats["cached_rules"] is True
        assert stats["rules_last_update"] == 12345.67

    @pytest.mark.asyncio
    async def test_start_stop_no_project_id(self, agent_config: AgentConfig) -> None:
        """Test start/stop when project_id is not configured."""
        config = agent_config.model_copy(update={"project_id": None})
        handler = GuardAgentHandler(config)
        handler.transport = AsyncMock()
        handler.buffer = AsyncMock()

        await handler.start()
        assert handler._running is True
        assert handler._rules_task is None

        await handler.stop()
        assert handler._running is False

    @pytest.mark.asyncio
    async def test_flush_loop(self, agent_config: AgentConfig) -> None:
        """Test the background flush loop."""
        config = agent_config.model_copy(update={"flush_interval": 0.01})
        handler = GuardAgentHandler(config)

        with patch.object(
            handler, "flush_buffer", new_callable=AsyncMock
        ) as mock_flush:
            handler._running = True

            task = asyncio.create_task(handler._flush_loop())
            await asyncio.sleep(0.05)
            handler._running = False
            await task

            assert mock_flush.call_count > 1

    @pytest.mark.asyncio
    async def test_status_loop(self, agent_config: AgentConfig) -> None:
        """Test the background status reporting loop."""
        config = agent_config.model_copy(update={"project_id": "test-project"})
        handler = GuardAgentHandler(config)
        handler.transport = AsyncMock()
        handler._running = True

        with patch.object(
            handler, "get_status", new_callable=AsyncMock
        ) as mock_get_status:

            def stop_loop_after_2_calls(*args: Any, **kwargs: Any) -> Any:
                if mock_get_status.call_count >= 2:
                    handler._running = False
                return MagicMock()

            mock_get_status.side_effect = stop_loop_after_2_calls

            # Mock sleep to return immediately and allow the loop to run
            with patch(
                "guard_agent.client.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep:
                mock_sleep.return_value = None
                await handler._status_loop()

            assert mock_get_status.call_count > 1
        assert handler.transport.send_status.call_count > 1

    @pytest.mark.asyncio
    async def test_rules_loop(self, agent_config: AgentConfig) -> None:
        """Test the background dynamic rules fetching loop."""
        config = agent_config.model_copy(update={"project_id": "test-project"})
        handler = GuardAgentHandler(config)
        handler._running = True

        with patch.object(
            handler, "get_dynamic_rules", new_callable=AsyncMock
        ) as mock_get_rules:

            def stop_loop_after_2_calls(*args: Any, **kwargs: Any) -> Any:
                if mock_get_rules.call_count >= 2:
                    handler._running = False

            mock_get_rules.side_effect = stop_loop_after_2_calls

            # Mock sleep to return immediately and allow the loop to run
            with patch(
                "guard_agent.client.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep:
                mock_sleep.return_value = None
                await handler._rules_loop()

            assert mock_get_rules.call_count > 1

    @pytest.mark.asyncio
    async def test_flush_loop_exception(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test exception handling in the flush loop."""
        config = agent_config.model_copy(update={"flush_interval": 0.01})
        handler = GuardAgentHandler(config)
        with patch.object(
            handler,
            "flush_buffer",
            new_callable=AsyncMock,
            side_effect=Exception("Flush failed"),
        ):
            handler._running = True

            task = asyncio.create_task(handler._flush_loop())
            await asyncio.sleep(0.05)
            handler._running = False
            await task

            assert "flush loop failed" in caplog.text
            assert "Exception: Flush failed" in caplog.text

    @pytest.mark.asyncio
    async def test_status_loop_exception(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test exception handling in the status loop."""
        handler = GuardAgentHandler(agent_config)
        handler._running = True

        with patch.object(
            handler, "get_status", new_callable=AsyncMock
        ) as mock_get_status:

            def raise_exception_then_stop(*args: Any, **kwargs: Any) -> Any:
                if mock_get_status.call_count == 1:
                    raise Exception("Status failed")
                handler._running = False

            mock_get_status.side_effect = raise_exception_then_stop

            # Mock sleep to return immediately and allow the loop to run
            with patch(
                "guard_agent.client.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep:
                mock_sleep.return_value = None
                await handler._status_loop()

            assert "status loop failed" in caplog.text
            assert "Exception: Status failed" in caplog.text
            assert handler._last_status_push_ok is False

    @pytest.mark.asyncio
    async def test_rules_loop_exception(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test exception handling in the rules loop."""
        config = agent_config.model_copy(update={"project_id": "test-project"})
        handler = GuardAgentHandler(config)
        handler._running = True

        with patch.object(
            handler, "get_dynamic_rules", new_callable=AsyncMock
        ) as mock_get_rules:

            def raise_exception_then_stop(*args: Any, **kwargs: Any) -> Any:
                if mock_get_rules.call_count == 1:
                    raise Exception("Rules fetch failed")
                handler._running = False

            mock_get_rules.side_effect = raise_exception_then_stop

            # Mock sleep to return immediately and allow the loop to run
            with patch(
                "guard_agent.client.asyncio.sleep", new_callable=AsyncMock
            ) as mock_sleep:
                mock_sleep.return_value = None
                await handler._rules_loop()

            assert "rules loop failed" in caplog.text
            assert "Exception: Rules fetch failed" in caplog.text

    @pytest.mark.asyncio
    async def test_configuration_validation_failure(self) -> None:
        """Test that invalid configuration raises ValueError (line 40)."""
        # Create a config with invalid api_key (too short)
        with pytest.raises(ValueError, match="Invalid agent configuration"):
            invalid_config = AgentConfig(
                api_key="short",  # Too short, needs at least 10 characters
                endpoint="https://api.example.com",
            )
            GuardAgentHandler(invalid_config)

    @pytest.mark.asyncio
    async def test_flush_loop_cancelled_error(self, agent_config: AgentConfig) -> None:
        """Test CancelledError handling in flush loop (line 257)."""
        handler = GuardAgentHandler(agent_config)
        handler._running = True
        with patch.object(
            handler, "flush_buffer", new_callable=AsyncMock
        ):  # Mock to avoid actual flushing
            # Start the flush loop task
            flush_task = asyncio.create_task(handler._flush_loop())

            # Wait a bit to let the task start and hit the sleep, then cancel
            await asyncio.sleep(0.01)
            flush_task.cancel()

            await flush_task

    @pytest.mark.asyncio
    async def test_status_loop_cancelled_error(self, agent_config: AgentConfig) -> None:
        """Test CancelledError handling in status loop (line 271)."""
        handler = GuardAgentHandler(agent_config)
        handler._running = True
        with patch.object(
            handler, "get_status", new_callable=AsyncMock
        ):  # Mock to avoid actual status generation
            handler.transport = AsyncMock()  # Mock transport

            # Start the status loop task
            status_task = asyncio.create_task(handler._status_loop())

            # Wait a bit to let the task start and hit the sleep, then cancel
            await asyncio.sleep(0.01)
            status_task.cancel()

            await status_task

    @pytest.mark.asyncio
    async def test_rules_loop_cancelled_error(self, agent_config: AgentConfig) -> None:
        """Test CancelledError handling in rules loop (line 284)."""
        config = agent_config.model_copy(update={"project_id": "test-project"})
        handler = GuardAgentHandler(config)
        handler._running = True
        with patch.object(
            handler, "get_dynamic_rules", new_callable=AsyncMock
        ):  # Mock to avoid actual rules fetching
            # Start the rules loop task
            rules_task = asyncio.create_task(handler._rules_loop())

            # Wait a bit to let the task start and hit the sleep, then cancel
            await asyncio.sleep(0.01)
            rules_task.cancel()

            await rules_task

    @staticmethod
    def _setup_high_failure_rate(handler: GuardAgentHandler) -> None:
        """Helper to set up high failure rate scenario."""
        handler.events_sent = 10
        handler.metrics_sent = 10
        handler.events_failed = 15
        handler.metrics_failed = 15

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "scenario,setup",
        [
            ("not_running", lambda h: setattr(h, "_running", False)),
            (
                "circuit_breaker_open",
                lambda h: h.transport.get_stats.return_value.__setitem__(
                    "circuit_breaker_state", "OPEN"
                ),
            ),
            (
                "buffer_nearly_full",
                lambda h: setattr(
                    h.buffer.get_buffer_size,
                    "return_value",
                    h.config.buffer_size * 0.95,
                ),
            ),
            (
                "high_failure_rate",
                lambda h: TestGuardAgentHandler._setup_high_failure_rate(h),
            ),
        ],
    )
    async def test_health_check_failure_scenarios(
        self, agent_config: AgentConfig, scenario: str, setup: Any
    ) -> None:
        """Test health_check returns False for various failure scenarios."""
        handler = GuardAgentHandler(agent_config)
        handler._running = True
        handler.buffer = AsyncMock()
        handler.buffer.get_buffer_size = AsyncMock(
            return_value=5
        )  # Default healthy buffer
        handler.transport = MagicMock()
        handler.transport.get_stats = MagicMock(
            return_value={"circuit_breaker_state": "CLOSED"}
        )

        # Apply scenario-specific setup
        setup(handler)

        result = await handler.health_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_success(self, agent_config: AgentConfig) -> None:
        """Test health_check returns True when everything is healthy."""
        handler = GuardAgentHandler(agent_config)
        handler._running = True
        handler.buffer = AsyncMock()
        handler.buffer.get_buffer_size = AsyncMock(return_value=5)  # Low buffer usage
        handler.transport = MagicMock()
        handler.transport.get_stats = MagicMock(
            return_value={"circuit_breaker_state": "CLOSED"}
        )
        handler.events_sent = 100
        handler.metrics_sent = 100
        handler.events_failed = 5
        handler.metrics_failed = 5  # Low failure rate

        result = await handler.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_exception(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test health_check handles exceptions gracefully."""
        handler = GuardAgentHandler(agent_config)
        handler._running = True
        handler.buffer = AsyncMock()
        handler.buffer.get_buffer_size = AsyncMock(
            side_effect=Exception("Buffer error")
        )
        handler.transport = MagicMock()

        result = await handler.health_check()
        assert result is False
        assert "Error during health check: Buffer error" in caplog.text

    @pytest.mark.asyncio
    async def test_send_duck_typed_event(self, agent_config: AgentConfig) -> None:
        """Test that duck-typed events are normalized into SecurityEvent."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()

        duck_event = type(
            "SecurityEvent",
            (),
            {
                "timestamp": datetime.now(timezone.utc),
                "event_type": "pattern_anomaly_timing",
                "ip_address": "10.0.0.1",
                "action_taken": "logged",
                "reason": "anomaly detected",
            },
        )()

        await handler.send_event(duck_event)

        handler.buffer.add_event.assert_called_once()
        buffered = handler.buffer.add_event.call_args[0][0]
        assert isinstance(buffered, SecurityEvent)
        assert buffered.event_type == "pattern_anomaly_timing"
        assert buffered.ip_address == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_send_duck_typed_metric(self, agent_config: AgentConfig) -> None:
        """Test that duck-typed metrics are normalized into SecurityMetric."""
        handler = GuardAgentHandler(agent_config)
        handler.buffer = AsyncMock()

        duck_metric = type(
            "SecurityMetric",
            (),
            {
                "timestamp": datetime.now(timezone.utc),
                "metric_type": "request_count",
                "value": 42.0,
            },
        )()

        await handler.send_metric(duck_metric)

        handler.buffer.add_metric.assert_called_once()
        buffered = handler.buffer.add_metric.call_args[0][0]
        assert isinstance(buffered, SecurityMetric)
        assert buffered.metric_type == "request_count"
        assert buffered.value == 42.0

    def test_protocol_compliance(self, agent_config: AgentConfig) -> None:
        """Test that GuardAgentHandler satisfies AgentHandlerProtocol."""
        handler = GuardAgentHandler(agent_config)
        assert isinstance(handler, AgentHandlerProtocol)
