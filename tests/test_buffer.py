import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from pytest import LogCaptureFixture

from guard_agent._client_flush import FlushMixin
from guard_agent.buffer import EventBuffer
from guard_agent.exceptions import BufferFullError, GuardAgentError
from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric


class FakeRedisHandler:
    """Dict-backed Redis double that actually stores and deletes values,
    for tests that must prove no record is left orphaned."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get_key(self, namespace: str, key: str) -> str | None:
        return self.store.get(f"{namespace}:{key}")

    async def set_key(
        self, namespace: str, key: str, value: str, ttl: int | None = None
    ) -> bool:
        self.store[f"{namespace}:{key}"] = value
        return True

    async def delete(self, namespace: str, key: str) -> int:
        return 1 if self.store.pop(f"{namespace}:{key}", None) is not None else 0

    async def keys(self, pattern: str) -> list[str]:
        prefix = pattern.rstrip("*")
        return [k for k in self.store if k.startswith(prefix)]

    async def initialize(self) -> None:
        return None

    def get_connection(self) -> None:
        return None


class YieldingFakeRedisHandler(FakeRedisHandler):
    """FakeRedisHandler whose set/get/delete/keys yield control before
    completing, reproducing the interleaving window a real Redis
    round-trip creates."""

    async def set_key(
        self, namespace: str, key: str, value: str, ttl: int | None = None
    ) -> bool:
        await asyncio.sleep(0)
        return await super().set_key(namespace, key, value, ttl)

    async def get_key(self, namespace: str, key: str) -> str | None:
        await asyncio.sleep(0)
        return await super().get_key(namespace, key)

    async def delete(self, namespace: str, key: str) -> int:
        await asyncio.sleep(0)
        return await super().delete(namespace, key)

    async def keys(self, pattern: str) -> list[str]:
        await asyncio.sleep(0)
        return await super().keys(pattern)


def _make_named_event(reason: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        event_type="ip_banned",
        ip_address="127.0.0.1",
        action_taken="block",
        reason=reason,
    )


def _make_named_metric(value: float) -> SecurityMetric:
    return SecurityMetric(
        timestamp=datetime.now(timezone.utc),
        metric_type="request_count",
        value=value,
    )


def _assert_key_map_matches_buffer(buffer: EventBuffer) -> None:
    """C26 invariant: every id tracked in a Redis-key map is an item
    currently in the matching buffer, and vice versa. Without a Redis
    handler no id is ever tracked, so both maps must stay empty."""
    if buffer.redis_handler is None:
        assert buffer._event_redis_keys == {}
        assert buffer._metric_redis_keys == {}
        return
    event_ids = {id(item) for item in buffer.event_buffer}
    metric_ids = {id(item) for item in buffer.metric_buffer}
    assert set(buffer._event_redis_keys) == event_ids
    assert set(buffer._metric_redis_keys) == metric_ids


class _FlushHost(FlushMixin):
    """Minimal host exercising the real FlushMixin._flush_events /
    _flush_metrics against a real buffer and a scripted transport."""

    def __init__(self, config: AgentConfig, buffer: EventBuffer, transport: object):
        import logging

        self.config = config
        self.logger = logging.getLogger(__name__)
        self.buffer = buffer
        self.transport = transport
        self.events_sent = 0
        self.metrics_sent = 0
        self.events_failed = 0
        self.metrics_failed = 0
        self._events_failure_streak = 0
        self._metrics_failure_streak = 0
        self._events_retry_after = 0.0
        self._metrics_retry_after = 0.0


class TestBufferOverflowConcurrency:
    """C23: the overflow check-and-append must be atomic with the append,
    or a concurrent caller can evict an item whose Redis key was never
    forgotten, orphaning its record."""

    @pytest.mark.asyncio
    async def test_concurrent_add_event_at_capacity_leaves_no_orphaned_key(
        self,
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="drop")
        buffer = EventBuffer(config)
        fake_redis = YieldingFakeRedisHandler()
        await buffer.initialize_redis(fake_redis)

        e1, e2, e3, e4 = (_make_named_event(r) for r in ("e1", "e2", "e3", "e4"))
        await buffer.add_event(e1)
        await buffer.add_event(e2)

        await asyncio.gather(buffer.add_event(e3), buffer.add_event(e4))

        assert len(buffer.event_buffer) == 2
        assert buffer.events_dropped == 2

        tracked_keys = set(buffer._event_redis_keys.values())
        stored_keys = {
            k.split(":", 1)[1]
            for k in fake_redis.store
            if k.startswith("agent_events:")
        }
        assert stored_keys == tracked_keys
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_concurrent_add_metric_at_capacity_leaves_no_orphaned_key(
        self,
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="drop")
        buffer = EventBuffer(config)
        fake_redis = YieldingFakeRedisHandler()
        await buffer.initialize_redis(fake_redis)

        m1, m2, m3, m4 = (_make_named_metric(v) for v in (1.0, 2.0, 3.0, 4.0))
        await buffer.add_metric(m1)
        await buffer.add_metric(m2)

        await asyncio.gather(buffer.add_metric(m3), buffer.add_metric(m4))

        assert len(buffer.metric_buffer) == 2
        assert buffer.metrics_dropped == 2

        tracked_keys = set(buffer._metric_redis_keys.values())
        stored_keys = {
            k.split(":", 1)[1]
            for k in fake_redis.store
            if k.startswith("agent_metrics:")
        }
        assert stored_keys == tracked_keys
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_concurrent_flushes_and_requeue_leave_no_orphaned_keys(
        self,
    ) -> None:
        """Two flush attempts permitted by max_concurrent_flushes=2, one of
        which fails and requeues, interleaved with a concurrent add_event,
        must not corrupt the buffer or orphan a tracked Redis key."""
        config = AgentConfig(
            api_key="k",
            buffer_size=3,
            buffer_overflow_policy="drop",
            max_concurrent_flushes=2,
            flush_interval=100,
            high_watermark_ratio=0.99,
        )
        buffer = EventBuffer(config)
        fake_redis = YieldingFakeRedisHandler()
        await buffer.initialize_redis(fake_redis)

        e1, e2, e3, e4 = (_make_named_event(r) for r in ("e1", "e2", "e3", "e4"))
        await buffer.add_event(e1)
        await buffer.add_event(e2)
        await buffer.add_event(e3)

        send_attempts = {"n": 0}

        async def flush_once() -> None:
            events, keys = await buffer.flush_events_with_keys()
            if not events:
                return
            send_attempts["n"] += 1
            await asyncio.sleep(0)
            if send_attempts["n"] > 1:
                await buffer.confirm_event_redis_keys(keys)
                return
            evicted = await buffer.requeue_events_in_memory(events, keys)
            if evicted:
                await buffer.confirm_event_redis_keys(evicted)

        buffer._flush_callback = flush_once
        await buffer.start()
        try:
            await asyncio.gather(
                buffer._flush_if_needed(),
                buffer._flush_if_needed(),
                buffer.add_event(e4),
            )
        finally:
            await buffer.stop()

        assert len(buffer.event_buffer) <= config.buffer_size

        tracked_keys = set(buffer._event_redis_keys.values())
        stored_keys = {
            k.split(":", 1)[1]
            for k in fake_redis.store
            if k.startswith("agent_events:")
        }
        assert stored_keys == tracked_keys
        _assert_key_map_matches_buffer(buffer)


class TestBufferClearInvariant:
    """C26: clear_buffer must forget the Redis-key maps too, or a later
    object can inherit a stale/foreign key once CPython reuses its id()."""

    @pytest.mark.asyncio
    async def test_clear_buffer_clears_redis_key_maps(
        self, security_event: SecurityEvent, security_metric: SecurityMetric
    ) -> None:
        config = AgentConfig(api_key="k")
        buffer = EventBuffer(config)
        fake_redis = FakeRedisHandler()
        await buffer.initialize_redis(fake_redis)

        await buffer.add_event(security_event)
        await buffer.add_metric(security_metric)
        assert buffer._event_redis_keys
        assert buffer._metric_redis_keys

        await buffer.clear_buffer()

        assert buffer._event_redis_keys == {}
        assert buffer._metric_redis_keys == {}
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_key_map_matches_buffer_after_every_public_operation(
        self,
    ) -> None:
        """Walks add/flush/requeue/clear and checks the invariant after
        each step, not just at the end."""
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="drop")
        buffer = EventBuffer(config)
        fake_redis = FakeRedisHandler()
        await buffer.initialize_redis(fake_redis)
        _assert_key_map_matches_buffer(buffer)

        e1, e2, e3 = (_make_named_event(r) for r in ("e1", "e2", "e3"))
        await buffer.add_event(e1)
        _assert_key_map_matches_buffer(buffer)
        await buffer.add_event(e2)
        _assert_key_map_matches_buffer(buffer)
        await buffer.add_event(e3)
        _assert_key_map_matches_buffer(buffer)

        events, keys = await buffer.flush_events_with_keys()
        _assert_key_map_matches_buffer(buffer)

        evicted = await buffer.requeue_events_in_memory(events, keys)
        _assert_key_map_matches_buffer(buffer)
        if evicted:
            await buffer.confirm_event_redis_keys(evicted)
            _assert_key_map_matches_buffer(buffer)

        await buffer.clear_buffer()
        _assert_key_map_matches_buffer(buffer)
        assert buffer._event_redis_keys == {}
        assert buffer._metric_redis_keys == {}


class TestBufferBlockPolicyStarvation:
    """C25: a requeue after a failed send always keeps its slot
    (durability over a new writer), and a blocked writer never depends
    solely on an explicit signal a 300s backoff can delay past -- it
    re-checks on its own at least once per BLOCK_POLICY_POLL_INTERVAL."""

    @pytest.mark.asyncio
    async def test_blocked_writer_rechecks_within_poll_interval_after_requeue_wins_slot(
        self,
    ) -> None:
        for _ in range(20):
            await self._run_one_iteration()

    async def _run_one_iteration(self) -> None:
        from guard_agent import _buffer_queue

        config = AgentConfig(api_key="k", buffer_size=1, buffer_overflow_policy="block")
        buffer = EventBuffer(config)

        class RaisingTransport:
            async def send_events(self, events: list[SecurityEvent]) -> bool:
                raise RuntimeError("boom")

        class SucceedingTransport:
            async def send_events(self, events: list[SecurityEvent]) -> bool:
                return True

        host = _FlushHost(config, buffer, RaisingTransport())

        e1, e2 = _make_named_event("e1"), _make_named_event("e2")
        await buffer.add_event(e1)

        with patch.object(
            _buffer_queue,
            "BLOCK_POLICY_POLL_INTERVAL",
            0.01,
        ):
            recheck = AsyncMock(wraps=buffer._resolve_event_overflow)
            with patch.object(buffer, "_resolve_event_overflow", recheck):
                pending = asyncio.create_task(buffer.add_event(e2))
                await asyncio.sleep(0)
                assert not pending.done()

                with pytest.raises(RuntimeError):
                    await host._flush_events()
                assert not pending.done()

                await asyncio.sleep(0.2)
                assert not pending.done()
                assert recheck.call_count >= 3, (
                    "writer must actively re-poll, not sleep on a signal nobody sends"
                )

                host._events_retry_after = 0.0
                host.transport = SucceedingTransport()
                await host._flush_events()

                await asyncio.wait_for(pending, timeout=2.0)

        assert e2 in list(buffer.event_buffer)
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_blocked_metric_writer_rechecks_within_bounded_poll_interval(
        self,
    ) -> None:
        from guard_agent import _buffer_queue

        config = AgentConfig(api_key="k", buffer_size=1, buffer_overflow_policy="block")
        buffer = EventBuffer(config)

        class RaisingTransport:
            async def send_metrics(self, metrics: list[SecurityMetric]) -> bool:
                raise RuntimeError("boom")

        class SucceedingTransport:
            async def send_metrics(self, metrics: list[SecurityMetric]) -> bool:
                return True

        host = _FlushHost(config, buffer, RaisingTransport())

        m1, m2 = _make_named_metric(1.0), _make_named_metric(2.0)
        await buffer.add_metric(m1)

        with patch.object(_buffer_queue, "BLOCK_POLICY_POLL_INTERVAL", 0.01):
            recheck = AsyncMock(wraps=buffer._resolve_metric_overflow)
            with patch.object(buffer, "_resolve_metric_overflow", recheck):
                pending = asyncio.create_task(buffer.add_metric(m2))
                await asyncio.sleep(0)
                assert not pending.done()

                with pytest.raises(RuntimeError):
                    await host._flush_metrics()
                assert not pending.done()

                await asyncio.sleep(0.2)
                assert not pending.done()
                assert recheck.call_count >= 3

                host._metrics_retry_after = 0.0
                host.transport = SucceedingTransport()
                await host._flush_metrics()

                await asyncio.wait_for(pending, timeout=2.0)

        assert m2 in list(buffer.metric_buffer)
        _assert_key_map_matches_buffer(buffer)


class TestFlushBoundaryExceptionHandling:
    """C29: a BaseException from the transport (asyncio.CancelledError,
    not an Exception subclass) must still requeue the popped batch and
    advance the failure bookkeeping before propagating, or the batch is
    silently lost and the backoff never advances.
    C30: on_error fires once per failed batch when an exception reaches
    the flush boundary, through the shared fire_error_hook helper."""

    @pytest.mark.asyncio
    async def test_cancelled_error_from_send_events_requeues_and_reraises(
        self,
    ) -> None:
        calls: list[tuple[str, BaseException, dict]] = []
        config = AgentConfig(
            api_key="k", on_error=lambda s, e, c: calls.append((s, e, c))
        )
        buffer = EventBuffer(config)

        class CancellingTransport:
            async def send_events(self, events: list[SecurityEvent]) -> bool:
                raise asyncio.CancelledError()

        host = _FlushHost(config, buffer, CancellingTransport())

        event = _make_named_event("e1")
        await buffer.add_event(event)

        with pytest.raises(asyncio.CancelledError):
            await host._flush_events()

        assert event in list(buffer.event_buffer)
        assert host.events_failed == 1
        assert host._events_failure_streak == 1
        assert host._events_retry_after > 0.0
        assert len(calls) == 1
        assert calls[0][0] == "flush_events"
        assert isinstance(calls[0][1], asyncio.CancelledError)
        assert calls[0][2] == {"batch_size": 1}
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_cancelled_error_from_send_metrics_requeues_and_reraises(
        self,
    ) -> None:
        calls: list[tuple[str, BaseException, dict]] = []
        config = AgentConfig(
            api_key="k", on_error=lambda s, e, c: calls.append((s, e, c))
        )
        buffer = EventBuffer(config)

        class CancellingTransport:
            async def send_metrics(self, metrics: list[SecurityMetric]) -> bool:
                raise asyncio.CancelledError()

        host = _FlushHost(config, buffer, CancellingTransport())

        metric = _make_named_metric(1.0)
        await buffer.add_metric(metric)

        with pytest.raises(asyncio.CancelledError):
            await host._flush_metrics()

        assert metric in list(buffer.metric_buffer)
        assert host.metrics_failed == 1
        assert host._metrics_failure_streak == 1
        assert len(calls) == 1
        assert calls[0][0] == "flush_metrics"
        assert isinstance(calls[0][1], asyncio.CancelledError)
        assert calls[0][2] == {"batch_size": 1}
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_on_error_hook_raising_is_swallowed_and_logged(
        self, caplog: LogCaptureFixture
    ) -> None:
        def bad_hook(stage: str, exc: BaseException, ctx: dict) -> None:
            raise RuntimeError("hook fail")

        config = AgentConfig(api_key="k", on_error=bad_hook)
        buffer = EventBuffer(config)

        class RaisingTransport:
            async def send_events(self, events: list[SecurityEvent]) -> bool:
                raise ValueError("boom")

        host = _FlushHost(config, buffer, RaisingTransport())
        await buffer.add_event(_make_named_event("e1"))

        with caplog.at_level("ERROR"):
            with pytest.raises(ValueError):
                await host._flush_events()

        assert any("on_error hook raised" in r.message for r in caplog.records)


# Test basic functionality
class TestBufferBasic:
    """Tests for EventBuffer basic functionality."""

    @pytest.mark.asyncio
    async def test_add_event(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        await buffer.add_event(security_event)
        assert len(buffer.event_buffer) == 1
        assert buffer.events_buffered == 1
        assert await buffer.get_buffer_size() == 1

    @pytest.mark.asyncio
    async def test_add_metric(
        self, buffer: EventBuffer, security_metric: SecurityMetric
    ) -> None:
        await buffer.add_metric(security_metric)
        assert len(buffer.metric_buffer) == 1
        assert buffer.metrics_buffered == 1
        assert await buffer.get_buffer_size() == 1

    @pytest.mark.asyncio
    async def test_flush_events(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        await buffer.add_event(security_event)
        flushed_events = await buffer.flush_events()
        assert len(flushed_events) == 1
        assert flushed_events[0] == security_event
        assert len(buffer.event_buffer) == 0
        assert buffer.events_flushed == 1
        assert buffer.last_flush_time is not None

    @pytest.mark.asyncio
    async def test_flush_metrics(
        self, buffer: EventBuffer, security_metric: SecurityMetric
    ) -> None:
        await buffer.add_metric(security_metric)
        flushed_metrics = await buffer.flush_metrics()
        assert len(flushed_metrics) == 1
        assert flushed_metrics[0] == security_metric
        assert len(buffer.metric_buffer) == 0
        assert buffer.metrics_flushed == 1
        assert buffer.last_flush_time is not None

    @pytest.mark.asyncio
    async def test_clear_buffer(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        security_metric: SecurityMetric,
    ) -> None:
        await buffer.add_event(security_event)
        await buffer.add_metric(security_metric)
        assert await buffer.get_buffer_size() == 2
        await buffer.clear_buffer()
        assert await buffer.get_buffer_size() == 0
        assert len(buffer.event_buffer) == 0
        assert len(buffer.metric_buffer) == 0


# Test Redis integration
class TestBufferRedisIntegration:
    """Tests for EventBuffer Redis integration."""

    @pytest.mark.asyncio
    async def test_initialize_redis(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        with patch.object(
            buffer, "_load_from_redis", new_callable=AsyncMock
        ) as mock_load:
            await buffer.initialize_redis(mock_redis_handler)
            assert buffer.redis_handler is mock_redis_handler
            mock_load.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_add_event_with_redis(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        with patch.object(
            buffer, "_persist_event_to_redis", new_callable=AsyncMock
        ) as mock_persist:
            await buffer.add_event(security_event)
            mock_persist.assert_awaited_once_with(security_event)

    @pytest.mark.asyncio
    async def test_add_metric_with_redis(
        self,
        buffer: EventBuffer,
        security_metric: SecurityMetric,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        with patch.object(
            buffer, "_persist_metric_to_redis", new_callable=AsyncMock
        ) as mock_persist:
            await buffer.add_metric(security_metric)
            mock_persist.assert_awaited_once_with(security_metric)

    @pytest.mark.asyncio
    async def test_flush_events_with_redis(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_event(security_event)

        await buffer.flush_events()

        assert mock_redis_handler.delete.call_count == 1
        args = mock_redis_handler.delete.call_args.args
        assert args[0] == "agent_events"
        assert args[1].startswith("event_")

    @pytest.mark.asyncio
    async def test_flush_metrics_with_redis(
        self,
        buffer: EventBuffer,
        security_metric: SecurityMetric,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_metric(security_metric)

        await buffer.flush_metrics()

        assert mock_redis_handler.delete.call_count == 1
        args = mock_redis_handler.delete.call_args.args
        assert args[0] == "agent_metrics"
        assert args[1].startswith("metric_")

    @pytest.mark.asyncio
    async def test_clear_buffer_with_redis(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        with patch.object(
            buffer, "_clear_redis_buffers", new_callable=AsyncMock
        ) as mock_clear:
            await buffer.clear_buffer()
            mock_clear.assert_awaited_once()


# Test auto-flush
class TestBufferAutoFlush:
    """Tests for EventBuffer auto-flush functionality."""

    @pytest.mark.asyncio
    async def test_start_stop_auto_flush(self, buffer: EventBuffer) -> None:
        await buffer.start_auto_flush()
        assert buffer._running
        assert buffer._flush_task is not None
        assert not buffer._flush_task.done()

        # Calling start again should do nothing
        task = buffer._flush_task
        await buffer.start_auto_flush()
        assert buffer._flush_task is task

        await buffer.stop_auto_flush()
        assert not buffer._running

    @pytest.mark.asyncio
    async def test_auto_flush_loop(
        self, buffer: EventBuffer, agent_config: AgentConfig
    ) -> None:
        agent_config.flush_interval = 1
        buffer = EventBuffer(agent_config)
        with patch.object(
            buffer, "_flush_if_needed", new_callable=AsyncMock
        ) as mock_flush:
            await buffer.start_auto_flush()
            await asyncio.sleep(1.5)
            await buffer.stop_auto_flush()
            mock_flush.assert_awaited()

    @pytest.mark.asyncio
    async def test_auto_flush_loop_cancel(self, buffer: EventBuffer) -> None:
        await buffer.start_auto_flush()
        await buffer.stop_auto_flush()
        assert buffer._flush_task and buffer._flush_task.cancelled()

    @pytest.mark.asyncio
    async def test_auto_flush_loop_exception(
        self, buffer: EventBuffer, caplog: LogCaptureFixture
    ) -> None:
        buffer.config.flush_interval = 1
        with patch.object(
            buffer, "_flush_if_needed", side_effect=Exception("Test Error")
        ):
            await buffer.start_auto_flush()
            await asyncio.sleep(1.5)
            await buffer.stop_auto_flush()
            assert "Error in auto flush loop: Test Error" in caplog.text


# Test _flush_if_needed
class TestBufferFlushIfNeeded:
    """Tests for EventBuffer _flush_if_needed method."""

    @pytest.mark.asyncio
    async def test_flush_if_needed_by_size(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        called: list[int] = []

        async def cb() -> None:
            called.append(1)

        buffer._flush_callback = cb
        buffer._flush_semaphore = asyncio.Semaphore(1)
        buffer.config.buffer_size = 10
        for _ in range(8):
            await buffer.add_event(security_event)

        with patch.object(buffer.logger, "debug") as mock_debug:
            await buffer._flush_if_needed()
            mock_debug.assert_called_with("Triggering buffer flush - size: 8")

        assert called, "callback must be invoked when watermark is reached"

    @pytest.mark.asyncio
    async def test_flush_if_needed_by_time(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        called: list[int] = []

        async def cb() -> None:
            called.append(1)

        buffer._flush_callback = cb
        buffer._flush_semaphore = asyncio.Semaphore(1)
        buffer.config.flush_interval = 1
        buffer.last_flush_time = time.time() - 2
        await buffer.add_event(security_event)

        with patch.object(buffer.logger, "debug") as mock_debug:
            await buffer._flush_if_needed()
            mock_debug.assert_called_with("Triggering buffer flush - size: 1")

        assert called, "callback must be invoked when flush interval elapsed"

    @pytest.mark.asyncio
    async def test_flush_if_needed_not_needed(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        called: list[int] = []

        async def cb() -> None:
            called.append(1)

        buffer._flush_callback = cb
        buffer._flush_semaphore = asyncio.Semaphore(1)
        buffer.config.flush_interval = 10
        buffer.last_flush_time = time.time()
        await buffer.add_event(security_event)

        with patch.object(buffer.logger, "debug") as mock_debug:
            await buffer._flush_if_needed()
            mock_debug.assert_not_called()

        assert not called, (
            "callback must not fire when below watermark and time not elapsed"
        )


# Test Redis persistence methods
class TestBufferRedisPersistence:
    """Tests for EventBuffer Redis persistence methods."""

    @pytest.mark.asyncio
    async def test_persist_event_to_redis(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._persist_event_to_redis(security_event)
        mock_redis_handler.set_key.assert_awaited_once()
        args, kwargs = mock_redis_handler.set_key.call_args
        assert args[0] == "agent_events"
        assert args[1].startswith("event_")
        assert "ip_banned" in args[2]

    @pytest.mark.asyncio
    async def test_persist_metric_to_redis(
        self,
        buffer: EventBuffer,
        security_metric: SecurityMetric,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._persist_metric_to_redis(security_metric)
        mock_redis_handler.set_key.assert_awaited_once()
        args, kwargs = mock_redis_handler.set_key.call_args
        assert args[0] == "agent_metrics"
        assert args[1].startswith("metric_")
        assert "request_count" in args[2]

    @pytest.mark.asyncio
    async def test_persist_duck_typed_metric_to_redis(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
    ) -> None:
        """Test Redis persistence for duck-typed metric without model_dump."""
        await buffer.initialize_redis(mock_redis_handler)
        duck_metric = type(
            "Metric", (), {"metric_type": "request_count", "value": 1.0}
        )()
        await buffer._persist_metric_to_redis(duck_metric)
        mock_redis_handler.set_key.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_persist_duck_typed_event_to_redis(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
    ) -> None:
        """Test Redis persistence for duck-typed event without model_dump."""
        await buffer.initialize_redis(mock_redis_handler)
        duck_event = type(
            "Event", (), {"event_type": "ip_banned", "ip_address": "1.1.1.1"}
        )()
        await buffer._persist_event_to_redis(duck_event)
        mock_redis_handler.set_key.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_persist_to_redis_no_handler(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        security_metric: SecurityMetric,
    ) -> None:
        # No redis handler, should not raise error
        await buffer._persist_event_to_redis(security_event)
        await buffer._persist_metric_to_redis(security_metric)

    @pytest.mark.asyncio
    async def test_persist_event_to_redis_exception(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.set_key.side_effect = Exception("Redis Error")
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._persist_event_to_redis(security_event)
        assert "Failed to persist event to Redis: Redis Error" in caplog.text

    @pytest.mark.asyncio
    async def test_persist_metric_to_redis_exception(
        self,
        buffer: EventBuffer,
        security_metric: SecurityMetric,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.set_key.side_effect = Exception("Redis Error")
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._persist_metric_to_redis(security_metric)
        assert "Failed to persist metric to Redis: Redis Error" in caplog.text


# Test loading from Redis
class TestBufferRedisMixinContract:
    """BufferRedisMixin declares stub methods that BufferOverflowMixin
    fulfills in the real EventBuffer composition; a bare mixin raises,
    documenting the contract rather than silently returning None."""

    def test_stub_methods_raise_not_implemented(self) -> None:
        from guard_agent._buffer_redis import BufferRedisMixin

        mixin = BufferRedisMixin()
        for method_name in (
            "_get_event_condition",
            "_get_metric_condition",
            "_is_event_buffer_full",
            "_is_metric_buffer_full",
            "_forget_oldest_event_key",
            "_forget_oldest_metric_key",
        ):
            with pytest.raises(NotImplementedError):
                getattr(mixin, method_name)()


class TestBufferLoadFromRedis:
    """Tests for EventBuffer loading from Redis."""

    @pytest.mark.asyncio
    async def test_load_from_redis(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        security_event: SecurityEvent,
        security_metric: SecurityMetric,
        caplog: LogCaptureFixture,
    ) -> None:
        event_key = "event_123"
        metric_key = "metric_456"
        unknown_key = "unknown_key"
        mock_redis_handler.keys.side_effect = [
            [f"agent_events:{event_key}", f"agent_events:{unknown_key}"],
            [f"agent_metrics:{metric_key}"],
        ]

        from guard_agent.utils import safe_json_serialize

        event_data = await safe_json_serialize(security_event.model_dump())
        metric_data = await safe_json_serialize(security_metric.model_dump())

        async def get_key_side_effect(namespace: str, key: str) -> str | None:
            if namespace == "agent_events" and key == event_key:
                return event_data
            if namespace == "agent_metrics" and key == metric_key:
                return metric_data
            return None

        mock_redis_handler.get_key.side_effect = get_key_side_effect

        await buffer.initialize_redis(mock_redis_handler)  # this calls _load_from_redis

        assert len(buffer.event_buffer) == 1
        assert len(buffer.metric_buffer) == 1
        assert buffer.events_buffered == 1
        assert buffer.metrics_buffered == 1
        assert buffer.event_buffer[0].event_type == "ip_banned"
        assert buffer.metric_buffer[0].metric_type == "request_count"

        message = "Failed to load event from Redis key"
        details = "No data found for key"
        assert f"{message} agent_events:{unknown_key}: {details}" in caplog.text

    @pytest.mark.asyncio
    async def test_load_from_redis_no_handler(self, buffer: EventBuffer) -> None:
        await buffer._load_from_redis()  # should do nothing and not fail

    @pytest.mark.asyncio
    async def test_load_from_redis_exception(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.side_effect = Exception("Redis Error")
        await buffer.initialize_redis(mock_redis_handler)
        assert "Failed to load from Redis: Redis Error" in caplog.text

    @pytest.mark.asyncio
    async def test_load_from_redis_item_exception(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.return_value = ["agent_events:event_123"]
        mock_redis_handler.get_key.side_effect = Exception("Get Key Error")
        await buffer.initialize_redis(mock_redis_handler)
        assert (
            "Failed to load event from Redis key agent_events:event_123: Get Key Error"
            in caplog.text
        )

    @pytest.mark.asyncio
    async def test_load_from_redis_deserialize_fail(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.return_value = ["agent_events:event_123"]
        mock_redis_handler.get_key.return_value = "invalid json"
        await buffer.initialize_redis(mock_redis_handler)
        assert len(buffer.event_buffer) == 0
        assert "Failed to deserialize JSON" in caplog.text

    @pytest.mark.asyncio
    async def test_load_from_redis_model_validation_fail(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.return_value = ["agent_events:event_123"]
        mock_redis_handler.get_key.return_value = """{"invalid": "data"}"""
        await buffer.initialize_redis(mock_redis_handler)
        assert len(buffer.event_buffer) == 0
        assert "Failed to load event from Redis key" in caplog.text

    @pytest.mark.asyncio
    async def test_load_from_redis_unknown_key(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.return_value = ["agent_events:unknown_key"]
        mock_redis_handler.get_key.return_value = (
            None  # Simulate get_key returning None for an unknown key
        )

        await buffer.initialize_redis(mock_redis_handler)

        assert len(buffer.event_buffer) == 0
        assert len(buffer.metric_buffer) == 0

        message = "Failed to load event from Redis key"
        details = "No data found for key"
        assert f"{message} agent_events:unknown_key: {details}" in caplog.text

    @pytest.mark.asyncio
    async def test_initialize_redis_load_does_not_race_add_event(self) -> None:
        """C31: loading persisted events at startup must not race live
        add_event traffic touching the same deque and Redis-key map."""
        from guard_agent.utils import safe_json_serialize

        config = AgentConfig(api_key="k", buffer_size=20)
        buffer = EventBuffer(config)
        fake_redis = YieldingFakeRedisHandler()

        preexisting = [_make_named_event(f"preload-{i}") for i in range(5)]
        for i, event in enumerate(preexisting):
            data = await safe_json_serialize(event.model_dump())
            await fake_redis.set_key("agent_events", f"preload_{i}", data)

        live_event = _make_named_event("live")

        await asyncio.gather(
            buffer.initialize_redis(fake_redis),
            buffer.add_event(live_event),
        )

        assert len(buffer.event_buffer) >= 6
        assert live_event in list(buffer.event_buffer)
        loaded_reasons = {e.reason for e in preexisting}
        buffered_reasons = {e.reason for e in buffer.event_buffer}
        assert loaded_reasons <= buffered_reasons
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_initialize_redis_load_does_not_race_add_metric(self) -> None:
        """C31: mirrors the event case for metrics."""
        from guard_agent.utils import safe_json_serialize

        config = AgentConfig(api_key="k", buffer_size=20)
        buffer = EventBuffer(config)
        fake_redis = YieldingFakeRedisHandler()

        preexisting = [_make_named_metric(float(i)) for i in range(5)]
        for i, metric in enumerate(preexisting):
            data = await safe_json_serialize(metric.model_dump())
            await fake_redis.set_key("agent_metrics", f"preload_{i}", data)

        live_metric = _make_named_metric(99.0)

        await asyncio.gather(
            buffer.initialize_redis(fake_redis),
            buffer.add_metric(live_metric),
        )

        assert len(buffer.metric_buffer) >= 6
        assert live_metric in list(buffer.metric_buffer)
        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_load_does_not_orphan_key_racing_add_event_at_capacity(
        self,
    ) -> None:
        """C31, decisive: at capacity, a startup load's raw append can
        evict the item add_event just placed. The lock must serialize
        the two so add_event's own key bookkeeping finishes first, and
        the load must forget that key before its own append evicts it."""
        from guard_agent.utils import safe_json_serialize

        config = AgentConfig(api_key="k", buffer_size=1)
        buffer = EventBuffer(config)

        persist_gate = asyncio.Event()

        class GatedRedisHandler(FakeRedisHandler):
            async def set_key(
                self, namespace: str, key: str, value: str, ttl: int | None = None
            ) -> bool:
                await persist_gate.wait()
                return await super().set_key(namespace, key, value, ttl)

        fake_redis = GatedRedisHandler()
        preload_event = _make_named_event("preload")
        fake_redis.store["agent_events:preload"] = await safe_json_serialize(
            preload_event.model_dump()
        )
        buffer.redis_handler = fake_redis

        live_event = _make_named_event("live")

        add_task = asyncio.create_task(buffer.add_event(live_event))
        await asyncio.sleep(0)
        assert live_event in list(buffer.event_buffer)

        load_task = asyncio.create_task(buffer._load_from_redis())
        await asyncio.sleep(0)

        persist_gate.set()
        await add_task
        await load_task

        _assert_key_map_matches_buffer(buffer)

    @pytest.mark.asyncio
    async def test_load_does_not_orphan_key_racing_add_metric_at_capacity(
        self,
    ) -> None:
        """C31, decisive: mirrors the event case for metrics."""
        from guard_agent.utils import safe_json_serialize

        config = AgentConfig(api_key="k", buffer_size=1)
        buffer = EventBuffer(config)

        persist_gate = asyncio.Event()

        class GatedRedisHandler(FakeRedisHandler):
            async def set_key(
                self, namespace: str, key: str, value: str, ttl: int | None = None
            ) -> bool:
                await persist_gate.wait()
                return await super().set_key(namespace, key, value, ttl)

        fake_redis = GatedRedisHandler()
        preload_metric = _make_named_metric(0.0)
        fake_redis.store["agent_metrics:preload"] = await safe_json_serialize(
            preload_metric.model_dump()
        )
        buffer.redis_handler = fake_redis

        live_metric = _make_named_metric(1.0)

        add_task = asyncio.create_task(buffer.add_metric(live_metric))
        await asyncio.sleep(0)
        assert live_metric in list(buffer.metric_buffer)

        load_task = asyncio.create_task(buffer._load_from_redis())
        await asyncio.sleep(0)

        persist_gate.set()
        await add_task
        await load_task

        _assert_key_map_matches_buffer(buffer)


# Test clearing from Redis
class TestBufferClearFromRedis:
    """Tests for EventBuffer clearing from Redis."""

    @pytest.mark.parametrize(
        "event_keys,clear_count,expected_deletes",
        [
            (
                ["agent_events:event_1", "agent_events:event_2"],
                2,
                ["event_1", "event_2"],
            ),  # Clear all
            (
                [
                    "agent_events:event_1",
                    "agent_events:event_2",
                    "agent_events:event_3",
                ],
                2,
                ["event_1", "event_2"],
            ),  # Partial clear (covers break condition)
        ],
    )
    @pytest.mark.asyncio
    async def test_clear_events_from_redis(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        event_keys: list[str],
        clear_count: int,
        expected_deletes: list[str],
    ) -> None:
        mock_redis_handler.keys.return_value = event_keys
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._clear_events_from_redis(clear_count)
        assert mock_redis_handler.delete.call_count == len(expected_deletes)
        for event_id in expected_deletes:
            mock_redis_handler.delete.assert_any_await("agent_events", event_id)

    @pytest.mark.asyncio
    async def test_clear_metrics_from_redis(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        mock_redis_handler.keys.return_value = [
            "agent_metrics:metric_1",
            "agent_metrics:metric_2",
        ]
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._clear_metrics_from_redis(1)
        assert mock_redis_handler.delete.call_count == 1
        mock_redis_handler.delete.assert_awaited_once_with("agent_metrics", "metric_1")

    @pytest.mark.asyncio
    async def test_clear_from_redis_no_handler(self, buffer: EventBuffer) -> None:
        await buffer._clear_events_from_redis(1)
        await buffer._clear_metrics_from_redis(1)
        await buffer._clear_redis_buffers()

    @pytest.mark.asyncio
    async def test_clear_events_from_redis_exception(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.side_effect = Exception("Redis Error")
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._clear_events_from_redis(1)
        assert "Failed to clear events from Redis: Redis Error" in caplog.text

    @pytest.mark.asyncio
    async def test_clear_metrics_from_redis_exception(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.side_effect = Exception("Redis Error")
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._clear_metrics_from_redis(1)
        assert "Failed to clear metrics from Redis: Redis Error" in caplog.text

    @pytest.mark.asyncio
    async def test_clear_redis_buffers(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        mock_redis_handler.keys.side_effect = [
            [],  # For _load_from_redis events
            [],  # For _load_from_redis metrics
            ["agent_events:event_1"],  # For _clear_redis_buffers events
            ["agent_metrics:metric_1"],  # For _clear_redis_buffers metrics
        ]
        mock_redis_handler.delete.return_value = None
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._clear_redis_buffers()
        mock_redis_handler.delete.assert_any_await("agent_events", "event_1")
        mock_redis_handler.delete.assert_any_await("agent_metrics", "metric_1")

    @pytest.mark.asyncio
    async def test_clear_redis_buffers_exception(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        mock_redis_handler.keys.side_effect = Exception("Redis Error")
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._clear_redis_buffers()
        assert "Failed to clear Redis buffers: Redis Error" in caplog.text


# Test error handling in add_event/add_metric
class TestBufferErrorHandling:
    """Tests for EventBuffer error handling."""

    @pytest.mark.asyncio
    async def test_add_event_exception(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        with patch.object(
            buffer,
            "_persist_event_to_redis",
            side_effect=Exception("Redis Persist Error"),
        ):
            await buffer.add_event(security_event)
            assert "Failed to buffer event: Redis Persist Error" in caplog.text

    @pytest.mark.asyncio
    async def test_add_metric_exception(
        self,
        buffer: EventBuffer,
        security_metric: SecurityMetric,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        with patch.object(
            buffer,
            "_persist_metric_to_redis",
            side_effect=Exception("Redis Persist Error"),
        ):
            await buffer.add_metric(security_metric)
            assert "Failed to buffer metric: Redis Persist Error" in caplog.text


# Test buffer full immediate flush
class TestBufferFullImmediateFlush:
    """Tests for EventBuffer full buffer immediate flush."""

    @pytest.mark.asyncio
    async def test_add_event_full_buffer_flush(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        buffer.config.buffer_size = 1
        with patch.object(
            buffer, "_flush_if_needed", new_callable=AsyncMock
        ) as mock_flush:
            await buffer.add_event(security_event)
            mock_flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_metric_full_buffer_flush(
        self, buffer: EventBuffer, security_metric: SecurityMetric
    ) -> None:
        buffer.config.buffer_size = 1
        with patch.object(
            buffer, "_flush_if_needed", new_callable=AsyncMock
        ) as mock_flush:
            await buffer.add_metric(security_metric)
            mock_flush.assert_called_once()


# Test get_stats
class TestGetStats:
    """Tests for EventBuffer get_stats method."""

    def test_get_stats(self, buffer: EventBuffer) -> None:
        stats = buffer.get_stats()
        assert "events_buffered" in stats
        assert "metrics_buffered" in stats
        assert "events_flushed" in stats
        assert "metrics_flushed" in stats
        assert "events_dropped" in stats
        assert "metrics_dropped" in stats
        assert "current_event_buffer_size" in stats
        assert "current_metric_buffer_size" in stats
        assert "last_flush_time" in stats
        assert "auto_flush_running" in stats


class TestBufferOverflowDropTracking:
    """Tests for buffer overflow drop accounting."""

    @pytest.mark.asyncio
    async def test_event_overflow_increments_drop_counter(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        buffer.config.buffer_size = 3
        buffer.event_buffer = type(buffer.event_buffer)(maxlen=3)

        for _ in range(5):
            await buffer.add_event(security_event)

        assert len(buffer.event_buffer) == 3
        assert buffer.events_dropped == 2
        assert buffer.events_buffered == 5
        assert buffer.get_stats()["events_dropped"] == 2

    @pytest.mark.asyncio
    async def test_metric_overflow_increments_drop_counter(
        self, buffer: EventBuffer, security_metric: SecurityMetric
    ) -> None:
        buffer.config.buffer_size = 2
        buffer.metric_buffer = type(buffer.metric_buffer)(maxlen=2)

        for _ in range(5):
            await buffer.add_metric(security_metric)

        assert len(buffer.metric_buffer) == 2
        assert buffer.metrics_dropped == 3
        assert buffer.get_stats()["metrics_dropped"] == 3

    @pytest.mark.asyncio
    async def test_metric_overflow_drop_deletes_dropped_items_redis_record(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        """C21, metric side: overflow-drop must confirm (delete) the
        dropped metric's Redis key, not just forget the in-memory pointer."""
        await buffer.initialize_redis(mock_redis_handler)
        buffer.config.buffer_size = 1
        buffer.metric_buffer = type(buffer.metric_buffer)(maxlen=1)

        first = SecurityMetric(
            timestamp=datetime.now(timezone.utc), metric_type="request_count", value=1.0
        )
        second = SecurityMetric(
            timestamp=datetime.now(timezone.utc), metric_type="request_count", value=2.0
        )
        await buffer.add_metric(first)
        mock_redis_handler.delete.reset_mock()

        await buffer.add_metric(second)

        mock_redis_handler.delete.assert_awaited_once()
        assert mock_redis_handler.delete.call_args.args[0] == "agent_metrics"

    @pytest.mark.asyncio
    async def test_no_drops_when_buffer_has_capacity(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        for _ in range(buffer.config.buffer_size - 1):
            await buffer.add_event(security_event)

        assert buffer.events_dropped == 0

    @pytest.mark.asyncio
    async def test_overflow_logs_warning_at_first_drop(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        caplog: LogCaptureFixture,
    ) -> None:
        buffer.config.buffer_size = 1
        buffer.event_buffer = type(buffer.event_buffer)(maxlen=1)
        await buffer.add_event(security_event)

        with caplog.at_level("WARNING", logger="guard_agent.buffer"):
            await buffer.add_event(security_event)

        assert any("buffer full" in r.message.lower() for r in caplog.records)

    @pytest.mark.asyncio
    async def test_overflow_drop_deletes_dropped_items_redis_record(self) -> None:
        """C21: dropping the oldest event on overflow must delete its Redis
        record too, not just forget the in-memory pointer, or it orphans."""
        config = AgentConfig(api_key="k", endpoint="http://x", buffer_size=2)
        buffer = EventBuffer(config)
        fake_redis = FakeRedisHandler()
        await buffer.initialize_redis(fake_redis)

        def make_event(reason: str) -> SecurityEvent:
            return SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="127.0.0.1",
                action_taken="block",
                reason=reason,
            )

        e1, e2, e3 = (make_event(r) for r in ("e1", "e2", "e3"))

        await buffer.add_event(e1)
        e1_key = buffer._event_redis_keys[id(e1)]
        await buffer.add_event(e2)
        await buffer.add_event(e3)

        assert list(buffer.event_buffer) == [e2, e3]
        assert buffer.events_dropped == 1
        assert f"agent_events:{e1_key}" not in fake_redis.store

        in_buffer_ids = {id(item) for item in buffer.event_buffer}
        for item in buffer.event_buffer:
            assert id(item) in buffer._event_redis_keys
        for tracked_id in buffer._event_redis_keys:
            assert tracked_id in in_buffer_ids

        tracked_keys = set(buffer._event_redis_keys.values())
        stored_keys = {
            k.split(":")[-1] for k in fake_redis.store if k.startswith("agent_events:")
        }
        assert stored_keys == tracked_keys

        events, keys = await buffer.flush_events_with_keys()
        assert events == [e2, e3]
        await buffer.confirm_event_redis_keys(keys)
        assert not any(k.startswith("agent_events:") for k in fake_redis.store)


class TestBufferConfirmAndRequeue:
    """Tests for transport-acked Redis confirmation and requeue on failure."""

    @pytest.mark.asyncio
    async def test_persisted_event_keys_are_unique_per_event(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_event(security_event)
        await buffer.add_event(security_event)

        keys = [c.args[1] for c in mock_redis_handler.set_key.call_args_list]
        assert len(keys) == 2
        assert len(set(keys)) == 2
        assert all(k.startswith("event_") for k in keys)

    @pytest.mark.asyncio
    async def test_flush_with_keys_does_not_delete_redis_until_confirmed(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_event(security_event)

        events, keys = await buffer.flush_events_with_keys()

        assert len(events) == 1
        assert len(keys) == 1
        assert mock_redis_handler.delete.call_count == 0

        await buffer.confirm_event_redis_keys(keys)
        assert mock_redis_handler.delete.call_count == 1
        assert mock_redis_handler.delete.call_args.args == ("agent_events", keys[0])

    @pytest.mark.asyncio
    async def test_requeue_restores_events_for_retry(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_event(security_event)

        events, keys = await buffer.flush_events_with_keys()
        assert len(buffer.event_buffer) == 0

        await buffer.requeue_events_in_memory(events, keys)
        assert len(buffer.event_buffer) == 1
        assert id(buffer.event_buffer[0]) in buffer._event_redis_keys

    @pytest.mark.asyncio
    async def test_requeue_after_failed_send_without_redis_preserves_events(
        self, buffer: EventBuffer, security_metric: SecurityMetric
    ) -> None:
        """C16: no Redis means keys are all "", requeue must not drop items."""
        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="127.0.0.1",
                action_taken="block",
                reason=f"test-{i}",
            )
            for i in range(3)
        ]
        for event in events:
            await buffer.add_event(event)
        await buffer.add_metric(security_metric)

        flushed_events, event_keys = await buffer.flush_events_with_keys()
        flushed_metrics, metric_keys = await buffer.flush_metrics_with_keys()
        assert event_keys == ["", "", ""]
        assert metric_keys == [""]
        assert len(buffer.event_buffer) == 0
        assert len(buffer.metric_buffer) == 0

        await buffer.requeue_events_in_memory(flushed_events, event_keys)
        await buffer.requeue_metrics_in_memory(flushed_metrics, metric_keys)

        assert len(buffer.event_buffer) == 3
        assert len(buffer.metric_buffer) == 1

        resent_events, resent_event_keys = await buffer.flush_events_with_keys()
        resent_metrics, resent_metric_keys = await buffer.flush_metrics_with_keys()
        assert resent_events == flushed_events
        assert resent_metrics == flushed_metrics
        assert resent_event_keys == ["", "", ""]
        assert resent_metric_keys == [""]

    @pytest.mark.asyncio
    async def test_legacy_flush_events_still_deletes_redis(
        self,
        buffer: EventBuffer,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_event(security_event)

        events = await buffer.flush_events()

        assert len(events) == 1
        assert mock_redis_handler.delete.call_count == 1

    def test_forget_oldest_event_key_no_op_when_buffer_empty(
        self, buffer: EventBuffer
    ) -> None:
        buffer._forget_oldest_event_key()

    def test_forget_oldest_metric_key_no_op_when_buffer_empty(
        self, buffer: EventBuffer
    ) -> None:
        buffer._forget_oldest_metric_key()

    @pytest.mark.asyncio
    async def test_confirm_event_redis_keys_no_op_when_redis_missing(
        self, buffer: EventBuffer
    ) -> None:
        await buffer.confirm_event_redis_keys(["evt_1"])

    @pytest.mark.asyncio
    async def test_confirm_event_redis_keys_no_op_on_empty_list(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.confirm_event_redis_keys([])
        assert mock_redis_handler.delete.call_count == 0

    @pytest.mark.asyncio
    async def test_confirm_event_redis_keys_swallows_redis_failure(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        mock_redis_handler.delete.side_effect = RuntimeError("redis down")

        with caplog.at_level("WARNING", logger="guard_agent.buffer"):
            await buffer.confirm_event_redis_keys(["evt_1"])

        assert any(
            "Failed to delete confirmed event key" in r.message for r in caplog.records
        )

    @pytest.mark.asyncio
    async def test_confirm_event_redis_keys_skips_empty_keys(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)

        await buffer.confirm_event_redis_keys(["", "evt_real", ""])

        mock_redis_handler.delete.assert_awaited_once_with("agent_events", "evt_real")

    @pytest.mark.asyncio
    async def test_confirm_metric_redis_keys_skips_empty_keys(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)

        await buffer.confirm_metric_redis_keys(["", "m_real", ""])

        mock_redis_handler.delete.assert_awaited_once_with("agent_metrics", "m_real")

    @pytest.mark.asyncio
    async def test_confirm_metric_redis_keys_no_op_when_redis_missing(
        self, buffer: EventBuffer
    ) -> None:
        await buffer.confirm_metric_redis_keys(["m_1"])

    @pytest.mark.asyncio
    async def test_confirm_metric_redis_keys_no_op_on_empty_list(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.confirm_metric_redis_keys([])
        assert mock_redis_handler.delete.call_count == 0

    @pytest.mark.asyncio
    async def test_confirm_metric_redis_keys_swallows_redis_failure(
        self,
        buffer: EventBuffer,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        mock_redis_handler.delete.side_effect = RuntimeError("redis down")

        with caplog.at_level("WARNING", logger="guard_agent.buffer"):
            await buffer.confirm_metric_redis_keys(["m_1"])

        assert any(
            "Failed to delete confirmed metric key" in r.message for r in caplog.records
        )

    @pytest.mark.asyncio
    async def test_requeue_events_drops_when_buffer_already_full(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        buffer.config.buffer_size = 1
        buffer.event_buffer = type(buffer.event_buffer)(maxlen=1)
        await buffer.add_event(security_event)

        before_dropped = buffer.events_dropped
        await buffer.requeue_events_in_memory([security_event], ["evt_x"])

        assert buffer.events_dropped == before_dropped + 1
        assert len(buffer.event_buffer) == 1

    @pytest.mark.asyncio
    async def test_requeue_metrics_restores_for_retry_and_drops_overflow(
        self,
        buffer: EventBuffer,
        security_metric: SecurityMetric,
        mock_redis_handler: AsyncMock,
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_metric(security_metric)
        metrics, keys = await buffer.flush_metrics_with_keys()
        assert len(buffer.metric_buffer) == 0

        await buffer.requeue_metrics_in_memory(metrics, keys)
        assert len(buffer.metric_buffer) == 1
        assert id(buffer.metric_buffer[0]) in buffer._metric_redis_keys

        buffer.config.buffer_size = 1
        buffer.metric_buffer = type(buffer.metric_buffer)(maxlen=1)
        await buffer.add_metric(security_metric)

        before_dropped = buffer.metrics_dropped
        await buffer.requeue_metrics_in_memory([security_metric], ["m_x"])
        assert buffer.metrics_dropped == before_dropped + 1
        assert len(buffer.metric_buffer) == 1

    @pytest.mark.asyncio
    async def test_requeue_appendleft_evicts_tail_not_head_no_orphaned_redis_keys(
        self,
    ) -> None:
        """C19: appendleft evicts the tail when the buffer is full, so the
        tail's key (not the head's) must be the one forgotten and its
        Redis record confirmed, reproducing the critic's exact sequence."""
        config = AgentConfig(api_key="k", endpoint="http://x", buffer_size=2)
        buffer = EventBuffer(config)
        fake_redis = FakeRedisHandler()
        await buffer.initialize_redis(fake_redis)

        def make_event(reason: str) -> SecurityEvent:
            return SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="127.0.0.1",
                action_taken="block",
                reason=reason,
            )

        e1, e2, e3, e4 = (make_event(r) for r in ("e1", "e2", "e3", "e4"))

        await buffer.add_event(e1)
        await buffer.add_event(e2)
        events, keys = await buffer.flush_events_with_keys()
        assert events == [e1, e2]

        await buffer.add_event(e3)
        await buffer.add_event(e4)

        evicted_keys = await buffer.requeue_events_in_memory(events, keys)
        for evicted_key in evicted_keys:
            await buffer.confirm_event_redis_keys([evicted_key])

        assert list(buffer.event_buffer) == [e1, e2]

        in_buffer_ids = {id(item) for item in buffer.event_buffer}
        for item in buffer.event_buffer:
            assert id(item) in buffer._event_redis_keys
        for tracked_id in buffer._event_redis_keys:
            assert tracked_id in in_buffer_ids

        tracked_keys = set(buffer._event_redis_keys.values())
        stored_keys = {
            k.split(":")[-1] for k in fake_redis.store if k.startswith("agent_events:")
        }
        assert stored_keys == tracked_keys

        events2, keys2 = await buffer.flush_events_with_keys()
        assert events2 == [e1, e2]
        await buffer.confirm_event_redis_keys(keys2)
        assert not any(k.startswith("agent_events:") for k in fake_redis.store)

    def test_forget_newest_event_key_no_op_when_buffer_empty(
        self, buffer: EventBuffer
    ) -> None:
        assert buffer._forget_newest_event_key() is None

    def test_forget_newest_metric_key_no_op_when_buffer_empty(
        self, buffer: EventBuffer
    ) -> None:
        assert buffer._forget_newest_metric_key() is None

    @pytest.mark.asyncio
    async def test_requeue_metrics_eviction_with_no_tracked_key_returns_no_evicted_keys(
        self, buffer: EventBuffer, security_metric: SecurityMetric
    ) -> None:
        """The evicted (tail) item had no Redis key, so nothing to confirm."""
        buffer.config.buffer_size = 1
        buffer.metric_buffer = type(buffer.metric_buffer)(maxlen=1)
        buffer.metric_buffer.append(security_metric)

        evicted_keys = await buffer.requeue_metrics_in_memory([security_metric], [""])

        assert evicted_keys == []
        assert len(buffer.metric_buffer) == 1


class TestBufferMissingBranches:
    @pytest.mark.asyncio
    async def test_stop_auto_flush_when_task_already_done(
        self, buffer: EventBuffer
    ) -> None:
        await buffer.start_auto_flush()
        await buffer.stop_auto_flush()
        await buffer.stop_auto_flush()
        assert not buffer._running
        assert buffer._flush_semaphore is None

    @pytest.mark.asyncio
    async def test_stop_auto_flush_awaits_inflight_tasks(
        self, buffer: EventBuffer
    ) -> None:
        completed: list[int] = []

        async def slow_flush() -> None:
            await asyncio.sleep(0.05)
            completed.append(1)

        buffer._flush_semaphore = asyncio.Semaphore(1)
        buffer._flush_callback = slow_flush
        buffer._running = True
        task: asyncio.Task[None] = asyncio.create_task(buffer._flush_if_needed())
        buffer._inflight_flush_tasks.add(task)
        task.add_done_callback(buffer._inflight_flush_tasks.discard)
        buffer.last_flush_time = None
        await buffer.add_event(
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_blocked",
                ip_address="1.2.3.4",
            )
        )
        await buffer.stop_auto_flush()
        assert not buffer._inflight_flush_tasks
        assert buffer._flush_semaphore is None

    @pytest.mark.asyncio
    async def test_add_event_redis_persist_returns_none_skips_key_store(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        with patch.object(
            buffer, "_persist_event_to_redis", new_callable=AsyncMock, return_value=None
        ):
            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_blocked",
                ip_address="1.2.3.4",
            )
            await buffer.add_event(event)
        assert id(event) not in buffer._event_redis_keys

    @pytest.mark.asyncio
    async def test_add_metric_redis_persist_returns_none_skips_key_store(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        await buffer.initialize_redis(mock_redis_handler)
        with patch.object(
            buffer,
            "_persist_metric_to_redis",
            new_callable=AsyncMock,
            return_value=None,
        ):
            metric = SecurityMetric(
                timestamp=datetime.now(timezone.utc),
                metric_type="request_count",
                value=1.0,
            )
            await buffer.add_metric(metric)
        assert id(metric) not in buffer._metric_redis_keys

    @pytest.mark.asyncio
    async def test_requeue_events_with_empty_key_skips_redis_tracking(
        self, buffer: EventBuffer, security_event: SecurityEvent
    ) -> None:
        await buffer.requeue_events_in_memory([security_event], [""])
        assert id(security_event) not in buffer._event_redis_keys

    @pytest.mark.asyncio
    async def test_requeue_metrics_with_empty_key_skips_redis_tracking(
        self, buffer: EventBuffer, security_metric: SecurityMetric
    ) -> None:
        await buffer.requeue_metrics_in_memory([security_metric], [""])
        assert id(security_metric) not in buffer._metric_redis_keys

    @pytest.mark.asyncio
    async def test_auto_flush_loop_exits_normally_when_running_set_false(
        self, buffer: EventBuffer
    ) -> None:
        buffer.config.flush_interval = 1
        buffer._running = True
        buffer._flush_semaphore = asyncio.Semaphore(1)

        loop_task: asyncio.Task[None] = asyncio.create_task(buffer._auto_flush_loop())
        await asyncio.sleep(0)
        buffer._running = False
        await asyncio.sleep(1.1)
        assert loop_task.done()
        assert not loop_task.cancelled()

    @pytest.mark.asyncio
    async def test_auto_flush_loop_skips_flush_when_running_false_after_sleep(
        self, buffer: EventBuffer
    ) -> None:
        flushed: list[int] = []

        async def fake_flush() -> None:
            flushed.append(1)

        buffer.config.flush_interval = 1
        buffer._flush_callback = fake_flush
        buffer._flush_semaphore = asyncio.Semaphore(1)
        buffer._running = True

        loop_task = asyncio.create_task(buffer._auto_flush_loop())
        await asyncio.sleep(0.5)
        buffer._running = False
        await asyncio.sleep(0.7)
        loop_task.cancel()
        try:
            await loop_task
        except asyncio.CancelledError:
            pass
        assert not flushed

    @pytest.mark.asyncio
    async def test_clear_metrics_from_redis_all_keys_cleared_without_break(
        self, buffer: EventBuffer, mock_redis_handler: AsyncMock
    ) -> None:
        mock_redis_handler.keys.side_effect = [
            [],
            [],
            ["agent_metrics:metric_1", "agent_metrics:metric_2"],
        ]
        await buffer.initialize_redis(mock_redis_handler)
        await buffer._clear_metrics_from_redis(10)
        assert mock_redis_handler.delete.call_count == 2


class TestBufferIdempotencyKey:
    """Tests verifying SecurityEvent.idempotency_key survives the buffer lifecycle."""

    @pytest.mark.asyncio
    async def test_buffer_preserves_idempotency_key_through_add_and_flush(
        self, buffer: EventBuffer
    ) -> None:
        from uuid import UUID

        explicit_key = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="10.0.0.2",
            idempotency_key=explicit_key,
        )

        await buffer.add_event(event)
        flushed = await buffer.flush_events()

        assert len(flushed) == 1
        assert flushed[0].idempotency_key == explicit_key


class TestBufferOverflowPolicy:
    """Tests for the configurable buffer_overflow_policy."""

    def test_overflow_policy_default_is_drop(self) -> None:
        config = AgentConfig(api_key="k")
        assert config.buffer_overflow_policy == "drop"

    def test_buffer_full_error_is_guard_agent_error(self) -> None:
        assert issubclass(BufferFullError, GuardAgentError)
        assert issubclass(GuardAgentError, Exception)

    @pytest.mark.asyncio
    async def test_overflow_policy_drop_evicts_oldest_and_increments_counter(
        self, security_event: SecurityEvent
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="drop")
        buffer = EventBuffer(config)

        first = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="1.1.1.1",
        )
        second = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="2.2.2.2",
        )
        third = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="3.3.3.3",
        )

        await buffer.add_event(first)
        await buffer.add_event(second)
        await buffer.add_event(third)

        assert buffer.events_dropped == 1
        assert len(buffer.event_buffer) == 2
        assert first not in list(buffer.event_buffer)
        assert third in list(buffer.event_buffer)

    @pytest.mark.asyncio
    async def test_metric_overflow_policy_drop_evicts_oldest(self) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="drop")
        buffer = EventBuffer(config)

        first = SecurityMetric(
            timestamp=datetime.now(timezone.utc),
            metric_type="request_count",
            value=1.0,
        )
        second = SecurityMetric(
            timestamp=datetime.now(timezone.utc),
            metric_type="request_count",
            value=2.0,
        )
        third = SecurityMetric(
            timestamp=datetime.now(timezone.utc),
            metric_type="request_count",
            value=3.0,
        )

        await buffer.add_metric(first)
        await buffer.add_metric(second)
        await buffer.add_metric(third)

        assert buffer.metrics_dropped == 1
        assert len(buffer.metric_buffer) == 2
        assert first not in list(buffer.metric_buffer)
        assert third in list(buffer.metric_buffer)

    @pytest.mark.asyncio
    async def test_overflow_policy_raise_throws_buffer_full_error_for_events(
        self, security_event: SecurityEvent
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="raise")
        buffer = EventBuffer(config)

        await buffer.add_event(security_event)
        await buffer.add_event(security_event)

        with pytest.raises(BufferFullError):
            await buffer.add_event(security_event)

        assert len(buffer.event_buffer) == 2
        assert buffer.events_dropped == 0

    @pytest.mark.asyncio
    async def test_overflow_policy_raise_throws_buffer_full_error_for_metrics(
        self, security_metric: SecurityMetric
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="raise")
        buffer = EventBuffer(config)

        await buffer.add_metric(security_metric)
        await buffer.add_metric(security_metric)

        with pytest.raises(BufferFullError):
            await buffer.add_metric(security_metric)

        assert len(buffer.metric_buffer) == 2
        assert buffer.metrics_dropped == 0

    @pytest.mark.asyncio
    async def test_overflow_policy_raise_is_not_swallowed_by_redis_try_block(
        self,
        security_event: SecurityEvent,
        mock_redis_handler: AsyncMock,
        caplog: LogCaptureFixture,
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=1, buffer_overflow_policy="raise")
        buffer = EventBuffer(config)
        await buffer.initialize_redis(mock_redis_handler)
        await buffer.add_event(security_event)

        with caplog.at_level("ERROR", logger="guard_agent.buffer"):
            with pytest.raises(BufferFullError):
                await buffer.add_event(security_event)

        assert not any("Failed to buffer event" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_overflow_policy_block_awaits_until_space_frees_for_events(
        self, security_event: SecurityEvent
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="block")
        buffer = EventBuffer(config)

        await buffer.add_event(security_event)
        await buffer.add_event(security_event)
        assert len(buffer.event_buffer) == 2

        third = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="9.9.9.9",
        )
        pending = asyncio.create_task(buffer.add_event(third))
        await asyncio.sleep(0.05)
        assert not pending.done()

        await buffer.flush_events()

        await asyncio.wait_for(pending, timeout=1.0)
        assert third in list(buffer.event_buffer)
        assert buffer.events_dropped == 0

    @pytest.mark.asyncio
    async def test_overflow_policy_block_awaits_until_space_frees_for_metrics(
        self, security_metric: SecurityMetric
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="block")
        buffer = EventBuffer(config)

        await buffer.add_metric(security_metric)
        await buffer.add_metric(security_metric)
        assert len(buffer.metric_buffer) == 2

        third = SecurityMetric(
            timestamp=datetime.now(timezone.utc),
            metric_type="request_count",
            value=99.0,
        )
        pending = asyncio.create_task(buffer.add_metric(third))
        await asyncio.sleep(0.05)
        assert not pending.done()

        await buffer.flush_metrics()

        await asyncio.wait_for(pending, timeout=1.0)
        assert third in list(buffer.metric_buffer)
        assert buffer.metrics_dropped == 0

    @pytest.mark.asyncio
    async def test_flush_events_with_keys_no_op_when_buffer_empty(
        self, buffer: EventBuffer
    ) -> None:
        events, keys = await buffer.flush_events_with_keys()
        assert events == []
        assert keys == []

    @pytest.mark.asyncio
    async def test_flush_metrics_with_keys_no_op_when_buffer_empty(
        self, buffer: EventBuffer
    ) -> None:
        metrics, keys = await buffer.flush_metrics_with_keys()
        assert metrics == []
        assert keys == []

    @pytest.mark.asyncio
    async def test_get_condition_returns_existing_when_already_initialized(
        self,
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=2, buffer_overflow_policy="block")
        buffer = EventBuffer(config)

        first_event = buffer._get_event_condition()
        second_event = buffer._get_event_condition()
        assert first_event is second_event

        first_metric = buffer._get_metric_condition()
        second_metric = buffer._get_metric_condition()
        assert first_metric is second_metric

    @pytest.mark.asyncio
    async def test_overflow_policy_block_resumes_via_clear_buffer(
        self, security_event: SecurityEvent, security_metric: SecurityMetric
    ) -> None:
        config = AgentConfig(api_key="k", buffer_size=1, buffer_overflow_policy="block")
        buffer = EventBuffer(config)

        await buffer.add_event(security_event)
        await buffer.add_metric(security_metric)

        pending_event = asyncio.create_task(buffer.add_event(security_event))
        pending_metric = asyncio.create_task(buffer.add_metric(security_metric))
        await asyncio.sleep(0.05)
        assert not pending_event.done()
        assert not pending_metric.done()

        await buffer.clear_buffer()

        await asyncio.wait_for(pending_event, timeout=1.0)
        await asyncio.wait_for(pending_metric, timeout=1.0)
