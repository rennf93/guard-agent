import asyncio
import logging
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

from guard_agent.exceptions import BufferFullError
from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric
from guard_agent.protocols import BufferProtocol, RedisHandlerProtocol
from guard_agent.utils import (
    safe_json_deserialize,
    safe_json_serialize,
)


class EventBuffer(BufferProtocol):
    _DROP_LOG_INTERVAL = 100

    def __init__(
        self,
        config: AgentConfig,
        flush_callback: Callable[[], Awaitable[None]] | None = None,
    ):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._flush_callback = flush_callback

        self.event_buffer: deque[SecurityEvent] = deque(maxlen=config.buffer_size)
        self.metric_buffer: deque[SecurityMetric] = deque(maxlen=config.buffer_size)

        self.redis_handler: RedisHandlerProtocol | None = None

        self._flush_task: asyncio.Task[None] | None = None
        self._flush_semaphore: asyncio.Semaphore | None = None
        self._running = False
        self._inflight_flush_tasks: set[asyncio.Task[None]] = set()

        self._event_redis_keys: dict[int, str] = {}
        self._metric_redis_keys: dict[int, str] = {}

        self._event_space_available: asyncio.Event | None = None
        self._metric_space_available: asyncio.Event | None = None

        self.events_buffered = 0
        self.metrics_buffered = 0
        self.events_flushed = 0
        self.metrics_flushed = 0
        self.events_dropped = 0
        self.metrics_dropped = 0
        self.redis_persist_failures = 0
        self.last_flush_time: float | None = None

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        self.redis_handler = redis_handler
        await self._load_from_redis()

    async def start_auto_flush(self) -> None:
        if self._flush_task and not self._flush_task.done():
            return

        self._flush_semaphore = asyncio.Semaphore(self.config.max_concurrent_flushes)
        self._running = True
        self._flush_task = asyncio.create_task(self._auto_flush_loop())

    async def start(self) -> None:
        await self.start_auto_flush()

    async def stop_auto_flush(self) -> None:
        self._running = False
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        if self._inflight_flush_tasks:
            await asyncio.gather(*self._inflight_flush_tasks, return_exceptions=True)
        self._inflight_flush_tasks.clear()
        self._flush_semaphore = None

    async def stop(self) -> None:
        await self.stop_auto_flush()

    async def add_event(self, event: SecurityEvent) -> None:
        """Add security event to buffer honoring the configured overflow policy."""
        await self._apply_event_overflow_policy()
        try:
            self.event_buffer.append(event)
            self.events_buffered += 1

            if self.redis_handler:
                key = await self._persist_event_to_redis(event)
                if key is not None:
                    self._event_redis_keys[id(event)] = key

            if (
                len(self.event_buffer)
                >= self.config.buffer_size * self.config.high_watermark_ratio
            ):
                task: asyncio.Task[None] = asyncio.create_task(self._flush_if_needed())
                self._inflight_flush_tasks.add(task)
                task.add_done_callback(self._inflight_flush_tasks.discard)

        except Exception as e:
            self.logger.error(f"Failed to buffer event: {str(e)}")

    async def add_metric(self, metric: SecurityMetric) -> None:
        """Add metric to buffer honoring the configured overflow policy."""
        await self._apply_metric_overflow_policy()
        try:
            self.metric_buffer.append(metric)
            self.metrics_buffered += 1

            if self.redis_handler:
                key = await self._persist_metric_to_redis(metric)
                if key is not None:
                    self._metric_redis_keys[id(metric)] = key

            if (
                len(self.metric_buffer)
                >= self.config.buffer_size * self.config.high_watermark_ratio
            ):
                task = asyncio.create_task(self._flush_if_needed())
                self._inflight_flush_tasks.add(task)
                task.add_done_callback(self._inflight_flush_tasks.discard)

        except Exception as e:
            self.logger.error(f"Failed to buffer metric: {str(e)}")

    async def _apply_event_overflow_policy(self) -> None:
        if not self._is_event_buffer_full():
            return
        policy = self.config.buffer_overflow_policy
        if policy == "raise":
            raise BufferFullError(
                f"Event buffer full at maxlen={self.config.buffer_size} "
                "and buffer_overflow_policy='raise'"
            )
        if policy == "block":
            await self._await_event_space()
            return
        self.events_dropped += 1
        if self.events_dropped % self._DROP_LOG_INTERVAL == 1:
            self.logger.warning(
                f"Event buffer full at maxlen={self.config.buffer_size}; "
                f"dropping oldest event ({self.events_dropped} dropped total)"
            )
        self._forget_oldest_event_key()

    async def _apply_metric_overflow_policy(self) -> None:
        if not self._is_metric_buffer_full():
            return
        policy = self.config.buffer_overflow_policy
        if policy == "raise":
            raise BufferFullError(
                f"Metric buffer full at maxlen={self.config.buffer_size} "
                "and buffer_overflow_policy='raise'"
            )
        if policy == "block":
            await self._await_metric_space()
            return
        self.metrics_dropped += 1
        if self.metrics_dropped % self._DROP_LOG_INTERVAL == 1:
            self.logger.warning(
                f"Metric buffer full at maxlen={self.config.buffer_size}; "
                f"dropping oldest metric ({self.metrics_dropped} dropped total)"
            )
        self._forget_oldest_metric_key()

    def _get_event_space_event(self) -> asyncio.Event:
        if self._event_space_available is None:
            self._event_space_available = asyncio.Event()
        return self._event_space_available

    def _get_metric_space_event(self) -> asyncio.Event:
        if self._metric_space_available is None:
            self._metric_space_available = asyncio.Event()
        return self._metric_space_available

    async def _await_event_space(self) -> None:
        space_event = self._get_event_space_event()
        while self._is_event_buffer_full():
            space_event.clear()
            await space_event.wait()

    async def _await_metric_space(self) -> None:
        space_event = self._get_metric_space_event()
        while self._is_metric_buffer_full():
            space_event.clear()
            await space_event.wait()

    def _signal_event_space_available(self) -> None:
        if self._event_space_available is not None:
            self._event_space_available.set()

    def _signal_metric_space_available(self) -> None:
        if self._metric_space_available is not None:
            self._metric_space_available.set()

    def _forget_oldest_event_key(self) -> None:
        if not self.event_buffer:
            return
        oldest = self.event_buffer[0]
        self._event_redis_keys.pop(id(oldest), None)

    def _forget_oldest_metric_key(self) -> None:
        if not self.metric_buffer:
            return
        oldest = self.metric_buffer[0]
        self._metric_redis_keys.pop(id(oldest), None)

    def _is_event_buffer_full(self) -> bool:
        return self.event_buffer.maxlen is not None and (
            len(self.event_buffer) >= self.event_buffer.maxlen
        )

    def _is_metric_buffer_full(self) -> bool:
        return self.metric_buffer.maxlen is not None and (
            len(self.metric_buffer) >= self.metric_buffer.maxlen
        )

    async def flush_events(self) -> list[SecurityEvent]:
        """Flush events and immediately forget Redis keys (legacy semantics)."""
        events, keys = await self.flush_events_with_keys()
        if keys:
            await self.confirm_event_redis_keys(keys)
        return events

    async def flush_metrics(self) -> list[SecurityMetric]:
        """Flush metrics and immediately forget Redis keys (legacy semantics)."""
        metrics, keys = await self.flush_metrics_with_keys()
        if keys:
            await self.confirm_metric_redis_keys(keys)
        return metrics

    async def flush_events_with_keys(
        self,
    ) -> tuple[list[SecurityEvent], list[str]]:
        """Flush events plus their Redis keys; keys remain in Redis until confirmed."""
        events = list(self.event_buffer)
        keys = [self._event_redis_keys.pop(id(event), "") for event in events]
        keys = [k for k in keys if k]
        self.event_buffer.clear()
        self.events_flushed += len(events)
        self.last_flush_time = time.time()
        if events:
            self._signal_event_space_available()
        return events, keys

    async def flush_metrics_with_keys(
        self,
    ) -> tuple[list[SecurityMetric], list[str]]:
        """Flush metrics plus their Redis keys; keys remain in Redis until confirmed."""
        metrics = list(self.metric_buffer)
        keys = [self._metric_redis_keys.pop(id(metric), "") for metric in metrics]
        keys = [k for k in keys if k]
        self.metric_buffer.clear()
        self.metrics_flushed += len(metrics)
        self.last_flush_time = time.time()
        if metrics:
            self._signal_metric_space_available()
        return metrics, keys

    async def confirm_event_redis_keys(self, keys: list[str]) -> None:
        """Delete the given event keys from Redis after the transport confirms."""
        if not self.redis_handler or not keys:
            return
        for key in keys:
            try:
                await self.redis_handler.delete("agent_events", key)
            except Exception as e:
                self.logger.warning(f"Failed to delete confirmed event key {key}: {e}")

    async def confirm_metric_redis_keys(self, keys: list[str]) -> None:
        """Delete the given metric keys from Redis after the transport confirms."""
        if not self.redis_handler or not keys:
            return
        for key in keys:
            try:
                await self.redis_handler.delete("agent_metrics", key)
            except Exception as e:
                self.logger.warning(f"Failed to delete confirmed metric key {key}: {e}")

    def requeue_events_in_memory(
        self, events: list[SecurityEvent], keys: list[str]
    ) -> None:
        """Push unsent events back to the front of the buffer; keep Redis keys."""
        for event, key in zip(reversed(events), reversed(keys), strict=False):
            if self._is_event_buffer_full():
                self.events_dropped += 1
                self._forget_oldest_event_key()
            self.event_buffer.appendleft(event)
            if key:
                self._event_redis_keys[id(event)] = key

    def requeue_metrics_in_memory(
        self, metrics: list[SecurityMetric], keys: list[str]
    ) -> None:
        """Push unsent metrics back to the front of the buffer; keep Redis keys."""
        for metric, key in zip(reversed(metrics), reversed(keys), strict=False):
            if self._is_metric_buffer_full():
                self.metrics_dropped += 1
                self._forget_oldest_metric_key()
            self.metric_buffer.appendleft(metric)
            if key:
                self._metric_redis_keys[id(metric)] = key

    async def get_buffer_size(self) -> int:
        """Get current total buffer size."""
        return len(self.event_buffer) + len(self.metric_buffer)

    async def clear_buffer(self) -> None:
        """Clear all buffers."""
        self.event_buffer.clear()
        self.metric_buffer.clear()
        self._signal_event_space_available()
        self._signal_metric_space_available()

        if self.redis_handler:
            await self._clear_redis_buffers()

    async def _auto_flush_loop(self) -> None:
        """Automatic flush loop."""
        while self._running:
            try:
                await asyncio.sleep(self.config.flush_interval)
                if self._running:
                    await self._flush_if_needed()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in auto flush loop: {str(e)}")

    async def _flush_if_needed(self) -> None:
        current_time = time.time()

        time_since_last_flush = (
            current_time - self.last_flush_time
            if self.last_flush_time
            else self.config.flush_interval + 1
        )

        buffer_size = await self.get_buffer_size()
        at_watermark = (
            buffer_size >= self.config.buffer_size * self.config.high_watermark_ratio
        )
        time_elapsed = time_since_last_flush >= self.config.flush_interval

        if not (at_watermark or time_elapsed) or buffer_size == 0:
            return

        if self._flush_callback is None or self._flush_semaphore is None:
            return

        if self._flush_semaphore.locked():
            return

        self.logger.debug(f"Triggering buffer flush - size: {buffer_size}")
        async with self._flush_semaphore:
            await self._flush_callback()

    async def _persist_event_to_redis(self, event: SecurityEvent) -> str | None:
        """Persist event to Redis under a globally-unique key; return that key."""
        if not self.redis_handler:
            return None

        try:
            key = f"event_{time.time_ns()}_{uuid.uuid4().hex[:8]}"
            data = event.model_dump() if hasattr(event, "model_dump") else vars(event)
            serialized = await safe_json_serialize(data)
            await self.redis_handler.set_key(
                "agent_events",
                key,
                serialized,
                ttl=3600,
            )
            return key
        except Exception as e:
            self.redis_persist_failures += 1
            self.logger.warning(f"Failed to persist event to Redis: {str(e)}")
            return None

    async def _persist_metric_to_redis(self, metric: SecurityMetric) -> str | None:
        """Persist metric to Redis under a globally-unique key; return that key."""
        if not self.redis_handler:
            return None

        try:
            key = f"metric_{time.time_ns()}_{uuid.uuid4().hex[:8]}"
            if hasattr(metric, "model_dump"):
                data = metric.model_dump()
            else:
                data = vars(metric)
            serialized = await safe_json_serialize(data)
            await self.redis_handler.set_key(
                "agent_metrics",
                key,
                serialized,
                ttl=3600,
            )
            return key
        except Exception as e:
            self.redis_persist_failures += 1
            self.logger.warning(f"Failed to persist metric to Redis: {str(e)}")
            return None

    async def _load_from_redis(self) -> None:
        """Load persisted events/metrics from Redis on startup; track keys."""
        if not self.redis_handler:
            return

        try:
            await self._load_events_from_redis()
            await self._load_metrics_from_redis()

            if self.event_buffer or self.metric_buffer:
                loaded_events = f"Loaded {len(self.event_buffer)} events"
                loaded_metrics = f"Loaded {len(self.metric_buffer)} metrics"
                self.logger.info(f"{loaded_events} and {loaded_metrics} from Redis")

        except Exception as e:
            self.logger.warning(f"Failed to load from Redis: {str(e)}")

    async def _load_events_from_redis(self) -> None:
        """Load persisted events from Redis."""
        assert self.redis_handler is not None
        event_keys = await self.redis_handler.keys("agent_events:*") or []
        for key in event_keys:
            await self._load_one_event_from_redis(key)

    async def _load_one_event_from_redis(self, key: str) -> None:
        """Load a single event from Redis, recording the key on success."""
        assert self.redis_handler is not None
        try:
            short_key = key.split(":")[-1]
            event_data = await self.redis_handler.get_key("agent_events", short_key)
            if not event_data:
                self.logger.warning(
                    f"Failed to load event from Redis key {key}: No data found for key"
                )
                return
            event_dict = await safe_json_deserialize(event_data)
            if not event_dict:
                return
            event = SecurityEvent(**event_dict)
            self.event_buffer.append(event)
            self.events_buffered += 1
            self._event_redis_keys[id(event)] = short_key
        except Exception as e:
            self.logger.warning(f"Failed to load event from Redis key {key}: {e}")

    async def _load_metrics_from_redis(self) -> None:
        """Load persisted metrics from Redis."""
        assert self.redis_handler is not None
        metric_keys = await self.redis_handler.keys("agent_metrics:*") or []
        for key in metric_keys:
            await self._load_one_metric_from_redis(key)

    async def _load_one_metric_from_redis(self, key: str) -> None:
        """Load a single metric from Redis, recording the key on success."""
        assert self.redis_handler is not None
        try:
            short_key = key.split(":")[-1]
            metric_data = await self.redis_handler.get_key("agent_metrics", short_key)
            if not metric_data:
                self.logger.warning(
                    f"Failed to load metric from Redis key {key}: No data found for key"
                )
                return
            metric_dict = await safe_json_deserialize(metric_data)
            if not metric_dict:
                return
            metric = SecurityMetric(**metric_dict)
            self.metric_buffer.append(metric)
            self.metrics_buffered += 1
            self._metric_redis_keys[id(metric)] = short_key
        except Exception as e:
            self.logger.warning(f"Failed to load metric from Redis key {key}: {e}")

    async def _clear_events_from_redis(self, count: int) -> None:
        """Clear flushed events from Redis."""
        if not self.redis_handler:
            return

        try:
            event_keys = await self.redis_handler.keys("agent_events:*") or []
            sorted_keys = sorted(event_keys)

            for i, key in enumerate(sorted_keys):
                if i >= count:
                    break
                key_name = key.split(":")[-1]
                await self.redis_handler.delete("agent_events", key_name)

        except Exception as e:
            self.logger.warning(f"Failed to clear events from Redis: {str(e)}")

    async def _clear_metrics_from_redis(self, count: int) -> None:
        """Clear flushed metrics from Redis."""
        if not self.redis_handler:
            return

        try:
            metric_keys = await self.redis_handler.keys("agent_metrics:*") or []
            sorted_keys = sorted(metric_keys)

            for i, key in enumerate(sorted_keys):
                if i >= count:
                    break
                key_name = key.split(":")[-1]
                await self.redis_handler.delete("agent_metrics", key_name)

        except Exception as e:
            self.logger.warning(f"Failed to clear metrics from Redis: {str(e)}")

    async def _clear_redis_buffers(self) -> None:
        """Clear all Redis buffers."""
        if not self.redis_handler:
            return

        try:
            event_keys = await self.redis_handler.keys("agent_events:*") or []
            for key in event_keys:
                key_name = key.split(":")[-1]
                await self.redis_handler.delete("agent_events", key_name)

            metric_keys = await self.redis_handler.keys("agent_metrics:*") or []
            for key in metric_keys:
                key_name = key.split(":")[-1]
                await self.redis_handler.delete("agent_metrics", key_name)

            self.logger.info("Cleared all Redis buffers")

        except Exception as e:
            self.logger.warning(f"Failed to clear Redis buffers: {str(e)}")

    def get_stats(self) -> dict[str, Any]:
        """Get buffer statistics."""
        return {
            "events_buffered": self.events_buffered,
            "metrics_buffered": self.metrics_buffered,
            "events_flushed": self.events_flushed,
            "metrics_flushed": self.metrics_flushed,
            "events_dropped": self.events_dropped,
            "metrics_dropped": self.metrics_dropped,
            "current_event_buffer_size": len(self.event_buffer),
            "current_metric_buffer_size": len(self.metric_buffer),
            "redis_persist_failures": self.redis_persist_failures,
            "durability_degraded": (
                self.redis_handler is not None and self.redis_persist_failures > 0
            ),
            "last_flush_time": self.last_flush_time,
            "auto_flush_running": self._running,
        }
