import asyncio
import logging
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

from guard_agent._buffer_queue import BufferQueueMixin
from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric
from guard_agent.protocols import BufferProtocol, RedisHandlerProtocol


class EventBuffer(BufferQueueMixin, BufferProtocol):
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

        self._event_condition: asyncio.Condition | None = None
        self._metric_condition: asyncio.Condition | None = None

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
