import asyncio

from guard_agent._buffer_redis import BufferRedisMixin
from guard_agent.exceptions import BufferFullError
from guard_agent.models import AgentConfig

BLOCK_POLICY_POLL_INTERVAL = 0.5


class BufferOverflowMixin(BufferRedisMixin):
    _DROP_LOG_INTERVAL: int
    config: AgentConfig
    events_dropped: int
    metrics_dropped: int
    _event_condition: asyncio.Condition | None
    _metric_condition: asyncio.Condition | None

    def _get_event_condition(self) -> asyncio.Condition:
        if self._event_condition is None:
            self._event_condition = asyncio.Condition()
        return self._event_condition

    def _get_metric_condition(self) -> asyncio.Condition:
        if self._metric_condition is None:
            self._metric_condition = asyncio.Condition()
        return self._metric_condition

    async def _resolve_event_overflow(self) -> bool:
        """Apply the overflow policy for one slot; caller holds the event
        condition's lock.

        Returns True when the caller must wait on the condition for space
        before retrying, False when it is safe to append now.
        """
        if not self._is_event_buffer_full():
            return False
        policy = self.config.buffer_overflow_policy
        if policy == "raise":
            raise BufferFullError(
                f"Event buffer full at maxlen={self.config.buffer_size} "
                "and buffer_overflow_policy='raise'"
            )
        if policy == "block":
            return True
        self.events_dropped += 1
        if self.events_dropped % self._DROP_LOG_INTERVAL == 1:
            self.logger.warning(
                f"Event buffer full at maxlen={self.config.buffer_size}; "
                f"dropping oldest event ({self.events_dropped} dropped total)"
            )
        dropped_key = self._forget_oldest_event_key()
        if dropped_key:
            await self.confirm_event_redis_keys([dropped_key])
        return False

    async def _resolve_metric_overflow(self) -> bool:
        """Apply the overflow policy for one slot; caller holds the metric
        condition's lock.

        Returns True when the caller must wait on the condition for space
        before retrying, False when it is safe to append now.
        """
        if not self._is_metric_buffer_full():
            return False
        policy = self.config.buffer_overflow_policy
        if policy == "raise":
            raise BufferFullError(
                f"Metric buffer full at maxlen={self.config.buffer_size} "
                "and buffer_overflow_policy='raise'"
            )
        if policy == "block":
            return True
        self.metrics_dropped += 1
        if self.metrics_dropped % self._DROP_LOG_INTERVAL == 1:
            self.logger.warning(
                f"Metric buffer full at maxlen={self.config.buffer_size}; "
                f"dropping oldest metric ({self.metrics_dropped} dropped total)"
            )
        dropped_key = self._forget_oldest_metric_key()
        if dropped_key:
            await self.confirm_metric_redis_keys([dropped_key])
        return False

    def _forget_oldest_event_key(self) -> str | None:
        if not self.event_buffer:
            return None
        oldest = self.event_buffer[0]
        return self._event_redis_keys.pop(id(oldest), None)

    def _forget_oldest_metric_key(self) -> str | None:
        if not self.metric_buffer:
            return None
        oldest = self.metric_buffer[0]
        return self._metric_redis_keys.pop(id(oldest), None)

    def _forget_newest_event_key(self) -> str | None:
        if not self.event_buffer:
            return None
        newest = self.event_buffer[-1]
        return self._event_redis_keys.pop(id(newest), None)

    def _forget_newest_metric_key(self) -> str | None:
        if not self.metric_buffer:
            return None
        newest = self.metric_buffer[-1]
        return self._metric_redis_keys.pop(id(newest), None)

    def _is_event_buffer_full(self) -> bool:
        return self.event_buffer.maxlen is not None and (
            len(self.event_buffer) >= self.event_buffer.maxlen
        )

    def _is_metric_buffer_full(self) -> bool:
        return self.metric_buffer.maxlen is not None and (
            len(self.metric_buffer) >= self.metric_buffer.maxlen
        )
