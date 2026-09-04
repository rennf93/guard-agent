import asyncio
import time

from guard_agent._buffer_lifecycle import BufferLifecycleMixin
from guard_agent._buffer_overflow import BLOCK_POLICY_POLL_INTERVAL, BufferOverflowMixin
from guard_agent.models import SecurityEvent, SecurityMetric


class BufferQueueMixin(BufferOverflowMixin, BufferLifecycleMixin):
    events_flushed: int
    metrics_flushed: int

    async def add_event(self, event: SecurityEvent) -> None:
        """Add security event to buffer honoring the configured overflow
        policy.

        Under the block policy, a requeue after a failed send always keeps
        its slot (durability wins over a new writer); this waiter never
        stalls past BLOCK_POLICY_POLL_INTERVAL before re-checking for space.
        """
        condition = self._get_event_condition()
        async with condition:
            while True:
                must_wait = await self._resolve_event_overflow()
                if not must_wait:
                    try:
                        self.event_buffer.append(event)
                        self.events_buffered += 1
                        if self.redis_handler:
                            key = await self._persist_event_to_redis(event)
                            if key is not None:
                                self._event_redis_keys[id(event)] = key
                    except Exception as e:
                        self.logger.error(f"Failed to buffer event: {str(e)}")
                    break
                try:
                    await asyncio.wait_for(
                        condition.wait(), timeout=BLOCK_POLICY_POLL_INTERVAL
                    )
                except asyncio.TimeoutError:
                    pass

        if (
            len(self.event_buffer)
            >= self.config.buffer_size * self.config.high_watermark_ratio
        ):
            task: asyncio.Task[None] = asyncio.create_task(self._flush_if_needed())
            self._inflight_flush_tasks.add(task)
            task.add_done_callback(self._inflight_flush_tasks.discard)

    async def add_metric(self, metric: SecurityMetric) -> None:
        """Add metric to buffer honoring the configured overflow policy.

        See add_event for the block-policy starvation rule.
        """
        condition = self._get_metric_condition()
        async with condition:
            while True:
                must_wait = await self._resolve_metric_overflow()
                if not must_wait:
                    try:
                        self.metric_buffer.append(metric)
                        self.metrics_buffered += 1
                        if self.redis_handler:
                            key = await self._persist_metric_to_redis(metric)
                            if key is not None:
                                self._metric_redis_keys[id(metric)] = key
                    except Exception as e:
                        self.logger.error(f"Failed to buffer metric: {str(e)}")
                    break
                try:
                    await asyncio.wait_for(
                        condition.wait(), timeout=BLOCK_POLICY_POLL_INTERVAL
                    )
                except asyncio.TimeoutError:
                    pass

        if (
            len(self.metric_buffer)
            >= self.config.buffer_size * self.config.high_watermark_ratio
        ):
            task = asyncio.create_task(self._flush_if_needed())
            self._inflight_flush_tasks.add(task)
            task.add_done_callback(self._inflight_flush_tasks.discard)

    async def flush_events(self) -> list[SecurityEvent]:
        """Flush events and immediately forget Redis keys (legacy semantics)."""
        events, keys = await self.flush_events_with_keys()
        await self.confirm_event_redis_keys(keys)
        return events

    async def flush_metrics(self) -> list[SecurityMetric]:
        """Flush metrics and immediately forget Redis keys (legacy semantics)."""
        metrics, keys = await self.flush_metrics_with_keys()
        await self.confirm_metric_redis_keys(keys)
        return metrics

    async def flush_events_with_keys(
        self,
    ) -> tuple[list[SecurityEvent], list[str]]:
        """Flush events plus their Redis keys (one entry per event, "" when the
        event was never persisted to Redis); keys stay aligned with events so
        a failed send can requeue correctly with or without Redis configured."""
        condition = self._get_event_condition()
        async with condition:
            events = list(self.event_buffer)
            keys = [self._event_redis_keys.pop(id(event), "") for event in events]
            self.event_buffer.clear()
            self.events_flushed += len(events)
            self.last_flush_time = time.time()
            if events:
                condition.notify_all()
        return events, keys

    async def flush_metrics_with_keys(
        self,
    ) -> tuple[list[SecurityMetric], list[str]]:
        """Flush metrics plus their Redis keys (one entry per metric, "" when
        the metric was never persisted to Redis); keys stay aligned with
        metrics so a failed send can requeue correctly with or without Redis
        configured."""
        condition = self._get_metric_condition()
        async with condition:
            metrics = list(self.metric_buffer)
            keys = [self._metric_redis_keys.pop(id(metric), "") for metric in metrics]
            self.metric_buffer.clear()
            self.metrics_flushed += len(metrics)
            self.last_flush_time = time.time()
            if metrics:
                condition.notify_all()
        return metrics, keys

    async def requeue_events_in_memory(
        self, events: list[SecurityEvent], keys: list[str]
    ) -> list[str]:
        """Push unsent events back to the front of the buffer; keep Redis
        keys. appendleft evicts from the tail when the buffer is full, so
        that is the side whose key gets forgotten; the caller must confirm
        (delete) the returned keys so their Redis records do not orphan."""
        evicted_keys: list[str] = []
        async with self._get_event_condition():
            for event, key in zip(reversed(events), reversed(keys), strict=True):
                if self._is_event_buffer_full():
                    self.events_dropped += 1
                    evicted_key = self._forget_newest_event_key()
                    if evicted_key:
                        evicted_keys.append(evicted_key)
                self.event_buffer.appendleft(event)
                if key:
                    self._event_redis_keys[id(event)] = key
        return evicted_keys

    async def requeue_metrics_in_memory(
        self, metrics: list[SecurityMetric], keys: list[str]
    ) -> list[str]:
        """Push unsent metrics back to the front of the buffer; keep Redis
        keys. appendleft evicts from the tail when the buffer is full, so
        that is the side whose key gets forgotten; the caller must confirm
        (delete) the returned keys so their Redis records do not orphan."""
        evicted_keys: list[str] = []
        async with self._get_metric_condition():
            for metric, key in zip(reversed(metrics), reversed(keys), strict=True):
                if self._is_metric_buffer_full():
                    self.metrics_dropped += 1
                    evicted_key = self._forget_newest_metric_key()
                    if evicted_key:
                        evicted_keys.append(evicted_key)
                self.metric_buffer.appendleft(metric)
                if key:
                    self._metric_redis_keys[id(metric)] = key
        return evicted_keys

    async def clear_buffer(self) -> None:
        """Clear all buffers, including the Redis-key maps so a later
        object cannot inherit a stale or foreign key via id() reuse."""
        event_condition = self._get_event_condition()
        async with event_condition:
            self.event_buffer.clear()
            self._event_redis_keys.clear()
            event_condition.notify_all()

        metric_condition = self._get_metric_condition()
        async with metric_condition:
            self.metric_buffer.clear()
            self._metric_redis_keys.clear()
            metric_condition.notify_all()

        if self.redis_handler:
            await self._clear_redis_buffers()
