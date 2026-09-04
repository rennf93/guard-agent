import logging
import time
from typing import Any

from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric
from guard_agent.utils import calculate_backoff_delay, fire_error_hook

_PARTIAL_FAILURE_MAX_BACKOFF_SECONDS = 300.0


class FlushMixin:
    config: AgentConfig
    logger: logging.Logger
    buffer: Any
    transport: Any
    events_sent: int
    metrics_sent: int
    events_failed: int
    metrics_failed: int
    _events_failure_streak: int
    _metrics_failure_streak: int
    _events_retry_after: float
    _metrics_retry_after: float

    def _fire_error_hook(
        self, stage: str, exc: BaseException, context: dict[str, Any]
    ) -> None:
        fire_error_hook(self.config.on_error, self.logger, stage, exc, context)

    async def flush_buffer(self) -> None:
        try:
            await self._flush_events()
            await self._flush_metrics()
        except Exception as e:
            self.logger.error(f"Error during buffer flush: {str(e)}")

    async def _flush_events(self) -> None:
        if time.time() < self._events_retry_after:
            return

        events, event_keys = await self.buffer.flush_events_with_keys()
        if not events:
            return

        exc: BaseException | None = None
        try:
            success = bool(await self.transport.send_events(events))
        except BaseException as caught:
            success = False
            exc = caught

        if success:
            await self.buffer.confirm_event_redis_keys(event_keys)
            self.events_sent += len(events)
            self.logger.debug(f"Flushed {len(events)} events")
            if self._events_failure_streak:
                self.logger.warning(
                    f"Events flush recovered after "
                    f"{self._events_failure_streak} consecutive partial failure(s)"
                )
            self._events_failure_streak = 0
            self._events_retry_after = 0.0
            return

        await self._requeue_and_confirm_events(events, event_keys)
        self.events_failed += len(events)
        self._events_failure_streak += 1
        delay = calculate_backoff_delay(
            self._events_failure_streak - 1,
            base_delay=self.config.flush_interval,
            max_delay=_PARTIAL_FAILURE_MAX_BACKOFF_SECONDS,
        )
        self._events_retry_after = time.time() + delay
        if self._events_failure_streak == 1:
            self.logger.warning(
                f"Failed to send {len(events)} events; "
                f"requeued in memory and retained in Redis for retry; "
                f"backing off up to {delay:.0f}s between attempts"
            )
        if exc is not None:
            self.logger.error(f"Transport raised sending events: {str(exc)}")
            self._fire_error_hook("flush_events", exc, {"batch_size": len(events)})
            raise exc

    async def _flush_metrics(self) -> None:
        if time.time() < self._metrics_retry_after:
            return

        metrics, metric_keys = await self.buffer.flush_metrics_with_keys()
        if not metrics:
            return

        exc: BaseException | None = None
        try:
            success = bool(await self.transport.send_metrics(metrics))
        except BaseException as caught:
            success = False
            exc = caught

        if success:
            await self.buffer.confirm_metric_redis_keys(metric_keys)
            self.metrics_sent += len(metrics)
            self.logger.debug(f"Flushed {len(metrics)} metrics")
            if self._metrics_failure_streak:
                self.logger.warning(
                    f"Metrics flush recovered after "
                    f"{self._metrics_failure_streak} consecutive partial failure(s)"
                )
            self._metrics_failure_streak = 0
            self._metrics_retry_after = 0.0
            return

        await self._requeue_and_confirm_metrics(metrics, metric_keys)
        self.metrics_failed += len(metrics)
        self._metrics_failure_streak += 1
        delay = calculate_backoff_delay(
            self._metrics_failure_streak - 1,
            base_delay=self.config.flush_interval,
            max_delay=_PARTIAL_FAILURE_MAX_BACKOFF_SECONDS,
        )
        self._metrics_retry_after = time.time() + delay
        if self._metrics_failure_streak == 1:
            self.logger.warning(
                f"Failed to send {len(metrics)} metrics; "
                f"requeued in memory and retained in Redis for retry; "
                f"backing off up to {delay:.0f}s between attempts"
            )
        if exc is not None:
            self.logger.error(f"Transport raised sending metrics: {str(exc)}")
            self._fire_error_hook("flush_metrics", exc, {"batch_size": len(metrics)})
            raise exc

    async def _requeue_and_confirm_events(
        self, events: list[SecurityEvent], event_keys: list[str]
    ) -> None:
        evicted_event_keys = await self.buffer.requeue_events_in_memory(
            events, event_keys
        )
        if evicted_event_keys:
            await self.buffer.confirm_event_redis_keys(evicted_event_keys)

    async def _requeue_and_confirm_metrics(
        self, metrics: list[SecurityMetric], metric_keys: list[str]
    ) -> None:
        evicted_metric_keys = await self.buffer.requeue_metrics_in_memory(
            metrics, metric_keys
        )
        if evicted_metric_keys:
            await self.buffer.confirm_metric_redis_keys(evicted_metric_keys)
