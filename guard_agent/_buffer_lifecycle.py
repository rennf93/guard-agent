import asyncio
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable

from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric


class BufferLifecycleMixin:
    config: AgentConfig
    logger: logging.Logger
    event_buffer: "deque[SecurityEvent]"
    metric_buffer: "deque[SecurityMetric]"
    last_flush_time: float | None
    _flush_callback: Callable[[], Awaitable[None]] | None
    _flush_task: asyncio.Task[None] | None
    _flush_semaphore: asyncio.Semaphore | None
    _running: bool
    _inflight_flush_tasks: set[asyncio.Task[None]]

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

    async def get_buffer_size(self) -> int:
        """Get current total buffer size."""
        return len(self.event_buffer) + len(self.metric_buffer)

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
