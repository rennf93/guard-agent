import asyncio
import logging
import os
import threading
import time
from typing import Any

from guard_agent._client_ingest import IngestMixin
from guard_agent._client_loops import LoopsMixin
from guard_agent.buffer import EventBuffer
from guard_agent.logging_utils import setup_agent_logging
from guard_agent.models import AgentConfig, DynamicRules
from guard_agent.protocols import AgentHandlerProtocol, RedisHandlerProtocol
from guard_agent.transport import HTTPTransport
from guard_agent.utils import validate_config


class GuardAgentHandler(IngestMixin, LoopsMixin, AgentHandlerProtocol):
    """
    Async agent handler for ASGI frameworks (FastAPI, etc.).
    All public methods are coroutines compatible with async guard-core adapters.
    """

    _instance: "GuardAgentHandler | None" = None
    _initialized: bool
    _owner_pid: int
    _fork_hook_registered: bool = False

    def __new__(cls, config: AgentConfig) -> "GuardAgentHandler":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
            cls._instance._owner_pid = os.getpid()
            cls._register_fork_hook()
        elif cls._instance._owner_pid != os.getpid():
            cls._instance._initialized = False
            cls._instance._owner_pid = os.getpid()
            cls._instance._flush_task = None
            cls._instance._status_task = None
            cls._instance._rules_task = None
        return cls._instance

    @classmethod
    def _register_fork_hook(cls) -> None:
        if cls._fork_hook_registered:
            return
        register = getattr(os, "register_at_fork", None)
        if register is not None:
            register(after_in_child=cls._reset_after_fork)
        cls._fork_hook_registered = True

    @classmethod
    def _reset_after_fork(cls) -> None:
        if cls._instance is None:
            return
        cls._instance._initialized = False
        cls._instance._owner_pid = os.getpid()
        cls._instance._flush_task = None
        cls._instance._status_task = None
        cls._instance._rules_task = None

    def __init__(self, config: AgentConfig):
        setup_agent_logging(reconfigure=False)

        if hasattr(self, "_initialized") and self._initialized:
            self.config = config
            return

        self.config = config
        self.logger = logging.getLogger(__name__)

        config_errors = validate_config(config)
        if config_errors:
            raise ValueError(f"Invalid agent configuration: {'; '.join(config_errors)}")

        self.buffer = EventBuffer(config, flush_callback=self.flush_buffer)
        self.transport = HTTPTransport(config)

        self.redis_handler: RedisHandlerProtocol | None = None

        self._running = False
        self._flush_task: asyncio.Task | None = None
        self._status_task: asyncio.Task | None = None
        self._rules_task: asyncio.Task | None = None
        self._start_time = time.time()

        self.events_sent = 0
        self.metrics_sent = 0
        self.events_failed = 0
        self.metrics_failed = 0
        self.rules_fetched = 0

        self._flush_consecutive_failures = 0
        self._status_consecutive_failures = 0
        self._rules_consecutive_failures = 0
        self._loop_error_log_threshold = 3
        self._last_status_push_ok: bool | None = None

        self._events_failure_streak = 0
        self._metrics_failure_streak = 0
        self._events_retry_after = 0.0
        self._metrics_retry_after = 0.0

        self._cached_rules: DynamicRules | None = None
        self._rules_last_update: float = 0

        self._initialized = True
        self.logger.info("Guard Agent Handler initialized")

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        self.redis_handler = redis_handler
        await self.buffer.initialize_redis(redis_handler)
        self.logger.info("Redis integration initialized")

    async def start(self) -> None:
        if self._running:
            self.logger.warning("Agent is already running")
            return

        try:
            await self.transport.initialize()
            await self.buffer.start_auto_flush()

            self._running = True
            self._flush_task = asyncio.create_task(self._flush_loop())
            self._status_task = asyncio.create_task(self._status_loop())

            if self.config.project_id:
                self._rules_task = asyncio.create_task(self._rules_loop())

            self.logger.info("Guard Agent started successfully")

        except Exception as e:
            self.logger.error(f"Failed to start agent: {str(e)}")
            await self.stop()
            raise

    async def stop(self) -> None:
        self._running = False

        tasks = [self._flush_task, self._status_task, self._rules_task]
        for task in tasks:
            if task and not task.done():
                task.cancel()

        for task in tasks:
            if task:
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        await self.buffer.stop_auto_flush()
        await self.flush_buffer()
        await self.transport.close()

        self.logger.info("Guard Agent stopped")

    async def close(self) -> None:
        await self.stop()


class SyncGuardAgentHandler:
    """
    Sync wrapper around GuardAgentHandler for WSGI frameworks (Django, Flask).
    Runs async logic in a dedicated background thread with its own event loop,
    providing a fully synchronous interface compatible with guard-core's sync
    CompositeAgentHandler.
    """

    _instance: "SyncGuardAgentHandler | None" = None

    def __new__(cls, config: AgentConfig) -> "SyncGuardAgentHandler":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config: AgentConfig) -> None:
        setup_agent_logging(reconfigure=False)

        if hasattr(self, "_loop"):
            return
        self._inner = GuardAgentHandler(config)
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, args=(self._loop,), daemon=True
        )
        self._thread.start()
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _run_loop(loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def _run(self, coro: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        self._run(self._inner.initialize_redis(redis_handler))

    def start(self) -> None:
        self._run(self._inner.start())

    def stop(self) -> None:
        self._run(self._inner.stop())
        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    def send_event(self, event: Any) -> None:
        self._run(self._inner.send_event(event))

    def send_metric(self, metric: Any) -> None:
        self._run(self._inner.send_metric(metric))

    def flush_buffer(self) -> None:
        self._run(self._inner.flush_buffer())

    def get_dynamic_rules(self) -> DynamicRules | None:
        result: DynamicRules | None = self._run(self._inner.get_dynamic_rules())
        return result

    def health_check(self) -> bool:
        result: bool = self._run(self._inner.health_check())
        return result

    def get_stats(self) -> dict[str, Any]:
        return self._inner.get_stats()


def guard_agent(config: AgentConfig) -> GuardAgentHandler | SyncGuardAgentHandler:
    """
    Factory function for the agent handler.
    Returns SyncGuardAgentHandler when called from a sync context (no running
    event loop), and GuardAgentHandler when called from an async context.
    """
    try:
        asyncio.get_running_loop()
        return GuardAgentHandler(config)
    except RuntimeError:
        return SyncGuardAgentHandler(config)
