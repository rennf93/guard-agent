import asyncio
import logging
import os
import threading
import time
from typing import Any, Literal

from guard_agent.buffer import EventBuffer
from guard_agent.logging_utils import setup_agent_logging
from guard_agent.models import (
    AgentConfig,
    AgentStatus,
    DynamicRules,
    SecurityEvent,
    SecurityMetric,
)
from guard_agent.protocols import AgentHandlerProtocol, RedisHandlerProtocol
from guard_agent.transport import HTTPTransport
from guard_agent.utils import (
    calculate_backoff_delay,
    get_current_timestamp,
    validate_config,
)

_PARTIAL_FAILURE_MAX_BACKOFF_SECONDS = 300.0


class GuardAgentHandler(AgentHandlerProtocol):
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

    async def send_event(self, event: Any) -> None:
        if not self.config.enable_events:
            return

        try:
            if not isinstance(event, SecurityEvent):
                event = self._normalize_event(event)
            await self.buffer.add_event(event)
            self.logger.debug(
                f"Event buffered: {event.event_type} from {event.ip_address}"
            )
        except Exception as e:
            self.logger.error(f"Failed to buffer event: {str(e)}")

    async def send_metric(self, metric: Any) -> None:
        if not self.config.enable_metrics:
            return

        try:
            if not isinstance(metric, SecurityMetric):
                metric = self._normalize_metric(metric)
            await self.buffer.add_metric(metric)
            self.logger.debug(f"Metric buffered: {metric.metric_type} = {metric.value}")
        except Exception as e:
            self.logger.error(f"Failed to buffer metric: {str(e)}")

    def _normalize_event(self, event: Any) -> SecurityEvent:
        event_data: dict[str, Any] = {}
        for field_name in SecurityEvent.model_fields:
            if hasattr(event, field_name):
                event_data[field_name] = getattr(event, field_name)
        return SecurityEvent(**event_data)

    def _normalize_metric(self, metric: Any) -> SecurityMetric:
        metric_data: dict[str, Any] = {}
        for field_name in SecurityMetric.model_fields:
            if hasattr(metric, field_name):
                metric_data[field_name] = getattr(metric, field_name)
        return SecurityMetric(**metric_data)

    async def get_dynamic_rules(self) -> DynamicRules | None:
        current_time = time.time()

        if (
            self._cached_rules
            and current_time - self._rules_last_update < self._cached_rules.ttl
        ):
            return self._cached_rules

        try:
            rules = await self.transport.fetch_dynamic_rules()
            if rules:
                self._cached_rules = rules
                self._rules_last_update = current_time
                self.rules_fetched += 1
                self.logger.debug("Dynamic rules updated")
            return rules
        except Exception as e:
            self.logger.error(f"Failed to fetch dynamic rules: {str(e)}")
            return self._cached_rules

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

        success = await self.transport.send_events(events)
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

        self.buffer.requeue_events_in_memory(events, event_keys)
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

    async def _flush_metrics(self) -> None:
        if time.time() < self._metrics_retry_after:
            return

        metrics, metric_keys = await self.buffer.flush_metrics_with_keys()
        if not metrics:
            return

        success = await self.transport.send_metrics(metrics)
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

        self.buffer.requeue_metrics_in_memory(metrics, metric_keys)
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

    async def get_status(self) -> AgentStatus:
        current_time = get_current_timestamp()
        uptime = time.time() - self._start_time
        buffer_size = await self.buffer.get_buffer_size()

        transport_stats = self.transport.get_stats()
        buffer_stats = self.buffer.get_stats()

        status: Literal["healthy", "degraded", "failed"] = "healthy"
        errors: list[str] = []

        if transport_stats["circuit_breaker_state"] == "OPEN":
            status = "degraded"
            errors.append("Transport circuit breaker is open")

        if buffer_size >= self.config.buffer_size * 0.9:
            status = "degraded"
            errors.append("Buffer nearly full")

        if self.events_failed + self.metrics_failed > 0:
            failure_rate = (self.events_failed + self.metrics_failed) / max(
                1,
                self.events_sent
                + self.metrics_sent
                + self.events_failed
                + self.metrics_failed,
            )
            if failure_rate > 0.1:
                status = "degraded"
                errors.append(f"High failure rate: {failure_rate:.1%}")

        return AgentStatus(
            timestamp=current_time,
            status=status,
            uptime=uptime,
            events_sent=self.events_sent,
            events_failed=self.events_failed,
            buffer_size=buffer_size,
            last_flush=buffer_stats.get("last_flush_time"),
            errors=errors,
        )

    async def close(self) -> None:
        await self.stop()

    def _log_loop_failure(self, loop_name: str, count: int, exc: Exception) -> None:
        message = (
            f"{loop_name} failed {count} consecutive time(s); "
            f"cause: {type(exc).__name__}: {exc}"
        )
        if count >= self._loop_error_log_threshold:
            self.logger.error(message)
        else:
            self.logger.warning(message)

    async def _flush_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.config.flush_interval)
                if self._running:
                    await self.flush_buffer()
                self._flush_consecutive_failures = 0
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._flush_consecutive_failures += 1
                self._log_loop_failure(
                    "flush loop", self._flush_consecutive_failures, e
                )

    async def _status_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.config.status_interval)
                if self._running:
                    status = await self.get_status()
                    ok = await self.transport.send_status(status)
                    self._last_status_push_ok = bool(ok)
                    if ok:
                        self._status_consecutive_failures = 0
                    else:
                        self._status_consecutive_failures += 1
                        self._log_loop_failure(
                            "status loop",
                            self._status_consecutive_failures,
                            RuntimeError("send_status returned False"),
                        )
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._last_status_push_ok = False
                self._status_consecutive_failures += 1
                self._log_loop_failure(
                    "status loop", self._status_consecutive_failures, e
                )

    async def _rules_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self.config.dynamic_rule_interval)
                if self._running:
                    await self.get_dynamic_rules()
                self._rules_consecutive_failures = 0
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._rules_consecutive_failures += 1
                self._log_loop_failure(
                    "rules loop", self._rules_consecutive_failures, e
                )

    def get_stats(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "uptime": time.time() - self._start_time,
            "events_sent": self.events_sent,
            "metrics_sent": self.metrics_sent,
            "events_failed": self.events_failed,
            "metrics_failed": self.metrics_failed,
            "rules_fetched": self.rules_fetched,
            "buffer_stats": self.buffer.get_stats(),
            "transport_stats": self.transport.get_stats(),
            "cached_rules": self._cached_rules is not None,
            "rules_last_update": self._rules_last_update,
            "loop_failures": {
                "flush": self._flush_consecutive_failures,
                "status": self._status_consecutive_failures,
                "rules": self._rules_consecutive_failures,
            },
            "last_status_push_ok": self._last_status_push_ok,
        }

    async def health_check(self) -> bool:
        if not self._running:
            return False

        try:
            transport_stats = self.transport.get_stats()
            if transport_stats.get("circuit_breaker_state") == "OPEN":
                return False

            buffer_size = await self.buffer.get_buffer_size()
            if buffer_size >= self.config.buffer_size * 0.95:
                return False

            total_sent = self.events_sent + self.metrics_sent
            total_failed = self.events_failed + self.metrics_failed
            total_attempts = total_sent + total_failed

            if total_attempts > 0:
                failure_rate = total_failed / total_attempts
                if failure_rate > 0.5:
                    return False

            return True
        except Exception as e:
            self.logger.error(f"Error during health check: {str(e)}")
            return False


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
