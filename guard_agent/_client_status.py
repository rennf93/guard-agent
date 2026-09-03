import logging
import time
from typing import Any, Literal

from guard_agent.models import AgentConfig, AgentStatus, DynamicRules
from guard_agent.utils import get_current_timestamp


class StatusMixin:
    config: AgentConfig
    logger: logging.Logger
    buffer: Any
    transport: Any
    _start_time: float
    _running: bool
    events_sent: int
    metrics_sent: int
    events_failed: int
    metrics_failed: int
    rules_fetched: int
    _cached_rules: DynamicRules | None
    _rules_last_update: float
    _flush_consecutive_failures: int
    _status_consecutive_failures: int
    _rules_consecutive_failures: int
    _last_status_push_ok: bool | None

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
