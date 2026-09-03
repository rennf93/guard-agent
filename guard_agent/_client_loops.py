import asyncio
import logging
import time
from typing import Any

from guard_agent._client_flush import FlushMixin
from guard_agent._client_status import StatusMixin
from guard_agent.models import AgentConfig, DynamicRules
from guard_agent.protocols import TransportProtocol


class RulesMixin:
    logger: logging.Logger
    transport: TransportProtocol
    rules_fetched: int
    _cached_rules: DynamicRules | None
    _rules_last_update: float

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


class LoopsMixin(FlushMixin, StatusMixin, RulesMixin):
    config: AgentConfig
    logger: logging.Logger
    transport: Any
    _running: bool
    _loop_error_log_threshold: int
    _flush_consecutive_failures: int
    _status_consecutive_failures: int
    _rules_consecutive_failures: int
    _last_status_push_ok: bool | None

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
