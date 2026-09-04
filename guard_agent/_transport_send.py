import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from guard_agent._transport_dispatch import TransportDispatchMixin
from guard_agent._version import __version__ as _AGENT_VERSION
from guard_agent.exceptions import PayloadTooLargeError, PermanentClientError
from guard_agent.models import (
    AgentConfig,
    AgentStatus,
    DynamicRules,
    EventBatch,
    SecurityEvent,
    SecurityMetric,
)
from guard_agent.utils import (
    RateLimitedError,
    calculate_backoff_delay,
    generate_batch_id,
    get_current_timestamp,
)

_MAX_RETRY_AFTER_SECONDS = 300.0


class TransportSendMixin(TransportDispatchMixin):
    config: AgentConfig
    logger: logging.Logger

    async def send_events(self, events: list[SecurityEvent]) -> bool:
        """Send security events to the SaaS platform.

        Returns True when the batch was durably accepted OR intentionally
        dropped because it is permanently un-sendable (non-retryable 4xx);
        the caller deletes Redis keys and does not requeue in both cases.
        Returns False only on transient failure, so the caller requeues and
        retains the Redis keys for retry.
        """
        if not events:
            return True

        try:
            batch = EventBatch(
                project_id=self.config.project_id or "default",
                events=events,
                batch_id=generate_batch_id(),
                created_at=get_current_timestamp(),
                agent_version=_AGENT_VERSION,
                guard_version=self.config.guard_version,
                guard_core_version=self.config.guard_core_version,
            )

            return await self._send_with_retry(
                "/api/v1/events", batch.model_dump(), "events"
            )

        except PayloadTooLargeError as e:
            return await self._split_or_drop_on_payload_too_large(
                events, e, "events", self.send_events
            )
        except PermanentClientError as e:
            self._drop_permanent_rejection(events, e, "events")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send events: {str(e)}")
            self.requests_failed += 1
            return False

    async def send_metrics(self, metrics: list[SecurityMetric]) -> bool:
        """Send metrics to the SaaS platform."""
        if not metrics:
            return True

        try:
            batch = EventBatch(
                project_id=self.config.project_id or "default",
                metrics=metrics,
                batch_id=generate_batch_id(),
                created_at=get_current_timestamp(),
                agent_version=_AGENT_VERSION,
                guard_version=self.config.guard_version,
                guard_core_version=self.config.guard_core_version,
            )

            return await self._send_with_retry(
                "/api/v1/metrics", batch.model_dump(), "metrics"
            )

        except PayloadTooLargeError as e:
            return await self._split_or_drop_on_payload_too_large(
                metrics, e, "metrics", self.send_metrics
            )
        except PermanentClientError as e:
            self._drop_permanent_rejection(metrics, e, "metrics")
            return True
        except Exception as e:
            self.logger.error(f"Failed to send metrics: {str(e)}")
            self.requests_failed += 1
            return False

    async def _split_or_drop_on_payload_too_large(
        self,
        items: list,
        error: PayloadTooLargeError,
        data_type: str,
        send_half: Callable[[list], Awaitable[bool]],
    ) -> bool:
        if len(items) <= 1:
            self.logger.warning(
                f"Dropping {data_type} batch of {len(items)} item; "
                f"payload exceeds size cap even as a single item: {error.detail}"
            )
            self.requests_failed += 1
            self._fire_error_hook(
                "transport_send",
                error,
                {"data_type": data_type, "item_count": len(items)},
            )
            return True
        midpoint = len(items) // 2
        left = await send_half(items[:midpoint])
        right = await send_half(items[midpoint:])
        return left and right

    def _drop_permanent_rejection(
        self, items: list, error: PermanentClientError, data_type: str
    ) -> None:
        self.logger.warning(
            f"Dropping {data_type} batch of {len(items)} item(s); "
            f"permanently rejected ({error.status_code}): {error.detail}"
        )
        self.requests_failed += 1
        self._fire_error_hook(
            "transport_send",
            error,
            {"data_type": data_type, "item_count": len(items)},
        )

    async def fetch_dynamic_rules(self) -> DynamicRules | None:
        """Fetch dynamic rules from the SaaS platform."""
        try:
            response_data = await self._get_with_retry("/api/v1/rules")

            if response_data:
                return DynamicRules(**response_data)

            return None

        except Exception as e:
            self.logger.error(f"Failed to fetch dynamic rules: {str(e)}")
            return None

    async def send_status(self, status: AgentStatus) -> bool:
        """Send agent status/health information."""
        try:
            return await self._send_with_retry(
                "/api/v1/status", status.model_dump(), "status"
            )

        except Exception as e:
            self.logger.error(f"Failed to send status: {str(e)}")
            return False

    def _evaluate_send_result(self, result: Any, data_type: str) -> bool | None:
        """Return True (accepted), False (partial failure), or None (retry)."""
        if isinstance(result, dict) and (
            result.get("success") is False or result.get("errors")
        ):
            self.logger.warning(
                f"Server acknowledged {data_type} batch with partial failure: "
                f"success={result.get('success')!r} errors={result.get('errors')!r}"
            )
            self.requests_failed += 1
            return False
        if result:
            self.requests_sent += 1
            self.logger.debug(f"Successfully sent {data_type} batch")
            return True
        self.requests_failed += 1
        return None

    async def _sleep_or_record_giveup(self, attempt: int, delay: float) -> bool:
        """Sleep to retry (return True) or record a final failure (return False)."""
        if attempt < self.config.retry_attempts:
            await asyncio.sleep(delay)
            return True
        self.requests_failed += 1
        return False

    async def _send_with_retry(
        self, endpoint: str, data: dict[str, Any], data_type: str
    ) -> bool:
        """Send data with retry logic and circuit breaker."""
        for attempt in range(self.config.retry_attempts + 1):
            try:
                if not await self.rate_limiter.acquire():
                    retry_after = self.rate_limiter.get_retry_after()
                    self.logger.warning(
                        f"Rate limit exceeded, waiting {retry_after:.1f}s"
                    )
                    await asyncio.sleep(retry_after)
                    continue

                result = await self.circuit_breaker.call(
                    self._make_request, "POST", endpoint, data
                )

                outcome = self._evaluate_send_result(result, data_type)
                if outcome is not None:
                    return outcome

            except RateLimitedError as e:
                delay = min(e.retry_after_seconds, _MAX_RETRY_AFTER_SECONDS)
                self.logger.warning(
                    f"Server rate-limited {data_type}; sleeping {delay:.1f}s "
                    f"per Retry-After"
                )
                await self._sleep_or_record_giveup(attempt, delay)
            except PermanentClientError:
                raise
            except Exception as e:
                self.logger.warning(
                    f"Attempt {attempt + 1} failed for {data_type}: {str(e)}"
                )

                delay = calculate_backoff_delay(attempt, self.config.backoff_factor)
                if not await self._sleep_or_record_giveup(attempt, delay):
                    self.logger.error(f"All retry attempts failed for {data_type}")
                    self._fire_error_hook(
                        "transport_send",
                        e,
                        {"endpoint": endpoint, "data_type": data_type},
                    )

        return False

    async def _get_with_retry(self, endpoint: str) -> dict[str, Any] | None:
        """GET request with retry logic and circuit breaker."""
        for attempt in range(self.config.retry_attempts + 1):
            try:
                if not await self.rate_limiter.acquire():
                    retry_after = self.rate_limiter.get_retry_after()
                    await asyncio.sleep(retry_after)
                    continue

                response_data = await self.circuit_breaker.call(
                    self._make_request, "GET", endpoint, None
                )

                if isinstance(response_data, dict):
                    self.requests_sent += 1
                    return response_data
                else:
                    self.requests_failed += 1

            except RateLimitedError as e:
                delay = min(e.retry_after_seconds, _MAX_RETRY_AFTER_SECONDS)
                self.logger.warning(
                    f"Server rate-limited GET {endpoint}; sleeping {delay:.1f}s "
                    f"per Retry-After"
                )
                if attempt < self.config.retry_attempts:
                    await asyncio.sleep(delay)
                else:
                    self.requests_failed += 1
            except Exception as e:
                self.logger.warning(
                    f"GET attempt {attempt + 1} failed for {endpoint}: {str(e)}"
                )

                if attempt < self.config.retry_attempts:
                    delay = calculate_backoff_delay(attempt, self.config.backoff_factor)
                    await asyncio.sleep(delay)
                else:
                    self.requests_failed += 1

        return None
