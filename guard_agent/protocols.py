from typing import Any, Protocol, runtime_checkable

from guard_agent.models import AgentStatus, DynamicRules, SecurityEvent, SecurityMetric


@runtime_checkable
class RedisHandlerProtocol(Protocol):
    """Storage backend the agent uses for durable, cross-worker buffering.

    WHAT: a namespaced async key-value store; the agent persists pending
    events/metrics here so nothing is lost across workers or restarts.
    WHEN: ``initialize`` runs once at startup; reads/writes happen as the agent
    buffers and flushes. Shared with fastapi-guard's own Redis handler.
    HOW: implement a thin adapter over your Redis client. Reads return ``None``
    on a miss (never raise for absent keys); TTLs are in seconds.
    """

    async def get_key(self, namespace: str, key: str) -> Any:
        """Return the value stored at ``namespace:key``, or ``None`` if absent."""
        ...

    async def set_key(
        self, namespace: str, key: str, value: Any, ttl: int | None = None
    ) -> bool | None:
        """Store ``value`` at ``namespace:key``, expiring after ``ttl`` seconds.

        ``ttl=None`` persists with no expiry. Returns the backend's set result
        (truthy on success) or ``None`` when the backend reports nothing.
        """
        ...

    async def delete(self, namespace: str, key: str) -> int | None:
        """Delete ``namespace:key``; return the number of keys removed (0 if none)."""
        ...

    async def keys(self, pattern: str) -> list[str] | None:
        """Return keys matching ``pattern``, or ``None`` when none can be listed."""
        ...

    async def initialize(self) -> None:
        """Open the connection/pool. Called once at startup before any access."""
        ...

    def get_connection(self) -> Any:
        """Return a raw client for operations not covered by this protocol."""
        ...


@runtime_checkable
class TransportProtocol(Protocol):
    """Carries events, metrics and status to the collector, and pulls rules back.

    WHAT: the network seam between the agent and the Guard Core API; the only
    component that performs outbound HTTP.
    WHEN: invoked by the agent's flush loop once a batch is ready, and by the
    rule-sync loop on its interval.
    HOW: implement the send/fetch calls over your HTTP client. ``send_*`` return
    ``True`` only when the batch was accepted (so the caller can requeue on
    ``False``); surface unrecoverable failures as the agent's own errors rather
    than raising into the flush loop.
    """

    async def send_events(self, events: list[SecurityEvent]) -> bool:
        """Deliver a batch of events; return ``True`` only if accepted."""
        ...

    async def send_metrics(self, metrics: list[SecurityMetric]) -> bool:
        """Deliver a batch of metrics; return ``True`` only if accepted."""
        ...

    async def fetch_dynamic_rules(self) -> DynamicRules | None:
        """Fetch the current dynamic rules, or ``None`` if none/unreachable."""
        ...

    async def send_status(self, status: AgentStatus) -> bool:
        """Report agent health/status; return ``True`` only if accepted."""
        ...


@runtime_checkable
class BufferProtocol(Protocol):
    """Holds events/metrics between production and delivery for at-least-once send.

    WHAT: a durable queue. Items are added as they occur, drained in batches for
    sending, then either confirmed (on success) or requeued (on failure).
    WHEN: the agent adds on every event/metric and flushes on its interval; the
    ``*_with_keys`` / ``confirm_*`` / ``requeue_*`` calls implement the
    at-least-once handshake around a send attempt.
    HOW: back it with Redis (via ``RedisHandlerProtocol``) so the buffer
    survives restarts. ``flush_*`` drain and return the pending batch;
    ``flush_*_with_keys`` also return the backing keys to confirm or requeue
    once the send result is known.
    """

    async def add_event(self, event: SecurityEvent) -> None:
        """Append an event to the buffer."""
        ...

    async def add_metric(self, metric: SecurityMetric) -> None:
        """Append a metric to the buffer."""
        ...

    async def flush_events(self) -> list[SecurityEvent]:
        """Drain and return the buffered events (empty list if none)."""
        ...

    async def flush_metrics(self) -> list[SecurityMetric]:
        """Drain and return the buffered metrics (empty list if none)."""
        ...

    async def flush_events_with_keys(
        self,
    ) -> tuple[list[SecurityEvent], list[str]]:
        """Drain events and their backing keys, for later confirm/requeue."""
        ...

    async def flush_metrics_with_keys(
        self,
    ) -> tuple[list[SecurityMetric], list[str]]:
        """Drain metrics and their backing keys, for later confirm/requeue."""
        ...

    async def confirm_event_redis_keys(self, keys: list[str]) -> None:
        """Permanently drop event keys after a successful send."""
        ...

    async def confirm_metric_redis_keys(self, keys: list[str]) -> None:
        """Permanently drop metric keys after a successful send."""
        ...

    async def requeue_events_in_memory(
        self, events: list[SecurityEvent], keys: list[str]
    ) -> list[str]:
        """Return events to the in-memory buffer after a failed send.

        Returns the Redis keys of any items evicted to make room, which the
        caller must confirm (delete) so their records do not orphan.
        """
        ...

    async def requeue_metrics_in_memory(
        self, metrics: list[SecurityMetric], keys: list[str]
    ) -> list[str]:
        """Return metrics to the in-memory buffer after a failed send.

        Returns the Redis keys of any items evicted to make room, which the
        caller must confirm (delete) so their records do not orphan.
        """
        ...

    async def get_buffer_size(self) -> int:
        """Return the number of items currently buffered."""
        ...

    async def clear_buffer(self) -> None:
        """Discard all buffered items."""
        ...


@runtime_checkable
class AgentHandlerProtocol(Protocol):
    """Top-level agent the host middleware drives to ship telemetry off-box.

    WHAT: the facade over buffer, transport and rule-sync; what fastapi-guard
    holds and calls. Aligned with fastapi-guard's ``AgentHandlerProtocol``.
    WHEN: ``initialize_redis`` then ``start`` at startup; ``send_event`` /
    ``send_metric`` per request; ``get_dynamic_rules`` on the rule-sync
    interval; ``stop`` / ``close`` at shutdown.
    HOW: implement ``send_*`` as non-blocking, fire-and-forget enqueues that
    never raise into the request path; do delivery on background loops.
    """

    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        """Attach the shared Redis backend used for durable buffering."""
        ...

    async def send_event(self, event: Any) -> None:
        """Enqueue a security event for delivery. Must not block or raise."""
        ...

    async def send_metric(self, metric: Any) -> None:
        """Enqueue a metric for delivery. Must not block or raise."""
        ...

    async def start(self) -> None:
        """Start the background flush and rule-sync loops."""
        ...

    async def stop(self) -> None:
        """Stop background loops, flushing what is buffered. Idempotent."""
        ...

    async def flush_buffer(self) -> None:
        """Force an immediate send of any buffered events and metrics."""
        ...

    async def get_dynamic_rules(self) -> DynamicRules | None:
        """Return the latest dynamic rules, or ``None`` if unavailable."""
        ...

    async def health_check(self) -> bool:
        """Return ``True`` when the agent can reach its collector."""
        ...

    async def get_status(self) -> AgentStatus:
        """Return a snapshot of the agent's current health/status."""
        ...

    async def close(self) -> None:
        """Release all resources; the agent is unusable afterward."""
        ...
