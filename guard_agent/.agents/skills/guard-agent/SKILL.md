---
name: guard-agent
description: guard-agent telemetry client for the Guard security ecosystem. Use when integrating guard-agent with fastapi-guard/flaskapi-guard/djapi-guard/tornadoapi-guard, configuring AgentConfig (buffer_size, flush_interval, retry_attempts, endpoint), wiring Redis persistence, or diagnosing 413 split-or-drop / permanent-rejection / requeue behavior. Also use when a host app calls logfire.instrument_pydantic() and you need to reason about the agent's per-event validation span mute.
---

# guard-agent

Framework-agnostic telemetry and monitoring agent for the Guard ecosystem. Buffers security events and metrics, flushes them to the Guard SaaS API, and fetches dynamic rules.

## Quick Reference

* Client setup: build an `AgentConfig`, call `guard_agent(config)` for the handler; see [Client Setup](#client-setup).
* Buffer/flush config: `buffer_size`, `flush_interval`, `high_watermark_ratio`; keep the buffer small vs the 256 KiB SaaS body cap; see [the buffering reference](references/buffering.md).
* Redis persistence: `ttl=3600s`, keys retained on failure and deleted only on success; see [the Redis reference](references/redis.md).
* 413 / permanent rejections: HTTP 413 splits the batch in half and retries each half (or drops a single over-cap item); 400/404/422 are dropped, not requeued; see [the transport reference](references/transport.md).
* logfire mute: the agent mutes its telemetry Pydantic models at import so a host `logfire.instrument_pydantic()` does not emit per-event validation spans; see [the logfire mute reference](references/logfire-mute.md).
* Config reference: every `AgentConfig` field with defaults; see [the config reference](references/config.md).

## Client Setup

`guard_agent` is imported by a framework adapter (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard); you rarely instantiate it directly. When you do, build an `AgentConfig` and use the `guard_agent` factory, which returns a `GuardAgentHandler` in an async context or a `SyncGuardAgentHandler` in a sync context.

Only do this in a process with no adapter enabling the agent through `SecurityConfig`. Combined with an adapter, `guard_agent()` returns a different singleton than the middleware's (sync module-load context dispatches to `SyncGuardAgentHandler`, the middleware's async init dispatches to `GuardAgentHandler`), so events sent through the one you built here never reach the dashboard. Configure `agent_*` fields on `SecurityConfig` instead.

```python
from guard_agent import AgentConfig, guard_agent

config = AgentConfig(
    api_key="sk-...",
    endpoint="https://api.guard-core.com",
    project_id="my-project",
)
handler = guard_agent(config)
await handler.start()
```

The async handler (`GuardAgentHandler`) is a singleton per process and reinitializes after `os.fork()`. The sync wrapper (`SyncGuardAgentHandler`) runs the async loop in a daemon thread for WSGI frameworks.

Send events/metrics through the handler; do not call the transport directly:

```python
from guard_agent import SecurityEvent, SecurityMetric
from datetime import datetime, timezone

await handler.send_event(SecurityEvent(
    timestamp=datetime.now(timezone.utc),
    event_type="ip_banned",
    ip_address="1.2.3.4",
    action_taken="blocked",
))
```

`send_event` / `send_metric` accept a `SecurityEvent` / `SecurityMetric` or any object with matching attributes (the handler normalizes it).

## Buffer and Flush

Events and metrics live in two fixed-size `deque` buffers (`maxlen=config.buffer_size`). An auto-flush loop drains them every `flush_interval` seconds, or early when occupancy reaches `high_watermark_ratio` of `buffer_size`. Overflow policy is `drop` by default (evict oldest); `block` backpressures the caller, `raise` throws `BufferFullError`.

Keep `buffer_size` small. The SaaS ingestion endpoint caps request bodies at 256 KiB; a large buffer that flushes a giant batch triggers a 413 and forces a split-or-drop cascade. The default of 100 is a safe ceiling for typical event sizes. See [the buffering reference](references/buffering.md) for the full overflow/early-flush mechanics.

## Redis Persistence

When `initialize_redis(redis_handler)` is called, every buffered item is also written to Redis under a globally-unique key with `ttl=3600` seconds. On a successful flush, the corresponding Redis keys are deleted. On a transient failure the items are requeued in memory and the Redis keys are retained, so a process restart can re-load them. See [the Redis reference](references/redis.md).

## Transport: 413 and Permanent Rejections

`send_events` / `send_metrics` return `True` when the batch was durably accepted OR intentionally dropped because it is permanently un-sendable; the caller deletes Redis keys and does not requeue in both cases. They return `False` only on transient failure, so the caller requeues and retains the Redis keys.

* HTTP 413 raises `PayloadTooLargeError`. The caller splits the batch in half and retries each half recursively; a single over-cap item is dropped with a warning.
* HTTP 400 / 404 / 422 raises `PermanentClientError`; the batch is dropped with a warning (no requeue, no poison-loop retry).
* HTTP 429 honors `Retry-After`. 5xx and network errors are retried up to `retry_attempts` with backoff.

See [the transport reference](references/transport.md) for the exact return semantics, including the split-batch transient-failure edge case.

## logfire Mute (this release)

`SecurityEvent`, `SecurityMetric`, and `EventBatch` are validated per request and `EventBatch` re-validates every buffered event on each flush. A host app that calls `logfire.instrument_pydantic()` would otherwise emit a span per security event. At import time, guard-agent sets `model_config["plugin_settings"]["logfire"] = {"record": "off"}` on each of those three models and force-rebuilds them. This works without logfire installed and is idempotent (guard-core applies the same mute to the same models at its import; re-applying is harmless). See [the logfire mute reference](references/logfire-mute.md).
