# Redis Persistence

## Wiring

`GuardAgentHandler.initialize_redis(redis_handler)` stores the handler and calls `EventBuffer.initialize_redis`, which loads any previously-persisted items back into the in-memory buffers before the agent starts. The handler accepts any object implementing `RedisHandlerProtocol` (guard-core's `redis_handler` is the canonical implementation).

## Write Path

On `add_event` / `add_metric`, after appending to the in-memory deque, the buffer persists the item to Redis:

* Key: `event_<time_ns()>_<uuid4 hex[:8]>` (events) or `metric_<time_ns()>_<uuid4 hex[:8]>` (metrics), namespaced under `agent_events` / `agent_metrics`.
* Value: `safe_json_serialize(item.model_dump())`.
* TTL: `3600` seconds.
* The buffer records the short key on the item via `id(item)` for later confirmation.

A persist failure increments `redis_persist_failures` and logs a WARNING; the item still lives in the in-memory buffer (durability degraded, not lost).

## Load Path (Restart Recovery)

On `initialize_redis`, the buffer scans `agent_events:*` / `agent_metrics:*`, deserializes each value into a `SecurityEvent` / `SecurityMetric`, appends it to the in-memory deque, and re-records the short key. This means a process restart re-loads items that were buffered but not yet confirmed flushed.

## Delete Path (Success Only)

`flush_events_with_keys` / `flush_metrics_with_keys` pop the items and their keys out of the buffer and return both. The handler calls `transport.send_events` / `send_metrics`:

* `True` (accepted or permanently dropped) → `confirm_event_redis_keys` / `confirm_metric_redis_keys` deletes the Redis keys. The items are gone everywhere.
* `False` (transient failure) → `requeue_events_in_memory` / `requeue_metrics_in_memory` pushes the items back to the front of the deque and re-associates the Redis keys. The Redis keys are retained for the next retry or for restart recovery.

Redis keys are never deleted on failure. The 3600s TTL is the only failure-case expiry, bounding how long an un-flushed item survives a downed SaaS.

## Clear

`clear_buffer()` wipes both in-memory deques and deletes all `agent_events:*` / `agent_metrics:*` keys. Use only when you intend to lose pending telemetry.