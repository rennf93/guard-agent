# Buffering and Flush

## Buffers

`EventBuffer` holds two `collections.deque` buffers, each with `maxlen=config.buffer_size`:

* `event_buffer` — `SecurityEvent` instances
* `metric_buffer` — `SecurityMetric` instances

A `deque(maxlen=...)` silently evicts the oldest entry when full. The overflow policy gates whether that happens.

## Overflow Policy

`config.buffer_overflow_policy` controls behavior when a buffer is full at insert time:

| Policy | Behavior |
|---|---|
| `drop` (default) | Evict the oldest entry, increment a drop counter, log every 100th drop at WARNING. |
| `block` | Await an `asyncio.Event` signaled when flush frees space; backpressures the caller. |
| `raise` | Raise `BufferFullError` so the caller can react. |

## Auto Flush

`start_auto_flush()` runs `_auto_flush_loop`, which sleeps `flush_interval` seconds between attempts. A flush is triggered when:

* buffer occupancy reaches `high_watermark_ratio` of `buffer_size` (early flush), or
* `flush_interval` seconds elapsed since the last flush.

Early flushes are concurrency-limited by `max_concurrent_flushes` (default 1) via a `Semaphore`; a locked semaphore skips the early flush rather than queuing.

## Flush Callback

`EventBuffer` is constructed with `flush_callback` (the handler's `flush_buffer` coroutine). The callback drains both buffers via `flush_events_with_keys` / `flush_metrics_with_keys`, which return the items plus their Redis keys. The handler then calls `transport.send_events` / `send_metrics`:

* success → `confirm_*_redis_keys(keys)` deletes the Redis keys.
* failure (`False`) → `requeue_*_in_memory(items, keys)` pushes items back to the front of the buffer and keeps the Redis keys.

## Safe-Setting Guidance

The SaaS ingestion endpoint caps request bodies at 256 KiB. A flush serializes the whole buffer into one `EventBatch` JSON body (optionally gzip-compressed above `compression_threshold`). If the body exceeds the cap, the server returns 413 and the transport splits the batch in half recursively. A large `buffer_size` combined with large event payloads makes 413 cascades likely and wastes retry budget. Keep `buffer_size` at the default (100) or lower for verbose events; raise `flush_interval` to batch more tightly only if events are small.

## Stats

`buffer.get_stats()` returns `events_buffered`, `metrics_buffered`, `events_flushed`, `metrics_flushed`, `events_dropped`, `metrics_dropped`, `current_event_buffer_size`, `current_metric_buffer_size`, `redis_persist_failures`, `durability_degraded` (True when Redis is configured and persist failures occurred), `last_flush_time`, `auto_flush_running`.
