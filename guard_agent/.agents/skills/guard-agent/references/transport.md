# Transport: 413, Permanent Rejections, Retries

`HTTPTransport.send_events` / `send_metrics` build an `EventBatch`, serialize it, optionally gzip-compress and HMAC-sign it, and POST to `/api/v1/events` or `/api/v1/metrics`. Encrypted configurations POST to `/api/v1/events/encrypted` instead.

## Return Semantics

| Outcome | Return | Caller action |
|---|---|---|
| Server accepted (200/201) | `True` | Delete Redis keys, do not requeue. |
| Partial-failure 200 (`success=False` or `errors` present) | `False` | Requeue in memory, retain Redis keys. |
| 413 Payload Too Large | split-or-drop; `True` if both halves resolve, else `False` | See below. |
| 400 / 404 / 422 Permanent | `True` | Delete Redis keys, do not requeue. |
| 429 Rate Limited | retry after `Retry-After` | Retained during retry loop. |
| 5xx / network error | `False` after retries exhausted | Requeue in memory, retain Redis keys. |
| 401 / 403 | raises `Exception` | Caught by `send_events`, returns `False`. |

## 413 Split-or-Drop

When `_handle_response` sees HTTP 413 it raises `PayloadTooLargeError` (a subclass of `PermanentClientError`). `send_events` / `send_metrics` catch `PayloadTooLargeError` and call `_split_or_drop_on_payload_too_large`:

* If the batch has more than one item, split it in half at the midpoint and recursively call `send_events` / `send_metrics` on each half. Each half may itself 413 and split again, or hit a permanent 4xx and drop, or transiently fail.
* If the batch is a single item that still exceeds the cap, drop it with a WARNING, fire the `on_error` hook, and return `True` (no requeue).
* The split returns `left and right`. Both halves `True` (accepted or permanently dropped) → `True`, caller does not requeue. If either half transiently fails (`False`), the split returns `False` and the caller requeues the original full batch. Note: items already accepted by the server in a succeeding half are not un-sent, so a transient failure on the other half can cause the requeued full batch to re-send already-accepted events. This is the current release behavior; prefer keeping `buffer_size` small so 413 splits are rare.

## Permanent Rejections (400 / 404 / 422)

`_NON_RETRYABLE_STATUS_CODES = (400, 404, 413, 422)`. For 400/404/422, `_handle_response` raises `PermanentClientError(status_code, detail)`. `send_events` / `send_metrics` catch it, call `_drop_permanent_rejection` (WARNING log + `on_error` hook), and return `True`. The caller deletes Redis keys and does not requeue. This prevents poison-loop retries of batches the server will never accept.

## Retries and Backoff

`_send_with_retry` loops `retry_attempts + 1` times. On a transient exception it sleeps `calculate_backoff_delay(attempt, backoff_factor)` before retrying. `RateLimitedError` (429) sleeps `min(Retry-After, 300s)`. A `CircuitBreaker` (threshold 5 failures, 60s recovery) wraps each request; an open breaker raises instead of calling the server. A `RateLimiter` (100 calls / 60s client-side) gates outbound calls.

## Encryption and Signing

When `project_encryption_key` is set, the transport encrypts events/metrics payloads (AES-256-GCM via `PayloadEncryptor`) and POSTs to `/api/v1/events/encrypted`. When `payload_signing_secret` is set, each body is HMAC-SHA256-signed and the signature sent in `X-Payload-Signature`. Encryption round-trip is verified at transport init; a failure raises `EncryptionConfigError` and refuses plaintext fallback.

## Fork Safety

`os.register_at_fork` resets the httpx client, circuit breaker, rate limiter, and stats in the child process. `GuardAgentHandler` similarly reinitializes after fork.