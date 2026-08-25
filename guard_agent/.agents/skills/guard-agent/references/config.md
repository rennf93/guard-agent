# AgentConfig Reference

`AgentConfig` is a Pydantic `BaseModel`. Required field: `api_key`. All others have defaults.

## Fields

| Field | Default | Notes |
|---|---|---|
| `api_key` | required | Guard Agent API key. |
| `endpoint` | `https://api.guard-core.com` | Bare host. A trailing `/api/v1` is stripped with a one-time WARNING (transport appends versioned paths). |
| `project_id` | `None` | Org/project ID. When set, the dynamic-rules poll loop starts. |
| `buffer_size` | `100` | Per-buffer `deque maxlen` (events and metrics each). Keep small vs the 256 KiB SaaS body cap. |
| `flush_interval` | `30` | Seconds between auto-flush attempts. |
| `dynamic_rule_interval` | `300` (min 60) | Seconds between dynamic-rule polls. |
| `status_interval` | `300` (min 60) | Seconds between agent-status reports. |
| `high_watermark_ratio` | `0.8` | Buffer occupancy that triggers an early flush. |
| `max_concurrent_flushes` | `1` | Early-flush concurrency limit. |
| `buffer_overflow_policy` | `drop` | `drop` / `block` / `raise`. |
| `enable_metrics` | `True` | When False, `send_metric` is a no-op. |
| `enable_events` | `True` | When False, `send_event` is a no-op. |
| `retry_attempts` | `3` | Transient-failure retries per batch. |
| `timeout` | `30` | Request timeout in seconds. |
| `backoff_factor` | `1.0` | Backoff multiplier for retries. |
| `sensitive_headers` | `["authorization", "cookie", "x-api-key"]` | Headers excluded from telemetry. |
| `max_payload_size` | `1024` | Max payload size included in an event (bytes). |
| `project_encryption_key` | `None` | When set, payloads are AES-256-GCM encrypted to `/api/v1/events/encrypted`. |
| `guard_version` | `None` | Framework adapter version, set by the adapter at init. |
| `guard_core_version` | `None` | guard-core library version, set by guard-core at init. |
| `compression_enabled` | `True` | Gzip bodies above `compression_threshold`. |
| `compression_threshold` | `1024` | Min body size in bytes before gzip applies. |
| `install_id` | `None` | Override agent install ID (auto-generated otherwise). |
| `payload_signing_secret` | `None` | HMAC-SHA256 secret for `X-Payload-Signature`. |
| `on_error` | `None` | Best-effort callback `(stage, exc, context)` for transport/encryption failures; a raising callback is caught and logged. |

## Env-Var Mapping (Adapter Side)

guard-agent itself does not read environment variables. The framework adapter (fastapi-guard, etc.) reads `AGENT_*` env vars and maps them onto `AgentConfig` fields. The verified defaults the adapter passes through are `buffer_size=100`, `flush_interval=30`, `retry_attempts=3`, `endpoint=https://api.guard-core.com`. An `agent_strict=False` style setting, when present, belongs to the adapter's own `SecurityConfig`, not to `AgentConfig` (guard-agent has no `strict` field).

## Endpoint Validation

`AgentConfig.validate_endpoint` rejects empty values, non-HTTP schemes, and missing scheme/netloc. A trailing `/api/v1` is stripped once with a WARNING and a module-level guard prevents repeating the warning.
