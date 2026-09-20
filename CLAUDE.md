# AGENTS.md

Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

Guard Agent is the framework-agnostic telemetry and monitoring agent for the Guard security ecosystem. It buffers security events and metrics, flushes them to the Guard SaaS API, fetches dynamic rules, and serves `fastapi-guard`, `flaskapi-guard`, `djapi-guard`, and `tornadoapi-guard`.

- **Package (PyPI)**: `guard-agent` v3.0.0
- **Import path**: `guard_agent` (unchanged across the rename)
- **Legacy PyPI alias**: `fastapi-guard-agent==1.2.0`, a meta-package that installs `guard-agent>=2.0.0,<3.0.0`
- **Python**: 3.10-3.14
- **Build**: Hatchling
- **Package Manager**: `uv`
- **License**: MIT

### Rename History

The package was renamed from `fastapi-guard-agent` to `guard-agent` in v2.0.0 to reflect its multi-adapter scope. Design spec: `docs/superpowers/specs/2026-04-24-guard-agent-rename-design.md`. There is no Python API change (`from guard_agent import ...` works exactly as before); the legacy name still resolves on PyPI through the meta-package under `shim/`.

## Ecosystem Position

```
adapters (fastapi-guard, flaskapi-guard, djapi-guard, tornadoapi-guard)
    └── guard-agent (this repo)   <- telemetry client: buffer, encrypt, sign, ship
            └── guard-core-app ingestion (api.guard-core.com)  <- SaaS API, dashboard
```

Guard Agent is the write side of the Guard telemetry path. Framework adapters do not talk to the SaaS directly: setting `enable_agent=True` on a guard-core `SecurityConfig` (plus the `agent_*` fields) builds an `AgentConfig` and wires the agent into the middleware, so the adapter emits events and metrics through it. The agent ships batches over HTTP to the Guard SaaS ingestion endpoint (the `guard-core-app` backend) and also fetches dynamic rules from it.

The agent is deliberately framework-agnostic: it speaks HTTP to the dashboard, not to any web framework. That is why `fastapi`, `flask`, and the adapter packages appear only in dev/test dependencies and never in the runtime dependency set. `guard-core` bundles the same event models and pulls the agent in lazily when `enable_agent=True`; the agent is not a hard dependency of guard-core.

## Architecture

Source in `guard_agent/` (roughly 1,900 LOC):

| Module | Purpose |
|--------|---------|
| `client.py` | `GuardAgentHandler` - main orchestrator (async), plus the sync wrapper |
| `transport.py` | `HTTPTransport` - HTTP layer with retries |
| `buffer.py` | Event buffering (in-memory deques + Redis persistence) |
| `models.py` | Pydantic models (`AgentConfig`, security events, metrics, batches) |
| `encryption.py` | AES-256-GCM payload encryption |
| `protocols.py` | Type protocols for extensibility |
| `utils.py` | `CircuitBreaker`, `RateLimiter`, validation helpers |
| `exceptions.py` | `GuardAgentError`, `BufferFullError`, `PermanentClientError`, `PayloadTooLargeError` |
| `signing.py` | Payload signing (`payload_signing_secret`) |
| `install_id.py` | Stable per-install identifier |
| `logging_utils.py` | Prefixed logger setup (`setup_agent_logging`) |

Buffer, client, and transport internals are split into private `_buffer_*.py`, `_client_*.py`, and `_transport_*.py` helper modules; treat those as implementation details and keep the public surface on the modules above.

Shim in `shim/` (legacy PyPI meta-package):

| File | Purpose |
|------|---------|
| `shim/pyproject.toml` | `fastapi_guard_agent==1.2.0` depending only on `guard-agent>=2,<3` |
| `shim/fastapi_guard_agent/` | Tiny alias module that emits `DeprecationWarning` on import |

## Quick Start

```bash
pip install guard-agent          # or: uv add guard-agent
pip install "guard-agent[redis]" # optional: Redis-backed buffer persistence
```

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

`guard_agent(config)` returns a `GuardAgentHandler` in an async context or a `SyncGuardAgentHandler` in a sync context. The async handler is a singleton per process and reinitializes after `os.fork()`. The sync wrapper runs the async loop in a daemon thread for WSGI frameworks.

Send events/metrics through the handler; do not call the transport directly:

```python
from datetime import datetime, timezone
from guard_agent import SecurityEvent

await handler.send_event(
    SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        event_type="ip_banned",
        ip_address="1.2.3.4",
        action_taken="blocked",
    )
)
```

`send_event` / `send_metric` accept a `SecurityEvent` / `SecurityMetric` or any object with matching attributes (the handler normalizes it).

Most integrations never construct the agent by hand: set `enable_agent=True` and the `agent_*` fields on `SecurityConfig` in the adapter instead, so the middleware's singleton is the one shipping events.

## Configuration

All behavior is `AgentConfig` (Pydantic). Key fields and their defaults:

| Field | Default | Purpose |
|-------|---------|---------|
| `endpoint` | `"https://api.guard-core.com"` | Guard SaaS ingestion base URL |
| `api_key` | (required) | Guard Agent API key |
| `project_id` | `None` | SaaS project the telemetry is attributed to |
| `buffer_size` | `100` | Per-buffer deque capacity (events and metrics each) |
| `flush_interval` | `30` | Seconds between automatic flushes |
| `high_watermark_ratio` | `0.8` | Occupancy fraction that triggers an early flush |
| `buffer_overflow_policy` | `"drop"` | Overflow behavior: `drop` (evict oldest), `block` (backpressure), `raise` (`BufferFullError`) |
| `retry_attempts` | `3` | Retries for transient failures |
| `backoff_factor` | `1.0` | Backoff multiplier between retries |
| `timeout` | `30` | Per-request timeout in seconds |
| `max_concurrent_flushes` | `1` | Concurrent flush limit |
| `enable_events` / `enable_metrics` | `True` | Which buffers are active |
| `dynamic_rule_interval` / `status_interval` | `300` | Seconds between rule fetches / status reports |
| `sensitive_headers` | header list | Headers redacted before shipping |
| `project_encryption_key` | `None` | AES-256-GCM payload encryption key |
| `payload_signing_secret` | `None` | Enables payload signing |
| `on_error` | `None` | Sync error callback `(message, exception, context)` |

Adapters expose the same knobs as `agent_*` fields on guard-core's `SecurityConfig` (`agent_buffer_size`, `agent_flush_interval`, `agent_retry_attempts`, `agent_endpoint`, and friends); `SecurityConfig.to_agent_config()` is what builds this model, so change the adapter config rather than constructing `AgentConfig` separately.

## Reliability Semantics

**Buffer and flush.** Events and metrics live in two fixed-size `deque` buffers (`maxlen=config.buffer_size`). An auto-flush loop drains them every `flush_interval` seconds, or early when occupancy reaches `high_watermark_ratio` of `buffer_size`. Overflow policy is `drop` by default (evict oldest); `block` backpressures the caller and `raise` throws `BufferFullError`.

**Retry.** HTTP 429 honors `Retry-After`. 5xx responses and network errors are retried up to `retry_attempts` with `backoff_factor` backoff. A `CircuitBreaker` in `utils.py` stops hammering a failing endpoint.

**413 split-or-drop.** HTTP 413 raises `PayloadTooLargeError`. The caller splits the batch in half and retries each half recursively; a single item that is still over the cap is dropped with a warning.

**Permanent rejection.** HTTP 400 / 404 / 422 raises `PermanentClientError`; the batch is dropped with a warning, never requeued, so a poison batch cannot loop forever.

**Requeue.** `send_events` / `send_metrics` return `True` when the batch was durably accepted OR intentionally dropped because it is permanently un-sendable (Redis keys are then deleted), and `False` only on transient failure. A `False` return means the caller requeues the items in memory and retains the Redis keys. A `True` return therefore does not by itself mean the events reached the dashboard; permanent drops are also `True`.

**Redis persistence.** When `initialize_redis(redis_handler)` is called, every buffered item is also written to Redis under a globally unique key with `ttl=3600` seconds. Successful flushes delete the corresponding keys; transient failures retain them so a process restart can reload the items. Redis keys never expire on their own before the TTL, and the agent never deletes keys it did not write.

**Body cap.** The SaaS ingestion endpoint caps request bodies at 256 KiB. Keep `buffer_size` small (the default of 100 is a safe ceiling for typical event sizes); a large buffer that flushes a giant batch triggers a 413 and the split-or-drop cascade above.

## Development Commands

```bash
make install-dev    # Install dev dependencies
make local-test     # Run tests locally (uv run pytest -v --cov=guard_agent)
make lint           # Lint via Docker (ruff + mypy)
make fix            # Auto-fix with ruff
make test           # Run tests via Docker (Python 3.10)
make test-all       # Test all Python versions (3.10-3.14)
make serve-docs     # Serve MkDocs documentation
make lint-docs      # Lint markdown docs
make fix-docs       # Fix markdown issues
make vulture        # Find dead code
make bandit         # Security scan
make pip-audit      # Audit dependencies
make radon          # Complexity analysis
make xenon          # Complexity thresholds
make deptry         # Dependency analysis
make semgrep        # Static analysis
make security       # bandit + pip-audit
make quality        # lint + vulture + radon + xenon
make check-all      # lint + security + quality + analysis
make clean          # Clean cache files
make bump-version VERSION=x.y.z

# Build both distributions:
uv build             # builds guard-agent (main)
cd shim && uv build  # builds the fastapi-guard-agent shim
```

## Testing Guidelines

```bash
# Local suite with coverage
make local-test

# Docker, default Python 3.10, or a specific version
make test
make test-3.12

# Single test
uv run pytest tests/test_buffer.py::test_name -v
```

- pytest runs with `asyncio_mode = "auto"`, so async tests need no marker
- `addopts = "--cov=guard_agent --cov-branch --cov-report=term-missing"`; coverage is on by default
- `filterwarnings = ["error", ...]` turns warnings into failures (with narrow documented exceptions)
- Tests that spawn a real server subprocess are marked and skipped by default where applicable
- Dev extras install the adapters (`fastapi-guard`, `flask`, `django`, `djapi-guard`) and `redis`, so integration-style tests can exercise a real adapter without adding runtime dependencies

### Code Standards

- **Linting**: Ruff (E, F, UP, B, I rules) + Mypy strict mode
- **Formatting**: Ruff format
- **Types**: Full type annotations required (mypy strict)
- **Target**: Python 3.10 minimum

## Best Practices

1. **Always use uv** for package management
2. **Keep the agent framework-agnostic**: HTTP to the dashboard only; never import a web framework in runtime code
3. **Send through the handler**, never the transport directly, so buffering, retry, and Redis persistence stay consistent
4. **Prefer adapter configuration** (`SecurityConfig.agent_*`) over building `AgentConfig` yourself; a second handler in the same process is a different singleton whose events never reach the dashboard
5. **Keep `buffer_size` small** relative to the 256 KiB ingestion cap
6. **Run tests** before committing and keep mypy strict clean
7. **Update both distributions** (`uv build` and the `shim/` package) when the version changes; `make bump-version` handles the main package
8. **Document changes** in `CHANGELOG.md` and `docs/`

## Related Projects

- **guard-core** - Framework-agnostic security engine (telemetry models live here too): <https://github.com/rennf93/guard-core>
- **fastapi-guard** - FastAPI/Starlette adapter: <https://github.com/rennf93/fastapi-guard>
- **flaskapi-guard** - Flask extension adapter: <https://github.com/rennf93/flaskapi-guard>
- **djapi-guard** - Django middleware adapter: <https://github.com/rennf93/djapi-guard>
- **tornadoapi-guard** - Tornado handler/middleware adapter: <https://github.com/rennf93/tornadoapi-guard>
- **guard-core-mcp** - MCP server for config validation and docs search: <https://github.com/rennf93/guard-core-mcp>
- **guard-core-app** - SaaS platform this agent reports to (ingestion API, dashboard, playground): <https://github.com/rennf93/guard-core-app>
