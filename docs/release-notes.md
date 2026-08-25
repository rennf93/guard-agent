Release Notes
=============

___

v2.9.0 (2026-08-25)
-------------------

Carry guard_core_version on telemetry so the SaaS can identify vulnerable guard-core releases (v2.9.0)
------------------------------------------------------------------------------------------------------

### Added

- **`AgentConfig` and `EventBatch` now carry `guard_core_version`, and `HTTPTransport` sends it on all three send paths.** guard-core 3.13.0 sets `guard_core_version` to the running `guard_core.__version__` when it builds the agent config at init, so the SaaS can identify deployments running a vulnerable guard-core release independently of the wrapper's own version. guard-agent 2.8.1 had no such field and silently dropped the value (Pydantic default `extra=ignore`), so it never reached the platform. The field is now accepted, carried on the two `EventBatch` constructions and the encrypted-payload dict, and sent alongside `guard_version`.

___

v2.8.1 (2026-08-09)
-------------------

Documentation accuracy sweep: six snippets showed middleware that never attaches (v2.8.1)
-----------------------------------------------------------------------------------------

### Fixed

- **Six documented snippets built a middleware that was never installed.** `SecurityMiddleware(app, config=config)` constructs the middleware and discards it; only `app.add_middleware(SecurityMiddleware, config=config)` installs it, which is observable as `len(app.user_middleware)` staying at zero. This affected `docs/tutorial/getting-started.md` in three places, including the block labelled "The recommended deployment", plus `docs/api/overview.md`, `docs/installation.md`'s configuration-verification script (which printed a success message regardless of whether anything was wired), and `examples/basic_usage.py`. Anyone copying them ran an application with no security middleware and no telemetry, with nothing to indicate it.
- **`examples/basic_usage.py` presented the duplicate-singleton anti-pattern as recommended.** It hand-built an `AgentConfig` and wired its own lifespan, which creates an agent handler that never receives traffic and leaves the dashboard empty. It now uses the supported path, where `SecurityConfig`'s `agent_*` fields drive the agent the middleware itself builds.
- **`buffer_size` guidance contradicted itself.** The README showed `5000` while the in-wheel skill said keep the default of 100. The 256 KiB request body cap is real and enforced server side, and no client side batch count limit exists anywhere in the agent. All surfaces now agree on 100.
- **The pydantic plugin mute was described as unconditional.** It is not. An `ImportError` on `guard_agent.models` returns silently with nothing logged, all three models share one `try`/`except` so a failure on the first leaves the rest unmuted, and it runs once at import with no retry, making a failure permanent for the process. The documentation now states what actually holds, and describes the mute in the README and `docs/index.md` for the first time.
- **`make lint-docs` was scanning almost nothing.** Repeated `-e` flags do not accumulate in pymarkdownlnt, so every exclusion but the last was silently discarded, and YAML front matter was being misparsed as heading content. Exclusions moved to `[tool.pymarkdown.system] exclude_path`, with the package directory deliberately left in scope so the shipped in-wheel skill is linted. The gate now exits zero against a real scan.
- **`guard_agent.__version__` reported the wrong version.** `guard_agent/_version.py` was left at `2.7.1` when 2.8.0 was released, while `pyproject.toml` said `2.8.0`. That file is the single source of truth imported by `guard_agent.__init__`, and it feeds the transport's User-Agent header and `EventBatch.agent_version`, so telemetry emitted by 2.8.0 identified itself as 2.7.1 to the platform. It is now `2.8.1`, matching the package metadata.
- **Rendered list structure in the troubleshooting and validation sections.** Code fences separated from their list items by a blank line need a four space indent for python-markdown to keep them inside the item; at three spaces each item fractured into its own single-item list with the fence orphaned beside it. Neither pymarkdownlnt nor `mkdocs build --strict` detects this, so it was verified against the built HTML.

### Documentation

- Roughly sixteen further corrections across the README, `docs/`, the in-wheel skill and the example, each verified against the code as shipped rather than against neighbouring documentation. No runtime behaviour changed in this release.

___

v2.8.0 (2026-08-03)
-------------------

Split-or-drop on 413, drop on permanent 4xx, standalone logfire mute, library-skills skill (v2.8.0)
---------------------------------------------------------------------------------------------------

### Fixed

- **413 poison flush loop closed.** The SaaS platform caps request bodies at 256 KiB, so an oversized batch always 413s; guard-agent retried 4xx blindly and requeued the whole batch, producing an infinite serialize+encrypt+POST loop on the event loop. On `PayloadTooLargeError` the batch is now halved and each half retried recursively; a single item that still 413s is dropped (it will never fit). Permanent 4xx (auth, quota, etc.) drops the whole batch via `_drop_permanent_rejection` instead of requeuing forever.
- **Permanent 4xx no longer trips the circuit breaker.** A permanent 4xx is a healthy server rejecting a payload, not a transient failure. `CircuitBreaker.call` now re-raises `PermanentClientError` before the `except Exception` that increments `failure_count`. Without this, five consecutive 413s opened the breaker; split halves then hit the plain `Exception("Circuit breaker is OPEN")`, which `_send_with_retry` treats as transient, flipping `return left and right` to `False` and requeuing the entire original batch forever. The split fix alone did not close the loop; this one-line guard in the shared function fixes every caller.

### Added

- **Standalone logfire mute.** When guard-core is not imported, guard-agent now mutes its own telemetry pydantic models (`SecurityEvent` / `SecurityMetric` / `EventBatch`) at import via pydantic `plugin_settings`, mirroring guard-core v3.8.1's mute. Closes the standalone-guard-agent edge case where a host's bare `instrument_pydantic()` emitted guard-event validation spans.
- **Library-skills skill** embedded at `guard_agent/.agents/skills/guard-agent/SKILL.md` so `uvx library-skills --claude` discovers guard-agent from the installed wheel.

### Internal

- `examples/basic_usage.py` import-path, async-handler, and typing bugs fixed.

### Behaviour changes

- Oversized batches that 413 are now split and dropped instead of requeued forever; permanent-4xx batches are dropped instead of retried. Callers that relied on infinite requeue will see batches drop (the intended behavior).

___

v2.7.1 (2026-07-30)
-------------------

Bounded response-body logging and partial-failure backoff (v2.7.1)
--------------------------------------------------------------------

### Fixed

- **Unbounded response bodies no longer flood logs.** A branded HTML maintenance page served during a 5xx window caused `response.text` — the full, untruncated body — to be embedded verbatim in exception messages and log lines on every retry, filling a customer's hosting logs with thousands of lines of HTML and inline CSS per request. New `summarize_response_body()` (`guard_agent/utils.py`) collapses all whitespace/newlines into a single line and caps the summary at 300 characters with a truncation-plus-original-length indicator, and is now used at every site in `HTTPTransport._handle_response` where a response body reached a log line or exception message: the non-retryable 4xx path (`PermanentClientError` detail and its log line), the 5xx path (which now also includes the URL, previously missing), and the generic client-error log path. Status code and URL are always kept in the message.
- **A permanently-rejected 200 (e.g. quota exceeded) no longer retries every 30 seconds forever.** The SaaS platform can answer HTTP 200 with `success=False` for conditions a retry cannot fix (e.g. `"Event quota exceeded. Upgrade your plan."`), which the existing 4xx `PermanentClientError` handling does not cover, so the agent re-sent and re-logged the same rejected batch on every flush indefinitely. `GuardAgentHandler` now tracks consecutive partial failures per data type (events/metrics) and backs off the next attempt with `calculate_backoff_delay` (capped at 5 minutes), resetting on the first success — no reliance on parsing the error message, so it also covers future rejection reasons. The "failed to send" and "recovered" log lines now fire once per streak transition instead of once per flush. Buffered events/metrics are left untouched during the backoff window — never dropped beyond the buffer's existing overflow policy — and are retried once the backoff elapses.

### Internal

- Tests added in `tests/test_client_backoff.py`, `tests/test_transport.py`, and `tests/test_utils.py` covering the bounded-body summarizer (short text unchanged, whitespace/newline collapsing, truncation with original length) and the backoff behavior (skips repeat attempts, logs once per transition, resets on success, preserves buffered events/metrics across the backoff window). Full suite at 406 passed / 2 skipped, coverage maintained at 100% line + 100% branch.

___

v2.7.0 (2026-06-23)
-------------------

Observable transport errors and documented Protocols (v2.7.0)
-------------------------------------------------------------

### Added

- **`AgentConfig.on_error` hook for observable delivery failures.** New optional `on_error: Callable[[str, BaseException, dict[str, Any]], None]`. `HTTPTransport` fires it at the real failure points — serialization/encryption (`stage="encryption"`), unencrypted serialization and delivery (`stage="transport_send"`), on a permanent client error, and after retry exhaustion — so a host can observe that telemetry could not be shipped. The hook is best-effort and guaranteed never to propagate into the send path: a hook that raises is caught and logged, never destabilizing the application.

### Documentation

- **Documented the integrator-facing Protocols.** `RedisHandlerProtocol`, `TransportProtocol`, `BufferProtocol`, and `AgentHandlerProtocol` upgraded from thin one-line class docstrings to WHAT/WHEN/HOW class contracts plus a per-method docstring on every method, documenting the previously implicit semantics: `send_*` returns `bool` meaning *accepted* (caller requeues on `False`), `None`-on-miss for reads, the buffer's drain → confirm-on-success / requeue-on-failure at-least-once handshake, and TTL in seconds. Docstrings only — no signature, name, or `@runtime_checkable` change.

### Internal

- Refactored `_send_with_retry` / `_handle_response` into smaller helpers (`_evaluate_send_result`, `_sleep_or_record_giveup`, `_handle_200`) to satisfy the complexity gate, and enabled branch coverage. Behavior-preserving.

___

v2.6.0 (2026-05-12)
-------------------

Configurable rules and status loop intervals (v2.6.0)
-----------------------------------------------------

- **Added** — `AgentConfig.dynamic_rule_interval: int` (default 300, ge=60) — interval in seconds between dynamic rule polls.
- **Added** — `AgentConfig.status_interval: int` (default 300, ge=60) — interval in seconds between agent status reports.
- **Changed** — `_rules_loop` now sleeps `self.config.dynamic_rule_interval` instead of a hardcoded `300`. `_status_loop` now sleeps `self.config.status_interval` instead of a hardcoded `300`. Both loops were previously ignoring any caller-configured value, so `SecurityConfig.dynamic_rule_interval` (and the new `SecurityConfig.agent_status_interval` in guard-core >= 3.1.0) had no effect on the agent's poll cadence. The fields are now honored end-to-end.
- Tests added in `tests/test_loop_intervals.py` covering field defaults, persistence, lower-bound rejection (`ge=60`), and end-to-end assertions that both loops invoke `asyncio.sleep` with the configured value.

___

v2.5.0 (2026-05-06)
-------------------

Install ID fingerprinting and optional HMAC payload signing (v2.5.0)
--------------------------------------------------------------------

- **Added** — Persistent install ID. Each agent process now resolves a stable UUID per installation (default storage at `~/.guard-agent/install-id`, override via `AgentConfig.install_id`), sent on every request as `X-Agent-Install-Id`. The server uses this to detect when a single API key is being used from many distinct installs (a signal that the key has leaked or is being shared across hosts). Auto-creates the file on first call; OSError on read or write is logged via `logger.exception` and falls through to a fresh UUID rather than failing the start-up. New module: `guard_agent.install_id` exposing `resolve_install_id(*, state_path, override)`.
- **Added** — Opt-in HMAC-SHA256 payload signing. When `AgentConfig.payload_signing_secret` is set, every outbound request carries `X-Payload-Signature: v1=<hex>` computed over the exact bytes that go on the wire — post-gzip and post-encryption — so the server can verify integrity against `request.body()` without re-decoding. No header is sent when the secret is unset, preserving the existing default behavior. New module: `guard_agent.signing` exposing `sign_payload(body, *, secret)`.
- **Added** — Two new fields on `AgentConfig`: `install_id: str | None` (override the auto-resolved install ID) and `payload_signing_secret: str | None` (HMAC secret; both default to `None`).
- **Changed** — Transport sets the install-ID header once on the cached `httpx.AsyncClient` default headers (applies to every request) and computes the signature per-request inside both encrypted and unencrypted send paths.
- Tests added for both modules, full suite at 363 passed / 2 skipped.

___

v2.4.1 (2026-04-29)
-------------------

Diagnostic-friendly transport error logging (v2.4.1)
----------------------------------------------------

- **Fixed** — `HTTPTransport._log_request_error` now formats the captured exception as `<ClassName>: <repr>` instead of `str(exc)`. Several httpx exception classes raised on transport-level connection drops (`RemoteProtocolError`, `WriteError`, some `httpcore` wrappers) carry no message body, so `str(exc)` rendered empty and the previous error line was `HTTP client error for POST <url>:` with no diagnostic suffix. Operators chasing a CloudFlare/origin RST storm could not tell which httpx class actually fired without attaching a debugger. The new format always shows the class identity even when the message is empty, e.g. `HTTP client error for POST https://example/api/v1/events/encrypted: RemoteProtocolError: RemoteProtocolError('')`. No behavior change beyond log accuracy. Coverage on `guard_agent/transport.py` maintained at 100% line + 100% branch.

___

v2.4.0 (2026-04-29)
-------------------

Per-event idempotency keys, configurable overflow policy, and framework-version reporting (v2.4.0)
--------------------------------------------------------------------------------------------------

### Added

- **`SecurityEvent.idempotency_key: UUID`** — every emitted event now carries a stable per-event identifier (default `uuid4()` via `default_factory`). Combined with the existing batch-stable `batch_id`, this lets the SaaS dedup at the event level when an ACK is lost mid-batch and the batch is retried. The field is named `idempotency_key`, not `event_id`, to avoid collision with the SaaS API's existing `event_id` (the prefixed external id, e.g. `evt_abc123`). Backward-compatible: callers that don't set the field automatically get a generated one.
- **`AgentConfig.guard_version: str | None`** — new optional config field set by the framework adapter (e.g. fastapi-guard middleware) at agent init time, identifying the wrapper package's version. Default `None` for callers that construct `AgentConfig` directly without going through a framework wrapper. Framework adapters should set `config.guard_version = framework_package.__version__` immediately before passing the config to `GuardAgentHandler`.
- **`EventBatch.guard_version: str | None`** — propagated through the wire payload on both the plaintext (`/api/v1/events`, `/api/v1/metrics`) and encrypted (`/api/v1/events/encrypted`) ingestion paths. Sourced from `AgentConfig.guard_version`. The SaaS persists this on the project record so analytics can attribute telemetry to the wrapper version, not just the agent version. Without this field the SaaS could only see `agent_version` (guard-agent's own version) and had no way to know which middleware version the customer was running.
- **`encryption._default_json_handler`** now serializes `UUID` values to their string form alongside the existing `datetime` → `isoformat()` branch. Required for the encrypted-payload path to handle events carrying the new `idempotency_key`.
- **`AgentConfig.buffer_overflow_policy: Literal["drop", "block", "raise"] = "drop"`** — operators can now choose how the in-memory event/metric buffer behaves at capacity:
  - `drop` (default) — silent eviction of the oldest entry; preserves prior behavior verbatim. Production-safe for high-throughput; loses events when the SaaS is unreachable.
  - `block` — backpressures the caller until a flush frees space. Appropriate when event integrity is critical. Use only when `start_auto_flush` is wired or a flush callback is in place; otherwise `clear_buffer` is the manual escape hatch.
  - `raise` — `BufferFullError` propagates to the caller. Appropriate for tests or strict environments where dropping events is unacceptable.
- **`BufferFullError(GuardAgentError)`** exception class added in `guard_agent.exceptions` and re-exported from the top-level `guard_agent` module.

### Fixed

- **`HTTPTransport._make_request` was logging the wrong URL on POST failures.** When encryption was enabled, the actual request hit `/api/v1/events/encrypted` but the error log printed the unencrypted endpoint string (`url = f"{endpoint}{plain_path}"`). Operators chasing down 503s and decrypt errors saw `POST .../api/v1/events` in their logs even though the wire request went to `/api/v1/events/encrypted`. Fix: compute the actual posted URL (encrypted vs plain) up-front and pass that to `_log_request_error`. No behavior change beyond log accuracy.

### Compatibility

- Default behavior unchanged for callers that don't opt into either feature: `idempotency_key` has a `default_factory`, and `buffer_overflow_policy` defaults to `"drop"` (which preserves prior eviction semantics including the silent-overflow counter and warning-every-100th log).
- SaaS-side coordination: this release is paired with the SaaS dedup work that ships the `idempotency_key` column on `security_events`, the unique constraint, and the `pg_insert ... on_conflict_do_nothing` ingest path. SaaS deployments that don't yet recognize the field treat it as an unknown column and silently drop the bytes — no behavior change to those callers.

___

v2.3.0 (2026-04-26)
-------------------

Production Safety (v2.3.0)
--------------------------
- **Fork-safe `GuardAgentHandler` singleton.** Class-level `_instance` survived `os.fork()`, so Gunicorn pre-fork workers all inherited a stale `_initialized=True` flag and dead asyncio task handles from the parent loop. Calling `start()` in the child was a silent no-op and the child never connected to the agent endpoint. Register an `os.register_at_fork(after_in_child=...)` hook that resets `_initialized` and clears inherited task references. Add a per-call PID guard for non-fork-aware multiprocessing setups. Companion fix to the transport-level fork-safety shipped in 2.2.0.
- **Real watermark-driven early flush.** `EventBuffer._flush_if_needed` was previously a no-op marker — bursts that filled the buffer continued dropping events for the entire flush_interval window even though the early-flush task was scheduled. Trigger a real async flush when buffer occupancy exceeds the high-watermark ratio (default 80%). Cap concurrent flushes via an `asyncio.Semaphore` (default 1) to prevent runaway parallel sends under sustained pressure. New `AgentConfig` fields: `high_watermark_ratio: float = 0.8`, `max_concurrent_flushes: int = 1`. `EventBuffer.stop_auto_flush()` now awaits in-flight watermark-triggered flushes before returning, eliminating data loss on shutdown.
- **Hard-fail on encryption init.** When the `project_encryption_key` round-trip failed at startup, transport logged a warning and proceeded with plaintext over the wire. Operators got no signal stronger than a log line and could ship traffic encrypted in the dashboard's mind but not on the network. Now raises `EncryptionConfigError` on any startup encryption failure. No plaintext fallback. Operators get a loud failure they can react to.

Internal (v2.3.0)
-----------------
- Test coverage maintained at **100%** line + branch across `guard_agent/buffer.py`, `client.py`, `encryption.py`, `models.py`, `protocols.py`, `transport.py`, `utils.py` (1135 statements, 0 missed).
- Added test coverage to verify `EventBatch.batch_id` is stable across retries (the underlying behavior was already correct in 2.2.0 — the new tests pin it down so future refactors can't regress).
- Performance tests (`test_agent_performance_impact`, `test_memory_usage`) hardened against coverage-instrumentation noise: `gc.collect()` before RSS baseline, coverage-aware overhead threshold, `enable_redis=False` in test apps to eliminate ResourceWarning pollution.
- Fixed pre-existing typing gaps in test mocks; all resolved at the root without any suppression directives.

___

v2.2.0 (2026-04-25)
-------------------

Production Safety (v2.2.0)
--------------------------
- **Fork-safe transport.** `HTTPTransport.__init__` registers an `os.register_at_fork(after_in_child=...)` hook that resets the inherited `httpx.AsyncClient`, `CircuitBreaker`, and `RateLimiter` in every forked child. A pid-drift check runs on every send so spawn-style workers (uvicorn `--workers` without `--preload`) get the same protection. Fixes a class of bugs where Gunicorn `--preload` workers would corrupt the shared socket between parent and child.
- **Observable buffer drops.** `EventBuffer` now exposes `events_dropped` and `metrics_dropped` counters via `get_stats()`. The first drop and every 100th drop log a `WARN`. Previously the deque silently evicted the oldest event when full.
- **Honor server `Retry-After`.** A 429 response now raises `RateLimitedError(retry_after_seconds=...)`, and `_send_with_retry` / `_get_with_retry` sleep that exact value (capped at 300s) instead of falling back to client-side exponential backoff. Prevents the agent from hammering an already-overloaded SaaS.
- **Persist-confirm Redis recovery.** Redis persist keys are now `event_{ns}_{uuid8}` / `metric_{ns}_{uuid8}` so two events arriving in the same millisecond no longer collide. Deletion happens only after the transport confirms via the new `confirm_event_redis_keys` / `confirm_metric_redis_keys` helpers, and `requeue_events_in_memory` / `requeue_metrics_in_memory` push unsent events back to the front of the buffer on transport failure. Previously a transport failure cleared both deque and Redis simultaneously, dropping the events permanently.
- **`BufferProtocol` adds new methods.** `flush_events_with_keys`, `flush_metrics_with_keys`, `confirm_event_redis_keys`, `confirm_metric_redis_keys`, `requeue_events_in_memory`, `requeue_metrics_in_memory`. Custom buffer implementations need to implement these or fall back to the bundled `EventBuffer`.

Compression (v2.2.0)
--------------------
- **Gzip compression of outgoing batch bodies** above `compression_threshold` (default 1024 bytes). When the body exceeds the threshold the agent compresses with gzip and sends `Content-Encoding: gzip`; the Guard Core SaaS decompresses request bodies via its `GzipRequestMiddleware` before pydantic validation. Smaller bodies skip compression and ship as plain JSON.
- **Default is ON.** `AgentConfig.compression_enabled=True`. Set `compression_enabled=False` if you are pointing the agent at an ingestion endpoint that does not handle `Content-Encoding: gzip` request bodies (e.g. a custom backend without a decompression middleware).
- `EventBatch.compressed` field now reflects whether the body was actually compressed.

Versioning hygiene (v2.2.0)
---------------------------
- `agent_version` in HTTP request headers (`User-Agent`) and batch payloads now derives from `guard_agent.__version__` instead of the hardcoded `"1.1.0"` string the previous releases were sending. SaaS-side analytics that key off `agent_version` will now see the real installed version.

Test coverage (v2.2.0)
----------------------
- Test coverage raised to **100%** across `guard_agent/buffer.py`, `client.py`, `encryption.py`, `models.py`, `protocols.py`, `transport.py`, `utils.py` (1053 statements, 0 missed). Adds the previously-missing branches for the fork-hook unavailable path, the Retry-After exhausted-attempts path, the GET retry-after path, the buffer overflow drop accounting, the empty-key forget paths, the Redis-failure swallowing in `confirm_event_redis_keys` / `confirm_metric_redis_keys`, and the `requeue_metrics_in_memory` end-to-end + overflow-drop paths.

___

v2.1.0 (2026-04-24)
-------------------

Multi-Adapter Coverage (v2.1.0)
-------------------------------
- Added per-adapter integration smoke tests: `tests/test_adapter_fastapi.py`, `test_adapter_flask.py`, `test_adapter_django.py`. Each verifies `SecurityConfig.to_agent_config()` roundtrip and request delivery through the adapter's middleware with `enable_agent=True`.
- Added per-adapter documentation pages under `docs/adapters/`: FastAPI, Flask, Django, Tornado. Each page covers install, minimal example, and agent wiring specific to that framework.
- `mkdocs.yml` navigation updated with a new top-level **Adapters** section.

Dependency Changes (v2.1.0)
---------------------------
- Added `django`, `djapi-guard>=2.0.0`, `flask`, `flaskapi-guard>=2.0.0`, `tornado` to `[project.optional-dependencies].dev` so the test suite can exercise every adapter.
- `tornadoapi-guard` is not yet included in dev extras — it has not been published to PyPI (only a yanked 0.0.1 exists). Integration tests for Tornado are stubbed with `pytest.mark.skip` in `tests/test_adapter_tornado.py`. Re-enable once the adapter ships a 1.0.0+ release.

___

v2.0.0 (2026-04-24)
-------------------

Package Rename (v2.0.0)
-----------------------
- **Renamed on PyPI**: `fastapi-guard-agent` → `guard-agent`. The Python import path (`from guard_agent import ...`) is unchanged — no code changes are required in consuming applications.
- Repositioned as a framework-agnostic telemetry agent serving `fastapi-guard`, `flaskapi-guard`, `djapi-guard`, and `tornadoapi-guard`.
- **Legacy name preserved**: a meta-package `fastapi-guard-agent==1.2.0` is published alongside this release, whose only dependency is `guard-agent>=2.0.0,<3.0.0`. Existing `pip install fastapi-guard-agent` invocations continue to resolve correctly and pull the renamed distribution transitively.
- Repository renamed on GitHub: `rennf93/fastapi-guard-agent` → `rennf93/guard-agent`. GitHub auto-redirects the old URLs.
- Documentation site moved to `https://rennf93.github.io/guard-agent/`.

Dependency Changes (v2.0.0)
---------------------------
- Removed `fastapi` and `fastapi-guard` from runtime dependencies — the agent is framework-agnostic and speaks HTTP to the dashboard, not to any web framework.
- Runtime deps are now: `cryptography`, `httpx`, `pydantic`, `typing-extensions`.
- `fastapi` and `fastapi-guard` remain as dev extras so the existing test suite keeps passing. Each framework adapter brings its own web framework.
- Dropped `Framework :: FastAPI` classifier; development status promoted from `Alpha` to `Beta`.

Breaking Changes (v2.0.0)
-------------------------
- **None in Python API** — `from guard_agent import ...`, `GuardAgentHandler`, `AgentConfig`, and every public symbol behave identically.
- **Distribution name change only**: scripts, Dockerfiles, and lockfiles that install `fastapi-guard-agent` directly should migrate to `guard-agent`. The shim keeps old commands working but new projects should install `guard-agent` directly.

Migration Guide (v2.0.0)
------------------------
- Existing code: no changes.
- Install commands (uv): replace `uv add fastapi-guard-agent` with `uv add guard-agent` at your leisure — both resolve to the same underlying package.
- Poetry / pip equivalents: `poetry add guard-agent` / `pip install guard-agent`.
- Lockfiles: running `uv lock`, `poetry lock`, or `pip-compile` after bumping will transparently update entries to `guard-agent`.

___

v1.1.1 (2026-03-11)
-------------------

Bug Fixes (v1.1.1)
-------------------
- Fixed misalignment on documentation headers and model parameters.
- Added support for Python 3.14.

Maintenance (v1.1.1)
--------------------
- Code alignment and cleanup.

___

v1.1.0 (2025-10-14)
-------------------

New Features (v1.1.0)
---------------------
- Added end-to-end payload encryption for secure telemetry transmission using AES-256-GCM.
- Implemented `PayloadEncryptor` class with project-specific encryption keys.
- Added encrypted endpoint support for events and metrics (`/api/v1/events/encrypted`).
- Integrated automatic datetime serialization in encrypted payloads via custom JSON handler.
- Added encryption key verification during transport initialization.

Technical Details (v1.1.0)
--------------------------
- Encryption uses AES-256-GCM with 96-bit nonces and 128-bit authentication tags.
- Pydantic models are serialized using `.model_dump(mode="json")` before encryption.
- Custom `_default_json_handler` ensures datetime objects are properly ISO-formatted.

___

v1.0.2 (2025-09-12)
-------------------

Enhancements (v1.0.2)
---------------------
- Added dynamic rule updated event type.

___

v1.0.1 (2025-08-07)
-------------------

Enhancements (v1.0.1)
------------
- Added path_excluded event type.

___

v1.0.0 (2025-07-24)
-------------------

Official Release
-----------------

___

v0.1.1 (2025-07-09)
-------------------

Enhancements (v0.1.1)
---------------------
- Standardized Redis Protocl/Manager methods across libraries.

___

v0.1.0 (2025-07-08)
-------------------

Enhancements (v0.1.0)
---------------------
- Switched from aiohttp to httpx for HTTP client.
- Completed implementation.
- 100% test coverage.

___

v0.0.1 (2025-06-22)
-------------------

New Features (v0.0.1)
---------------------
- Initial release FastAPI Guard Agent.
