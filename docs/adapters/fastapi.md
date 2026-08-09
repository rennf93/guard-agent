# FastAPI Adapter — `fastapi-guard`

Guard Agent integrates with FastAPI through the [`fastapi-guard`](https://pypi.org/project/fastapi-guard/) middleware. **You do not call the `guard_agent()` factory yourself** — `fastapi-guard`'s `SecurityMiddleware` creates the agent, wires it into the request pipeline, and drives its async lifecycle (start, flush loop, status loop, dynamic-rule loop, stop) for you.

The integration surface is *only* the `agent_*` fields on `SecurityConfig`. Past versions of this doc showed an explicit `AgentConfig` + `lifespan` pattern; that pattern silently creates a second singleton (`SyncGuardAgentHandler` from sync module-load context, vs the `GuardAgentHandler` the middleware controls) and the events you think are flowing don't reach the dashboard. **Do not use it.**

## Install

=== "uv"

    ```bash
    uv add fastapi-guard guard-agent
    ```

=== "poetry"

    ```bash
    poetry add fastapi-guard guard-agent
    ```

=== "pip"

    ```bash
    pip install fastapi-guard guard-agent
    ```

## Minimal example

```python
import os

from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

try:
    from guard import __version__ as _GUARD_VERSION
except ImportError:
    _GUARD_VERSION = None

config = SecurityConfig(
    # Local protection (independent of the agent)
    enable_redis=True,
    redis_url="redis://localhost:6379",
    rate_limit=100,
    rate_limit_window=60,
    auto_ban_threshold=5,
    auto_ban_duration=300,
    enable_penetration_detection=True,

    # Agent telemetry
    enable_agent=True,
    agent_api_key=os.environ["GUARD_API_KEY"],
    agent_project_id=os.environ["GUARD_PROJECT_ID"],
    agent_endpoint="https://api.guard-core.com",
    agent_buffer_size=100,
    agent_flush_interval=2,
    agent_enable_events=True,
    agent_enable_metrics=True,
    agent_guard_version=_GUARD_VERSION,

    # Optional — pull dynamic rule updates from the dashboard
    enable_dynamic_rules=True,
    dynamic_rule_interval=60,
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
```

That is the entire integration. No `AgentConfig`, no `lifespan` hook, no `guard_agent()` call.

## Encrypted telemetry

For deployments where end-to-end payload encryption between agent and SaaS is a contract requirement (PII processing, regulated industries), add a per-project encryption key paired with an encryption-enforced API key:

```python
config = SecurityConfig(
    # ... everything above ...
    agent_api_key=os.environ["GUARD_API_KEY_W_ENCRYPTION"],
    agent_project_encryption_key=os.environ["GUARD_PROJECT_ENCRYPTION_KEY"],
)
```

When `agent_project_encryption_key` is set, the agent posts to `POST /api/v1/events/encrypted` with the body encrypted client-side via AES-256-GCM. The encryption key is **paired** with a specific API key in the dashboard — mixing keys produces `HTTP 400: Failed to decrypt payload`.

## How the lifecycle is actually driven

`SecurityMiddleware.__init__` calls `SecurityConfig.to_agent_config()` and passes the result to `guard_agent(agent_config)`, getting back a `GuardAgentHandler` singleton. On the first request, the middleware's lazy initializer (`_ensure_initialized`) calls `composite_handler.start()`, which in turn calls `agent_handler.start()` — that's what kicks off the buffer's auto-flush task, the status loop, and the dynamic-rules poller. On app shutdown the inverse happens via `composite_handler.stop()`.

You don't see any of this in your code, and you don't need to.

## When you need the full guide

For the decision tree across all three integration paths (standalone / SaaS / encrypted SaaS), env-var conventions, common pitfalls (nginx body limits, key/api-key pairing, circuit-breaker behavior), see the canonical [**fastapi-guard Integration Guide**](https://rennf93.github.io/fastapi-guard/latest/tutorial/integration/).

## Dashboard & Playground

- Get an API key and project ID at [**app.guard-core.com**](https://app.guard-core.com).
- Try the full stack without installing anything at [**playground.guard-core.com**](https://playground.guard-core.com).

## Related

- [`fastapi-guard` on GitHub](https://github.com/rennf93/fastapi-guard)
- [`fastapi-guard` integration guide](https://rennf93.github.io/fastapi-guard/latest/tutorial/integration/) — full decision tree + pitfalls
- [Canonical full example](https://github.com/rennf93/guard-core-app/blob/master/examples/app.py) in `guard-core-app`
