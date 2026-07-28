<p align="center">
    <a href="https://rennf93.github.io/guard-agent/latest/">
        <img src="https://rennf93.github.io/guard-agent/latest/assets/guard_agent_legend.svg" alt="Guard Agent">
    </a>
</p>

---

<p align="center">
    <strong>Guard Agent is an enterprise-grade, framework-agnostic telemetry and monitoring agent for the Guard security ecosystem. It integrates with <code>fastapi-guard</code>, <code>flaskapi-guard</code>, <code>djangoapi-guard</code>, and <code>tornadoapi-guard</code> to provide centralized security intelligence, real-time policy updates, and comprehensive event collection across any Python web framework.</strong>
</p>

<p align="center">
    <a href="https://badge.fury.io/py/guard-agent">
        <img src="https://badge.fury.io/py/guard-agent.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4" alt="PyPiVersion">
    </a>
    <a href="https://github.com/rennf93/guard-agent/actions/workflows/release.yml">
        <img src="https://github.com/rennf93/guard-agent/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/rennf93/guard-agent/actions/workflows/ci.yml">
        <img src="https://github.com/rennf93/guard-agent/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/rennf93/guard-agent/actions/workflows/code-ql.yml">
        <img src="https://github.com/rennf93/guard-agent/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/rennf93/guard-agent/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/rennf93/guard-agent/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/rennf93/guard-agent/actions/workflows/docs.yml">
        <img src="https://github.com/rennf93/guard-agent/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/rennf93/guard-agent?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&amp;logo=Python&amp;logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&amp;logo=Redis&amp;logoColor=white" alt="Redis">
    <a href="https://pepy.tech/project/guard-agent">
        <img src="https://pepy.tech/badge/guard-agent" alt="Downloads">
    </a>
</p>

<p align="center">
  <a href="https://guard-core.com">Website</a> &middot;
  <a href="https://rennf93.github.io/guard-agent/latest/">Docs</a> &middot;
  <a href="https://playground.guard-core.com">Playground</a> &middot;
  <a href="https://app.guard-core.com">Dashboard</a> &middot;
  <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

<p align="center">
  Framework-agnostic security telemetry for Python web apps.<br>
  Feeds the Guard dashboard with events, metrics, and dynamic rules from any supported adapter.
</p>

---

> **Renamed from `fastapi-guard-agent`.** As of `guard-agent` 2.0.0, the package has been renamed to reflect its multi-framework scope. The Python import path (`from guard_agent import ...`) is unchanged. Existing `pip install fastapi-guard-agent` commands continue to work via a meta-package that transitively pulls the renamed distribution.

---

Documentation & Platform
========================

- 🌐 **[guard-core.com](https://guard-core.com)** — marketing site & product overview
- 📚 **[Documentation](https://rennf93.github.io/guard-agent/latest/)** — full technical documentation
- 🎮 **[Playground](https://playground.guard-core.com)** — try the Guard stack in-browser, no install required
- 📊 **[Dashboard](https://app.guard-core.com)** — real-time security events, metrics, and dynamic rules for your projects
- 💬 **[Discord](https://discord.gg/ZW7ZJbjMkK)** — community & maintainer support

---

Ecosystem
---------

Guard Agent is the Python telemetry agent for the Guard ecosystem. It pairs with any framework adapter built on the shared engine. Parallel implementations of the engine and adapters exist for TypeScript (on npm) and Rust (on crates.io).

### Python

| Package | Role | PyPI |
|---|---|---|
| [guard-core](https://github.com/rennf93/guard-core) | Framework-agnostic security engine | [![PyPI](https://img.shields.io/pypi/v/guard-core)](https://pypi.org/project/guard-core/) |
| [guard-agent](https://github.com/rennf93/guard-agent) | Telemetry agent (this package) | [![PyPI](https://img.shields.io/pypi/v/guard-agent)](https://pypi.org/project/guard-agent/) |
| [fastapi-guard](https://github.com/rennf93/fastapi-guard) | FastAPI / Starlette adapter | [![PyPI](https://img.shields.io/pypi/v/fastapi-guard)](https://pypi.org/project/fastapi-guard/) |
| [flaskapi-guard](https://github.com/rennf93/flaskapi-guard) | Flask adapter | [![PyPI](https://img.shields.io/pypi/v/flaskapi-guard)](https://pypi.org/project/flaskapi-guard/) |
| [djapi-guard](https://github.com/rennf93/djapi-guard) | Django adapter | [![PyPI](https://img.shields.io/pypi/v/djapi-guard)](https://pypi.org/project/djapi-guard/) |
| [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard) | Tornado adapter | [![PyPI](https://img.shields.io/pypi/v/tornadoapi-guard)](https://pypi.org/project/tornadoapi-guard/) |

### TypeScript / JavaScript

Published under the [`@guardcore`](https://www.npmjs.com/org/guardcore) npm scope. Source in the [guard-core-ts](https://github.com/rennf93/guard-core-ts) monorepo. **Production-ready.**

| Package | Role | npm |
|---|---|---|
| [@guardcore/core](https://github.com/rennf93/guard-core-ts/tree/master/packages/core) | Core engine | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fcore)](https://www.npmjs.com/package/@guardcore/core) |
| [@guardcore/express](https://github.com/rennf93/guard-core-ts/tree/master/packages/express) | Express adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fexpress)](https://www.npmjs.com/package/@guardcore/express) |
| [@guardcore/nestjs](https://github.com/rennf93/guard-core-ts/tree/master/packages/nestjs) | NestJS adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fnestjs)](https://www.npmjs.com/package/@guardcore/nestjs) |
| [@guardcore/fastify](https://github.com/rennf93/guard-core-ts/tree/master/packages/fastify) | Fastify adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Ffastify)](https://www.npmjs.com/package/@guardcore/fastify) |
| [@guardcore/hono](https://github.com/rennf93/guard-core-ts/tree/master/packages/hono) | Hono adapter | [![npm](https://img.shields.io/npm/v/%40guardcore%2Fhono)](https://www.npmjs.com/package/@guardcore/hono) |

### Rust

Published on crates.io. **🚧 Placeholder crates — implementation in progress.**

| Package | Role | crates.io |
|---|---|---|
| [guard-core](https://github.com/rennf93/guard-core-rs) | Core engine | [![crates.io](https://img.shields.io/crates/v/guard-core)](https://crates.io/crates/guard-core) |
| [actix-guard-rs](https://github.com/rennf93/actix-guard-rs) | Actix adapter | [![crates.io](https://img.shields.io/crates/v/actix-guard-rs)](https://crates.io/crates/actix-guard-rs) |
| [axum-guard-rs](https://github.com/rennf93/axum-guard-rs) | Axum adapter | [![crates.io](https://img.shields.io/crates/v/axum-guard-rs)](https://crates.io/crates/axum-guard-rs) |
| [rocket-guard-rs](https://github.com/rennf93/rocket-guard-rs) | Rocket adapter | [![crates.io](https://img.shields.io/crates/v/rocket-guard-rs)](https://crates.io/crates/rocket-guard-rs) |
| [tower-guard-rs](https://github.com/rennf93/tower-guard-rs) | Tower adapter | [![crates.io](https://img.shields.io/crates/v/tower-guard-rs)](https://crates.io/crates/tower-guard-rs) |

### AI Coding Agents

| Package | Role | PyPI |
|---|---|---|
| [guard-core-mcp](https://github.com/rennf93/guard-core-mcp) | MCP server — config validation, docs search, detection sandbox | [![PyPI](https://img.shields.io/pypi/v/guard-core-mcp)](https://pypi.org/project/guard-core-mcp/) |

An MCP server that answers questions about Guard Agent from the version **installed in your project**, rather than from a model's memory of it. It validates a config against the real `AgentConfig` model — catching typos pydantic would otherwise ignore silently — looks up any field's type, default and description, and searches the bundled docs for all three Python packages.

```bash
uv add --dev guard-core-mcp
claude mcp add guard-core -- uv run guard-core-mcp
```

Install it into the same environment as Guard Agent — it introspects what is actually installed there, so an isolated run (`uvx`) has nothing to read.

All Python adapters share the same Guard Agent runtime and dashboard — a single telemetry contract across every framework.

---

Key Features
------------

-   **Framework-Agnostic Core**: One agent, one dashboard — works with every Guard adapter (FastAPI, Flask, Django, Tornado) through a shared wire protocol.
-   **Automatic Integration**: Adapters wire the agent into their middleware automatically. Enable it through the adapter's `SecurityConfig` — no glue code required.
-   **High-Performance Architecture**: Built on asynchronous I/O principles to ensure zero performance impact on your application while maintaining real-time data collection capabilities.
-   **Enterprise-Grade Reliability**: Implements industry-standard resilience patterns including circuit breakers, exponential backoff with jitter, and intelligent retry mechanisms to guarantee data delivery.
-   **Intelligent Data Management**: Features multi-tier buffering with in-memory and optional Redis persistence, ensuring zero data loss during network interruptions or application restarts.
-   **Real-Time Security Updates**: Supports dynamic security policy updates from the centralized management platform, enabling immediate threat response without service interruption.
-   **Extensible Architecture**: Designed with protocol-based abstractions, allowing seamless integration with custom transport layers, storage backends, and monitoring systems.
-   **Comprehensive Security Intelligence**: Captures granular security events and performance metrics, providing actionable insights for security operations and compliance requirements.

---

Installation
------------

```bash
uv add guard-agent
```

Alternatives:

```bash
poetry add guard-agent
```

```bash
pip install guard-agent
```

> The legacy name `fastapi-guard-agent` is still published as a meta-package that installs `guard-agent` transitively — existing installs keep working, but new projects should use `guard-agent` directly.

Optional extras:

```bash
uv add "guard-agent[redis]"    # Enable Redis-backed event buffer
```

---

Getting Started
---------------

Guard Agent is embedded by your framework's adapter — you enable it through the adapter's `SecurityConfig` and drive its lifecycle appropriately for that framework. Each adapter's doc page covers the exact pattern; the FastAPI pattern below is the canonical async integration.

### FastAPI example

With fastapi-guard, the `SecurityMiddleware` owns the agent lifecycle: enable it through `SecurityConfig` and the middleware starts and stops the flush loop on the app's event loop for you. Do **not** construct an `AgentConfig`, call `guard_agent()`, or wire a `lifespan` hook here --- that creates a second agent that never receives traffic.

```python
import os

from fastapi import FastAPI
from guard import SecurityConfig, SecurityDecorator, SecurityMiddleware

api_key = os.environ.get("GUARD_API_KEY", "")
project_id = os.environ.get("GUARD_PROJECT_ID", "")
core_url = os.environ.get("GUARD_CORE_URL", "https://api.guard-core.com")

security_config = SecurityConfig(
    auto_ban_threshold=5,
    auto_ban_duration=300,
    enable_agent=bool(api_key),
    agent_api_key=api_key,
    agent_endpoint=core_url,
    agent_project_id=project_id,
    agent_buffer_size=5000,
    agent_flush_interval=2,
    enable_dynamic_rules=bool(api_key),
    dynamic_rule_interval=60,
)

guard = SecurityDecorator(security_config)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=security_config)
SecurityMiddleware.configure_cors(app, security_config)
app.state.guard_decorator = guard


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Hello World"}
```

Flask is synchronous and handles start/stop internally; Tornado uses `await security_middleware.initialize()` / `reset()`; Django wires the middleware via settings. See [docs/adapters](https://rennf93.github.io/guard-agent/latest/adapters/fastapi/) for the canonical pattern per framework.

With `enable_agent=True`, the agent automatically:

- Captures security violations (IP bans, rate-limit breaches, suspicious request patterns)
- Collects performance telemetry for security operations monitoring
- Synchronizes security policies from the centralized management platform
- Implements intelligent buffering for optimal network utilization
- Recovers automatically from transient network failures

---

Advanced Configuration
----------------------

For standalone use or custom event handling, instantiate the agent directly:

```python
from guard_agent.client import guard_agent
from guard_agent.models import AgentConfig

config = AgentConfig(
    api_key="YOUR_API_KEY",
    project_id="YOUR_PROJECT_ID",
)

agent = guard_agent(config)
```

### Configuration Parameters

#### Authentication & Identification
-   **`api_key: str`** (Required): Authentication key for the Guard management platform
-   **`project_id: str | None`**: Unique project identifier for data segregation and multi-tenancy support

#### Network Configuration
-   **`endpoint: str`**: Management platform API endpoint (Default: `https://api.guard-core.com`)
-   **`timeout: int`**: HTTP request timeout in seconds (Default: `30`)
-   **`retry_attempts: int`**: Maximum retry attempts for failed requests (Default: `3`)
-   **`backoff_factor: float`**: Exponential backoff multiplier for retry delays (Default: `1.0`)

#### Data Management
-   **`buffer_size: int`**: Maximum events in memory buffer before automatic flush (Default: `100`)
-   **`flush_interval: int`**: Automatic buffer flush interval in seconds (Default: `30`)
-   **`max_payload_size: int`**: Maximum payload size in bytes before truncation (Default: `1024`)
-   **`buffer_overflow_policy: Literal["drop", "block", "raise"]`**: Behavior when the in-memory buffer is full (Default: `"drop"`)
    -   `"drop"`: silently evict the oldest entry; production-safe for high-throughput, loses events when the SaaS endpoint is unreachable
    -   `"block"`: backpressure the caller until a flush frees space; appropriate when event integrity matters more than request latency
    -   `"raise"`: throw `BufferFullError` so callers can react; appropriate in tests or strict environments

#### Feature Control
-   **`enable_metrics: bool`**: Enable performance metrics collection (Default: `True`)
-   **`enable_events: bool`**: Enable security event collection (Default: `True`)

#### Security & Privacy
-   **`sensitive_headers: list[str]`**: HTTP headers to redact from collected data (Default: `["authorization", "cookie", "x-api-key"]`)

---

Migration from `fastapi-guard-agent`
------------------------------------

No code changes required. The import path was always `guard_agent`:

```python
# This worked before and still works:
from guard_agent import GuardAgentHandler, AgentConfig
```

To switch your install command:

```bash
# Old (still works via shim)
uv add fastapi-guard-agent

# New (preferred)
uv add guard-agent
```

Equivalent in other package managers:

```bash
# Poetry
poetry remove fastapi-guard-agent && poetry add guard-agent

# pip (or pip-tools)
pip uninstall fastapi-guard-agent && pip install guard-agent
```

The legacy `fastapi-guard-agent` name is maintained as a meta-package pointing to `guard-agent>=2.0.0,<3.0.0`, so pinned environments keep resolving correctly.

---

Contributing
------------

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

---

License
-------

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Author
------

Renzo Franceschini - [rennf93@users.noreply.github.com](mailto:rennf93@users.noreply.github.com)

---

Acknowledgements
----------------

- [FastAPI](https://fastapi.tiangolo.com/)
- [Flask](https://flask.palletsprojects.com/)
- [Django](https://www.djangoproject.com/)
- [Tornado](https://www.tornadoweb.org/)
- [Redis](https://redis.io/)
- [httpx](https://www.python-httpx.org/)
- [Pydantic](https://pydantic-docs.helpmanual.io/)
