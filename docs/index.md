---
title: Guard Agent - Framework-Agnostic Security Telemetry for Python Web Apps
description: Enterprise-grade telemetry and monitoring agent for the Guard security ecosystem. Integrates with fastapi-guard, flaskapi-guard, djapi-guard, and tornadoapi-guard to provide real-time security event collection, performance monitoring, and dynamic policy management through a centralized platform.
keywords: fastapi, flask, django, tornado, security, middleware, telemetry, monitoring, enterprise, cloud, saas, compliance, threat intelligence
---

# Guard Agent

<p align="center">
    <a href="https://rennf93.github.io/guard-agent/latest/">
        <img src="https://rennf93.github.io/guard-agent/latest/assets/guard_agent_legend.svg" alt="Guard Agent">
    </a>
</p>

<p align="center">
    <strong>Guard Agent is a framework-agnostic telemetry and monitoring solution for the Guard security ecosystem. Paired with an adapter (<code>fastapi-guard</code>, <code>flaskapi-guard</code>, <code>djapi-guard</code>, or <code>tornadoapi-guard</code>), it collects security events, performance metrics, and operational telemetry in real time — feeding centralized security operations, compliance reporting, and dynamic threat response through an enterprise-grade management platform.</strong>
</p>

!!! info "Renamed from `fastapi-guard-agent` in 2.0.0"
    This package was previously published as `fastapi-guard-agent`. The Python import path (`from guard_agent import ...`) is unchanged. Existing `pip install fastapi-guard-agent` commands continue to work via a meta-package that transitively pulls `guard-agent`.

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
  <a href="https://playground.guard-core.com">Playground</a> &middot;
  <a href="https://app.guard-core.com">Dashboard</a> &middot;
  <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

Guard Agent bridges application-level security enforcement and enterprise security operations. It collects security events, performance metrics, and operational telemetry from any supported Guard adapter, providing real-time visibility into threats and anomalies across your Python web stack regardless of framework.

The collected telemetry flows to the Guard platform:

- **[app.guard-core.com](https://app.guard-core.com)** — the dashboard where your project's security events, metrics, and dynamic rules are managed in real time.
- **[playground.guard-core.com](https://playground.guard-core.com)** — a sandbox environment for experimenting with Guard configurations before wiring them into production.
- **[guard-core.com](https://guard-core.com)** — the umbrella product site with ecosystem overview and adapter matrix.

___

## Quick Start

Guard Agent is embedded by each framework's adapter — enable it via the adapter's `SecurityConfig`. The following example uses the FastAPI adapter; Flask, Django, and Tornado adapters expose analogous interfaces (see [Installation](installation.md) for per-adapter setup).

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityDecorator, SecurityMiddleware

config = SecurityConfig(
    # Basic security settings
    auto_ban_threshold=5,
    auto_ban_duration=300,

    # Enable agent for telemetry
    enable_agent=True,
    agent_api_key="YOUR_API_KEY",
    agent_project_id="YOUR_PROJECT_ID",
    agent_endpoint="https://api.guard-core.com",

    # Agent configuration
    agent_buffer_size=100,
    agent_flush_interval=30,
    agent_enable_events=True,
    agent_enable_metrics=True,

    # Enable dynamic rules from SaaS
    enable_dynamic_rules=True,
    dynamic_rule_interval=300,
)

guard = SecurityDecorator(config)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)
app.state.guard_decorator = guard

@app.get("/")
async def root():
    return {"message": "Hello World"}
```

___

## Core Capabilities

### Security Intelligence
-   **Automated Event Collection**: Captures comprehensive security events including authentication failures, authorization violations, rate limit breaches, and suspicious request patterns without manual instrumentation
-   **Real-Time Threat Detection**: Provides immediate visibility into security incidents with sub-second event propagation to the management platform
-   **Behavioral Analytics**: Tracks request patterns and user behavior to identify anomalies and potential security threats

### Enterprise Architecture
-   **Zero-Impact Performance**: Leverages asynchronous I/O and intelligent buffering to ensure telemetry collection adds negligible overhead to application performance
-   **Fault-Tolerant Design**: Implements circuit breakers, exponential backoff, and intelligent retry mechanisms to maintain operation during network disruptions
-   **Multi-Tier Buffering**: Combines in-memory and persistent Redis buffering to guarantee zero data loss during outages or maintenance windows

### Operational Excellence
-   **Dynamic Policy Management**: Supports real-time security policy updates without application restart, enabling immediate threat response
-   **Protocol-Based Extensibility**: Provides clean abstractions for custom transport implementations, storage backends, and data processors
-   **Comprehensive Observability**: Captures granular metrics including response times, error rates, and resource utilization for complete operational visibility

### Data Governance
-   **Privacy-First Design**: Implements configurable data redaction for sensitive headers and payload truncation to meet compliance requirements
-   **Intelligent Rate Limiting**: Prevents API exhaustion through client-side rate limiting with adaptive backpressure
-   **Health Monitoring**: Continuous self-diagnostics with automatic health reporting and degradation detection

___

## Installation

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

The legacy `fastapi-guard-agent` name is still published as a meta-package that installs `guard-agent` transitively — existing installs keep working, but new projects should use `guard-agent` directly.

### System Requirements
- Python 3.10 or higher (3.11+ recommended for optimal performance)
- A Guard adapter matching your web framework: `fastapi-guard`, `flaskapi-guard`, `djapi-guard`, or `tornadoapi-guard`
- Optional Redis 6.0+ for persistent buffering

___

## Implementation Patterns

### Primary Integration Pattern

The recommended approach leverages FastAPI Guard's built-in agent support for automatic telemetry collection:

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

config = SecurityConfig(
    # Enable agent
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_project_id="your-project-id",

    # Other security settings
    enable_rate_limiting=True,
    rate_limit=100,
    rate_limit_window=60,
)

app = FastAPI()
app.add_middleware(SecurityMiddleware, config=config)

# Agent automatically initialized with comprehensive event collection
```

### Advanced Usage Pattern

!!! warning "Do not use this pattern with fastapi-guard"
    The snippet below uses `guard_agent()` directly. If your app already uses `fastapi-guard`'s `SecurityMiddleware`, **do not** also call `guard_agent()` from your module-level code. The factory dispatches to `SyncGuardAgentHandler` when called from sync context (module load) and `GuardAgentHandler` when called from async context (the middleware's init) — they are **separate singletons**, and only the middleware's instance receives the telemetry stream. For fastapi-guard users, configure `agent_*` fields on `SecurityConfig` instead. See the [fastapi-guard Integration Guide](https://rennf93.github.io/fastapi-guard/latest/tutorial/integration/).

For specialized use cases that *don't* go through a framework adapter — custom event reporting in a worker, direct agent embedding in a non-adapter system, or sync-only frameworks (Flask, Django) integrated with `SyncGuardAgentHandler`:

```python
from guard_agent import guard_agent, AgentConfig, SecurityEvent
from guard_agent.utils import get_current_timestamp

# Configure agent directly
config = AgentConfig(
    api_key="your-api-key",
    project_id="your-project-id",
    buffer_size=100,
    flush_interval=30,
)

agent = guard_agent(config)
await agent.start()

# Manually send an event
event = SecurityEvent(
    timestamp=get_current_timestamp(),
    event_type="custom_rule_triggered",
    ip_address="192.168.1.100",
    action_taken="logged",
    reason="Manual event",
)
await agent.send_event(event)

# At shutdown
await agent.stop()
```

___

## Advanced Configuration

### Redis Integration

For production deployments, enable Redis for persistent buffering:

```python
from guard_agent.protocols import RedisHandlerProtocol

# Supply any object implementing RedisHandlerProtocol
# (the fastapi-guard Redis handler satisfies this protocol)
redis_handler: RedisHandlerProtocol = your_redis_handler

# Initialize agent with Redis
agent = guard_agent(config)
await agent.initialize_redis(redis_handler)
```

### Custom Transport

Implement custom transport for specialized backends:

```python
from guard_agent.protocols import TransportProtocol
from guard_agent.models import SecurityEvent, SecurityMetric, AgentStatus, DynamicRules

class CustomTransport(TransportProtocol):
    async def send_events(self, events: list[SecurityEvent]) -> bool:
        # Your custom implementation
        return True

    async def send_metrics(self, metrics: list[SecurityMetric]) -> bool:
        # Your custom implementation
        return True

    async def fetch_dynamic_rules(self) -> DynamicRules | None:
        # Your custom implementation
        return None

    async def send_status(self, status: AgentStatus) -> bool:
        # Your custom implementation
        return True

# Use custom transport
agent = guard_agent(config)
agent.transport = CustomTransport()
```

___

## Data Models

### SecurityEvent

Represents security-related events in your application:

```python
from guard_agent.models import SecurityEvent
from guard_agent.utils import get_current_timestamp

event = SecurityEvent(
    timestamp=get_current_timestamp(),
    event_type="ip_banned",
    ip_address="192.168.1.100",
    country="US",
    user_agent="Mozilla/5.0...",
    action_taken="block",
    reason="Rate limit exceeded",
    endpoint="/api/v1/login",
    method="POST",
    status_code=429,
    response_time=0.125,
    metadata={"attempts": 5, "window": 60}
)

await agent.send_event(event)
```

### SecurityMetric

Represents performance and usage metrics:

```python
from guard_agent.models import SecurityMetric

metric = SecurityMetric(
    timestamp=get_current_timestamp(),
    metric_type="request_count",
    value=100.0,
    endpoint="/api/v1/users",
    tags={"method": "GET", "status": "200"}
)

await agent.send_metric(metric)
```

___

## Dynamic Rules

Fetch and apply dynamic security rules from your SaaS backend:

```python
# Fetch current rules
rules = await agent.get_dynamic_rules()

if rules:
    # Apply IP blacklist
    if client_ip in rules.ip_blacklist:
        # Block request
        pass

    # Apply rate limits
    endpoint_limit = rules.endpoint_rate_limits.get("/api/sensitive")
    if endpoint_limit:
        requests, window = endpoint_limit
        # Apply endpoint-specific rate limit
        pass

    # Check emergency mode
    if rules.emergency_mode:
        # Apply stricter security measures
        pass
```

___

## Monitoring and Health

### Agent Status

Monitor agent health and performance:

```python
status = await agent.get_status()

print(f"Status: {status.status}")  # type allows healthy/degraded/failed; get_status() emits only healthy or degraded today
print(f"Uptime: {status.uptime}s")
print(f"Events sent: {status.events_sent}")
print(f"Buffer size: {status.buffer_size}")
print(f"Errors: {status.errors}")
```

### Statistics

Get detailed agent statistics:

```python
stats = agent.get_stats()

print(f"Running: {stats['running']}")
print(f"Events sent: {stats['events_sent']}")
print(f"Transport stats: {stats['transport_stats']}")
print(f"Buffer stats: {stats['buffer_stats']}")
```

___

## Error Handling

### Circuit Breaker

The agent includes a circuit breaker to handle backend failures gracefully:

```python
# Check circuit breaker state
transport_stats = agent.transport.get_stats()
if transport_stats["circuit_breaker_state"] == "OPEN":
    print("Backend is unavailable, circuit breaker is open")
```

### Retry Logic

Failed requests are automatically retried with exponential backoff:

```python
config = AgentConfig(
    api_key="your-api-key",
    retry_attempts=3,      # Number of retries
    backoff_factor=1.5,    # Exponential backoff factor
    timeout=30,            # Request timeout
)
```

___

## Documentation

- [Installation](installation.md)
- [Getting Started](tutorial/getting-started.md)
- [FastAPI Adapter](adapters/fastapi.md)
- [API Overview](api/overview.md)
- [Release Notes](release-notes.md)

[📖 **Learn More in the Documentation**](tutorial/getting-started.md)
