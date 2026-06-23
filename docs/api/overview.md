# API Overview

The Guard Agent API provides a comprehensive, protocol-driven architecture for enterprise-grade security telemetry. Designed with extensibility and reliability at its core, the API enables seamless integration with diverse monitoring ecosystems while maintaining strict performance guarantees.

## System Architecture

The agent implements a layered architecture optimized for high-throughput telemetry collection with minimal application impact:

```mermaid
graph TB
    subgraph "FastAPI Application"
        FG[FastAPI Guard<br/>Security Middleware]
        SC[SecurityConfig<br/>enable_agent=True]
    end

    subgraph "Guard Agent (Auto-initialized)"
        AH[Agent Handler<br/>Central Orchestrator]
        EB[Event Buffer<br/>High-Performance Queue]
        TR[HTTP Transport<br/>Resilient Network Layer]

        subgraph "Protocol Abstractions"
            BP[Buffer Protocol]
            TP[Transport Protocol]
            RP[Redis Protocol]
            AP[Agent Protocol]
        end
    end

    subgraph "External Systems"
        RD[(Redis<br/>Persistent Buffer)]
        BE[Management Platform<br/>Analytics & Policy Engine]
    end

    SC --> FG
    FG --> AH
    AH --> EB
    EB --> TR
    EB -.-> RD
    TR --> BE

    AH -.-> BP
    AH -.-> TP
    EB -.-> RP
    AH -.-> AP
```

## Core Components

### 1. Agent Handler (`GuardAgentHandler`)

The central orchestration component responsible for coordinating all telemetry operations.

**Core Responsibilities:**
- **Lifecycle Management**: Orchestrates initialization, operation, and graceful shutdown sequences
- **Event Processing**: Implements high-throughput event ingestion with backpressure handling
- **Metric Aggregation**: Performs efficient metric collection with configurable sampling rates
- **Task Coordination**: Manages asynchronous operations including buffer flushing and policy synchronization

**Basic Usage (Auto-integrated with FastAPI Guard):**
```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

# Configure with agent enabled
config = SecurityConfig(
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_project_id="your-project-id",
    agent_endpoint="https://api.guard-core.com",
)

app = FastAPI()
middleware = SecurityMiddleware(app, config=config)
# Agent starts automatically with middleware
```

**Direct Usage (Advanced):**
```python
from guard_agent import guard_agent, AgentConfig

# Initialize directly
config = AgentConfig(
    api_key="your-api-key",
    project_id="your-project-id",
)
agent = guard_agent(config)

# Lifecycle
await agent.start()
await agent.stop()

# Send data manually
await agent.send_event(security_event)
await agent.send_metric(performance_metric)
```

### 2. Event Buffer (`EventBuffer`)

High-performance buffering subsystem engineered for optimal throughput and reliability.

**Technical Capabilities:**
- **Lock-Free Architecture**: Utilizes deque-based storage for minimal contention
- **Persistent Buffering**: Optional Redis integration for durability across restarts
- **Intelligent Flushing**: Adaptive algorithms balance latency and efficiency
- **Concurrency Safety**: Full async/await compatibility with thread-safe operations

**Usage Patterns:**
```python
from guard_agent.buffer import EventBuffer
from guard_agent.models import AgentConfig, SecurityEvent

# Create buffer (sizing comes from AgentConfig.buffer_size / flush_interval)
config = AgentConfig(api_key="your-api-key")
buffer = EventBuffer(config, flush_callback=None)

# Optional Redis durability
await buffer.initialize_redis(redis_client)

# Add events
await buffer.add_event(security_event)
await buffer.add_metric(performance_metric)

# Manual flush
events = await buffer.flush_events()
metrics = await buffer.flush_metrics()
```

### 3. HTTP Transport (`HTTPTransport`)

Enterprise-grade network layer implementing industry best practices for reliable data delivery.

**Reliability Features:**
- **Intelligent Retry**: Deterministic exponential backoff (no jitter), capped at 60s per delay
- **Circuit Breaker**: Automatic failure detection with graceful degradation
- **Fixed Rate Limiting**: Client-side sliding window (100 req/60s); server `429 Retry-After` is honored separately
- **Comprehensive Telemetry**: Real-time transport statistics for operational visibility

**Configuration:**
```python
from guard_agent.transport import HTTPTransport
from guard_agent.models import AgentConfig

# Retry, timeout, and backoff all come from AgentConfig
config = AgentConfig(
    api_key="your-api-key",
    endpoint="https://api.guard-core.com",
    timeout=30,
    retry_attempts=3,
    backoff_factor=1.0,
)
transport = HTTPTransport(config)
```

### 4. Data Models

Strongly-typed data structures leveraging Pydantic for validation and serialization.

**Primary Models:**
- `AgentConfig`: Comprehensive configuration with validation and defaults
- `SecurityEvent`: Rich security event representation with contextual metadata
- `SecurityMetric`: Performance metrics with dimensional tagging support
- `EventBatch`: Optimized batch container for network efficiency
- `AgentStatus`: Real-time operational telemetry and health indicators

### 5. Protocol System

Clean abstraction layer enabling custom implementations while maintaining compatibility.

**Protocol Interfaces:**
- `AgentHandlerProtocol`: Defines agent lifecycle and event handling contracts
- `BufferProtocol`: Specifies buffering semantics and performance guarantees
- `TransportProtocol`: Establishes network transport requirements and capabilities
- `RedisHandlerProtocol`: Standardizes persistent storage integration patterns

## API Reference by Module

### Core Handler API

#### `GuardAgentHandler`

The main entry point for all agent operations.

```python
class GuardAgentHandler:
    def __init__(self, config: AgentConfig) -> None: ...

    # Lifecycle Management
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def close(self) -> None: ...

    # Event & Metric Handling
    async def send_event(self, event: Any) -> None: ...
    async def send_metric(self, metric: Any) -> None: ...
    async def flush_buffer(self) -> None: ...

    # Status & Health
    async def get_status(self) -> AgentStatus: ...
    async def health_check(self) -> bool: ...
    def get_stats(self) -> dict[str, Any]: ...

    # Redis & Dynamic Rules
    async def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...
    async def get_dynamic_rules(self) -> DynamicRules | None: ...
```

**Key Methods:**

| Method | Description | Usage |
|--------|-------------|-------|
| `start()` | Initialize agent and start background tasks | Called on app startup |
| `stop()` | Graceful shutdown with data preservation | Called on app shutdown |
| `send_event()` | Send security event to buffer | Auto-called by FastAPI Guard |
| `send_metric()` | Send performance metric | Manual or auto collection |
| `get_status()` | Get real-time agent status | Health monitoring |

### Buffer API

#### `EventBuffer`

Intelligent event and metric buffering with persistence.

```python
class EventBuffer:
    def __init__(
        self,
        config: AgentConfig,
        flush_callback: Callable[[], Awaitable[None]] | None = None,
    ) -> None: ...

    # Data Management
    async def add_event(self, event: SecurityEvent) -> None: ...
    async def add_metric(self, metric: SecurityMetric) -> None: ...
    async def flush_events(self) -> list[SecurityEvent]: ...
    async def flush_metrics(self) -> list[SecurityMetric]: ...

    # Status & Configuration
    def get_stats(self) -> dict[str, Any]: ...
    async def get_buffer_size(self) -> int: ...
    async def clear_buffer(self) -> None: ...
```

### Transport API

#### `HTTPTransport`

Enterprise-grade HTTP client with resilience features.

```python
class HTTPTransport:
    def __init__(self, config: AgentConfig) -> None: ...

    # Lifecycle
    async def initialize(self) -> None: ...
    async def close(self) -> None: ...

    # Data Transmission
    async def send_events(self, events: list[SecurityEvent]) -> bool: ...
    async def send_metrics(self, metrics: list[SecurityMetric]) -> bool: ...
    async def send_status(self, status: AgentStatus) -> bool: ...

    # Health & Status
    def get_stats(self) -> dict[str, Any]: ...

    # Dynamic Rules
    async def fetch_dynamic_rules(self) -> DynamicRules | None: ...
```

### Models API

#### Core Data Models

**AgentConfig**
```python
class AgentConfig(BaseModel):
    api_key: str
    endpoint: str = "https://api.guard-core.com"
    project_id: str | None = None
    buffer_size: int = 100
    flush_interval: int = 30
    enable_events: bool = True
    enable_metrics: bool = True

    retry_attempts: int = 3
    timeout: int = 30
    backoff_factor: float = 1.0

    compression_enabled: bool = True
    compression_threshold: int = 1024

    project_encryption_key: str | None = None
    # ... additional fields
```

**Compression fields**

- `compression_enabled` (default `True`) — when set, the agent gzip-compresses every outgoing batch body whose JSON exceeds `compression_threshold` bytes and sends it with `Content-Encoding: gzip`. Smaller bodies skip compression. The Guard Core SaaS decompresses gzip request bodies via `GzipRequestMiddleware` before pydantic validation. Set `compression_enabled=False` only if your ingestion endpoint does not handle `Content-Encoding: gzip` request bodies.
- `compression_threshold` (default `1024` bytes) — minimum body size in bytes before gzip kicks in. Tune lower for chatty deployments, higher to save CPU on small batches.

**Retry-After**

429 responses raise `RateLimitedError(retry_after_seconds)`; the transport sleeps that exact value (capped at 300s) before retrying instead of falling back to client-side exponential backoff.

**SecurityEvent**
```python
class SecurityEvent(BaseModel):
    timestamp: datetime
    event_type: str
    ip_address: str = ""
    action_taken: str = ""
    reason: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    # ... additional fields
```

**SecurityMetric**
```python
class SecurityMetric(BaseModel):
    timestamp: datetime
    metric_type: Literal[
        "request_count",
        "response_time",
        "error_rate",
        "bandwidth_usage",
        "threat_level",
        "block_rate",
        "cache_hit_rate",
    ]
    value: float
    endpoint: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    # ... additional fields
```

## Implementation Patterns

### Pattern 1: Standard Deployment

```python
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

app = FastAPI()

# Configure FastAPI Guard with agent
config = SecurityConfig(
    # Enable agent
    enable_agent=True,
    agent_api_key="your-api-key",
    agent_project_id="your-project-id",

    # Security settings
    enable_rate_limiting=True,
    enable_ip_banning=True,
    enable_penetration_detection=True,
)

# Add middleware - agent starts automatically
middleware = SecurityMiddleware(app, config=config)
```

### Pattern 2: Custom Event Integration

```python
from guard_agent import guard_agent, AgentConfig, SecurityEvent
from guard_agent.utils import get_current_timestamp

# Get agent instance
config = AgentConfig(
    api_key="your-api-key",
    project_id="your-project-id",
)
agent = guard_agent(config)

async def custom_security_check(request):
    """Custom security validation with event reporting."""

    if is_suspicious(request):
        # Create custom event
        event = SecurityEvent(
            timestamp=get_current_timestamp(),
            event_type="custom_rule_triggered",
            ip_address=request.client.host,
            action_taken="blocked",
            reason="Custom security check failed",
            endpoint=str(request.url.path),
            method=request.method,
            metadata={
                "check_type": "business_logic",
                "severity": "high"
            }
        )

        # Send to agent
        await agent.send_event(event)

        return False

    return True
```

### Pattern 3: Performance Monitoring

```python
from guard_agent import guard_agent, SecurityMetric
from guard_agent.utils import get_current_timestamp
import time

# Get agent instance (singleton)
agent = guard_agent(AgentConfig(
    api_key="your-api-key",
    project_id="your-project-id",
))

async def monitor_endpoint_performance():
    """Monitor endpoint performance and send metrics."""

    start_time = time.time()

    try:
        # Your endpoint logic
        result = await process_request()

        # Success metric
        await agent.send_metric(SecurityMetric(
            timestamp=get_current_timestamp(),
            metric_type="response_time",
            value=time.time() - start_time,
            endpoint="/api/process",
            tags={"status": "success"}
        ))

        return result

    except Exception as e:
        # Error metric
        await agent.send_metric(SecurityMetric(
            timestamp=get_current_timestamp(),
            metric_type="error_rate",
            value=1.0,
            endpoint="/api/process",
            tags={"error": str(type(e).__name__)}
        ))
        raise
```

### Pattern 4: Health Monitoring

```python
@app.get("/health")
async def health_check():
    """Application health check including agent status."""

    agent_healthy = await agent.health_check()
    agent_status = await agent.get_status()

    return {
        "status": "healthy" if agent_healthy else "degraded",
        "agent": {
            "status": agent_status.status,
            "events_sent": agent_status.events_sent,
            "last_flush": agent_status.last_flush,
            "buffer_size": agent_status.buffer_size
        }
    }
```

## Reliability Patterns

### Graceful Degradation

The agent implements comprehensive failure isolation to protect application availability:

```python
try:
    await agent.send_event(event)
except Exception as e:
    # Agent failure doesn't break your app
    logger.warning(f"Agent error: {e}")
    # Application continues normally
```

### Circuit Breaker Implementation

Advanced failure detection with automatic recovery mechanisms:

```python
# Circuit breaker state machine:
# - CLOSED: Normal operation with request forwarding
# - OPEN: Fast-fail mode preventing backend overload
# - HALF_OPEN: Controlled recovery testing with limited traffic
```

### Retry Strategies

Sophisticated retry algorithms optimize for both reliability and backend protection:

```python
# Retry configuration (delay = backoff_factor * 2**attempt, capped at max_delay):
retry_attempts: 3                # Retries after the first try (~retry_attempts + 1 total attempts)
backoff_factor: 1.0              # Multiplier on the hardcoded 2**attempt growth
max_delay: 60                    # Caps maximum retry delay (no jitter)
```

## Performance Engineering

### Memory Optimization

Strategic memory management for various deployment scales:

- **Buffer Sizing**: Dynamic sizing based on traffic patterns and memory constraints
- **Flush Strategies**: Adaptive algorithms balance latency requirements with efficiency
- **Persistent Buffering**: Redis integration for memory-constrained environments

### Network Optimization

Advanced techniques minimize bandwidth and latency:

- **Intelligent Batching**: Adaptive batch sizes based on network conditions
- **Compression**: Automatic gzip compression for payload optimization
- **Connection Management**: HTTP/1.1 with keep-alive connection pooling

### Deployment Profiles

```python
# Microservice deployment (low memory, high frequency)
config = AgentConfig(api_key="your-api-key", buffer_size=100, flush_interval=10)

# Standard API service (balanced profile)
config = AgentConfig(api_key="your-api-key", buffer_size=1000, flush_interval=30)

# High-throughput gateway (optimized for volume)
config = AgentConfig(api_key="your-api-key", buffer_size=10000, flush_interval=60)
```
