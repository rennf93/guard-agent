# Installation Guide

This guide provides detailed instructions for deploying Guard Agent across various environments and configurations.

!!! info "Renamed from `fastapi-guard-agent` in 2.0.0"
    The package was previously published as `fastapi-guard-agent`. The Python import path (`from guard_agent import ...`) is unchanged. Existing `pip install fastapi-guard-agent` commands still resolve via a meta-package that depends on `guard-agent>=2.0.0,<3.0.0`.

## System Requirements

### Python Runtime

Guard Agent requires **Python 3.10 or higher**. For optimal performance and feature compatibility, Python 3.11+ is recommended.

Verify your Python installation:

```bash
python --version
```

### Core Dependencies

The following dependencies are automatically managed during installation:

#### Required Components
- **`pydantic`** ≥ 2.0 - Type-safe data validation and serialization
- **`httpx`** - High-performance async HTTP client with connection pooling
- **`cryptography`** - AES-256-GCM payload encryption
- **`typing-extensions`** ≥ 4.0 - Enhanced type hints for Python 3.10 compatibility

#### Optional Components
- A Guard adapter for your framework (install alongside the agent):
  - **`fastapi-guard`** for FastAPI
  - **`flaskapi-guard`** for Flask
  - **`djapi-guard`** for Django
  - **`tornadoapi-guard`** for Tornado *(coming soon — not yet published on PyPI)*
- **`redis`** ≥ 6.0.0 - Client library for persistent buffering (production recommended)
- **Redis Server** 6.0+ - External service for high-availability deployments
- **ASGI/WSGI Server** - Uvicorn, Hypercorn, Gunicorn, or similar for application hosting

## Installation Methods

### Standard Installation (uv)

Install Guard Agent together with the adapter for your framework:

```bash
# FastAPI
uv add fastapi-guard guard-agent

# Flask
uv add flaskapi-guard guard-agent

# Django
uv add djapi-guard guard-agent
```

!!! note "Tornado adapter — coming soon"
    The Tornado adapter (`tornadoapi-guard`) is not yet published on PyPI. Until it ships, use Guard Agent standalone (see below) for Tornado applications.

For standalone agent deployments (direct wire protocol, no adapter):

```bash
uv add guard-agent
```

### Version-Specific Installation

Pin to a specific version for reproducible deployments:

```bash
uv add "guard-agent==2.8.0"
```

### Alternative Package Managers

#### Poetry

```bash
poetry add guard-agent
```

For development dependencies:

```bash
poetry add --group dev guard-agent
```

#### pip

```bash
pip install guard-agent
```

#### pip-tools Workflow

Define in `requirements.in`:

```text
guard-agent==2.8.0
```

Generate locked requirements:

```bash
pip-compile requirements.in
pip-sync requirements.txt
```

### Development Installation

For contributors and advanced users requiring source access:

```bash
git clone https://github.com/rennf93/guard-agent.git
cd guard-agent
uv sync --extra dev
```

Install pre-commit hooks for code quality:

```bash
pre-commit install
```

### Container Deployment

#### Production Dockerfile

Optimized multi-stage build for minimal image size:

```dockerfile
FROM python:3.11-slim as builder

# Install uv
RUN pip install --user uv
ENV PATH=/root/.local/bin:$PATH

# Sync project dependencies
WORKDIR /build
COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-dev

FROM python:3.11-slim

# Copy installed packages
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Application setup
WORKDIR /app
COPY . .

# Security: Run as non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Installation Verification

Comprehensive validation ensures proper deployment:

### 1. Package Import Validation

Verify successful installation through systematic import testing:

```python
# test_installation.py
try:
    # Validate Guard Agent module availability
    from guard_agent import __version__
    from guard_agent.client import guard_agent
    from guard_agent.models import AgentConfig
    print(f"Guard Agent {__version__} successfully installed")

    # Validate your framework's adapter (example: FastAPI)
    from guard import SecurityConfig, SecurityMiddleware
    print("FastAPI adapter (fastapi-guard) verified")
except ImportError as e:
    print(f"Installation validation failed: {e}")
```

Run the test:

```bash
python test_installation.py
```

### 2. Configuration Validation Test

Validate proper integration between your framework's adapter and the telemetry agent (example uses the FastAPI adapter):

```python
# test_config.py
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

try:
    app = FastAPI()

    # Validate integrated configuration
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        agent_project_id="test-project"
    )
    app.add_middleware(SecurityMiddleware, config=config)
    print("✅ Security middleware with telemetry pipeline successfully configured")
except Exception as e:
    print(f"❌ Configuration validation failed: {e}")
```

### 3. Redis Connectivity Validation (Production Environments)

For production deployments utilizing Redis for persistent buffering:

```python
# test_redis.py
import asyncio
from redis.asyncio import Redis

async def validate_redis_connectivity():
    try:
        redis = Redis.from_url("redis://localhost:6379")
        await redis.ping()
        print("✅ Redis connectivity validated - persistent buffering available")
    except Exception as e:
        print(f"❌ Redis connectivity validation failed: {e}")
    finally:
        await redis.close()

if __name__ == "__main__":
    asyncio.run(validate_redis_connectivity())
```

## Configuration Verification

Create a minimal application to ensure everything works:

```python
# minimal_test.py
from fastapi import FastAPI
from guard import SecurityConfig, SecurityMiddleware

app = FastAPI()

# Configure FastAPI Guard with agent
config = SecurityConfig(
    # Basic security
    enable_rate_limiting=True,
    rate_limit=100,

    # Enable agent
    enable_agent=True,
    agent_api_key="your-test-api-key",
    agent_project_id="your-test-project",
    agent_endpoint="https://api.guard-core.com"
)

# Add middleware - agent starts automatically
app.add_middleware(SecurityMiddleware, config=config)

@app.get("/")
async def root():
    return {"message": "Guard Agent is running!"}

@app.get("/test")
async def test():
    return {"agent_enabled": config.enable_agent}

# Run with: uvicorn minimal_test:app --reload
```

## Troubleshooting Guide

### Module Import Failures

**Symptom**: `ModuleNotFoundError: No module named 'guard_agent'`

**Resolution Strategies**:

1. Ensure you're using the correct Python environment:

    ```bash
    which python
    pip list | grep guard-agent
    ```

2. If using virtual environments, make sure it's activated:

    ```bash
    source venv/bin/activate  # Linux/Mac
    # or
    venv\Scripts\activate     # Windows
    ```

3. Reinstall the package:

    ```bash
    uv remove guard-agent && uv add guard-agent
    # or with pip:
    # pip uninstall guard-agent && pip install guard-agent
    ```

### Redis Connectivity Issues

**Symptom**: `ConnectionError: Error connecting to Redis`

**Resolution Strategies**:

1. Ensure Redis server is running:

    ```bash
    redis-cli ping
    ```

2. Check Redis configuration in your agent config:

    ```python
    # Make sure Redis URL is correct
    redis = Redis.from_url("redis://localhost:6379/0")
    ```

3. Install Redis server if not installed:

    ```bash
    # Ubuntu/Debian
    sudo apt-get install redis-server

    # macOS with Homebrew
    brew install redis

    # Start Redis
    redis-server
    ```

### Network Transport Failures

**Symptom**: `httpx.HTTPError` or connection timeout exceptions

**Resolution Strategies**:

1. Check your API endpoint configuration:

    ```python
    config = AgentConfig(
        endpoint="https://api.guard-core.com",  # Ensure this is correct
        api_key="your-api-key"
    )
    ```

2. Verify network connectivity:

    ```bash
    curl -I https://api.guard-core.com/health
    ```

3. Check firewall settings and proxy configuration if behind corporate network.

### Installation Permission Errors

**Symptom**: `PermissionError` during package installation

**Resolution Strategies**:

1. Use a project-local virtual environment (recommended — this is what `uv` does by default):

    ```bash
    uv sync
    ```

2. With pip, use a manual venv:

    ```bash
    python -m venv .venv
    source .venv/bin/activate
    pip install guard-agent
    ```

3. With pip, user-scoped install as a last resort:

    ```bash
    pip install --user guard-agent
    ```

## Post-Installation Guidance

Following successful installation of `guard-agent`, proceed with:

1. **[Getting Started Guide](tutorial/getting-started.md)** - Comprehensive implementation walkthrough

### Get an API Key

The agent reports to the Guard management platform. Sign in or create a project at [**app.guard-core.com**](https://app.guard-core.com) to obtain the `api_key` and `project_id` used in the configuration examples above. You can also experiment with the full Guard stack — no install required — at [**playground.guard-core.com**](https://playground.guard-core.com).

## System Requirements Summary

| Component | Requirement |
|-----------|-------------|
| Python | 3.10+ (3.11+ recommended) |
| Memory | 64MB+ available RAM |
| Network | HTTPS outbound access |
| Storage | 10MB+ disk space |
| Redis | Optional but recommended for production |
