"""
Basic usage example for Guard Agent with the FastAPI adapter (fastapi-guard).

This example shows how to:
1. Integrate Guard Agent with fastapi-guard (recommended)
2. Use the direct agent API for custom events (advanced)
3. Monitor agent status and health

For Flask, Django, and Tornado integrations, see the adapter-specific
documentation — Guard Agent itself is framework-agnostic.
"""

import asyncio
from typing import Any

from fastapi import FastAPI
from guard import SecurityConfig, SecurityDecorator, SecurityMiddleware
from guard.lifespan import guard_lifespan

from guard_agent import (
    AgentConfig,
    GuardAgentHandler,
    SecurityEvent,
    SecurityMetric,
    get_current_timestamp,
)


async def basic_agent_usage() -> None:
    """Example of direct agent usage (ADVANCED USERS ONLY).

    NOTE: Most users should use the automatic integration with their framework
    adapter (fastapi-guard / flaskapi-guard / djangoapi-guard / tornadoapi-guard)
    shown in create_fastapi_app_with_agent() above. Direct usage is only needed
    for custom events or standalone deployments.
    """
    print("\n=== Direct Agent Usage (Advanced) ===")
    print("NOTE: This is for advanced use cases only!")
    print("Most users should use the automatic integration with their adapter.\n")

    # Configure the agent
    config = AgentConfig(
        api_key="demo-api-key-12345",
        project_id="demo-project",
        endpoint="https://api.guard-core.com",
        buffer_size=10,
        flush_interval=5,
    )

    # Get agent instance (singleton)
    agent = GuardAgentHandler(config)

    try:
        # Start the agent (only needed for direct usage)
        await agent.start()
        print("Agent started manually (for demonstration)")

        # Example: Send custom business logic events
        custom_event = SecurityEvent(
            timestamp=get_current_timestamp(),
            event_type="custom_business_rule",
            ip_address="192.168.1.100",
            action_taken="logged",
            reason="Custom validation failed",
            endpoint="/api/custom",
            method="POST",
            metadata={"rule": "business_logic_1", "severity": "medium"},
        )

        await agent.send_event(custom_event)
        print(f"Sent custom event: {custom_event.event_type}")

        # Example: Send custom metrics
        custom_metric = SecurityMetric(
            timestamp=get_current_timestamp(),
            metric_type="request_count",
            value=42.0,
            endpoint="/api/custom",
            tags={"type": "business_metric", "category": "validation"},
        )

        await agent.send_metric(custom_metric)
        print(
            f"Sent custom metric: {custom_metric.metric_type} = {custom_metric.value}"
        )

        # Get agent status
        status = await agent.get_status()
        print(f"\nDirect agent status: {status.status}")
        print(f"Events processed: {status.events_sent}")

    finally:
        # Stop the agent (only needed for direct usage)
        await agent.stop()
        print("Agent stopped (manual cleanup)")


def create_fastapi_app_with_agent() -> FastAPI:
    """Example of integrating Guard Agent with the FastAPI adapter (RECOMMENDED).

    The agent is enabled entirely through SecurityConfig's ``agent_*`` fields;
    ``SecurityMiddleware`` constructs and owns the agent singleton, and
    ``guard.lifespan.guard_lifespan`` drives boot-time initialization on the
    app's event loop. This matches the canonical pattern in
    ``guard-core-app/examples/app.py``. Do **not** build an ``AgentConfig``,
    call ``guard_agent()``/``GuardAgentHandler()``, or wire your own
    ``lifespan`` here — that constructs a second agent that never receives
    traffic and leaves the dashboard empty.
    """
    print("\n=== fastapi-guard + Guard Agent Integration (Recommended) ===")

    api_key = "demo-api-key-12345"
    project_id = "fastapi-demo"
    endpoint = "https://api.guard-core.com"

    # Configure the security middleware (includes agent_* fields)
    security_config = SecurityConfig(
        # Basic security settings
        auto_ban_threshold=5,
        auto_ban_duration=300,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        # Enable agent for telemetry
        enable_agent=True,
        agent_api_key=api_key,
        agent_project_id=project_id,
        agent_endpoint=endpoint,
        agent_buffer_size=50,
        agent_flush_interval=30,
        agent_enable_events=True,
        agent_enable_metrics=True,
        # Dynamic rules from the dashboard
        enable_dynamic_rules=True,
        dynamic_rule_interval=300,
    )

    app = FastAPI(title="Guard Agent Example (FastAPI)", lifespan=guard_lifespan)

    # Attach middleware and decorator. guard_lifespan (imported above) starts
    # and stops the agent the middleware built; nothing else to wire.
    app.add_middleware(SecurityMiddleware, config=security_config)
    guard = SecurityDecorator(security_config)
    app.state.guard_decorator = guard

    @app.get("/")
    async def root() -> dict[str, str]:
        """Root endpoint."""
        return {"message": "Guard Agent Demo (FastAPI adapter) - Automatic Integration"}

    @app.get("/protected")
    @guard.rate_limit(requests=5, window=60)
    async def protected_endpoint() -> dict[str, str]:
        """Rate limited endpoint - violations automatically sent to agent."""
        return {"message": "This endpoint is rate limited"}

    @app.get("/admin")
    @guard.require_ip(whitelist=["127.0.0.1", "10.0.0.0/8"])
    @guard.rate_limit(requests=2, window=300)
    async def admin_endpoint() -> dict[str, str]:
        """Admin endpoint - all security events automatically tracked."""
        return {"message": "Admin access granted"}

    @app.get("/api/data")
    @guard.block_countries(["CN", "RU"])
    @guard.rate_limit(requests=10, window=60)
    async def api_endpoint() -> dict[str, str]:
        """API endpoint with country blocking - events sent automatically."""
        return {"data": "Sensitive information"}

    @app.get("/health")
    async def health_check() -> dict[str, Any]:
        """Health check reporting whether the agent is enabled.

        There is no supported way to reach the middleware's own agent
        singleton from a route handler in fastapi-guard's public API; this
        mirrors what guard-core-app/examples/app.py exposes instead of
        reconstructing an AgentConfig here.
        """
        return {"app": "healthy", "agent_enabled": security_config.enable_agent}

    print("FastAPI app created with automatic agent integration")
    print("Endpoints:")
    print("  GET /                - Basic endpoint")
    print("  GET /protected       - Rate limited (5 req/min)")
    print("  GET /admin           - IP whitelist + rate limit")
    print("  GET /api/data        - Country blocking + rate limit")
    print("  GET /health          - Health check")
    print("\nAll security violations are automatically sent to the agent!")

    return app


async def integrated_app_example() -> None:
    """Example showing the complete integration with FastAPI Guard."""
    print("\n=== Complete Integration Example ===")

    print("When using FastAPI Guard with agent enabled:")
    print("1. Agent starts automatically with SecurityMiddleware")
    print("2. All security events are collected automatically:")
    print("   - IP bans and blocks")
    print("   - Rate limit violations")
    print("   - Country/region blocks")
    print("   - Suspicious request patterns")
    print("   - Authentication failures")
    print("   - Custom security rules")
    print("3. Performance metrics are collected")
    print("4. Dynamic rules are fetched from SaaS")
    print("5. Redis integration is handled by FastAPI Guard")
    print("\nNo manual agent management needed!")


async def main() -> None:
    """Run all examples."""
    print("Guard Agent Examples (FastAPI adapter)")
    print("=" * 40)

    # Show recommended integration first
    app = create_fastapi_app_with_agent()  # noqa: F841

    # Show complete integration benefits
    await integrated_app_example()

    # Basic direct usage example (advanced users)
    await basic_agent_usage()

    print("\n" + "=" * 40)
    print("Examples completed!")
    print("\nTo run the FastAPI app with automatic agent integration:")
    print("uvicorn examples.basic_usage:app --reload")
    print("\nThe agent will start automatically and collect all security events!")


# Export the app for uvicorn
app = create_fastapi_app_with_agent()

if __name__ == "__main__":
    # NOTE: This will try to connect to the demo endpoint which doesn't exist
    # In a real implementation, you would have a valid API key and endpoint
    asyncio.run(main())
