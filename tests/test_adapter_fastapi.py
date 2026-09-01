"""Integration smoke tests for the FastAPI adapter (fastapi-guard).

These tests verify that guard-agent integrates correctly with ``fastapi-guard``
when ``SecurityConfig.enable_agent=True``. They do not exercise agent wire
behavior (events, metrics, dynamic rules) — that's covered by the unit tests
in ``test_client.py`` etc. The goal here is a narrow integration contract:

1. ``SecurityConfig.to_agent_config()`` produces a valid ``AgentConfig``.
2. The adapter's middleware accepts an agent-enabled config without raising.
3. A request through the middleware completes successfully.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from guard import SecurityConfig, SecurityMiddleware

from guard_agent.models import AgentConfig


class TestFastAPIAdapterIntegration:
    """Agent wiring via fastapi-guard (FastAPI adapter)."""

    API_KEY = "test-api-key-1234567890"
    PROJECT_ID = "test-project"

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key=self.API_KEY,
            agent_project_id=self.PROJECT_ID,
            passive_mode=True,
        )
        app.add_middleware(SecurityMiddleware, config=config)

        @app.get("/")
        def root() -> dict[str, bool]:
            return {"ok": True}

        return app

    def test_security_config_produces_agent_config(self) -> None:
        """`SecurityConfig.to_agent_config()` returns a valid `AgentConfig`."""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key=self.API_KEY,
            agent_project_id=self.PROJECT_ID,
        )

        agent_config = config.to_agent_config()

        assert agent_config is not None
        assert isinstance(agent_config, AgentConfig)
        assert agent_config.api_key == self.API_KEY
        assert agent_config.project_id == self.PROJECT_ID

    def test_app_with_agent_enabled_serves_requests(self) -> None:
        """Middleware attaches cleanly and requests flow through."""
        app = self._build_app()
        client = TestClient(app)

        response = client.get("/")

        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_agent_disabled_does_not_produce_config(self) -> None:
        """With `enable_agent=False`, `to_agent_config()` returns `None`."""
        config = SecurityConfig(enable_agent=False)
        assert config.to_agent_config() is None
