"""Integration smoke tests for the Flask adapter (flaskapi-guard).

Verifies guard-agent integrates correctly with ``flaskapi-guard`` when
``SecurityConfig.enable_agent=True``. Scope matches ``test_adapter_fastapi``:
config roundtrip + request roundtrip, not agent wire behavior.

In sync contexts (Flask, Django) guard_core invokes async agent methods
without an event loop, producing RuntimeWarnings that are harmless for these
smoke tests — the agent effectively no-ops. Filter them here so test output
stays focused on real failures; true agent wire behavior is covered in the
unit tests for ``guard_agent/client.py``.
"""

import warnings

import pytest
from flask import Flask
from flaskapi_guard import FlaskAPIGuard
from guard_core.models import SecurityConfig

from guard_agent.models import AgentConfig

pytestmark = pytest.mark.filterwarnings(
    "ignore:coroutine .* was never awaited:RuntimeWarning"
)


def setup_module(_module: object) -> None:
    warnings.filterwarnings(
        "ignore",
        message="coroutine .* was never awaited",
        category=RuntimeWarning,
    )


class TestFlaskAdapterIntegration:
    """Agent wiring via flaskapi-guard (Flask adapter)."""

    API_KEY = "test-api-key-1234567890"
    PROJECT_ID = "test-project"

    def _build_app(self) -> Flask:
        app = Flask(__name__)
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key=self.API_KEY,
            agent_project_id=self.PROJECT_ID,
            passive_mode=True,
        )
        FlaskAPIGuard(app, config=config)

        @app.route("/")
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
        """Extension attaches cleanly and requests flow through."""
        app = self._build_app()
        client = app.test_client()

        response = client.get("/")

        assert response.status_code == 200
        assert response.get_json() == {"ok": True}

    def test_deferred_init_app_pattern(self) -> None:
        """Flask app-factory pattern (`guard.init_app(app)`) works too."""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key=self.API_KEY,
            agent_project_id=self.PROJECT_ID,
            passive_mode=True,
        )
        guard = FlaskAPIGuard()
        app = Flask(__name__)
        guard.init_app(app, config=config)

        @app.route("/")
        def root() -> dict[str, bool]:
            return {"ok": True}

        response = app.test_client().get("/")
        assert response.status_code == 200
