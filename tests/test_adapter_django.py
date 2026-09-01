from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest, JsonResponse
from django.test import Client
from django.urls import path
from guard_core.models import SecurityConfig

from guard_agent.models import AgentConfig

API_KEY = "test-api-key-1234567890"
PROJECT_ID = "test-project"

settings.GUARD_SECURITY_CONFIG = SecurityConfig(
    enable_agent=True,
    agent_api_key=API_KEY,
    agent_project_id=PROJECT_ID,
    passive_mode=True,
)


def _view(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"ok": True})


urlpatterns = [path("", _view)]


class TestDjangoAdapterIntegration:
    """Agent wiring via djapi-guard (Django adapter)."""

    def test_security_config_produces_agent_config(self) -> None:
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key=API_KEY,
            agent_project_id=PROJECT_ID,
        )

        agent_config = config.to_agent_config()

        assert agent_config is not None
        assert isinstance(agent_config, AgentConfig)
        assert agent_config.api_key == API_KEY
        assert agent_config.project_id == PROJECT_ID

    def test_app_with_agent_enabled_serves_requests(self) -> None:
        client = Client()

        response = client.get("/")

        assert response.status_code == 200
        assert response.json() == {"ok": True}
