import base64
import logging
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from guard_agent.exceptions import PermanentClientError
from guard_agent.models import AgentConfig, SecurityEvent
from guard_agent.transport import HTTPTransport
from guard_agent.utils import SerializationError


def _config(**kwargs: Any) -> AgentConfig:
    return AgentConfig(
        api_key="x", endpoint="https://example.com", retry_attempts=0, **kwargs
    )


def _event() -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        event_type="ip_banned",
        ip_address="1.1.1.1",
        action_taken="banned",
        reason="t",
    )


def test_on_error_defaults_none() -> None:
    assert AgentConfig(api_key="x", endpoint="https://example.com").on_error is None


def test_on_error_accepts_callable() -> None:
    def hook(stage: str, exc: BaseException, ctx: dict[str, Any]) -> None:
        pass

    assert _config(on_error=hook).on_error is hook


def test_fire_error_hook_none_is_noop() -> None:
    transport = HTTPTransport(_config())
    transport._fire_error_hook("transport_send", ValueError("x"), {})


def test_fire_error_hook_forwards_stage_exc_context() -> None:
    calls: list[tuple[str, BaseException, dict[str, Any]]] = []
    transport = HTTPTransport(_config(on_error=lambda s, e, c: calls.append((s, e, c))))
    err = ValueError("boom")
    transport._fire_error_hook("encryption", err, {"k": "v"})
    assert calls == [("encryption", err, {"k": "v"})]


def test_fire_error_hook_swallows_raising_hook(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def bad_hook(stage: str, exc: BaseException, ctx: dict[str, Any]) -> None:
        raise RuntimeError("hook fail")

    transport = HTTPTransport(_config(on_error=bad_hook))
    with caplog.at_level(logging.ERROR):
        transport._fire_error_hook("geoip", ValueError("x"), {})
    assert any("on_error hook raised" in r.message for r in caplog.records)


async def test_hook_fires_on_send_exhaustion() -> None:
    captured: list[tuple[str, BaseException, dict[str, Any]]] = []
    transport = HTTPTransport(
        _config(on_error=lambda s, e, c: captured.append((s, e, c)))
    )
    with patch.object(
        transport, "_make_request", side_effect=httpx.HTTPError("net down")
    ):
        assert await transport.send_events([_event()]) is False
    assert captured[0][0] == "transport_send"


async def test_hook_fires_on_permanent_client_error() -> None:
    captured: list[tuple[str, BaseException, dict[str, Any]]] = []
    transport = HTTPTransport(
        _config(on_error=lambda s, e, c: captured.append((s, e, c)))
    )
    transport._client = AsyncMock()
    with patch.object(
        transport, "_make_request", side_effect=PermanentClientError(400, "bad")
    ):
        assert await transport.send_events([_event()]) is True
    assert captured[0][0] == "transport_send"
    assert isinstance(captured[0][1], PermanentClientError)


async def test_hook_fires_on_unencrypted_serialization_abort() -> None:
    captured: list[tuple[str, BaseException, dict[str, Any]]] = []
    transport = HTTPTransport(
        _config(on_error=lambda s, e, c: captured.append((s, e, c)))
    )
    transport._client = AsyncMock()
    with patch(
        "guard_agent._transport_dispatch.safe_json_serialize",
        side_effect=SerializationError("bad"),
    ):
        result = await transport._post_unencrypted("https://example.com/x", {"a": 1})
    assert result is False
    assert captured[0][0] == "transport_send"


async def test_hook_fires_on_encrypted_serialization_abort() -> None:
    captured: list[tuple[str, BaseException, dict[str, Any]]] = []
    valid_key = base64.urlsafe_b64encode(b"a" * 32).decode()
    transport = HTTPTransport(
        _config(
            project_encryption_key=valid_key,
            on_error=lambda s, e, c: captured.append((s, e, c)),
        )
    )
    transport._client = AsyncMock()
    with patch(
        "guard_agent._transport_dispatch.safe_json_serialize",
        side_effect=SerializationError("bad"),
    ):
        result = await transport._post_encrypted({"batch_id": "b", "a": 1})
    assert result is False
    assert captured[0][0] == "encryption"


def test_permanent_client_error_without_detail() -> None:
    err = PermanentClientError(404)
    assert err.status_code == 404
    assert str(err) == "Permanent client error 404"


def test_endpoint_strips_legacy_api_v1_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import guard_agent.models as models

    monkeypatch.setattr(models, "_endpoint_suffix_warned", False)
    config = AgentConfig(api_key="x", endpoint="https://example.com/api/v1")
    assert config.endpoint == "https://example.com"


def test_endpoint_strip_does_not_rewarn_when_already_warned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import guard_agent.models as models

    monkeypatch.setattr(models, "_endpoint_suffix_warned", True)
    config = AgentConfig(api_key="x", endpoint="https://example.com/api/v1")
    assert config.endpoint == "https://example.com"


async def test_send_with_retry_partial_failure_returns_false() -> None:
    transport = HTTPTransport(_config())
    with patch.object(transport, "_make_request", return_value={"success": False}):
        assert await transport.send_events([_event()]) is False


async def test_handle_response_200_partial_failure_returns_payload() -> None:
    transport = HTTPTransport(_config())
    response = MagicMock()
    response.status_code = 200
    response.url = "https://example.com/api/v1/events"
    response.json = MagicMock(return_value={"success": False})
    result = await transport._handle_response(response)
    assert result == {"success": False}
