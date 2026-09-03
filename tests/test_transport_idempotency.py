from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guard_agent.models import AgentConfig, AgentStatus, SecurityEvent, SecurityMetric
from guard_agent.transport import HTTPTransport


@pytest.fixture
def config_with_retry() -> AgentConfig:
    return AgentConfig(
        api_key="test-key",
        endpoint="http://example.com",
        project_id="proj",
        retry_attempts=2,
        backoff_factor=0.0,
        timeout=5,
    )


@pytest.mark.asyncio
async def test_retry_reuses_same_batch_id_for_events(
    config_with_retry: AgentConfig,
) -> None:
    transport = HTTPTransport(config_with_retry)

    sent_ids: list[object] = []
    call_count = 0

    async def fake_make_request(
        method: str,
        endpoint: str,
        data: dict[str, object],
    ) -> bool:
        nonlocal call_count
        call_count += 1
        sent_ids.append(data.get("batch_id"))
        if call_count < 3:
            raise TimeoutError("transient")
        return True

    with patch.object(transport, "_make_request", side_effect=fake_make_request):
        with patch("guard_agent._transport_send.asyncio.sleep", new_callable=AsyncMock):
            result = await transport.send_events(
                [
                    SecurityEvent(
                        timestamp=datetime.now(timezone.utc),
                        event_type="ip_banned",
                        ip_address="1.2.3.4",
                        action_taken="banned",
                        reason="test",
                    )
                ]
            )

    assert result is True
    assert len(sent_ids) == 3
    assert len(set(sent_ids)) == 1, (
        f"batch_id must be stable across retries; saw {sent_ids}"
    )
    assert sent_ids[0] is not None


@pytest.mark.asyncio
async def test_retry_reuses_same_batch_id_for_metrics(
    config_with_retry: AgentConfig,
) -> None:
    transport = HTTPTransport(config_with_retry)

    sent_ids: list[object] = []
    call_count = 0

    async def fake_make_request(
        method: str,
        endpoint: str,
        data: dict[str, object],
    ) -> bool:
        nonlocal call_count
        call_count += 1
        sent_ids.append(data.get("batch_id"))
        if call_count < 3:
            raise TimeoutError("transient")
        return True

    with patch.object(transport, "_make_request", side_effect=fake_make_request):
        with patch("guard_agent._transport_send.asyncio.sleep", new_callable=AsyncMock):
            result = await transport.send_metrics(
                [
                    SecurityMetric(
                        timestamp=datetime.now(timezone.utc),
                        metric_type="request_count",
                        value=10.0,
                    )
                ]
            )

    assert result is True
    assert len(sent_ids) == 3
    assert len(set(sent_ids)) == 1, (
        f"batch_id must be stable across retries; saw {sent_ids}"
    )
    assert sent_ids[0] is not None


@pytest.mark.asyncio
async def test_initialize_without_project_id() -> None:
    config = AgentConfig(
        api_key="test-key",
        endpoint="http://example.com",
        retry_attempts=0,
        timeout=5,
    )
    assert config.project_id is None

    transport = HTTPTransport(config)
    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.is_closed = False
        mock_client_cls.return_value = mock_instance
        await transport.initialize()

    call_kwargs = mock_client_cls.call_args[1]
    headers = call_kwargs["headers"]
    assert "X-Project-ID" not in headers


@pytest.mark.asyncio
async def test_close_when_client_is_none() -> None:
    config = AgentConfig(
        api_key="test-key",
        endpoint="http://example.com",
        retry_attempts=0,
        timeout=5,
    )
    transport = HTTPTransport(config)
    assert transport._client is None
    await transport.close()


@pytest.mark.asyncio
async def test_send_status_exception_returns_false(
    config_with_retry: AgentConfig,
) -> None:
    transport = HTTPTransport(config_with_retry)

    status = AgentStatus(
        timestamp=datetime.now(timezone.utc),
        status="healthy",
        uptime=1.0,
        events_sent=0,
        events_failed=0,
        buffer_size=0,
    )

    with patch.object(
        transport,
        "_send_with_retry",
        side_effect=RuntimeError("boom"),
    ):
        result = await transport.send_status(status)

    assert result is False
