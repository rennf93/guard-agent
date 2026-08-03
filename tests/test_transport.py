import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from guard_agent.models import AgentConfig, AgentStatus, SecurityEvent, SecurityMetric
from guard_agent.transport import HTTPTransport


class TestHTTPTransport:
    """Tests for HTTPTransport class."""

    @pytest.mark.asyncio
    async def test_initialization(self, agent_config: AgentConfig) -> None:
        """Test transport initialization."""
        transport = HTTPTransport(agent_config)

        with patch("httpx.AsyncClient") as mock_client:
            await transport.initialize()

            # Verify client was created
            mock_client.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialization_failure(self, agent_config: AgentConfig) -> None:
        """Test transport initialization failure."""
        transport = HTTPTransport(agent_config)

        with patch("httpx.AsyncClient", side_effect=Exception("Test Init Error")):
            with pytest.raises(Exception, match="Test Init Error"):
                await transport.initialize()

    @pytest.mark.asyncio
    async def test_send_events_success(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test successful event sending."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]

        result = await transport.send_events(events)

        assert result is True
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_events_includes_guard_version_in_payload(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        agent_config.guard_version = "6.0.0"
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]

        await transport.send_events(events)

        body = mock_client.post.call_args.kwargs["content"]
        payload = json.loads(body)
        assert payload["guard_version"] == "6.0.0"
        assert payload["agent_version"]

    @pytest.mark.asyncio
    async def test_send_metrics_includes_guard_version_in_payload(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        agent_config.guard_version = "6.0.0"
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        metrics = [
            SecurityMetric(
                timestamp=datetime.now(timezone.utc),
                metric_type="request_count",
                value=1.0,
            )
        ]

        await transport.send_metrics(metrics)

        body = mock_client.post.call_args.kwargs["content"]
        payload = json.loads(body)
        assert payload["guard_version"] == "6.0.0"

    @pytest.mark.asyncio
    async def test_send_events_failure(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test event sending failure handling."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # Configure mock for failure response
        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_client.post.return_value = mock_response

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]

        result = await transport.send_events(events)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_events_exception_during_send(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test send_events when an exception occurs during the send process."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        with patch.object(
            transport,
            "_send_with_retry",
            side_effect=Exception("Test Send Events Exception"),
        ):
            events = [
                SecurityEvent(
                    timestamp=datetime.now(timezone.utc),
                    event_type="ip_banned",
                    ip_address="192.168.1.1",
                    action_taken="banned",
                    reason="test",
                )
            ]

            result = await transport.send_events(events)
            assert result is False
            assert transport.requests_failed == 1

    @pytest.mark.asyncio
    async def test_send_metrics_exception_during_send(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test send_metrics when an exception occurs during the send process."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        with patch.object(
            transport,
            "_send_with_retry",
            side_effect=Exception("Test Send Metrics Exception"),
        ):
            metrics = [
                SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type="request_count",
                    value=1.0,
                )
            ]

            result = await transport.send_metrics(metrics)
            assert result is False
            assert transport.requests_failed == 1

    @pytest.mark.asyncio
    async def test_rate_limiting(self, agent_config: AgentConfig) -> None:
        """Test rate limiting functionality."""
        transport = HTTPTransport(agent_config)

        # Verify rate limiter is working
        assert transport.rate_limiter.max_calls == 100
        assert transport.rate_limiter.time_window == 60.0

    @pytest.mark.asyncio
    async def test_circuit_breaker(self, agent_config: AgentConfig) -> None:
        """Test circuit breaker functionality."""
        transport = HTTPTransport(agent_config)

        # Verify circuit breaker is configured
        assert transport.circuit_breaker.failure_threshold == 5
        assert transport.circuit_breaker.recovery_timeout == 60.0

    @pytest.mark.asyncio
    async def test_retry_logic(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test retry logic for failed requests."""
        agent_config.retry_attempts = 2
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # Configure mock for retry logic - first call fails, second succeeds
        call_count = 0

        def create_mock_response(*args: Any, **kwargs: Any) -> AsyncMock:
            nonlocal call_count
            call_count += 1

            mock_response = AsyncMock()
            if call_count == 1:
                # First call fails
                mock_response.status_code = 500
                mock_response.text = "Server Error"
            else:
                # Second call succeeds
                mock_response.status_code = 200
                mock_response.json = MagicMock(return_value={"status": "ok"})
            return mock_response

        mock_client.post.side_effect = create_mock_response

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]

        with patch("asyncio.sleep"):  # Skip actual sleep delays
            result = await transport.send_events(events)

        assert result is True
        assert call_count == 2  # One retry

    @pytest.mark.asyncio
    async def test_send_with_retry_all_attempts_fail(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _send_with_retry when all retry attempts fail."""
        agent_config.retry_attempts = 2
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        mock_client.post.side_effect = httpx.HTTPError("Simulated Network Error")

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]

        with patch("asyncio.sleep"):
            result = await transport.send_events(events)

        assert result is False
        assert transport.requests_failed == 1
        assert mock_client.post.call_count == 3  # Initial + 2 retries

    @pytest.mark.asyncio
    async def test_send_with_retry_make_request_returns_false(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """
        Test _send_with_retry when _make_request returns False (e.g., client error).
        """
        agent_config.retry_attempts = 0  # No retries
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        with patch.object(
            transport, "_make_request", return_value=False
        ) as mock_make_request:
            events = [
                SecurityEvent(
                    timestamp=datetime.now(timezone.utc),
                    event_type="ip_banned",
                    ip_address="192.168.1.1",
                    action_taken="banned",
                    reason="test",
                )
            ]
            result = await transport.send_events(events)

            assert result is False
            assert transport.requests_failed == 1
            mock_make_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_with_retry_make_request_returns_none(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _get_with_retry when _make_request returns None (e.g., no rules)."""
        agent_config.retry_attempts = 0  # No retries
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        with patch.object(
            transport, "_make_request", return_value=None
        ) as mock_make_request:
            rules = await transport.fetch_dynamic_rules()

            assert rules is None
            assert transport.requests_failed == 1
            mock_make_request.assert_called_once()

    @pytest.mark.asyncio
    async def test_make_request_session_init_fails(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _make_request when session initialization fails."""
        transport = HTTPTransport(agent_config)
        transport._client = None

        with patch.object(
            transport, "initialize", side_effect=Exception("Init Failed")
        ):
            with pytest.raises(Exception, match="Init Failed"):
                await transport._make_request("POST", "/test", {"key": "value"})

    @pytest.mark.asyncio
    async def test_fetch_dynamic_rules(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test fetching dynamic rules."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # Configure mock for dynamic rules response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(
            return_value={
                "rule_id": "test-rule-123",
                "version": 1,
                "timestamp": "2025-01-08T10:00:00Z",
                "ip_blacklist": ["192.168.1.1"],
                "ttl": 300,
            }
        )
        mock_client.get.return_value = mock_response

        rules = await transport.fetch_dynamic_rules()

        assert rules is not None
        assert rules.rule_id == "test-rule-123"
        assert rules.version == 1
        assert "192.168.1.1" in rules.ip_blacklist

    @pytest.mark.asyncio
    async def test_fetch_dynamic_rules_failure(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test fetching dynamic rules failure."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client
        mock_client.get.side_effect = Exception("Test Fetch Rules Exception")

        rules = await transport.fetch_dynamic_rules()
        assert rules is None

    @pytest.mark.asyncio
    async def test_send_status(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test sending agent status."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # Configure mock for status response
        mock_response = AsyncMock()
        mock_response.status_code = 201
        mock_client.post.return_value = mock_response

        status = AgentStatus(
            timestamp=datetime.now(timezone.utc),
            status="healthy",
            uptime=3600.0,
            events_sent=100,
            events_failed=0,
            buffer_size=5,
        )

        result = await transport.send_status(status)

        assert result is True

    @pytest.mark.asyncio
    async def test_authentication_header(self, agent_config: AgentConfig) -> None:
        """Test that authentication headers are properly set."""
        transport = HTTPTransport(agent_config)

        with patch("httpx.AsyncClient") as mock_client_class:
            await transport.initialize()

            # Check that session was created with auth header
            call_args = mock_client_class.call_args
            headers = call_args[1]["headers"]

            assert "X-API-Key" in headers
            assert headers["X-API-Key"] == agent_config.api_key

    def test_get_stats(self, agent_config: AgentConfig) -> None:
        """Test getting transport statistics."""
        transport = HTTPTransport(agent_config)

        stats = transport.get_stats()

        assert isinstance(stats, dict)
        assert "requests_sent" in stats
        assert "requests_failed" in stats
        assert "bytes_sent" in stats
        assert "circuit_breaker_state" in stats

    @pytest.mark.asyncio
    async def test_close(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test transport cleanup."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        await transport.close()

        mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_initialize_already_initialized(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test that initialize does nothing if already initialized."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client  # Simulate already initialized client

        with patch("httpx.AsyncClient") as mock_client_class:
            await transport.initialize()
            mock_client_class.assert_not_called()  # Should not create a new client

    @pytest.mark.asyncio
    async def test_send_events_empty_list(self, agent_config: AgentConfig) -> None:
        """Test send_events with an empty list."""
        transport = HTTPTransport(agent_config)
        result = await transport.send_events([])
        assert result is True  # Should return True for empty list

    @pytest.mark.asyncio
    async def test_send_metrics_empty_list(self, agent_config: AgentConfig) -> None:
        """Test send_metrics with an empty list."""
        transport = HTTPTransport(agent_config)
        result = await transport.send_metrics([])
        assert result is True  # Should return True for empty list

    @pytest.mark.asyncio
    async def test_get_with_retry_rate_limited(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _get_with_retry when rate limited."""
        agent_config.retry_attempts = 1
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        with patch.object(transport.rate_limiter, "acquire", side_effect=[False, True]):
            with patch("asyncio.sleep"):
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json = MagicMock(return_value={"status": "ok"})
                mock_client.get.return_value = mock_response

                rules = await transport.fetch_dynamic_rules()
                assert rules is not None
                assert transport.requests_sent == 1

    @pytest.mark.asyncio
    async def test_make_request_client_none_after_initialize(
        self, agent_config: AgentConfig
    ) -> None:
        """
        Test _make_request when client is None initially, but initialized successfully.
        """
        transport = HTTPTransport(agent_config)
        transport._client = None  # Ensure client is None

        with patch.object(
            transport, "initialize", wraps=transport.initialize
        ) as mock_initialize:
            with patch("httpx.AsyncClient.post") as mock_post:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json = MagicMock(return_value={"status": "ok"})
                mock_post.return_value = mock_response

                result = await transport._make_request(
                    "POST", "/test", {"key": "value"}
                )
                assert result == {"status": "ok"}
                mock_initialize.assert_called_once()
                mock_post.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_with_retry_rate_limited(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _send_with_retry when rate limited."""
        agent_config.retry_attempts = 1
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        with patch.object(transport.rate_limiter, "acquire", side_effect=[False, True]):
            with patch("asyncio.sleep"):
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json = MagicMock(return_value={"status": "ok"})
                mock_client.post.return_value = mock_response

                events = [
                    SecurityEvent(
                        timestamp=datetime.now(timezone.utc),
                        event_type="ip_banned",
                        ip_address="192.168.1.1",
                        action_taken="banned",
                        reason="test",
                    )
                ]
                result = await transport.send_events(events)
                assert result is True
                assert transport.requests_sent == 1

    @pytest.mark.asyncio
    async def test_send_with_retry_circuit_breaker_open(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _send_with_retry when circuit breaker is open."""
        agent_config.retry_attempts = 0
        transport = HTTPTransport(agent_config)
        transport._client = mock_client
        transport.circuit_breaker.state = "OPEN"

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]
        result = await transport.send_events(events)
        assert result is False
        assert transport.requests_failed == 1

    @pytest.mark.asyncio
    async def test_make_request_client_none(self, agent_config: AgentConfig) -> None:
        """Test _make_request when client is None initially."""
        transport = HTTPTransport(agent_config)
        transport._client = None  # Ensure client is None

        with patch.object(
            transport, "initialize", wraps=transport.initialize
        ) as mock_initialize:
            with patch("httpx.AsyncClient.post") as mock_post:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json = MagicMock(return_value={"status": "ok"})
                mock_post.return_value = mock_response

                result = await transport._make_request(
                    "POST", "/test", {"key": "value"}
                )
                assert result == {"status": "ok"}
                mock_initialize.assert_called_once()
                mock_post.assert_called_once()

    @pytest.mark.asyncio
    async def test_make_request_client_error(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _make_request with httpx.HTTPError."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client
        mock_client.post.side_effect = httpx.HTTPError("Test Client Error")

        with pytest.raises(httpx.HTTPError):
            await transport._make_request("POST", "/test", {"key": "value"})

    @pytest.mark.asyncio
    async def test_make_request_timeout_error(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _make_request with asyncio.TimeoutError."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client
        mock_client.post.side_effect = asyncio.TimeoutError("Test Timeout Error")

        with pytest.raises(asyncio.TimeoutError):
            await transport._make_request("POST", "/test", {"key": "value"})

    @pytest.mark.asyncio
    async def test_make_request_generic_exception(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _make_request with a generic Exception."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client
        mock_client.post.side_effect = Exception("Generic Error")

        with pytest.raises(Exception, match="Generic Error"):
            await transport._make_request("POST", "/test", {"key": "value"})

    @pytest.mark.asyncio
    async def test_make_request_unsupported_method(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _make_request with an unsupported HTTP method."""
        transport = HTTPTransport(agent_config)
        with pytest.raises(ValueError, match="Unsupported method: PUT"):
            await transport._make_request("PUT", "/test", {"key": "value"})

    @pytest.mark.asyncio
    async def test_handle_response_200_non_json(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response with 200 status and non-JSON content."""
        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(side_effect=Exception("Not JSON"))
        mock_response.url = "http://test.com"

        result = await transport._handle_response(mock_response)
        assert result is False

    @pytest.mark.asyncio
    async def test_handle_response_200_non_dict_json(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response with 200 status and valid JSON that's not a dict."""
        transport = HTTPTransport(agent_config)

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.url = "http://test.com"

        # Test with JSON array
        mock_response.json = MagicMock(return_value=["item1", "item2", "item3"])
        result = await transport._handle_response(mock_response)
        assert result is True

        # Test with JSON string
        mock_response.json = MagicMock(return_value="just a string")
        result = await transport._handle_response(mock_response)
        assert result is True

        # Test with JSON number
        mock_response.json = MagicMock(return_value=123)
        result = await transport._handle_response(mock_response)
        assert result is True

        # Test with JSON boolean
        mock_response.json = MagicMock(return_value=True)
        result = await transport._handle_response(mock_response)
        assert result is True

        # Test with JSON null
        mock_response.json = MagicMock(return_value=None)
        result = await transport._handle_response(mock_response)
        assert result is True

    @pytest.mark.asyncio
    async def test_handle_response_429_rate_limited(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response with 429 status (Rate Limited)."""
        from guard_agent.utils import RateLimitedError

        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "120"}
        mock_response.url = "http://test.com"

        with pytest.raises(RateLimitedError) as exc_info:
            await transport._handle_response(mock_response)
        assert exc_info.value.retry_after_seconds == 120.0

    @pytest.mark.asyncio
    async def test_handle_response_401_unauthorized(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response with 401 status (Unauthorized)."""
        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 401
        mock_response.url = "http://test.com"

        with pytest.raises(Exception, match="Authentication failed: 401"):
            await transport._handle_response(mock_response)

    @pytest.mark.asyncio
    async def test_handle_response_403_forbidden(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response with 403 status (Forbidden)."""
        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 403
        mock_response.url = "http://test.com"

        with pytest.raises(Exception, match="Authentication failed: 403"):
            await transport._handle_response(mock_response)

    @pytest.mark.asyncio
    async def test_handle_response_500_server_error(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response with 500 status (Server Error)."""
        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.url = "http://test.com"

        with pytest.raises(
            Exception,
            match="Server error 500 for http://test.com: Internal Server Error",
        ):
            await transport._handle_response(mock_response)

    @pytest.mark.asyncio
    async def test_handle_response_other_client_error(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response with a non-listed client error (e.g., 451)."""
        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 451
        mock_response.text = "Unavailable For Legal Reasons"
        mock_response.url = "http://test.com"

        result = await transport._handle_response(mock_response)
        assert result is False

    @pytest.mark.asyncio
    async def test_handle_response_non_retryable_client_error(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _handle_response raises PermanentClientError on a 4xx like 404."""
        from guard_agent.exceptions import PermanentClientError

        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_response.url = "http://test.com"

        with pytest.raises(PermanentClientError) as exc_info:
            await transport._handle_response(mock_response)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_handle_response_413_raises_payload_too_large_error(
        self, agent_config: AgentConfig
    ) -> None:
        from guard_agent.exceptions import PayloadTooLargeError

        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 413
        mock_response.text = "Request Entity Too Large"
        mock_response.url = "http://test.com"

        with pytest.raises(PayloadTooLargeError) as exc_info:
            await transport._handle_response(mock_response)
        assert exc_info.value.status_code == 413
        from guard_agent.exceptions import PermanentClientError as _PCE

        assert isinstance(exc_info.value, _PCE)

    @pytest.mark.asyncio
    async def test_close_client_closed(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test close method closes the client."""
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        await transport.close()

        mock_client.aclose.assert_called_once()

    def test_get_stats_session_closed(self, agent_config: AgentConfig) -> None:
        """Test get_stats when session is closed."""
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()
        transport._client.is_closed = True

        stats = transport.get_stats()
        assert stats["session_closed"] is True

    def test_get_stats_session_none(self, agent_config: AgentConfig) -> None:
        """Test get_stats when session is None."""
        transport = HTTPTransport(agent_config)
        transport._client = None

        stats = transport.get_stats()
        assert stats["session_closed"] is True

    @pytest.mark.asyncio
    async def test_get_with_retry_rate_limited_fetch_rules(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test _get_with_retry rate limiting in fetch_dynamic_rules path."""
        agent_config.retry_attempts = 1
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # Mock rate limiter to be rate limited on first call, then succeed
        with patch.object(
            transport.rate_limiter, "acquire", side_effect=[False, True]
        ) as mock_acquire:
            with patch.object(
                transport.rate_limiter, "get_retry_after", return_value=0.1
            ) as mock_get_retry_after:
                with patch("asyncio.sleep") as mock_sleep:
                    mock_response = AsyncMock()
                    mock_response.status_code = 200
                    mock_response.json = MagicMock(
                        return_value={
                            "rule_id": "test-rule",
                            "version": 1,
                            "timestamp": "2025-01-08T10:00:00Z",
                            "ip_blacklist": [],
                            "ttl": 300,
                        }
                    )
                    mock_client.get.return_value = mock_response

                    rules = await transport.fetch_dynamic_rules()

                    # Verify the rate limiting code was executed
                    assert (
                        mock_acquire.call_count == 2
                    )  # Called twice due to rate limiting
                    mock_get_retry_after.assert_called_once()  # Should get retry delay
                    mock_sleep.assert_called_once_with(
                        0.1
                    )  # Should sleep for retry delay

                    # Verify the request eventually succeeded
                    assert rules is not None
                    assert rules.rule_id == "test-rule"

    @pytest.mark.asyncio
    async def test_make_request_client_remains_none_after_initialize(
        self, agent_config: AgentConfig
    ) -> None:
        """Test _make_request when client remains None even after initialize."""
        transport = HTTPTransport(agent_config)
        transport._client = None

        # Mock initialize to succeed but leave session as None
        async def mock_initialize() -> None:
            # Simulate initialize succeeding but client somehow ending up None
            pass

        with patch.object(transport, "initialize", side_effect=mock_initialize):
            with pytest.raises(Exception, match="Failed to initialize HTTP client"):
                await transport._make_request("POST", "/test", {"key": "value"})

    @pytest.mark.asyncio
    async def test_fetch_dynamic_rules_invalid_response_data(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """
        Test fetch_dynamic_rules, response data is invalid, causes parsing to fail.
        """
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # return invalid data that will cause DynamicRules(**response_data) to fail
        # Using invalid data types that will cause Pydantic validation errors
        invalid_response_data = {
            "version": "not_an_integer",  # version expects int
            "timestamp": "invalid_datetime_format",  # timestamp expects datetime
            "ttl": "not_an_integer",  # ttl expects int
        }

        with patch.object(
            transport, "_get_with_retry", return_value=invalid_response_data
        ):
            rules = await transport.fetch_dynamic_rules()

            # Should return None due to exception in DynamicRules parsing
            assert rules is None

    @pytest.mark.asyncio
    async def test_transport_interface_compatibility(
        self, mock_transport: AsyncMock
    ) -> None:
        """
        Test that mock_transport fixture provides the expected transport interface.
        """
        # Verify all expected methods are available
        assert hasattr(mock_transport, "initialize")
        assert hasattr(mock_transport, "close")
        assert hasattr(mock_transport, "send_events")
        assert hasattr(mock_transport, "send_metrics")
        assert hasattr(mock_transport, "fetch_dynamic_rules")
        assert hasattr(mock_transport, "send_status")

        # Verify methods can be called and return expected defaults
        await mock_transport.initialize()
        await mock_transport.close()

        events_result = await mock_transport.send_events([])
        assert events_result is True

        metrics_result = await mock_transport.send_metrics([])
        assert metrics_result is True

        rules_result = await mock_transport.fetch_dynamic_rules()
        assert rules_result is None

        status_result = await mock_transport.send_status(None)
        assert status_result is True

        # Verify methods were called
        mock_transport.initialize.assert_called_once()
        mock_transport.close.assert_called_once()
        mock_transport.send_events.assert_called_once()
        mock_transport.send_metrics.assert_called_once()
        mock_transport.fetch_dynamic_rules.assert_called_once()
        mock_transport.send_status.assert_called_once()


class TestHTTPTransportEncryption:
    """Tests for HTTPTransport encryption functionality."""

    @pytest.mark.asyncio
    async def test_init_encryption_with_valid_key(self) -> None:
        """Test encryption initialization with valid key."""
        import base64

        valid_key = base64.urlsafe_b64encode(b"0" * 32).decode()
        config = AgentConfig(
            api_key="test_key",
            endpoint="http://test.com",
            project_id="test_project",
            project_encryption_key=valid_key,
        )

        transport = HTTPTransport(config)

        assert transport._encryption_enabled is True
        assert transport._encryptor is not None

    @pytest.mark.asyncio
    async def test_init_encryption_with_invalid_key(self) -> None:
        from guard_agent.encryption import EncryptionConfigError

        config = AgentConfig(
            api_key="test_key",
            endpoint="http://test.com",
            project_id="test_project",
            project_encryption_key="invalid_key",
        )

        with pytest.raises(EncryptionConfigError):
            HTTPTransport(config)

    @pytest.mark.asyncio
    async def test_init_encryption_with_verify_key_failure(self) -> None:
        import base64
        from unittest.mock import patch

        from guard_agent.encryption import EncryptionConfigError

        valid_key = base64.urlsafe_b64encode(b"0" * 32).decode()
        config = AgentConfig(
            api_key="test_key",
            endpoint="http://test.com",
            project_id="test_project",
            project_encryption_key=valid_key,
        )

        with patch(
            "guard_agent.encryption.PayloadEncryptor.verify_key", return_value=False
        ):
            with pytest.raises(EncryptionConfigError):
                HTTPTransport(config)

    @pytest.mark.asyncio
    async def test_init_encryption_with_encryptor_creation_error(self) -> None:
        from unittest.mock import patch

        from guard_agent.encryption import EncryptionConfigError, EncryptionError

        config = AgentConfig(
            api_key="test_key",
            endpoint="http://test.com",
            project_id="test_project",
            project_encryption_key="some_key",
        )

        with patch(
            "guard_agent.transport.create_encryptor",
            side_effect=EncryptionError("Test error"),
        ):
            with pytest.raises(EncryptionConfigError):
                HTTPTransport(config)

    @pytest.mark.asyncio
    async def test_make_request_encrypted_events_endpoint(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test encrypted request for events endpoint."""
        import base64

        valid_key = base64.urlsafe_b64encode(b"0" * 32).decode()
        agent_config.project_encryption_key = valid_key

        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # Configure successful response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value={"status": "ok"})
        mock_client.post.return_value = mock_response

        data = {
            "events": [{"event_type": "test"}],
            "metrics": [],
            "batch_id": "test_123",
        }

        result = await transport._make_request("POST", "/api/v1/events", data)

        assert result == {"status": "ok"}
        # Verify POST was called to encrypted endpoint
        assert mock_client.post.call_count == 1
        call_args = mock_client.post.call_args
        assert "/api/v1/events/encrypted" in str(call_args[0][0])

    @pytest.mark.asyncio
    async def test_make_request_encrypted_metrics_endpoint(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test encrypted request for metrics endpoint."""
        import base64

        valid_key = base64.urlsafe_b64encode(b"0" * 32).decode()
        agent_config.project_encryption_key = valid_key

        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        # Configure successful response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value={"status": "ok"})
        mock_client.post.return_value = mock_response

        data = {
            "events": [],
            "metrics": [{"metric_type": "test"}],
            "batch_id": "test_123",
        }

        result = await transport._make_request("POST", "/api/v1/metrics", data)

        assert result == {"status": "ok"}
        # Verify POST was called to encrypted endpoint
        assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_make_request_encrypted_without_encryptor(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test encrypted endpoint when encryptor not initialized."""
        import base64

        from guard_agent.encryption import EncryptionError

        valid_key = base64.urlsafe_b64encode(b"0" * 32).decode()
        agent_config.project_encryption_key = valid_key

        transport = HTTPTransport(agent_config)
        transport._client = mock_client
        transport._encryption_enabled = True
        transport._encryptor = None  # Force encryptor to None

        data = {"events": [], "metrics": [], "batch_id": "test"}

        with pytest.raises(EncryptionError, match="Encryptor not initialized"):
            await transport._make_request("POST", "/api/v1/events", data)

    @pytest.mark.asyncio
    async def test_make_request_encryption_error_handling(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        """Test EncryptionError handling during encryption."""
        import base64
        from unittest.mock import patch

        from guard_agent.encryption import EncryptionError

        valid_key = base64.urlsafe_b64encode(b"0" * 32).decode()
        agent_config.project_encryption_key = valid_key

        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        data = {"events": [], "metrics": [], "batch_id": "test"}

        # Mock encryptor to raise error
        with patch.object(
            transport._encryptor, "encrypt", side_effect=EncryptionError("Test error")
        ):
            with pytest.raises(EncryptionError):
                await transport._make_request("POST", "/api/v1/events", data)

    @pytest.mark.asyncio
    async def test_send_events_with_encryption(self, mock_client: AsyncMock) -> None:
        """Test end-to-end event sending with encryption enabled."""
        import base64

        valid_key = base64.urlsafe_b64encode(b"0" * 32).decode()
        config = AgentConfig(
            api_key="test_key",
            endpoint="http://test.com",
            project_id="test_project",
            project_encryption_key=valid_key,
        )

        transport = HTTPTransport(config)
        transport._client = mock_client

        # Configure successful response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(return_value={"status": "ok"})
        mock_client.post.return_value = mock_response

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]

        result = await transport.send_events(events)

        assert result is True
        assert transport._encryption_enabled is True
        # Verify encrypted endpoint was used
        assert mock_client.post.call_count >= 1


class TestHTTPTransportForkSafety:
    """Tests for fork-aware transport state reset."""

    def test_register_fork_hook_called_on_init(self, agent_config: AgentConfig) -> None:
        with patch("guard_agent.transport.os.register_at_fork") as mock_register:
            HTTPTransport(agent_config)
            mock_register.assert_called_once()
            assert "after_in_child" in mock_register.call_args.kwargs

    def test_reset_after_fork_clears_client_and_resets_state(
        self, agent_config: AgentConfig
    ) -> None:
        transport = HTTPTransport(agent_config)
        transport._client = cast(Any, MagicMock())
        transport.requests_sent = 42
        transport.requests_failed = 7
        transport.bytes_sent = 9000
        transport.circuit_breaker.failure_count = 3
        transport.circuit_breaker.state = "OPEN"

        transport._reset_after_fork()

        assert transport._client is None
        assert transport._pid == os.getpid()
        assert transport.requests_sent == 0
        assert transport.requests_failed == 0
        assert transport.bytes_sent == 0
        assert transport.circuit_breaker.failure_count == 0
        assert transport.circuit_breaker.state == "CLOSED"

    @pytest.mark.asyncio
    async def test_ensure_client_for_current_process_reinitializes_on_pid_drift(
        self, agent_config: AgentConfig
    ) -> None:
        transport = HTTPTransport(agent_config)
        transport._client = MagicMock()
        transport._client.is_closed = False
        transport._pid = transport._pid - 1

        with patch.object(transport, "initialize", new_callable=AsyncMock) as mock_init:
            await transport._ensure_client_for_current_process()
            mock_init.assert_called_once()
            assert transport._pid == os.getpid()

    @pytest.mark.asyncio
    async def test_ensure_client_no_op_when_pid_matches_and_client_open(
        self, agent_config: AgentConfig
    ) -> None:
        transport = HTTPTransport(agent_config)
        existing = MagicMock()
        existing.is_closed = False
        transport._client = existing

        with patch.object(transport, "initialize", new_callable=AsyncMock) as mock_init:
            await transport._ensure_client_for_current_process()
            mock_init.assert_not_called()
            assert transport._client is existing


class TestHTTPTransportRetryAfter:
    """Tests for honoring server-supplied Retry-After on 429."""

    @pytest.mark.asyncio
    async def test_handle_response_429_raises_rate_limited_error_with_seconds(
        self, agent_config: AgentConfig
    ) -> None:
        from guard_agent.utils import RateLimitedError

        transport = HTTPTransport(agent_config)
        response = MagicMock()
        response.status_code = 429
        response.headers = {"Retry-After": "12"}
        response.url = "http://test/api/v1/events"

        with pytest.raises(RateLimitedError) as exc_info:
            await transport._handle_response(response)

        assert exc_info.value.retry_after_seconds == 12.0

    @pytest.mark.asyncio
    async def test_send_with_retry_sleeps_retry_after_value_not_backoff(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "7"}
        rate_limited_response.url = "http://test/api/v1/events"

        success_response = AsyncMock()
        success_response.status_code = 200
        success_response.json = MagicMock(return_value={"ok": True})
        success_response.headers = {}
        success_response.url = "http://test/api/v1/events"

        mock_client.post.side_effect = [rate_limited_response, success_response]

        with patch("guard_agent.transport.asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            result = await transport._send_with_retry(
                "/api/v1/events", {"events": []}, "events"
            )

        assert result is True
        sleep_calls = [c.args[0] for c in mock_sleep.call_args_list if c.args]
        assert 7.0 in sleep_calls

    @pytest.mark.asyncio
    async def test_send_with_retry_caps_retry_after_to_max(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "9999"}
        rate_limited_response.url = "http://test/api/v1/events"

        success_response = AsyncMock()
        success_response.status_code = 200
        success_response.json = MagicMock(return_value={"ok": True})
        success_response.headers = {}
        success_response.url = "http://test/api/v1/events"

        mock_client.post.side_effect = [rate_limited_response, success_response]

        with patch("guard_agent.transport.asyncio.sleep") as mock_sleep:
            mock_sleep.return_value = None
            await transport._send_with_retry("/api/v1/events", {"events": []}, "events")

        sleep_calls = [c.args[0] for c in mock_sleep.call_args_list if c.args]
        assert max(sleep_calls) <= 300.0

    def test_register_fork_hook_no_op_when_register_at_fork_unavailable(
        self, agent_config: AgentConfig
    ) -> None:
        with patch("guard_agent.transport.os") as mock_os:
            mock_os.getpid.return_value = 4242
            del mock_os.register_at_fork
            HTTPTransport(agent_config)

    def test_register_fork_hook_swallows_register_failure(
        self, agent_config: AgentConfig
    ) -> None:
        with patch(
            "guard_agent.transport.os.register_at_fork",
            side_effect=RuntimeError("fork registration not allowed"),
        ):
            HTTPTransport(agent_config)

    @pytest.mark.asyncio
    async def test_send_with_retry_records_failure_after_retry_after_attempts_exhausted(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        agent_config.retry_attempts = 1
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "5"}
        rate_limited_response.url = "http://test/api/v1/events"
        mock_client.post.side_effect = [
            rate_limited_response,
            rate_limited_response,
        ]

        before = transport.requests_failed
        with patch("guard_agent.transport.asyncio.sleep", new_callable=AsyncMock):
            result = await transport._send_with_retry(
                "/api/v1/events", {"events": []}, "events"
            )

        assert result is False
        assert transport.requests_failed == before + 1

    @pytest.mark.asyncio
    async def test_get_with_retry_honors_retry_after_then_succeeds(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        agent_config.retry_attempts = 1
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "8"}
        rate_limited_response.url = "http://test/api/v1/rules"

        ok_response = AsyncMock()
        ok_response.status_code = 200
        ok_response.json = MagicMock(return_value={"rule_id": "r1", "version": 2})
        ok_response.headers = {}
        ok_response.url = "http://test/api/v1/rules"

        mock_client.get.side_effect = [rate_limited_response, ok_response]

        with patch(
            "guard_agent.transport.asyncio.sleep", new_callable=AsyncMock
        ) as mock_sleep:
            result = await transport._get_with_retry("/api/v1/rules")

        assert result == {"rule_id": "r1", "version": 2}
        sleep_args = [c.args[0] for c in mock_sleep.call_args_list if c.args]
        assert 8.0 in sleep_args

    @pytest.mark.asyncio
    async def test_get_with_retry_records_failure_after_retry_after_attempts_exhausted(
        self, agent_config: AgentConfig, mock_client: AsyncMock
    ) -> None:
        agent_config.retry_attempts = 1
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        rate_limited_response = MagicMock()
        rate_limited_response.status_code = 429
        rate_limited_response.headers = {"Retry-After": "3"}
        rate_limited_response.url = "http://test/api/v1/rules"
        mock_client.get.side_effect = [rate_limited_response, rate_limited_response]

        before = transport.requests_failed
        with patch("guard_agent.transport.asyncio.sleep", new_callable=AsyncMock):
            result = await transport._get_with_retry("/api/v1/rules")

        assert result is None
        assert transport.requests_failed == before + 1


class TestHTTPTransportCompression:
    """Tests for the gzip compression of outgoing request bodies."""

    def test_maybe_compress_skips_when_below_threshold(
        self, agent_config: AgentConfig
    ) -> None:
        agent_config.compression_enabled = True
        agent_config.compression_threshold = 10_000
        transport = HTTPTransport(agent_config)
        body, headers = transport._maybe_compress("hi")
        assert body == b"hi"
        assert headers == {}

    def test_maybe_compress_skips_when_disabled(
        self, agent_config: AgentConfig
    ) -> None:
        agent_config.compression_enabled = False
        agent_config.compression_threshold = 1
        transport = HTTPTransport(agent_config)
        body, headers = transport._maybe_compress("x" * 100)
        assert body == b"x" * 100
        assert headers == {}

    def test_maybe_compress_gzips_above_threshold(
        self, agent_config: AgentConfig
    ) -> None:
        import gzip

        agent_config.compression_enabled = True
        agent_config.compression_threshold = 10
        transport = HTTPTransport(agent_config)
        body, headers = transport._maybe_compress("y" * 200)
        assert headers == {"Content-Encoding": "gzip"}
        assert gzip.decompress(body) == b"y" * 200
        assert len(body) < 200

    @pytest.mark.asyncio
    async def test_send_events_uses_gzip_when_payload_is_large(
        self,
        agent_config: AgentConfig,
        mock_client: AsyncMock,
    ) -> None:
        import gzip

        agent_config.compression_enabled = True
        agent_config.compression_threshold = 100
        transport = HTTPTransport(agent_config)
        transport._client = mock_client

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="x" * 4000,
            )
        ]

        result = await transport.send_events(events)
        assert result is True

        post_call = mock_client.post.call_args
        assert post_call.kwargs.get("headers", {}).get("Content-Encoding") == "gzip"
        sent_body = post_call.kwargs["content"]
        assert isinstance(sent_body, bytes)
        decoded = gzip.decompress(sent_body)
        assert b"ip_banned" in decoded


class TestLogRequestError:
    """Tests for HTTPTransport._log_request_error.

    Reason for the type+repr formatting: transport-level connection drops
    (CloudFlare/origin RST mid-stream, half-closed sockets) raise httpx
    exceptions whose ``str(exc)`` is empty. Logging only ``str(exc)`` produced
    error lines like ``HTTP client error for POST <url>:`` with no diagnostic
    info, hiding which httpx class actually fired. The format must surface the
    exception class and its repr so operators can distinguish RemoteProtocolError
    from ReadTimeout from ConnectError without a debugger.
    """

    @pytest.mark.asyncio
    async def test_log_includes_exception_class_when_str_exc_is_empty(
        self,
        agent_config: AgentConfig,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        transport = HTTPTransport(agent_config)
        empty_protocol_error = httpx.RemoteProtocolError("")
        assert str(empty_protocol_error) == ""

        with caplog.at_level("ERROR", logger="guard_agent.transport"):
            transport._log_request_error("POST", "https://x/y", empty_protocol_error)

        records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(records) == 1
        message = records[0].getMessage()
        assert "HTTP client error for POST https://x/y:" in message
        assert "RemoteProtocolError" in message

    @pytest.mark.asyncio
    async def test_log_classifies_encryption_error(
        self,
        agent_config: AgentConfig,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from guard_agent.encryption import EncryptionError

        transport = HTTPTransport(agent_config)
        with caplog.at_level("ERROR", logger="guard_agent.transport"):
            transport._log_request_error(
                "POST", "https://x/y", EncryptionError("decrypt failed")
            )

        records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(records) == 1
        message = records[0].getMessage()
        assert message.startswith("Encryption error for POST https://x/y:")
        assert "EncryptionError" in message
        assert "decrypt failed" in message

    @pytest.mark.asyncio
    async def test_log_classifies_timeout_error(
        self,
        agent_config: AgentConfig,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        transport = HTTPTransport(agent_config)
        with caplog.at_level("ERROR", logger="guard_agent.transport"):
            transport._log_request_error("POST", "https://x/y", asyncio.TimeoutError())

        records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(records) == 1
        message = records[0].getMessage()
        assert message.startswith("Timeout error for POST https://x/y:")
        assert "TimeoutError" in message

    @pytest.mark.asyncio
    async def test_log_classifies_unexpected_error(
        self,
        agent_config: AgentConfig,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        transport = HTTPTransport(agent_config)
        with caplog.at_level("ERROR", logger="guard_agent.transport"):
            transport._log_request_error(
                "POST", "https://x/y", ValueError("bad payload")
            )

        records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(records) == 1
        message = records[0].getMessage()
        assert message.startswith("Unexpected error for POST https://x/y:")
        assert "ValueError" in message
        assert "bad payload" in message


class TestResponseBodyBounding:
    """A branded HTML maintenance page must never flood the customer's logs."""

    @pytest.mark.asyncio
    async def test_500_with_large_html_body_produces_bounded_single_line_message(
        self, agent_config: AgentConfig
    ) -> None:
        """5xx with a large HTML body: bounded, single-line, has status+url."""
        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 500
        huge_body = (
            "<html><body>\n  <style>.a{color:red}</style>\n"
            + ("  <div>Under maintenance</div>\n" * 2000)
            + "</body></html>"
        )
        mock_response.text = huge_body
        mock_response.url = "https://api.guard-core.com/api/v1/events"

        with pytest.raises(Exception) as exc_info:
            await transport._handle_response(mock_response)

        message = str(exc_info.value)
        assert "\n" not in message
        assert len(message) < 500
        assert "500" in message
        assert "api.guard-core.com" in message
        assert huge_body not in message
        assert "truncated" in message
        assert str(len(huge_body)) in message

    @pytest.mark.asyncio
    async def test_4xx_permanent_error_bounds_detail_and_log(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Non-retryable 4xx: both the log line and exception detail are bounded."""
        from guard_agent.exceptions import PermanentClientError

        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 404
        huge_body = "Not Found\n" * 3000
        mock_response.text = huge_body
        mock_response.url = "https://api.guard-core.com/api/v1/events"

        with caplog.at_level("ERROR", logger="guard_agent.transport"):
            with pytest.raises(PermanentClientError) as exc_info:
                await transport._handle_response(mock_response)

        assert exc_info.value.status_code == 404
        assert huge_body not in exc_info.value.detail
        assert "\n" not in exc_info.value.detail
        assert len(exc_info.value.detail) < 500

        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(error_records) == 1
        message = error_records[0].getMessage()
        assert huge_body not in message
        assert "\n" not in message
        assert "404" in message

    @pytest.mark.asyncio
    async def test_other_client_error_bounds_log_message(
        self, agent_config: AgentConfig, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A non-listed client error (e.g. 451) also gets a bounded log line."""
        transport = HTTPTransport(agent_config)
        mock_response = AsyncMock()
        mock_response.status_code = 451
        huge_body = "Unavailable For Legal Reasons " * 500
        mock_response.text = huge_body
        mock_response.url = "https://api.guard-core.com/api/v1/events"

        with caplog.at_level("ERROR", logger="guard_agent.transport"):
            result = await transport._handle_response(mock_response)

        assert result is False
        error_records = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(error_records) == 1
        message = error_records[0].getMessage()
        assert huge_body not in message
        assert "451" in message
        assert len(message) < 500


class TestPayloadTooLargeSplitOrDrop:
    """HTTP 413 must split the batch recursively or drop a singleton, never requeue."""

    @pytest.mark.asyncio
    async def test_413_splits_batch_until_each_half_fits(
        self, agent_config: AgentConfig
    ) -> None:
        from guard_agent.exceptions import PayloadTooLargeError

        agent_config.retry_attempts = 0
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()

        max_items = 2
        accepted_sizes: list[int] = []

        async def fake_make_request(
            method: str, endpoint: str, data: dict[str, Any]
        ) -> dict[str, Any]:
            count = len(data.get("events", []))
            if count > max_items:
                raise PayloadTooLargeError("too big")
            accepted_sizes.append(count)
            return {"status": "ok"}

        with patch.object(transport, "_make_request", side_effect=fake_make_request):
            events = [
                SecurityEvent(
                    timestamp=datetime.now(timezone.utc),
                    event_type="ip_banned",
                    ip_address="1.1.1.1",
                    action_taken="banned",
                    reason="x",
                )
                for _ in range(5)
            ]
            result = await transport.send_events(events)

        assert result is True
        assert accepted_sizes, "no batch was accepted"
        assert all(size <= max_items for size in accepted_sizes)
        assert sum(accepted_sizes) == 5

    @pytest.mark.asyncio
    async def test_413_on_single_item_drops_with_warning_and_hook(
        self,
        agent_config: AgentConfig,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from guard_agent.exceptions import PayloadTooLargeError

        agent_config.retry_attempts = 0
        captured: list[tuple[str, BaseException, dict[str, Any]]] = []
        agent_config.on_error = lambda s, e, c: captured.append((s, e, c))
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()

        async def fake_make_request(
            method: str, endpoint: str, data: dict[str, Any]
        ) -> dict[str, Any]:
            raise PayloadTooLargeError("still too big")

        with patch.object(transport, "_make_request", side_effect=fake_make_request):
            with caplog.at_level("WARNING", logger="guard_agent.transport"):
                events = [
                    SecurityEvent(
                        timestamp=datetime.now(timezone.utc),
                        event_type="ip_banned",
                        ip_address="1.1.1.1",
                        action_taken="banned",
                        reason="x",
                    )
                ]
                result = await transport.send_events(events)

        assert result is True
        assert any(
            "Dropping events batch of 1 item" in r.getMessage() for r in caplog.records
        )
        assert captured
        assert isinstance(captured[0][1], PayloadTooLargeError)
        assert captured[0][2]["item_count"] == 1

    @pytest.mark.asyncio
    async def test_413_does_not_escape_as_payload_too_large_error(
        self, agent_config: AgentConfig
    ) -> None:
        from guard_agent.exceptions import PayloadTooLargeError

        agent_config.retry_attempts = 0
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()

        async def fake_make_request(
            method: str, endpoint: str, data: dict[str, Any]
        ) -> dict[str, Any]:
            raise PayloadTooLargeError("too big")

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="1.1.1.1",
                action_taken="banned",
                reason="x",
            )
        ]
        with patch.object(transport, "_make_request", side_effect=fake_make_request):
            result = await transport.send_events(events)

        assert result is True

    @pytest.mark.asyncio
    async def test_413_splits_metrics_until_each_half_fits(
        self, agent_config: AgentConfig
    ) -> None:
        from guard_agent.exceptions import PayloadTooLargeError

        agent_config.retry_attempts = 0
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()

        max_items = 1
        accepted_sizes: list[int] = []

        async def fake_make_request(
            method: str, endpoint: str, data: dict[str, Any]
        ) -> dict[str, Any]:
            count = len(data.get("metrics", []))
            if count > max_items:
                raise PayloadTooLargeError("too big")
            accepted_sizes.append(count)
            return {"status": "ok"}

        with patch.object(transport, "_make_request", side_effect=fake_make_request):
            metrics = [
                SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type="request_count",
                    value=1.0,
                )
                for _ in range(3)
            ]
            result = await transport.send_metrics(metrics)

        assert result is True
        assert accepted_sizes, "no batch was accepted"
        assert all(size <= max_items for size in accepted_sizes)
        assert sum(accepted_sizes) == 3


class TestPermanentRejectionDrop:
    """400/404/422 must drop the batch (return True), never requeue."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status_code", [400, 404, 422])
    async def test_permanent_rejection_drops_batch_and_fires_hook(
        self,
        agent_config: AgentConfig,
        status_code: int,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        from guard_agent.exceptions import PermanentClientError

        agent_config.retry_attempts = 0
        captured: list[tuple[str, BaseException, dict[str, Any]]] = []
        agent_config.on_error = lambda s, e, c: captured.append((s, e, c))
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()

        with patch.object(
            transport,
            "_make_request",
            side_effect=PermanentClientError(status_code, "rejected"),
        ):
            with caplog.at_level("WARNING", logger="guard_agent.transport"):
                events = [
                    SecurityEvent(
                        timestamp=datetime.now(timezone.utc),
                        event_type="ip_banned",
                        ip_address="1.1.1.1",
                        action_taken="banned",
                        reason="x",
                    )
                    for _ in range(3)
                ]
                result = await transport.send_events(events)

        assert result is True
        assert any(
            f"permanently rejected ({status_code})" in r.getMessage()
            for r in caplog.records
        )
        assert captured
        assert captured[0][1].status_code == status_code
        assert captured[0][2]["item_count"] == 3

    @pytest.mark.asyncio
    async def test_permanent_rejection_does_not_recurse_or_split(
        self, agent_config: AgentConfig
    ) -> None:
        from guard_agent.exceptions import PermanentClientError

        agent_config.retry_attempts = 0
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()

        call_count = 0

        async def fake_make_request(
            method: str, endpoint: str, data: dict[str, Any]
        ) -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            raise PermanentClientError(422, "rejected")

        events = [
            SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type="ip_banned",
                ip_address="1.1.1.1",
                action_taken="banned",
                reason="x",
            )
            for _ in range(4)
        ]
        with patch.object(transport, "_make_request", side_effect=fake_make_request):
            result = await transport.send_events(events)

        assert result is True
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_permanent_rejection_drops_metrics_batch(
        self, agent_config: AgentConfig
    ) -> None:
        from guard_agent.exceptions import PermanentClientError

        agent_config.retry_attempts = 0
        captured: list[tuple[str, BaseException, dict[str, Any]]] = []
        agent_config.on_error = lambda s, e, c: captured.append((s, e, c))
        transport = HTTPTransport(agent_config)
        transport._client = AsyncMock()

        with patch.object(
            transport,
            "_make_request",
            side_effect=PermanentClientError(400, "bad metric"),
        ):
            metrics = [
                SecurityMetric(
                    timestamp=datetime.now(timezone.utc),
                    metric_type="request_count",
                    value=1.0,
                )
                for _ in range(2)
            ]
            result = await transport.send_metrics(metrics)

        assert result is True
        assert captured
        assert captured[0][1].status_code == 400
        assert captured[0][2]["data_type"] == "metrics"
