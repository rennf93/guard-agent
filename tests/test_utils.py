import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError

from guard_agent.models import AgentConfig
from guard_agent.utils import (
    CircuitBreaker,
    RateLimitedError,
    RateLimiter,
    SerializationError,
    calculate_backoff_delay,
    generate_batch_id,
    get_current_timestamp,
    hash_ip,
    parse_retry_after_seconds,
    safe_json_deserialize,
    safe_json_serialize,
    sanitize_headers,
    summarize_response_body,
    truncate_payload,
    validate_config,
)


class TestUtils:
    def test_generate_batch_id(self) -> None:
        batch_id = generate_batch_id()
        assert isinstance(batch_id, str)
        assert len(batch_id) > 0
        parts = batch_id.split("-")
        assert len(parts) == 2
        assert parts[0].isdigit()  # timestamp part

    def test_sanitize_headers(self) -> None:
        headers = {
            "Authorization": "Bearer token",
            "Content-Type": "application/json",
            "X-Api-Key": "secret",
            "Custom-Header": "value",
        }
        sensitive_headers = ["authorization", "x-api-key"]
        sanitized = sanitize_headers(headers, sensitive_headers)

        assert sanitized["Authorization"] == "[REDACTED]"
        assert sanitized["X-Api-Key"] == "[REDACTED]"
        assert sanitized["Content-Type"] == "application/json"
        assert sanitized["Custom-Header"] == "value"
        assert len(sanitized) == 4

    def test_truncate_payload(self) -> None:
        long_payload = "This is a very long payload that needs to be truncated."
        short_payload = "Short payload."

        truncated = truncate_payload(long_payload, 10)
        assert truncated == "This is a ...[TRUNCATED]"
        assert len(truncated) == 10 + len("...[TRUNCATED]")

        not_truncated = truncate_payload(short_payload, 20)
        assert not_truncated == short_payload

        edge_case_exact_size = truncate_payload("12345", 5)
        assert edge_case_exact_size == "12345"

    def test_summarize_response_body_returns_short_text_unchanged(self) -> None:
        text = "Event quota exceeded. Upgrade your plan."
        assert summarize_response_body(text) == text

    def test_summarize_response_body_collapses_whitespace_and_newlines(self) -> None:
        text = "line one\n  line two\t\tline three\n\n"
        summary = summarize_response_body(text)
        assert "\n" not in summary
        assert "\t" not in summary
        assert summary == "line one line two line three"

    def test_summarize_response_body_truncates_and_reports_original_length(
        self,
    ) -> None:
        body = "x" * 5000
        summary = summarize_response_body(body, max_length=300)
        assert len(summary) < len(body)
        assert body not in summary
        assert "truncated" in summary
        assert "5000" in summary

    def test_summarize_response_body_reports_raw_length_for_whitespace_heavy_html(
        self,
    ) -> None:
        body = ("<div>\n    " * 200) + "maintenance" + ("\n    </div>" * 200)
        original_length = len(body)
        summary = summarize_response_body(body, max_length=20)
        assert "\n" not in summary
        assert str(original_length) in summary

    def test_hash_ip(self) -> None:
        ip = "192.168.1.1"
        hashed_ip = hash_ip(ip)
        assert isinstance(hashed_ip, str)
        assert len(hashed_ip) == 16  # Truncated to 16 characters
        assert hashed_ip != ip

        hashed_ip_with_salt = hash_ip(ip, salt="test_salt")
        assert hashed_ip_with_salt != hashed_ip
        assert len(hashed_ip_with_salt) == 16

    def test_get_current_timestamp(self) -> None:
        timestamp = get_current_timestamp()
        assert isinstance(timestamp, datetime)
        assert timestamp.tzinfo == timezone.utc
        # Check if it's close to now (within a small margin)
        assert (datetime.now(timezone.utc) - timestamp).total_seconds() < 1

    def test_calculate_backoff_delay(self) -> None:
        assert calculate_backoff_delay(0) == 1.0
        assert calculate_backoff_delay(1) == 2.0
        assert calculate_backoff_delay(2) == 4.0
        assert calculate_backoff_delay(3, base_delay=0.5) == 4.0  # 0.5 * (2**3) = 4.0
        assert (
            calculate_backoff_delay(10, max_delay=10.0) == 10.0
        )  # Should cap at max_delay

    @pytest.mark.asyncio
    async def test_safe_json_serialize_success(self) -> None:
        data = {"key": "value", "number": 123}
        serialized = await safe_json_serialize(data)
        assert json.loads(serialized) == data

    @pytest.mark.asyncio
    async def test_safe_json_serialize_with_unserializable_object(self) -> None:
        class Unserializable:
            def __str__(self) -> str:
                raise TypeError("Cannot serialize this object")

        data = {"obj": Unserializable()}
        with pytest.raises(SerializationError):
            await safe_json_serialize(data)

    @pytest.mark.asyncio
    async def test_safe_json_deserialize_success(self) -> None:
        json_str = '{"key": "value", "number": 123}'
        deserialized = await safe_json_deserialize(json_str)
        assert deserialized == {"key": "value", "number": 123}

    @pytest.mark.asyncio
    async def test_safe_json_deserialize_invalid_json(self) -> None:
        invalid_json_str = '{"key": "value", "number": 123'  # Missing closing brace
        deserialized = await safe_json_deserialize(invalid_json_str)
        assert deserialized is None

    @pytest.mark.asyncio
    async def test_safe_json_deserialize_non_dict_json(self) -> None:
        """Test safe_json_deserialize when JSON is valid but not a dict."""
        # Test with JSON array
        json_array = '["item1", "item2", "item3"]'
        deserialized = await safe_json_deserialize(json_array)
        assert deserialized is None

        # Test with JSON string
        json_string = '"just a string"'
        deserialized = await safe_json_deserialize(json_string)
        assert deserialized is None

        # Test with JSON number
        json_number = "123"
        deserialized = await safe_json_deserialize(json_number)
        assert deserialized is None

        # Test with JSON boolean
        json_boolean = "true"
        deserialized = await safe_json_deserialize(json_boolean)
        assert deserialized is None

        # Test with JSON null
        json_null = "null"
        deserialized = await safe_json_deserialize(json_null)
        assert deserialized is None

    def test_validate_config_success(self) -> None:
        config = AgentConfig(
            api_key="a" * 10,
            endpoint="https://example.com",
            buffer_size=1,
            flush_interval=1,
            timeout=1,
            retry_attempts=0,
            backoff_factor=0.1,
        )
        errors = validate_config(config)
        assert len(errors) == 0

    @pytest.mark.parametrize(
        """
        api_key,
        endpoint,
        buffer_size,
        flush_interval,
        timeout,
        retry_attempts,
        backoff_factor,
        expected_errors
        """,
        [
            (
                "",
                "https://example.com",
                1,
                1,
                1,
                0,
                0.1,
                ["api_key must be at least 10 characters long"],
            ),
            (
                "short",
                "https://example.com",
                1,
                1,
                1,
                0,
                0.1,
                ["api_key must be at least 10 characters long"],
            ),
            (
                "a" * 10,
                "https://example.com",
                0,
                1,
                1,
                0,
                0.1,
                ["buffer_size must be greater than 0"],
            ),
            (
                "a" * 10,
                "https://example.com",
                1,
                0,
                1,
                0,
                0.1,
                ["flush_interval must be greater than 0"],
            ),
            (
                "a" * 10,
                "https://example.com",
                1,
                1,
                0,
                0,
                0.1,
                ["timeout must be greater than 0"],
            ),
            (
                "a" * 10,
                "https://example.com",
                1,
                1,
                1,
                -1,
                0.1,
                ["retry_attempts cannot be negative"],
            ),
            (
                "a" * 10,
                "https://example.com",
                1,
                1,
                1,
                0,
                0,
                ["backoff_factor must be greater than 0"],
            ),
        ],
    )
    def test_validate_config_failures(
        self,
        api_key: str,
        endpoint: str,
        buffer_size: int,
        flush_interval: int,
        timeout: int,
        retry_attempts: int,
        backoff_factor: float,
        expected_errors: list[str],
    ) -> None:
        config = AgentConfig(
            api_key=api_key,
            endpoint=endpoint,
            buffer_size=buffer_size,
            flush_interval=flush_interval,
            timeout=timeout,
            retry_attempts=retry_attempts,
            backoff_factor=backoff_factor,
        )
        errors = validate_config(config)
        assert sorted(errors) == sorted(expected_errors)

    @pytest.mark.parametrize(
        "endpoint, expected_error_msg",
        [
            ("invalid-url", "Endpoint must be a valid URL with scheme and domain"),
            ("ftp://example.com", "Endpoint URL must use http or https scheme"),
        ],
    )
    def test_validate_config_endpoint_failures(
        self, endpoint: str, expected_error_msg: str
    ) -> None:
        with pytest.raises(ValidationError) as excinfo:
            AgentConfig(
                api_key="a" * 10,
                endpoint=endpoint,
                buffer_size=1,
                flush_interval=1,
                timeout=1,
                retry_attempts=0,
                backoff_factor=0.1,
            )
        assert expected_error_msg in str(excinfo.value)

    def test_validate_config_endpoint_non_http_https_scheme(self) -> None:
        # Create a valid AgentConfig and then manually set invalid endpoint
        config = AgentConfig(
            api_key="a" * 10,
            endpoint="https://example.com",  # Valid scheme initially
            buffer_size=1,
            flush_interval=1,
            timeout=1,
            retry_attempts=0,
            backoff_factor=0.1,
        )

        # Manually override the endpoint to test our validation logic
        object.__setattr__(config, "endpoint", "ws://example.com")

        errors = validate_config(config)
        assert "endpoint must be a valid HTTP/HTTPS URL" in errors


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_acquire_within_limit(self) -> None:
        limiter = RateLimiter(max_calls=3, time_window=10)
        with patch("time.time", side_effect=[0, 1, 2]):
            assert await limiter.acquire() is True
            assert await limiter.acquire() is True
            assert await limiter.acquire() is True
            assert len(limiter.calls) == 3

    @pytest.mark.asyncio
    async def test_acquire_exceed_limit(self) -> None:
        limiter = RateLimiter(max_calls=1, time_window=10)
        with patch("time.time", side_effect=[0, 1]):
            assert await limiter.acquire() is True
            assert await limiter.acquire() is False

    @pytest.mark.asyncio
    async def test_acquire_old_calls_removed(self) -> None:
        limiter = RateLimiter(max_calls=2, time_window=10)
        current_time = 0

        def mock_time() -> float:
            nonlocal current_time
            current_time += 1
            return current_time

        with patch("time.time", side_effect=mock_time):
            # Call 1: time=1, calls=[1]
            assert await limiter.acquire() is True
            assert limiter.calls == [1]

            # Call 2: time=2, calls=[1, 2]
            assert await limiter.acquire() is True
            assert limiter.calls == [1, 2]

            # Call 3: time=3, max_calls reached, returns False, calls remain [1, 2]
            assert await limiter.acquire() is False
            assert limiter.calls == [1, 2]

            # Advance time to 11 (next time.time() will be 12)
            current_time = 11

            # Call 4: time=12. 1 and 2 are now outside window (12-1=11, 12-2=10).
            # Both should be removed. calls=[]. Then 12 is added. calls=[12].
            assert await limiter.acquire() is True
            assert limiter.calls == [12]

            # Call 5: time=13. calls=[12, 13]
            assert await limiter.acquire() is True
            assert limiter.calls == [12, 13]

            # Call 6: time=14. max_calls reached, returns False, calls remain [12, 13]
            assert await limiter.acquire() is False
            assert limiter.calls == [12, 13]

    @pytest.mark.asyncio
    async def test_get_retry_after(self) -> None:
        limiter = RateLimiter(max_calls=1, time_window=10)

        # Test case 1: No calls
        assert limiter.get_retry_after() == 0.0

        # Test case 2: One call, still within window
        limiter.calls = [0]  # Simulate a call at time 0
        with patch("time.time", return_value=1):  # Current time is 1
            assert limiter.get_retry_after() == 9.0  # 10 - (1 - 0) = 9

        # Test case 3: One call, exactly at window edge
        limiter.calls = [0]
        with patch("time.time", return_value=10):  # Current time is 10
            assert limiter.get_retry_after() == 0.0  # 10 - (10 - 0) = 0

        # Test case 4: One call, outside window
        limiter.calls = [0]
        with patch("time.time", return_value=11):  # Current time is 11
            assert limiter.get_retry_after() == 0.0  # 10 - (11 - 0) = -1, capped at 0

        # Test case 5: Multiple calls, oldest is within window
        limiter.calls = [0, 5]  # Calls at 0 and 5
        with patch("time.time", return_value=8):  # Current time is 8
            assert limiter.get_retry_after() == 2.0  # Oldest is 0. 10 - (8 - 0) = 2

        # Test case 6: Multiple calls, oldest is outside window
        limiter.calls = [0, 5]
        with patch("time.time", return_value=11):  # Current time is 11
            assert (
                limiter.get_retry_after() == 0.0
            )  # Oldest is 0. 10 - (11 - 0) = -1, capped at 0

    def test_get_retry_after_no_calls(self) -> None:
        limiter = RateLimiter(max_calls=1, time_window=10)
        assert limiter.get_retry_after() == 0.0


class TestCircuitBreaker:
    @pytest.mark.asyncio
    async def test_closed_state_success(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=1)
        mock_func = AsyncMock(return_value="success")

        result = await breaker.call(mock_func)
        assert result == "success"
        assert breaker.state == "CLOSED"
        assert breaker.failure_count == 0

    @pytest.mark.asyncio
    async def test_closed_state_failure_below_threshold(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=1)
        mock_func = AsyncMock(side_effect=Exception("test error"))

        with pytest.raises(Exception, match="test error"):
            await breaker.call(mock_func)
        assert breaker.state == "CLOSED"
        assert breaker.failure_count == 1

        with pytest.raises(Exception, match="test error"):
            await breaker.call(mock_func)
        assert breaker.state == "OPEN"  # Threshold reached
        assert breaker.failure_count == 2

    @pytest.mark.asyncio
    async def test_open_state(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=10)
        mock_func = AsyncMock(side_effect=Exception("test error"))

        with pytest.raises(Exception, match="test error"):
            await breaker.call(mock_func)  # First failure, state becomes OPEN

        assert breaker.state == "OPEN"
        with pytest.raises(Exception, match="Circuit breaker is OPEN"):
            await breaker.call(mock_func)  # Should raise immediately

    @pytest.mark.asyncio
    async def test_half_open_state_success(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        mock_func = AsyncMock(return_value="success")

        current_time = 0.0

        def mock_time() -> float:
            nonlocal current_time
            current_time += 1
            return current_time

        with patch("time.time", side_effect=mock_time):
            # First failure to open the circuit
            with pytest.raises(Exception, match="initial failure"):
                await breaker.call(AsyncMock(side_effect=Exception("initial failure")))
            assert breaker.state == "OPEN"

            # Advance time past recovery_timeout
            current_time += breaker.recovery_timeout + 1  # Ensure time is past recovery

            # Call in HALF_OPEN state, should succeed and close circuit
            result = await breaker.call(mock_func)
            assert result == "success"
            assert breaker.state == "CLOSED"
            assert breaker.failure_count == 0

    @pytest.mark.asyncio
    async def test_half_open_state_failure(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=1)
        mock_func = AsyncMock(side_effect=Exception("test error"))

        current_time = 0.0

        def mock_time() -> float:
            nonlocal current_time
            current_time += 1
            return current_time

        with patch("time.time", side_effect=mock_time):
            # First failure to open the circuit
            with pytest.raises(Exception, match="initial failure"):
                await breaker.call(AsyncMock(side_effect=Exception("initial failure")))
            assert breaker.state == "OPEN"

            # Advance time past recovery_timeout
            current_time += breaker.recovery_timeout + 1

            # Call in HALF_OPEN state, should fail and re-open circuit
            with pytest.raises(Exception, match="test error"):
                await breaker.call(mock_func)
            assert breaker.state == "OPEN"  # Failure in HALF_OPEN re-opens breaker
            assert breaker.failure_count == 2  # Incremented failure count


class TestParseRetryAfter:
    """Tests for parse_retry_after_seconds and RateLimitedError."""

    def test_parses_integer_seconds(self) -> None:
        assert parse_retry_after_seconds("5") == 5.0

    def test_parses_float_seconds(self) -> None:
        assert parse_retry_after_seconds("2.5") == 2.5

    def test_returns_default_for_none(self) -> None:
        assert parse_retry_after_seconds(None, default=42.0) == 42.0

    def test_returns_default_for_unparseable(self) -> None:
        assert parse_retry_after_seconds("not-a-number", default=99.0) == 99.0

    def test_clamps_negative_to_zero(self) -> None:
        assert parse_retry_after_seconds("-5") == 0.0

    def test_rate_limited_error_carries_seconds(self) -> None:
        err = RateLimitedError(retry_after_seconds=15.0)
        assert err.retry_after_seconds == 15.0
        assert "15" in str(err)
