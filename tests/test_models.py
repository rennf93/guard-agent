from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from guard_agent.models import (
    AgentConfig,
    AgentStatus,
    DynamicRules,
    EventBatch,
    SecurityEvent,
    SecurityMetric,
)


class TestAgentConfig:
    """Tests for AgentConfig model."""

    def test_valid_config(self) -> None:
        """Test creating a valid agent configuration."""
        config = AgentConfig(
            api_key="test-key",
            endpoint="https://api.example.com",
            project_id="test-project",
        )

        assert config.api_key == "test-key"
        assert config.endpoint == "https://api.example.com"
        assert config.project_id == "test-project"
        assert config.buffer_size == 100  # default
        assert config.flush_interval == 30  # default

    def test_invalid_config_missing_api_key(self) -> None:
        with pytest.raises(ValidationError):
            AgentConfig.model_validate({})

    def test_config_defaults(self) -> None:
        """Test that default values are set correctly."""
        config = AgentConfig(api_key="test")

        assert config.endpoint == "https://api.guard-core.com"
        assert config.buffer_size == 100
        assert config.flush_interval == 30
        assert config.enable_metrics is True
        assert config.enable_events is True
        assert config.guard_version is None
        assert config.guard_core_version is None

    def test_invalid_endpoint_empty(self) -> None:
        """Test that empty endpoint raises validation error."""
        with pytest.raises(ValidationError, match="Endpoint URL cannot be empty"):
            AgentConfig(api_key="test", endpoint="")

    def test_invalid_endpoint_no_scheme(self) -> None:
        """Test that endpoint without scheme raises validation error."""
        with pytest.raises(
            ValidationError, match="Endpoint must be a valid URL with scheme and domain"
        ):
            AgentConfig(api_key="test", endpoint="api.example.com")

    def test_invalid_endpoint_no_domain(self) -> None:
        """Test that endpoint without domain raises validation error."""
        with pytest.raises(
            ValidationError, match="Endpoint must be a valid URL with scheme and domain"
        ):
            AgentConfig(api_key="test", endpoint="https://")

    def test_invalid_endpoint_scheme(self) -> None:
        """Test that endpoint with invalid scheme raises validation error."""
        with pytest.raises(
            ValidationError, match="Endpoint URL must use http or https scheme"
        ):
            AgentConfig(api_key="test", endpoint="ftp://api.example.com")

    def test_valid_endpoint_http(self) -> None:
        """Test that HTTP endpoint is valid."""
        config = AgentConfig(api_key="test", endpoint="http://api.example.com")
        assert config.endpoint == "http://api.example.com"

    def test_valid_endpoint_https(self) -> None:
        """Test that HTTPS endpoint is valid."""
        config = AgentConfig(api_key="test", endpoint="https://api.example.com")
        assert config.endpoint == "https://api.example.com"

    def test_config_ignores_unknown_kwarg_from_a_newer_caller(self) -> None:
        """A guard-core newer than this guard-agent may pass a kwarg this
        version does not declare yet; it must be silently dropped, not
        raise, so old guard-agent releases stay compatible with new
        guard-core releases."""
        config = AgentConfig.model_validate(
            {
                "api_key": "test",
                "some_future_field_this_version_does_not_know": "value",
            }
        )
        assert config.api_key == "test"
        assert not hasattr(config, "some_future_field_this_version_does_not_know")


class TestSecurityEvent:
    """Tests for SecurityEvent model."""

    def test_valid_event(self) -> None:
        """Test creating a valid security event."""
        timestamp = datetime.now(timezone.utc)
        event = SecurityEvent(
            timestamp=timestamp,
            event_type="ip_banned",
            ip_address="192.168.1.1",
            action_taken="banned",
            reason="threshold_exceeded",
        )

        assert event.timestamp == timestamp
        assert event.event_type == "ip_banned"
        assert event.ip_address == "192.168.1.1"
        assert event.action_taken == "banned"
        assert event.reason == "threshold_exceeded"

    def test_dynamic_event_type(self) -> None:
        """Test that dynamic event types are accepted (parent uses f-strings)."""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="pattern_anomaly_timing",
            ip_address="192.168.1.1",
            action_taken="logged",
            reason="anomaly detected",
        )
        assert event.event_type == "pattern_anomaly_timing"

    def test_event_without_ip_and_reason(self) -> None:
        """Test creating event without ip_address/reason (security_headers_handler)."""
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="security_headers_applied",
        )
        assert event.ip_address == ""
        assert event.reason == ""
        assert event.action_taken == ""

    def test_event_with_extra_fields(self) -> None:
        event = SecurityEvent.model_validate(
            {
                "timestamp": datetime.now(timezone.utc),
                "event_type": "ip_banned",
                "ip_address": "10.0.0.1",
                "action_taken": "banned",
                "reason": "test",
                "custom_field": "custom_value",
                "severity": 5,
            }
        )
        extras = event.model_extra or {}
        assert extras["custom_field"] == "custom_value"
        assert extras["severity"] == 5

    def test_security_event_auto_generates_idempotency_key(self) -> None:
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="suspicious_request",
        )
        assert event.idempotency_key is not None
        assert isinstance(event.idempotency_key, UUID)
        assert len(str(event.idempotency_key)) == 36

    def test_security_event_idempotency_key_is_unique_per_instance(self) -> None:
        first = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="suspicious_request",
        )
        second = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="suspicious_request",
        )
        assert first.idempotency_key != second.idempotency_key

    def test_security_event_idempotency_key_round_trips_through_serialization(
        self,
    ) -> None:
        original = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            ip_address="10.0.0.1",
        )
        dumped = original.model_dump()
        rehydrated = SecurityEvent.model_validate(dumped)
        assert rehydrated.idempotency_key == original.idempotency_key

    def test_security_event_accepts_explicit_idempotency_key(self) -> None:
        explicit = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        event = SecurityEvent(
            timestamp=datetime.now(timezone.utc),
            event_type="ip_banned",
            idempotency_key=explicit,
        )
        assert event.idempotency_key == explicit


class TestSecurityMetric:
    """Tests for SecurityMetric model."""

    def test_valid_metric(self) -> None:
        """Test creating a valid security metric."""
        timestamp = datetime.now(timezone.utc)
        metric = SecurityMetric(
            timestamp=timestamp,
            metric_type="request_count",
            value=42.0,
            tags={"endpoint": "/api/test"},
        )

        assert metric.timestamp == timestamp
        assert metric.metric_type == "request_count"
        assert metric.value == 42.0
        assert metric.tags == {"endpoint": "/api/test"}

    def test_invalid_metric_type(self) -> None:
        with pytest.raises(ValidationError):
            SecurityMetric.model_validate(
                {
                    "timestamp": datetime.now(timezone.utc),
                    "metric_type": "invalid_metric",
                    "value": 1.0,
                }
            )


class TestDynamicRules:
    """Tests for DynamicRules model."""

    def test_valid_rules(self) -> None:
        """Test creating valid dynamic rules."""
        rules = DynamicRules(
            ip_blacklist=["192.168.1.1", "10.0.0.1"],
            ip_whitelist=["127.0.0.1"],
            blocked_countries=["XX"],
            whitelist_countries=["US"],
            global_rate_limit=100,
            ttl=300,
            auto_ban_threshold=5,
            auto_ban_duration=1800,
            enable_rate_limit_auto_ban=True,
        )

        assert "192.168.1.1" in rules.ip_blacklist
        assert "127.0.0.1" in rules.ip_whitelist
        assert "XX" in rules.blocked_countries
        assert "US" in rules.whitelist_countries
        assert rules.global_rate_limit == 100
        assert rules.ttl == 300
        assert rules.auto_ban_threshold == 5
        assert rules.auto_ban_duration == 1800
        assert rules.enable_rate_limit_auto_ban is True

    def test_default_rules(self) -> None:
        """Test default values for dynamic rules."""
        rules = DynamicRules()

        assert rules.ip_blacklist == []
        assert rules.ip_whitelist == []
        assert rules.blocked_countries == []
        assert rules.whitelist_countries == []
        assert rules.endpoint_rate_limits == {}
        assert rules.auto_ban_threshold is None
        assert rules.auto_ban_duration is None
        assert rules.enable_rate_limit_auto_ban is None
        assert rules.ttl == 300
        assert rules.rule_id == "default-rule"
        assert rules.version == 1

    @pytest.mark.parametrize("field", ["auto_ban_threshold", "auto_ban_duration"])
    def test_auto_ban_ints_reject_values_below_one(self, field: str) -> None:
        """Mirror guard-core's ge=1 floor so a push of 0 fails here, not mid-apply."""
        kwargs: dict[str, Any] = {field: 1}
        assert getattr(DynamicRules(**kwargs), field) == 1
        with pytest.raises(ValidationError):
            DynamicRules(**kwargs | {field: 0})
        with pytest.raises(ValidationError):
            DynamicRules(**kwargs | {field: -5})


class TestAgentStatus:
    """Tests for AgentStatus model."""

    def test_valid_status(self) -> None:
        """Test creating a valid agent status."""
        timestamp = datetime.now(timezone.utc)
        status = AgentStatus(
            timestamp=timestamp,
            status="healthy",
            uptime=3600.0,
            events_sent=100,
            events_failed=5,
            buffer_size=10,
        )

        assert status.timestamp == timestamp
        assert status.status == "healthy"
        assert status.uptime == 3600.0
        assert status.events_sent == 100
        assert status.events_failed == 5
        assert status.buffer_size == 10


class TestEventBatch:
    """Tests for EventBatch model."""

    def test_valid_batch(self) -> None:
        """Test creating a valid event batch."""
        timestamp = datetime.now(timezone.utc)
        events = [
            SecurityEvent(
                timestamp=timestamp,
                event_type="ip_banned",
                ip_address="192.168.1.1",
                action_taken="banned",
                reason="test",
            )
        ]

        batch = EventBatch(
            project_id="test-project",
            events=events,
            batch_id="test-batch-123",
            created_at=timestamp,
        )

        assert batch.project_id == "test-project"
        assert len(batch.events) == 1
        assert batch.batch_id == "test-batch-123"
        assert batch.created_at == timestamp
        assert batch.guard_version is None
        assert batch.guard_core_version is None

    def test_batch_carries_guard_core_version_independently_of_guard_version(
        self,
    ) -> None:
        """guard_core_version is a distinct field from guard_version and
        agent_version; setting one must not affect the others."""
        batch = EventBatch(
            project_id="test-project",
            batch_id="test-batch-123",
            created_at=datetime.now(timezone.utc),
            agent_version="2.8.1",
            guard_version="7.0.0",
            guard_core_version="3.12.0",
        )

        assert batch.agent_version == "2.8.1"
        assert batch.guard_version == "7.0.0"
        assert batch.guard_core_version == "3.12.0"
