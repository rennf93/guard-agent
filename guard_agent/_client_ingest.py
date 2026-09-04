import logging
from typing import Any

from guard_agent.models import AgentConfig, SecurityEvent, SecurityMetric
from guard_agent.utils import sanitize_headers


class IngestMixin:
    config: AgentConfig
    logger: logging.Logger
    buffer: Any

    async def send_event(self, event: Any) -> None:
        if not self.config.enable_events:
            return

        try:
            if not isinstance(event, SecurityEvent):
                event = self._normalize_event(event)
            event = self._redact_event_metadata(event)
            await self.buffer.add_event(event)
            self.logger.debug(
                f"Event buffered: {event.event_type} from {event.ip_address}"
            )
        except Exception as e:
            self.logger.error(f"Failed to buffer event: {str(e)}")

    async def send_metric(self, metric: Any) -> None:
        if not self.config.enable_metrics:
            return

        try:
            if not isinstance(metric, SecurityMetric):
                metric = self._normalize_metric(metric)
            metric = self._redact_metric_tags(metric)
            await self.buffer.add_metric(metric)
            self.logger.debug(f"Metric buffered: {metric.metric_type} = {metric.value}")
        except Exception as e:
            self.logger.error(f"Failed to buffer metric: {str(e)}")

    def _redact_event_metadata(self, event: SecurityEvent) -> SecurityEvent:
        redacted = sanitize_headers(event.metadata, self.config.sensitive_headers)
        return event.model_copy(update={"metadata": redacted})

    def _redact_metric_tags(self, metric: SecurityMetric) -> SecurityMetric:
        redacted = sanitize_headers(metric.tags, self.config.sensitive_headers)
        return metric.model_copy(update={"tags": redacted})

    def _normalize_event(self, event: Any) -> SecurityEvent:
        event_data: dict[str, Any] = {}
        for field_name in SecurityEvent.model_fields:
            if hasattr(event, field_name):
                event_data[field_name] = getattr(event, field_name)
        return SecurityEvent(**event_data)

    def _normalize_metric(self, metric: Any) -> SecurityMetric:
        metric_data: dict[str, Any] = {}
        for field_name in SecurityMetric.model_fields:
            if hasattr(metric, field_name):
                metric_data[field_name] = getattr(metric, field_name)
        return SecurityMetric(**metric_data)
