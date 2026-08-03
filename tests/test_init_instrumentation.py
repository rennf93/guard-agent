import logging
import subprocess
import sys

import pytest

import guard_agent
from guard_agent.models import EventBatch, SecurityEvent, SecurityMetric

_STANALONE_CHECK = (
    "import sys; "
    "assert 'guard_core' not in sys.modules, 'guard-core leaked into standalone'; "
    "import guard_agent; "
    "from guard_agent.models import SecurityEvent, SecurityMetric, EventBatch; "
    "models = [SecurityEvent, SecurityMetric, EventBatch]; "
    "muted = all(m.model_config.get('plugin_settings', {}).get('logfire') == "
    "{'record': 'off'} for m in models); "
    "assert 'guard_core' not in sys.modules, 'guard-core imported by guard_agent'; "
    "assert muted, 'telemetry models not muted without guard-core'; "
    "print('standalone-ok')"
)


def test_telemetry_models_muted_after_import() -> None:
    expected = {"record": "off"}
    for model in (SecurityEvent, SecurityMetric, EventBatch):
        plugin_settings = model.model_config.get("plugin_settings", {})
        assert plugin_settings.get("logfire") == expected, (
            f"{model.__name__} logfire plugin_settings not muted"
        )


def test_mute_survives_rebuild_failure(
    monkeypatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def boom(*args, **kwargs) -> None:
        raise RuntimeError("rebuild failed")

    monkeypatch.setattr(SecurityEvent, "model_rebuild", boom)

    with caplog.at_level(logging.WARNING, logger="guard_agent"):
        guard_agent._mute_pydantic_plugin_instrumentation()

    assert "Could not opt guard-agent telemetry models" in caplog.text


def test_mute_applied_standalone_without_guard_core() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _STANALONE_CHECK],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"standalone mute check failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert "standalone-ok" in result.stdout
