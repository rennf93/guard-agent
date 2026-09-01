import json
import logging
from collections.abc import Generator
from typing import Any

import pytest

from guard_agent.client import GuardAgentHandler, SyncGuardAgentHandler
from guard_agent.logging_utils import (
    JsonFormatter,
    _create_formatter,
    _YieldToHostRootHandlers,
    setup_agent_logging,
)

GUARD_AGENT_LOGGER_NAME = "guard_agent"


@pytest.fixture(autouse=True)
def reset_singletons_and_logger() -> Generator[None, None, None]:
    GuardAgentHandler._instance = None
    SyncGuardAgentHandler._instance = None
    logger = logging.getLogger(GUARD_AGENT_LOGGER_NAME)
    logger.handlers = []
    logger.setLevel(logging.NOTSET)
    yield
    GuardAgentHandler._instance = None
    sync_instance: SyncGuardAgentHandler | None = SyncGuardAgentHandler._instance
    SyncGuardAgentHandler._instance = None
    if sync_instance is not None:
        if not sync_instance._loop.is_closed():
            sync_instance._loop.call_soon_threadsafe(sync_instance._loop.stop)
            sync_instance._thread.join(timeout=2)
            sync_instance._loop.close()
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    logger.handlers = []
    logger.setLevel(logging.NOTSET)


def make_record(
    name: str = "guard_agent.client", level: int = logging.INFO
) -> logging.LogRecord:
    return logging.LogRecord(
        name=name,
        level=level,
        pathname=__file__,
        lineno=1,
        msg="Events flush recovered after 3 consecutive partial failure(s)",
        args=(),
        exc_info=None,
    )


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class TestSetupAgentLogging:
    def test_attaches_console_handler_and_is_idempotent(self) -> None:
        logger = logging.getLogger(GUARD_AGENT_LOGGER_NAME)
        stale_handler = logging.StreamHandler()
        logger.addHandler(stale_handler)

        result = setup_agent_logging()

        assert result is logger
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)
        assert not isinstance(logger.handlers[0], logging.FileHandler)
        assert logger.level == logging.INFO
        assert stale_handler not in logger.handlers

        setup_agent_logging()
        assert len(logger.handlers) == 1

    def test_explicit_recall_reapplies_host_intent(self, tmp_path: Any) -> None:
        log_file = tmp_path / "agent.log"
        setup_agent_logging(log_file=str(log_file), log_format="json")

        logger = setup_agent_logging()

        assert len(logger.handlers) == 1
        assert not isinstance(logger.handlers[0], logging.FileHandler)
        assert not isinstance(logger.handlers[0].formatter, JsonFormatter)
        assert logger.level == logging.INFO

    def test_text_format_shape(self) -> None:
        setup_agent_logging()
        formatter = logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers[0].formatter
        assert formatter is not None

        rendered = formatter.format(make_record())
        prefix, rest = rendered.split(" ", 1)

        assert prefix == "[guard_agent.client]"
        assert rendered.endswith(
            "- INFO - Events flush recovered after 3 consecutive partial failure(s)"
        )
        assert " - INFO - " in rendered

    def test_json_mode_emits_expected_keys(self) -> None:
        setup_agent_logging(log_format="json")
        formatter = logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers[0].formatter
        assert isinstance(formatter, JsonFormatter)

        entry = json.loads(formatter.format(make_record()))

        assert set(entry) == {"timestamp", "level", "logger", "message"}
        assert entry["level"] == "INFO"
        assert entry["logger"] == "guard_agent.client"
        assert (
            entry["message"]
            == "Events flush recovered after 3 consecutive partial failure(s)"
        )

    def test_flush_recovery_record_carries_guard_agent_name(self) -> None:
        setup_agent_logging()
        client_logger = logging.getLogger("guard_agent.client")

        assert client_logger.parent is logging.getLogger(GUARD_AGENT_LOGGER_NAME)
        assert client_logger.handlers == []

        formatter = client_logger.parent.handlers[0].formatter
        assert formatter is not None
        rendered = formatter.format(make_record())

        assert rendered.startswith("[guard_agent.client]")
        assert (
            "Events flush recovered after 3 consecutive partial failure(s)" in rendered
        )

    def test_file_handler_created_when_log_file_given(self, tmp_path: Any) -> None:
        log_file = tmp_path / "agent.log"

        setup_agent_logging(log_file=str(log_file))

        logger = logging.getLogger(GUARD_AGENT_LOGGER_NAME)
        assert len(logger.handlers) == 2
        assert isinstance(logger.handlers[1], logging.FileHandler)
        assert logger.handlers[1].baseFilename == str(log_file)

    def test_file_handler_created_in_missing_directory(self, tmp_path: Any) -> None:
        log_dir = tmp_path / "nested" / "logs"
        log_file = log_dir / "agent.log"

        setup_agent_logging(log_file=str(log_file))

        assert log_dir.is_dir()
        handler = logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers[1]
        assert isinstance(handler, logging.FileHandler)

    def test_bare_filename_skips_directory_creation(self, tmp_path: Any) -> None:
        log_file = tmp_path / "agent.log"

        setup_agent_logging(log_file=log_file.name)

        assert isinstance(
            logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers[1], logging.FileHandler
        )

    def test_unwritable_log_path_warns_and_keeps_console_handler(
        self, tmp_path: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")

        logger = setup_agent_logging(log_file=str(blocker / "nested" / "agent.log"))

        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0], logging.StreamHandler)
        assert any(
            "Failed to create log file" in record.getMessage()
            and "agent.log" in record.getMessage()
            for record in caplog.records
        )


class TestYieldToHostRootHandlersFilter:
    def test_suppresses_when_root_logger_has_handlers(self) -> None:
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        host_handler = logging.StreamHandler()
        root.addHandler(host_handler)

        try:
            assert root.handlers
            assert _YieldToHostRootHandlers().filter(make_record()) is False
        finally:
            root.removeHandler(host_handler)
            root.handlers = original_handlers

    def test_allows_when_root_logger_has_no_handlers(self) -> None:
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        root.handlers = []

        try:
            assert _YieldToHostRootHandlers().filter(make_record()) is True
        finally:
            root.handlers = original_handlers

    def test_console_handler_emits_only_without_host_handlers(self) -> None:
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        root.handlers = []

        try:
            setup_agent_logging()
            handler = logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers[0]
            assert handler.filter(make_record()) is True
        finally:
            root.handlers = original_handlers

    def test_console_handler_yields_when_host_has_handlers(self) -> None:
        setup_agent_logging()
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        host_handler = logging.StreamHandler()
        root.addHandler(host_handler)

        try:
            assert setup_agent_logging().handlers[0].filter(make_record()) is False
        finally:
            root.removeHandler(host_handler)
            root.handlers = original_handlers


class TestClientConstructorLogging:
    def test_repeated_async_constructions_keep_single_console_handler(
        self, agent_config: Any
    ) -> None:
        for _ in range(5):
            GuardAgentHandler(agent_config)
            assert len(logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers) == 1

    def test_sync_constructor_invokes_setup(
        self, agent_config: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import guard_agent.client as client_module

        real_setup = client_module.setup_agent_logging
        setup_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

        def counted_setup(*args: Any, **kwargs: Any) -> logging.Logger:
            setup_calls.append((args, kwargs))
            return real_setup(**kwargs)

        monkeypatch.setattr(client_module, "setup_agent_logging", counted_setup)

        SyncGuardAgentHandler(agent_config)

        assert len(setup_calls) >= 1
        assert all(kwargs == {"reconfigure": False} for _, kwargs in setup_calls)
        assert len(logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers) == 1

    def test_host_debug_level_survives_repeated_constructions(
        self, agent_config: Any
    ) -> None:
        logger = logging.getLogger(GUARD_AGENT_LOGGER_NAME)
        recorder = RecordingHandler()
        logger.addHandler(recorder)
        logger.setLevel(logging.DEBUG)

        for _ in range(3):
            GuardAgentHandler(agent_config)

        assert logger.level == logging.DEBUG
        assert logger.handlers == [recorder]

        logger.debug("host debug record flows")
        assert any(
            record.levelno == logging.DEBUG
            and record.getMessage() == "host debug record flows"
            for record in recorder.records
        )

    def test_host_preset_level_without_handlers_keeps_level(
        self, agent_config: Any
    ) -> None:
        logger = logging.getLogger(GUARD_AGENT_LOGGER_NAME)
        logger.setLevel(logging.DEBUG)

        GuardAgentHandler(agent_config)

        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1
        assert not isinstance(logger.handlers[0], logging.FileHandler)

    def test_host_json_file_config_survives_handler_construction(
        self, agent_config: Any, tmp_path: Any
    ) -> None:
        log_file = tmp_path / "agent.json"
        setup_agent_logging(log_file=str(log_file), log_format="json")
        logger = logging.getLogger(GUARD_AGENT_LOGGER_NAME)

        GuardAgentHandler(agent_config)

        assert len(logger.handlers) == 2
        assert isinstance(logger.handlers[1], logging.FileHandler)
        assert logger.handlers[1].baseFilename == str(log_file)
        assert isinstance(logger.handlers[0].formatter, JsonFormatter)
        assert logger.level == logging.INFO

    def test_repeated_sync_constructions_keep_single_console_handler(
        self, agent_config: Any
    ) -> None:
        for _ in range(3):
            SyncGuardAgentHandler(agent_config)
            assert len(logging.getLogger(GUARD_AGENT_LOGGER_NAME).handlers) == 1


class TestJsonFormatter:
    def test_format_returns_json_line(self) -> None:
        formatter = JsonFormatter()
        record = make_record(name="guard_agent.custom")

        entry = json.loads(formatter.format(record))

        assert set(entry) == {"timestamp", "level", "logger", "message"}
        assert entry["logger"] == "guard_agent.custom"
        assert entry["level"] == "INFO"
        assert (
            entry["message"]
            == "Events flush recovered after 3 consecutive partial failure(s)"
        )
        assert entry["timestamp"]


@pytest.mark.parametrize(
    "log_format, expected",
    [("json", JsonFormatter), ("text", logging.Formatter)],
)
def test_create_formatter_branches(log_format: str, expected: type) -> None:
    assert isinstance(_create_formatter(log_format), expected)
