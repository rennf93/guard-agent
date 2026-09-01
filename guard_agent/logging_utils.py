import json
import logging
import os

logger = logging.getLogger("guard_agent")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_entry, default=str)


def _create_formatter(log_format: str) -> logging.Formatter:
    if log_format == "json":
        return JsonFormatter()
    return logging.Formatter("[%(name)s] %(asctime)s - %(levelname)s - %(message)s")


class _YieldToHostRootHandlers(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not logging.getLogger().handlers


def logger_is_configured(candidate: logging.Logger) -> bool:
    return bool(candidate.handlers)


def _attach_handlers(
    logger: logging.Logger, log_file: str | None, log_format: str
) -> logging.Logger:
    formatter = _create_formatter(log_format)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(_YieldToHostRootHandlers())
    logger.addHandler(console_handler)

    if log_file:
        try:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Failed to create log file {log_file}: {e}")

    return logger


def setup_agent_logging(
    log_file: str | None = None,
    log_format: str = "text",
    *,
    reconfigure: bool = True,
) -> logging.Logger:
    logger = logging.getLogger("guard_agent")

    if not reconfigure:
        if logger_is_configured(logger):
            return logger
        if logger.level == logging.NOTSET:
            logger.setLevel(logging.INFO)
        return _attach_handlers(logger, log_file, log_format)

    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)

    logger.setLevel(logging.INFO)

    return _attach_handlers(logger, log_file, log_format)
