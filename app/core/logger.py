import logging
import sys
from typing import Any

import structlog

from app.core.config import settings


def _configure_stdlib_logging() -> None:
    logging.basicConfig(
        level=settings.log_level,
        format="%(message)s",
        stream=sys.stdout,
    )


def configure_logging() -> None:
    _configure_stdlib_logging()

    timestamper = structlog.processors.TimeStamper(fmt="iso")

    processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        timestamper,
    ]

    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(**initial_values: Any) -> structlog.stdlib.BoundLogger:
    logger = structlog.get_logger()
    if initial_values:
        logger = logger.bind(**initial_values)
    return logger
