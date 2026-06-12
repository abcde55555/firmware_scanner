"""Unified logging configuration for firmware_scanner."""
from __future__ import annotations

import logging
import sys


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    """Configure logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    handlers: list[logging.Handler] = [console_handler]

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers, force=True)

    # Suppress noisy third-party loggers
    logging.getLogger("lief").setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a module."""
    return logging.getLogger(name)
