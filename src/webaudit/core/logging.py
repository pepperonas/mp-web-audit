"""Structured Logging fuer mp-web-audit."""

from __future__ import annotations

import logging
import sys


def setup_logging(verbose: bool = False, log_file: str | None = None) -> logging.Logger:
    """Konfiguriert das Logging-System.

    Console-Handler geht auf stderr (stoert --json-stdout nicht).
    File-Handler optional.
    """
    logger = logging.getLogger("webaudit")
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)

    # Bestehende Handler entfernen (bei Mehrfachaufruf)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console-Handler auf stderr
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File-Handler optional
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
