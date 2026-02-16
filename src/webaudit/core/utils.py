"""Hilfsfunktionen fuer mp-web-audit."""

from __future__ import annotations

import time
from contextlib import contextmanager
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """Normalisiert eine URL (fuegt Schema hinzu wenn noetig)."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    # Trailing Slash entfernen (ausser root)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def extract_domain(url: str) -> str:
    """Extrahiert die Domain aus einer URL."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]


@contextmanager
def timer():
    """Kontextmanager der die vergangene Zeit misst."""
    t = {"elapsed": 0.0}
    start = time.monotonic()
    try:
        yield t
    finally:
        t["elapsed"] = round(time.monotonic() - start, 3)


def format_bytes(size_bytes: int) -> str:
    """Formatiert Bytes in menschenlesbare Groesse."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} TB"
