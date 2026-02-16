"""BaseScanner ABC - Basis fuer alle Scanner."""

from __future__ import annotations

from abc import ABC, abstractmethod

from webaudit.core.config import ScanConfig
from webaudit.core.http_client import AuditHttpClient
from webaudit.core.models import ScanContext, ScanResult


class BaseScanner(ABC):
    """Abstrakte Basisklasse fuer alle Scanner."""

    name: str = ""
    description: str = ""
    category: str = ""  # "web", "security", "techstack", "discovery"

    def __init__(self, config: ScanConfig, http_client: AuditHttpClient) -> None:
        self.config = config
        self.http = http_client

    @abstractmethod
    async def scan(self, context: ScanContext) -> ScanResult:
        """Fuehrt den Scan durch und liefert Ergebnisse."""
        ...

    async def setup(self) -> None:
        """Optionale Vorbereitung vor dem Scan."""

    async def teardown(self) -> None:
        """Optionale Aufraeumarbeiten nach dem Scan."""

    def is_available(self) -> bool:
        """Prueft ob externe Abhaengigkeiten verfuegbar sind."""
        return True
