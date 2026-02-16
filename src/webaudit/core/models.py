"""Pydantic-Datenmodelle fuer mp-web-audit."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Schweregrad eines Findings - auf Deutsch."""

    KRITISCH = "KRITISCH"
    HOCH = "HOCH"
    MITTEL = "MITTEL"
    NIEDRIG = "NIEDRIG"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            Severity.KRITISCH: "red",
            Severity.HOCH: "orange1",
            Severity.MITTEL: "yellow",
            Severity.NIEDRIG: "blue",
            Severity.INFO: "green",
        }[self]

    @property
    def sort_order(self) -> int:
        return {
            Severity.KRITISCH: 0,
            Severity.HOCH: 1,
            Severity.MITTEL: 2,
            Severity.NIEDRIG: 3,
            Severity.INFO: 4,
        }[self]


class Finding(BaseModel):
    """Ein einzelnes Ergebnis eines Scanners."""

    scanner: str
    kategorie: str
    titel: str
    severity: Severity
    beschreibung: str
    beweis: str = ""
    empfehlung: str = ""
    referenzen: list[str] = Field(default_factory=list)
    cwe_id: str = ""
    cwe_name: str = ""
    owasp_category: str = ""


class ScanResult(BaseModel):
    """Ergebnis eines einzelnen Scanners."""

    scanner_name: str
    kategorie: str
    success: bool = True
    error: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    dauer: float = 0.0


class AutorisierungInfo(BaseModel):
    """Dokumentation der Autorisierungs-Bestaetigung."""

    bestaetigt: bool
    zeitstempel: datetime
    ziel: str
    scan_typ: str


class ScanMetadata(BaseModel):
    """Metadaten zum Scan-Durchlauf."""

    tool_version: str = ""
    python_version: str = ""
    scan_config: dict[str, Any] = Field(default_factory=dict)
    scanner_scores: dict[str, float] = Field(default_factory=dict)


class AuditReport(BaseModel):
    """Kompletter Audit-Report."""

    target_url: str
    target_ip: str = ""
    zeitstempel: datetime = Field(default_factory=datetime.now)
    dauer: float = 0.0
    results: list[ScanResult] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)
    autorisierung: AutorisierungInfo | None = None
    metadata: ScanMetadata | None = None

    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for r in self.results:
            findings.extend(r.findings)
        findings.sort(key=lambda f: f.severity.sort_order)
        return findings

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for f in self.all_findings:
            result.setdefault(f.severity, []).append(f)
        return result

    def deduplicated_findings(self) -> list[Finding]:
        """Dedupliziert Findings nach (titel, severity) Tupel."""
        seen: set[tuple[str, str]] = set()
        deduped: list[Finding] = []
        for f in self.all_findings:
            key = (f.titel, f.severity.value)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped


class ScanContext(BaseModel):
    """Kontext der an Scanner uebergeben wird."""

    model_config = {"arbitrary_types_allowed": True}

    target_url: str
    final_url: str = ""
    status_code: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    soup: BeautifulSoup | None = None
    redirects: list[str] = Field(default_factory=list)
    response_time: float = 0.0
    cookies: dict[str, Any] = Field(default_factory=dict)
