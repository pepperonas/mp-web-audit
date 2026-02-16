"""Tests fuer das Reporting-System."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

from webaudit.core.models import AuditReport, Finding, ScanResult, Severity
from webaudit.reporting.html_reporter import generate_html_report
from webaudit.reporting.json_reporter import generate_json_report, load_report_from_json


def _sample_report() -> AuditReport:
    return AuditReport(
        target_url="https://example.com",
        zeitstempel=datetime(2025, 1, 15, 14, 30),
        dauer=12.5,
        scores={"Performance": 85.0, "Sicherheit": 60.0, "Gesamt": 72.5},
        results=[
            ScanResult(
                scanner_name="headers",
                kategorie="Sicherheit",
                findings=[
                    Finding(
                        scanner="headers",
                        kategorie="Sicherheit",
                        titel="CSP fehlt",
                        severity=Severity.HOCH,
                        beschreibung="Content-Security-Policy fehlt.",
                        empfehlung="CSP setzen.",
                    ),
                ],
                raw_data={"present_headers": ["hsts"]},
            ),
        ],
    )


class TestJsonReporter:
    def test_roundtrip(self):
        report = _sample_report()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.json"
            generate_json_report(report, path)

            assert path.exists()
            data = json.loads(path.read_text())
            assert data["target_url"] == "https://example.com"
            assert len(data["results"]) == 1

            loaded = load_report_from_json(path)
            assert loaded.target_url == report.target_url
            assert len(loaded.results) == 1
            assert loaded.scores["Gesamt"] == 72.5


class TestHtmlReporter:
    def test_generates_html(self):
        report = _sample_report()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.html"
            generate_html_report(report, path)

            assert path.exists()
            html = path.read_text()
            assert "Web-Audit Report" in html
            assert "example.com" in html
            assert "CSP fehlt" in html
            assert "<style>" in html  # CSS eingebettet
