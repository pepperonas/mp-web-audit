"""Tests fuer Pydantic-Datenmodelle."""

from datetime import datetime

from webaudit.core.models import (
    AuditReport,
    Finding,
    ScanResult,
    Severity,
)


class TestSeverity:
    def test_sort_order(self):
        assert Severity.KRITISCH.sort_order < Severity.HOCH.sort_order
        assert Severity.HOCH.sort_order < Severity.MITTEL.sort_order
        assert Severity.MITTEL.sort_order < Severity.NIEDRIG.sort_order
        assert Severity.NIEDRIG.sort_order < Severity.INFO.sort_order

    def test_colors(self):
        assert Severity.KRITISCH.color == "red"
        assert Severity.INFO.color == "green"


class TestFinding:
    def test_create_finding(self):
        f = Finding(
            scanner="headers",
            kategorie="Sicherheit",
            titel="Test Finding",
            severity=Severity.HOCH,
            beschreibung="Testbeschreibung",
        )
        assert f.scanner == "headers"
        assert f.severity == Severity.HOCH
        assert f.beweis == ""
        assert f.referenzen == []


class TestScanResult:
    def test_create_result(self):
        r = ScanResult(scanner_name="headers", kategorie="Sicherheit")
        assert r.success is True
        assert r.findings == []
        assert r.raw_data == {}

    def test_result_with_findings(self):
        f = Finding(
            scanner="headers", kategorie="Sicherheit",
            titel="Test", severity=Severity.INFO, beschreibung="Test",
        )
        r = ScanResult(scanner_name="headers", kategorie="Sicherheit", findings=[f])
        assert len(r.findings) == 1


class TestAuditReport:
    def test_all_findings_sorted(self):
        f_info = Finding(scanner="a", kategorie="X", titel="Info", severity=Severity.INFO, beschreibung="")
        f_krit = Finding(scanner="b", kategorie="Y", titel="Krit", severity=Severity.KRITISCH, beschreibung="")
        report = AuditReport(
            target_url="https://example.com",
            results=[
                ScanResult(scanner_name="a", kategorie="X", findings=[f_info]),
                ScanResult(scanner_name="b", kategorie="Y", findings=[f_krit]),
            ],
        )
        findings = report.all_findings
        assert findings[0].severity == Severity.KRITISCH
        assert findings[1].severity == Severity.INFO

    def test_findings_by_severity(self):
        findings = [
            Finding(scanner="a", kategorie="X", titel="1", severity=Severity.HOCH, beschreibung=""),
            Finding(scanner="a", kategorie="X", titel="2", severity=Severity.HOCH, beschreibung=""),
            Finding(scanner="a", kategorie="X", titel="3", severity=Severity.INFO, beschreibung=""),
        ]
        report = AuditReport(
            target_url="https://example.com",
            results=[ScanResult(scanner_name="a", kategorie="X", findings=findings)],
        )
        by_sev = report.findings_by_severity
        assert len(by_sev[Severity.HOCH]) == 2
        assert len(by_sev[Severity.INFO]) == 1
