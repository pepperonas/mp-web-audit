"""Tests fuer das Scoring-Modul."""

from webaudit.core.models import AuditReport, Finding, ScanResult, Severity
from webaudit.core.scoring import calculate_scores


class TestCalculateScores:
    def test_empty_report(self):
        report = AuditReport(target_url="https://example.com")
        scores = calculate_scores(report)
        assert scores == {}

    def test_performance_score_from_raw_data(self):
        result = ScanResult(
            scanner_name="performance",
            kategorie="Performance",
            raw_data={
                "ttfb_ms": 100,
                "page_size_kb": 500,
                "redirect_count": 0,
                "has_compression": True,
            },
        )
        report = AuditReport(target_url="https://example.com", results=[result])
        scores = calculate_scores(report)
        assert scores["Performance"] == 100.0

    def test_slow_ttfb_reduces_score(self):
        result = ScanResult(
            scanner_name="performance",
            kategorie="Performance",
            raw_data={
                "ttfb_ms": 1500,
                "page_size_kb": 100,
                "redirect_count": 0,
                "has_compression": True,
            },
        )
        report = AuditReport(target_url="https://example.com", results=[result])
        scores = calculate_scores(report)
        assert scores["Performance"] < 100.0

    def test_severity_penalty_scoring(self):
        findings = [
            Finding(
                scanner="test", kategorie="X", titel="A", severity=Severity.HOCH, beschreibung=""
            ),
            Finding(
                scanner="test", kategorie="X", titel="B", severity=Severity.MITTEL, beschreibung=""
            ),
        ]
        result = ScanResult(scanner_name="usability", kategorie="Usability", findings=findings)
        report = AuditReport(target_url="https://example.com", results=[result])
        scores = calculate_scores(report)
        assert scores["Usability"] < 100.0
        assert scores["Usability"] > 0.0

    def test_custom_weights(self):
        result = ScanResult(
            scanner_name="performance",
            kategorie="Performance",
            raw_data={
                "ttfb_ms": 100,
                "page_size_kb": 100,
                "redirect_count": 0,
                "has_compression": True,
            },
        )
        report = AuditReport(target_url="https://example.com", results=[result])
        custom = {"Performance": 1.0}
        scores = calculate_scores(report, custom_weights=custom)
        assert "Gesamt" in scores
        assert scores["Gesamt"] == 100.0

    def test_headers_score(self):
        result = ScanResult(
            scanner_name="headers",
            kategorie="Sicherheit",
            raw_data={
                "present_headers": [
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                    "permissions-policy",
                ]
            },
        )
        report = AuditReport(target_url="https://example.com", results=[result])
        scores = calculate_scores(report)
        assert scores["Sicherheit"] == 100.0

    def test_failed_scanner_excluded(self):
        result = ScanResult(scanner_name="performance", kategorie="Performance", success=False)
        report = AuditReport(target_url="https://example.com", results=[result])
        scores = calculate_scores(report)
        # Failed scanner should be excluded from scoring, so no Performance score
        assert "Performance" not in scores
