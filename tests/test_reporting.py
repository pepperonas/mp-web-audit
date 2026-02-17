"""Tests fuer das Reporting-System."""

import json
import tempfile
from datetime import datetime
from pathlib import Path

from webaudit.core.models import AuditReport, Finding, ScanResult, Severity
from webaudit.reporting.html_reporter import (
    _generate_improvements,
    _prepare_template_context,
    _radar_points,
    generate_html_report,
)
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


def _full_report() -> AuditReport:
    """Report mit SEO-, Performance- und Mobile-Scanner raw_data."""
    return AuditReport(
        target_url="https://example.com",
        zeitstempel=datetime(2025, 1, 15, 14, 30),
        dauer=12.5,
        scores={
            "Sicherheit": 60.0,
            "Performance": 75.0,
            "SEO": 50.0,
            "Mobile": 80.0,
            "Usability": 70.0,
            "Techstack": 90.0,
            "Gesamt": 68.0,
        },
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
            ScanResult(
                scanner_name="seo",
                kategorie="SEO",
                findings=[
                    Finding(
                        scanner="seo",
                        kategorie="SEO",
                        titel="Title fehlt",
                        severity=Severity.HOCH,
                        beschreibung="Kein Title-Tag.",
                        empfehlung="Title-Tag setzen.",
                    ),
                ],
                raw_data={
                    "has_title": False,
                    "has_meta_description": True,
                    "has_h1": True,
                    "has_canonical": False,
                    "has_lang": True,
                    "has_og_tags": False,
                    "has_structured_data": True,
                    "has_robots_txt": True,
                    "has_sitemap": False,
                    "has_hreflang": False,
                },
            ),
            ScanResult(
                scanner_name="performance",
                kategorie="Performance",
                findings=[],
                raw_data={
                    "ttfb_ms": 320.5,
                    "page_size_kb": 450.2,
                    "redirect_count": 1,
                    "has_compression": True,
                    "content_encoding": "gzip",
                    "render_blocking_scripts": 2,
                    "legacy_image_count": 5,
                    "has_http2_or_h3": True,
                },
            ),
            ScanResult(
                scanner_name="mobile",
                kategorie="Mobile",
                findings=[],
                raw_data={
                    "has_viewport": True,
                    "has_responsive_meta": True,
                    "small_tap_targets": 3,
                },
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


class TestRadarPoints:
    def test_returns_6_points(self):
        scores = {"Sicherheit": 80, "Performance": 60, "SEO": 70}
        points = _radar_points(scores)
        assert len(points) == 6

    def test_zero_scores_center(self):
        points = _radar_points({})
        for p in points:
            assert p["score"] == 0
            # All points should be at center (200, 200)
            assert p["x"] == 200.0 or abs(p["x"] - 200.0) < 0.5
            assert p["y"] == 200.0 or abs(p["y"] - 200.0) < 0.5

    def test_full_score_at_max_radius(self):
        scores = {
            "Sicherheit": 100,
            "Performance": 100,
            "SEO": 100,
            "Mobile": 100,
            "Usability": 100,
            "Techstack": 100,
        }
        points = _radar_points(scores, cx=200, cy=200, max_r=160)
        for p in points:
            assert p["score"] == 100
            # Distance from center should be ~160
            dist = ((p["x"] - 200) ** 2 + (p["y"] - 200) ** 2) ** 0.5
            assert abs(dist - 160) < 1

    def test_points_have_required_keys(self):
        points = _radar_points({"Sicherheit": 50})
        for p in points:
            assert "x" in p
            assert "y" in p
            assert "score" in p
            assert "label" in p


class TestPrepareTemplateContext:
    def test_with_full_data(self):
        report = _full_report()
        ctx = _prepare_template_context(report)

        # Radar
        assert len(ctx["radar_polygon"]) == 6
        assert len(ctx["radar_grid_rings"]) == 3
        assert len(ctx["radar_labels"]) == 6
        assert len(ctx["radar_axes"]) == 6

        # SEO
        assert len(ctx["seo_checks"]) == 10
        assert (
            ctx["seo_pass_count"] == 5
        )  # title=F, desc=T, h1=T, canonical=F, lang=T, og=F, sd=T, robots=T, sitemap=F, hreflang=F

        # Performance
        assert ctx["perf_metrics"]["ttfb_ms"] == 320.5
        assert ctx["perf_metrics"]["ttfb_rating"] == "mittel"
        assert ctx["perf_metrics"]["size_rating"] == "gut"
        assert ctx["perf_metrics"]["has_compression"] is True

        # Improvements
        assert "SEO" in ctx["improvements"]
        assert "Sicherheit" in ctx["improvements"]

    def test_without_scanner_data(self):
        report = _sample_report()
        ctx = _prepare_template_context(report)

        # Should gracefully return empty data
        assert ctx["seo_checks"] == []
        assert ctx["seo_pass_count"] == 0
        assert ctx["perf_metrics"] == {}

    def test_radar_present_even_without_all_scores(self):
        report = _sample_report()
        ctx = _prepare_template_context(report)

        # Radar is always computed from scores
        assert len(ctx["radar_polygon"]) == 6


class TestGenerateImprovements:
    def test_seo_improvements(self):
        scanner_data = {
            "seo": {
                "has_title": False,
                "has_meta_description": False,
                "has_h1": True,
                "has_canonical": True,
                "has_lang": True,
                "has_og_tags": True,
                "has_structured_data": True,
                "has_robots_txt": True,
                "has_sitemap": False,
                "has_hreflang": True,
            },
        }
        report = AuditReport(
            target_url="https://example.com",
            zeitstempel=datetime(2025, 1, 1),
        )
        improvements = _generate_improvements(report, scanner_data)

        assert "SEO" in improvements
        seo = improvements["SEO"]
        # Title, Meta-Desc, Sitemap missing
        assert len(seo) == 3
        # Title should be Sofort/Hoch
        title_item = next(i for i in seo if "Title" in i["text"])
        assert title_item["prioritaet"] == "Sofort"
        assert title_item["auswirkung"] == "Hoch"
        # Sitemap should be Kurzfristig
        sitemap_item = next(i for i in seo if "Sitemap" in i["text"])
        assert sitemap_item["prioritaet"] == "Kurzfristig"

    def test_perf_improvements_high_ttfb(self):
        scanner_data = {
            "performance": {
                "ttfb_ms": 800,
                "has_compression": True,
                "render_blocking_scripts": 0,
                "legacy_image_count": 0,
                "page_size_kb": 200,
                "has_http2_or_h3": True,
            },
        }
        report = AuditReport(
            target_url="https://example.com",
            zeitstempel=datetime(2025, 1, 1),
        )
        improvements = _generate_improvements(report, scanner_data)

        assert "Performance" in improvements
        perf = improvements["Performance"]
        assert len(perf) == 1
        assert "TTFB" in perf[0]["text"]
        assert perf[0]["prioritaet"] == "Sofort"

    def test_security_improvements_from_findings(self):
        report = AuditReport(
            target_url="https://example.com",
            zeitstempel=datetime(2025, 1, 1),
            results=[
                ScanResult(
                    scanner_name="headers",
                    kategorie="Sicherheit",
                    findings=[
                        Finding(
                            scanner="headers",
                            kategorie="Sicherheit",
                            titel="CSP fehlt",
                            severity=Severity.KRITISCH,
                            beschreibung="CSP fehlt.",
                            empfehlung="CSP setzen.",
                        ),
                    ],
                ),
            ],
        )
        improvements = _generate_improvements(report, {})

        assert "Sicherheit" in improvements
        assert improvements["Sicherheit"][0]["text"] == "CSP setzen."
        assert improvements["Sicherheit"][0]["prioritaet"] == "Sofort"

    def test_mobile_improvements(self):
        scanner_data = {
            "mobile": {
                "has_viewport": False,
                "has_responsive_meta": False,
                "small_tap_targets": 5,
            },
        }
        report = AuditReport(
            target_url="https://example.com",
            zeitstempel=datetime(2025, 1, 1),
        )
        improvements = _generate_improvements(report, scanner_data)

        assert "Mobile" in improvements
        assert len(improvements["Mobile"]) == 3

    def test_no_improvements_when_all_good(self):
        scanner_data = {
            "seo": {
                "has_title": True,
                "has_meta_description": True,
                "has_h1": True,
                "has_canonical": True,
                "has_lang": True,
                "has_og_tags": True,
                "has_structured_data": True,
                "has_robots_txt": True,
                "has_sitemap": True,
                "has_hreflang": True,
            },
            "performance": {
                "ttfb_ms": 100,
                "has_compression": True,
                "render_blocking_scripts": 0,
                "legacy_image_count": 0,
                "page_size_kb": 200,
                "has_http2_or_h3": True,
            },
            "mobile": {
                "has_viewport": True,
                "has_responsive_meta": True,
                "small_tap_targets": 0,
            },
        }
        report = AuditReport(
            target_url="https://example.com",
            zeitstempel=datetime(2025, 1, 1),
        )
        improvements = _generate_improvements(report, scanner_data)
        assert improvements == {}


class TestHtmlOutputContainsNewSections:
    def test_full_report_has_all_sections(self):
        report = _full_report()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.html"
            generate_html_report(report, path)
            html = path.read_text()

            assert 'id="radar"' in html
            assert "Kategorie-Radar" in html
            assert 'id="seo-details"' in html
            assert "SEO-Details" in html
            assert 'id="perf-details"' in html
            assert "Performance-Details" in html
            assert 'id="improvements"' in html
            assert "Verbesserungsvorschlaege" in html

            # Radar SVG elements
            assert "radar-svg" in html
            assert "<polygon" in html
            assert "<circle" in html

            # SEO checklist
            assert "check-pass" in html
            assert "check-fail" in html
            assert "5/10" in html

            # Performance metrics
            assert "TTFB" in html
            assert "320" in html  # TTFB value
            assert "metric-tile" in html

            # Improvements
            assert "priority-sofort" in html
            assert "impact-badge" in html

            # TOC links
            assert 'href="#radar"' in html
            assert 'href="#seo-details"' in html
            assert 'href="#perf-details"' in html
            assert 'href="#improvements"' in html

    def test_minimal_report_omits_new_sections(self):
        """Sektionen fehlen graceful wenn Scanner nicht gelaufen."""
        report = AuditReport(
            target_url="https://example.com",
            zeitstempel=datetime(2025, 1, 1),
            dauer=1.0,
            results=[],
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "report.html"
            generate_html_report(report, path)
            html = path.read_text()

            assert "Web-Audit Report" in html
            assert 'id="seo-details"' not in html
            assert 'id="perf-details"' not in html
            assert 'id="improvements"' not in html
