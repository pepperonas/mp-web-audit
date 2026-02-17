"""HTML-Report via Jinja2 (Single-File, portable)."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from webaudit.core.models import AuditReport, Severity

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Kategorie-Reihenfolge fuer Radar-Chart (6 Achsen)
_RADAR_CATEGORIES = [
    "Sicherheit",
    "Performance",
    "SEO",
    "Mobile",
    "Usability",
    "Techstack",
]


def _score_color_class(score: float) -> str:
    if score >= 80:
        return "score-green"
    if score >= 60:
        return "score-yellow"
    if score >= 40:
        return "score-orange"
    return "score-red"


def _bar_color_class(score: float) -> str:
    if score >= 80:
        return "bar-green"
    if score >= 60:
        return "bar-yellow"
    if score >= 40:
        return "bar-orange"
    return "bar-red"


def _radar_points(
    scores: dict[str, float],
    cx: float = 200,
    cy: float = 200,
    max_r: float = 160,
) -> list[dict[str, Any]]:
    """Berechnet SVG-Polygon-Koordinaten fuer ein 6-Eck-Radar-Chart.

    Gibt eine Liste von Dicts mit x, y, score, label zurueck.
    """
    n = len(_RADAR_CATEGORIES)
    points: list[dict[str, Any]] = []
    for i, cat in enumerate(_RADAR_CATEGORIES):
        score = scores.get(cat, 0)
        angle = (2 * math.pi * i / n) - math.pi / 2  # Start oben
        r = max_r * (score / 100)
        x = cx + r * math.cos(angle)
        y = cy + r * math.sin(angle)
        points.append({"x": round(x, 1), "y": round(y, 1), "score": score, "label": cat})
    return points


def _radar_grid_rings(
    cx: float = 200,
    cy: float = 200,
    max_r: float = 160,
    percentages: tuple[float, ...] = (0.33, 0.66, 1.0),
) -> list[list[dict[str, float]]]:
    """Erzeugt konzentrische Ringe fuer das Radar-Grid."""
    n = len(_RADAR_CATEGORIES)
    rings: list[list[dict[str, float]]] = []
    for pct in percentages:
        ring: list[dict[str, float]] = []
        r = max_r * pct
        for i in range(n):
            angle = (2 * math.pi * i / n) - math.pi / 2
            ring.append(
                {"x": round(cx + r * math.cos(angle), 1), "y": round(cy + r * math.sin(angle), 1)}
            )
        rings.append(ring)
    return rings


def _radar_labels(
    scores: dict[str, float],
    cx: float = 200,
    cy: float = 200,
    max_r: float = 160,
    label_offset: float = 25,
) -> list[dict[str, Any]]:
    """Erzeugt Label-Positionen fuer das Radar-Chart."""
    n = len(_RADAR_CATEGORIES)
    labels: list[dict[str, Any]] = []
    for i, cat in enumerate(_RADAR_CATEGORIES):
        angle = (2 * math.pi * i / n) - math.pi / 2
        r = max_r + label_offset
        x = cx + r * math.cos(angle)
        y = cy + r * math.sin(angle)
        score = scores.get(cat, 0)
        anchor = "middle"
        if x < cx - 10:
            anchor = "end"
        elif x > cx + 10:
            anchor = "start"
        labels.append(
            {
                "x": round(x, 1),
                "y": round(y, 1),
                "label": cat,
                "score": score,
                "anchor": anchor,
            }
        )
    return labels


def _prepare_seo_checks(
    scanner_data: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Extrahiert SEO-Checks aus raw_data des SEO-Scanners."""
    seo_raw = scanner_data.get("seo", {})
    if not seo_raw:
        return [], 0

    checks = [
        {"label": "Title-Tag", "passed": seo_raw.get("has_title", False)},
        {"label": "Meta-Description", "passed": seo_raw.get("has_meta_description", False)},
        {"label": "H1-Ueberschrift", "passed": seo_raw.get("has_h1", False)},
        {"label": "Canonical-URL", "passed": seo_raw.get("has_canonical", False)},
        {"label": "Lang-Attribut", "passed": seo_raw.get("has_lang", False)},
        {"label": "Open-Graph-Tags", "passed": seo_raw.get("has_og_tags", False)},
        {"label": "Structured Data", "passed": seo_raw.get("has_structured_data", False)},
        {"label": "robots.txt", "passed": seo_raw.get("has_robots_txt", False)},
        {"label": "Sitemap", "passed": seo_raw.get("has_sitemap", False)},
        {"label": "hreflang", "passed": seo_raw.get("has_hreflang", False)},
    ]
    pass_count = sum(1 for c in checks if c["passed"])
    return checks, pass_count


def _prepare_perf_metrics(scanner_data: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Extrahiert Performance-Metriken aus raw_data des Performance-Scanners."""
    perf_raw = scanner_data.get("performance", {})
    if not perf_raw:
        return {}

    ttfb = perf_raw.get("ttfb_ms", 0)
    size_kb = perf_raw.get("page_size_kb", 0)

    if ttfb <= 200:
        ttfb_rating = "gut"
    elif ttfb <= 500:
        ttfb_rating = "mittel"
    else:
        ttfb_rating = "schlecht"

    if size_kb <= 500:
        size_rating = "gut"
    elif size_kb <= 1500:
        size_rating = "mittel"
    else:
        size_rating = "schlecht"

    return {
        "ttfb_ms": ttfb,
        "page_size_kb": size_kb,
        "redirect_count": perf_raw.get("redirect_count", 0),
        "has_compression": perf_raw.get("has_compression", False),
        "content_encoding": perf_raw.get("content_encoding", ""),
        "render_blocking_scripts": perf_raw.get("render_blocking_scripts", 0),
        "legacy_image_count": perf_raw.get("legacy_image_count", 0),
        "has_http2_or_h3": perf_raw.get("has_http2_or_h3", False),
        "ttfb_rating": ttfb_rating,
        "size_rating": size_rating,
    }


def _generate_improvements(
    report: AuditReport,
    scanner_data: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, str]]]:
    """Erzeugt priorisierte Verbesserungsvorschlaege nach Kategorie."""
    improvements: dict[str, list[dict[str, str]]] = {}

    # SEO-Verbesserungen
    seo_raw = scanner_data.get("seo", {})
    if seo_raw:
        seo_items: list[dict[str, str]] = []
        if not seo_raw.get("has_title"):
            seo_items.append(
                {
                    "text": "Title-Tag hinzufuegen – wichtigster On-Page SEO-Faktor",
                    "prioritaet": "Sofort",
                    "auswirkung": "Hoch",
                }
            )
        if not seo_raw.get("has_meta_description"):
            seo_items.append(
                {
                    "text": "Meta-Description ergaenzen fuer bessere Klickraten in Suchergebnissen",
                    "prioritaet": "Sofort",
                    "auswirkung": "Hoch",
                }
            )
        if not seo_raw.get("has_h1"):
            seo_items.append(
                {
                    "text": "H1-Ueberschrift hinzufuegen – strukturiert den Seiteninhalt",
                    "prioritaet": "Sofort",
                    "auswirkung": "Mittel",
                }
            )
        if not seo_raw.get("has_canonical"):
            seo_items.append(
                {
                    "text": "Canonical-URL setzen um Duplicate Content zu vermeiden",
                    "prioritaet": "Kurzfristig",
                    "auswirkung": "Mittel",
                }
            )
        if not seo_raw.get("has_sitemap"):
            seo_items.append(
                {
                    "text": "XML-Sitemap erstellen und einreichen",
                    "prioritaet": "Kurzfristig",
                    "auswirkung": "Mittel",
                }
            )
        if not seo_raw.get("has_structured_data"):
            seo_items.append(
                {
                    "text": "Structured Data (JSON-LD) implementieren fuer Rich Snippets",
                    "prioritaet": "Mittelfristig",
                    "auswirkung": "Mittel",
                }
            )
        if not seo_raw.get("has_og_tags"):
            seo_items.append(
                {
                    "text": "Open-Graph-Tags fuer Social-Media-Vorschauen hinzufuegen",
                    "prioritaet": "Mittelfristig",
                    "auswirkung": "Niedrig",
                }
            )
        if seo_items:
            improvements["SEO"] = seo_items

    # Performance-Verbesserungen
    perf_raw = scanner_data.get("performance", {})
    if perf_raw:
        perf_items: list[dict[str, str]] = []
        ttfb = perf_raw.get("ttfb_ms", 0)
        if ttfb > 500:
            perf_items.append(
                {
                    "text": f"TTFB reduzieren (aktuell {ttfb:.0f}ms) – Server-Caching oder CDN einsetzen",
                    "prioritaet": "Sofort",
                    "auswirkung": "Hoch",
                }
            )
        if not perf_raw.get("has_compression"):
            perf_items.append(
                {
                    "text": "Komprimierung aktivieren (gzip/Brotli) – spart erheblich Bandbreite",
                    "prioritaet": "Sofort",
                    "auswirkung": "Hoch",
                }
            )
        blocking = perf_raw.get("render_blocking_scripts", 0)
        if blocking > 0:
            perf_items.append(
                {
                    "text": f"{blocking} render-blockierende Scripts mit async/defer laden",
                    "prioritaet": "Sofort",
                    "auswirkung": "Hoch",
                }
            )
        legacy = perf_raw.get("legacy_image_count", 0)
        if legacy > 0:
            perf_items.append(
                {
                    "text": f"{legacy} Bilder in moderne Formate (WebP/AVIF) konvertieren",
                    "prioritaet": "Kurzfristig",
                    "auswirkung": "Mittel",
                }
            )
        size_kb = perf_raw.get("page_size_kb", 0)
        if size_kb > 1500:
            perf_items.append(
                {
                    "text": f"Seitengroesse reduzieren (aktuell {size_kb:.0f} KB)",
                    "prioritaet": "Kurzfristig",
                    "auswirkung": "Mittel",
                }
            )
        if not perf_raw.get("has_http2_or_h3"):
            perf_items.append(
                {
                    "text": "HTTP/2 oder HTTP/3 aktivieren fuer schnelleres Laden",
                    "prioritaet": "Mittelfristig",
                    "auswirkung": "Mittel",
                }
            )
        if perf_items:
            improvements["Performance"] = perf_items

    # Sicherheits-Verbesserungen aus KRITISCH/HOCH-Findings
    sec_items: list[dict[str, str]] = []
    for finding in report.all_findings:
        if finding.kategorie == "Sicherheit" and finding.empfehlung:
            if finding.severity == Severity.KRITISCH:
                sec_items.append(
                    {
                        "text": finding.empfehlung,
                        "prioritaet": "Sofort",
                        "auswirkung": "Hoch",
                    }
                )
            elif finding.severity == Severity.HOCH:
                sec_items.append(
                    {
                        "text": finding.empfehlung,
                        "prioritaet": "Sofort",
                        "auswirkung": "Hoch",
                    }
                )
    if sec_items:
        improvements["Sicherheit"] = sec_items

    # Mobile-Verbesserungen
    mobile_raw = scanner_data.get("mobile", {})
    if mobile_raw:
        mobile_items: list[dict[str, str]] = []
        if not mobile_raw.get("has_viewport"):
            mobile_items.append(
                {
                    "text": "Viewport Meta-Tag hinzufuegen fuer mobile Darstellung",
                    "prioritaet": "Sofort",
                    "auswirkung": "Hoch",
                }
            )
        if not mobile_raw.get("has_responsive_meta"):
            mobile_items.append(
                {
                    "text": "Responsive Viewport konfigurieren (width=device-width)",
                    "prioritaet": "Sofort",
                    "auswirkung": "Hoch",
                }
            )
        small_taps = mobile_raw.get("small_tap_targets", 0)
        if small_taps > 0:
            mobile_items.append(
                {
                    "text": f"{small_taps} Touch-Ziele auf mindestens 44x44px vergroessern",
                    "prioritaet": "Kurzfristig",
                    "auswirkung": "Mittel",
                }
            )
        if mobile_items:
            improvements["Mobile"] = mobile_items

    return improvements


def _extract_scanner_data(report: AuditReport) -> dict[str, dict[str, Any]]:
    """Extrahiert raw_data aus Report-Ergebnissen, indiziert nach Scanner-Name."""
    data: dict[str, dict[str, Any]] = {}
    for result in report.results:
        if result.raw_data:
            data[result.scanner_name] = result.raw_data
    return data


def _prepare_template_context(report: AuditReport) -> dict[str, Any]:
    """Bereitet alle zusaetzlichen Template-Variablen auf."""
    scores = {k: v for k, v in report.scores.items() if k != "Gesamt"}
    scanner_data = _extract_scanner_data(report)

    # Radar-Chart
    radar_polygon = _radar_points(scores)
    radar_grid = _radar_grid_rings()
    radar_lbls = _radar_labels(scores)

    # Achsenlinien (vom Zentrum zu den aeusseren Punkten)
    radar_axes = radar_grid[-1] if radar_grid else []

    # SEO-Dashboard
    seo_checks, seo_pass_count = _prepare_seo_checks(scanner_data)

    # Performance-Dashboard
    perf_metrics = _prepare_perf_metrics(scanner_data)

    # Verbesserungsvorschlaege
    improvements = _generate_improvements(report, scanner_data)

    return {
        "radar_polygon": radar_polygon,
        "radar_grid_rings": radar_grid,
        "radar_labels": radar_lbls,
        "radar_axes": radar_axes,
        "seo_checks": seo_checks,
        "seo_pass_count": seo_pass_count,
        "perf_metrics": perf_metrics,
        "improvements": improvements,
    }


def generate_html_report(report: AuditReport, output_path: Path) -> Path:
    """Generiert einen portablen HTML-Report (CSS eingebettet)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    env.globals["score_color_class"] = _score_color_class
    env.globals["bar_color_class"] = _bar_color_class

    css = (TEMPLATES_DIR / "style.css").read_text()
    template = env.get_template("report.html.j2")

    ctx = _prepare_template_context(report)
    html = template.render(report=report, css=css, severity_enum=Severity, **ctx)
    output_path.write_text(html, encoding="utf-8")
    return output_path
