"""Score-Berechnung (0-100) pro Kategorie."""

from __future__ import annotations

from webaudit.core.models import AuditReport, Severity


# Gewichtung der Kategorien fuer den Gesamt-Score
CATEGORY_WEIGHTS: dict[str, float] = {
    "Performance": 0.15,
    "SEO": 0.15,
    "Mobile": 0.10,
    "Usability": 0.10,
    "Sicherheit": 0.40,
    "Techstack": 0.10,
}


def _score_from_raw_data(scanner_name: str, raw_data: dict) -> float | None:
    """Berechnet Score fuer einen Scanner basierend auf raw_data."""

    if scanner_name == "performance":
        score = 100.0
        ttfb = raw_data.get("ttfb_ms", 0)
        if ttfb > 1000:
            score -= 40
        elif ttfb > 500:
            score -= 25
        elif ttfb > 200:
            score -= 10

        size_kb = raw_data.get("page_size_kb", 0)
        if size_kb > 5000:
            score -= 30
        elif size_kb > 2000:
            score -= 20
        elif size_kb > 1000:
            score -= 10

        redirects = raw_data.get("redirect_count", 0)
        score -= min(redirects * 5, 20)
        return max(0.0, score)

    if scanner_name == "seo":
        score = 100.0
        checks = [
            "has_title",
            "has_meta_description",
            "has_h1",
            "has_canonical",
            "has_lang",
            "has_og_tags",
            "has_robots_txt",
            "has_sitemap",
        ]
        for check in checks:
            if not raw_data.get(check, False):
                score -= 12.5
        return max(0.0, score)

    if scanner_name == "mobile":
        score = 100.0
        if not raw_data.get("has_viewport", False):
            score -= 50
        if not raw_data.get("has_responsive_meta", False):
            score -= 25
        if not raw_data.get("has_touch_icon", False):
            score -= 25
        return max(0.0, score)

    if scanner_name == "headers":
        score = 100.0
        expected = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]
        present = raw_data.get("present_headers", [])
        for h in expected:
            if h not in present:
                score -= 100 / len(expected)
        return max(0.0, score)

    if scanner_name == "cookies":
        score = 100.0
        total = raw_data.get("total_cookies", 0)
        insecure = raw_data.get("insecure_count", 0)
        if total > 0:
            score -= (insecure / total) * 100
        return max(0.0, score)

    if scanner_name == "ssl_scanner":
        score = 100.0
        if not raw_data.get("valid_cert", True):
            score -= 40
        if raw_data.get("has_weak_protocols", False):
            score -= 30
        if raw_data.get("has_weak_ciphers", False):
            score -= 20
        if raw_data.get("has_vulnerabilities", False):
            score -= 30
        return max(0.0, score)

    return None


# Zuordnung Scanner -> Report-Kategorie
SCANNER_TO_CATEGORY: dict[str, str] = {
    "performance": "Performance",
    "seo": "SEO",
    "mobile": "Mobile",
    "usability": "Usability",
    "headers": "Sicherheit",
    "cookies": "Sicherheit",
    "ssl_scanner": "Sicherheit",
    "ports": "Sicherheit",
    "misconfig": "Sicherheit",
    "techstack": "Techstack",
}


def calculate_scores(report: AuditReport) -> dict[str, float]:
    """Berechnet Scores pro Kategorie und den Gesamt-Score."""
    category_scores: dict[str, list[float]] = {}

    for result in report.results:
        if not result.success:
            continue
        score = _score_from_raw_data(result.scanner_name, result.raw_data)
        if score is not None:
            cat = SCANNER_TO_CATEGORY.get(result.scanner_name, "Sonstiges")
            category_scores.setdefault(cat, []).append(score)

    # Severity-basierter Abzug fuer Kategorien ohne raw_data-Score
    severity_penalty = {
        Severity.KRITISCH: 25,
        Severity.HOCH: 15,
        Severity.MITTEL: 8,
        Severity.NIEDRIG: 3,
        Severity.INFO: 0,
    }

    for result in report.results:
        cat = SCANNER_TO_CATEGORY.get(result.scanner_name, "Sonstiges")
        if cat not in category_scores:
            base = 100.0
            for finding in result.findings:
                base -= severity_penalty.get(finding.severity, 0)
            category_scores.setdefault(cat, []).append(max(0.0, base))

    scores: dict[str, float] = {}
    for cat, values in category_scores.items():
        scores[cat] = round(sum(values) / len(values), 1)

    # Gesamt-Score
    if scores:
        weighted_sum = 0.0
        weight_sum = 0.0
        for cat, s in scores.items():
            w = CATEGORY_WEIGHTS.get(cat, 0.1)
            weighted_sum += s * w
            weight_sum += w
        if weight_sum > 0:
            scores["Gesamt"] = round(weighted_sum / weight_sum, 1)

    return scores
