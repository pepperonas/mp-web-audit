"""Performance-Scanner: TTFB, Ladezeiten, Seitengroesse, Redirects."""

from __future__ import annotations

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class PerformanceScanner(BaseScanner):
    name = "performance"
    description = "Misst TTFB, Ladezeit, Seitengroesse und Redirects"
    category = "web"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []

        ttfb_ms = context.response_time * 1000
        page_size_bytes = len(context.body.encode("utf-8", errors="ignore"))
        page_size_kb = page_size_bytes / 1024
        redirect_count = len(context.redirects)

        # Ressourcen zaehlen (Bilder, Scripts, Stylesheets)
        resource_count = 0
        if context.soup:
            resource_count = (
                len(context.soup.find_all("img"))
                + len(context.soup.find_all("script", src=True))
                + len(context.soup.find_all("link", rel="stylesheet"))
            )

        # TTFB bewerten
        if ttfb_ms > 1000:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Sehr langsame Server-Antwortzeit (TTFB)",
                    severity=Severity.HOCH,
                    beschreibung=f"Die Time to First Byte betraegt {ttfb_ms:.0f}ms (Ziel: <200ms).",
                    beweis=f"TTFB: {ttfb_ms:.0f}ms",
                    empfehlung="Server-Konfiguration, Caching und Datenbankabfragen optimieren.",
                )
            )
        elif ttfb_ms > 500:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Langsame Server-Antwortzeit (TTFB)",
                    severity=Severity.MITTEL,
                    beschreibung=f"Die Time to First Byte betraegt {ttfb_ms:.0f}ms (Ziel: <200ms).",
                    beweis=f"TTFB: {ttfb_ms:.0f}ms",
                    empfehlung="Server-seitiges Caching aktivieren.",
                )
            )
        elif ttfb_ms > 200:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Server-Antwortzeit verbesserungswuerdig",
                    severity=Severity.NIEDRIG,
                    beschreibung=f"TTFB: {ttfb_ms:.0f}ms. Optimaler Wert liegt unter 200ms.",
                    beweis=f"TTFB: {ttfb_ms:.0f}ms",
                    empfehlung="Server-Antwortzeit weiter optimieren.",
                )
            )

        # Seitengroesse bewerten
        if page_size_kb > 5000:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Sehr grosse Seite",
                    severity=Severity.HOCH,
                    beschreibung=f"Die Seite ist {page_size_kb:.0f} KB gross (Ziel: <1000 KB).",
                    beweis=f"Seitengroesse: {page_size_kb:.0f} KB",
                    empfehlung="Bilder komprimieren, CSS/JS minifizieren, unnoetige Ressourcen entfernen.",
                )
            )
        elif page_size_kb > 2000:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Grosse Seite",
                    severity=Severity.MITTEL,
                    beschreibung=f"Die Seite ist {page_size_kb:.0f} KB gross.",
                    beweis=f"Seitengroesse: {page_size_kb:.0f} KB",
                    empfehlung="Ressourcen optimieren und komprimieren.",
                )
            )

        # Redirects bewerten
        if redirect_count > 2:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Zu viele Redirects",
                    severity=Severity.MITTEL,
                    beschreibung=f"{redirect_count} Redirects erkannt. Jeder Redirect erhoet die Ladezeit.",
                    beweis=f"Redirect-Kette: {' -> '.join(context.redirects)}",
                    empfehlung="Redirect-Kette verkuerzen, direkt zum Ziel verlinken.",
                )
            )
        elif redirect_count > 0:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Redirects erkannt",
                    severity=Severity.INFO,
                    beschreibung=f"{redirect_count} Redirect(s) erkannt.",
                    beweis=f"Redirects: {' -> '.join(context.redirects)}",
                    empfehlung="",
                )
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Performance",
            findings=findings,
            raw_data={
                "ttfb_ms": round(ttfb_ms, 1),
                "page_size_kb": round(page_size_kb, 1),
                "page_size_bytes": page_size_bytes,
                "redirect_count": redirect_count,
                "resource_count": resource_count,
                "redirects": context.redirects,
            },
        )
