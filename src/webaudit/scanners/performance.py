"""Performance-Scanner: TTFB, Ladezeiten, Seitengroesse, Redirects, Komprimierung, Caching."""

from __future__ import annotations

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class PerformanceScanner(BaseScanner):
    name = "performance"
    description = "Misst TTFB, Ladezeit, Seitengroesse, Komprimierung und Caching"
    category = "web"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []

        ttfb_ms = context.response_time * 1000
        page_size_bytes = len(context.body.encode("utf-8", errors="ignore"))
        page_size_kb = page_size_bytes / 1024
        redirect_count = len(context.redirects)

        # Ressourcen zaehlen (Bilder, Scripts, Stylesheets)
        resource_count = 0
        render_blocking_scripts = 0
        if context.soup:
            resource_count = (
                len(context.soup.find_all("img"))
                + len(context.soup.find_all("script", src=True))
                + len(context.soup.find_all("link", rel="stylesheet"))
            )
            # Render-blockierende Scripts zaehlen
            for script in context.soup.find_all("script", src=True):
                has_async = script.get("async") is not None
                has_defer = script.get("defer") is not None
                if not has_async and not has_defer:
                    render_blocking_scripts += 1

        headers_lower = {k.lower(): v for k, v in context.headers.items()}

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

        # Komprimierung pruefen
        content_encoding = headers_lower.get("content-encoding", "").lower()
        has_compression = content_encoding in ("gzip", "br", "deflate")
        if not has_compression and page_size_kb > 10:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Keine Komprimierung aktiviert",
                    severity=Severity.MITTEL,
                    beschreibung=f"Die Antwort nutzt keine Komprimierung (gzip/brotli). Seitengroesse: {page_size_kb:.0f} KB.",
                    beweis=f"Content-Encoding: {content_encoding or 'nicht gesetzt'}",
                    empfehlung="gzip oder Brotli-Komprimierung auf dem Webserver aktivieren.",
                )
            )

        # Cache-Headers pruefen
        cache_control = headers_lower.get("cache-control", "")
        has_etag = "etag" in headers_lower
        has_last_modified = "last-modified" in headers_lower
        if not cache_control and not has_etag and not has_last_modified:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Keine Cache-Headers gesetzt",
                    severity=Severity.MITTEL,
                    beschreibung="Weder Cache-Control, ETag noch Last-Modified Header sind gesetzt.",
                    empfehlung="Cache-Control Header setzen, um Browser-Caching zu ermoeglichen.",
                )
            )

        # Render-blockierende Ressourcen
        if render_blocking_scripts > 2:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Viele render-blockierende Scripts",
                    severity=Severity.MITTEL,
                    beschreibung=f"{render_blocking_scripts} Script-Tags ohne async/defer blockieren das Rendering.",
                    beweis=f"{render_blocking_scripts} blockierende <script>-Tags",
                    empfehlung="Scripts mit async oder defer laden, oder ans Ende des <body> verschieben.",
                )
            )
        elif render_blocking_scripts > 0:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Performance",
                    titel="Render-blockierende Scripts vorhanden",
                    severity=Severity.NIEDRIG,
                    beschreibung=f"{render_blocking_scripts} Script-Tag(s) ohne async/defer.",
                    beweis=f"{render_blocking_scripts} blockierende <script>-Tags",
                    empfehlung="Scripts mit async oder defer laden.",
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
                "has_compression": has_compression,
                "content_encoding": content_encoding,
                "render_blocking_scripts": render_blocking_scripts,
            },
        )
