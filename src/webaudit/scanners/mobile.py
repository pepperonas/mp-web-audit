"""Mobile-Readiness-Scanner."""

from __future__ import annotations

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class MobileScanner(BaseScanner):
    name = "mobile"
    description = "Prueft Mobile-Readiness (Viewport, responsive Indikatoren)"
    category = "web"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        soup = context.soup
        raw: dict = {}

        # Viewport Meta-Tag
        viewport = soup.find("meta", attrs={"name": "viewport"}) if soup else None
        viewport_content = viewport.get("content", "") if viewport else ""
        raw["has_viewport"] = bool(viewport)
        raw["has_responsive_meta"] = "width=device-width" in viewport_content if viewport_content else False

        if not viewport:
            findings.append(Finding(
                scanner=self.name, kategorie="Mobile",
                titel="Viewport Meta-Tag fehlt",
                severity=Severity.HOCH,
                beschreibung="Ohne Viewport-Tag wird die Seite auf Mobilgeraeten nicht korrekt dargestellt.",
                empfehlung='<meta name="viewport" content="width=device-width, initial-scale=1"> hinzufuegen.',
            ))
        elif not raw["has_responsive_meta"]:
            findings.append(Finding(
                scanner=self.name, kategorie="Mobile",
                titel="Viewport nicht responsive konfiguriert",
                severity=Severity.MITTEL,
                beschreibung=f"Der Viewport ist gesetzt, aber 'width=device-width' fehlt: {viewport_content}",
                beweis=f"viewport: {viewport_content}",
                empfehlung="width=device-width zum Viewport hinzufuegen.",
            ))

        # Touch-Icons (Apple, Android)
        touch_icons = []
        if soup:
            touch_icons = soup.find_all("link", rel=lambda r: r and "icon" in r.lower() if isinstance(r, str) else r and any("icon" in x.lower() for x in r))
        raw["has_touch_icon"] = len(touch_icons) > 0
        if not touch_icons:
            findings.append(Finding(
                scanner=self.name, kategorie="Mobile",
                titel="Touch-Icons fehlen",
                severity=Severity.NIEDRIG,
                beschreibung="Keine Touch-Icons (apple-touch-icon o.ae.) gefunden.",
                empfehlung="Touch-Icons fuer iOS und Android hinzufuegen.",
            ))

        # Responsive Indikatoren im CSS (media queries via inline styles oder link tags)
        has_media_queries = False
        if soup:
            styles = soup.find_all("style")
            for style in styles:
                if style.string and "@media" in style.string:
                    has_media_queries = True
                    break
        raw["has_media_queries"] = has_media_queries

        # text-size-adjust
        if context.body and "text-size-adjust" in context.body:
            raw["has_text_size_adjust"] = True
        else:
            raw["has_text_size_adjust"] = False

        return ScanResult(
            scanner_name=self.name,
            kategorie="Mobile",
            findings=findings,
            raw_data=raw,
        )
