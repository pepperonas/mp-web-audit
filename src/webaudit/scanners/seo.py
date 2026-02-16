"""SEO-Scanner: Meta-Tags, Headings, OG, robots.txt, sitemap.xml, Structured Data, hreflang."""

from __future__ import annotations

import json as json_module
from urllib.parse import urljoin

import httpx

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class SeoScanner(BaseScanner):
    name = "seo"
    description = "Prueft SEO-relevante Elemente"
    category = "web"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        soup = context.soup
        raw: dict = {}

        # Title
        title_tag = soup.find("title") if soup else None
        title = title_tag.get_text(strip=True) if title_tag else ""
        raw["has_title"] = bool(title)
        if not title:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Title-Tag fehlt",
                    severity=Severity.HOCH,
                    beschreibung="Die Seite hat keinen <title>-Tag.",
                    empfehlung="Einen aussagekraeftigen Title-Tag mit 50-60 Zeichen setzen.",
                )
            )
        elif len(title) > 60:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Title-Tag zu lang",
                    severity=Severity.NIEDRIG,
                    beschreibung=f"Der Title hat {len(title)} Zeichen (empfohlen: 50-60).",
                    beweis=f"Title: {title[:100]}",
                    empfehlung="Title auf 50-60 Zeichen kuerzen.",
                )
            )

        # Meta-Description
        meta_desc = soup.find("meta", attrs={"name": "description"}) if soup else None
        desc_content = meta_desc.get("content", "") if meta_desc else ""
        raw["has_meta_description"] = bool(desc_content)
        if not desc_content:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Meta-Description fehlt",
                    severity=Severity.MITTEL,
                    beschreibung="Die Seite hat keine Meta-Description.",
                    empfehlung="Eine Meta-Description mit 150-160 Zeichen setzen.",
                )
            )

        # robots meta
        robots_meta = soup.find("meta", attrs={"name": "robots"}) if soup else None
        robots_content = robots_meta.get("content", "").lower() if robots_meta else ""
        if "noindex" in robots_content:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Seite ist als noindex markiert",
                    severity=Severity.HOCH,
                    beschreibung="Die Seite hat ein meta robots noindex-Tag. Sie wird nicht indexiert.",
                    beweis=f'<meta name="robots" content="{robots_content}">',
                    empfehlung="noindex entfernen, falls die Seite in Suchmaschinen erscheinen soll.",
                )
            )

        # H1
        h1_tags = soup.find_all("h1") if soup else []
        raw["has_h1"] = len(h1_tags) > 0
        raw["h1_count"] = len(h1_tags)
        if not h1_tags:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="H1-Ueberschrift fehlt",
                    severity=Severity.MITTEL,
                    beschreibung="Die Seite hat keine H1-Ueberschrift.",
                    empfehlung="Genau eine H1-Ueberschrift pro Seite verwenden.",
                )
            )
        elif len(h1_tags) > 1:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Mehrere H1-Ueberschriften",
                    severity=Severity.NIEDRIG,
                    beschreibung=f"Die Seite hat {len(h1_tags)} H1-Tags (empfohlen: 1).",
                    empfehlung="Nur eine H1-Ueberschrift pro Seite verwenden.",
                )
            )

        # Canonical
        canonical = soup.find("link", rel="canonical") if soup else None
        raw["has_canonical"] = canonical is not None
        if not canonical:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Canonical-Tag fehlt",
                    severity=Severity.NIEDRIG,
                    beschreibung="Kein Canonical-Link gesetzt.",
                    empfehlung="Canonical-URL setzen um Duplicate Content zu vermeiden.",
                )
            )

        # lang-Attribut
        html_tag = soup.find("html") if soup else None
        lang = html_tag.get("lang", "") if html_tag else ""
        raw["has_lang"] = bool(lang)
        if not lang:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Sprach-Attribut fehlt",
                    severity=Severity.NIEDRIG,
                    beschreibung="Das <html>-Element hat kein lang-Attribut.",
                    empfehlung='<html lang="de"> setzen (oder passende Sprache).',
                )
            )

        # Open Graph Tags
        og_tags = (
            soup.find_all("meta", property=lambda x: x and x.startswith("og:")) if soup else []
        )
        raw["has_og_tags"] = len(og_tags) > 0
        if not og_tags:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Open Graph Tags fehlen",
                    severity=Severity.NIEDRIG,
                    beschreibung="Keine Open Graph Meta-Tags gefunden.",
                    empfehlung="OG-Tags (og:title, og:description, og:image) fuer Social Media setzen.",
                )
            )

        # Structured Data (JSON-LD)
        json_ld_scripts = soup.find_all("script", type="application/ld+json") if soup else []
        has_structured_data = False
        for script in json_ld_scripts:
            try:
                json_module.loads(script.string or "")
                has_structured_data = True
            except (json_module.JSONDecodeError, TypeError):
                pass
        raw["has_structured_data"] = has_structured_data
        if not has_structured_data:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="Structured Data fehlt",
                    severity=Severity.NIEDRIG,
                    beschreibung="Keine Schema.org/JSON-LD Structured Data gefunden.",
                    empfehlung="JSON-LD Structured Data hinzufuegen (z.B. Organization, WebPage).",
                )
            )

        # hreflang
        hreflang_tags = soup.find_all("link", hreflang=True) if soup else []
        raw["has_hreflang"] = len(hreflang_tags) > 0
        if lang and not hreflang_tags:
            # Nur hinweisen wenn Sprache gesetzt ist (deutet auf i18n-Bewusstsein hin)
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="SEO",
                    titel="hreflang-Tags fehlen",
                    severity=Severity.INFO,
                    beschreibung="Keine hreflang-Tags gefunden. Bei mehrsprachigen Seiten empfohlen.",
                    empfehlung="hreflang-Tags setzen falls die Seite in mehreren Sprachen existiert.",
                )
            )

        # robots.txt
        base_url = context.target_url.rstrip("/")
        robots_url = urljoin(base_url + "/", "robots.txt")
        try:
            resp = await self.http.get(robots_url)
            raw["has_robots_txt"] = resp.status_code == 200
            if resp.status_code == 200:
                robots_text = resp.text
                # robots.txt Inhalt analysieren
                if "disallow: /" in robots_text.lower():
                    lines = robots_text.lower().split("\n")
                    for line in lines:
                        stripped = line.strip()
                        if stripped == "disallow: /":
                            findings.append(
                                Finding(
                                    scanner=self.name,
                                    kategorie="SEO",
                                    titel="robots.txt blockiert gesamte Seite",
                                    severity=Severity.HOCH,
                                    beschreibung='robots.txt enthaelt "Disallow: /" - die gesamte Seite ist fuer Crawler gesperrt.',
                                    beweis="Disallow: /",
                                    empfehlung="Disallow-Regel anpassen, um Crawling zu ermoeglichen.",
                                )
                            )
                            break
            else:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="SEO",
                        titel="robots.txt nicht gefunden",
                        severity=Severity.NIEDRIG,
                        beschreibung=f"robots.txt liefert Status {resp.status_code}.",
                        empfehlung="Eine robots.txt mit Crawling-Regeln erstellen.",
                    )
                )
        except httpx.HTTPError:
            raw["has_robots_txt"] = False

        # sitemap.xml
        sitemap_url = urljoin(base_url + "/", "sitemap.xml")
        try:
            resp = await self.http.get(sitemap_url)
            raw["has_sitemap"] = resp.status_code == 200
            if resp.status_code != 200:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="SEO",
                        titel="Sitemap nicht gefunden",
                        severity=Severity.NIEDRIG,
                        beschreibung=f"sitemap.xml liefert Status {resp.status_code}.",
                        empfehlung="Eine XML-Sitemap erstellen und in robots.txt referenzieren.",
                    )
                )
        except httpx.HTTPError:
            raw["has_sitemap"] = False

        return ScanResult(
            scanner_name=self.name,
            kategorie="SEO",
            findings=findings,
            raw_data=raw,
        )
