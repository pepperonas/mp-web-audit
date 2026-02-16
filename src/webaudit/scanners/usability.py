"""Usability-Scanner: Broken Links, Alt-Tags, Formular-Barrierefreiheit."""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class UsabilityScanner(BaseScanner):
    name = "usability"
    description = "Prueft Usability und Barrierefreiheit"
    category = "web"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        soup = context.soup
        raw: dict = {
            "images_total": 0,
            "images_without_alt": 0,
            "links_total": 0,
            "broken_links": 0,
            "forms_total": 0,
            "forms_without_labels": 0,
        }

        if not soup:
            return ScanResult(
                scanner_name=self.name,
                kategorie="Usability",
                findings=findings,
                raw_data=raw,
            )

        # Alt-Tags bei Bildern
        images = soup.find_all("img")
        raw["images_total"] = len(images)
        imgs_without_alt = [img for img in images if not img.get("alt")]
        raw["images_without_alt"] = len(imgs_without_alt)
        if imgs_without_alt:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Usability",
                    titel=f"{len(imgs_without_alt)} Bild(er) ohne Alt-Text",
                    severity=Severity.MITTEL,
                    beschreibung=f"Von {len(images)} Bildern haben {len(imgs_without_alt)} keinen Alt-Text.",
                    beweis=", ".join(
                        img.get("src", "unbekannt")[:80] for img in imgs_without_alt[:5]
                    ),
                    empfehlung="Alle Bilder mit beschreibenden Alt-Texten versehen.",
                )
            )

        # Broken Links (stichprobenartig, max. 20 interne Links)
        links = soup.find_all("a", href=True)
        raw["links_total"] = len(links)
        internal_links = []
        for link in links:
            href = link["href"]
            if href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full_url = urljoin(context.target_url, href)
            if context.target_url.split("/")[2] in full_url:
                internal_links.append(full_url)

        broken: list[str] = []
        for url in internal_links[:50]:
            try:
                resp = await self.http.head(url)
                if resp.status_code >= 400:
                    broken.append(f"{url} ({resp.status_code})")
            except httpx.HTTPError:
                broken.append(f"{url} (Fehler)")

        raw["broken_links"] = len(broken)
        if broken:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Usability",
                    titel=f"{len(broken)} defekte(r) Link(s) gefunden",
                    severity=Severity.MITTEL,
                    beschreibung=f"Von {len(internal_links[:20])} geprüften internen Links sind {len(broken)} defekt.",
                    beweis="\n".join(broken[:10]),
                    empfehlung="Defekte Links reparieren oder entfernen.",
                )
            )

        # Formulare: Labels und ARIA
        forms = soup.find_all("form")
        raw["forms_total"] = len(forms)
        forms_issues = 0
        for form in forms:
            inputs = form.find_all(["input", "select", "textarea"])
            for inp in inputs:
                if inp.get("type") in ("hidden", "submit", "button"):
                    continue
                inp_id = inp.get("id", "")
                has_label = bool(inp_id and form.find("label", attrs={"for": inp_id}))
                has_aria = bool(inp.get("aria-label") or inp.get("aria-labelledby"))
                if not (has_label or has_aria):
                    forms_issues += 1

        raw["forms_without_labels"] = forms_issues
        if forms_issues:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Usability",
                    titel=f"{forms_issues} Formularfeld(er) ohne Label",
                    severity=Severity.MITTEL,
                    beschreibung=f"{forms_issues} Eingabefeld(er) haben weder ein <label> noch aria-label.",
                    empfehlung="Alle Formularfelder mit Labels oder ARIA-Attributen versehen.",
                )
            )

        # Sprungmarken / Skip-Navigation
        skip_link = (
            soup.find("a", href="#main")
            or soup.find("a", href="#content")
            or soup.find("a", class_=lambda c: c and "skip" in c.lower() if c else False)
        )
        raw["has_skip_link"] = skip_link is not None

        # Heading-Hierarchie pruefen
        heading_levels = []
        for level in range(1, 7):
            tags = soup.find_all(f"h{level}")
            if tags:
                heading_levels.append(level)
        raw["heading_levels"] = heading_levels

        if len(heading_levels) >= 2:
            gaps = []
            for i in range(len(heading_levels) - 1):
                if heading_levels[i + 1] - heading_levels[i] > 1:
                    gaps.append(f"H{heading_levels[i]} -> H{heading_levels[i + 1]}")
            if gaps:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Usability",
                        titel="Heading-Hierarchie nicht korrekt",
                        severity=Severity.NIEDRIG,
                        beschreibung=f"Die Heading-Struktur hat Luecken: {', '.join(gaps)}.",
                        beweis=f"Vorhandene Levels: {', '.join(f'H{lv}' for lv in heading_levels)}",
                        empfehlung="Headings in logischer Reihenfolge verwenden fuer Barrierefreiheit.",
                    )
                )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Usability",
            findings=findings,
            raw_data=raw,
        )
