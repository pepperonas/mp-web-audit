"""Tech-Stack-Fingerprinting-Scanner."""

from __future__ import annotations

import re

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

# Bekannte JS-Frameworks anhand von Dateipfaden/Variablen
JS_FRAMEWORKS: dict[str, list[str]] = {
    "React": ["react", "react-dom", "__NEXT_DATA__", "_next/"],
    "Vue.js": ["vue.js", "vue.min.js", "__vue__", "vue-router"],
    "Angular": ["angular", "ng-version", "ng-app"],
    "jQuery": ["jquery", "jQuery"],
    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
    "Tailwind CSS": ["tailwindcss", "tailwind"],
    "Next.js": ["_next/static", "__NEXT_DATA__"],
    "Nuxt.js": ["_nuxt/", "__NUXT__"],
    "Svelte": ["__svelte"],
}

# CMS-Erkennung
CMS_INDICATORS: dict[str, list[str]] = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Joomla": ["/media/jui/", "Joomla!"],
    "Drupal": ["Drupal.settings", "/sites/default/"],
    "TYPO3": ["typo3", "TYPO3"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme"],
    "Magento": ["mage/cookies", "Magento_"],
    "Wix": ["static.wixstatic.com", "_wix_browser_sess"],
    "Squarespace": ["squarespace.com", "static.squarespace.com"],
}


@register_scanner
class TechstackScanner(BaseScanner):
    name = "techstack"
    description = "Erkennt den Tech-Stack (Server, CMS, Frameworks)"
    category = "techstack"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        detected: dict[str, list[str]] = {
            "server": [],
            "frameworks": [],
            "cms": [],
            "other": [],
        }

        headers_lower = {k.lower(): v for k, v in context.headers.items()}

        # Server-Header
        server = headers_lower.get("server", "")
        if server:
            detected["server"].append(server)

        # X-Powered-By
        powered_by = headers_lower.get("x-powered-by", "")
        if powered_by:
            detected["other"].append(f"X-Powered-By: {powered_by}")

        # Generator Meta-Tag
        if context.soup:
            generator = context.soup.find("meta", attrs={"name": "generator"})
            if generator:
                gen_content = generator.get("content", "")
                if gen_content:
                    detected["other"].append(f"Generator: {gen_content}")

        body = context.body

        # JS-Frameworks erkennen
        for framework, indicators in JS_FRAMEWORKS.items():
            for indicator in indicators:
                if indicator in body:
                    if framework not in detected["frameworks"]:
                        detected["frameworks"].append(framework)
                    break

        # CMS erkennen
        for cms, indicators in CMS_INDICATORS.items():
            for indicator in indicators:
                if indicator in body:
                    if cms not in detected["cms"]:
                        detected["cms"].append(cms)
                    break

        # Cookie-basierte Erkennung
        for name in context.cookies:
            name_lower = name.lower()
            if "wordpress" in name_lower or "wp-" in name_lower:
                if "WordPress" not in detected["cms"]:
                    detected["cms"].append("WordPress")
            if "phpsessid" in name_lower:
                if "PHP" not in detected["other"]:
                    detected["other"].append("PHP (via PHPSESSID)")
            if "jsessionid" in name_lower:
                if "Java" not in detected["other"]:
                    detected["other"].append("Java (via JSESSIONID)")
            if "asp.net" in name_lower or "aspsessionid" in name_lower:
                if "ASP.NET" not in detected["other"]:
                    detected["other"].append("ASP.NET")

        # Zusammenfassung als Findings
        all_tech = []
        for category, items in detected.items():
            all_tech.extend(items)

        if all_tech:
            findings.append(Finding(
                scanner=self.name,
                kategorie="Techstack",
                titel="Erkannte Technologien",
                severity=Severity.INFO,
                beschreibung="Folgende Technologien wurden erkannt:\n" + "\n".join(f"- {t}" for t in all_tech),
                beweis=", ".join(all_tech),
                empfehlung="Unnoetige Technologie-Hinweise in Headern und HTML entfernen.",
            ))
        else:
            findings.append(Finding(
                scanner=self.name,
                kategorie="Techstack",
                titel="Keine Technologien erkannt",
                severity=Severity.INFO,
                beschreibung="Es konnten keine spezifischen Technologien identifiziert werden.",
                empfehlung="",
            ))

        return ScanResult(
            scanner_name=self.name,
            kategorie="Techstack",
            findings=findings,
            raw_data={
                "server": detected["server"],
                "frameworks": detected["frameworks"],
                "cms": detected["cms"],
                "other": detected["other"],
                "all_technologies": all_tech,
            },
        )
