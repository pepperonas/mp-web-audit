"""Injection Detection Scanner (passiv): Reflected Parameter, CSRF, Mixed Content."""

from __future__ import annotations

import logging
import uuid
from urllib.parse import urlencode

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

logger = logging.getLogger("webaudit")

# Gaengige GET-Parameter fuer Reflection-Tests
REFLECTION_PARAMS = ["q", "search", "query", "name", "id", "page", "redirect", "url", "next"]


@register_scanner
class InjectionScanner(BaseScanner):
    name = "injection"
    description = "Prueft auf Injection-Risiken (Reflected Params, CSRF, Mixed Content)"
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        raw: dict = {
            "reflected_params": [],
            "forms_without_csrf": 0,
            "mixed_content_count": 0,
        }

        # 1. Reflected Parameter (passiv - unique Marker injizieren)
        marker = f"wa{uuid.uuid4().hex[:8]}"
        base_url = context.target_url.rstrip("/")

        for param in REFLECTION_PARAMS:
            test_url = f"{base_url}?{urlencode({param: marker})}"
            try:
                resp = await self.http.get(test_url)
                if marker in resp.text:
                    raw["reflected_params"].append(param)
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel=f"Reflektierter Parameter: {param}",
                            severity=Severity.MITTEL,
                            beschreibung=f"Der GET-Parameter '{param}' wird ungefiltert in der Antwort reflektiert. "
                            f"Dies ist ein Indikator fuer moeliches XSS.",
                            beweis=f"URL: {test_url} - Marker '{marker}' reflektiert",
                            empfehlung="Eingaben serverseitig validieren und Output-Encoding anwenden.",
                        )
                    )
            except Exception as e:
                logger.debug("Reflection-Test fuer %s fehlgeschlagen: %s", param, e)

        # 2. CSRF-Token Pruefung bei POST-Formularen
        if context.soup:
            forms = context.soup.find_all("form")
            for form in forms:
                method = (form.get("method") or "get").lower()
                if method != "post":
                    continue
                # Nach CSRF-Token suchen
                has_csrf = False
                for inp in form.find_all("input", type="hidden"):
                    name = (inp.get("name") or "").lower()
                    if any(
                        tok in name
                        for tok in ["csrf", "token", "_token", "nonce", "authenticity", "xsrf"]
                    ):
                        has_csrf = True
                        break
                if not has_csrf:
                    raw["forms_without_csrf"] += 1
                    action = form.get("action", "(kein action)")
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel="POST-Formular ohne CSRF-Token",
                            severity=Severity.HOCH,
                            beschreibung="Ein POST-Formular hat kein CSRF-Token. "
                            "Angreifer koennen Aktionen im Namen des Nutzers ausfuehren.",
                            beweis=f"Formular-Action: {action}",
                            empfehlung="CSRF-Token in allen POST-Formularen implementieren.",
                        )
                    )

        # 3. Mixed Content (HTTPS-Seite laedt HTTP-Ressourcen)
        if context.target_url.startswith("https") and context.soup:
            mixed_resources: list[str] = []

            # Scripts
            for tag in context.soup.find_all("script", src=True):
                src = tag["src"]
                if src.startswith("http://"):
                    mixed_resources.append(f"script: {src[:100]}")

            # Stylesheets
            for tag in context.soup.find_all("link", rel="stylesheet"):
                href = tag.get("href", "")
                if href.startswith("http://"):
                    mixed_resources.append(f"css: {href[:100]}")

            # Images
            for tag in context.soup.find_all("img", src=True):
                src = tag["src"]
                if src.startswith("http://"):
                    mixed_resources.append(f"img: {src[:100]}")

            # Iframes
            for tag in context.soup.find_all("iframe", src=True):
                src = tag["src"]
                if src.startswith("http://"):
                    mixed_resources.append(f"iframe: {src[:100]}")

            raw["mixed_content_count"] = len(mixed_resources)
            if mixed_resources:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel=f"Mixed Content: {len(mixed_resources)} HTTP-Ressource(n)",
                        severity=Severity.MITTEL,
                        beschreibung="HTTPS-Seite laedt Ressourcen ueber unverschluesseltes HTTP.",
                        beweis="\n".join(mixed_resources[:10]),
                        empfehlung="Alle Ressourcen ueber HTTPS laden.",
                    )
                )

        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Keine Injection-Risiken erkannt",
                    severity=Severity.INFO,
                    beschreibung="Keine offensichtlichen Injection-Schwachstellen gefunden.",
                    empfehlung="",
                )
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data=raw,
        )
