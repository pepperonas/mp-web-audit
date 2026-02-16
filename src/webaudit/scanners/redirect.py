"""Redirect-Scanner: HTTP->HTTPS, www-Konsistenz, Redirect-Ketten."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class RedirectScanner(BaseScanner):
    name = "redirect"
    description = "Prueft HTTP-HTTPS-Redirect und www-Konsistenz"
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        raw: dict = {}
        parsed = urlparse(context.target_url)
        hostname = parsed.hostname or ""

        # HTTP -> HTTPS Redirect pruefen
        if parsed.scheme == "https":
            http_url = context.target_url.replace("https://", "http://", 1)
            try:
                # follow_redirects=False um den Redirect selbst zu sehen
                resp = await self.http.get(http_url)
                # Durch follow_redirects=True im Client sehen wir die Historie
                if resp.history:
                    final = str(resp.url)
                    redirected_to_https = final.startswith("https://")
                    raw["http_redirects_to_https"] = redirected_to_https
                    if redirected_to_https:
                        findings.append(
                            Finding(
                                scanner=self.name,
                                kategorie="Sicherheit",
                                titel="HTTP->HTTPS Redirect vorhanden",
                                severity=Severity.INFO,
                                beschreibung="HTTP-Anfragen werden korrekt auf HTTPS umgeleitet.",
                                beweis=f"HTTP {http_url} -> {final}",
                                empfehlung="",
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                scanner=self.name,
                                kategorie="Sicherheit",
                                titel="HTTP->HTTPS Redirect fehlt",
                                severity=Severity.HOCH,
                                beschreibung="HTTP-Anfragen werden nicht auf HTTPS umgeleitet.",
                                beweis=f"HTTP {http_url} leitet nicht auf HTTPS weiter",
                                empfehlung="HTTP auf HTTPS Redirect einrichten (301 Redirect).",
                            )
                        )
                else:
                    raw["http_redirects_to_https"] = False
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel="HTTP->HTTPS Redirect fehlt",
                            severity=Severity.HOCH,
                            beschreibung="HTTP-Anfragen werden nicht weitergeleitet.",
                            empfehlung="HTTP auf HTTPS Redirect einrichten (301 Redirect).",
                        )
                    )
            except httpx.HTTPError:
                raw["http_redirects_to_https"] = None

        # www vs non-www Konsistenz
        if hostname.startswith("www."):
            alt_host = hostname[4:]
        else:
            alt_host = f"www.{hostname}"
        alt_url = f"{parsed.scheme}://{alt_host}{parsed.path or '/'}"

        try:
            resp = await self.http.get(alt_url)
            final_url = str(resp.url)
            final_host = urlparse(final_url).hostname or ""
            target_host = parsed.hostname or ""

            # Pruefen ob die alternative Version auf die Haupt-URL redirectet
            raw["www_consistent"] = final_host == target_host
            if final_host != target_host and final_host != alt_host:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="www/non-www Inkonsistenz",
                        severity=Severity.NIEDRIG,
                        beschreibung=f"{alt_url} leitet auf {final_url} weiter statt auf {context.target_url}.",
                        beweis=f"{alt_url} -> {final_url}",
                        empfehlung="www und non-www Version konsistent auf eine Variante weiterleiten.",
                    )
                )
            elif final_host == alt_host:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="www/non-www nicht vereinheitlicht",
                        severity=Severity.NIEDRIG,
                        beschreibung=f"Beide Varianten ({hostname} und {alt_host}) sind erreichbar ohne Redirect.",
                        empfehlung="Eine Variante waehlen und die andere per 301 weiterleiten.",
                    )
                )
        except httpx.HTTPError:
            raw["www_consistent"] = None

        # Redirect-Ketten-Laenge
        redirect_count = len(context.redirects)
        raw["redirect_chain_length"] = redirect_count
        if redirect_count > 3:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Lange Redirect-Kette",
                    severity=Severity.MITTEL,
                    beschreibung=f"Die URL hat {redirect_count} Redirects. Lange Ketten erhoehen die Ladezeit und koennen auf Fehlkonfiguration hindeuten.",
                    beweis=f"Redirect-Kette: {' -> '.join(context.redirects)}",
                    empfehlung="Redirect-Kette auf maximal 1-2 Hops verkuerzen.",
                )
            )

        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Redirect-Konfiguration in Ordnung",
                    severity=Severity.INFO,
                    beschreibung="Keine Redirect-Probleme erkannt.",
                    empfehlung="",
                )
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data=raw,
        )
