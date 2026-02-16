"""Security-Headers-Scanner."""

from __future__ import annotations

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

EXPECTED_HEADERS: dict[str, dict] = {
    "strict-transport-security": {
        "titel": "HSTS Header fehlt",
        "severity": Severity.HOCH,
        "beschreibung": "Der Strict-Transport-Security Header fehlt. Ohne HSTS koennen Angreifer HTTPS-Verbindungen downgraden.",
        "empfehlung": "HSTS Header setzen: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "content-security-policy": {
        "titel": "Content-Security-Policy fehlt",
        "severity": Severity.HOCH,
        "beschreibung": "Ohne CSP ist die Seite anfaelliger fuer XSS-Angriffe.",
        "empfehlung": "Eine restriktive Content-Security-Policy konfigurieren.",
    },
    "x-frame-options": {
        "titel": "X-Frame-Options fehlt",
        "severity": Severity.MITTEL,
        "beschreibung": "Ohne X-Frame-Options kann die Seite in Frames eingebettet werden (Clickjacking).",
        "empfehlung": "X-Frame-Options: DENY oder SAMEORIGIN setzen.",
    },
    "x-content-type-options": {
        "titel": "X-Content-Type-Options fehlt",
        "severity": Severity.MITTEL,
        "beschreibung": "Ohne nosniff kann der Browser MIME-Types erraten, was zu Sicherheitsproblemen fuehren kann.",
        "empfehlung": "X-Content-Type-Options: nosniff setzen.",
    },
    "referrer-policy": {
        "titel": "Referrer-Policy fehlt",
        "severity": Severity.NIEDRIG,
        "beschreibung": "Ohne Referrer-Policy werden moeglicherweise sensible URL-Parameter an Drittseiten weitergegeben.",
        "empfehlung": "Referrer-Policy: strict-origin-when-cross-origin setzen.",
    },
    "permissions-policy": {
        "titel": "Permissions-Policy fehlt",
        "severity": Severity.NIEDRIG,
        "beschreibung": "Ohne Permissions-Policy koennen Browser-Features wie Kamera/Mikrofon uneingeschraenkt genutzt werden.",
        "empfehlung": "Permissions-Policy konfigurieren um Browser-Features einzuschraenken.",
    },
}


@register_scanner
class HeadersScanner(BaseScanner):
    name = "headers"
    description = "Prueft HTTP-Security-Headers"
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        present_headers: list[str] = []
        header_values: dict[str, str] = {}
        headers_lower = {k.lower(): v for k, v in context.headers.items()}

        for header_name, info in EXPECTED_HEADERS.items():
            value = headers_lower.get(header_name)
            if value:
                present_headers.append(header_name)
                header_values[header_name] = value
            else:
                findings.append(Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel=info["titel"],
                    severity=info["severity"],
                    beschreibung=info["beschreibung"],
                    empfehlung=info["empfehlung"],
                ))

        # Pruefen ob Server-Header unnoetige Infos preisgibt
        server = headers_lower.get("server", "")
        if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
            findings.append(Finding(
                scanner=self.name,
                kategorie="Sicherheit",
                titel="Server-Version exponiert",
                severity=Severity.NIEDRIG,
                beschreibung=f"Der Server-Header gibt die Version preis: {server}",
                beweis=f"Server: {server}",
                empfehlung="Server-Version aus dem Header entfernen.",
            ))

        x_powered = headers_lower.get("x-powered-by", "")
        if x_powered:
            findings.append(Finding(
                scanner=self.name,
                kategorie="Sicherheit",
                titel="X-Powered-By Header exponiert",
                severity=Severity.NIEDRIG,
                beschreibung=f"Der X-Powered-By Header gibt Technologie-Infos preis: {x_powered}",
                beweis=f"X-Powered-By: {x_powered}",
                empfehlung="X-Powered-By Header entfernen.",
            ))

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data={
                "present_headers": present_headers,
                "header_values": header_values,
                "total_expected": len(EXPECTED_HEADERS),
                "total_present": len(present_headers),
            },
        )
