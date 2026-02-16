"""Security-Headers-Scanner mit CSP-Analyse und CORS-Pruefung."""

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

CSP_UNSAFE_DIRECTIVES = ["'unsafe-inline'", "'unsafe-eval'"]


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
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel=info["titel"],
                        severity=info["severity"],
                        beschreibung=info["beschreibung"],
                        empfehlung=info["empfehlung"],
                    )
                )

        # CSP-Staerke pruefen wenn vorhanden
        csp_value = headers_lower.get("content-security-policy", "")
        if csp_value:
            csp_lower = csp_value.lower()
            csp_issues = []

            for directive in CSP_UNSAFE_DIRECTIVES:
                if directive in csp_lower:
                    csp_issues.append(directive)

            # Wildcard in script-src
            if "script-src" in csp_lower:
                script_part = csp_lower.split("script-src")[1].split(";")[0]
                if " * " in f" {script_part} " or script_part.strip() == "*":
                    csp_issues.append("Wildcard (*) in script-src")

            if csp_issues:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="CSP ist zu permissiv",
                        severity=Severity.MITTEL,
                        beschreibung=f"Die Content-Security-Policy enthaelt unsichere Direktiven: {', '.join(csp_issues)}",
                        beweis=f"CSP: {csp_value[:200]}",
                        empfehlung="unsafe-inline und unsafe-eval entfernen, Nonces oder Hashes verwenden.",
                    )
                )

        # CORS pruefen
        cors_origin = headers_lower.get("access-control-allow-origin", "")
        if cors_origin == "*":
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="CORS erlaubt alle Origins",
                    severity=Severity.MITTEL,
                    beschreibung="Access-Control-Allow-Origin ist auf * gesetzt. Jede Domain kann Anfragen stellen.",
                    beweis=f"Access-Control-Allow-Origin: {cors_origin}",
                    empfehlung="CORS auf spezifische, vertrauenswuerdige Origins beschraenken.",
                )
            )

        # Cache-Control bei Seiten mit Cookies
        has_set_cookie = "set-cookie" in headers_lower
        cache_control = headers_lower.get("cache-control", "")
        if has_set_cookie and cache_control:
            cc_lower = cache_control.lower()
            if "public" in cc_lower and "no-store" not in cc_lower:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="Cache-Control bei authentifizierten Seiten zu permissiv",
                        severity=Severity.MITTEL,
                        beschreibung="Die Seite setzt Cookies, aber Cache-Control erlaubt oeffentliches Caching.",
                        beweis=f"Cache-Control: {cache_control}",
                        empfehlung="Cache-Control: no-store, no-cache, private setzen bei Seiten mit Cookies.",
                    )
                )

        # Server-Version pruefen
        server = headers_lower.get("server", "")
        if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Server-Version exponiert",
                    severity=Severity.NIEDRIG,
                    beschreibung=f"Der Server-Header gibt die Version preis: {server}",
                    beweis=f"Server: {server}",
                    empfehlung="Server-Version aus dem Header entfernen.",
                )
            )

        x_powered = headers_lower.get("x-powered-by", "")
        if x_powered:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="X-Powered-By Header exponiert",
                    severity=Severity.NIEDRIG,
                    beschreibung=f"Der X-Powered-By Header gibt Technologie-Infos preis: {x_powered}",
                    beweis=f"X-Powered-By: {x_powered}",
                    empfehlung="X-Powered-By Header entfernen.",
                )
            )

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
