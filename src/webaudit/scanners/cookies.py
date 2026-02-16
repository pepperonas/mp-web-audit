"""Cookie-Sicherheitsflags-Scanner."""

from __future__ import annotations

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class CookiesScanner(BaseScanner):
    name = "cookies"
    description = "Prueft Cookie-Sicherheitsflags"
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        insecure_count = 0
        cookie_details: list[dict] = []

        # Cookies aus den Response-Headern parsen
        set_cookies = []
        for key, value in context.headers.items():
            if key.lower() == "set-cookie":
                set_cookies.append(value)

        # Auch ggf. mehrere Set-Cookie aus raw cookies
        if not set_cookies and context.cookies:
            for name, val in context.cookies.items():
                set_cookies.append(f"{name}={val}")

        for cookie_str in set_cookies:
            parts = cookie_str.split(";")
            name = parts[0].split("=")[0].strip() if parts else "unbekannt"
            flags_lower = cookie_str.lower()

            cookie_info = {
                "name": name,
                "secure": "secure" in flags_lower,
                "httponly": "httponly" in flags_lower,
                "samesite": "samesite" in flags_lower,
            }
            cookie_details.append(cookie_info)

            issues = []
            if not cookie_info["secure"]:
                issues.append("Secure")
            if not cookie_info["httponly"]:
                issues.append("HttpOnly")
            if not cookie_info["samesite"]:
                issues.append("SameSite")

            if issues:
                insecure_count += 1
                findings.append(Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel=f"Cookie '{name}' - fehlende Flags: {', '.join(issues)}",
                    severity=Severity.MITTEL if "Secure" in issues else Severity.NIEDRIG,
                    beschreibung=f"Dem Cookie '{name}' fehlen wichtige Sicherheitsflags: {', '.join(issues)}.",
                    beweis=cookie_str[:200],
                    empfehlung=f"Fehlende Flags setzen: {', '.join(issues)}.",
                ))

        if not set_cookies:
            findings.append(Finding(
                scanner=self.name,
                kategorie="Sicherheit",
                titel="Keine Cookies gesetzt",
                severity=Severity.INFO,
                beschreibung="Die Seite setzt keine Cookies.",
                empfehlung="",
            ))

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data={
                "total_cookies": len(set_cookies),
                "insecure_count": insecure_count,
                "cookie_details": cookie_details,
            },
        )
