"""Cookie-Sicherheitsflags-Scanner mit SameSite, Prefix und Entropie-Checks."""

from __future__ import annotations

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

# Cookie-Namen die auf Session-Cookies hindeuten
SESSION_COOKIE_INDICATORS = ["session", "token", "auth", "sid", "jwt", "access"]


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
            value = parts[0].split("=", 1)[1].strip() if "=" in parts[0] else ""
            flags_lower = cookie_str.lower()

            # Parse SameSite value
            samesite_value = ""
            for part in parts[1:]:
                stripped = part.strip().lower()
                if stripped.startswith("samesite"):
                    if "=" in stripped:
                        samesite_value = stripped.split("=", 1)[1].strip()
                    break

            cookie_info = {
                "name": name,
                "secure": "secure" in flags_lower,
                "httponly": "httponly" in flags_lower,
                "samesite": "samesite" in flags_lower,
                "samesite_value": samesite_value,
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
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel=f"Cookie '{name}' - fehlende Flags: {', '.join(issues)}",
                        severity=Severity.MITTEL if "Secure" in issues else Severity.NIEDRIG,
                        beschreibung=f"Dem Cookie '{name}' fehlen wichtige Sicherheitsflags: {', '.join(issues)}.",
                        beweis=cookie_str[:200],
                        empfehlung=f"Fehlende Flags setzen: {', '.join(issues)}.",
                    )
                )

            # SameSite=None ohne Secure
            if samesite_value == "none" and not cookie_info["secure"]:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel=f"Cookie '{name}': SameSite=None ohne Secure",
                        severity=Severity.HOCH,
                        beschreibung=f"Cookie '{name}' hat SameSite=None ohne Secure-Flag. "
                        f"Browser lehnen dieses Cookie ab.",
                        beweis=cookie_str[:200],
                        empfehlung="Bei SameSite=None muss das Secure-Flag gesetzt sein.",
                    )
                )

            # __Secure- und __Host- Prefix Validierung
            if name.startswith("__Secure-"):
                if not cookie_info["secure"]:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel=f"__Secure- Cookie '{name}' ohne Secure-Flag",
                            severity=Severity.HOCH,
                            beschreibung="Cookie mit __Secure-Prefix muss das Secure-Flag haben.",
                            beweis=cookie_str[:200],
                            empfehlung="Secure-Flag fuer __Secure-Prefix Cookies setzen.",
                        )
                    )

            if name.startswith("__Host-"):
                host_issues = []
                if not cookie_info["secure"]:
                    host_issues.append("Secure fehlt")
                if "path=/" not in flags_lower:
                    host_issues.append("Path=/ fehlt")
                if "domain=" in flags_lower:
                    host_issues.append("Domain darf nicht gesetzt sein")
                if host_issues:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel=f"__Host- Cookie '{name}' verletzt Prefix-Anforderungen",
                            severity=Severity.HOCH,
                            beschreibung=f"Cookie mit __Host-Prefix: {', '.join(host_issues)}.",
                            beweis=cookie_str[:200],
                            empfehlung="__Host-Cookies benoetigen Secure, Path=/ und kein Domain-Attribut.",
                        )
                    )

            # Session-Cookie Entropie pruefen
            name_lower = name.lower()
            is_session_cookie = any(ind in name_lower for ind in SESSION_COOKIE_INDICATORS)
            if is_session_cookie and value and len(value) < 16:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel=f"Session-Cookie '{name}' hat geringe Entropie",
                        severity=Severity.MITTEL,
                        beschreibung=f"Der Session-Cookie-Wert hat nur {len(value)} Zeichen (empfohlen: >= 16).",
                        beweis=f"Cookie-Wert Laenge: {len(value)} Zeichen",
                        empfehlung="Session-IDs mit mindestens 128 Bit Entropie generieren.",
                    )
                )

        if not set_cookies:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Keine Cookies gesetzt",
                    severity=Severity.INFO,
                    beschreibung="Die Seite setzt keine Cookies.",
                    empfehlung="",
                )
            )

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
