"""Information Disclosure Scanner: Interne IPs, Error-Pattern, sensible Kommentare."""

from __future__ import annotations

import re

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

# RFC 1918 private IP patterns
PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r")\b"
)

# Error patterns indicating stack traces or debug info
ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)PHP (?:Fatal|Parse|Warning) error", "PHP Fehler"),
    (r"(?i)Traceback \(most recent call last\)", "Python Traceback"),
    (r"(?i)(?:java|javax)\.\w+Exception", "Java Exception"),
    (r"(?i)(?:Microsoft|ASP\.NET).+(?:error|exception)", "ASP.NET Fehler"),
    (r"(?i)(?:mysql_|pg_|sqlite_|ORA-\d+|SQL syntax)", "SQL Fehler/Leak"),
    (r"(?i)stack\s*trace:", "Stack Trace"),
    (r"(?i)(?:SQLSTATE|PDOException|mysqli_)", "Datenbank-Fehler"),
    (r"(?i)(?:undefined variable|undefined index|undefined offset)", "PHP Notice"),
    (r"(?i)(?:Error \d{3}:.*at )", "Application Error"),
]

# Sensitive HTML comment patterns
SENSITIVE_COMMENT_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)(?:password|passwd|pwd)\s*[:=]", "Passwort in Kommentar", Severity.MITTEL),
    (r"(?i)(?:secret|api[_-]?key|token)\s*[:=]", "Secret/API-Key in Kommentar", Severity.MITTEL),
    (r"(?i)(?:TODO|FIXME|HACK|BUG|XXX)\b", "Debug-Kommentar (TODO/FIXME)", Severity.NIEDRIG),
    (r"(?i)(?:DEBUG|TESTING|TEMPORARY)\b", "Debug-Hinweis in Kommentar", Severity.NIEDRIG),
]

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


@register_scanner
class InfoDisclosureScanner(BaseScanner):
    name = "info_disclosure"
    description = "Prueft auf Information Disclosure (IPs, Fehler, Kommentare)"
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        body = context.body
        headers_str = " ".join(f"{k}: {v}" for k, v in context.headers.items())

        # 1. Interne IPs in Body und Headers
        all_text = body + " " + headers_str
        private_ips = set(PRIVATE_IP_PATTERN.findall(all_text))
        # Localhost und Loopback filtern
        private_ips -= {"127.0.0.1", "0.0.0.0"}
        if private_ips:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Interne IP-Adressen exponiert",
                    severity=Severity.MITTEL,
                    beschreibung=f"{len(private_ips)} interne IP-Adresse(n) in Response gefunden.",
                    beweis=", ".join(sorted(private_ips)[:10]),
                    empfehlung="Interne IP-Adressen aus Headern und Body entfernen.",
                )
            )

        # 2. Error-Pattern
        for pattern, error_type in ERROR_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel=f"Fehler-Information exponiert: {error_type}",
                        severity=Severity.HOCH,
                        beschreibung=f"{error_type} im Quelltext gefunden. Dies kann Angreifern Server-Interna verraten.",
                        beweis=matches[0][:200],
                        empfehlung="Fehlerausgabe in Produktion deaktivieren. Custom Error-Pages verwenden.",
                    )
                )
                break  # Ein Error-Finding reicht

        # 3. Sensible HTML-Kommentare
        if context.soup:
            from bs4 import Comment

            comments = context.soup.find_all(string=lambda t: isinstance(t, Comment))
            for comment in comments:
                comment_text = str(comment)
                for pattern, desc, sev in SENSITIVE_COMMENT_PATTERNS:
                    if re.search(pattern, comment_text):
                        findings.append(
                            Finding(
                                scanner=self.name,
                                kategorie="Sicherheit",
                                titel=f"Sensibler HTML-Kommentar: {desc}",
                                severity=sev,
                                beschreibung=f"Ein HTML-Kommentar enthaelt moeglicherweise sensible Informationen ({desc}).",
                                beweis=f"<!-- {comment_text[:150]} -->",
                                empfehlung="Sensible Kommentare vor Deployment entfernen.",
                            )
                        )
                        break

        # 4. Email-Adressen im Quelltext
        emails = set(EMAIL_PATTERN.findall(body))
        # Gaengige technische Emails filtern
        emails = {
            e
            for e in emails
            if not any(e.endswith(d) for d in ["@example.com", "@w3.org", "@sentry.io"])
        }
        if emails:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel=f"{len(emails)} E-Mail-Adresse(n) im Quelltext",
                    severity=Severity.INFO,
                    beschreibung="E-Mail-Adressen im Quelltext koennen fuer Spam und Phishing genutzt werden.",
                    beweis=", ".join(sorted(emails)[:10]),
                    empfehlung="E-Mail-Adressen per JavaScript obfuskieren oder Kontaktformulare verwenden.",
                )
            )

        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Keine Information Disclosure erkannt",
                    severity=Severity.INFO,
                    beschreibung="Keine offensichtlichen Informations-Lecks gefunden.",
                    empfehlung="",
                )
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data={
                "private_ips_found": len(private_ips) if "private_ips" in dir() else 0,
                "emails_found": len(emails) if "emails" in dir() else 0,
            },
        )
