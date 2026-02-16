"""Fehlkonfigurations-Scanner: Exponierte Dateien und Admin-Panels."""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

# Dateien/Pfade die nicht oeffentlich zugaenglich sein sollten
SENSITIVE_PATHS: list[dict] = [
    {
        "path": "/.env",
        "titel": ".env-Datei exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Die .env-Datei enthaelt haeufig Passwoerter und API-Keys.",
    },
    {
        "path": "/.git/HEAD",
        "titel": "Git-Repository exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Das .git-Verzeichnis ist offen. Angreifer koennen den kompletten Quellcode herunterladen.",
    },
    {
        "path": "/.git/config",
        "titel": "Git-Konfiguration exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Die Git-Konfiguration ist zugaenglich und kann Repository-URLs und Zugangsdaten enthalten.",
    },
    {
        "path": "/.htaccess",
        "titel": ".htaccess exponiert",
        "severity": Severity.MITTEL,
        "beschreibung": "Die .htaccess-Datei ist zugaenglich und kann Server-Konfiguration preisgeben.",
    },
    {
        "path": "/.htpasswd",
        "titel": ".htpasswd exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Die .htpasswd-Datei enthaelt gehashte Passwoerter.",
    },
    {
        "path": "/wp-config.php.bak",
        "titel": "WordPress-Konfig-Backup exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Ein Backup der WordPress-Konfiguration mit Datenbank-Zugangsdaten.",
    },
    {
        "path": "/backup.sql",
        "titel": "Datenbank-Backup exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Eine SQL-Backup-Datei ist oeffentlich zugaenglich.",
    },
    {
        "path": "/backup.zip",
        "titel": "Backup-Archiv exponiert",
        "severity": Severity.HOCH,
        "beschreibung": "Ein Backup-Archiv ist oeffentlich zugaenglich.",
    },
    {
        "path": "/phpinfo.php",
        "titel": "phpinfo() exponiert",
        "severity": Severity.HOCH,
        "beschreibung": "phpinfo() gibt detaillierte Server-Informationen preis.",
    },
    {
        "path": "/server-status",
        "titel": "Apache Server-Status exponiert",
        "severity": Severity.HOCH,
        "beschreibung": "Apache mod_status gibt Serverinformationen preis.",
    },
    {
        "path": "/server-info",
        "titel": "Apache Server-Info exponiert",
        "severity": Severity.HOCH,
        "beschreibung": "Apache mod_info gibt Konfigurationsdetails preis.",
    },
    {
        "path": "/phpmyadmin/",
        "titel": "phpMyAdmin gefunden",
        "severity": Severity.HOCH,
        "beschreibung": "phpMyAdmin ist oeffentlich zugaenglich.",
    },
    {
        "path": "/adminer.php",
        "titel": "Adminer gefunden",
        "severity": Severity.HOCH,
        "beschreibung": "Adminer Datenbank-Manager ist oeffentlich zugaenglich.",
    },
    {
        "path": "/admin/",
        "titel": "Admin-Panel gefunden",
        "severity": Severity.MITTEL,
        "beschreibung": "Ein Admin-Panel ist oeffentlich erreichbar.",
    },
    {
        "path": "/wp-admin/",
        "titel": "WordPress-Admin gefunden",
        "severity": Severity.INFO,
        "beschreibung": "WordPress-Adminbereich ist erreichbar.",
    },
    {
        "path": "/debug/",
        "titel": "Debug-Endpunkt gefunden",
        "severity": Severity.HOCH,
        "beschreibung": "Ein Debug-Endpunkt ist oeffentlich zugaenglich.",
    },
    {
        "path": "/elmah.axd",
        "titel": "ELMAH Error Log exponiert",
        "severity": Severity.HOCH,
        "beschreibung": "ELMAH Error-Logs sind oeffentlich einsehbar.",
    },
    {
        "path": "/crossdomain.xml",
        "titel": "crossdomain.xml gefunden",
        "severity": Severity.NIEDRIG,
        "beschreibung": "Eine permissive crossdomain.xml kann Flash-basierte Angriffe ermoeglichen.",
    },
]


@register_scanner
class MisconfigScanner(BaseScanner):
    name = "misconfig"
    description = "Prueft auf exponierte Dateien und Fehlkonfigurationen"
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        exposed: list[str] = []
        checked: list[str] = []
        base_url = context.target_url.rstrip("/")

        for entry in SENSITIVE_PATHS:
            url = urljoin(base_url + "/", entry["path"].lstrip("/"))
            checked.append(entry["path"])
            try:
                resp = await self.http.get(url)
                # Nur als gefunden werten wenn 200 und nicht leere / Fehlerseite
                if resp.status_code == 200 and len(resp.text) > 0:
                    # Einfache Heuristik: bei HTML-Seiten mit <title>404 o.ae. ignorieren
                    if "text/html" in resp.headers.get("content-type", ""):
                        text_lower = resp.text.lower()
                        if any(
                            kw in text_lower
                            for kw in ["404", "not found", "page not found", "seite nicht gefunden"]
                        ):
                            continue
                    exposed.append(entry["path"])
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel=entry["titel"],
                            severity=entry["severity"],
                            beschreibung=entry["beschreibung"],
                            beweis=f"URL: {url} - Status: {resp.status_code}, Groesse: {len(resp.text)} Bytes",
                            empfehlung="Zugriff auf diese Ressource blockieren (z.B. via .htaccess oder Webserver-Konfiguration).",
                        )
                    )
            except httpx.HTTPError:
                continue

        if not exposed:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Keine exponierten Dateien gefunden",
                    severity=Severity.INFO,
                    beschreibung=f"{len(checked)} Pfade geprueft - keine sensiblen Dateien exponiert.",
                    empfehlung="",
                )
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data={
                "paths_checked": len(checked),
                "paths_exposed": exposed,
            },
        )
