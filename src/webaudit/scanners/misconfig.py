"""Fehlkonfigurations-Scanner: Exponierte Dateien und Admin-Panels mit Content-Validierung."""

from __future__ import annotations

import asyncio
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
        "validate": lambda text: "=" in text,
    },
    {
        "path": "/.git/HEAD",
        "titel": "Git-Repository exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Das .git-Verzeichnis ist offen. Angreifer koennen den kompletten Quellcode herunterladen.",
        "validate": lambda text: text.strip().startswith("ref:"),
    },
    {
        "path": "/.git/config",
        "titel": "Git-Konfiguration exponiert",
        "severity": Severity.KRITISCH,
        "beschreibung": "Die Git-Konfiguration ist zugaenglich und kann Repository-URLs und Zugangsdaten enthalten.",
        "validate": lambda text: "[core]" in text.lower(),
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
        "path": "/.DS_Store",
        "titel": ".DS_Store exponiert",
        "severity": Severity.NIEDRIG,
        "beschreibung": "Eine macOS .DS_Store Datei gibt Verzeichnisstruktur-Informationen preis.",
    },
    {
        "path": "/.svn/entries",
        "titel": "SVN-Repository exponiert",
        "severity": Severity.HOCH,
        "beschreibung": "Das .svn-Verzeichnis ist zugaenglich und kann Quellcode offenlegen.",
    },
    {
        "path": "/.idea/workspace.xml",
        "titel": "IntelliJ-Konfiguration exponiert",
        "severity": Severity.NIEDRIG,
        "beschreibung": "IntelliJ/JetBrains Projekt-Konfiguration ist oeffentlich zugaenglich.",
    },
    {
        "path": "/.vscode/settings.json",
        "titel": "VS Code-Konfiguration exponiert",
        "severity": Severity.NIEDRIG,
        "beschreibung": "VS Code Projekt-Einstellungen sind oeffentlich zugaenglich.",
    },
    {
        "path": "/package.json",
        "titel": "package.json exponiert",
        "severity": Severity.MITTEL,
        "beschreibung": "Die package.json gibt Abhaengigkeiten und Version preis.",
        "validate": lambda text: '"dependencies"' in text or '"name"' in text,
    },
    {
        "path": "/composer.json",
        "titel": "composer.json exponiert",
        "severity": Severity.MITTEL,
        "beschreibung": "Die composer.json gibt PHP-Abhaengigkeiten preis.",
        "validate": lambda text: '"require"' in text or '"name"' in text,
    },
    {
        "path": "/web.config",
        "titel": "web.config exponiert",
        "severity": Severity.MITTEL,
        "beschreibung": "Die IIS web.config kann sensible Konfiguration enthalten.",
    },
    {
        "path": "/.dockerenv",
        "titel": "Docker-Umgebung erkannt",
        "severity": Severity.INFO,
        "beschreibung": "Die Anwendung laeuft in einem Docker-Container.",
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
        base_url = context.target_url.rstrip("/")

        async def check_path(entry: dict) -> Finding | None:
            url = urljoin(base_url + "/", entry["path"].lstrip("/"))
            try:
                resp = await self.http.get(url)
                if resp.status_code == 200 and len(resp.text) > 0:
                    # HTML-404-Seiten filtern
                    if "text/html" in resp.headers.get("content-type", ""):
                        text_lower = resp.text.lower()
                        if any(
                            kw in text_lower
                            for kw in ["404", "not found", "page not found", "seite nicht gefunden"]
                        ):
                            return None

                    # Content-Validierung falls definiert
                    validator = entry.get("validate")
                    if validator and not validator(resp.text):
                        return None

                    exposed.append(entry["path"])
                    return Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel=entry["titel"],
                        severity=entry["severity"],
                        beschreibung=entry["beschreibung"],
                        beweis=f"URL: {url} - Status: {resp.status_code}, Groesse: {len(resp.text)} Bytes",
                        empfehlung="Zugriff auf diese Ressource blockieren (z.B. via .htaccess oder Webserver-Konfiguration).",
                    )
            except httpx.HTTPError:
                pass
            return None

        # Parallele Pruefung aller Pfade
        results = await asyncio.gather(
            *(check_path(entry) for entry in SENSITIVE_PATHS),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        if not exposed:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Keine exponierten Dateien gefunden",
                    severity=Severity.INFO,
                    beschreibung=f"{len(SENSITIVE_PATHS)} Pfade geprueft - keine sensiblen Dateien exponiert.",
                    empfehlung="",
                )
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data={
                "paths_checked": len(SENSITIVE_PATHS),
                "paths_exposed": exposed,
            },
        )
