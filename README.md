# mp-web-audit

[![CI](https://github.com/pepperonas/mp-web-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/pepperonas/mp-web-audit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-%3E%3D3.11-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.0.1-blue.svg)](https://github.com/pepperonas/mp-web-audit)

CLI-basiertes Web-Auditing-Framework fuer genehmigte Sicherheitspruefungen.

---

## Inhaltsverzeichnis

- [Ueberblick](#ueberblick)
- [Rechtlicher Hinweis](#rechtlicher-hinweis)
- [Installation](#installation)
- [Nutzung](#nutzung)
- [Scanner-Uebersicht](#scanner-uebersicht)
- [Bewertungssystem](#bewertungssystem)
- [CLI-Optionen](#cli-optionen)
- [Report-Formate](#report-formate)
- [CI/CD-Integration](#cicd-integration)
- [Architektur](#architektur)
- [Entwicklung](#entwicklung)
- [Lizenz](#lizenz)

---

## Ueberblick

**mp-web-audit** ist ein umfassendes Web-Auditing-Framework fuer autorisierte Sicherheitspruefungen von Webanwendungen. Das Tool bietet 13 spezialisierte Scanner, die Sicherheitsluecken, Performance-Probleme, SEO-Schwaechen und Technologie-Stack-Informationen aufdecken.

### Highlights

- **13 Scanner** in 4 Kategorien: Sicherheit, Web/Performance, Tech Stack, Discovery
- **Parallele Ausfuehrung** aller Scanner via `asyncio.TaskGroup` — Scan-Zeit = max(Scanner) statt sum(Scanner)
- **HTTP-Retry** mit exponentiellem Backoff bei Timeout/429/502/503
- **CI/CD-tauglich**: `--fail-on`, `--quiet`, `--json-stdout` fuer Pipeline-Integration
- **4 Report-Formate**: HTML (portable Single-File), JSON, CSV, Terminal
- **Konfigurierbare Score-Gewichtung** via `--weights`
- **Rate-Limiting** via Token-Bucket-Algorithmus
- **Plugin-System** mit Decorator-basierter Scanner-Registrierung

---

## Rechtlicher Hinweis

**WICHTIG: Nur fuer autorisierte Sicherheitspruefungen verwenden.**

Dieses Tool fuehrt aktive Scans durch, die ohne ausdrueckliche Genehmigung illegal sein koennen. Vor der Durchfuehrung von Port-Scans oder Directory-Discovery fordert das Tool eine explizite Bestaetigung an:

```
┌──────────────────────────────────────────────────────────────┐
│ WARNUNG: Dieses Tool fuehrt aktive Sicherheits-             │
│ pruefungen durch. Die Nutzung ohne ausdrueckliche            │
│ Genehmigung des Ziel-Betreibers ist illegal.                 │
│                                                              │
│ Ziel: https://example.com                                    │
│ Scan-Typ: Vollaudit                                          │
│ Port-Scan: Ja                                                │
│ Directory-Discovery: Ja                                      │
└──────────────────────────────────────────────────────────────┘
Haben Sie die ausdrueckliche Genehmigung, dieses Ziel zu scannen? [j/N]:
```

Der Zeitstempel der Autorisierung wird im Report dokumentiert.

---

## Installation

### Voraussetzungen

- Python 3.11 oder hoeher
- `nmap` (optional, fuer Port-Scanning)

### Setup

```bash
# Repository klonen
git clone https://github.com/pepperonas/mp-web-audit.git
cd mp-web-audit

# Virtuelle Umgebung erstellen und aktivieren
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows

# Installation mit Development-Dependencies
pip install -e ".[dev]"
```

### Virtuelle Umgebung aktivieren

Die virtuelle Umgebung muss vor jeder Nutzung aktiviert werden:

```bash
cd mp-web-audit
source .venv/bin/activate
```

Nach der Aktivierung erscheint `(.venv)` im Terminal-Prompt. Der Befehl `webaudit` ist dann verfuegbar:

```bash
(.venv) $ webaudit --version
mp-web-audit v0.0.1
```

Zum Deaktivieren:

```bash
deactivate
```

### Optional: nmap installieren (macOS)

```bash
brew install nmap
```

---

## Nutzung

### Vollstaendiges Audit

Fuehrt alle 13 Scanner parallel aus (erfordert Autorisierungsbestaetigung fuer Port-Scan und Directory-Discovery):

```bash
webaudit scan https://example.com
```

### Nur Web-Checks (ohne Autorisierung)

Prueft Performance, SEO, Mobile und Usability — keine invasiven Scans:

```bash
webaudit web https://example.com
```

### Nur Sicherheits-Checks

Headers, Cookies, SSL/TLS, DNS, Redirects, Fehlkonfigurationen und Port-Scanning:

```bash
webaudit security https://example.com
```

### Nur Tech-Stack-Erkennung

Erkennt Frameworks, CMS, Server-Software:

```bash
webaudit techstack https://example.com
```

### Nur Directory-Discovery

Wordlist-basiertes Fuzzing nach versteckten Pfaden (50 parallele HEAD-Requests):

```bash
webaudit discover https://example.com
```

### Report aus JSON neu generieren

```bash
webaudit report reports/audit_example.com_20260216.json
```

### Beispiel-Ausgabe

```
mp-web-audit v0.0.1

Lade Ziel: https://example.com/
Geladen: Status 200, 1256 Bytes, 85ms TTFB

Starte 8 Scanner...

╭──────────────────────────── mp-web-audit ────────────────────────────────╮
│ Web-Audit Report                                                         │
│ Ziel: https://example.com/                                               │
│ Dauer: 4.2s                                                              │
╰──────────────────────────────────────────────────────────────────────────╯

                     Bewertung
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Kategorie       ┃ Score                          ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ GESAMT          │ ███████████████░░░░░ 76/100    │
│ Sicherheit      │ █████████████░░░░░░░ 65/100    │
│ Performance     │ ████████████████████ 100/100   │
│ SEO             │ ███████░░░░░░░░░░░░░ 38/100    │
│ Mobile          │ ███████████████░░░░░ 75/100    │
│ Usability       │ ████████████████████ 100/100   │
└─────────────────┴────────────────────────────────┘

Findings: 1 HOCH, 2 MITTEL, 5 NIEDRIG, 3 INFO

Reports gespeichert:
  HTML: ./reports/audit_example.com_20260216_205654.html
  JSON: ./reports/audit_example.com_20260216_205654.json
```

---

## Scanner-Uebersicht

### Sicherheit (6 Scanner)

| Scanner | Beschreibung |
|---------|--------------|
| **headers** | HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), CSP-Staerke-Analyse (`unsafe-inline`, `unsafe-eval`, Wildcard), CORS-Konfiguration, Cache-Control bei Cookies, Server-Versions-Leaks |
| **cookies** | Cookie-Sicherheit (HttpOnly, Secure, SameSite-Attribute) |
| **ssl_scanner** | SSL/TLS-Analyse via sslyze: Zertifikatsvalidierung, Zertifikats-Ablaufdatum (Abgelaufen/30d/90d), schwache Protokolle (SSLv2/3, TLS 1.0/1.1), schwache Cipher-Suites (RC4, 3DES, CBC), TLS 1.3-Support, Heartbleed, ROBOT |
| **dns** | DNS-Sicherheitseintraege: SPF-Record Existenz und Staerke (+all/-all), DMARC-Record, CAA-Records (dnspython) |
| **redirect** | HTTP->HTTPS Redirect-Pruefung, www/non-www Konsistenz, Redirect-Ketten-Laenge |
| **misconfig** | Erkennung exponierter Dateien (.env, .git/HEAD, .DS_Store, .svn, .idea, .vscode, package.json, composer.json, web.config, .dockerenv, phpMyAdmin, wp-admin) mit Content-Validierung, parallele Pruefung |
| **ports** | Port-Scanning via nmap mit Erkennung riskanter Dienste (FTP, Telnet, RDP, Datenbanken) |

### Web (4 Scanner)

| Scanner | Beschreibung |
|---------|--------------|
| **performance** | TTFB-Messung, Seitengroesse, Redirect-Analyse, Komprimierungs-Check (gzip/brotli), Cache-Header-Analyse (Cache-Control, ETag, Last-Modified), Render-blockierende Scripts (ohne async/defer) |
| **seo** | Meta-Tags, Canonical URLs, robots.txt (Existenz und Inhalt-Analyse), Sitemap, Open Graph, robots-Meta noindex-Erkennung, JSON-LD Structured Data, hreflang-Tags |
| **mobile** | Viewport-Meta-Tags, Responsive Design, Touch-Icons |
| **usability** | Alt-Texte fuer Bilder, Formular-Labels und ARIA-Attribute, Skip-Links, Broken-Link-Erkennung |

### Tech Stack (1 Scanner)

| Scanner | Beschreibung |
|---------|--------------|
| **techstack** | JS-Frameworks (React, Vue, Angular, jQuery), CMS (WordPress, Joomla, Drupal), Server-Software, Sprach-Erkennung via Cookies und Headers |

### Discovery (1 Scanner)

| Scanner | Beschreibung |
|---------|--------------|
| **directory** | Wordlist-basiertes Directory-/File-Fuzzing mit 50 parallelen HEAD-Requests, eigener schneller HTTP-Client (umgeht Rate-Limiter), konfigurierbare Datei-Erweiterungen |

---

## Bewertungssystem

### Score-Berechnung

Gewichtetes Scoring von 0-100 Punkten pro Kategorie:

| Kategorie | Gewichtung | Scoring-Methode |
|-----------|------------|-----------------|
| Sicherheit | 40% | Raw-Data-basiert (Headers, SSL, Cookies) + Severity-Penalty |
| Performance | 15% | TTFB, Seitengroesse, Redirects, Komprimierung |
| SEO | 15% | 8 Checks (Title, Meta, H1, Canonical, Lang, OG, robots.txt, Sitemap) |
| Mobile | 10% | Viewport, Responsive Meta, Touch Icon |
| Usability | 10% | Severity-basierter Abzug |
| Techstack | 10% | Severity-basierter Abzug |

### Severity-Levels

| Level | Penalty | Bedeutung |
|-------|---------|-----------|
| **KRITISCH** | -25 | Sofortiger Handlungsbedarf (abgelaufenes Zertifikat, Heartbleed) |
| **HOCH** | -15 | Hohes Risiko (fehlende Security Headers, schwache Protokolle) |
| **MITTEL** | -8 | Moderates Risiko (schwache Ciphers, fehlende SPF/DMARC) |
| **NIEDRIG** | -3 | Geringes Risiko (fehlende CAA-Records, kein TLS 1.3) |
| **INFO** | 0 | Informativ (alles in Ordnung) |

### Score-Bewertung

| Score | Bewertung |
|-------|-----------|
| 90-100 | Exzellent |
| 75-89 | Gut |
| 60-74 | Akzeptabel |
| 40-59 | Verbesserungswuerdig |
| 0-39 | Kritisch |

Die Gewichtung kann per `--weights` ueberschrieben werden:

```bash
webaudit scan https://example.com --weights '{"Sicherheit": 0.6, "Performance": 0.2, "SEO": 0.2}'
```

---

## CLI-Optionen

### Ausgabe

| Option | Beschreibung | Default |
|--------|-------------|---------|
| `-o, --output PATH` | Ausgabeverzeichnis | `./reports` |
| `-f, --format TEXT` | Report-Formate (kommasepariert: html,json,csv,terminal) | `html,json,terminal` |
| `-q, --quiet` | Keine Terminal-Ausgabe (fuer Scripting) | - |
| `--json-stdout` | JSON-Report nach stdout statt in Datei | - |

### HTTP-Konfiguration

| Option | Beschreibung | Default |
|--------|-------------|---------|
| `-t, --timeout FLOAT` | HTTP-Timeout in Sekunden | `10.0` |
| `--rate-limit INT` | Max. Requests pro Sekunde | `10` |
| `--user-agent TEXT` | Custom User-Agent | `mp-web-audit/0.0.1` |
| `--no-verify-ssl` | SSL-Verifizierung deaktivieren | - |

### Scanner-Konfiguration

| Option | Beschreibung | Default |
|--------|-------------|---------|
| `--skip-ssl` | SSL-Scanner ueberspringen | - |
| `--skip-ports` | Port-Scanning ueberspringen | - |
| `--skip-discovery` | Directory-Discovery ueberspringen | - |
| `--port-range TEXT` | Nmap Port-Range | `1-1000` |
| `--wordlist PATH` | Eigene Wordlist fuer Discovery | eingebaut (454 Pfade) |
| `--extensions TEXT` | Datei-Erweiterungen fuer Discovery | `php,html,js,txt,bak` |

### CI/CD und Bewertung

| Option | Beschreibung |
|--------|-------------|
| `--fail-on LEVEL` | Exit-Code 1 bei Findings >= Severity (KRITISCH/HOCH/MITTEL/NIEDRIG) |
| `--weights JSON` | Eigene Score-Gewichtung als JSON-String |

### Sonstige

| Option | Beschreibung |
|--------|-------------|
| `-v, --verbose` | Ausfuehrliche Ausgabe |
| `-V, --version` | Version anzeigen |

### Beispiele

```bash
# Schneller Web-Check mit nur HTML-Report
webaudit web https://example.com -f html

# Sicherheits-Check ohne SSL-Scanner und mit erhoehtem Timeout
webaudit security https://example.com --skip-ssl -t 20

# Vollaudit ohne SSL-Verifizierung (z.B. interne Systeme)
webaudit scan https://internal.example.com --no-verify-ssl

# Discovery mit eigener Wordlist und erweiterten Dateiendungen
webaudit discover https://example.com --wordlist /path/to/wordlist.txt --extensions "php,asp,jsp"

# Vollaudit mit erweitertem Port-Range
webaudit scan https://example.com --port-range 1-65535

# CI/CD: Fail bei HOCH-Findings, JSON nach stdout
webaudit scan https://example.com --fail-on HOCH --json-stdout --quiet

# JSON-Output pipen
webaudit web https://example.com --json-stdout --quiet | jq '.scores'

# Eigene Score-Gewichtung
webaudit scan https://example.com --weights '{"Sicherheit": 0.7, "Performance": 0.3}'
```

---

## Report-Formate

### HTML

Portable Single-File-Reports mit eingebettetem CSS und JavaScript:
- Farbcodierte Score-Uebersicht mit Gesamt- und Kategorie-Scores
- Inhaltsverzeichnis mit Anker-Links zu jeder Kategorie
- **Severity-Filter**: Buttons zum Ein-/Ausblenden von Findings nach Severity
- Findings-Tabelle mit Severity-Levels, Beweisen und Empfehlungen
- Scan-Metadaten (Tool-Version, Python-Version, Scan-Konfiguration)
- `@media print` CSS fuer sauberen PDF-Druck direkt aus dem Browser

### JSON

Strukturierte Datenexporte fuer Weiterverarbeitung und CI/CD-Pipelines:

```json
{
  "target_url": "https://example.com",
  "zeitstempel": "2026-02-16T14:32:15",
  "dauer": 12.3,
  "scores": {
    "Gesamt": 78.0,
    "Sicherheit": 65.0,
    "Performance": 82.0
  },
  "metadata": {
    "tool_version": "0.0.1",
    "python_version": "3.11.8",
    "scan_config": {
      "categories": ["web", "security", "techstack", "discovery"],
      "timeout": 10.0,
      "rate_limit": 10
    }
  },
  "results": [
    {
      "scanner_name": "headers",
      "kategorie": "Sicherheit",
      "findings": [
        {
          "titel": "HSTS Header fehlt",
          "severity": "HOCH",
          "beschreibung": "...",
          "empfehlung": "..."
        }
      ]
    }
  ]
}
```

### CSV

Eine Zeile pro Finding — ideal fuer Tabellenkalkulationen und Datenanalyse:

```
severity,scanner,kategorie,titel,beschreibung,beweis,empfehlung
HOCH,headers,Sicherheit,HSTS Header fehlt,...,...,...
MITTEL,dns,Sicherheit,SPF-Record fehlt,...,...,...
```

### Terminal

Rich-formatierte Konsolen-Ausgabe mit farbigen Score-Balken, Findings-Tabelle und Live-Fortschrittsanzeigen waehrend des Scans.

---

## CI/CD-Integration

### GitHub Actions

```yaml
- name: Web Audit
  run: |
    pip install mp-web-audit
    webaudit scan https://staging.example.com \
      --fail-on HOCH \
      --json-stdout \
      --quiet \
      --no-verify-ssl \
      --skip-ports \
      --skip-discovery \
      > audit-report.json
```

### Exit-Codes

| Code | Bedeutung |
|------|-----------|
| 0 | Scan erfolgreich, keine Findings >= Threshold |
| 1 | Findings >= `--fail-on` Threshold gefunden |

### JSON nach stdout pipen

```bash
# Nur Scores extrahieren
webaudit web https://example.com --json-stdout --quiet | jq '.scores'

# Findings nach Severity filtern
webaudit scan https://example.com --json-stdout --quiet | jq '[.results[].findings[] | select(.severity == "HOCH")]'

# Report speichern und analysieren
webaudit scan https://example.com --json-stdout --quiet > report.json
```

---

## Architektur

### Scan-Ablauf

```
1. URL normalisieren → initiale HTTP-Anfrage → ScanContext bauen
2. Scanner nach Kategorie und Skip-Flags filtern
3. Alle Scanner parallel via asyncio.TaskGroup ausfuehren
4. Gewichtete Scores berechnen
5. Reports generieren (HTML/JSON/CSV/Terminal)
```

### Plugin-System

Scanner registrieren sich via `@register_scanner` Decorator:

```python
from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import ScanContext, ScanResult
from webaudit.scanners import register_scanner

@register_scanner
class CustomScanner(BaseScanner):
    name = "custom_scanner"
    description = "Mein Custom Scanner"
    category = "security"  # web / security / techstack / discovery

    def is_available(self) -> bool:
        # Optional: externe Abhaengigkeiten pruefen
        return True

    async def scan(self, context: ScanContext) -> ScanResult:
        # context.target_url, context.headers, context.soup, context.cookies
        ...
```

### Komponenten

```
src/webaudit/
├── cli/                   # Typer-basierte CLI
│   ├── app.py             # App-Definition und Subcommand-Registrierung
│   ├── common.py          # Shared build_config() und check_fail_on()
│   └── commands/          # Subcommands (scan, web, security, techstack, discover, report)
├── core/                  # Core-Engine
│   ├── base_scanner.py    # BaseScanner ABC
│   ├── config.py          # ScanConfig dataclass
│   ├── http_client.py     # Async HTTP-Client mit Rate-Limiting und Retry
│   ├── models.py          # Pydantic-Datenmodelle (Finding, ScanResult, AuditReport, ScanMetadata)
│   ├── scoring.py         # Konfigurierbare Score-Berechnung
│   ├── exceptions.py      # Custom Exceptions
│   └── utils.py           # Hilfsfunktionen
├── orchestrator.py        # Parallele Scan-Koordination via asyncio.TaskGroup
├── scanners/              # 13 Scanner-Implementierungen
│   ├── __init__.py        # Registry mit @register_scanner Decorator
│   ├── headers.py         # Security Headers + CSP + CORS
│   ├── cookies.py         # Cookie-Sicherheit
│   ├── ssl_scanner.py     # SSL/TLS + Zertifikats-Ablauf + Cipher-Analyse
│   ├── dns_scanner.py     # SPF, DMARC, CAA (dnspython)
│   ├── redirect.py        # HTTP->HTTPS, www-Konsistenz, Redirect-Ketten
│   ├── misconfig.py       # Exponierte Dateien mit Content-Validierung
│   ├── ports.py           # Port-Scanning via nmap
│   ├── performance.py     # TTFB, Komprimierung, Caching, Render-Blocking
│   ├── seo.py             # Meta, Structured Data, hreflang, robots.txt-Analyse
│   ├── mobile.py          # Viewport, Responsive, Touch-Icons
│   ├── usability.py       # Accessibility, Links, Formulare
│   ├── techstack.py       # Technologie-Erkennung
│   └── directory.py       # Schnelle Wordlist-Enumeration (50 parallele HEAD-Requests)
├── reporting/             # Report-Generatoren
│   ├── engine.py          # Report-Orchestrierung (HTML, JSON, CSV, Terminal)
│   ├── html_reporter.py   # Jinja2-basierte HTML-Reports
│   ├── json_reporter.py   # JSON-Export/Import
│   ├── csv_reporter.py    # CSV-Export (eine Zeile pro Finding)
│   ├── terminal_reporter.py # Rich-Konsolen-Ausgabe
│   └── templates/         # Jinja2-Templates mit eingebettetem CSS/JS
└── wordlists/             # Wordlists fuer Directory-Discovery (454 Pfade)
```

### Datenfluss

```
ScanConfig → Orchestrator → [Scanner₁, Scanner₂, ...] (parallel)
                                    ↓
                              ScanContext (shared: URL, Headers, HTML, Cookies)
                                    ↓
                              ScanResult (Findings + raw_data pro Scanner)
                                    ↓
                              AuditReport → Scoring → Reports (HTML/JSON/CSV/Terminal)
```

---

## Entwicklung

### Setup

```bash
git clone https://github.com/pepperonas/mp-web-audit.git
cd mp-web-audit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Tests

```bash
pytest                                    # Alle Tests (64 Tests)
pytest -v                                 # Verbose
pytest tests/scanners/test_headers.py     # Einzelne Datei
pytest -k "test_missing"                  # Pattern-Match
pytest -x                                 # Stop bei erstem Fehler
```

Tests nutzen `pytest-asyncio` (auto-mode) und `MockHttpClient`/`MockResponse` aus `conftest.py`.

### Linting

```bash
ruff check src/ tests/                    # Pruefen
ruff format src/ tests/                   # Formatieren
ruff check --fix src/ tests/              # Auto-Fix
```

Konfiguration: Python 3.11, Line Length 100 (siehe `pyproject.toml`).

### CI/CD

GitHub Actions fuehrt bei jedem Push und Pull Request automatisch aus:
- **Linting**: `ruff check` und `ruff format --check`
- **Tests**: `pytest` auf Python 3.11, 3.12 und 3.13

---

## Lizenz

MIT License - siehe [LICENSE](LICENSE).

---

**Autor:** Martin Pfeffer

**Disclaimer:** Dieses Tool ist ausschliesslich fuer autorisierte Sicherheitspruefungen gedacht. Der Nutzer ist fuer die Einhaltung aller geltenden Gesetze und Vorschriften verantwortlich.
