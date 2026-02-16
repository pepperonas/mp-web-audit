# mp-web-audit

![Python Version](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![Version](https://img.shields.io/badge/version-0.1.0-green)
![License](https://img.shields.io/badge/license-TBD-lightgrey)

CLI-basiertes Web-Auditing-Framework für genehmigte Sicherheitsprüfungen.

---

## Inhaltsverzeichnis

- [Überblick](#überblick)
- [Rechtlicher Hinweis](#rechtlicher-hinweis)
- [Features](#features)
- [Scanner-Übersicht](#scanner-übersicht)
- [Bewertungssystem](#bewertungssystem)
- [Installation](#installation)
- [Schnellstart](#schnellstart)
- [CLI-Befehle](#cli-befehle)
- [CLI-Optionen](#cli-optionen)
- [Report-Formate](#report-formate)
- [Architektur](#architektur)
- [Entwicklung](#entwicklung)
- [Tests](#tests)
- [Linting](#linting)

---

## Überblick

**mp-web-audit** ist ein umfassendes Web-Auditing-Framework für autorisierte Sicherheitsprüfungen von Webanwendungen. Das Tool bietet 11 spezialisierte Scanner, die Sicherheitslücken, Performance-Probleme, SEO-Schwächen und Technologie-Stack-Informationen aufdecken.

Das Framework ist vollständig asynchron aufgebaut und nutzt moderne Python-Bibliotheken für maximale Effizienz. Alle Scans werden mit Rate-Limiting und konfigurierbaren Timeouts durchgeführt, um Zielsysteme nicht zu überlasten.

---

## Rechtlicher Hinweis

**WICHTIG: Nur für autorisierte Sicherheitsprüfungen verwenden.**

Dieses Tool führt aktive Scans durch, die ohne ausdrückliche Genehmigung illegal sein können. Vor der Durchführung von Port-Scans oder Directory-Discovery fordert das Tool eine explizite Bestätigung an:

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                  AUTORISIERUNGS-WARNUNG                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Haben Sie die ausdrückliche Genehmigung, dieses Ziel    ┃
┃ zu scannen?                                              ┃
┃                                                          ┃
┃ Unbefugte Scans können gegen Gesetze verstoßen.         ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

Der Zeitstempel der Autorisierung wird im Report dokumentiert. Der Nutzer trägt die volle Verantwortung für den rechtmäßigen Einsatz dieses Tools.

---

## Features

- **11 spezialisierte Scanner** in 5 Kategorien (Sicherheit, Performance, SEO, Mobile, Techstack)
- **Vollständig asynchrone Architektur** mit asyncio und httpx
- **Plugin-basiertes Scanner-System** mit `@register_scanner` Decorator
- **Gewichtetes Scoring-System** (0-100 Punkte) mit kategorie-basierten Schwerpunkten
- **Mehrere Report-Formate**: HTML, JSON, Terminal
- **Rate-Limiting** mit Token-Bucket-Algorithmus
- **Autorisierungs-Workflow** für invasive Scans
- **Rich Console UI** mit Fortschrittsanzeigen und farbigen Ausgaben
- **Pydantic-Datenmodelle** für Type-Safety und Validierung
- **Umfangreiche Konfiguration** via CLI-Optionen

---

## Scanner-Übersicht

Das Framework umfasst 11 Scanner in folgenden Kategorien:

| Scanner | Kategorie | Beschreibung |
|---------|-----------|--------------|
| **headers** | Sicherheit | Prüft HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) und erkennt Server-Versions-Leaks |
| **cookies** | Sicherheit | Analysiert Cookie-Sicherheit (HttpOnly, Secure, SameSite-Attribute) |
| **ssl_scanner** | Sicherheit | SSL/TLS-Analyse via sslyze: Zertifikatsgültigkeit, schwache Protokolle, unsichere Cipher, bekannte Schwachstellen |
| **misconfig** | Sicherheit | Erkennung häufiger Fehlkonfigurationen und Sicherheitslücken |
| **ports** | Sicherheit | Port-Scanning via nmap (erfordert installiertes nmap) |
| **performance** | Web | Misst Page Load Time (TTFB), Seitengröße, analysiert Redirects |
| **seo** | Web | Überprüft Meta-Tags, Structured Data, Canonical URLs, robots.txt, Sitemap |
| **mobile** | Web | Analysiert Viewport-Meta-Tags, Responsive Design, Touch-Icons |
| **usability** | Web | Accessibility-Checks, Formular- und Link-Validierung |
| **directory** | Discovery | Directory- und File-Fuzzing mit Wordlists |
| **techstack** | Tech Stack | Erkennt JS-Frameworks (React, Vue, Angular, jQuery, Next.js, Nuxt, Svelte), CMS (WordPress, Joomla, Drupal, TYPO3, Shopify), Server-Software und Sprachen |

---

## Bewertungssystem

Das Scoring-System bewertet Websites auf einer Skala von 0-100 Punkten. Die Kategorien sind unterschiedlich gewichtet:

| Kategorie | Gewichtung |
|-----------|------------|
| Sicherheit | 40% |
| Performance | 15% |
| SEO | 15% |
| Mobile | 10% |
| Usability | 10% |
| Techstack | 10% |

Jeder Scanner liefert Findings mit Severity-Levels (KRITISCH, HOCH, MITTEL, NIEDRIG, INFO), die in die Kategorie-Scores einfließen. Der Gesamt-Score wird aus den gewichteten Kategorie-Scores berechnet.

**Score-Interpretation:**
- **90-100**: Exzellent
- **75-89**: Gut
- **60-74**: Akzeptabel
- **40-59**: Verbesserungswürdig
- **0-39**: Kritisch

---

## Installation

### Voraussetzungen

- Python 3.11 oder höher
- `nmap` (optional, für Port-Scanning)

### nmap installieren (macOS)

```bash
brew install nmap
```

### Framework installieren

```bash
# Repository klonen
git clone <repository-url>
cd mp-web-audit

# Development-Installation mit allen Dependencies
pip install -e ".[dev]"
```

Die Installation erstellt den CLI-Befehl `webaudit`, der global verfügbar ist.

---

## Schnellstart

### Vollständiges Audit durchführen

```bash
webaudit scan https://example.com
```

**Beispiel-Ausgabe:**

```
╭────────────────────────────────────────────────────────────────╮
│                    mp-web-audit v0.1.0                         │
│          Web Security & Performance Auditing Framework         │
╰────────────────────────────────────────────────────────────────╯

Ziel: https://example.com
Zeitpunkt: 2026-02-16 14:32:15

[1/11] Scanning headers...         ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[2/11] Scanning cookies...         ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[3/11] Scanning ssl_scanner...     ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[4/11] Scanning misconfig...       ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[5/11] Scanning performance...     ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[6/11] Scanning seo...             ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[7/11] Scanning mobile...          ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[8/11] Scanning usability...       ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[9/11] Scanning techstack...       ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                  AUTORISIERUNGS-WARNUNG                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Die folgenden Scans erfordern Ihre Genehmigung:         ┃
┃ - Port Scanning (nmap)                                  ┃
┃ - Directory Discovery (Fuzzing)                         ┃
┃                                                          ┃
┃ Fortfahren? [y/N]                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

[10/11] Scanning ports...          ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
[11/11] Scanning directory...      ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

╭─────────────────── Scan Results ───────────────────╮
│ Gesamt-Score: 78/100                               │
│                                                    │
│ Sicherheit:    ████████████░░░░░░ 65/100  (40%)   │
│ Performance:   ████████████████░░ 82/100  (15%)   │
│ SEO:           ██████████████████ 91/100  (15%)   │
│ Mobile:        ████████████████░░ 88/100  (10%)   │
│ Usability:     ██████████████░░░░ 75/100  (10%)   │
│ Techstack:     ████████████████░░ 85/100  (10%)   │
╰────────────────────────────────────────────────────╯

Reports gespeichert:
  HTML:     ./reports/example_com_20260216_143215.html
  JSON:     ./reports/example_com_20260216_143215.json
```

---

## CLI-Befehle

```bash
# Vollaudit – alle Scanner
webaudit scan <URL>

# Nur Web-Checks (Performance, SEO, Mobile, Usability)
webaudit web <URL>

# Nur Sicherheits-Checks (Headers, Cookies, SSL, Misconfig, Ports)
webaudit security <URL>

# Nur Tech-Stack-Erkennung
webaudit techstack <URL>

# Nur Directory-Discovery
webaudit discover <URL>

# Report aus JSON neu generieren
webaudit report <JSON-Datei>

# Version anzeigen
webaudit --version
```

---

## CLI-Optionen

Alle Optionen sind für den `scan`-Befehl verfügbar (analog für andere Befehle):

### Ausgabe-Optionen

```bash
-o, --output PATH          # Ausgabeverzeichnis (default: ./reports)
-f, --format TEXT          # Report-Formate: html,json,terminal (default: html,json,terminal)
```

### HTTP-Konfiguration

```bash
-t, --timeout FLOAT        # HTTP-Timeout in Sekunden (default: 10.0)
--rate-limit INTEGER       # Max. Requests pro Sekunde (default: 10)
--user-agent TEXT          # Custom User-Agent String
--no-verify-ssl            # SSL-Zertifikatsverifizierung deaktivieren
```

### Scanner-Konfiguration

```bash
--skip-ssl                 # SSL-Scanner überspringen
--skip-ports               # Port-Scanning überspringen
--skip-discovery           # Directory-Discovery überspringen
--port-range TEXT          # Nmap Port-Range (default: 1-1000)
--wordlist PATH            # Eigene Wordlist für Directory-Discovery
--extensions TEXT          # Datei-Erweiterungen für Discovery (default: php,html,js,txt,bak)
```

### Sonstige Optionen

```bash
-v, --verbose              # Ausführliche Ausgabe
-V, --version              # Version anzeigen
```

### Beispiele

```bash
# Scan mit HTML-Report und erhöhtem Timeout
webaudit scan https://example.com -f html -t 20

# Nur Sicherheits-Checks, SSL-Scanner überspringen
webaudit security https://example.com --skip-ssl

# Discovery mit eigener Wordlist
webaudit discover https://example.com --wordlist /path/to/wordlist.txt

# Vollaudit mit erweiterten Ports und ohne SSL-Verifizierung
webaudit scan https://internal.example.com --port-range 1-5000 --no-verify-ssl
```

---

## Report-Formate

### HTML

Portable Single-File-HTML-Reports mit eingebettetem CSS. Enthält:
- Farbcodierte Score-Übersicht
- Detaillierte Findings-Tabelle mit Severity-Levels
- Kategorie-basierte Gruppierung
- Technische Details und Empfehlungen
- Autorisierungs-Zeitstempel

**Beispiel:** `./reports/example_com_20260216_143215.html`

### JSON

Strukturierte Datenexporte für Weiterverarbeitung, CI/CD-Integration oder Custom-Reporting:

```json
{
  "target_url": "https://example.com",
  "zeitstempel": "2026-02-16T14:32:15",
  "dauer": 12.3,
  "scores": {
    "Gesamt": 78.0,
    "Sicherheit": 65.0,
    "Performance": 82.0,
    "SEO": 91.0
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
  ],
  "autorisierung": {
    "zeitstempel": "2026-02-16T14:32:18",
    "bestaetigt": true
  }
}
```

**Beispiel:** `./reports/example_com_20260216_143215.json`

### Terminal

Rich-formatierte Konsolen-Ausgabe mit:
- Farbigen Score-Balken
- Tabellarischer Findings-Übersicht
- Severity-basierter Farbcodierung (KRITISCH: rot, HOCH: orange, MITTEL: gelb, NIEDRIG: blau, INFO: gruen)
- Live-Progress-Indikatoren während des Scans

---

## Architektur

### Plugin-System

Scanner werden ueber den `@register_scanner` Decorator registriert:

```python
from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import ScanContext, ScanResult
from webaudit.scanners import register_scanner

@register_scanner
class CustomScanner(BaseScanner):
    name = "custom_scanner"
    description = "Mein Custom Scanner"
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        # Scanner-Logik
        ...
```

### Asynchrone Architektur

- Vollständig asynchron mit `asyncio`
- HTTP-Requests via `httpx.AsyncClient`
- Parallele Scanner-Ausführung
- Token-Bucket-basiertes Rate-Limiting

### Datenmodelle

Pydantic-basierte Type-Safe Models:
- `ScanConfig` — Scan-Konfiguration (dataclass)
- `ScanContext` — Shared State fuer Scanner (URL, Headers, HTML, Cookies)
- `Finding` — Einzelnes Scan-Ergebnis mit Severity
- `ScanResult` — Ergebnis eines Scanners (Findings + raw_data)
- `AuditReport` — Gesamter Audit-Report mit Scores

### Komponenten

```
src/webaudit/
├── cli/                   # Typer-basierte CLI
│   ├── app.py             # App-Definition und Subcommand-Registrierung
│   └── commands/          # Subcommands (scan, web, security, techstack, discover, report)
├── core/                  # Core-Engine
│   ├── base_scanner.py    # BaseScanner ABC
│   ├── config.py          # ScanConfig dataclass
│   ├── http_client.py     # Async HTTP-Client mit Rate-Limiting
│   ├── models.py          # Pydantic-Datenmodelle
│   ├── scoring.py         # Score-Berechnung
│   ├── exceptions.py      # Custom Exceptions
│   └── utils.py           # Hilfsfunktionen
├── orchestrator.py        # Scan-Koordination
├── scanners/              # 11 Scanner-Implementierungen
│   ├── __init__.py        # Registry mit @register_scanner Decorator
│   ├── headers.py
│   ├── cookies.py
│   ├── ssl_scanner.py
│   └── ...
├── reporting/             # Report-Generatoren
│   ├── engine.py          # Report-Orchestrierung
│   ├── html_reporter.py   # HTML via Jinja2
│   ├── json_reporter.py   # JSON-Export
│   ├── terminal_reporter.py  # Rich-Konsolen-Ausgabe
│   └── templates/         # Jinja2-Templates und CSS
└── wordlists/             # Wordlists fuer Directory-Discovery
```

---

## Entwicklung

### Development Setup

```bash
# Virtuelle Umgebung erstellen
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Development-Installation
pip install -e ".[dev]"
```

### Dependencies

**Runtime:**
- `httpx` — Async HTTP Client
- `beautifulsoup4` — HTML-Parsing
- `sslyze` — SSL/TLS-Analyse
- `python-nmap` — Nmap-Integration
- `typer[all]` — CLI-Framework
- `rich` — Terminal-UI
- `jinja2` — HTML-Template-Engine
- `pydantic` — Datenvalidierung
- `lxml` — XML/HTML-Parser

**Development:**
- `pytest` — Testing-Framework
- `pytest-asyncio` — Async-Tests
- `pytest-httpx` — HTTP-Mocking
- `respx` — HTTP-Router-Mocking
- `ruff` — Linting & Formatting

---

## Tests

### Test-Suite ausführen

```bash
# Alle Tests
pytest

# Verbose Mode
pytest -v

# Nur bestimmte Datei
pytest tests/scanners/test_headers.py

# Pattern-basierte Auswahl
pytest -k "test_missing"

# Stoppen bei erstem Fehler
pytest -x
```

Tests nutzen `pytest-asyncio` (auto-mode) fuer asynchrone Tests und `MockHttpClient`/`MockResponse` aus `conftest.py` fuer HTTP-Mocking.

---

## Linting

Das Projekt nutzt **Ruff** für Linting und Code-Formatierung:

```bash
# Code prüfen
ruff check src/ tests/

# Code formatieren
ruff format src/ tests/

# Auto-Fix für behebbare Issues
ruff check --fix src/ tests/
```

**Konfiguration:** siehe `[tool.ruff]` in `pyproject.toml`
- Target: Python 3.11
- Line Length: 100 Zeichen

---

---

**Disclaimer:** Dieses Tool ist ausschliesslich fuer autorisierte Sicherheitspruefungen gedacht. Der Nutzer ist fuer die Einhaltung aller geltenden Gesetze und Vorschriften verantwortlich.
