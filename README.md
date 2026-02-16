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
- [Architektur](#architektur)
- [Entwicklung](#entwicklung)
- [Lizenz](#lizenz)

---

## Ueberblick

**mp-web-audit** ist ein umfassendes Web-Auditing-Framework fuer autorisierte Sicherheitspruefungen von Webanwendungen. Das Tool bietet 11 spezialisierte Scanner, die Sicherheitsluecken, Performance-Probleme, SEO-Schwaechen und Technologie-Stack-Informationen aufdecken.

Das Framework ist vollstaendig asynchron aufgebaut und nutzt moderne Python-Bibliotheken fuer maximale Effizienz. Alle Scans werden mit Rate-Limiting und konfigurierbaren Timeouts durchgefuehrt, um Zielsysteme nicht zu ueberlasten.

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

Fuehrt alle 11 Scanner aus (erfordert Autorisierungsbestaetigung fuer Port-Scan und Directory-Discovery):

```bash
webaudit scan https://example.com
```

### Nur Web-Checks (ohne Autorisierung)

Prueft Performance, SEO, Mobile und Usability — keine invasiven Scans:

```bash
webaudit web https://example.com
```

### Nur Sicherheits-Checks

Headers, Cookies, SSL/TLS, Fehlkonfigurationen und Port-Scanning:

```bash
webaudit security https://example.com
```

### Nur Tech-Stack-Erkennung

Erkennt Frameworks, CMS, Server-Software:

```bash
webaudit techstack https://example.com
```

### Nur Directory-Discovery

Wordlist-basiertes Fuzzing nach versteckten Pfaden:

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

Starte 4 Scanner...

╭──────────────────────────── mp-web-audit ────────────────────────────────╮
│ Web-Audit Report                                                         │
│ Ziel: https://example.com/                                               │
│ Dauer: 0.3s                                                              │
╰──────────────────────────────────────────────────────────────────────────╯

                     Bewertung
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Kategorie       ┃ Score                          ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ GESAMT          │ ███████████████░░░░░ 76/100    │
│ Performance     │ ████████████████████ 100/100   │
│ SEO             │ ███████░░░░░░░░░░░░░ 38/100    │
│ Mobile          │ ███████████████░░░░░ 75/100    │
│ Usability       │ ████████████████████ 100/100   │
└─────────────────┴────────────────────────────────┘

Findings: 1 MITTEL, 5 NIEDRIG

Reports gespeichert:
  HTML: ./reports/audit_example.com_20260216_205654.html
  JSON: ./reports/audit_example.com_20260216_205654.json
```

---

## Scanner-Uebersicht

| Scanner | Kategorie | Beschreibung |
|---------|-----------|--------------|
| **headers** | Sicherheit | HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), Server-Versions-Leaks |
| **cookies** | Sicherheit | Cookie-Sicherheit (HttpOnly, Secure, SameSite-Attribute) |
| **ssl_scanner** | Sicherheit | SSL/TLS-Analyse via sslyze: Zertifikatsvalidierung, schwache Protokolle, unsichere Cipher, Heartbleed, ROBOT |
| **misconfig** | Sicherheit | Erkennung haeufiger Fehlkonfigurationen |
| **ports** | Sicherheit | Port-Scanning via nmap (erfordert installiertes nmap) |
| **performance** | Web | Page Load Time (TTFB), Seitengroesse, Redirect-Analyse |
| **seo** | Web | Meta-Tags, Canonical URLs, robots.txt, Sitemap, Open Graph |
| **mobile** | Web | Viewport-Meta-Tags, Responsive Design, Touch-Icons |
| **usability** | Web | Accessibility, Formular- und Link-Validierung |
| **directory** | Discovery | Wordlist-basiertes Directory-/File-Fuzzing |
| **techstack** | Tech Stack | JS-Frameworks, CMS, Server-Software, Sprach-Erkennung via Cookies |

---

## Bewertungssystem

Gewichtetes Scoring von 0-100 Punkten:

| Kategorie | Gewichtung |
|-----------|------------|
| Sicherheit | 40% |
| Performance | 15% |
| SEO | 15% |
| Mobile | 10% |
| Usability | 10% |
| Techstack | 10% |

Severity-Levels der Findings: **KRITISCH** / **HOCH** / **MITTEL** / **NIEDRIG** / **INFO**

| Score | Bewertung |
|-------|-----------|
| 90-100 | Exzellent |
| 75-89 | Gut |
| 60-74 | Akzeptabel |
| 40-59 | Verbesserungswuerdig |
| 0-39 | Kritisch |

---

## CLI-Optionen

### Ausgabe

| Option | Beschreibung | Default |
|--------|-------------|---------|
| `-o, --output PATH` | Ausgabeverzeichnis | `./reports` |
| `-f, --format TEXT` | Report-Formate (kommasepariert) | `html,json,terminal` |

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
| `--wordlist PATH` | Eigene Wordlist fuer Discovery | eingebaut |
| `--extensions TEXT` | Datei-Erweiterungen fuer Discovery | `php,html,js,txt,bak` |

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
```

---

## Report-Formate

### HTML

Portable Single-File-Reports mit eingebettetem CSS:
- Farbcodierte Score-Uebersicht
- Findings-Tabelle mit Severity-Levels
- Technische Details und Empfehlungen

### JSON

Strukturierte Datenexporte fuer Weiterverarbeitung:

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

### Terminal

Rich-formatierte Konsolen-Ausgabe mit farbigen Score-Balken, Findings-Tabelle und Live-Fortschrittsanzeigen.

---

## Architektur

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
    category = "security"

    async def scan(self, context: ScanContext) -> ScanResult:
        ...
```

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
│   └── __init__.py        # Registry mit @register_scanner Decorator
├── reporting/             # Report-Generatoren (HTML, JSON, Terminal)
│   └── templates/         # Jinja2-Templates und CSS
└── wordlists/             # Wordlists fuer Directory-Discovery
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
pytest                                    # Alle Tests
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
