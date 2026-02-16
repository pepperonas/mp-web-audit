# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**mp-web-audit** is a German-language CLI web auditing tool for authorized security assessments. It checks websites for security vulnerabilities, performance issues, SEO problems, mobile compatibility, and tech stack identification.

- Python 3.11+, built with Hatchling
- CLI via Typer, async HTTP via httpx, HTML parsing via BeautifulSoup/lxml
- All user-facing output, findings, severity levels, and field names are in German

## Commands

```bash
# Install (editable with dev deps)
pip install -e ".[dev]"

# Run CLI
webaudit scan https://example.com        # Full audit
webaudit web https://example.com          # Web checks only (perf, SEO, mobile, usability)
webaudit security https://example.com     # Security checks only
webaudit techstack https://example.com    # Tech stack detection
webaudit discover https://example.com     # Directory discovery
webaudit report reports/audit.json        # Regenerate report from JSON

# Tests
pytest                                    # Run all tests
pytest tests/scanners/test_headers.py     # Run a single test file
pytest -k "test_missing"                  # Run tests matching pattern

# Linting
ruff check src/ tests/                    # Lint
ruff format src/ tests/                   # Format
```

## Architecture

### Plugin-based Scanner System

The core pattern is a **scanner registry with decorator-based auto-discovery**:

1. `src/webaudit/scanners/__init__.py` — `@register_scanner` decorator stores scanner classes in `_SCANNER_REGISTRY` keyed by `cls.name`
2. Each scanner in `src/webaudit/scanners/` subclasses `BaseScanner` (ABC) and implements async `scan(context) -> ScanResult`
3. `discover_scanners()` imports all scanner modules to trigger registration
4. Scanner categories: `"web"`, `"security"`, `"techstack"`, `"discovery"`

### Scan Flow (orchestrator.py)

`run_audit(config)` coordinates the entire process:
1. Normalize URL → initial HTTP request → build `ScanContext` (URL, headers, parsed HTML, cookies)
2. Filter scanners by category and skip flags → execute sequentially with Rich progress
3. Calculate weighted scores (`scoring.py`) → generate reports (HTML/JSON/terminal)

### Data Models (core/models.py)

All Pydantic — key types:
- `ScanContext` — shared state passed to every scanner (target URL, response headers, BeautifulSoup soup, cookies)
- `Finding` — single audit finding with `severity` (KRITISCH/HOCH/MITTEL/NIEDRIG/INFO), `titel`, `beschreibung`, `empfehlung`
- `ScanResult` — one scanner's output: findings list + raw_data dict + success flag
- `AuditReport` — aggregated results, scores, authorization info

### Scoring (core/scoring.py)

Category-weighted scoring (0–100). Weights: Sicherheit 40%, Performance 15%, SEO 15%, Mobile 10%, Usability 10%, Techstack 10%. Some scanners use `raw_data`-based scoring, others use severity-based penalty deduction.

### Key Conventions

- Scanner field names use German: `kategorie`, `titel`, `beschreibung`, `beweis`, `empfehlung`, `dauer`
- External tool dependencies (nmap for port scanning, sslyze for SSL) are checked via `is_available()` and gracefully skipped
- Rate limiting uses a token bucket algorithm in `core/http_client.py`
- Tests use `MockHttpClient`/`MockResponse` from `conftest.py` — not httpx mocking
- pytest-asyncio with `asyncio_mode = "auto"` — no `@pytest.mark.asyncio` needed
- Ruff for linting/formatting, line length 100, target Python 3.11
