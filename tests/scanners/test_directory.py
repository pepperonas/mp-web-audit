"""Tests fuer den Directory-Scanner."""

import pytest
from pathlib import Path
from tests.conftest import MockHttpClient

from webaudit.core.models import ScanContext
from webaudit.scanners.directory import DirectoryScanner


@pytest.fixture
def scan_config():
    from webaudit.core.config import ScanConfig

    return ScanConfig(
        target_url="https://example.com",
        rate_limit=100,
        wordlist=Path(__file__).parent.parent.parent / "wordlists" / "common.txt",
        extensions="php,html",
    )


@pytest.fixture
def temp_wordlist(tmp_path):
    """Erstellt eine temporaere Wordlist fuer Tests."""
    wordlist = tmp_path / "test_wordlist.txt"
    wordlist.write_text("admin\nbackup\ntest\n# comment\n")
    return wordlist


@pytest.mark.asyncio
async def test_directory_scan_finds_paths(scan_config, temp_wordlist):
    """Directory-Scan findet vorhandene Pfade."""
    scan_config.wordlist = temp_wordlist
    mock_http = MockHttpClient(
        responses={
            "https://example.com/admin": (200, "Admin panel"),
            "https://example.com/backup": (403, "Forbidden"),
            "https://example.com/test": (404, "Not Found"),
            "https://example.com/admin.php": (200, "Admin PHP"),
            "https://example.com/backup.php": (404, "Not Found"),
        }
    )
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = DirectoryScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    assert result.raw_data["total_discovered"] >= 2
    discovered_findings = [f for f in result.findings if "Pfad(e) entdeckt" in f.titel]
    assert len(discovered_findings) >= 1


@pytest.mark.asyncio
async def test_directory_scan_detects_403(scan_config, temp_wordlist):
    """403-Pfade werden separat gemeldet."""
    scan_config.wordlist = temp_wordlist
    mock_http = MockHttpClient(
        responses={
            "https://example.com/admin": (403, "Forbidden"),
            "https://example.com/backup": (403, "Forbidden"),
        }
    )
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = DirectoryScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    forbidden_findings = [f for f in result.findings if "403" in f.titel]
    assert len(forbidden_findings) >= 1


@pytest.mark.asyncio
async def test_directory_scan_no_results(scan_config, temp_wordlist):
    """Keine Pfade gefunden -> INFO Finding."""
    scan_config.wordlist = temp_wordlist
    mock_http = MockHttpClient(responses={})
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = DirectoryScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    info_findings = [f for f in result.findings if "Keine zusaetzlichen" in f.titel]
    assert len(info_findings) == 1


@pytest.mark.asyncio
async def test_directory_scan_missing_wordlist(scan_config):
    """Fehlende Wordlist fuehrt zu Fehler."""
    scan_config.wordlist = Path("/nonexistent/wordlist.txt")
    mock_http = MockHttpClient()
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = DirectoryScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert not result.success
    assert "Wordlist nicht gefunden" in result.error


@pytest.mark.asyncio
async def test_directory_scan_with_extensions(scan_config, temp_wordlist):
    """Extensions werden korrekt angewendet."""
    scan_config.wordlist = temp_wordlist
    scan_config.extensions = "php,html"
    mock_http = MockHttpClient(
        responses={
            "https://example.com/admin.php": (200, "Admin PHP"),
            "https://example.com/test.html": (200, "Test HTML"),
        }
    )
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = DirectoryScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    # Wordlist hat 3 Eintraege (ohne Kommentar), mit 2 Extensions: 3 + (3*2) = 9 Pfade
    assert result.raw_data["paths_tested"] == 9
