"""Tests fuer den Misconfig-Scanner."""

import pytest
from tests.conftest import MockHttpClient

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.misconfig import MisconfigScanner


@pytest.fixture
def scan_config():
    from webaudit.core.config import ScanConfig

    return ScanConfig(target_url="https://example.com", rate_limit=100)


@pytest.mark.asyncio
async def test_no_exposed_files(scan_config):
    """Keine sensiblen Dateien gefunden -> INFO."""
    mock_http = MockHttpClient()
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = MisconfigScanner(scan_config, mock_http)
    result = await scanner.scan(context)
    assert result.success
    info = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info) >= 1


@pytest.mark.asyncio
async def test_env_file_exposed(scan_config):
    """Exponierte .env-Datei wird als KRITISCH erkannt."""
    mock_http = MockHttpClient(
        responses={
            "https://example.com/.env": (200, "DB_PASSWORD=secret123\nAPI_KEY=abc"),
        }
    )
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = MisconfigScanner(scan_config, mock_http)
    result = await scanner.scan(context)
    env_findings = [f for f in result.findings if ".env" in f.titel]
    assert len(env_findings) == 1
    assert env_findings[0].severity == Severity.KRITISCH


@pytest.mark.asyncio
async def test_git_head_exposed(scan_config):
    """Exponiertes .git/HEAD wird als KRITISCH erkannt."""
    mock_http = MockHttpClient(
        responses={
            "https://example.com/.git/HEAD": (200, "ref: refs/heads/main\n"),
        }
    )
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = MisconfigScanner(scan_config, mock_http)
    result = await scanner.scan(context)
    git_findings = [f for f in result.findings if "Git-Repository" in f.titel]
    assert len(git_findings) == 1


@pytest.mark.asyncio
async def test_env_without_equals_not_flagged(scan_config):
    """Content-Validierung: .env ohne '=' wird nicht als .env gewertet."""
    mock_http = MockHttpClient(
        responses={
            "https://example.com/.env": (200, "this is not an env file"),
        }
    )
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = MisconfigScanner(scan_config, mock_http)
    result = await scanner.scan(context)
    env_findings = [f for f in result.findings if ".env" in f.titel]
    assert len(env_findings) == 0


@pytest.mark.asyncio
async def test_html_404_page_ignored(scan_config):
    """HTML-Seiten mit 404-Inhalt bei Status 200 werden ignoriert."""
    mock_http = MockHttpClient(
        responses={
            "https://example.com/.env": (200, "<html><title>404 Not Found</title></html>"),
        }
    )
    context = ScanContext(target_url="https://example.com", status_code=200, headers={}, body="")
    scanner = MisconfigScanner(scan_config, mock_http)
    result = await scanner.scan(context)
    env_findings = [f for f in result.findings if ".env" in f.titel]
    assert len(env_findings) == 0
