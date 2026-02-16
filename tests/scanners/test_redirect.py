"""Tests fuer den Redirect-Scanner."""

import pytest
from tests.conftest import MockHttpClient

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.redirect import RedirectScanner


@pytest.fixture
def scan_config():
    from webaudit.core.config import ScanConfig

    return ScanConfig(target_url="https://example.com", rate_limit=100)


@pytest.mark.asyncio
async def test_no_redirect_issues(scan_config):
    """Keine Redirect-Probleme -> INFO Finding."""
    mock_http = MockHttpClient(
        responses={
            "http://example.com": (200, "redirected"),
            "https://www.example.com/": (200, "ok"),
        }
    )
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
        redirects=[],
    )
    scanner = RedirectScanner(scan_config, mock_http)
    result = await scanner.scan(context)
    assert result.success


@pytest.mark.asyncio
async def test_long_redirect_chain(scan_config):
    """Lange Redirect-Kette wird als MITTEL erkannt."""
    mock_http = MockHttpClient(
        responses={
            "http://example.com": (200, "ok"),
            "https://www.example.com/": (200, "ok"),
        }
    )
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
        redirects=["http://a.com", "http://b.com", "http://c.com", "http://d.com"],
    )
    scanner = RedirectScanner(scan_config, mock_http)
    result = await scanner.scan(context)
    chain_findings = [f for f in result.findings if "Redirect-Kette" in f.titel]
    assert len(chain_findings) == 1
    assert chain_findings[0].severity == Severity.MITTEL
