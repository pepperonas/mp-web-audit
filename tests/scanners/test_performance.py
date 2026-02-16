"""Tests fuer den Performance-Scanner."""

import pytest
from bs4 import BeautifulSoup

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.performance import PerformanceScanner


@pytest.mark.asyncio
async def test_fast_site(scan_config, mock_http):
    """Schnelle Seite erzeugt keine Hochschweregrads-Findings."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="<html><body>Kurz</body></html>",
        soup=BeautifulSoup("<html><body>Kurz</body></html>", "lxml"),
        response_time=0.1,
        redirects=[],
    )
    scanner = PerformanceScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    high_findings = [f for f in result.findings if f.severity in (Severity.KRITISCH, Severity.HOCH)]
    assert len(high_findings) == 0
    assert result.raw_data["ttfb_ms"] == 100.0


@pytest.mark.asyncio
async def test_slow_ttfb(scan_config, mock_http):
    """Langsame TTFB wird als Finding gemeldet."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="x",
        response_time=1.5,
        redirects=[],
    )
    scanner = PerformanceScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    ttfb_findings = [f for f in result.findings if "TTFB" in f.titel]
    assert len(ttfb_findings) == 1
    assert ttfb_findings[0].severity == Severity.HOCH


@pytest.mark.asyncio
async def test_many_redirects(scan_config, mock_http):
    """Viele Redirects werden erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="x",
        response_time=0.1,
        redirects=["https://a.com", "https://b.com", "https://c.com"],
    )
    scanner = PerformanceScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    redirect_findings = [f for f in result.findings if "Redirect" in f.titel]
    assert len(redirect_findings) == 1
    assert redirect_findings[0].severity == Severity.MITTEL
