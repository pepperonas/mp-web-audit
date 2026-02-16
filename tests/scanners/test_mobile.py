"""Tests fuer den Mobile-Scanner."""

import pytest
from bs4 import BeautifulSoup

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.mobile import MobileScanner


@pytest.mark.asyncio
async def test_mobile_ready(scan_config, mock_http):
    html = '<html><head><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="/icon.png"></head><body></body></html>'
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=BeautifulSoup(html, "lxml"),
    )
    scanner = MobileScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.raw_data["has_viewport"] is True
    assert result.raw_data["has_responsive_meta"] is True
    high = [f for f in result.findings if f.severity in (Severity.KRITISCH, Severity.HOCH)]
    assert len(high) == 0


@pytest.mark.asyncio
async def test_missing_viewport(scan_config, mock_http):
    html = "<html><head></head><body></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=BeautifulSoup(html, "lxml"),
    )
    scanner = MobileScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.raw_data["has_viewport"] is False
    assert any("Viewport" in f.titel for f in result.findings)
