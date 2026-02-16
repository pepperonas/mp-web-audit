"""Tests fuer den Techstack-Scanner."""

import pytest
from bs4 import BeautifulSoup

from webaudit.core.models import ScanContext
from webaudit.scanners.techstack import TechstackScanner


@pytest.mark.asyncio
async def test_detects_server(scan_config, mock_http):
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Server": "nginx", "X-Powered-By": "Express"},
        body="<html><head></head><body></body></html>",
        soup=BeautifulSoup("<html><body></body></html>", "lxml"),
    )
    scanner = TechstackScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert "nginx" in result.raw_data["server"]
    assert "X-Powered-By: Express" in result.raw_data["other"]


@pytest.mark.asyncio
async def test_detects_react(scan_config, mock_http):
    html = '<html><head></head><body><div id="__next"><script src="/_next/static/chunk.js"></script></div></body></html>'
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=BeautifulSoup(html, "lxml"),
    )
    scanner = TechstackScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert "Next.js" in result.raw_data["frameworks"] or "React" in result.raw_data["frameworks"]


@pytest.mark.asyncio
async def test_detects_wordpress(scan_config, mock_http):
    html = '<html><head><meta name="generator" content="WordPress 6.4"></head><body><link href="/wp-content/style.css"></body></html>'
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=BeautifulSoup(html, "lxml"),
        cookies={"wordpress_logged_in": "xyz"},
    )
    scanner = TechstackScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert "WordPress" in result.raw_data["cms"]
