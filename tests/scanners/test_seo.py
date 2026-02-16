"""Tests fuer den SEO-Scanner."""

import pytest
from bs4 import BeautifulSoup

from webaudit.core.models import ScanContext
from webaudit.scanners.seo import SeoScanner


GOOD_HTML = """\
<html lang="de"><head>
<title>Test</title>
<meta name="description" content="Beschreibung">
<meta property="og:title" content="Test">
<link rel="canonical" href="https://example.com/">
</head><body><h1>Titel</h1></body></html>
"""

BAD_HTML = "<html><head></head><body><p>Kein Title, keine Meta</p></body></html>"


@pytest.mark.asyncio
async def test_good_seo(scan_config):
    mock = type("M", (), {
        "get": staticmethod(lambda *a, **k: _mock_resp(200, "ok")),
    })()
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=GOOD_HTML,
        soup=BeautifulSoup(GOOD_HTML, "lxml"),
    )
    scanner = SeoScanner(scan_config, mock)
    result = await scanner.scan(context)

    assert result.raw_data["has_title"] is True
    assert result.raw_data["has_meta_description"] is True
    assert result.raw_data["has_h1"] is True
    assert result.raw_data["has_canonical"] is True
    assert result.raw_data["has_lang"] is True
    assert result.raw_data["has_og_tags"] is True


@pytest.mark.asyncio
async def test_bad_seo(scan_config):
    mock = type("M", (), {
        "get": staticmethod(lambda *a, **k: _mock_resp(404, "")),
    })()
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=BAD_HTML,
        soup=BeautifulSoup(BAD_HTML, "lxml"),
    )
    scanner = SeoScanner(scan_config, mock)
    result = await scanner.scan(context)

    assert result.raw_data["has_title"] is False
    assert result.raw_data["has_h1"] is False
    # Mindestens 5 Findings (Title, Desc, H1, Canonical, Lang, OG, robots, sitemap)
    assert len(result.findings) >= 5


class _mock_resp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text

    def __await__(self):
        async def _inner():
            return self
        return _inner().__await__()
