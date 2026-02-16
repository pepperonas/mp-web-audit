"""Tests fuer den Cookies-Scanner."""

import pytest

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.cookies import CookiesScanner


@pytest.mark.asyncio
async def test_secure_cookie(scan_config, mock_http):
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Set-Cookie": "id=abc; Secure; HttpOnly; SameSite=Strict"},
        body="",
    )
    scanner = CookiesScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.raw_data["insecure_count"] == 0


@pytest.mark.asyncio
async def test_insecure_cookie(scan_config, mock_http):
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Set-Cookie": "id=abc; Path=/"},
        body="",
    )
    scanner = CookiesScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.raw_data["insecure_count"] == 1
    assert any("fehlende Flags" in f.titel for f in result.findings)


@pytest.mark.asyncio
async def test_no_cookies(scan_config, mock_http):
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
        cookies={},
    )
    scanner = CookiesScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.raw_data["total_cookies"] == 0
    assert any("Keine Cookies" in f.titel for f in result.findings)
