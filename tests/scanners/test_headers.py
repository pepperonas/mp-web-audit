"""Tests fuer den Headers-Scanner."""

import pytest

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.headers import HeadersScanner


@pytest.mark.asyncio
async def test_missing_headers(scan_config, mock_http):
    """Fehlende Security-Headers werden erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    # Alle 6 expected Headers fehlen
    missing = [f for f in result.findings if "fehlt" in f.titel]
    assert len(missing) == 6


@pytest.mark.asyncio
async def test_all_headers_present(scan_config, mock_http):
    """Wenn alle Headers gesetzt sind, keine Findings zu fehlenden Headers."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    missing = [f for f in result.findings if "fehlt" in f.titel]
    assert len(missing) == 0
    assert len(result.raw_data["present_headers"]) == 6


@pytest.mark.asyncio
async def test_server_version_exposed(scan_config, mock_http):
    """Server-Version im Header wird erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Server": "Apache/2.4.52"},
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    version_findings = [f for f in result.findings if "Server-Version" in f.titel]
    assert len(version_findings) == 1
    assert version_findings[0].severity == Severity.NIEDRIG
