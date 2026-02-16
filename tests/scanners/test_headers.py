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
    # 6 expected Headers + 3 Cross-Origin Headers (COEP, COOP, CORP) fehlen
    missing = [f for f in result.findings if "fehlt" in f.titel]
    assert len(missing) == 9


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

    # 6 expected headers present, but 3 cross-origin headers + HSTS includeSubDomains still reported
    missing_security = [
        f
        for f in result.findings
        if f.titel
        in [
            "HSTS Header fehlt",
            "Content-Security-Policy fehlt",
            "X-Frame-Options fehlt",
            "X-Content-Type-Options fehlt",
            "Referrer-Policy fehlt",
            "Permissions-Policy fehlt",
        ]
    ]
    assert len(missing_security) == 0
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


@pytest.mark.asyncio
async def test_csp_unsafe_inline_detected(scan_config, mock_http):
    """CSP mit unsafe-inline wird als zu permissiv erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    csp_findings = [f for f in result.findings if "CSP ist zu permissiv" in f.titel]
    assert len(csp_findings) == 1
    assert csp_findings[0].severity == Severity.MITTEL
    assert "unsafe-inline" in csp_findings[0].beweis


@pytest.mark.asyncio
async def test_csp_unsafe_eval_detected(scan_config, mock_http):
    """CSP mit unsafe-eval wird als zu permissiv erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Content-Security-Policy": "script-src 'self' 'unsafe-eval'",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    csp_findings = [f for f in result.findings if "CSP ist zu permissiv" in f.titel]
    assert len(csp_findings) == 1
    assert "'unsafe-eval'" in csp_findings[0].beschreibung


@pytest.mark.asyncio
async def test_csp_nonce_overrides_unsafe_inline(scan_config, mock_http):
    """CSP mit Nonce: unsafe-inline wird ignoriert (Browser-Verhalten)."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'nonce-abc123'",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    # unsafe-inline sollte NICHT gemeldet werden wenn Nonce vorhanden
    csp_findings = [f for f in result.findings if "CSP ist zu permissiv" in f.titel]
    assert len(csp_findings) == 0


@pytest.mark.asyncio
async def test_csp_without_default_src_or_script_src(scan_config, mock_http):
    """CSP ohne default-src und script-src wird erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Content-Security-Policy": "img-src 'self'; style-src 'self'",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    no_default = [f for f in result.findings if "ohne default-src" in f.titel]
    assert len(no_default) == 1
    assert no_default[0].severity == Severity.MITTEL


@pytest.mark.asyncio
async def test_hsts_max_age_too_short(scan_config, mock_http):
    """HSTS max-age unter 1 Jahr wird erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=86400",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    hsts_findings = [f for f in result.findings if "max-age zu kurz" in f.titel]
    assert len(hsts_findings) == 1
    assert hsts_findings[0].severity == Severity.NIEDRIG
    assert "86400" in hsts_findings[0].beschreibung


@pytest.mark.asyncio
async def test_hsts_without_includesubdomains(scan_config, mock_http):
    """HSTS ohne includeSubDomains wird erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    subdom_findings = [f for f in result.findings if "includeSubDomains" in f.titel]
    assert len(subdom_findings) == 1
    assert subdom_findings[0].severity == Severity.NIEDRIG


@pytest.mark.asyncio
async def test_cors_wildcard_origin(scan_config, mock_http):
    """CORS mit Access-Control-Allow-Origin: * wird erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    cors_findings = [f for f in result.findings if "CORS" in f.titel]
    assert len(cors_findings) == 1
    assert cors_findings[0].severity == Severity.MITTEL


@pytest.mark.asyncio
async def test_x_powered_by_exposed(scan_config, mock_http):
    """X-Powered-By Header wird als Informationsleck erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "X-Powered-By": "PHP/8.2.0",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    xpb_findings = [f for f in result.findings if "X-Powered-By" in f.titel]
    assert len(xpb_findings) == 1
    assert xpb_findings[0].severity == Severity.NIEDRIG
    assert "PHP/8.2.0" in xpb_findings[0].beweis


@pytest.mark.asyncio
async def test_cross_origin_headers_missing(scan_config, mock_http):
    """Fehlende COEP, COOP, CORP Headers werden erkannt."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    coep = [f for f in result.findings if "COEP" in f.titel]
    coop = [f for f in result.findings if "COOP" in f.titel]
    corp = [f for f in result.findings if "CORP" in f.titel]
    assert len(coep) == 1
    assert len(coop) == 1
    assert len(corp) == 1
    # Alle NIEDRIG
    assert coep[0].severity == Severity.NIEDRIG
    assert coop[0].severity == Severity.NIEDRIG
    assert corp[0].severity == Severity.NIEDRIG


@pytest.mark.asyncio
async def test_full_security_headers_minimal_findings(scan_config, mock_http):
    """Volle Security-Headers: minimale Findings."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
        body="",
    )
    scanner = HeadersScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    assert len(result.raw_data["present_headers"]) == 6
    # Keine fehlenden Security-Headers, keine fehlenden Cross-Origin-Headers
    missing = [f for f in result.findings if "fehlt" in f.titel]
    assert len(missing) == 0
