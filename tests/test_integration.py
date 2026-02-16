"""Leichtgewichtiger Integrations-Test: Scanner End-to-End."""

from bs4 import BeautifulSoup

from webaudit.core.config import ScanConfig
from webaudit.core.models import ScanContext, ScanResult, Severity
from webaudit.scanners.info_disclosure import InfoDisclosureScanner

from tests.conftest import MockHttpClient


async def test_scanner_end_to_end_produces_scan_result():
    """Ein Scanner durchlaeuft den kompletten Pfad und liefert ein gueltiges ScanResult."""
    config = ScanConfig(
        target_url="https://example.com",
        rate_limit=100,
        timeout=5.0,
    )
    http = MockHttpClient()

    body = "<html><body><p>Server IP: 10.0.0.42</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers={"Content-Type": "text/html", "Server": "nginx"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
        redirects=[],
        response_time=0.12,
        cookies={},
    )

    scanner = InfoDisclosureScanner(config, http)
    result = await scanner.scan(context)

    # Verify ScanResult structure
    assert isinstance(result, ScanResult)
    assert result.scanner_name == "info_disclosure"
    assert result.kategorie == "Sicherheit"
    assert result.success is True
    assert result.error is None
    assert isinstance(result.findings, list)
    assert len(result.findings) > 0
    assert isinstance(result.raw_data, dict)

    # Verify Finding structure
    finding = result.findings[0]
    assert finding.scanner == "info_disclosure"
    assert finding.kategorie == "Sicherheit"
    assert isinstance(finding.severity, Severity)
    assert finding.titel != ""
    assert finding.beschreibung != ""


async def test_scanner_result_raw_data_populated():
    """raw_data im ScanResult enthaelt erwartete Schluessel."""
    config = ScanConfig(
        target_url="https://example.com",
        rate_limit=100,
        timeout=5.0,
    )
    http = MockHttpClient()

    body = "<html><body><p>Clean page</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )

    scanner = InfoDisclosureScanner(config, http)
    result = await scanner.scan(context)

    assert "private_ips_found" in result.raw_data
    assert "emails_found" in result.raw_data
    assert isinstance(result.raw_data["private_ips_found"], int)
    assert isinstance(result.raw_data["emails_found"], int)


async def test_mock_http_client_raise_for():
    """MockHttpClient raise_for-Feature funktioniert korrekt."""
    error = ConnectionError("Connection refused")
    http = MockHttpClient(
        responses={"https://example.com": (200, "OK")},
        raise_for={"https://fail.example.com": error},
    )

    # Normal request works
    resp = await http.get("https://example.com")
    assert resp.status_code == 200

    # Error request raises
    import pytest

    with pytest.raises(ConnectionError, match="Connection refused"):
        await http.get("https://fail.example.com")

    # Request log is populated
    assert ("GET", "https://example.com") in http.request_log
    assert ("GET", "https://fail.example.com") in http.request_log


async def test_mock_http_client_prefix_matching():
    """MockHttpClient Prefix-Matching funktioniert korrekt."""
    http = MockHttpClient(
        responses={"https://example.com": (200, "Homepage")},
    )

    # Exact match
    resp = await http.get("https://example.com")
    assert resp.status_code == 200
    assert resp.text == "Homepage"

    # Prefix match
    resp = await http.get("https://example.com/page?q=test")
    assert resp.status_code == 200
    assert resp.text == "Homepage"
