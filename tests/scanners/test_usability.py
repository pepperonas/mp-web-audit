"""Tests fuer den Usability-Scanner."""

import pytest
from bs4 import BeautifulSoup
from tests.conftest import MockHttpClient

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.usability import UsabilityScanner


@pytest.fixture
def scan_config():
    from webaudit.core.config import ScanConfig

    return ScanConfig(target_url="https://example.com", rate_limit=100)


@pytest.mark.asyncio
async def test_images_without_alt(scan_config):
    """Bilder ohne Alt-Text werden als MITTEL erkannt."""
    html = """
    <html>
    <body>
        <img src="/image1.jpg" alt="Good image">
        <img src="/image2.jpg">
        <img src="/image3.jpg">
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "lxml")
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=soup,
    )
    mock_http = MockHttpClient()
    scanner = UsabilityScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    alt_findings = [f for f in result.findings if "ohne Alt-Text" in f.titel]
    assert len(alt_findings) == 1
    assert alt_findings[0].severity == Severity.MITTEL
    assert result.raw_data["images_total"] == 3
    assert result.raw_data["images_without_alt"] == 2


@pytest.mark.asyncio
async def test_all_images_have_alt(scan_config):
    """Alle Bilder mit Alt-Text -> keine Findings."""
    html = """
    <html>
    <body>
        <img src="/image1.jpg" alt="Image 1">
        <img src="/image2.jpg" alt="Image 2">
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "lxml")
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=soup,
    )
    mock_http = MockHttpClient()
    scanner = UsabilityScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    alt_findings = [f for f in result.findings if "ohne Alt-Text" in f.titel]
    assert len(alt_findings) == 0


@pytest.mark.asyncio
async def test_broken_links_detection(scan_config):
    """Defekte Links werden erkannt."""
    html = """
    <html>
    <body>
        <a href="/page1">Link 1</a>
        <a href="/page2">Link 2</a>
        <a href="/page3">Link 3</a>
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "lxml")
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=soup,
    )
    mock_http = MockHttpClient(
        responses={
            "https://example.com/page1": (200, "OK"),
            "https://example.com/page2": (404, "Not Found"),
            "https://example.com/page3": (500, "Server Error"),
        }
    )
    scanner = UsabilityScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    broken_findings = [f for f in result.findings if "defekte" in f.titel]
    assert len(broken_findings) == 1
    assert result.raw_data["broken_links"] == 2


@pytest.mark.asyncio
async def test_forms_without_labels(scan_config):
    """Formularfelder ohne Labels werden erkannt."""
    html = """
    <html>
    <body>
        <form>
            <label for="name">Name</label>
            <input type="text" id="name" name="name">
            <input type="email" name="email">
            <input type="text" name="phone">
        </form>
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "lxml")
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=soup,
    )
    mock_http = MockHttpClient()
    scanner = UsabilityScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    form_findings = [f for f in result.findings if "Formularfeld" in f.titel]
    assert len(form_findings) == 1
    assert result.raw_data["forms_without_labels"] == 2


@pytest.mark.asyncio
async def test_forms_with_aria_labels(scan_config):
    """Formularfelder mit aria-label werden als korrekt erkannt."""
    html = """
    <html>
    <body>
        <form>
            <input type="text" aria-label="Name" name="name">
            <input type="email" aria-labelledby="email-label" name="email">
            <span id="email-label">Email</span>
        </form>
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "lxml")
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=soup,
    )
    mock_http = MockHttpClient()
    scanner = UsabilityScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    form_findings = [f for f in result.findings if "Formularfeld" in f.titel]
    assert len(form_findings) == 0


@pytest.mark.asyncio
async def test_skip_link_detection(scan_config):
    """Skip-Link wird erkannt."""
    html = """
    <html>
    <body>
        <a href="#main" class="skip-link">Skip to content</a>
        <main id="main">Content</main>
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "lxml")
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body=html,
        soup=soup,
    )
    mock_http = MockHttpClient()
    scanner = UsabilityScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.raw_data["has_skip_link"] is True


@pytest.mark.asyncio
async def test_no_soup_returns_empty_result(scan_config):
    """Ohne BeautifulSoup wird ein leeres Ergebnis zurückgegeben."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
        soup=None,
    )
    mock_http = MockHttpClient()
    scanner = UsabilityScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    assert len(result.findings) == 0
    assert result.raw_data["images_total"] == 0
