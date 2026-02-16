"""Shared Fixtures fuer Tests."""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

from webaudit.core.config import ScanConfig
from webaudit.core.http_client import AuditHttpClient
from webaudit.core.models import ScanContext


SAMPLE_HTML = """\
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Test-Seite fuer Web-Audit">
    <meta property="og:title" content="Test">
    <title>Test-Seite</title>
    <link rel="canonical" href="https://example.com/">
    <link rel="icon" href="/favicon.ico">
</head>
<body>
    <h1>Willkommen</h1>
    <p>Ein Absatz mit <a href="/seite1">einem Link</a>.</p>
    <img src="/bild.jpg" alt="Testbild">
    <img src="/bild2.jpg">
    <form>
        <label for="name">Name</label>
        <input type="text" id="name" name="name">
        <input type="email" name="email">
        <input type="submit" value="Absenden">
    </form>
</body>
</html>
"""

SAMPLE_HEADERS = {
    "Content-Type": "text/html; charset=utf-8",
    "Server": "nginx/1.24.0",
    "X-Powered-By": "Express",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Set-Cookie": "session=abc123; Path=/; HttpOnly",
}


@pytest.fixture
def scan_config() -> ScanConfig:
    return ScanConfig(
        target_url="https://example.com",
        rate_limit=100,
        timeout=5.0,
    )


@pytest.fixture
def scan_context() -> ScanContext:
    soup = BeautifulSoup(SAMPLE_HTML, "lxml")
    return ScanContext(
        target_url="https://example.com",
        final_url="https://example.com/",
        status_code=200,
        headers=SAMPLE_HEADERS,
        body=SAMPLE_HTML,
        soup=soup,
        redirects=[],
        response_time=0.15,
        cookies={"session": "abc123"},
    )


class MockHttpClient:
    """Mock HTTP-Client fuer Scanner-Tests."""

    def __init__(self, responses: dict[str, tuple[int, str]] | None = None) -> None:
        self.responses = responses or {}
        self.requests: list[str] = []

    async def get(self, url: str, **kwargs):
        self.requests.append(url)
        status, text = self.responses.get(url, (404, "Not Found"))
        return MockResponse(status, text, url)

    async def head(self, url: str, **kwargs):
        self.requests.append(url)
        status, text = self.responses.get(url, (404, ""))
        return MockResponse(status, text, url)


class MockResponse:
    def __init__(self, status_code: int, text: str, url: str = "") -> None:
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = {"content-type": "text/html"}


@pytest.fixture
def mock_http() -> MockHttpClient:
    return MockHttpClient()
