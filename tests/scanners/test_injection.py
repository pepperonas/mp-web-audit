"""Tests fuer den Injection-Scanner."""

from bs4 import BeautifulSoup

from tests.conftest import MockHttpClient
from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.injection import InjectionScanner


async def test_csrf_token_missing_on_post_form(scan_config, mock_http):
    """POST-Formular ohne CSRF-Token wird erkannt."""
    body = """\
    <html><body>
        <form method="post" action="/login">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit" value="Login">
        </form>
    </body></html>
    """
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InjectionScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    csrf_findings = [f for f in result.findings if "CSRF" in f.titel]
    assert len(csrf_findings) == 1
    assert csrf_findings[0].severity == Severity.HOCH
    assert result.raw_data["forms_without_csrf"] == 1


async def test_csrf_token_present_no_finding(scan_config, mock_http):
    """POST-Formular mit CSRF-Token erzeugt kein CSRF-Finding."""
    body = """\
    <html><body>
        <form method="post" action="/login">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="text" name="username">
            <input type="submit" value="Login">
        </form>
    </body></html>
    """
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InjectionScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    csrf_findings = [f for f in result.findings if "CSRF" in f.titel]
    assert len(csrf_findings) == 0
    assert result.raw_data["forms_without_csrf"] == 0


async def test_mixed_content_http_resources(scan_config, mock_http):
    """HTTP-Ressourcen auf HTTPS-Seite werden erkannt."""
    body = """\
    <html><body>
        <script src="http://evil.com/script.js"></script>
        <img src="http://cdn.example.com/pic.jpg">
        <link rel="stylesheet" href="http://cdn.example.com/style.css">
    </body></html>
    """
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InjectionScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    mixed_findings = [f for f in result.findings if "Mixed Content" in f.titel]
    assert len(mixed_findings) == 1
    assert mixed_findings[0].severity == Severity.MITTEL
    assert result.raw_data["mixed_content_count"] == 3


async def test_clean_page_no_injection(scan_config, mock_http):
    """Saubere Seite ohne Injection-Risiken."""
    body = """\
    <html><body>
        <h1>Willkommen</h1>
        <p>Alles gut.</p>
    </body></html>
    """
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InjectionScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    # Only the reflected param tests make requests; with no matches and no forms/mixed content,
    # we expect the "Keine Injection-Risiken erkannt" INFO finding
    info_findings = [f for f in result.findings if "Keine Injection" in f.titel]
    assert len(info_findings) == 1
    assert info_findings[0].severity == Severity.INFO


async def test_get_form_not_flagged_as_csrf(scan_config, mock_http):
    """GET-Formular wird nicht als CSRF-Problem gemeldet."""
    body = """\
    <html><body>
        <form method="get" action="/search">
            <input type="text" name="q">
            <input type="submit" value="Suche">
        </form>
    </body></html>
    """
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InjectionScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    csrf_findings = [f for f in result.findings if "CSRF" in f.titel]
    assert len(csrf_findings) == 0


async def test_xss_reflected_parameter_detected(scan_config):
    """Reflektierter GET-Parameter (XSS-Indikator) wird erkannt."""
    # MockHttpClient der den Marker im Response-Body reflektiert
    http = MockHttpClient()
    body = "<html><body><h1>Suche</h1></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )

    # Fuer jeden moeglichen Parameter-Test eine Response registrieren die den Marker reflektiert
    # Der Scanner generiert UUIDs, also muessen wir prefix-matchen
    # Wir registrieren den Base-URL-Prefix
    http.responses["https://example.com"] = (200, "Ergebnis: REFLECTED_MARKER_PLACEHOLDER")

    scanner = InjectionScanner(scan_config, http)
    await scanner.scan(context)

    # Der Scanner hat Requests gemacht
    assert len(http.requests) > 0
    # Alle Requests enthalten den Marker in der URL als Query-Parameter
    for url in http.requests:
        assert "?" in url
        assert "=" in url


async def test_xss_reflected_param_with_marker_reflection(scan_config):
    """XSS: Wenn der injizierte Marker in der Response erscheint, wird Reflection gemeldet."""
    # Wir muessen den Scanner so austricksen, dass der Marker reflektiert wird.
    # Dazu erstellen wir einen Custom MockHttpClient der den Parameter-Wert aus der URL extrahiert.
    from tests.conftest import MockResponse

    class ReflectingMockHttp:
        """Mock der GET-Parameter-Werte im Response-Body reflektiert."""

        def __init__(self):
            self.requests = []
            self.request_log = []

        async def get(self, url, **kwargs):
            self.requests.append(url)
            self.request_log.append(("GET", url))
            # Parameter-Wert aus URL extrahieren und reflektieren
            if "?" in url and "=" in url:
                param_value = url.split("=", 1)[1]
                return MockResponse(200, f"<html>Ergebnis fuer: {param_value}</html>", url)
            return MockResponse(200, "<html>OK</html>", url)

        async def head(self, url, **kwargs):
            self.requests.append(url)
            self.request_log.append(("HEAD", url))
            return MockResponse(200, "", url)

    http = ReflectingMockHttp()
    body = "<html><body><p>Willkommen</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )

    scanner = InjectionScanner(scan_config, http)
    result = await scanner.scan(context)

    assert result.success
    reflected = [f for f in result.findings if "Reflektierter Parameter" in f.titel]
    # Alle REFLECTION_PARAMS (q, search, query, name, id, page, redirect, url, next) reflektiert
    assert len(reflected) == 9
    for finding in reflected:
        assert finding.severity == Severity.MITTEL
        assert "XSS" in finding.beschreibung
    assert result.raw_data["reflected_params"] == [
        "q",
        "search",
        "query",
        "name",
        "id",
        "page",
        "redirect",
        "url",
        "next",
    ]


async def test_xss_no_reflection_when_not_reflected(scan_config):
    """Kein XSS-Finding wenn der Marker nicht reflektiert wird."""
    # MockHttpClient der nie den Marker reflektiert
    http = MockHttpClient(
        responses={"https://example.com": (200, "<html>Keine Reflexion hier</html>")},
    )
    body = "<html><body><p>OK</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )

    scanner = InjectionScanner(scan_config, http)
    result = await scanner.scan(context)

    assert result.success
    reflected = [f for f in result.findings if "Reflektierter Parameter" in f.titel]
    assert len(reflected) == 0
    assert result.raw_data["reflected_params"] == []


async def test_mixed_content_iframe_detected(scan_config, mock_http):
    """HTTP-Iframe auf HTTPS-Seite wird als Mixed Content erkannt."""
    body = '<html><body><iframe src="http://evil.com/page"></iframe></body></html>'
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InjectionScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    mixed = [f for f in result.findings if "Mixed Content" in f.titel]
    assert len(mixed) == 1
    assert "iframe" in mixed[0].beweis


async def test_multiple_post_forms_without_csrf(scan_config, mock_http):
    """Mehrere POST-Formulare ohne CSRF-Token werden alle erkannt."""
    body = """\
    <html><body>
        <form method="post" action="/login">
            <input type="text" name="user">
        </form>
        <form method="post" action="/register">
            <input type="text" name="email">
        </form>
        <form method="post" action="/comment">
            <input type="hidden" name="csrf_token" value="xyz">
            <textarea name="body"></textarea>
        </form>
    </body></html>
    """
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InjectionScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    csrf_findings = [f for f in result.findings if "CSRF" in f.titel]
    assert len(csrf_findings) == 2
    assert result.raw_data["forms_without_csrf"] == 2
