"""Tests fuer den InfoDisclosure-Scanner."""

from bs4 import BeautifulSoup

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.info_disclosure import InfoDisclosureScanner


async def test_internal_ip_in_body(scan_config, mock_http):
    """Interne IP-Adressen im Body werden erkannt."""
    body = "<html><body>Server: 192.168.1.100 is running</body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    ip_findings = [f for f in result.findings if "IP-Adresse" in f.titel]
    assert len(ip_findings) == 1
    assert ip_findings[0].severity == Severity.MITTEL
    assert "192.168.1.100" in ip_findings[0].beweis


async def test_error_pattern_php_fatal(scan_config, mock_http):
    """PHP Fatal Error im Quelltext wird erkannt."""
    body = "<html><body>PHP Fatal error: Uncaught Exception in /var/www</body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    error_findings = [f for f in result.findings if "Fehler-Information" in f.titel]
    assert len(error_findings) == 1
    assert error_findings[0].severity == Severity.HOCH
    assert "PHP" in error_findings[0].titel


async def test_error_pattern_python_traceback(scan_config, mock_http):
    """Python Traceback im Quelltext wird erkannt."""
    body = "<html><body>Traceback (most recent call last):\n  File ...</body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    error_findings = [f for f in result.findings if "Fehler-Information" in f.titel]
    assert len(error_findings) == 1
    assert "Python" in error_findings[0].titel


async def test_sensitive_comment_password(scan_config, mock_http):
    """HTML-Kommentar mit Passwort wird erkannt."""
    body = "<html><body><!-- password: secret123 --><p>Hello</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    comment_findings = [f for f in result.findings if "Kommentar" in f.titel]
    assert len(comment_findings) == 1
    assert comment_findings[0].severity == Severity.MITTEL
    assert "Passwort" in comment_findings[0].titel


async def test_sensitive_comment_todo(scan_config, mock_http):
    """HTML-Kommentar mit TODO wird erkannt."""
    body = "<html><body><!-- TODO: remove debug code --><p>Hello</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    comment_findings = [f for f in result.findings if "Kommentar" in f.titel]
    assert len(comment_findings) == 1
    assert comment_findings[0].severity == Severity.NIEDRIG


async def test_email_in_body(scan_config, mock_http):
    """E-Mail-Adressen im Quelltext werden erkannt."""
    body = "<html><body>Kontakt: admin@firma.de und info@firma.de</body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    email_findings = [f for f in result.findings if "E-Mail" in f.titel]
    assert len(email_findings) == 1
    assert email_findings[0].severity == Severity.INFO
    assert "admin@firma.de" in email_findings[0].beweis


async def test_clean_page_no_disclosure(scan_config, mock_http):
    """Saubere Seite ohne Information Disclosure."""
    body = "<html><body><h1>Willkommen</h1><p>Alles gut.</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    assert len(result.findings) == 1
    assert "Keine Information Disclosure" in result.findings[0].titel
    assert result.findings[0].severity == Severity.INFO


async def test_sql_error_mysql_syntax(scan_config, mock_http):
    """MySQL SQL-Syntax-Fehler im Response wird erkannt."""
    body = (
        "<html><body>"
        "You have an error in your SQL syntax; check the manual that "
        "corresponds to your MySQL server version"
        "</body></html>"
    )
    context = ScanContext(
        target_url="https://example.com",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    error_findings = [f for f in result.findings if "Fehler-Information" in f.titel]
    assert len(error_findings) == 1
    assert error_findings[0].severity == Severity.HOCH
    assert "SQL" in error_findings[0].titel


async def test_sql_error_pdo_exception(scan_config, mock_http):
    """PDOException (PHP SQL-Fehler) im Response wird erkannt."""
    body = (
        "<html><body>"
        "Fatal error: Uncaught PDOException: SQLSTATE[42S02]: "
        "Base table or view not found: 1146 Table 'users' doesn't exist"
        "</body></html>"
    )
    context = ScanContext(
        target_url="https://example.com",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    error_findings = [f for f in result.findings if "Fehler-Information" in f.titel]
    assert len(error_findings) >= 1
    assert error_findings[0].severity == Severity.HOCH


async def test_sql_error_oracle(scan_config, mock_http):
    """Oracle ORA-Fehler im Response wird erkannt."""
    body = "<html><body>ORA-00942: table or view does not exist</body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    error_findings = [f for f in result.findings if "Fehler-Information" in f.titel]
    assert len(error_findings) == 1
    assert "SQL" in error_findings[0].titel


async def test_sql_error_postgresql(scan_config, mock_http):
    """PostgreSQL pg_query Fehler im Response wird erkannt."""
    body = (
        "<html><body>"
        "Warning: pg_query(): Query failed: ERROR: relation "
        '"users" does not exist'
        "</body></html>"
    )
    context = ScanContext(
        target_url="https://example.com",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    error_findings = [f for f in result.findings if "Fehler-Information" in f.titel]
    assert len(error_findings) == 1
    assert error_findings[0].severity == Severity.HOCH


async def test_java_exception_detected(scan_config, mock_http):
    """Java Exception Stack Trace im Response wird erkannt."""
    body = (
        "<html><body>"
        "javax.ServletException: Something went wrong\n"
        "    at com.example.service.UserService.getUser(UserService.java:42)"
        "</body></html>"
    )
    context = ScanContext(
        target_url="https://example.com",
        status_code=500,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    error_findings = [f for f in result.findings if "Fehler-Information" in f.titel]
    assert len(error_findings) == 1
    assert "Java" in error_findings[0].titel


async def test_api_key_in_html_comment(scan_config, mock_http):
    """API-Key in HTML-Kommentar wird erkannt."""
    body = "<html><body><!-- api_key=sk_live_abc123def456 --><p>OK</p></body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    comment_findings = [f for f in result.findings if "Kommentar" in f.titel]
    assert len(comment_findings) == 1
    assert comment_findings[0].severity == Severity.MITTEL
    assert "Secret" in comment_findings[0].titel or "API" in comment_findings[0].titel


async def test_internal_ip_in_headers(scan_config, mock_http):
    """Interne IP-Adressen in Response-Headers werden erkannt."""
    body = "<html><body>OK</body></html>"
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={
            "Content-Type": "text/html",
            "X-Backend-Server": "10.0.1.50:8080",
        },
        body=body,
        soup=BeautifulSoup(body, "lxml"),
    )
    scanner = InfoDisclosureScanner(scan_config, mock_http)
    result = await scanner.scan(context)

    assert result.success
    ip_findings = [f for f in result.findings if "IP-Adresse" in f.titel]
    assert len(ip_findings) == 1
    assert "10.0.1.50" in ip_findings[0].beweis
