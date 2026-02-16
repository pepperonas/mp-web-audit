"""Tests fuer den Subdomain-Scanner."""

from unittest.mock import patch

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.subdomain import SubdomainScanner


async def test_subdomain_found_sensitive(scan_config, mock_http):
    """Sensitive Subdomains werden erkannt und als MITTEL gemeldet."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
    )

    with patch.object(SubdomainScanner, "_enumerate_subdomains") as mock_enum:
        from webaudit.core.models import Finding

        mock_enum.return_value = [
            Finding(
                scanner="subdomain",
                kategorie="Sicherheit",
                titel="2 sensible Subdomain(s) gefunden",
                severity=Severity.MITTEL,
                beschreibung="Subdomains die auf interne/sensible Dienste hindeuten.",
                beweis="staging.example.com (1.2.3.4)\nadmin.example.com (1.2.3.5)",
                empfehlung="Interne Dienste nicht oeffentlich aufloesbaren machen.",
            ),
            Finding(
                scanner="subdomain",
                kategorie="Discovery",
                titel="3 Subdomain(s) gefunden",
                severity=Severity.INFO,
                beschreibung="DNS-Enumeration hat 3 Subdomains gefunden.",
                beweis="www.example.com -> 1.2.3.4\nstaging.example.com -> 1.2.3.4\nadmin.example.com -> 1.2.3.5",
                empfehlung="Ueberpruefen ob alle Subdomains beabsichtigt sind.",
            ),
        ]

        scanner = SubdomainScanner(scan_config, mock_http)
        result = await scanner.scan(context)

    assert result.success
    sensitive_findings = [f for f in result.findings if "sensible" in f.titel]
    assert len(sensitive_findings) == 1
    assert sensitive_findings[0].severity == Severity.MITTEL

    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1


async def test_subdomain_scanner_is_available(scan_config, mock_http):
    """Subdomain-Scanner meldet Verfuegbarkeit korrekt."""
    scanner = SubdomainScanner(scan_config, mock_http)
    assert scanner.is_available() is True


async def test_subdomain_no_results(scan_config, mock_http):
    """Keine Subdomains gefunden ergibt INFO-Finding."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
    )

    with patch.object(SubdomainScanner, "_enumerate_subdomains") as mock_enum:
        from webaudit.core.models import Finding

        mock_enum.return_value = [
            Finding(
                scanner="subdomain",
                kategorie="Discovery",
                titel="Keine zusaetzlichen Subdomains gefunden",
                severity=Severity.INFO,
                beschreibung="75 Prefixes getestet.",
                empfehlung="",
            ),
        ]

        scanner = SubdomainScanner(scan_config, mock_http)
        result = await scanner.scan(context)

    assert result.success
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "Keine" in result.findings[0].titel


async def test_subdomain_scanner_metadata(scan_config, mock_http):
    """Subdomain-Scanner hat korrekte Metadaten."""
    scanner = SubdomainScanner(scan_config, mock_http)
    assert scanner.name == "subdomain"
    assert scanner.category == "discovery"
