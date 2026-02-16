"""Tests fuer den Port-Scanner."""

from unittest.mock import patch

from webaudit.core.models import ScanContext, Severity
from webaudit.scanners.ports import PortsScanner


async def test_nmap_not_available(scan_config, mock_http):
    """Wenn nmap nicht installiert ist, ist der Scanner nicht verfuegbar."""
    scanner = PortsScanner(scan_config, mock_http)
    with patch("shutil.which", return_value=None):
        assert scanner.is_available() is False


async def test_nmap_available(scan_config, mock_http):
    """Wenn nmap installiert ist, ist der Scanner verfuegbar."""
    scanner = PortsScanner(scan_config, mock_http)
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        assert scanner.is_available() is True


async def test_ports_scanner_metadata(scan_config, mock_http):
    """Port-Scanner hat korrekte Metadaten."""
    scanner = PortsScanner(scan_config, mock_http)
    assert scanner.name == "ports"
    assert scanner.category == "security"


async def test_risky_port_detected(scan_config, mock_http):
    """Riskante offene Ports werden als HOCH gemeldet."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
    )

    with patch.object(PortsScanner, "_run_nmap") as mock_nmap:
        mock_nmap.return_value = (
            [
                {
                    "port": 3306,
                    "protocol": "tcp",
                    "service": "mysql",
                    "version": "5.7",
                    "product": "MySQL",
                },
                {"port": 80, "protocol": "tcp", "service": "http", "version": "", "product": ""},
            ],
            {"hostname": "example.com", "port_range": "1-1000", "open_ports": [], "total_open": 2},
        )

        scanner = PortsScanner(scan_config, mock_http)
        result = await scanner.scan(context)

    assert result.success
    risky_findings = [f for f in result.findings if "Riskanter Port" in f.titel]
    assert len(risky_findings) == 1
    assert risky_findings[0].severity == Severity.HOCH
    assert "3306" in risky_findings[0].titel


async def test_no_open_ports(scan_config, mock_http):
    """Keine offenen Ports erzeugen INFO-Finding."""
    context = ScanContext(
        target_url="https://example.com",
        status_code=200,
        headers={},
        body="",
    )

    with patch.object(PortsScanner, "_run_nmap") as mock_nmap:
        mock_nmap.return_value = (
            [],
            {"hostname": "example.com", "port_range": "1-1000", "open_ports": [], "total_open": 0},
        )

        scanner = PortsScanner(scan_config, mock_http)
        result = await scanner.scan(context)

    assert result.success
    assert len(result.findings) == 1
    assert "Keine offenen Ports" in result.findings[0].titel
    assert result.findings[0].severity == Severity.INFO
