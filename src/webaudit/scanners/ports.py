"""Port-Scanner via python-nmap."""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.core.utils import extract_domain
from webaudit.scanners import register_scanner

# Ports die auf moeglicherweise gefaehrliche Dienste hindeuten
RISKY_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    445: "SMB",
    1433: "MS-SQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
}


@register_scanner
class PortsScanner(BaseScanner):
    name = "ports"
    description = "Scannt offene Ports via nmap"
    category = "security"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        hostname = extract_domain(context.target_url).split(":")[0]

        try:
            open_ports, raw = await asyncio.to_thread(
                self._run_nmap, hostname
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name, kategorie="Sicherheit",
                success=False, error=f"nmap Fehler: {e}",
            )

        # Risiko-Ports bewerten
        for port_info in open_ports:
            port_num = port_info["port"]
            service = port_info.get("service", "unbekannt")

            if port_num in RISKY_PORTS:
                findings.append(Finding(
                    scanner=self.name, kategorie="Sicherheit",
                    titel=f"Riskanter Port offen: {port_num} ({RISKY_PORTS[port_num]})",
                    severity=Severity.HOCH,
                    beschreibung=f"Port {port_num} ({RISKY_PORTS[port_num]}) ist offen. "
                                 f"Dieser Dienst sollte nicht oeffentlich zugaenglich sein.",
                    beweis=f"Port {port_num}/{port_info.get('protocol', 'tcp')} - {service}",
                    empfehlung=f"Port {port_num} per Firewall blockieren oder den Dienst absichern.",
                ))
            elif port_num not in (80, 443):
                findings.append(Finding(
                    scanner=self.name, kategorie="Sicherheit",
                    titel=f"Port {port_num} offen ({service})",
                    severity=Severity.INFO,
                    beschreibung=f"Port {port_num} ist offen und bietet den Dienst '{service}' an.",
                    beweis=f"Port {port_num}/{port_info.get('protocol', 'tcp')} - {service}",
                    empfehlung="",
                ))

        if not open_ports:
            findings.append(Finding(
                scanner=self.name, kategorie="Sicherheit",
                titel="Keine offenen Ports gefunden",
                severity=Severity.INFO,
                beschreibung="Im gescannten Bereich wurden keine offenen Ports gefunden.",
                empfehlung="",
            ))

        return ScanResult(
            scanner_name=self.name, kategorie="Sicherheit",
            findings=findings, raw_data=raw,
        )

    def _run_nmap(self, hostname: str) -> tuple[list[dict], dict]:
        import nmap

        nm = nmap.PortScanner()
        nm.scan(hostname, self.config.port_range, arguments="-sV --open -T4")

        open_ports: list[dict] = []
        raw: dict[str, Any] = {"hostname": hostname, "port_range": self.config.port_range}

        for host in nm.all_hosts():
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()
                for port in sorted(ports):
                    port_data = nm[host][protocol][port]
                    if port_data["state"] == "open":
                        open_ports.append({
                            "port": port,
                            "protocol": protocol,
                            "service": port_data.get("name", ""),
                            "version": port_data.get("version", ""),
                            "product": port_data.get("product", ""),
                        })

        raw["open_ports"] = open_ports
        raw["total_open"] = len(open_ports)
        return open_ports, raw
