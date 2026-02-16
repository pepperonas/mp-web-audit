"""SSL/TLS-Scanner via sslyze."""

from __future__ import annotations

import asyncio
from typing import Any

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.core.utils import extract_domain
from webaudit.scanners import register_scanner


@register_scanner
class SslScanner(BaseScanner):
    name = "ssl_scanner"
    description = "Prueft SSL/TLS-Konfiguration via sslyze"
    category = "security"

    def is_available(self) -> bool:
        try:
            import sslyze  # noqa: F401
            return True
        except ImportError:
            return False

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        raw: dict[str, Any] = {
            "valid_cert": True,
            "has_weak_protocols": False,
            "has_weak_ciphers": False,
            "has_vulnerabilities": False,
        }

        if not context.target_url.startswith("https"):
            findings.append(Finding(
                scanner=self.name, kategorie="Sicherheit",
                titel="Kein HTTPS",
                severity=Severity.KRITISCH,
                beschreibung="Die Seite nutzt kein HTTPS.",
                empfehlung="HTTPS aktivieren und alle HTTP-Anfragen weiterleiten.",
            ))
            raw["valid_cert"] = False
            return ScanResult(
                scanner_name=self.name, kategorie="Sicherheit",
                findings=findings, raw_data=raw,
            )

        domain = extract_domain(context.target_url)
        # Port extrahieren falls angegeben
        hostname = domain.split(":")[0]
        port = int(domain.split(":")[1]) if ":" in domain else 443

        try:
            result = await asyncio.to_thread(self._run_sslyze, hostname, port, raw)
            findings.extend(result)
        except Exception as e:
            return ScanResult(
                scanner_name=self.name, kategorie="Sicherheit",
                success=False, error=f"sslyze Fehler: {e}",
                findings=findings, raw_data=raw,
            )

        return ScanResult(
            scanner_name=self.name, kategorie="Sicherheit",
            findings=findings, raw_data=raw,
        )

    def _run_sslyze(self, hostname: str, port: int, raw: dict) -> list[Finding]:
        from sslyze import (
            Scanner,
            ServerScanRequest,
            ServerNetworkLocation,
            ScanCommand,
        )

        findings: list[Finding] = []

        location = ServerNetworkLocation(hostname=hostname, port=port)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([request])

        for result in scanner.get_results():
            # Zertifikat pruefen
            cert_result = result.scan_result.certificate_info
            if cert_result and cert_result.result:
                for deployment in cert_result.result.certificate_deployments:
                    if not deployment.leaf_certificate_subject_matches_hostname:
                        raw["valid_cert"] = False
                        findings.append(Finding(
                            scanner=self.name, kategorie="Sicherheit",
                            titel="Zertifikat stimmt nicht mit Hostname ueberein",
                            severity=Severity.HOCH,
                            beschreibung="Das SSL-Zertifikat passt nicht zum Hostnamen.",
                            empfehlung="Korrektes Zertifikat fuer den Hostnamen installieren.",
                        ))

            # Schwache Protokolle
            weak_protocols = []
            for attr, name in [
                ("ssl_2_0_cipher_suites", "SSLv2"),
                ("ssl_3_0_cipher_suites", "SSLv3"),
                ("tls_1_0_cipher_suites", "TLSv1.0"),
                ("tls_1_1_cipher_suites", "TLSv1.1"),
            ]:
                scan_result = getattr(result.scan_result, attr, None)
                if scan_result and scan_result.result:
                    if scan_result.result.accepted_cipher_suites:
                        weak_protocols.append(name)

            if weak_protocols:
                raw["has_weak_protocols"] = True
                findings.append(Finding(
                    scanner=self.name, kategorie="Sicherheit",
                    titel="Schwache SSL/TLS-Protokolle aktiv",
                    severity=Severity.HOCH,
                    beschreibung=f"Veraltete Protokolle sind aktiviert: {', '.join(weak_protocols)}",
                    beweis=f"Aktive schwache Protokolle: {', '.join(weak_protocols)}",
                    empfehlung="Nur TLSv1.2 und TLSv1.3 erlauben.",
                ))

            # TLS 1.3 pruefen
            tls13 = result.scan_result.tls_1_3_cipher_suites
            if tls13 and tls13.result and not tls13.result.accepted_cipher_suites:
                findings.append(Finding(
                    scanner=self.name, kategorie="Sicherheit",
                    titel="TLSv1.3 nicht unterstuetzt",
                    severity=Severity.NIEDRIG,
                    beschreibung="Der Server unterstuetzt kein TLS 1.3.",
                    empfehlung="TLSv1.3 aktivieren fuer bessere Performance und Sicherheit.",
                ))

            # Heartbleed
            heartbleed = result.scan_result.heartbleed
            if heartbleed and heartbleed.result and heartbleed.result.is_vulnerable_to_heartbleed:
                raw["has_vulnerabilities"] = True
                findings.append(Finding(
                    scanner=self.name, kategorie="Sicherheit",
                    titel="KRITISCH: Heartbleed-Schwachstelle!",
                    severity=Severity.KRITISCH,
                    beschreibung="Der Server ist anfaellig fuer den Heartbleed-Angriff (CVE-2014-0160).",
                    empfehlung="OpenSSL sofort aktualisieren und alle Zertifikate/Schluessel erneuern.",
                    referenzen=["https://heartbleed.com/"],
                ))

            # ROBOT
            robot = result.scan_result.robot
            if robot and robot.result:
                from sslyze import RobotScanResultEnum
                if robot.result.robot_result in (
                    RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
                    RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
                ):
                    raw["has_vulnerabilities"] = True
                    findings.append(Finding(
                        scanner=self.name, kategorie="Sicherheit",
                        titel="ROBOT-Schwachstelle erkannt",
                        severity=Severity.HOCH,
                        beschreibung="Der Server ist anfaellig fuer den ROBOT-Angriff.",
                        empfehlung="TLS-Konfiguration aktualisieren, RSA-Key-Exchange deaktivieren.",
                        referenzen=["https://robotattack.org/"],
                    ))

        if not findings:
            findings.append(Finding(
                scanner=self.name, kategorie="Sicherheit",
                titel="SSL/TLS-Konfiguration in Ordnung",
                severity=Severity.INFO,
                beschreibung="Keine Probleme bei der SSL/TLS-Konfiguration erkannt.",
                empfehlung="",
            ))

        return findings
