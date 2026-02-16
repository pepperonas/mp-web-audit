"""SSL/TLS-Scanner via sslyze mit Zertifikats-Ablauf und Cipher-Analyse."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.core.utils import extract_domain
from webaudit.scanners import register_scanner

WEAK_CIPHER_KEYWORDS = ["rc4", "3des", "des-cbc", "cbc"]


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
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="Kein HTTPS",
                    severity=Severity.KRITISCH,
                    beschreibung="Die Seite nutzt kein HTTPS.",
                    empfehlung="HTTPS aktivieren und alle HTTP-Anfragen weiterleiten.",
                )
            )
            raw["valid_cert"] = False
            return ScanResult(
                scanner_name=self.name,
                kategorie="Sicherheit",
                findings=findings,
                raw_data=raw,
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
                scanner_name=self.name,
                kategorie="Sicherheit",
                success=False,
                error=f"sslyze Fehler: {e}",
                findings=findings,
                raw_data=raw,
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data=raw,
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
            if result.scan_result is None:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="SSL-Scan fehlgeschlagen",
                        severity=Severity.HOCH,
                        beschreibung="Der SSL-Scan konnte nicht durchgefuehrt werden (keine Verbindung).",
                        empfehlung="Pruefen ob der Server erreichbar ist und SSL korrekt konfiguriert ist.",
                    )
                )
                raw["valid_cert"] = False
                return findings

            # Zertifikat pruefen
            cert_result = result.scan_result.certificate_info
            if cert_result and cert_result.result:
                for deployment in cert_result.result.certificate_deployments:
                    # Zertifikatskette validieren via path_validation_results
                    has_valid_path = any(
                        pv.verified_certificate_chain is not None and pv.validation_error is None
                        for pv in deployment.path_validation_results
                    )
                    if not has_valid_path:
                        raw["valid_cert"] = False
                        findings.append(
                            Finding(
                                scanner=self.name,
                                kategorie="Sicherheit",
                                titel="Zertifikat-Validierung fehlgeschlagen",
                                severity=Severity.HOCH,
                                beschreibung="Das SSL-Zertifikat konnte gegen keinen Trust-Store validiert werden.",
                                empfehlung="Korrektes Zertifikat fuer den Hostnamen installieren.",
                            )
                        )

                    # Zertifikats-Ablaufdatum pruefen
                    cert_chain = deployment.received_certificate_chain
                    if cert_chain:
                        leaf_cert = cert_chain[0]
                        not_after = leaf_cert.not_valid_after_utc
                        now = datetime.now(timezone.utc)
                        days_remaining = (not_after - now).days
                        raw["cert_days_remaining"] = days_remaining
                        raw["cert_not_after"] = not_after.isoformat()

                        if days_remaining < 0:
                            findings.append(
                                Finding(
                                    scanner=self.name,
                                    kategorie="Sicherheit",
                                    titel="SSL-Zertifikat abgelaufen!",
                                    severity=Severity.KRITISCH,
                                    beschreibung=f"Das Zertifikat ist seit {abs(days_remaining)} Tagen abgelaufen.",
                                    beweis=f"Ablaufdatum: {not_after.strftime('%d.%m.%Y')}",
                                    empfehlung="Zertifikat sofort erneuern.",
                                )
                            )
                        elif days_remaining < 30:
                            findings.append(
                                Finding(
                                    scanner=self.name,
                                    kategorie="Sicherheit",
                                    titel="SSL-Zertifikat laeuft bald ab",
                                    severity=Severity.HOCH,
                                    beschreibung=f"Das Zertifikat laeuft in {days_remaining} Tagen ab.",
                                    beweis=f"Ablaufdatum: {not_after.strftime('%d.%m.%Y')}",
                                    empfehlung="Zertifikat zeitnah erneuern.",
                                )
                            )
                        elif days_remaining < 90:
                            findings.append(
                                Finding(
                                    scanner=self.name,
                                    kategorie="Sicherheit",
                                    titel="SSL-Zertifikat Ablauf beachten",
                                    severity=Severity.MITTEL,
                                    beschreibung=f"Das Zertifikat laeuft in {days_remaining} Tagen ab.",
                                    beweis=f"Ablaufdatum: {not_after.strftime('%d.%m.%Y')}",
                                    empfehlung="Zertifikats-Erneuerung planen.",
                                )
                            )

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
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="Schwache SSL/TLS-Protokolle aktiv",
                        severity=Severity.HOCH,
                        beschreibung=f"Veraltete Protokolle sind aktiviert: {', '.join(weak_protocols)}",
                        beweis=f"Aktive schwache Protokolle: {', '.join(weak_protocols)}",
                        empfehlung="Nur TLSv1.2 und TLSv1.3 erlauben.",
                    )
                )

            # Schwache Cipher-Suites in TLS 1.2
            tls12 = result.scan_result.tls_1_2_cipher_suites
            if tls12 and tls12.result:
                weak_ciphers = []
                for cipher in tls12.result.accepted_cipher_suites:
                    cipher_name = cipher.cipher_suite.name.lower()
                    if any(kw in cipher_name for kw in WEAK_CIPHER_KEYWORDS):
                        weak_ciphers.append(cipher.cipher_suite.name)
                if weak_ciphers:
                    raw["has_weak_ciphers"] = True
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel="Schwache Cipher-Suites in TLS 1.2",
                            severity=Severity.MITTEL,
                            beschreibung=f"{len(weak_ciphers)} schwache Cipher-Suite(s) erkannt.",
                            beweis=f"Schwache Ciphers: {', '.join(weak_ciphers[:5])}",
                            empfehlung="Schwache Cipher-Suites (RC4, 3DES, CBC) deaktivieren.",
                        )
                    )

            # TLS 1.3 pruefen
            tls13 = result.scan_result.tls_1_3_cipher_suites
            if tls13 and tls13.result and not tls13.result.accepted_cipher_suites:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="TLSv1.3 nicht unterstuetzt",
                        severity=Severity.NIEDRIG,
                        beschreibung="Der Server unterstuetzt kein TLS 1.3.",
                        empfehlung="TLSv1.3 aktivieren fuer bessere Performance und Sicherheit.",
                    )
                )

            # Heartbleed
            heartbleed = result.scan_result.heartbleed
            if heartbleed and heartbleed.result and heartbleed.result.is_vulnerable_to_heartbleed:
                raw["has_vulnerabilities"] = True
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="KRITISCH: Heartbleed-Schwachstelle!",
                        severity=Severity.KRITISCH,
                        beschreibung="Der Server ist anfaellig fuer den Heartbleed-Angriff (CVE-2014-0160).",
                        empfehlung="OpenSSL sofort aktualisieren und alle Zertifikate/Schluessel erneuern.",
                        referenzen=["https://heartbleed.com/"],
                    )
                )

            # ROBOT
            robot = result.scan_result.robot
            if robot and robot.result:
                from sslyze import RobotScanResultEnum

                if robot.result.robot_result in (
                    RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
                    RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
                ):
                    raw["has_vulnerabilities"] = True
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel="ROBOT-Schwachstelle erkannt",
                            severity=Severity.HOCH,
                            beschreibung="Der Server ist anfaellig fuer den ROBOT-Angriff.",
                            empfehlung="TLS-Konfiguration aktualisieren, RSA-Key-Exchange deaktivieren.",
                            referenzen=["https://robotattack.org/"],
                        )
                    )

        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="SSL/TLS-Konfiguration in Ordnung",
                    severity=Severity.INFO,
                    beschreibung="Keine Probleme bei der SSL/TLS-Konfiguration erkannt.",
                    empfehlung="",
                )
            )

        return findings
