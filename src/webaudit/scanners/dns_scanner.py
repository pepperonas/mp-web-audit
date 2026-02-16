"""DNS-Scanner: SPF, DMARC, CAA, DNSSEC, Zone Transfer, MX."""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner


@register_scanner
class DnsScanner(BaseScanner):
    name = "dns"
    description = "Prueft DNS-Sicherheitseintraege (SPF, DMARC, CAA, DNSSEC)"
    category = "security"

    def is_available(self) -> bool:
        try:
            import dns.resolver  # noqa: F401

            return True
        except ImportError:
            return False

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        raw: dict[str, Any] = {}

        parsed = urlparse(context.target_url)
        domain = parsed.hostname or ""

        # Subdomain zu Root-Domain aufloesen (fuer Mail-Records)
        parts = domain.split(".")
        if len(parts) > 2:
            root_domain = ".".join(parts[-2:])
        else:
            root_domain = domain

        result_data = await asyncio.to_thread(self._check_dns, root_domain, raw)
        findings.extend(result_data)

        return ScanResult(
            scanner_name=self.name,
            kategorie="Sicherheit",
            findings=findings,
            raw_data=raw,
        )

    def _check_dns(self, domain: str, raw: dict) -> list[Finding]:
        import dns.resolver
        import dns.exception

        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()

        # SPF-Record
        try:
            answers = resolver.resolve(domain, "TXT")
            spf_records = [str(r).strip('"') for r in answers if "v=spf1" in str(r).lower()]
            raw["has_spf"] = len(spf_records) > 0
            if spf_records:
                spf = spf_records[0]
                raw["spf_record"] = spf
                # SPF-Staerke pruefen
                if "+all" in spf:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel="SPF-Record zu permissiv",
                            severity=Severity.HOCH,
                            beschreibung='Der SPF-Record endet mit "+all" - alle Server duerfen Mails senden.',
                            beweis=f"SPF: {spf}",
                            empfehlung='SPF auf "-all" oder "~all" umstellen.',
                        )
                    )
                elif "~all" not in spf and "-all" not in spf:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel="SPF-Record ohne Fail-Mechanismus",
                            severity=Severity.MITTEL,
                            beschreibung="Der SPF-Record hat keinen -all oder ~all Mechanismus.",
                            beweis=f"SPF: {spf}",
                            empfehlung='SPF-Record mit "-all" oder "~all" abschliessen.',
                        )
                    )
            else:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="SPF-Record fehlt",
                        severity=Severity.MITTEL,
                        beschreibung="Kein SPF-Record gefunden. E-Mail-Spoofing ist moeglich.",
                        empfehlung="SPF-Record im DNS setzen um E-Mail-Spoofing zu verhindern.",
                    )
                )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            raw["has_spf"] = False

        # DMARC-Record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = [str(r).strip('"') for r in answers if "v=dmarc1" in str(r).lower()]
            raw["has_dmarc"] = len(dmarc_records) > 0
            if dmarc_records:
                dmarc = dmarc_records[0]
                raw["dmarc_record"] = dmarc
                # DMARC Policy Staerke pruefen
                dmarc_lower = dmarc.lower()
                if "p=none" in dmarc_lower:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            kategorie="Sicherheit",
                            titel="DMARC Policy ist nur 'none' (Monitoring-Modus)",
                            severity=Severity.NIEDRIG,
                            beschreibung="DMARC ist auf p=none gesetzt. E-Mails werden nicht blockiert, nur gemeldet.",
                            beweis=f"DMARC: {dmarc}",
                            empfehlung="DMARC Policy auf p=quarantine oder p=reject umstellen.",
                        )
                    )
            else:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Sicherheit",
                        titel="DMARC-Record fehlt",
                        severity=Severity.MITTEL,
                        beschreibung="Kein DMARC-Record gefunden. E-Mail-Authentifizierung ist unvollstaendig.",
                        empfehlung="DMARC-Record setzen: _dmarc.domain TXT v=DMARC1; p=quarantine;",
                    )
                )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            raw["has_dmarc"] = False
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="DMARC-Record fehlt",
                    severity=Severity.MITTEL,
                    beschreibung="Kein DMARC-Record gefunden.",
                    empfehlung="DMARC-Record setzen um E-Mail-Authentifizierung zu verbessern.",
                )
            )

        # CAA-Records
        try:
            answers = resolver.resolve(domain, "CAA")
            caa_records = [str(r) for r in answers]
            raw["has_caa"] = len(caa_records) > 0
            raw["caa_records"] = caa_records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            raw["has_caa"] = False
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="CAA-Records fehlen",
                    severity=Severity.NIEDRIG,
                    beschreibung="Keine CAA-Records gesetzt. Jede CA kann Zertifikate ausstellen.",
                    empfehlung="CAA-Records setzen um erlaubte Zertifizierungsstellen einzuschraenken.",
                )
            )

        # MX-Records
        try:
            mx_answers = resolver.resolve(domain, "MX")
            mx_records = [str(r) for r in mx_answers]
            raw["mx_records"] = mx_records
            raw["has_mx"] = len(mx_records) > 0
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            raw["has_mx"] = False
            raw["mx_records"] = []

        # DNSSEC (DNSKEY-Record pruefen)
        try:
            resolver.resolve(domain, "DNSKEY")
            raw["has_dnssec"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            raw["has_dnssec"] = False
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="DNSSEC nicht konfiguriert",
                    severity=Severity.NIEDRIG,
                    beschreibung="Keine DNSKEY-Records gefunden. DNS-Antworten sind nicht kryptographisch verifizierbar.",
                    empfehlung="DNSSEC aktivieren um DNS-Spoofing zu erschweren.",
                )
            )

        # Zone Transfer (AXFR) Test
        try:
            ns_answers = resolver.resolve(domain, "NS")
            ns_servers = [str(r).rstrip(".") for r in ns_answers]
            raw["ns_records"] = ns_servers

            import dns.query
            import dns.zone

            for ns in ns_servers[:3]:  # Nur erste 3 NS testen
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                    if zone:
                        findings.append(
                            Finding(
                                scanner=self.name,
                                kategorie="Sicherheit",
                                titel=f"Zone Transfer (AXFR) moeglich: {ns}",
                                severity=Severity.HOCH,
                                beschreibung=f"Der Nameserver {ns} erlaubt Zone Transfers. "
                                f"Angreifer koennen alle DNS-Records der Domain einsehen.",
                                beweis=f"AXFR erfolgreich bei: {ns}",
                                empfehlung="Zone Transfers auf autorisierte Nameserver beschraenken.",
                            )
                        )
                        raw["axfr_vulnerable"] = True
                        break
                except Exception:
                    continue
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            raw["ns_records"] = []

        if not findings:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel="DNS-Sicherheitseintraege vorhanden",
                    severity=Severity.INFO,
                    beschreibung="SPF, DMARC und CAA Records sind gesetzt.",
                    empfehlung="",
                )
            )

        return findings
