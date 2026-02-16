"""Subdomain-Scanner: DNS-Bruteforce und Subdomain-Takeover-Check."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

logger = logging.getLogger("webaudit")

# Gaengige Subdomain-Prefixes
SUBDOMAIN_PREFIXES = [
    "www",
    "mail",
    "ftp",
    "admin",
    "dev",
    "staging",
    "test",
    "api",
    "app",
    "blog",
    "shop",
    "store",
    "portal",
    "vpn",
    "remote",
    "git",
    "gitlab",
    "jenkins",
    "ci",
    "cd",
    "jira",
    "confluence",
    "wiki",
    "docs",
    "cdn",
    "static",
    "assets",
    "media",
    "images",
    "img",
    "smtp",
    "pop",
    "imap",
    "mx",
    "ns1",
    "ns2",
    "internal",
    "intranet",
    "dashboard",
    "panel",
    "login",
    "beta",
    "alpha",
    "demo",
    "sandbox",
    "stage",
    "db",
    "database",
    "redis",
    "elastic",
    "search",
    "monitoring",
    "grafana",
    "prometheus",
    "kibana",
]

# CNAME-Ziele fuer Subdomain-Takeover
TAKEOVER_CNAMES: dict[str, str] = {
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3",
    "azurewebsites.net": "Azure",
    "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure",
    "github.io": "GitHub Pages",
    "gitbook.io": "GitBook",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "wordpress.com": "WordPress.com",
    "pantheonsite.io": "Pantheon",
    "netlify.app": "Netlify",
    "fly.dev": "Fly.io",
    "vercel.app": "Vercel",
    "surge.sh": "Surge",
    "zendesk.com": "Zendesk",
    "readme.io": "ReadMe",
    "freshdesk.com": "Freshdesk",
    "cargocollective.com": "Cargo",
    "feedpress.me": "FeedPress",
    "helpjuice.com": "HelpJuice",
    "helpscoutdocs.com": "HelpScout",
    "statuspage.io": "StatusPage",
    "teamwork.com": "Teamwork",
    "tictail.com": "Tictail",
    "unbounce.com": "Unbounce",
    "uservoice.com": "UserVoice",
}

# Subdomains die auf sensitive/interne Dienste hindeuten
SENSITIVE_SUBDOMAINS = {
    "staging",
    "internal",
    "intranet",
    "admin",
    "test",
    "dev",
    "jenkins",
    "ci",
    "git",
    "gitlab",
    "jira",
    "confluence",
    "db",
    "database",
    "redis",
    "elastic",
    "monitoring",
    "grafana",
    "prometheus",
    "kibana",
    "dashboard",
    "panel",
    "vpn",
    "remote",
    "sandbox",
    "beta",
    "alpha",
}


@register_scanner
class SubdomainScanner(BaseScanner):
    name = "subdomain"
    description = "Subdomain-Enumeration via DNS-Bruteforce"
    category = "discovery"

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

        # Root-Domain extrahieren
        parts = domain.split(".")
        if len(parts) > 2:
            root_domain = ".".join(parts[-2:])
        else:
            root_domain = domain

        result_data = await asyncio.to_thread(self._enumerate_subdomains, root_domain, raw)
        findings.extend(result_data)

        return ScanResult(
            scanner_name=self.name,
            kategorie="Discovery",
            findings=findings,
            raw_data=raw,
        )

    def _enumerate_subdomains(self, domain: str, raw: dict) -> list[Finding]:
        import dns.resolver
        import dns.exception

        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        found_subdomains: list[dict] = []
        takeover_candidates: list[dict] = []

        for prefix in SUBDOMAIN_PREFIXES:
            subdomain = f"{prefix}.{domain}"
            try:
                answers = resolver.resolve(subdomain, "A")
                ips = [str(r) for r in answers]
                found_subdomains.append(
                    {
                        "subdomain": subdomain,
                        "ips": ips,
                        "prefix": prefix,
                    }
                )

                # CNAME pruefen fuer Subdomain-Takeover
                try:
                    cname_answers = resolver.resolve(subdomain, "CNAME")
                    for cname in cname_answers:
                        cname_str = str(cname).rstrip(".")
                        for takeover_domain, service in TAKEOVER_CNAMES.items():
                            if cname_str.endswith(takeover_domain):
                                # Pruefen ob CNAME-Ziel noch existiert
                                try:
                                    resolver.resolve(cname_str, "A")
                                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                                    takeover_candidates.append(
                                        {
                                            "subdomain": subdomain,
                                            "cname": cname_str,
                                            "service": service,
                                        }
                                    )
                                break
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                    pass

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                continue

        raw["found_subdomains"] = [s["subdomain"] for s in found_subdomains]
        raw["total_found"] = len(found_subdomains)
        raw["takeover_candidates"] = len(takeover_candidates)

        # Subdomain-Takeover Findings (HOCH)
        for candidate in takeover_candidates:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel=f"Subdomain-Takeover moeglich: {candidate['subdomain']}",
                    severity=Severity.HOCH,
                    beschreibung=f"Die Subdomain {candidate['subdomain']} hat einen CNAME auf "
                    f"{candidate['cname']} ({candidate['service']}), aber das Ziel existiert nicht mehr.",
                    beweis=f"CNAME: {candidate['subdomain']} -> {candidate['cname']}",
                    empfehlung="DNS-Eintrag entfernen oder den Dienst wieder einrichten.",
                )
            )

        # Sensitive Subdomains (MITTEL)
        sensitive_found = [s for s in found_subdomains if s["prefix"] in SENSITIVE_SUBDOMAINS]
        if sensitive_found:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Sicherheit",
                    titel=f"{len(sensitive_found)} sensible Subdomain(s) gefunden",
                    severity=Severity.MITTEL,
                    beschreibung="Subdomains die auf interne/sensible Dienste hindeuten.",
                    beweis="\n".join(
                        f"{s['subdomain']} ({', '.join(s['ips'])})" for s in sensitive_found[:15]
                    ),
                    empfehlung="Interne Dienste nicht oeffentlich aufloesbaren machen. "
                    "Split-DNS oder VPN verwenden.",
                )
            )

        # Alle gefundenen Subdomains als INFO
        if found_subdomains:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Discovery",
                    titel=f"{len(found_subdomains)} Subdomain(s) gefunden",
                    severity=Severity.INFO,
                    beschreibung=f"DNS-Enumeration hat {len(found_subdomains)} Subdomains gefunden.",
                    beweis="\n".join(
                        f"{s['subdomain']} -> {', '.join(s['ips'])}" for s in found_subdomains[:20]
                    ),
                    empfehlung="Ueberpruefen ob alle Subdomains beabsichtigt sind.",
                )
            )
        else:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Discovery",
                    titel="Keine zusaetzlichen Subdomains gefunden",
                    severity=Severity.INFO,
                    beschreibung=f"{len(SUBDOMAIN_PREFIXES)} Prefixes getestet.",
                    empfehlung="",
                )
            )

        return findings
