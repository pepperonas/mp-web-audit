"""CWE/OWASP-Referenzmapping fuer Audit-Findings."""

from __future__ import annotations

from webaudit.core.models import Finding

# Mapping: Teilstring im Finding-Titel -> (CWE-ID, CWE-Name, OWASP-Category)
# Pattern-Matching ist case-insensitive gegen finding.titel.
# Die Reihenfolge ist relevant: der erste Treffer gewinnt.
FINDING_REFERENCES: dict[str, tuple[str, str, str]] = {
    # --- headers scanner ---
    "hsts header fehlt": (
        "CWE-319",
        "Cleartext Transmission of Sensitive Information",
        "A05:2021 Security Misconfiguration",
    ),
    "hsts max-age zu kurz": (
        "CWE-319",
        "Cleartext Transmission of Sensitive Information",
        "A05:2021 Security Misconfiguration",
    ),
    "hsts ohne includesubdomains": (
        "CWE-319",
        "Cleartext Transmission of Sensitive Information",
        "A05:2021 Security Misconfiguration",
    ),
    "content-security-policy fehlt": (
        "CWE-1021",
        "Improper Restriction of Rendered UI Layers or Frames",
        "A05:2021 Security Misconfiguration",
    ),
    "csp ist zu permissiv": (
        "CWE-79",
        "Improper Neutralization of Input During Web Page Generation (XSS)",
        "A03:2021 Injection",
    ),
    "x-frame-options fehlt": (
        "CWE-1021",
        "Improper Restriction of Rendered UI Layers or Frames",
        "A05:2021 Security Misconfiguration",
    ),
    "x-content-type-options fehlt": (
        "CWE-16",
        "Configuration",
        "A05:2021 Security Misconfiguration",
    ),
    "cors erlaubt alle origins": (
        "CWE-942",
        "Permissive Cross-domain Policy with Untrusted Domains",
        "A05:2021 Security Misconfiguration",
    ),
    "server-version exponiert": (
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "A05:2021 Security Misconfiguration",
    ),
    "x-powered-by header exponiert": (
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "A05:2021 Security Misconfiguration",
    ),
    # --- cookies scanner ---
    "fehlende flags": (
        "CWE-614",
        "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "A05:2021 Security Misconfiguration",
    ),
    "samesite=none ohne secure": (
        "CWE-1275",
        "Sensitive Cookie with Improper SameSite Attribute",
        "A05:2021 Security Misconfiguration",
    ),
    "__secure- cookie": (
        "CWE-614",
        "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "A05:2021 Security Misconfiguration",
    ),
    "__host- cookie": (
        "CWE-614",
        "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "A05:2021 Security Misconfiguration",
    ),
    "verletzt prefix-anforderungen": (
        "CWE-614",
        "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "A05:2021 Security Misconfiguration",
    ),
    # --- ssl_scanner ---
    "schwache ssl/tls-protokolle": (
        "CWE-326",
        "Inadequate Encryption Strength",
        "A02:2021 Cryptographic Failures",
    ),
    "schwache cipher-suites": (
        "CWE-327",
        "Use of a Broken or Risky Cryptographic Algorithm",
        "A02:2021 Cryptographic Failures",
    ),
    "zertifikat abgelaufen": (
        "CWE-295",
        "Improper Certificate Validation",
        "A02:2021 Cryptographic Failures",
    ),
    "zertifikat laeuft bald ab": (
        "CWE-295",
        "Improper Certificate Validation",
        "A02:2021 Cryptographic Failures",
    ),
    "heartbleed": (
        "CWE-119",
        "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "A06:2021 Vulnerable and Outdated Components",
    ),
    "robot-schwachstelle": (
        "CWE-203",
        "Observable Discrepancy (Padding Oracle)",
        "A02:2021 Cryptographic Failures",
    ),
    # --- redirect scanner ---
    "http->https redirect fehlt": (
        "CWE-319",
        "Cleartext Transmission of Sensitive Information",
        "A02:2021 Cryptographic Failures",
    ),
    "open redirect": (
        "CWE-601",
        "URL Redirection to Untrusted Site (Open Redirect)",
        "A01:2021 Broken Access Control",
    ),
    # --- dns scanner ---
    "spf-record fehlt": (
        "CWE-290",
        "Authentication Bypass by Spoofing",
        "A05:2021 Security Misconfiguration",
    ),
    "spf-record zu permissiv": (
        "CWE-290",
        "Authentication Bypass by Spoofing",
        "A05:2021 Security Misconfiguration",
    ),
    "dmarc-record fehlt": (
        "CWE-290",
        "Authentication Bypass by Spoofing",
        "A05:2021 Security Misconfiguration",
    ),
    "zone transfer": (
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "A01:2021 Broken Access Control",
    ),
    # --- injection scanner ---
    "reflektierter parameter": (
        "CWE-79",
        "Improper Neutralization of Input During Web Page Generation (XSS)",
        "A03:2021 Injection",
    ),
    "csrf-token": (
        "CWE-352",
        "Cross-Site Request Forgery (CSRF)",
        "A01:2021 Broken Access Control",
    ),
    "mixed content": (
        "CWE-311",
        "Missing Encryption of Sensitive Data",
        "A02:2021 Cryptographic Failures",
    ),
    # --- info_disclosure scanner ---
    "interne ip-adressen": (
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "A01:2021 Broken Access Control",
    ),
    "fehler-information exponiert": (
        "CWE-209",
        "Generation of Error Message Containing Sensitive Information",
        "A05:2021 Security Misconfiguration",
    ),
    "e-mail-adresse": (
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "A01:2021 Broken Access Control",
    ),
    # --- misconfig scanner ---
    ".env-datei exponiert": (
        "CWE-538",
        "Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "A05:2021 Security Misconfiguration",
    ),
    "git-repository exponiert": (
        "CWE-538",
        "Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "A05:2021 Security Misconfiguration",
    ),
    "exponiert": (
        "CWE-538",
        "Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "A05:2021 Security Misconfiguration",
    ),
}


def enrich_finding(finding: Finding) -> Finding:
    """Ergaenzt ein Finding mit CWE-ID, CWE-Name und OWASP-Kategorie.

    Durchsucht FINDING_REFERENCES nach dem ersten Teilstring-Treffer
    gegen finding.titel (case-insensitive). Setzt cwe_id, cwe_name und
    owasp_category direkt am Finding-Objekt.

    Args:
        finding: Das Finding das angereichert werden soll.

    Returns:
        Das gleiche Finding-Objekt (in-place modifiziert).
    """
    titel_lower = finding.titel.lower()
    for pattern, (cwe_id, cwe_name, owasp_category) in FINDING_REFERENCES.items():
        if pattern in titel_lower:
            finding.cwe_id = cwe_id
            finding.cwe_name = cwe_name
            finding.owasp_category = owasp_category
            break
    return finding
