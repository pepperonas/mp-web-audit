"""Shared CLI-Parameter und Config-Builder."""

from __future__ import annotations

import sys
from pathlib import Path

from webaudit.core.config import ScanConfig
from webaudit.core.models import AuditReport


def build_config(
    url: str,
    categories: list[str],
    output: Path = Path("./reports"),
    formats: str = "html,json,terminal",
    timeout: float = 10.0,
    rate_limit: int = 10,
    user_agent: str | None = None,
    no_verify_ssl: bool = False,
    skip_ssl: bool = False,
    skip_ports: bool = False,
    skip_discovery: bool = False,
    port_range: str = "1-1000",
    wordlist: Path | None = None,
    extensions: str = "php,html,js,txt,bak",
    verbose: bool = False,
    fail_on: str | None = None,
    quiet: bool = False,
    json_stdout: bool = False,
    weights: str | None = None,
    log_file: str | None = None,
    scanner_timeout: float = 60.0,
    proxy: str | None = None,
    auth_header: str | None = None,
    auth_cookie: str | None = None,
) -> ScanConfig:
    """Baut ScanConfig aus CLI-Parametern."""
    scoring_weights = None
    if weights:
        import json

        scoring_weights = json.loads(weights)

    # Logging einrichten
    from webaudit.core.logging import setup_logging

    setup_logging(verbose=verbose, log_file=log_file)

    return ScanConfig(
        target_url=url,
        output_dir=output,
        formats=[f.strip() for f in formats.split(",")],
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent or "mp-web-audit/0.4.0",
        verify_ssl=not no_verify_ssl,
        skip_ssl=skip_ssl,
        skip_ports=skip_ports,
        skip_discovery=skip_discovery,
        port_range=port_range,
        wordlist=wordlist,
        extensions=extensions,
        verbose=verbose,
        categories=categories,
        fail_on=fail_on,
        quiet=quiet,
        json_stdout=json_stdout,
        scoring_weights=scoring_weights,
        log_file=log_file,
        scanner_timeout=scanner_timeout,
        proxy_url=proxy,
        auth_header=auth_header,
        auth_cookie=auth_cookie,
    )


SEVERITY_ORDER = {
    "KRITISCH": 0,
    "HOCH": 1,
    "MITTEL": 2,
    "NIEDRIG": 3,
}


def check_fail_on(report: AuditReport, fail_on: str | None) -> None:
    """Prueft ob Findings >= Threshold vorhanden sind und beendet mit Exit-Code 1."""
    if not fail_on:
        return
    threshold = SEVERITY_ORDER.get(fail_on.upper())
    if threshold is None:
        return
    for finding in report.all_findings:
        if finding.severity.sort_order <= threshold:
            sys.exit(1)
