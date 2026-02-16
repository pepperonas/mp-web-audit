"""webaudit discover <URL> – Nur Directory-Discovery."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from webaudit.cli.commands.scan import _show_authorization_prompt
from webaudit.cli.common import build_config, check_fail_on

console = Console()


def discover_cmd(
    url: str = typer.Argument(..., help="Ziel-URL"),
    output: Path = typer.Option(Path("./reports"), "-o", "--output", help="Ausgabeverzeichnis"),
    formats: str = typer.Option("html,json,terminal", "-f", "--format", help="Report-Formate"),
    timeout: float = typer.Option(10.0, "-t", "--timeout", help="HTTP-Timeout in Sekunden"),
    rate_limit: int = typer.Option(10, "--rate-limit", help="Max. Requests pro Sekunde"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    no_verify_ssl: bool = typer.Option(
        False, "--no-verify-ssl", help="SSL-Verifizierung deaktivieren"
    ),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Eigene Wordlist"),
    extensions: str = typer.Option(
        "php,html,js,txt,bak", "--extensions", help="Datei-Erweiterungen"
    ),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Ausfuehrliche Ausgabe"),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit-Code 1 bei Findings >= Severity (KRITISCH|HOCH|MITTEL|NIEDRIG)",
    ),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Keine Terminal-Ausgabe"),
    json_stdout: bool = typer.Option(False, "--json-stdout", help="JSON-Report nach stdout"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Log-Datei Pfad"),
    scanner_timeout: float = typer.Option(
        60.0, "--scanner-timeout", help="Timeout pro Scanner in Sekunden"
    ),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP/SOCKS Proxy URL"),
    auth_header: Optional[str] = typer.Option(
        None, "--auth-header", help="Auth-Header (z.B. 'Authorization: Bearer token')"
    ),
    auth_cookie: Optional[str] = typer.Option(
        None, "--auth-cookie", help="Auth-Cookie (z.B. 'session=abc123')"
    ),
) -> None:
    """Fuehrt Directory-Discovery via Wordlist durch."""
    auth_time = _show_authorization_prompt(
        url,
        "Directory-Discovery",
        port_scan=False,
        discovery=True,
    )

    config = build_config(
        url=url,
        categories=["discovery"],
        output=output,
        formats=formats,
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent,
        no_verify_ssl=no_verify_ssl,
        wordlist=wordlist,
        extensions=extensions,
        verbose=verbose,
        fail_on=fail_on,
        quiet=quiet,
        json_stdout=json_stdout,
        log_file=log_file,
        scanner_timeout=scanner_timeout,
        proxy=proxy,
        auth_header=auth_header,
        auth_cookie=auth_cookie,
    )

    from webaudit.orchestrator import run_audit

    report = asyncio.run(
        run_audit(
            config, scan_typ="Directory-Discovery", console=console, autorisierung_zeit=auth_time
        )
    )
    check_fail_on(report, fail_on)
