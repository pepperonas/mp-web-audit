"""webaudit security <URL> – Nur Sicherheits-Checks."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from webaudit.cli.commands.scan import _show_authorization_prompt
from webaudit.cli.common import build_config, check_fail_on

console = Console()


def security_cmd(
    url: str = typer.Argument(..., help="Ziel-URL"),
    output: Path = typer.Option(Path("./reports"), "-o", "--output", help="Ausgabeverzeichnis"),
    formats: str = typer.Option("html,json,terminal", "-f", "--format", help="Report-Formate"),
    timeout: float = typer.Option(10.0, "-t", "--timeout", help="HTTP-Timeout in Sekunden"),
    rate_limit: int = typer.Option(10, "--rate-limit", help="Max. Requests pro Sekunde"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    no_verify_ssl: bool = typer.Option(
        False, "--no-verify-ssl", help="SSL-Verifizierung deaktivieren"
    ),
    skip_ssl: bool = typer.Option(False, "--skip-ssl", help="SSL-Scanner ueberspringen"),
    skip_ports: bool = typer.Option(False, "--skip-ports", help="Port-Scanning ueberspringen"),
    port_range: str = typer.Option("1-1000", "--port-range", help="Nmap Port-Range"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Ausfuehrliche Ausgabe"),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit-Code 1 bei Findings >= Severity (KRITISCH|HOCH|MITTEL|NIEDRIG)",
    ),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Keine Terminal-Ausgabe"),
    json_stdout: bool = typer.Option(False, "--json-stdout", help="JSON-Report nach stdout"),
    weights: Optional[str] = typer.Option(None, "--weights", help="Score-Gewichtung als JSON"),
) -> None:
    """Fuehrt nur Sicherheits-Checks durch."""
    auth_time = _show_authorization_prompt(
        url,
        "Sicherheits-Checks",
        port_scan=not skip_ports,
        discovery=False,
    )

    config = build_config(
        url=url,
        categories=["security"],
        output=output,
        formats=formats,
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent,
        no_verify_ssl=no_verify_ssl,
        skip_ssl=skip_ssl,
        skip_ports=skip_ports,
        skip_discovery=True,
        port_range=port_range,
        verbose=verbose,
        fail_on=fail_on,
        quiet=quiet,
        json_stdout=json_stdout,
        weights=weights,
    )

    from webaudit.orchestrator import run_audit

    report = asyncio.run(
        run_audit(
            config, scan_typ="Sicherheits-Checks", console=console, autorisierung_zeit=auth_time
        )
    )
    check_fail_on(report, fail_on)
