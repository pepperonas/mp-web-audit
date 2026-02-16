"""webaudit security <URL> – Nur Sicherheits-Checks."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from webaudit.cli.commands.scan import _show_authorization_prompt
from webaudit.core.config import ScanConfig

console = Console()


def security_cmd(
    url: str = typer.Argument(..., help="Ziel-URL"),
    output: Path = typer.Option(Path("./reports"), "-o", "--output", help="Ausgabeverzeichnis"),
    formats: str = typer.Option("html,json,terminal", "-f", "--format", help="Report-Formate"),
    timeout: float = typer.Option(10.0, "-t", "--timeout", help="HTTP-Timeout in Sekunden"),
    rate_limit: int = typer.Option(10, "--rate-limit", help="Max. Requests pro Sekunde"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="SSL-Verifizierung deaktivieren"),
    skip_ssl: bool = typer.Option(False, "--skip-ssl", help="SSL-Scanner ueberspringen"),
    skip_ports: bool = typer.Option(False, "--skip-ports", help="Port-Scanning ueberspringen"),
    port_range: str = typer.Option("1-1000", "--port-range", help="Nmap Port-Range"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Ausfuehrliche Ausgabe"),
) -> None:
    """Fuehrt nur Sicherheits-Checks durch."""
    auth_time = _show_authorization_prompt(
        url, "Sicherheits-Checks",
        port_scan=not skip_ports,
        discovery=False,
    )

    config = ScanConfig(
        target_url=url,
        output_dir=output,
        formats=[f.strip() for f in formats.split(",")],
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent or "mp-web-audit/0.1.0",
        verify_ssl=not no_verify_ssl,
        skip_ssl=skip_ssl,
        skip_ports=skip_ports,
        skip_discovery=True,
        port_range=port_range,
        verbose=verbose,
        categories=["security"],
    )

    from webaudit.orchestrator import run_audit
    asyncio.run(run_audit(config, scan_typ="Sicherheits-Checks", console=console, autorisierung_zeit=auth_time))
