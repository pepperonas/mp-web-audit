"""webaudit discover <URL> – Nur Directory-Discovery."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from webaudit.cli.commands.scan import _show_authorization_prompt
from webaudit.core.config import ScanConfig

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
) -> None:
    """Fuehrt Directory-Discovery via feroxbuster durch."""
    auth_time = _show_authorization_prompt(
        url,
        "Directory-Discovery",
        port_scan=False,
        discovery=True,
    )

    config = ScanConfig(
        target_url=url,
        output_dir=output,
        formats=[f.strip() for f in formats.split(",")],
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent or "mp-web-audit/0.1.0",
        verify_ssl=not no_verify_ssl,
        wordlist=wordlist,
        extensions=extensions,
        verbose=verbose,
        categories=["discovery"],
    )

    from webaudit.orchestrator import run_audit

    asyncio.run(
        run_audit(
            config, scan_typ="Directory-Discovery", console=console, autorisierung_zeit=auth_time
        )
    )
