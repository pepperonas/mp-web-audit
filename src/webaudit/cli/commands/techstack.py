"""webaudit techstack <URL> – Nur Tech-Stack-Erkennung."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from webaudit.core.config import ScanConfig

console = Console()


def techstack_cmd(
    url: str = typer.Argument(..., help="Ziel-URL"),
    output: Path = typer.Option(Path("./reports"), "-o", "--output", help="Ausgabeverzeichnis"),
    formats: str = typer.Option("html,json,terminal", "-f", "--format", help="Report-Formate"),
    timeout: float = typer.Option(10.0, "-t", "--timeout", help="HTTP-Timeout in Sekunden"),
    rate_limit: int = typer.Option(10, "--rate-limit", help="Max. Requests pro Sekunde"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent"),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="SSL-Verifizierung deaktivieren"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Ausfuehrliche Ausgabe"),
) -> None:
    """Erkennt den Tech-Stack der Ziel-Website."""
    console.print(Panel(
        f"[cyan]Tech-Stack-Analyse[/cyan] fuer: [bold]{url}[/bold]",
        border_style="blue",
    ))

    config = ScanConfig(
        target_url=url,
        output_dir=output,
        formats=[f.strip() for f in formats.split(",")],
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent or "mp-web-audit/0.1.0",
        verify_ssl=not no_verify_ssl,
        verbose=verbose,
        categories=["techstack"],
    )

    from webaudit.orchestrator import run_audit
    asyncio.run(run_audit(config, scan_typ="Tech-Stack-Analyse", console=console))
