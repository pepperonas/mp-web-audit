"""webaudit scan <URL> – Vollaudit (alle Scanner)."""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

from webaudit.cli.common import build_config, check_fail_on
from webaudit.core.exceptions import AuthorizationError

console = Console()


def _show_authorization_prompt(
    url: str,
    scan_typ: str,
    port_scan: bool = True,
    discovery: bool = True,
) -> datetime:
    """Zeigt den Autorisierungs-Disclaimer und gibt den Zeitstempel zurueck."""
    info_lines = [
        "[bold red]WARNUNG: Dieses Tool fuehrt aktive Sicherheits-[/bold red]",
        "[bold red]pruefungen durch. Die Nutzung ohne ausdrueckliche[/bold red]",
        "[bold red]Genehmigung des Ziel-Betreibers ist illegal.[/bold red]",
        "",
        f"Ziel: [cyan]{url}[/cyan]",
        f"Scan-Typ: [cyan]{scan_typ}[/cyan]",
        f"Port-Scan: [cyan]{'Ja' if port_scan else 'Nein'}[/cyan]",
        f"Directory-Discovery: [cyan]{'Ja' if discovery else 'Nein'}[/cyan]",
    ]
    console.print()
    console.print(Panel("\n".join(info_lines), border_style="red"))

    antwort = typer.prompt(
        "Haben Sie die ausdrueckliche Genehmigung, dieses Ziel zu scannen? [j/N]",
        default="N",
    )
    if antwort.lower() not in ("j", "ja", "y", "yes"):
        raise AuthorizationError("Autorisierung verweigert. Scan abgebrochen.")

    return datetime.now()


def scan_cmd(
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
    skip_discovery: bool = typer.Option(
        False, "--skip-discovery", help="Directory-Discovery ueberspringen"
    ),
    port_range: str = typer.Option("1-1000", "--port-range", help="Nmap Port-Range"),
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
    weights: Optional[str] = typer.Option(None, "--weights", help="Score-Gewichtung als JSON"),
) -> None:
    """Fuehrt ein Vollaudit durch (alle Scanner)."""
    auth_time = _show_authorization_prompt(
        url,
        "Vollaudit",
        port_scan=not skip_ports,
        discovery=not skip_discovery,
    )

    config = build_config(
        url=url,
        categories=["web", "security", "techstack", "discovery"],
        output=output,
        formats=formats,
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent,
        no_verify_ssl=no_verify_ssl,
        skip_ssl=skip_ssl,
        skip_ports=skip_ports,
        skip_discovery=skip_discovery,
        port_range=port_range,
        wordlist=wordlist,
        extensions=extensions,
        verbose=verbose,
        fail_on=fail_on,
        quiet=quiet,
        json_stdout=json_stdout,
        weights=weights,
    )

    from webaudit.orchestrator import run_audit

    report = asyncio.run(
        run_audit(config, scan_typ="Vollaudit", console=console, autorisierung_zeit=auth_time)
    )
    check_fail_on(report, fail_on)
