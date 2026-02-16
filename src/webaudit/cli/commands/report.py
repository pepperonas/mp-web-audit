"""webaudit report <JSON> – Report aus JSON neu generieren."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from webaudit.core.config import ScanConfig
from webaudit.reporting.engine import generate_reports
from webaudit.reporting.json_reporter import load_report_from_json

console = Console()


def report_cmd(
    json_file: Path = typer.Argument(..., help="Pfad zur JSON-Report-Datei", exists=True),
    output: Path = typer.Option(Path("./reports"), "-o", "--output", help="Ausgabeverzeichnis"),
    formats: str = typer.Option("html,terminal", "-f", "--format", help="Report-Formate"),
) -> None:
    """Generiert Reports aus einer bestehenden JSON-Datei neu."""
    console.print(f"[cyan]Lade Report:[/cyan] {json_file}")

    report = load_report_from_json(json_file)

    config = ScanConfig(
        target_url=report.target_url,
        output_dir=output,
        formats=[f.strip() for f in formats.split(",")],
    )

    generated = generate_reports(report, config, console)
    if generated:
        console.print(f"\n[green]{len(generated)} Report(s) generiert.[/green]")
