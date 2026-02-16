"""Report-Orchestrator: Koordiniert alle Report-Formate."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from webaudit.core.config import ScanConfig
from webaudit.core.models import AuditReport
from webaudit.reporting.csv_reporter import generate_csv_report
from webaudit.reporting.html_reporter import generate_html_report
from webaudit.reporting.json_reporter import generate_json_report
from webaudit.reporting.terminal_reporter import render_terminal_report


def generate_reports(
    report: AuditReport,
    config: ScanConfig,
    console: Console | None = None,
) -> list[Path]:
    """Generiert Reports in allen konfigurierten Formaten."""
    console = console or Console()
    generated: list[Path] = []

    timestamp = report.zeitstempel.strftime("%Y%m%d_%H%M%S")
    domain = report.target_url.split("//")[-1].split("/")[0].replace(":", "_")
    base_name = f"audit_{domain}_{timestamp}"

    if "terminal" in config.formats:
        render_terminal_report(report, console)

    if "json" in config.formats:
        json_path = config.output_dir / f"{base_name}.json"
        generate_json_report(report, json_path)
        generated.append(json_path)
        console.print(f"[green]JSON-Report:[/green] {json_path}")

    if "html" in config.formats:
        html_path = config.output_dir / f"{base_name}.html"
        generate_html_report(report, html_path)
        generated.append(html_path)
        console.print(f"[green]HTML-Report:[/green] {html_path}")

    if "csv" in config.formats:
        csv_path = config.output_dir / f"{base_name}.csv"
        generate_csv_report(report, csv_path)
        generated.append(csv_path)
        console.print(f"[green]CSV-Report:[/green] {csv_path}")

    return generated
