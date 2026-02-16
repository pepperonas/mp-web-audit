"""Rich-Konsolen-Ausgabe mit Scores und Findings."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from webaudit.core.models import AuditReport, Severity


def _score_color(score: float) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    if score >= 40:
        return "orange1"
    return "red"


def _score_bar(score: float, width: int = 20) -> Text:
    filled = int(score / 100 * width)
    color = _score_color(score)
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="dim")
    bar.append(f" {score:.0f}/100", style=f"bold {color}")
    return bar


def render_terminal_report(report: AuditReport, console: Console | None = None) -> None:
    """Gibt den Report auf der Konsole aus."""
    console = console or Console()

    # Header
    console.print()
    console.print(Panel(
        f"[bold]Web-Audit Report[/bold]\n"
        f"Ziel: [cyan]{report.target_url}[/cyan]\n"
        f"Zeitpunkt: {report.zeitstempel.strftime('%d.%m.%Y %H:%M:%S')}\n"
        f"Dauer: {report.dauer:.1f}s",
        title="mp-web-audit",
        border_style="blue",
    ))

    # Scores
    if report.scores:
        console.print()
        score_table = Table(title="Bewertung", show_header=True, header_style="bold")
        score_table.add_column("Kategorie", style="bold", min_width=15)
        score_table.add_column("Score", min_width=30)

        # Gesamt-Score zuerst
        if "Gesamt" in report.scores:
            gesamt = report.scores["Gesamt"]
            score_table.add_row(
                Text("GESAMT", style="bold"),
                _score_bar(gesamt),
            )
            score_table.add_row("", "")  # Leerzeile

        for cat, score in sorted(report.scores.items()):
            if cat == "Gesamt":
                continue
            score_table.add_row(cat, _score_bar(score))

        console.print(score_table)

    # Findings nach Schweregrad
    findings = report.all_findings
    if findings:
        console.print()

        # Zusammenfassung
        severity_counts: dict[Severity, int] = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        summary_parts = []
        for sev in Severity:
            count = severity_counts.get(sev, 0)
            if count:
                summary_parts.append(f"[{sev.color}]{count} {sev.value}[/{sev.color}]")

        console.print(f"Findings: {', '.join(summary_parts)}")
        console.print()

        # Detaillierte Findings-Tabelle
        findings_table = Table(show_header=True, header_style="bold", expand=True)
        findings_table.add_column("Schweregrad", width=10)
        findings_table.add_column("Scanner", width=12)
        findings_table.add_column("Titel", min_width=30)
        findings_table.add_column("Beschreibung", min_width=30)

        for f in findings:
            findings_table.add_row(
                Text(f.severity.value, style=f"bold {f.severity.color}"),
                f.scanner,
                f.titel,
                f.beschreibung[:100] + ("..." if len(f.beschreibung) > 100 else ""),
            )

        console.print(findings_table)

    # Scanner-Fehler
    errors = [r for r in report.results if not r.success]
    if errors:
        console.print()
        console.print("[bold red]Scanner-Fehler:[/bold red]")
        for r in errors:
            console.print(f"  [red]✗[/red] {r.scanner_name}: {r.error}")

    console.print()
