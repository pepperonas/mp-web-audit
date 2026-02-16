"""Typer-App mit Subcommands und Autorisierungs-Prompt."""

from __future__ import annotations

import typer

from webaudit import __version__

app = typer.Typer(
    name="webaudit",
    help="mp-web-audit – CLI-basiertes Web-Auditing-Framework fuer genehmigte Sicherheitspruefungen.",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mp-web-audit v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=version_callback,
        is_eager=True,
        help="Version anzeigen.",
    ),
) -> None:
    """mp-web-audit – Web-Auditing-Framework."""


# Subcommands importieren und registrieren
from webaudit.cli.commands.scan import scan_cmd  # noqa: E402
from webaudit.cli.commands.web import web_cmd  # noqa: E402
from webaudit.cli.commands.security import security_cmd  # noqa: E402
from webaudit.cli.commands.techstack import techstack_cmd  # noqa: E402
from webaudit.cli.commands.discover import discover_cmd  # noqa: E402
from webaudit.cli.commands.report import report_cmd  # noqa: E402

app.command(name="scan", help="Vollaudit – alle Scanner")(scan_cmd)
app.command(name="web", help="Nur Web-Checks (Performance, SEO, Mobile, Usability)")(web_cmd)
app.command(name="security", help="Nur Sicherheits-Checks")(security_cmd)
app.command(name="techstack", help="Nur Tech-Stack-Erkennung")(techstack_cmd)
app.command(name="discover", help="Nur Directory-Discovery")(discover_cmd)
app.command(name="report", help="Report aus JSON neu generieren")(report_cmd)
