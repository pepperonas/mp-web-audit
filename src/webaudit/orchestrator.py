"""Scan-Koordination: Orchestriert Scanner-Ausfuehrung und Report-Generierung."""

from __future__ import annotations

import time
from datetime import datetime

from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from webaudit.core.config import ScanConfig
from webaudit.core.http_client import create_http_client
from webaudit.core.models import AuditReport, AutorisierungInfo, ScanContext, ScanResult
from webaudit.core.scoring import calculate_scores
from webaudit.core.utils import normalize_url, timer
from webaudit.reporting.engine import generate_reports
from webaudit.scanners import discover_scanners, get_scanner_registry


async def run_audit(
    config: ScanConfig,
    scan_typ: str = "Vollaudit",
    console: Console | None = None,
    autorisierung_zeit: datetime | None = None,
) -> AuditReport:
    """Fuehrt ein komplettes Audit durch."""
    console = console or Console()
    discover_scanners()

    target_url = normalize_url(config.target_url)
    config.target_url = target_url

    report = AuditReport(target_url=target_url)
    if autorisierung_zeit:
        report.autorisierung = AutorisierungInfo(
            bestaetigt=True,
            zeitstempel=autorisierung_zeit,
            ziel=target_url,
            scan_typ=scan_typ,
        )

    start_time = time.monotonic()

    async with create_http_client(config) as http:
        # Initiale Anfrage
        console.print(f"\n[cyan]Lade Ziel:[/cyan] {target_url}")
        try:
            resp = await http.get(target_url)
        except Exception as e:
            console.print(f"[red]Fehler beim Laden der Ziel-URL:[/red] {e}")
            report.dauer = round(time.monotonic() - start_time, 1)
            return report

        # ScanContext bauen
        redirects = [str(r.url) for r in resp.history] if resp.history else []
        soup = BeautifulSoup(resp.text, "lxml")

        # Cookies extrahieren
        cookies_dict = {}
        for name, value in resp.cookies.items():
            cookies_dict[name] = value

        context = ScanContext(
            target_url=target_url,
            final_url=str(resp.url),
            status_code=resp.status_code,
            headers={k: v for k, v in resp.headers.items()},
            body=resp.text,
            soup=soup,
            redirects=redirects,
            response_time=resp.elapsed.total_seconds() if resp.elapsed else 0,
            cookies=cookies_dict,
        )

        console.print(
            f"[green]Geladen:[/green] Status {resp.status_code}, "
            f"{len(resp.text)} Bytes, "
            f"{context.response_time*1000:.0f}ms TTFB"
        )

        # Scanner filtern und ausfuehren
        registry = get_scanner_registry()
        scanners_to_run = _filter_scanners(registry, config)

        console.print(f"\n[cyan]Starte {len(scanners_to_run)} Scanner...[/cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            for scanner_name, scanner_cls in scanners_to_run.items():
                task = progress.add_task(f"{scanner_cls.description}...", total=None)
                scanner = scanner_cls(config, http)

                if not scanner.is_available():
                    progress.update(task, description=f"[yellow]{scanner_name}: nicht verfuegbar (uebersprungen)[/yellow]")
                    report.results.append(ScanResult(
                        scanner_name=scanner_name,
                        kategorie=scanner_cls.category,
                        success=False,
                        error="Externe Abhaengigkeit nicht verfuegbar",
                    ))
                    progress.remove_task(task)
                    continue

                try:
                    await scanner.setup()
                    with timer() as t:
                        result = await scanner.scan(context)
                    result.dauer = t["elapsed"]
                    report.results.append(result)

                    status = "[green]OK[/green]" if result.success else f"[red]Fehler: {result.error}[/red]"
                    findings_count = len(result.findings)
                    progress.update(
                        task,
                        description=f"{scanner_name}: {status} ({findings_count} Findings, {t['elapsed']:.1f}s)",
                    )
                except Exception as e:
                    report.results.append(ScanResult(
                        scanner_name=scanner_name,
                        kategorie=scanner_cls.category,
                        success=False,
                        error=str(e),
                    ))
                    progress.update(task, description=f"[red]{scanner_name}: {e}[/red]")
                finally:
                    try:
                        await scanner.teardown()
                    except Exception:
                        pass
                    progress.remove_task(task)

    # Scores berechnen
    report.scores = calculate_scores(report)
    report.dauer = round(time.monotonic() - start_time, 1)

    # Reports generieren
    generate_reports(report, config, console)

    return report


def _filter_scanners(registry: dict, config: ScanConfig) -> dict:
    """Filtert Scanner nach Kategorie und Skip-Flags."""
    filtered = {}
    for name, cls in registry.items():
        if cls.category not in config.categories:
            continue
        if config.skip_ssl and name == "ssl_scanner":
            continue
        if config.skip_ports and name == "ports":
            continue
        if config.skip_discovery and name == "directory":
            continue
        filtered[name] = cls
    return filtered
