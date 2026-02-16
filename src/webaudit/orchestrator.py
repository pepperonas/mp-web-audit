"""Scan-Koordination: Orchestriert Scanner-Ausfuehrung und Report-Generierung."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from webaudit import __version__
from webaudit.core.config import ScanConfig
from webaudit.core.http_client import create_http_client
from webaudit.core.models import (
    AuditReport,
    AutorisierungInfo,
    ScanContext,
    ScanMetadata,
    ScanResult,
)
from webaudit.core.scoring import calculate_scores
from webaudit.core.utils import normalize_url, timer
from webaudit.reporting.engine import generate_reports
from webaudit.scanners import discover_scanners, get_scanner_registry

# Scanner die ohne initiale HTTP-Response arbeiten koennen
NO_HTTP_SCANNERS = {"dns", "ports", "redirect"}


async def _run_scanner(
    scanner_cls: type,
    config: ScanConfig,
    http,
    context: ScanContext,
    progress: Progress,
) -> ScanResult:
    """Fuehrt einen einzelnen Scanner aus (Setup, Scan, Teardown)."""
    scanner_name = scanner_cls.name
    task = progress.add_task(f"{scanner_cls.description}...", total=None)

    scanner = scanner_cls(config, http)

    if not scanner.is_available():
        progress.update(
            task,
            description=f"[yellow]{scanner_name}: nicht verfuegbar (uebersprungen)[/yellow]",
        )
        progress.remove_task(task)
        return ScanResult(
            scanner_name=scanner_name,
            kategorie=scanner_cls.category,
            success=False,
            error="Externe Abhaengigkeit nicht verfuegbar",
        )

    try:
        await scanner.setup()
        with timer() as t:
            result = await scanner.scan(context)
        result.dauer = t["elapsed"]

        status = "[green]OK[/green]" if result.success else f"[red]Fehler: {result.error}[/red]"
        findings_count = len(result.findings)
        progress.update(
            task,
            description=f"{scanner_name}: {status} ({findings_count} Findings, {t['elapsed']:.1f}s)",
        )
        return result
    except Exception as e:
        progress.update(task, description=f"[red]{scanner_name}: {e}[/red]")
        return ScanResult(
            scanner_name=scanner_name,
            kategorie=scanner_cls.category,
            success=False,
            error=str(e),
        )
    finally:
        try:
            await scanner.teardown()
        except Exception:
            pass
        progress.remove_task(task)


async def run_audit(
    config: ScanConfig,
    scan_typ: str = "Vollaudit",
    console: Console | None = None,
    autorisierung_zeit: datetime | None = None,
) -> AuditReport:
    """Fuehrt ein komplettes Audit durch."""
    console = console or Console()
    if not config.quiet:
        console.print(f"\n[bold blue]mp-web-audit[/bold blue] [dim]v{__version__}[/dim]")
    discover_scanners()

    target_url = normalize_url(config.target_url)
    config.target_url = target_url

    # IP-Adresse resolven
    target_ip = _resolve_ip(target_url)

    report = AuditReport(target_url=target_url, target_ip=target_ip)
    if autorisierung_zeit:
        report.autorisierung = AutorisierungInfo(
            bestaetigt=True,
            zeitstempel=autorisierung_zeit,
            ziel=target_url,
            scan_typ=scan_typ,
        )

    start_time = time.monotonic()

    async with create_http_client(config) as http:
        # Initiale Anfrage mit Fallback-Strategien
        if not config.quiet:
            ip_info = f" [dim]({target_ip})[/dim]" if target_ip else ""
            console.print(f"\n[cyan]Lade Ziel:[/cyan] {target_url}{ip_info}")

        resp = await _try_connect(target_url, http, config, console)

        if resp is not None:
            # ScanContext bauen
            redirects = [str(r.url) for r in resp.history] if resp.history else []
            soup = BeautifulSoup(resp.text, "lxml")

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

            if not config.quiet:
                console.print(
                    f"[green]Geladen:[/green] Status {resp.status_code}, "
                    f"{len(resp.text)} Bytes, "
                    f"{context.response_time * 1000:.0f}ms TTFB"
                )
        else:
            if not config.quiet:
                console.print(
                    "[yellow]Fuehre netzwerk-unabhaengige Scanner trotzdem aus...[/yellow]"
                )
            context = ScanContext(
                target_url=target_url,
                status_code=0,
                headers={},
                body="",
            )

        # Scanner filtern und ausfuehren
        registry = get_scanner_registry()
        scanners_to_run = _filter_scanners(registry, config)

        # Bei fehlendem HTTP-Response nur netzwerk-unabhaengige Scanner laufen lassen
        if context.status_code == 0:
            http_dependent = {
                name: cls for name, cls in scanners_to_run.items() if name not in NO_HTTP_SCANNERS
            }
            skipped_names = list(http_dependent.keys())
            scanners_to_run = {
                name: cls for name, cls in scanners_to_run.items() if name in NO_HTTP_SCANNERS
            }
            if skipped_names and not config.quiet:
                console.print(f"[dim]Uebersprungen (kein HTTP): {', '.join(skipped_names)}[/dim]")

        if not config.quiet:
            console.print(f"\n[cyan]Starte {len(scanners_to_run)} Scanner...[/cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=Console(quiet=config.quiet),
        ) as progress:
            # Parallele Ausfuehrung aller Scanner via TaskGroup
            results: list[ScanResult] = []

            async with asyncio.TaskGroup() as tg:
                tasks = []
                for scanner_name, scanner_cls in scanners_to_run.items():
                    t = tg.create_task(_run_scanner(scanner_cls, config, http, context, progress))
                    tasks.append(t)

            results = [t.result() for t in tasks]
            report.results = results

    # Scores berechnen
    report.scores = calculate_scores(report, custom_weights=config.scoring_weights)
    report.dauer = round(time.monotonic() - start_time, 1)

    # Metadaten setzen
    import platform

    report.metadata = ScanMetadata(
        tool_version=__version__,
        python_version=platform.python_version(),
        scan_config={
            "categories": config.categories,
            "timeout": config.timeout,
            "rate_limit": config.rate_limit,
        },
    )

    # Reports generieren
    if config.json_stdout:
        import json
        import sys

        data = report.model_dump(mode="json")
        json.dump(data, sys.stdout, indent=2, ensure_ascii=False, default=str)
        sys.stdout.write("\n")
    else:
        generate_reports(report, config, console if not config.quiet else Console(quiet=True))

    return report


def _resolve_ip(target_url: str) -> str:
    """Loest den Hostnamen der Ziel-URL zu einer IP-Adresse auf."""
    import socket

    hostname = urlparse(target_url).hostname or ""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


async def _try_connect(
    target_url: str,
    http,
    config: ScanConfig,
    console: Console,
) -> httpx.Response | None:
    """Versucht verschiedene Verbindungsstrategien zum Ziel."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

    # Strategie 1: Original-URL
    try:
        return await http.get(target_url)
    except Exception:
        pass

    # Strategie 2: SSL-Verifizierung deaktivieren (self-signed certs)
    if parsed.scheme == "https" and config.verify_ssl:
        if not config.quiet:
            console.print("[dim]  Versuche ohne SSL-Verifizierung...[/dim]")
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(config.timeout),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": config.user_agent},
            ) as client:
                resp = await client.get(target_url)
                if not config.quiet:
                    console.print(
                        "[yellow]  Verbindung nur ohne SSL-Verifizierung moeglich.[/yellow]"
                    )
                return resp
        except Exception:
            pass

    # Strategie 3: Anderes Protokoll (https->http oder http->https)
    if parsed.scheme == "https":
        alt_url = target_url.replace("https://", "http://", 1)
    else:
        alt_url = target_url.replace("http://", "https://", 1)
    if not config.quiet:
        console.print(f"[dim]  Versuche {alt_url}...[/dim]")
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": config.user_agent},
        ) as client:
            resp = await client.get(alt_url)
            if not config.quiet:
                console.print(f"[yellow]  Erreichbar ueber {alt_url}[/yellow]")
            return resp
    except Exception:
        pass

    # Strategie 4: Alternative Ports (8080, 8443)
    alt_ports = [8443, 8080] if parsed.scheme == "https" else [8080, 8443]
    for port in alt_ports:
        alt = f"{parsed.scheme}://{hostname}:{port}{parsed.path or '/'}"
        if not config.quiet:
            console.print(f"[dim]  Versuche Port {port}...[/dim]")
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(config.timeout),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": config.user_agent},
            ) as client:
                resp = await client.get(alt)
                if not config.quiet:
                    console.print(f"[yellow]  Erreichbar ueber Port {port}[/yellow]")
                return resp
        except Exception:
            pass

    # Alle Strategien fehlgeschlagen
    if not config.quiet:
        console.print(
            f"[red]Ziel nicht erreichbar:[/red] {hostname} antwortet auf keinem Port "
            f"(80, 443, 8080, 8443).\n"
            f"[red]Moeglich:[/red] Server offline, Firewall blockiert, DNS falsch "
            f"(IP: {parsed.hostname})"
        )
    return None


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
