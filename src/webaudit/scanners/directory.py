"""Directory-Discovery via HTTP-Requests (Wordlist-basiert)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

DEFAULT_WORDLIST = Path(__file__).parent.parent.parent.parent / "wordlists" / "common.txt"
DISCOVERY_CONCURRENCY = 50
DISCOVERY_TIMEOUT = 5.0


@register_scanner
class DirectoryScanner(BaseScanner):
    name = "directory"
    description = "Verzeichnis-/Datei-Enumeration via Wordlist"
    category = "discovery"

    def _create_fast_client(self) -> httpx.AsyncClient:
        """Eigener schneller Client fuer Discovery (umgeht Rate-Limiter)."""
        return httpx.AsyncClient(
            timeout=httpx.Timeout(DISCOVERY_TIMEOUT),
            follow_redirects=True,
            verify=self.config.verify_ssl,
            headers={"User-Agent": self.config.user_agent},
            limits=httpx.Limits(
                max_connections=DISCOVERY_CONCURRENCY, max_keepalive_connections=30
            ),
        )

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        wordlist = self.config.wordlist or DEFAULT_WORDLIST

        if not wordlist.exists():
            return ScanResult(
                scanner_name=self.name,
                kategorie="Discovery",
                success=False,
                error=f"Wordlist nicht gefunden: {wordlist}",
            )

        paths = [
            line.strip()
            for line in wordlist.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

        # Erweiterungen anhaengen
        extensions = [e.strip() for e in self.config.extensions.split(",") if e.strip()]
        all_paths = list(paths)
        for path in paths:
            for ext in extensions:
                all_paths.append(f"{path}.{ext}")

        base_url = context.target_url.rstrip("/")
        semaphore = asyncio.Semaphore(DISCOVERY_CONCURRENCY)

        # Schnellen Client fuer Discovery verwenden, Fallback auf self.http
        use_fast_client = hasattr(self.http, "_client")
        if use_fast_client:
            client = self._create_fast_client()
        else:
            client = None

        try:
            discovered = await self._discover_paths(base_url, all_paths, semaphore, client)
        finally:
            if client:
                await client.aclose()

        raw: dict[str, Any] = {
            "wordlist": str(wordlist),
            "extensions": self.config.extensions,
            "paths_tested": len(all_paths),
            "total_discovered": len(discovered),
        }

        if discovered:
            summary_lines = []
            for entry in discovered[:50]:
                summary_lines.append(
                    f"  [{entry['status']}] {entry['url']} ({entry['content_length']} Bytes)"
                )

            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Discovery",
                    titel=f"{len(discovered)} Pfad(e) entdeckt",
                    severity=Severity.INFO,
                    beschreibung=f"Directory-Scan hat {len(discovered)} Pfade gefunden.",
                    beweis="\n".join(summary_lines[:20]),
                    empfehlung="Ueberpruefen ob alle gefundenen Pfade beabsichtigt sind.",
                )
            )

            # 403-Eintraege separat hervorheben
            forbidden = [e for e in discovered if e["status"] == 403]
            if forbidden:
                findings.append(
                    Finding(
                        scanner=self.name,
                        kategorie="Discovery",
                        titel=f"{len(forbidden)} Pfad(e) mit Zugriffsverweigerung (403)",
                        severity=Severity.NIEDRIG,
                        beschreibung="Diese Pfade existieren, der Zugriff wird aber verweigert.",
                        beweis="\n".join(e["url"] for e in forbidden[:10]),
                        empfehlung="Sicherstellen dass die 403-Seiten keine Informationen preisgeben.",
                    )
                )
        else:
            findings.append(
                Finding(
                    scanner=self.name,
                    kategorie="Discovery",
                    titel="Keine zusaetzlichen Pfade entdeckt",
                    severity=Severity.INFO,
                    beschreibung="Directory-Scan hat keine interessanten Pfade gefunden.",
                    empfehlung="",
                )
            )

        return ScanResult(
            scanner_name=self.name,
            kategorie="Discovery",
            findings=findings,
            raw_data=raw,
        )

    async def _discover_paths(
        self,
        base_url: str,
        all_paths: list[str],
        semaphore: asyncio.Semaphore,
        fast_client: httpx.AsyncClient | None,
    ) -> list[dict[str, Any]]:
        async def check_path(path: str) -> dict[str, Any] | None:
            url = f"{base_url}/{path.lstrip('/')}"
            async with semaphore:
                try:
                    if fast_client:
                        resp = await fast_client.head(url)
                        content_length = int(resp.headers.get("content-length", 0))
                    else:
                        resp = await self.http.head(url)
                        content_length = int(getattr(resp, "headers", {}).get("content-length", 0))
                    if resp.status_code in (200, 301, 302, 403):
                        return {
                            "url": url,
                            "status": resp.status_code,
                            "content_length": content_length,
                        }
                except Exception:
                    pass
            return None

        tasks = [check_path(p) for p in all_paths]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
