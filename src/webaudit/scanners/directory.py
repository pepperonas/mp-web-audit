"""Directory-Discovery via HTTP-Requests (Wordlist-basiert)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

DEFAULT_WORDLIST = Path(__file__).parent.parent.parent.parent / "wordlists" / "common.txt"


@register_scanner
class DirectoryScanner(BaseScanner):
    name = "directory"
    description = "Verzeichnis-/Datei-Enumeration via Wordlist"
    category = "discovery"

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
        discovered: list[dict[str, Any]] = []
        semaphore = asyncio.Semaphore(self.config.rate_limit)

        async def check_path(path: str) -> dict[str, Any] | None:
            url = f"{base_url}/{path.lstrip('/')}"
            async with semaphore:
                try:
                    resp = await self.http.get(url)
                    if resp.status_code in (200, 301, 302, 403):
                        content_length = len(resp.text) if hasattr(resp, "text") else 0
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
        discovered = [r for r in results if r is not None]

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
