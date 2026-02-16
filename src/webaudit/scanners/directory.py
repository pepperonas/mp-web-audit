"""Directory-Discovery via feroxbuster."""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from webaudit.core.base_scanner import BaseScanner
from webaudit.core.models import Finding, ScanContext, ScanResult, Severity
from webaudit.scanners import register_scanner

DEFAULT_WORDLIST = Path(__file__).parent.parent.parent.parent / "wordlists" / "common.txt"


@register_scanner
class DirectoryScanner(BaseScanner):
    name = "directory"
    description = "Verzeichnis-/Datei-Enumeration via feroxbuster"
    category = "discovery"

    def is_available(self) -> bool:
        return shutil.which("feroxbuster") is not None

    async def scan(self, context: ScanContext) -> ScanResult:
        findings: list[Finding] = []
        wordlist = self.config.wordlist or DEFAULT_WORDLIST

        if not wordlist.exists():
            return ScanResult(
                scanner_name=self.name, kategorie="Discovery",
                success=False, error=f"Wordlist nicht gefunden: {wordlist}",
            )

        try:
            discovered, raw = await self._run_feroxbuster(
                context.target_url, wordlist
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name, kategorie="Discovery",
                success=False, error=f"feroxbuster Fehler: {e}",
            )

        # Ergebnisse kategorisieren
        interesting: list[dict] = []
        for entry in discovered:
            status = entry.get("status", 0)
            if status in (200, 301, 302, 403):
                interesting.append(entry)

        if interesting:
            summary_lines = []
            for entry in interesting[:50]:
                summary_lines.append(
                    f"  [{entry.get('status')}] {entry.get('url', '')} "
                    f"({entry.get('content_length', 0)} Bytes)"
                )

            findings.append(Finding(
                scanner=self.name, kategorie="Discovery",
                titel=f"{len(interesting)} Pfad(e) entdeckt",
                severity=Severity.INFO,
                beschreibung=f"feroxbuster hat {len(interesting)} Pfade gefunden.",
                beweis="\n".join(summary_lines[:20]),
                empfehlung="Ueberpruefen ob alle gefundenen Pfade beabsichtigt sind.",
            ))

            # 403-Eintraege separat hervorheben
            forbidden = [e for e in interesting if e.get("status") == 403]
            if forbidden:
                findings.append(Finding(
                    scanner=self.name, kategorie="Discovery",
                    titel=f"{len(forbidden)} Pfad(e) mit Zugriffsverweigerung (403)",
                    severity=Severity.NIEDRIG,
                    beschreibung="Diese Pfade existieren, der Zugriff wird aber verweigert.",
                    beweis="\n".join(e.get("url", "") for e in forbidden[:10]),
                    empfehlung="Sicherstellen dass die 403-Seiten keine Informationen preisgeben.",
                ))
        else:
            findings.append(Finding(
                scanner=self.name, kategorie="Discovery",
                titel="Keine zusaetzlichen Pfade entdeckt",
                severity=Severity.INFO,
                beschreibung="feroxbuster hat keine interessanten Pfade gefunden.",
                empfehlung="",
            ))

        raw["total_discovered"] = len(interesting)
        return ScanResult(
            scanner_name=self.name, kategorie="Discovery",
            findings=findings, raw_data=raw,
        )

    async def _run_feroxbuster(
        self, target_url: str, wordlist: Path
    ) -> tuple[list[dict], dict]:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        extensions = self.config.extensions
        rate = self.config.rate_limit

        # Argumente als Liste (kein Shell-Invocation) - sicher gegen Injection
        cmd = [
            "feroxbuster",
            "-u", target_url,
            "-w", str(wordlist),
            "-o", output_file,
            "--json",
            "-t", str(min(rate, 50)),
            "--rate-limit", str(rate),
            "-x", extensions,
            "--no-state",
            "--silent",
        ]
        if not self.config.verify_ssl:
            cmd.append("-k")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()

        discovered: list[dict] = []
        output_path = Path(output_file)
        if output_path.exists():
            for line in output_path.read_text().strip().split("\n"):
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "response":
                        discovered.append(entry)
                except json.JSONDecodeError:
                    continue
            output_path.unlink(missing_ok=True)

        raw: dict[str, Any] = {
            "wordlist": str(wordlist),
            "extensions": extensions,
        }

        return discovered, raw
