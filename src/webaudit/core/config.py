"""Scan-Konfiguration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    """Konfiguration fuer einen Scan-Durchlauf."""

    target_url: str = ""
    output_dir: Path = field(default_factory=lambda: Path("./reports"))
    formats: list[str] = field(default_factory=lambda: ["html", "json", "terminal"])
    timeout: float = 10.0
    rate_limit: int = 10
    user_agent: str = "mp-web-audit/0.0.1"
    verify_ssl: bool = True
    skip_ssl: bool = False
    skip_ports: bool = False
    skip_discovery: bool = False
    port_range: str = "1-1000"
    wordlist: Path | None = None
    extensions: str = "php,html,js,txt,bak"
    verbose: bool = False
    categories: list[str] = field(
        default_factory=lambda: ["web", "security", "techstack", "discovery"]
    )
