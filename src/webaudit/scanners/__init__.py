"""Scanner-Registry mit @register_scanner Decorator."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webaudit.core.base_scanner import BaseScanner

_SCANNER_REGISTRY: dict[str, type["BaseScanner"]] = {}


def register_scanner(cls: type["BaseScanner"]) -> type["BaseScanner"]:
    """Decorator zum Registrieren eines Scanners."""
    _SCANNER_REGISTRY[cls.name] = cls
    return cls


def get_scanner_registry() -> dict[str, type["BaseScanner"]]:
    """Gibt die Registry aller registrierten Scanner zurueck."""
    return dict(_SCANNER_REGISTRY)


def get_scanners_by_category(category: str) -> dict[str, type["BaseScanner"]]:
    """Gibt alle Scanner einer Kategorie zurueck."""
    return {
        name: cls for name, cls in _SCANNER_REGISTRY.items() if cls.category == category
    }


def discover_scanners() -> None:
    """Importiert alle Scanner-Module damit sie sich registrieren."""
    from webaudit.scanners import (  # noqa: F401
        cookies,
        directory,
        headers,
        misconfig,
        mobile,
        performance,
        ports,
        seo,
        ssl_scanner,
        techstack,
        usability,
    )
