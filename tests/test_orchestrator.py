"""Tests fuer den Orchestrator."""

import pytest

from webaudit.core.config import ScanConfig
from webaudit.orchestrator import _filter_scanners
from webaudit.scanners import discover_scanners, get_scanner_registry


@pytest.fixture(autouse=True)
def setup_scanners():
    discover_scanners()


class TestFilterScanners:
    def test_filter_by_category(self):
        registry = get_scanner_registry()
        config = ScanConfig(categories=["web"])
        filtered = _filter_scanners(registry, config)
        for name, cls in filtered.items():
            assert cls.category == "web"

    def test_skip_ssl(self):
        registry = get_scanner_registry()
        config = ScanConfig(categories=["security"], skip_ssl=True)
        filtered = _filter_scanners(registry, config)
        assert "ssl_scanner" not in filtered

    def test_skip_ports(self):
        registry = get_scanner_registry()
        config = ScanConfig(categories=["security"], skip_ports=True)
        filtered = _filter_scanners(registry, config)
        assert "ports" not in filtered

    def test_skip_discovery(self):
        registry = get_scanner_registry()
        config = ScanConfig(categories=["discovery"], skip_discovery=True)
        filtered = _filter_scanners(registry, config)
        assert "directory" not in filtered

    def test_all_categories(self):
        registry = get_scanner_registry()
        config = ScanConfig(categories=["web", "security", "techstack", "discovery"])
        filtered = _filter_scanners(registry, config)
        assert len(filtered) > 0
