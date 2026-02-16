"""Tests fuer die CLI."""

from typer.testing import CliRunner

from webaudit.cli.app import app

runner = CliRunner()


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "web-audit" in result.output.lower() or "webaudit" in result.output.lower()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_scan_help():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "Ziel-URL" in result.output or "url" in result.output.lower()


def test_web_help():
    result = runner.invoke(app, ["web", "--help"])
    assert result.exit_code == 0


def test_security_help():
    result = runner.invoke(app, ["security", "--help"])
    assert result.exit_code == 0


def test_techstack_help():
    result = runner.invoke(app, ["techstack", "--help"])
    assert result.exit_code == 0


def test_discover_help():
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0


def test_report_help():
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
