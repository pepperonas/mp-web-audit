"""HTML-Report via Jinja2 (Single-File, portable)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from webaudit.core.models import AuditReport

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _score_color_class(score: float) -> str:
    if score >= 80:
        return "score-green"
    if score >= 60:
        return "score-yellow"
    if score >= 40:
        return "score-orange"
    return "score-red"


def _bar_color_class(score: float) -> str:
    if score >= 80:
        return "bar-green"
    if score >= 60:
        return "bar-yellow"
    if score >= 40:
        return "bar-orange"
    return "bar-red"


def generate_html_report(report: AuditReport, output_path: Path) -> Path:
    """Generiert einen portablen HTML-Report (CSS eingebettet)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    env.globals["score_color_class"] = _score_color_class
    env.globals["bar_color_class"] = _bar_color_class

    css = (TEMPLATES_DIR / "style.css").read_text()
    template = env.get_template("report.html.j2")

    html = template.render(report=report, css=css)
    output_path.write_text(html, encoding="utf-8")
    return output_path
