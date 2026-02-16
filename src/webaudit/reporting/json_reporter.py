"""JSON-Report-Export."""

from __future__ import annotations

import json
from pathlib import Path

from webaudit.core.models import AuditReport


def generate_json_report(report: AuditReport, output_path: Path) -> Path:
    """Exportiert den Report als JSON-Datei."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = report.model_dump(mode="json")
    output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    return output_path


def load_report_from_json(json_path: Path) -> AuditReport:
    """Laedt einen Report aus einer JSON-Datei."""
    data = json.loads(json_path.read_text())
    return AuditReport.model_validate(data)
