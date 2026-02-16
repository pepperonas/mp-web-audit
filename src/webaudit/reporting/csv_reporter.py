"""CSV-Report-Export: Eine Zeile pro Finding."""

from __future__ import annotations

import csv
from pathlib import Path

from webaudit.core.models import AuditReport


def generate_csv_report(report: AuditReport, output_path: Path) -> Path:
    """Exportiert alle Findings als CSV-Datei."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "severity",
                "scanner",
                "kategorie",
                "titel",
                "beschreibung",
                "beweis",
                "empfehlung",
            ]
        )
        for result in report.results:
            for finding in result.findings:
                writer.writerow(
                    [
                        finding.severity.value,
                        finding.scanner,
                        finding.kategorie,
                        finding.titel,
                        finding.beschreibung,
                        finding.beweis,
                        finding.empfehlung,
                    ]
                )

    return output_path
