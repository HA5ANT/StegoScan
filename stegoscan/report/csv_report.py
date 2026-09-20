"""CSV summary for bulk triage.

Written for whatever the examiner already uses -- a spreadsheet, a case
management import, or `sort -t, -k3`.
"""

from __future__ import annotations

import csv
import io
from typing import Sequence

COLUMNS = (
    "file",
    "carrier",
    "verdict",
    "score",
    "coverage_ran",
    "coverage_applicable",
    "top_finding",
    "sha256",
    "size",
    "report_dir",
    "error",
)


def render(results: Sequence) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS)
    for result in results:
        writer.writerow(
            [
                result.path,
                result.carrier,
                result.verdict,
                result.score,
                result.coverage_ran,
                result.coverage_applicable,
                result.top_finding,
                result.sha256,
                result.size,
                result.output_dir or "",
                result.error,
            ]
        )
    return buffer.getvalue()
