"""Canonical JSON rendering.

This is the authoritative serialisation; Markdown and CSV are derived views.
Keys are emitted in a stable order so two scans of the same evidence diff cleanly.
"""

from __future__ import annotations

import json

from ..model import ScanReport


def render(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False)


def render_compact(report: ScanReport) -> str:
    """One line per report, for streaming into a pipeline."""
    return json.dumps(report.to_dict(), separators=(",", ":"), ensure_ascii=False)
