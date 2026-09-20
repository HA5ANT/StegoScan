"""Report renderers. All of them are views over ``ScanReport``."""

from . import json_report, markdown  # noqa: F401

__all__ = ["json_report", "markdown"]
