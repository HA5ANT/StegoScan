"""stegdetect: statistical JPEG steganalysis.

stegdetect is old and false-positive prone, so its output never rises above
LIKELY and the report says as much.
"""

from __future__ import annotations

from ...model import Carrier, Confidence, Severity
from ...registry import register
from .base import ExternalAnalyzer


@register
class StegdetectAnalyzer(ExternalAnalyzer):
    name = "stegdetect"
    title = "stegdetect statistical analysis"
    binary = "stegdetect"
    applies_to = (Carrier.JPEG,)

    def run(self, evidence, ctx):
        run = self.execute(ctx, ["-t", "jopi", evidence.path])
        failed = self.failure(run, ctx)
        if failed:
            return failed

        artifact = self.save_output(ctx, run, "stegdetect.txt")
        findings = []
        for line in run.text().splitlines():
            if ":" not in line:
                continue
            verdict = line.split(":", 1)[1].strip()
            if not verdict or verdict.lower().startswith("negative"):
                continue
            findings.append(
                self.finding(
                    "stegdetect: {}".format(verdict[:80]),
                    Severity.MEDIUM,
                    Confidence.POSSIBLE,
                    detail=(
                        "Statistical detector flagged this carrier. stegdetect is known "
                        "for false positives; corroborate before acting on it."
                    ),
                    excerpt=verdict[:200],
                    artifact=artifact,
                )
            )

        return self.ok(findings, [artifact], detail=run.text().strip()[:120] or "no output")
