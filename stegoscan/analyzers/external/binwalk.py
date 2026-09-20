"""binwalk: embedded-file scan, cross-referenced against our own findings.

binwalk's value here is what it finds that the builtin scanner does not, so
results are split: offsets we already validated are reported as corroboration,
and offsets only binwalk saw are raised for review.
"""

from __future__ import annotations

import re

from ...model import Confidence, Severity
from ...registry import register
from .base import ExternalAnalyzer

_ROW = re.compile(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+?)\s*$")

# Descriptions that appear for almost every image and carry no signal.
_UNINTERESTING = ("jfif standard", "exif standard", "tiff image data", "xml document")


@register
class BinwalkAnalyzer(ExternalAnalyzer):
    name = "binwalk"
    title = "binwalk signature scan"
    binary = "binwalk"

    def run(self, evidence, ctx):
        run = self.execute(ctx, [evidence.path])
        failed = self.failure(run, ctx)
        if failed:
            return failed

        artifact = self.save_output(ctx, run, "binwalk.txt")
        known = {hit.offset for hit in ctx.index.hits if hit.validated}

        findings = []
        rows = 0
        for line in run.text().splitlines():
            match = _ROW.match(line)
            if not match:
                continue
            offset = int(match.group(1))
            description = match.group(3)
            rows += 1
            if offset == 0:
                continue  # the carrier's own header
            if any(token in description.lower() for token in _UNINTERESTING):
                continue

            corroborated = offset in known
            findings.append(
                self.finding(
                    "binwalk: {}".format(description[:90]),
                    Severity.INFO if corroborated else Severity.MEDIUM,
                    Confidence.LIKELY,
                    detail=(
                        "Corroborates a validated finding at this offset."
                        if corroborated
                        else "binwalk reports embedded data that the builtin scanner did not "
                        "validate; treat as a lead and verify before relying on it."
                    ),
                    offset=offset,
                    next_step="binwalk --extract --dd='.*' {}".format(evidence.name),
                    artifact=artifact,
                )
            )

        return self.ok(
            findings,
            [artifact],
            detail="{} rows parsed, {} reported".format(rows, len(findings)),
        )
