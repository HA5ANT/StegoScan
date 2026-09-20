"""zsteg: LSB and bit-plane analysis for PNG and BMP carriers."""

from __future__ import annotations

import re

from ...model import Carrier, Confidence, Severity
from ...registry import register
from .base import ExternalAnalyzer

_FLAGGY = re.compile(r"(?:flag|ctf|htb|thm|pico)\{", re.IGNORECASE)

# zsteg prints one line per channel/bit combination as `<spec> .. <result>`.
# The separator is part of every line, so filtering has to look at the result.
_SEPARATOR = re.compile(r"\s\.\.\s")
_EMPTY_RESULT = re.compile(r'^(?:nothing|text:\s*"[\s\x00.]*"|\[NUL\].*|file:\s*empty)$', re.IGNORECASE)

MAX_LINES = 20


@register
class ZstegAnalyzer(ExternalAnalyzer):
    name = "zsteg"
    title = "zsteg bit-plane analysis"
    binary = "zsteg"
    applies_to = (Carrier.PNG, Carrier.BMP)

    def run(self, evidence, ctx):
        args = ["-a", evidence.path] if ctx.options.aggressive else [evidence.path]
        run = self.execute(ctx, args)
        failed = self.failure(run, ctx)
        if failed:
            return failed

        artifact = self.save_output(ctx, run, "zsteg.txt")
        findings = []
        interesting = 0
        for line in run.text().splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            parts = _SEPARATOR.split(stripped, 1)
            result_part = parts[1].strip() if len(parts) == 2 else stripped
            if not result_part or _EMPTY_RESULT.match(result_part):
                continue
            interesting += 1
            if len(findings) >= MAX_LINES:
                continue
            has_flag = bool(_FLAGGY.search(stripped))
            findings.append(
                self.finding(
                    "zsteg: {}".format(stripped[:90]),
                    Severity.HIGH if has_flag else Severity.MEDIUM,
                    Confidence.CONFIRMED if has_flag else Confidence.POSSIBLE,
                    detail=(
                        "Flag-formatted text recovered from a bit plane."
                        if has_flag
                        else "zsteg surfaced data in a bit plane; these are frequently "
                        "coincidental and need a human read."
                    ),
                    excerpt=stripped[:200],
                    next_step="zsteg -a {}".format(evidence.name),
                    artifact=artifact,
                )
            )

        return self.ok(
            findings, [artifact], detail="{} interesting lines".format(interesting)
        )
