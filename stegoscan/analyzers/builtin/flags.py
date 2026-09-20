"""CTF flag detection.

A literal flag token is not a suspicion, it is the answer, so these findings are
CONFIRMED and outrank everything else in the report.
"""

from __future__ import annotations

import re

from ...model import Confidence, Severity
from ...registry import register
from ..base import Analyzer, Context, excerpt_bytes

MAX_FLAGS = 25

# Named prefixes first (high precision), then the generic wrapper shape.
_NAMED = re.compile(
    rb"\b(?:flag|ctf|htb|thm|picoCTF|pico|key|secret|pass|passwd|password)\{[^}\r\n]{1,200}\}",
    re.IGNORECASE,
)
_GENERIC = re.compile(rb"\b[A-Za-z][A-Za-z0-9_]{1,20}\{[ -~]{4,120}\}")


@register
class FlagAnalyzer(Analyzer):
    name = "flags"
    title = "CTF flag patterns"

    def run(self, evidence, ctx: Context):
        if evidence.size == 0:
            return self.skip("file is empty")

        named = []
        generic = []
        with evidence.map() as buf:
            named = [(m.start(), m.group()) for m in _NAMED.finditer(buf)]
            if not named:
                generic = [(m.start(), m.group()) for m in _GENERIC.finditer(buf)]

        findings = []
        seen = set()
        for offset, matched in named[:MAX_FLAGS]:
            token = matched.decode("utf-8", "replace")
            if token in seen:
                continue
            seen.add(token)
            findings.append(
                self.finding(
                    "Flag token found",
                    Severity.HIGH,
                    Confidence.CONFIRMED,
                    detail="Literal flag-formatted token in the file data.",
                    offset=offset,
                    length=len(matched),
                    excerpt=excerpt_bytes(matched, 200),
                    next_step="This is likely the answer; verify the prefix matches the challenge.",
                )
            )

        artifacts = []
        if findings:
            artifacts.append(
                ctx.write_artifact("flags.txt", "\n".join(f.excerpt for f in findings))
            )
        elif generic:
            # Shown at low severity because `word{...}` matches ordinary code
            # and CSS constantly; it is a lead, not a result.
            for offset, matched in generic[:5]:
                findings.append(
                    self.finding(
                        "Flag-shaped token",
                        Severity.LOW,
                        Confidence.POSSIBLE,
                        detail="Matches the generic name{value} shape; often a false positive.",
                        offset=offset,
                        length=len(matched),
                        excerpt=excerpt_bytes(matched, 200),
                    )
                )

        return self.ok(
            findings,
            artifacts,
            detail="{} named, {} generic candidates".format(len(named), len(generic)),
        )
