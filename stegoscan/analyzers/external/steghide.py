"""steghide: detect and, when a password is known, extract embedded data."""

from __future__ import annotations

import os
import re

from ...model import Carrier, Confidence, Severity
from ...registry import register
from .base import ExternalAnalyzer

_EMBEDDED = re.compile(r'embedded file "([^"]+)"')
_CAPACITY = re.compile(r"capacity:\s*(.+)")


@register
class SteghideAnalyzer(ExternalAnalyzer):
    name = "steghide"
    title = "steghide embedded data"
    binary = "steghide"
    # steghide only supports these carriers; running it elsewhere is noise.
    applies_to = (Carrier.JPEG, Carrier.BMP, Carrier.WAV)

    def run(self, evidence, ctx):
        password = ctx.options.password or ""
        run = self.execute(ctx, ["info", evidence.path, "-p", password])
        failed = self.failure(run, ctx)
        if failed:
            return failed

        output = run.text() + run.stderr.decode("utf-8", "replace")
        artifact = self.save_output(ctx, run, "steghide_info.txt")
        capacity = _CAPACITY.search(output)
        embedded = _EMBEDDED.search(output)

        if not embedded:
            detail = "no data recoverable with {}".format(
                "the supplied password" if ctx.options.password else "an empty password"
            )
            if capacity:
                detail += "; capacity {}".format(capacity.group(1).strip())
            return self.ok(artifacts=[artifact], detail=detail)

        name = embedded.group(1)
        findings = [
            self.finding(
                "steghide payload: {}".format(name),
                Severity.HIGH,
                Confidence.CONFIRMED,
                detail="steghide reports an embedded file recoverable with the supplied password.",
                excerpt=name,
                next_step="steghide extract -sf {} -p '<password>'".format(evidence.name),
                artifact=artifact,
            )
        ]

        extracted = self._extract(evidence, ctx, password, name)
        if extracted:
            findings[0].artifact = extracted

        return self.ok(findings, [artifact, extracted], detail="payload {}".format(name))

    def _extract(self, evidence, ctx, password: str, name: str):
        if not ctx.options.write_artifacts:
            return None
        target_dir = ctx.artifact_dir("steghide")
        target = os.path.join(target_dir, os.path.basename(name) or "payload.bin")
        run = self.execute(
            ctx, ["extract", "-sf", evidence.path, "-p", password, "-xf", target, "-f"]
        )
        if run.ok and os.path.exists(target):
            return os.path.relpath(target, ctx.output_dir)
        return None
