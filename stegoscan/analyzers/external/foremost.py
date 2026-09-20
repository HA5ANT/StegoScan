"""foremost: file carving, reported by what it actually recovered."""

from __future__ import annotations

import os

from ...model import Confidence, Severity
from ...registry import register
from .base import ExternalAnalyzer


@register
class ForemostAnalyzer(ExternalAnalyzer):
    name = "foremost"
    title = "foremost carving"
    binary = "foremost"

    def run(self, evidence, ctx):
        if not ctx.options.write_artifacts:
            return self.skip("carving needs an output directory (--no-artifacts is set)")

        # foremost insists on creating its own output directory.
        target = os.path.join(ctx.artifact_dir(), "foremost")
        if os.path.exists(target) and os.listdir(target):
            return self.skip("output directory already populated")

        run = self.execute(ctx, ["-i", evidence.path, "-o", target, "-q"])
        failed = self.failure(run, ctx)
        if failed:
            return failed

        carved = self._carved_files(target)
        if not carved:
            return self.ok(detail="nothing carved")

        findings = [
            self.finding(
                "foremost carved {} file(s)".format(len(carved)),
                Severity.MEDIUM,
                Confidence.LIKELY,
                detail="Recovered: {}".format(", ".join(sorted(os.path.basename(p) for p in carved[:10]))),
                next_step="Inspect {}".format(os.path.relpath(target, ctx.output_dir)),
                artifact=os.path.relpath(target, ctx.output_dir),
            )
        ]
        return self.ok(findings, detail="{} carved".format(len(carved)))

    def _carved_files(self, target: str):
        carved = []
        for root, _dirs, files in os.walk(target):
            for name in files:
                if name == "audit.txt":
                    continue
                carved.append(os.path.join(root, name))
        return carved
