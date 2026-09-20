"""stegseek: wordlist attack against steghide-embedded data.

Opt-in only. Brute force is slow and noisy, so it never runs unless the user
asked for it -- and when it does not run, the report says why rather than
leaving a silent gap.
"""

from __future__ import annotations

import os
import re

from ...model import Carrier, Confidence, Severity
from ...registry import register
from .base import ExternalAnalyzer

_PASSPHRASE = re.compile(r'Found passphrase:\s*"([^"]*)"')


@register
class StegseekAnalyzer(ExternalAnalyzer):
    name = "stegseek"
    title = "stegseek wordlist attack"
    binary = "stegseek"
    applies_to = (Carrier.JPEG, Carrier.BMP, Carrier.WAV)

    def run(self, evidence, ctx):
        if not ctx.options.aggressive:
            return self.skip("--aggressive not set")
        if not ctx.options.wordlist:
            return self.skip("no wordlist supplied (--wordlist)")
        if not os.path.isfile(ctx.options.wordlist):
            return self.skip("wordlist not found: {}".format(ctx.options.wordlist))

        output_file = os.path.join(ctx.artifact_dir("stegseek"), "payload.bin")
        run = self.execute(
            ctx, ["--crack", "-sf", evidence.path, "-wl", ctx.options.wordlist, "-xf", output_file, "-f"]
        )
        failed = self.failure(run, ctx)
        if failed:
            return failed

        text = run.text() + run.stderr.decode("utf-8", "replace")
        artifact = self.save_output(ctx, run, "stegseek.txt")
        match = _PASSPHRASE.search(text)
        if not match:
            return self.ok(
                artifacts=[artifact],
                detail="no passphrase in {} found".format(os.path.basename(ctx.options.wordlist)),
            )

        passphrase = match.group(1)
        payload = (
            os.path.relpath(output_file, ctx.output_dir) if os.path.exists(output_file) else None
        )
        finding = self.finding(
            "steghide passphrase recovered",
            Severity.HIGH,
            Confidence.CONFIRMED,
            detail='stegseek cracked the passphrase: "{}"'.format(passphrase),
            excerpt=passphrase,
            next_step="steghide extract -sf {} -p '{}'".format(evidence.name, passphrase),
            artifact=payload or artifact,
        )
        return self.ok([finding], [artifact, payload], detail="passphrase recovered")
