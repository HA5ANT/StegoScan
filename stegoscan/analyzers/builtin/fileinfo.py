"""Identify the carrier and flag content that contradicts its name."""

from __future__ import annotations

import os

from ...model import Carrier, Confidence, Severity
from ...registry import register
from ..base import Analyzer, Context

# Extensions that legitimately map to each detected carrier.
_EXPECTED = {
    Carrier.JPEG: {".jpg", ".jpeg", ".jpe", ".jfif"},
    Carrier.PNG: {".png"},
    Carrier.GIF: {".gif"},
    Carrier.BMP: {".bmp", ".dib"},
    Carrier.WAV: {".wav", ".wave"},
    Carrier.PDF: {".pdf"},
    Carrier.ZIP: {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub"},
}


@register
class FileInfoAnalyzer(Analyzer):
    name = "fileinfo"
    title = "File identification"

    def run(self, evidence, ctx: Context):
        findings = [
            self.finding(
                "Identified as {}".format(evidence.carrier),
                Severity.INFO,
                Confidence.CONFIRMED,
                detail="{} bytes, sha256 {}".format(evidence.size, evidence.digests.sha256),
                length=evidence.size,
            )
        ]

        if evidence.size == 0:
            findings.append(
                self.finding(
                    "File is empty",
                    Severity.LOW,
                    Confidence.CONFIRMED,
                    detail="Nothing to analyse; every content analyzer will report no findings.",
                )
            )
            return self.ok(findings)

        mismatch = self._extension_mismatch(evidence)
        if mismatch:
            findings.append(mismatch)
        return self.ok(findings, detail="carrier={}".format(evidence.carrier))

    def _extension_mismatch(self, evidence):
        extension = os.path.splitext(evidence.name)[1].lower()
        if not extension:
            return None
        expected = _EXPECTED.get(evidence.carrier)
        if expected is None:
            return None
        if extension in expected:
            return None
        # A name that disagrees with the bytes is a deliberate act often enough
        # to be worth surfacing, but the extension is an assertion, not evidence.
        return self.finding(
            "Extension does not match content",
            Severity.MEDIUM,
            Confidence.LIKELY,
            detail="Named {} but the magic bytes say {}.".format(extension, evidence.carrier),
            next_step="Treat the detected format as authoritative; ask why the file was named this way.",
        )
