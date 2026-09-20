"""exiftool: metadata, read as evidence rather than dumped verbatim."""

from __future__ import annotations

import base64
import binascii
import json
import re

from ...model import Confidence, Severity
from ...registry import register
from .base import ExternalAnalyzer

_FLAGGY = re.compile(r"(?:flag|ctf|htb|thm|pico)\{[^}]{1,200}\}", re.IGNORECASE)
_B64 = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")

# Free-text fields an operator can write anything into, including a payload.
_COMMENT_FIELDS = (
    "Comment",
    "UserComment",
    "XPComment",
    "ImageDescription",
    "XPSubject",
    "XPKeywords",
    "Description",
    "Artist",
    "Copyright",
)

_GPS_FIELDS = ("GPSLatitude", "GPSLongitude", "GPSPosition")

MAX_COMMENT_EXCERPT = 200


@register
class ExiftoolAnalyzer(ExternalAnalyzer):
    name = "exiftool"
    title = "Metadata"
    binary = "exiftool"

    def run(self, evidence, ctx):
        run = self.execute(ctx, ["-json", "-a", "-u", evidence.path])
        failed = self.failure(run, ctx)
        if failed:
            return failed

        artifact = self.save_output(ctx, run, "exiftool.json")
        try:
            parsed = json.loads(run.text() or "[]")
        except json.JSONDecodeError:
            return self.ok(artifacts=[artifact], detail="exiftool produced unparseable JSON")
        if not parsed:
            return self.ok(artifacts=[artifact], detail="no metadata")

        tags = parsed[0]
        findings = []

        for field in _COMMENT_FIELDS:
            value = tags.get(field)
            if not isinstance(value, str) or not value.strip():
                continue
            findings.append(self._comment_finding(field, value, artifact))

        gps = [f for f in _GPS_FIELDS if tags.get(f)]
        if gps:
            findings.append(
                self.finding(
                    "GPS coordinates in metadata",
                    Severity.LOW,
                    Confidence.CONFIRMED,
                    detail="; ".join("{}: {}".format(f, tags[f]) for f in gps),
                    next_step="Location data may matter for attribution or for privacy review.",
                    artifact=artifact,
                )
            )

        return self.ok(
            findings, [artifact], detail="{} metadata tags".format(len(tags))
        )

    def _comment_finding(self, field: str, value: str, artifact):
        flag = _FLAGGY.search(value)
        if flag:
            return self.finding(
                "Flag token in {} metadata".format(field),
                Severity.HIGH,
                Confidence.CONFIRMED,
                detail="Flag-formatted text stored in a metadata field.",
                excerpt=flag.group(0)[:MAX_COMMENT_EXCERPT],
                artifact=artifact,
            )

        decoded = self._decode_base64(value)
        if decoded:
            return self.finding(
                "Base64 payload in {} metadata".format(field),
                Severity.MEDIUM,
                Confidence.LIKELY,
                detail="A metadata comment decodes to readable data rather than plain text.",
                excerpt=decoded[:MAX_COMMENT_EXCERPT],
                next_step="Decode the field and inspect: exiftool -{} FILE | base64 -d".format(field),
                artifact=artifact,
            )

        return self.finding(
            "{} metadata present".format(field),
            Severity.INFO,
            Confidence.CONFIRMED,
            excerpt=value[:MAX_COMMENT_EXCERPT],
            artifact=artifact,
        )

    def _decode_base64(self, value: str):
        candidate = value.strip()
        if not _B64.match(candidate):
            return None
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(decoded) < 8:
            return None
        printable = sum(1 for b in decoded if 0x20 <= b < 0x7F or b in (9, 10, 13))
        if printable / len(decoded) < 0.9:
            return None
        return decoded.decode("utf-8", "replace")
