"""Base64 blobs that decode to something meaningful.

Every long alphanumeric run looks like base64; almost none of them are. Decoding
and then *validating* the result is what separates a finding from noise, so a
candidate is only reported if it decodes to readable text or to a recognised
container header.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Optional, Tuple

from ...model import Confidence, Severity
from ...registry import register
from ...scanning import SIGNATURES
from ..base import Analyzer, Context, excerpt_bytes

MIN_BLOB = 24
MAX_CANDIDATES = 2000
MAX_REPORTED = 15

_B64 = re.compile(rb"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_BLOB)
_FLAGGY = re.compile(rb"\b(?:flag|ctf|htb|thm|pico)\{[^}\r\n]{1,200}\}", re.IGNORECASE)
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _decode(blob: bytes) -> Optional[bytes]:
    usable = blob[: len(blob) - (len(blob) % 4)] if len(blob) % 4 else blob
    if len(usable) < MIN_BLOB:
        return None
    try:
        return base64.b64decode(usable, validate=True)
    except (binascii.Error, ValueError):
        return None


def _classify(decoded: bytes) -> Optional[Tuple[str, Severity, Confidence]]:
    """Decide whether a decoded blob is worth reporting, and how loudly."""
    if len(decoded) < 8:
        return None
    if _FLAGGY.search(decoded):
        return "flag token", Severity.HIGH, Confidence.CONFIRMED
    for sig in SIGNATURES:
        # Two-byte magics are too weak to survive this path without structure.
        if len(sig.magic) >= 4 and decoded.startswith(sig.magic):
            return sig.description, Severity.MEDIUM, Confidence.CONFIRMED
    printable = sum(1 for byte in decoded if byte in _PRINTABLE)
    if printable / len(decoded) > 0.90:
        return "readable text", Severity.LOW, Confidence.LIKELY
    return None


@register
class Base64Analyzer(Analyzer):
    name = "base64"
    title = "Base64-encoded payloads"

    def run(self, evidence, ctx: Context):
        if evidence.size == 0:
            return self.skip("file is empty")

        candidates = 0
        reported = []
        artifacts = []
        with evidence.map() as buf:
            for match in _B64.finditer(buf):
                candidates += 1
                if candidates > MAX_CANDIDATES:
                    break
                if len(reported) >= MAX_REPORTED:
                    break
                decoded = _decode(match.group())
                if decoded is None:
                    continue
                classified = _classify(decoded)
                if classified is None:
                    continue
                reported.append((match.start(), match.group(), decoded, classified))

        findings = []
        for offset, blob, decoded, (kind, severity, confidence) in reported:
            artifact = None
            if severity >= Severity.MEDIUM:
                artifact = ctx.write_artifact(
                    "{:08x}.bin".format(offset), decoded, subdir="base64_decoded"
                )
                if artifact:
                    artifacts.append(artifact)
            findings.append(
                self.finding(
                    "Base64 blob decodes to {}".format(kind),
                    severity,
                    confidence,
                    detail="{} encoded bytes at {} decode to {} bytes of {}.".format(
                        len(blob), hex(offset), len(decoded), kind
                    ),
                    offset=offset,
                    length=len(blob),
                    excerpt=excerpt_bytes(decoded, 160),
                    next_step="dd if={} bs=1 skip={} count={} status=none | base64 -d".format(
                        evidence.name, offset, len(blob)
                    ),
                    artifact=artifact,
                )
            )

        return self.ok(
            findings,
            artifacts,
            detail="{} candidate blobs, {} decoded to something meaningful".format(
                candidates, len(reported)
            ),
        )
