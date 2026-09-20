"""Embedded container detection: carve every magic-byte hit, then validate it.

Carve-and-validate is inherited from v2 and is the reason this analyzer is
worth trusting: a magic match alone is a coincidence generator, so every
candidate is parsed before it is reported, and rejected candidates are kept in
a log rather than silently dropped.
"""

from __future__ import annotations

from ...model import Carrier, Confidence, Severity
from ...registry import register
from ..base import Analyzer, Context

# Signature names that are unremarkable inside a given carrier -- EXIF
# thumbnails, for instance, are JPEGs inside JPEGs and mean nothing on their own.
_NATIVE_TO_CARRIER = {
    Carrier.JPEG: {"jpeg", "id3", "riff"},
    Carrier.PNG: {"png"},
    Carrier.GIF: {"gif87a", "gif89a"},
    Carrier.WAV: {"riff"},
    Carrier.ZIP: {"zip"},
    Carrier.PDF: {"pdf"},
}


@register
class SignatureAnalyzer(Analyzer):
    name = "signatures"
    title = "Embedded container signatures"

    def run(self, evidence, ctx: Context):
        index = ctx.index
        if not index.hits:
            return self.ok(detail="no magic-byte matches")

        findings = []
        artifacts = []
        native = _NATIVE_TO_CARRIER.get(evidence.carrier, set())

        for hit in index.embedded_hits[: ctx.options.max_findings_per_analyzer]:
            carved = evidence.read(hit.offset, ctx.options.extract_size)
            artifact = ctx.write_artifact(
                "{:08x}_{}.{}".format(hit.offset, hit.name, hit.extension),
                carved,
                subdir="carved",
            )
            if artifact:
                artifacts.append(artifact)

            is_native = hit.name in native
            if is_native:
                severity = Severity.LOW
                detail = "{} at offset {}. Common inside a {} (thumbnail or embedded stream); {}.".format(
                    hit.description, hex(hit.offset), evidence.carrier, hit.note
                )
            else:
                severity = Severity.HIGH if hit.strong else Severity.MEDIUM
                detail = "{} found inside a {} at offset {}; {}.".format(
                    hit.description, evidence.carrier, hex(hit.offset), hit.note
                )

            findings.append(
                self.finding(
                    "Embedded {}".format(hit.description),
                    severity,
                    Confidence.CONFIRMED if hit.strong else Confidence.LIKELY,
                    detail=detail,
                    offset=hit.offset,
                    length=min(ctx.options.extract_size, max(0, evidence.size - hit.offset)),
                    next_step="dd if={} bs=1 skip={} of=carved.{} status=none".format(
                        evidence.name, hit.offset, hit.extension
                    ),
                    artifact=artifact,
                )
            )

        rejected = index.rejected_hits
        if rejected:
            log = "\n".join(
                "{}\t{}\t{}".format(hex(h.offset), h.name, h.note) for h in rejected
            )
            rejected_artifact = ctx.write_artifact("rejected_signatures.tsv", log)
            if rejected_artifact:
                artifacts.append(rejected_artifact)

        detail = "{} validated, {} rejected".format(len(index.embedded_hits), len(rejected))
        if index.truncated_signatures:
            detail += "; hit cap reached for: {}".format(", ".join(index.truncated_signatures))
        return self.ok(findings, artifacts, detail=detail)
