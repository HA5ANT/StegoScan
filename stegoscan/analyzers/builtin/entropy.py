"""Entropy analysis, read in the context of the carrier.

A global entropy score is close to meaningless on its own: 7.9 bits/byte is
alarming in a BMP and completely ordinary in a JPEG. So the same measurement is
interpreted differently per carrier, and only anomalous *regions* are raised as
findings.
"""

from __future__ import annotations

from typing import List, Tuple

from ...model import Confidence, Severity
from ...registry import register
from ..base import Analyzer, Context

# Minimum size of a hot region before it is worth a human's attention.
_MIN_REGION_BYTES = 4096
_MAX_REGIONS = 12


@register
class EntropyAnalyzer(Analyzer):
    name = "entropy"
    title = "Entropy profile"

    def run(self, evidence, ctx: Context):
        index = ctx.index
        if not index.windows:
            return self.skip("file is empty")

        threshold = ctx.options.entropy_threshold
        detail = "mean {:.2f}, max {:.2f} bits/byte over {} windows of {} bytes".format(
            index.mean_entropy, index.max_entropy, len(index.windows), index.window_size
        )
        if index.sampled:
            # Never let a sampled measurement pass as an exhaustive one.
            detail += " (sampled: file larger than the analysis budget)"

        findings = [
            self.finding(
                "Entropy {:.2f} mean / {:.2f} max".format(index.mean_entropy, index.max_entropy),
                Severity.INFO,
                Confidence.CONFIRMED,
                detail=detail,
            )
        ]

        if evidence.carrier.is_lossy_compressed:
            # Payload bytes are already near-random here, so a hot region is not
            # a signal. Say so rather than emitting findings that cannot mean anything.
            findings[0].detail += (
                ". Carrier is already compressed, so high entropy is expected and "
                "entropy alone cannot indicate concealment here."
            )
            return self.ok(findings, detail=detail)

        regions = self._regions_above(index, threshold)
        for start, end, peak in regions[:_MAX_REGIONS]:
            length = end - start
            if length < _MIN_REGION_BYTES:
                continue
            findings.append(
                self.finding(
                    "High-entropy region in low-entropy carrier",
                    Severity.MEDIUM,
                    Confidence.LIKELY,
                    detail=(
                        "{} bytes from {} to {} average above {:.1f} bits/byte (peak {:.2f}) "
                        "inside a {}, which normally holds structured data.".format(
                            length, hex(start), hex(end), threshold, peak, evidence.carrier
                        )
                    ),
                    offset=start,
                    length=length,
                    next_step="dd if={} bs=1 skip={} count={} of=region.bin status=none".format(
                        evidence.name, start, length
                    ),
                )
            )
        return self.ok(findings, detail=detail)

    def _regions_above(self, index, threshold: float) -> List[Tuple[int, int, float]]:
        """Merge adjacent hot windows into regions."""
        regions: List[Tuple[int, int, float]] = []
        start = None
        end = 0
        peak = 0.0
        for window in index.windows:
            if window.entropy >= threshold:
                if start is None:
                    start = window.offset
                    peak = window.entropy
                end = window.offset + window.length
                peak = max(peak, window.entropy)
            elif start is not None:
                regions.append((start, end, peak))
                start = None
                peak = 0.0
        if start is not None:
            regions.append((start, end, peak))
        return regions
