"""Data hiding past a container's logical end.

Appending a payload after a format's terminator is the most common way to hide
data in an image, because every viewer ignores it. Finding it requires knowing
where the container actually ends, so each format is parsed structurally rather
than searched for its terminator: v2 took the last ``FFD9`` in a JPEG, which an
attacker defeats by putting ``FFD9`` inside the payload.
"""

from __future__ import annotations

from typing import Optional

from ...model import Carrier, Confidence, Severity
from ...registry import register
from ...scanning import shannon_entropy
from ..base import Analyzer, Context, excerpt_bytes

# Trailing whitespace after a PDF's %%EOF is normal and not worth reporting.
_TRIVIAL_TRAILER = 4

_SUPPORTED = (Carrier.JPEG, Carrier.PNG, Carrier.GIF, Carrier.BMP, Carrier.WAV, Carrier.PDF, Carrier.ZIP)


def jpeg_logical_end(buf, size: int) -> Optional[int]:
    """Walk JPEG segments to the real EOI marker.

    Returns the offset one byte past EOI, or None if the structure desyncs.
    """
    if size < 4 or buf[0:2] != b"\xff\xd8":
        return None
    i = 2
    while i + 1 < size:
        if buf[i] != 0xFF:
            return None
        j = i
        while j < size and buf[j] == 0xFF:  # fill bytes are legal before a marker
            j += 1
        if j >= size:
            return None
        marker = buf[j]
        i = j + 1
        if marker == 0xD9:  # EOI
            return i
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:  # standalone, no length field
            continue
        if i + 2 > size:
            return None
        seg_len = int.from_bytes(buf[i : i + 2], "big")
        if seg_len < 2:
            return None
        i += seg_len
        if marker == 0xDA:  # start of scan: entropy-coded data until next real marker
            while True:
                k = buf.find(b"\xff", i)
                if k < 0 or k + 1 >= size:
                    return None
                nxt = buf[k + 1]
                # 0xFF00 is a stuffed byte; RSTn markers are part of the scan.
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                    i = k + 2
                    continue
                i = k
                break
    return None


def png_logical_end(buf, size: int) -> Optional[int]:
    if size < 12 or buf[0:8] != b"\x89PNG\r\n\x1a\n":
        return None
    i = 8
    while i + 8 <= size:
        length = int.from_bytes(buf[i : i + 4], "big")
        chunk_type = bytes(buf[i + 4 : i + 8])
        end = i + 8 + length + 4  # header + data + CRC
        if length < 0 or end > size:
            return None
        if chunk_type == b"IEND":
            return end
        i = end
    return None


def gif_logical_end(buf, size: int) -> Optional[int]:
    if size < 14 or bytes(buf[0:3]) != b"GIF":
        return None
    i = 6
    flags = buf[i + 4]
    i += 7
    if flags & 0x80:  # global colour table
        i += 3 * (2 ** ((flags & 0x07) + 1))
    while i < size:
        block = buf[i]
        if block == 0x3B:  # trailer
            return i + 1
        if block == 0x21:  # extension
            i += 2
            i = _skip_sub_blocks(buf, size, i)
            if i is None:
                return None
            continue
        if block == 0x2C:  # image descriptor
            if i + 10 > size:
                return None
            local_flags = buf[i + 9]
            i += 10
            if local_flags & 0x80:
                i += 3 * (2 ** ((local_flags & 0x07) + 1))
            i += 1  # LZW minimum code size
            i = _skip_sub_blocks(buf, size, i)
            if i is None:
                return None
            continue
        return None
    return None


def _skip_sub_blocks(buf, size: int, i: int) -> Optional[int]:
    while i < size:
        length = buf[i]
        i += 1
        if length == 0:
            return i
        i += length
    return None


def bmp_logical_end(buf, size: int) -> Optional[int]:
    if size < 6 or bytes(buf[0:2]) != b"BM":
        return None
    declared = int.from_bytes(buf[2:6], "little")
    if declared < 14 or declared > size:
        return None
    return declared


def riff_logical_end(buf, size: int) -> Optional[int]:
    if size < 8 or bytes(buf[0:4]) != b"RIFF":
        return None
    declared = int.from_bytes(buf[4:8], "little") + 8
    if declared < 12 or declared > size:
        return None
    return declared


def pdf_logical_end(buf, size: int) -> Optional[int]:
    marker = buf.rfind(b"%%EOF")
    if marker < 0:
        return None
    return marker + 5


def zip_logical_end(buf, size: int) -> Optional[int]:
    eocd = buf.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > size:
        return None
    comment_len = int.from_bytes(buf[eocd + 20 : eocd + 22], "little")
    end = eocd + 22 + comment_len
    if end > size:
        return None
    return end


_PARSERS = {
    Carrier.JPEG: jpeg_logical_end,
    Carrier.PNG: png_logical_end,
    Carrier.GIF: gif_logical_end,
    Carrier.BMP: bmp_logical_end,
    Carrier.WAV: riff_logical_end,
    Carrier.PDF: pdf_logical_end,
    Carrier.ZIP: zip_logical_end,
}


@register
class AppendedDataAnalyzer(Analyzer):
    name = "appended"
    title = "Appended data past container end"
    applies_to = _SUPPORTED

    def run(self, evidence, ctx: Context):
        parser = _PARSERS.get(evidence.carrier)
        if parser is None:
            return self.skip("no structural parser for {}".format(evidence.carrier))
        if evidence.size == 0:
            return self.skip("file is empty")

        with evidence.map() as buf:
            end = parser(buf, evidence.size)

        if end is None:
            # Honest failure: we could not establish where the container ends,
            # so we must not claim there is nothing after it.
            return self.skip("could not locate a valid {} terminator".format(evidence.carrier))

        trailing = evidence.size - end
        if trailing <= 0:
            return self.ok(detail="container ends at EOF ({} bytes)".format(end))

        payload = evidence.read(end, min(trailing, ctx.options.extract_size))
        if trailing <= _TRIVIAL_TRAILER and not payload.strip():
            return self.ok(detail="{} trailing whitespace bytes".format(trailing))

        artifact = ctx.write_artifact("appended_data.bin", payload)
        entropy = shannon_entropy(payload[:65536])
        identified = self._identify(ctx, end)

        if identified is not None:
            severity, confidence = Severity.HIGH, Confidence.CONFIRMED
            title = "Appended {} after container end".format(identified.description)
            detail = (
                "{} bytes follow the {} terminator at {}, and the trailing data validates as {} ({}).".format(
                    trailing, evidence.carrier, hex(end), identified.description, identified.note
                )
            )
        else:
            severity, confidence = Severity.HIGH, Confidence.LIKELY
            title = "Appended data after container end"
            detail = (
                "{} bytes follow the {} terminator at {}. Entropy {:.2f}/8.00 "
                "({}).".format(
                    trailing,
                    evidence.carrier,
                    hex(end),
                    entropy,
                    "compressed or encrypted" if entropy > 7.0 else "structured or textual",
                )
            )

        finding = self.finding(
            title,
            severity,
            confidence,
            detail=detail,
            offset=end,
            length=trailing,
            excerpt=excerpt_bytes(payload),
            next_step="dd if={} bs=1 skip={} of=appended.bin status=none".format(evidence.name, end),
            artifact=artifact,
        )
        return self.ok([finding], [artifact], detail="{} trailing bytes".format(trailing))

    def _identify(self, ctx: Context, end: int):
        """Cross-reference the scan index: does a validated container start here?"""
        for hit in ctx.index.hits:
            if hit.offset == end and hit.validated:
                return hit
        return None
