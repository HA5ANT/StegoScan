"""Read-only access to the file under examination.

Two guarantees live here, and analyzers depend on both:

* the evidence is never opened for writing and never mapped writable
* its digests are taken before analysis and re-checked afterwards, so a report
  can state that the tool did not alter what it examined
"""

from __future__ import annotations

import hashlib
import mmap
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

from .model import Carrier, Integrity

_HASH_CHUNK = 1 << 20

# Longest header we need in order to classify a carrier.
_HEADER_BYTES = 64

_TEXT_SAMPLE = 8192
_PRINTABLE = bytes(range(0x20, 0x7F)) + b"\t\r\n\f\v\b"


class EvidenceError(Exception):
    """Raised when the target cannot be examined at all."""


@dataclass
class Digests:
    sha256: str
    md5: str

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Digests):
            return NotImplemented
        return self.sha256 == other.sha256 and self.md5 == other.md5


def digest_file(path: str) -> Digests:
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
    return Digests(sha256=sha.hexdigest(), md5=md5.hexdigest())


def detect_carrier(header: bytes, sample: bytes = b"") -> Carrier:
    """Classify by magic bytes, falling back to a printability test.

    Extension is deliberately ignored: in forensics the extension is an
    assertion by whoever named the file, not evidence.
    """
    if header.startswith(b"\xff\xd8\xff"):
        return Carrier.JPEG
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return Carrier.PNG
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return Carrier.GIF
    if header.startswith(b"BM"):
        return Carrier.BMP
    if header.startswith(b"RIFF") and header[8:12] == b"WAVE":
        return Carrier.WAV
    if header.startswith(b"%PDF-"):
        return Carrier.PDF
    if header[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return Carrier.ZIP
    if sample and _looks_like_text(sample):
        return Carrier.TEXT
    return Carrier.OTHER


def _looks_like_text(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(sample.count(byte) for byte in _PRINTABLE)
    return printable / len(sample) > 0.95


class Evidence:
    """A file being examined. Opened read-only, never modified."""

    def __init__(self, path: str, size: int, digests: Digests, carrier: Carrier, header: bytes):
        self.path = path
        self.name = os.path.basename(path)
        self.size = size
        self.digests = digests
        self.carrier = carrier
        self.header = header

    @classmethod
    def open(cls, path: str) -> "Evidence":
        if not os.path.exists(path):
            raise EvidenceError("no such file: {}".format(path))
        if os.path.isdir(path):
            raise EvidenceError("target is a directory: {}".format(path))
        if not os.path.isfile(path):
            raise EvidenceError("not a regular file: {}".format(path))
        if not os.access(path, os.R_OK):
            raise EvidenceError("not readable: {}".format(path))

        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            header = handle.read(_HEADER_BYTES)
            handle.seek(0)
            sample = handle.read(_TEXT_SAMPLE)
        digests = digest_file(path)
        carrier = detect_carrier(header, sample)
        return cls(os.path.abspath(path), size, digests, carrier, header)

    @contextmanager
    def map(self) -> Iterator[bytes]:
        """Memory-map the evidence read-only.

        Yields an empty bytes object for zero-length files, which cannot be
        mapped, so callers never need to special-case them.
        """
        if self.size == 0:
            yield b""
            return
        handle = open(self.path, "rb")
        try:
            mapped = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                yield mapped
            finally:
                mapped.close()
        finally:
            handle.close()

    def read(self, offset: int, length: int) -> bytes:
        """Read a bounded slice without mapping the whole file."""
        if offset < 0 or length <= 0 or offset >= self.size:
            return b""
        with open(self.path, "rb") as handle:
            handle.seek(offset)
            return handle.read(min(length, self.size - offset))

    def verify_unchanged(self) -> bool:
        try:
            return digest_file(self.path) == self.digests
        except OSError:
            return False

    def integrity(self, verified: Optional[bool] = None) -> Integrity:
        if verified is None:
            verified = self.verify_unchanged()
        return Integrity(
            sha256=self.digests.sha256,
            md5=self.digests.md5,
            size=self.size,
            verified_unchanged=verified,
        )
