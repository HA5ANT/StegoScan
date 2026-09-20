"""Carrier builders.

Fixtures are synthesized rather than committed as binary blobs: the test suite
stays readable, every byte in a fixture is there for a stated reason, and CI
needs neither a sample corpus nor any external forensics tool.
"""

from __future__ import annotations

import io
import os
import random
import struct
import zipfile
import zlib

import pytest


def make_jpeg(scan_data: bytes = b"\x00" * 64, trailing: bytes = b"") -> bytes:
    """A structurally valid minimal JPEG: SOI, APP0, SOS, scan data, EOI."""
    out = bytearray(b"\xff\xd8")  # SOI
    app0 = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    out += b"\xff\xe0" + struct.pack(">H", len(app0) + 2) + app0
    sos = b"\x01\x01\x00\x00\x3f\x00"
    out += b"\xff\xda" + struct.pack(">H", len(sos) + 2) + sos
    out += scan_data
    out += b"\xff\xd9"  # EOI
    out += trailing
    return bytes(out)


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def make_png(trailing: bytes = b"") -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\xff\xff")
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
        + trailing
    )


def make_gif(trailing: bytes = b"") -> bytes:
    return (
        b"GIF89a"
        + struct.pack("<HH", 1, 1)
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\xff\xff\xff"  # 2-entry global colour table
        + b"\x2c"
        + struct.pack("<HHHH", 0, 0, 1, 1)
        + b"\x00"
        + b"\x02"  # LZW minimum code size
        + b"\x02\x4c\x01"  # one sub-block
        + b"\x00"  # block terminator
        + b"\x3b"  # trailer
        + trailing
    )


def make_bmp(pixels: bytes = b"\x00\x00\xff\x00", trailing: bytes = b"") -> bytes:
    size = 14 + 40 + len(pixels)
    header = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    return header + info + pixels + trailing


def make_wav(samples: bytes = b"\x00\x00" * 32, trailing: bytes = b"") -> bytes:
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 16000, 2, 16)
    body = (
        b"WAVE"
        + b"fmt " + struct.pack("<I", len(fmt)) + fmt
        + b"data" + struct.pack("<I", len(samples)) + samples
    )
    return b"RIFF" + struct.pack("<I", len(body)) + body + trailing


def make_zip(names=("secret.txt",), content: bytes = b"hidden payload") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.writestr(name, content)
    return buffer.getvalue()


def make_pdf(trailing: bytes = b"") -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R >>\n"
        b"%%EOF" + trailing
    )


def random_bytes(length: int, seed: int = 1337) -> bytes:
    """Deterministic high-entropy data, so entropy assertions are stable."""
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(length))


def write(tmp_path, name: str, data: bytes) -> str:
    path = os.path.join(str(tmp_path), name)
    with open(path, "wb") as handle:
        handle.write(data)
    return path


@pytest.fixture
def clean_jpeg(tmp_path):
    return write(tmp_path, "clean.jpg", make_jpeg())


@pytest.fixture
def jpeg_with_appended_zip(tmp_path):
    """The classic: a valid image with an archive stapled to the end."""
    return write(tmp_path, "carrier.jpg", make_jpeg() + make_zip())


@pytest.fixture
def png_with_trailing_data(tmp_path):
    return write(tmp_path, "carrier.png", make_png(trailing=b"APPENDED-SECRET-PAYLOAD" * 8))


@pytest.fixture
def bmp_with_high_entropy(tmp_path):
    return write(tmp_path, "carrier.bmp", make_bmp(pixels=random_bytes(32768)))


@pytest.fixture
def flag_file(tmp_path):
    return write(tmp_path, "notes.txt", b"nothing here\nFLAG{synthetic_test_flag}\nmove along\n")


@pytest.fixture
def empty_file(tmp_path):
    return write(tmp_path, "empty.bin", b"")
