"""Evidence handling: identification, digests, and the read-only guarantee."""

from __future__ import annotations

import pytest

from conftest import make_bmp, make_gif, make_jpeg, make_pdf, make_png, make_wav, make_zip, write
from stegoscan.evidence import Evidence, EvidenceError, detect_carrier, digest_file
from stegoscan.model import Carrier


@pytest.mark.parametrize(
    "builder, expected",
    [
        (make_jpeg, Carrier.JPEG),
        (make_png, Carrier.PNG),
        (make_gif, Carrier.GIF),
        (make_bmp, Carrier.BMP),
        (make_wav, Carrier.WAV),
        (make_pdf, Carrier.PDF),
        (make_zip, Carrier.ZIP),
    ],
)
def test_carrier_detected_from_magic_bytes(tmp_path, builder, expected):
    evidence = Evidence.open(write(tmp_path, "sample.bin", builder()))
    assert evidence.carrier is expected


def test_extension_is_ignored_when_classifying(tmp_path):
    # A .jpg that is really a ZIP must be reported as a ZIP: the name is an
    # assertion by whoever created the file, not evidence.
    evidence = Evidence.open(write(tmp_path, "innocent.jpg", make_zip()))
    assert evidence.carrier is Carrier.ZIP


def test_text_and_binary_fallbacks():
    assert detect_carrier(b"hello world", b"hello world\n" * 10) is Carrier.TEXT
    assert detect_carrier(b"\x00\x01\x02\x03", b"\x00\x01\x02\x03" * 10) is Carrier.OTHER


def test_digests_match_hashlib(tmp_path):
    path = write(tmp_path, "d.bin", b"stegoscan")
    import hashlib

    digests = digest_file(path)
    assert digests.sha256 == hashlib.sha256(b"stegoscan").hexdigest()
    assert digests.md5 == hashlib.md5(b"stegoscan").hexdigest()


def test_verify_unchanged_detects_modification(tmp_path):
    path = write(tmp_path, "m.bin", b"original")
    evidence = Evidence.open(path)
    assert evidence.verify_unchanged() is True
    with open(path, "wb") as handle:
        handle.write(b"tampered")
    assert evidence.verify_unchanged() is False


def test_empty_file_maps_to_empty_bytes(empty_file):
    evidence = Evidence.open(empty_file)
    assert evidence.size == 0
    with evidence.map() as buf:
        assert buf == b""


def test_read_is_bounds_checked(tmp_path):
    evidence = Evidence.open(write(tmp_path, "r.bin", b"0123456789"))
    assert evidence.read(2, 4) == b"2345"
    assert evidence.read(8, 100) == b"89"
    assert evidence.read(100, 10) == b""
    assert evidence.read(-1, 10) == b""


def test_missing_and_directory_targets_raise(tmp_path):
    with pytest.raises(EvidenceError):
        Evidence.open(str(tmp_path / "nope.bin"))
    with pytest.raises(EvidenceError):
        Evidence.open(str(tmp_path))
