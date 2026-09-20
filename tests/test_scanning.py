"""Single-pass scanner: hit offsets, validation, and entropy."""

from __future__ import annotations

import struct

from conftest import make_jpeg, make_png, make_zip, random_bytes, write
from stegoscan.evidence import Evidence
from stegoscan.scanning import build_index, shannon_entropy, validate


def test_signature_hits_land_on_exact_offsets(tmp_path):
    prefix = make_jpeg()
    payload = make_zip()
    evidence = Evidence.open(write(tmp_path, "c.jpg", prefix + payload))
    index = build_index(evidence)

    offsets = {(hit.name, hit.offset) for hit in index.hits}
    assert ("jpeg", 0) in offsets
    assert ("zip", len(prefix)) in offsets


def test_file_header_is_not_reported_as_embedded(tmp_path):
    evidence = Evidence.open(write(tmp_path, "c.png", make_png()))
    index = build_index(evidence)
    assert all(hit.is_header for hit in index.hits if hit.offset == 0)
    assert not [h for h in index.embedded_hits if h.offset == 0]


def test_zip_validation_parses_the_archive(tmp_path):
    ok, strong, note = validate("zip", make_zip(names=("a.txt", "b.txt")))
    assert ok and strong
    assert "2 entries" in note


def test_truncated_zip_is_valid_but_not_strong():
    ok, strong, _ = validate("zip", make_zip()[:40])
    assert ok is True
    assert strong is False


def test_mz_without_pe_header_is_rejected():
    # "MZ" matches constantly by chance; without a PE pointer it is noise.
    ok, _, note = validate("mz", b"MZ" + b"\x00" * 200)
    assert ok is False
    assert "e_lfanew" in note or "PE" in note


def test_mz_with_pe_header_is_accepted():
    data = bytearray(b"\x00" * 0x100)
    data[0:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    ok, strong, _ = validate("mz", bytes(data))
    assert ok and strong


def test_riff_requires_a_known_form_type():
    assert validate("riff", b"RIFF" + b"\x10\x00\x00\x00" + b"ABCD" + b"\x00" * 8)[0] is False
    assert validate("riff", b"RIFF" + b"\x10\x00\x00\x00" + b"WAVE" + b"\x00" * 8)[0] is True


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 4096) == 0.0
    assert shannon_entropy(bytes(range(256)) * 16) > 7.99
    assert shannon_entropy(random_bytes(8192)) > 7.5


def test_entropy_windows_cover_the_file(tmp_path):
    evidence = Evidence.open(write(tmp_path, "e.bin", b"\x00" * 20000))
    index = build_index(evidence, window_size=8192)
    assert len(index.windows) == 3
    assert index.sampled is False
    assert index.max_entropy == 0.0


def test_large_files_are_sampled_and_say_so(tmp_path):
    evidence = Evidence.open(write(tmp_path, "big.bin", b"\x00" * 200_000))
    index = build_index(evidence, window_size=1024, max_windows=10)
    assert index.sampled is True
    assert len(index.windows) <= 11


def test_empty_file_produces_an_empty_index(tmp_path):
    evidence = Evidence.open(write(tmp_path, "z.bin", b""))
    index = build_index(evidence)
    assert index.hits == []
    assert index.windows == []
