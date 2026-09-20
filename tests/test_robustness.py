"""Malformed input must never crash or hang the scanner.

This tool is pointed at files chosen by someone else -- CTF authors, suspects,
attackers. A parser that raises on a truncated header is a denial of service in
a bulk triage run, and a crash mid-acquisition loses the whole batch. So the
contract is: any byte sequence produces a report, never an exception.

Analyzer-level failures are allowed; they surface as ERROR results with a stated
reason. What is not allowed is an exception escaping scan_file.
"""

from __future__ import annotations

import os
import random

import pytest

from conftest import (
    make_bmp,
    make_gif,
    make_jpeg,
    make_pdf,
    make_png,
    make_wav,
    make_zip,
    write,
)
from stegoscan.analyzers.base import Options
from stegoscan.model import Status
from stegoscan.runner import scan_file
from stegoscan.scanning import build_index
from stegoscan.evidence import Evidence

CARRIERS = {
    "jpeg": make_jpeg(),
    "png": make_png(),
    "gif": make_gif(),
    "bmp": make_bmp(),
    "wav": make_wav(),
    "zip": make_zip(),
    "pdf": make_pdf(),
}

# Builtin-only: these tests run thousands of scans, and shelling out to binwalk
# and friends for each one would make the suite unusable. The analyzers being
# stressed here are the parsers, which are all builtin.
NO_ARTIFACTS = Options(write_artifacts=False, use_external=False)


def scan_bytes(tmp_path, name, payload):
    path = write(tmp_path, name, payload)
    return scan_file(path, options=NO_ARTIFACTS)


@pytest.mark.parametrize("carrier", sorted(CARRIERS))
def test_every_truncation_is_survivable(tmp_path, carrier):
    """Truncate at every single length. Headers half-read are the classic crash."""
    data = CARRIERS[carrier]
    for length in range(len(data)):
        report = scan_bytes(tmp_path, "t_{}".format(carrier), data[:length])
        assert report.verdict is not None


@pytest.mark.parametrize("carrier", sorted(CARRIERS))
def test_single_byte_corruption_is_survivable(tmp_path, carrier):
    data = CARRIERS[carrier]
    rng = random.Random(20260921)
    for _ in range(80):
        mutated = bytearray(data)
        mutated[rng.randrange(len(mutated))] = rng.randrange(256)
        report = scan_bytes(tmp_path, "c_{}".format(carrier), bytes(mutated))
        assert report.verdict is not None


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        b"\xff" * 4096,
        b"\x00" * 4096,
        b"\xff\xd8\xff",  # JPEG magic and nothing else
        b"\x89PNG\r\n\x1a\n",  # PNG magic and nothing else
        b"PK\x03\x04",  # ZIP magic and nothing else
        b"RIFF\xff\xff\xff\xffWAVE",  # RIFF claiming a 4GB body
        b"BM" + b"\xff" * 12,  # BMP claiming an absurd file size
        b"GIF89a" + b"\xff" * 20,  # GIF with a nonsense colour table
        b"%PDF-1.4",  # PDF header with no EOF
    ],
    ids=[
        "empty",
        "one-byte",
        "all-ff",
        "all-nul",
        "jpeg-magic-only",
        "png-magic-only",
        "zip-magic-only",
        "riff-lying-length",
        "bmp-lying-length",
        "gif-bad-table",
        "pdf-no-eof",
    ],
)
def test_degenerate_inputs_produce_a_report(tmp_path, payload):
    report = scan_bytes(tmp_path, "degenerate.bin", payload)
    assert report.verdict is not None
    assert report.integrity.verified_unchanged is True


def test_declared_length_larger_than_the_file_does_not_over_read(tmp_path):
    """A container claiming to be bigger than it is must not be trusted."""
    lying = b"BM" + (10 ** 9).to_bytes(4, "little") + b"\x00" * 60
    report = scan_bytes(tmp_path, "lying.bmp", lying)
    appended = [r for r in report.results if r.analyzer == "appended"]
    # Either it skips (no valid terminator) or it reports honestly -- never crashes.
    assert appended and appended[0].status in (Status.RAN, Status.SKIPPED)


def test_nested_carriers_do_not_recurse_without_bound(tmp_path):
    """A carrier stuffed with other carriers must stay linear-time."""
    payload = make_jpeg() + b"".join(make_png() + make_zip() for _ in range(40))
    report = scan_bytes(tmp_path, "nested.jpg", payload)
    assert report.verdict is not None


def test_signature_hit_flood_is_capped(tmp_path):
    """Thousands of fake magic bytes must not produce thousands of findings."""
    flood = make_jpeg() + b"PK\x03\x04" * 5000
    evidence = Evidence.open(write(tmp_path, "flood.jpg", flood))
    index = build_index(evidence)
    assert len(index.hits) < 1000
    assert "zip" in index.truncated_signatures

    report = scan_file(evidence.path, options=NO_ARTIFACTS)
    for result in report.results:
        assert len(result.findings) <= NO_ARTIFACTS.max_findings_per_analyzer


def test_no_analyzer_crashes_on_a_random_binary(tmp_path):
    """A random blob exercises every analyzer's unhappy path at once."""
    rng = random.Random(7)
    blob = bytes(rng.randrange(256) for _ in range(200_000))
    report = scan_bytes(tmp_path, "random.bin", blob)
    crashed = [r for r in report.results if r.status is Status.ERROR]
    assert not crashed, "analyzers errored: {}".format(
        [(r.analyzer, r.reason) for r in crashed]
    )


def test_unreadable_file_raises_a_clean_error(tmp_path):
    from stegoscan.evidence import EvidenceError

    path = write(tmp_path, "locked.bin", b"data")
    os.chmod(path, 0o000)
    try:
        if os.access(path, os.R_OK):  # running as root: the test cannot apply
            pytest.skip("running as root; permissions are not enforced")
        with pytest.raises(EvidenceError):
            scan_file(path, options=NO_ARTIFACTS)
    finally:
        os.chmod(path, 0o644)
