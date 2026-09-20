"""Container-end parsing and appended-data detection."""

from __future__ import annotations

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
from stegoscan.analyzers.base import Context, Options
from stegoscan.analyzers.builtin.appended import (
    AppendedDataAnalyzer,
    bmp_logical_end,
    gif_logical_end,
    jpeg_logical_end,
    pdf_logical_end,
    png_logical_end,
    riff_logical_end,
    zip_logical_end,
)
from stegoscan.evidence import Evidence
from stegoscan.model import Confidence, Severity, Status
from stegoscan.scanning import build_index


@pytest.mark.parametrize(
    "builder, parser",
    [
        (make_jpeg, jpeg_logical_end),
        (make_png, png_logical_end),
        (make_gif, gif_logical_end),
        (make_bmp, bmp_logical_end),
        (make_wav, riff_logical_end),
        (make_pdf, pdf_logical_end),
        (make_zip, zip_logical_end),
    ],
)
def test_logical_end_is_eof_for_clean_carriers(builder, parser):
    data = builder()
    assert parser(data, len(data)) == len(data)


@pytest.mark.parametrize(
    "builder, parser",
    [
        (make_jpeg, jpeg_logical_end),
        (make_png, png_logical_end),
        (make_gif, gif_logical_end),
        (make_bmp, bmp_logical_end),
        (make_wav, riff_logical_end),
    ],
)
def test_logical_end_excludes_appended_bytes(builder, parser):
    clean = builder()
    payload = b"APPENDED" * 16
    assert parser(clean + payload, len(clean) + len(payload)) == len(clean)


def test_jpeg_parser_is_not_fooled_by_eoi_inside_the_payload():
    """The reason JPEG is parsed structurally instead of reverse-searched.

    v2 took the last FFD9 in the file, so burying an FFD9 inside the appended
    payload hid everything before it. Walking the segments finds the real EOI.
    """
    clean = make_jpeg()
    hostile = b"\xff\xd9" + b"hidden archive contents" * 4 + b"\xff\xd9"
    combined = clean + hostile
    assert jpeg_logical_end(combined, len(combined)) == len(clean)
    assert combined.rfind(b"\xff\xd9") > len(clean)  # a naive search would miss the payload


def test_jpeg_parser_handles_stuffed_bytes_and_restart_markers():
    scan = b"\x00" * 8 + b"\xff\x00" + b"\x11" * 8 + b"\xff\xd0" + b"\x22" * 8
    data = make_jpeg(scan_data=scan)
    assert jpeg_logical_end(data, len(data)) == len(data)


def test_truncated_container_yields_no_end():
    clean = make_png()
    assert png_logical_end(clean[:20], 20) is None


def _analyze(path):
    evidence = Evidence.open(path)
    ctx = Context(output_dir="", index=build_index(evidence), options=Options(write_artifacts=False))
    return evidence, AppendedDataAnalyzer().run(evidence, ctx)


def test_clean_carrier_reports_no_appended_findings(clean_jpeg):
    _, result = _analyze(clean_jpeg)
    assert result.status is Status.RAN
    assert result.findings == []


def test_appended_zip_is_confirmed_not_merely_suspected(jpeg_with_appended_zip):
    _, result = _analyze(jpeg_with_appended_zip)
    assert result.status is Status.RAN
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity is Severity.HIGH
    # The trailing bytes parsed as a real archive, so this is a fact, not a hunch.
    assert finding.confidence is Confidence.CONFIRMED
    assert "ZIP" in finding.title
    assert finding.offset == len(make_jpeg())


def test_unidentified_trailing_data_is_reported_as_likely(png_with_trailing_data):
    _, result = _analyze(png_with_trailing_data)
    finding = result.findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.LIKELY
    assert finding.next_step.startswith("dd ")


def test_unparseable_container_skips_rather_than_claiming_clean(tmp_path):
    """The honesty rule: no terminator found means unknown, not clean."""
    path = write(tmp_path, "broken.png", b"\x89PNG\r\n\x1a\n" + b"\xff" * 64)
    _, result = _analyze(path)
    assert result.status is Status.SKIPPED
    assert "terminator" in result.reason
