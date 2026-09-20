"""Builtin analyzer behaviour."""

from __future__ import annotations

import base64

from conftest import make_bmp, make_jpeg, make_png, make_zip, random_bytes, write
from stegoscan.analyzers.base import Context, Options
from stegoscan.analyzers.builtin.base64_ import Base64Analyzer
from stegoscan.analyzers.builtin.entropy import EntropyAnalyzer
from stegoscan.analyzers.builtin.fileinfo import FileInfoAnalyzer
from stegoscan.analyzers.builtin.flags import FlagAnalyzer
from stegoscan.analyzers.builtin.signatures import SignatureAnalyzer
from stegoscan.analyzers.builtin.strings_ import StringsAnalyzer
from stegoscan.evidence import Evidence
from stegoscan.model import Confidence, Severity, Status
from stegoscan.scanning import build_index


def context(evidence, tmp_path=None, **kwargs):
    options = Options(write_artifacts=tmp_path is not None, **kwargs)
    return Context(
        output_dir=str(tmp_path) if tmp_path else "",
        index=build_index(evidence),
        options=options,
    )


def run(analyzer, path, tmp_path=None, **kwargs):
    evidence = Evidence.open(path)
    return analyzer.run(evidence, context(evidence, tmp_path, **kwargs))


# --- fileinfo ---------------------------------------------------------------


def test_fileinfo_flags_extension_content_mismatch(tmp_path):
    path = write(tmp_path, "innocent.jpg", make_zip())
    result = run(FileInfoAnalyzer(), path)
    titles = [f.title for f in result.findings]
    assert "Extension does not match content" in titles
    mismatch = [f for f in result.findings if f.severity is Severity.MEDIUM][0]
    assert "zip" in mismatch.detail


def test_fileinfo_accepts_a_matching_extension(clean_jpeg):
    result = run(FileInfoAnalyzer(), clean_jpeg)
    assert all(f.severity is Severity.INFO for f in result.findings)


def test_empty_file_is_reported_not_ignored(empty_file):
    result = run(FileInfoAnalyzer(), empty_file)
    assert any("empty" in f.title.lower() for f in result.findings)


# --- signatures -------------------------------------------------------------


def test_embedded_archive_is_reported_as_high(tmp_path):
    path = write(tmp_path, "c.jpg", make_jpeg() + make_zip())
    result = run(SignatureAnalyzer(), path, tmp_path)
    archive = [f for f in result.findings if "ZIP" in f.title]
    assert archive
    assert archive[0].severity is Severity.HIGH
    assert archive[0].confidence is Confidence.CONFIRMED
    assert archive[0].artifact  # the carved payload is kept


def test_native_nested_signature_is_downgraded(tmp_path):
    # A JPEG inside a JPEG is usually an EXIF thumbnail, so it must not scream.
    inner = make_jpeg(scan_data=b"\x11" * 32)
    path = write(tmp_path, "thumb.jpg", make_jpeg(scan_data=b"\x00" * 8 + inner))
    result = run(SignatureAnalyzer(), path, tmp_path)
    nested = [f for f in result.findings if "JPEG" in f.title]
    assert nested
    assert all(f.severity is Severity.LOW for f in nested)


# --- entropy ----------------------------------------------------------------


def test_high_entropy_region_in_a_bmp_is_a_finding(bmp_with_high_entropy):
    result = run(EntropyAnalyzer(), bmp_with_high_entropy)
    hot = [f for f in result.findings if f.severity is Severity.MEDIUM]
    assert hot
    assert "low-entropy carrier" in hot[0].title


def test_entropy_is_informational_only_for_compressed_carriers(tmp_path):
    path = write(tmp_path, "c.jpg", make_jpeg(scan_data=random_bytes(40000)))
    result = run(EntropyAnalyzer(), path)
    assert all(f.severity is Severity.INFO for f in result.findings)
    assert "already compressed" in result.findings[0].detail


# --- flags ------------------------------------------------------------------


def test_flag_token_is_confirmed_and_high(flag_file):
    result = run(FlagAnalyzer(), flag_file)
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[0].confidence is Confidence.CONFIRMED
    assert "FLAG{synthetic_test_flag}" in result.findings[0].excerpt


def test_generic_brace_tokens_stay_low_confidence(tmp_path):
    path = write(tmp_path, "code.txt", b"body { color: red; }\nfunction x() { return 1; }\n")
    result = run(FlagAnalyzer(), path)
    assert all(f.confidence is Confidence.POSSIBLE for f in result.findings)
    assert all(f.severity is Severity.LOW for f in result.findings)


# --- strings ----------------------------------------------------------------


def test_private_key_material_is_high_severity(tmp_path):
    body = b"noise\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n"
    path = write(tmp_path, "k.bin", make_png() + body)
    result = run(StringsAnalyzer(), path, tmp_path)
    keys = [f for f in result.findings if "Private key" in f.title]
    assert keys and keys[0].severity is Severity.HIGH


def test_urls_are_collected_without_shouting(tmp_path):
    path = write(tmp_path, "u.txt", b"see http://example.com/payload for details\n")
    result = run(StringsAnalyzer(), path, tmp_path)
    urls = [f for f in result.findings if "URL" in f.title]
    assert urls and urls[0].severity <= Severity.LOW


# --- base64 -----------------------------------------------------------------


def test_base64_blob_decoding_to_a_flag_is_high(tmp_path):
    blob = base64.b64encode(b"FLAG{base64_wrapped_flag_value}")
    path = write(tmp_path, "b.txt", b"data: " + blob + b"\n")
    result = run(Base64Analyzer(), path, tmp_path)
    assert result.findings
    assert result.findings[0].severity is Severity.HIGH
    assert "flag token" in result.findings[0].title


def test_base64_noise_that_decodes_to_garbage_is_dropped(tmp_path):
    # Random alphanumerics decode to bytes that are neither text nor a container.
    path = write(tmp_path, "n.txt", b"7f3Kd9QmZp2LxWv8Nt4RyBc6Hj1Us5Ee" * 3)
    result = run(Base64Analyzer(), path, tmp_path)
    assert result.status is Status.RAN
    assert result.findings == []


def test_base64_embedded_container_is_extracted(tmp_path):
    blob = base64.b64encode(make_png())
    path = write(tmp_path, "img.txt", b"payload=" + blob)
    result = run(Base64Analyzer(), path, tmp_path)
    assert any("PNG" in f.title for f in result.findings)
