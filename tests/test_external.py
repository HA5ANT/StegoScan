"""External analyzers, driven by a stubbed tool runner.

No forensics binary is invoked here: the point is that StegoScan parses tool
output correctly and stays honest when a tool is absent, times out or crashes.
"""

from __future__ import annotations

import json

import pytest

from conftest import make_jpeg, make_png, write
from stegoscan import tools
from stegoscan.analyzers.base import Context, Options
from stegoscan.analyzers.external.binwalk import BinwalkAnalyzer
from stegoscan.analyzers.external.exiftool import ExiftoolAnalyzer
from stegoscan.analyzers.external.stegdetect import StegdetectAnalyzer
from stegoscan.analyzers.external.steghide import SteghideAnalyzer
from stegoscan.analyzers.external.stegseek import StegseekAnalyzer
from stegoscan.analyzers.external.zsteg import ZstegAnalyzer
from stegoscan.evidence import Evidence
from stegoscan.model import Confidence, Severity, Status
from stegoscan.runner import _run_one
from stegoscan.scanning import build_index


@pytest.fixture
def stub_run(monkeypatch):
    """Replace tool execution with canned output."""

    def install(stdout=b"", stderr=b"", returncode=0, timed_out=False, error=""):
        def fake(argv, timeout, cwd=None, stdin_data=None, env=None):
            return tools.ToolRun(list(argv), returncode, stdout, stderr, timed_out, error)

        monkeypatch.setattr(tools, "run", fake)

    return install


def make_ctx(path, tmp_path, **options):
    evidence = Evidence.open(path)
    ctx = Context(
        output_dir=str(tmp_path),
        index=build_index(evidence),
        options=Options(**options),
        available_tools={
            name: tools.ToolInfo(name, "/usr/bin/" + name, "stub 1.0")
            for name in ("binwalk", "exiftool", "steghide", "stegseek", "zsteg", "stegdetect")
        },
    )
    return evidence, ctx


# --- absence, timeouts and crashes ------------------------------------------


def test_missing_binary_is_skipped_with_a_reason(clean_jpeg, tmp_path):
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    ctx.available_tools["steghide"] = tools.ToolInfo("steghide", None)
    result = _run_one(SteghideAnalyzer(), evidence, ctx, ctx.available_tools)
    assert result.status is Status.SKIPPED
    assert "steghide not installed" in result.reason
    assert result.findings == []


def test_timeout_becomes_an_error_not_an_empty_result(clean_jpeg, tmp_path, stub_run):
    stub_run(timed_out=True)
    evidence, ctx = make_ctx(clean_jpeg, tmp_path, timeout=42)
    result = BinwalkAnalyzer().run(evidence, ctx)
    assert result.status is Status.ERROR
    assert "timed out after 42 seconds" in result.reason


def test_exec_failure_becomes_an_error(clean_jpeg, tmp_path, stub_run):
    stub_run(error="Permission denied")
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = BinwalkAnalyzer().run(evidence, ctx)
    assert result.status is Status.ERROR
    assert "Permission denied" in result.reason


def test_analyzer_exception_does_not_abort_the_scan(clean_jpeg, tmp_path, monkeypatch):
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)

    class Exploding(BinwalkAnalyzer):
        def run(self, evidence, ctx):
            raise RuntimeError("analyzer bug")

    result = _run_one(Exploding(), evidence, ctx, ctx.available_tools)
    assert result.status is Status.ERROR
    assert "RuntimeError: analyzer bug" in result.reason


# --- binwalk ----------------------------------------------------------------

_BINWALK_OUTPUT = b"""DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
544           0x220           Zip archive data, at least v2.0 to extract
9000          0x2328          PNG image, 100 x 100, 8-bit/color RGB
"""


def test_binwalk_skips_the_header_row(clean_jpeg, tmp_path, stub_run):
    stub_run(stdout=_BINWALK_OUTPUT)
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = BinwalkAnalyzer().run(evidence, ctx)
    assert all(f.offset != 0 for f in result.findings)
    assert len(result.findings) == 2


def test_binwalk_hit_the_builtin_scanner_missed_is_raised(tmp_path, stub_run):
    stub_run(stdout=_BINWALK_OUTPUT)
    path = write(tmp_path, "c.jpg", make_jpeg())
    evidence, ctx = make_ctx(path, tmp_path)
    result = BinwalkAnalyzer().run(evidence, ctx)
    uncorroborated = [f for f in result.findings if f.severity is Severity.MEDIUM]
    assert uncorroborated
    assert "did not validate" in uncorroborated[0].detail


# --- steghide ---------------------------------------------------------------


def test_steghide_reports_an_embedded_payload(clean_jpeg, tmp_path, stub_run):
    stub_run(stdout=b'"c.jpg":\n  format: jpeg\n  embedded file "secret.txt":\n    size: 100.0 Byte\n')
    evidence, ctx = make_ctx(clean_jpeg, tmp_path, write_artifacts=False)
    result = SteghideAnalyzer().run(evidence, ctx)
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[0].confidence is Confidence.CONFIRMED
    assert "secret.txt" in result.findings[0].title


def test_steghide_without_a_payload_reports_capacity_only(clean_jpeg, tmp_path, stub_run):
    stub_run(
        stdout=b'"c.jpg":\n  format: jpeg\n  capacity: 1.2 KB\n',
        stderr=b"steghide: could not extract any data with that passphrase!\n",
    )
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = SteghideAnalyzer().run(evidence, ctx)
    assert result.status is Status.RAN
    assert result.findings == []
    assert "capacity" in result.detail


def test_steghide_only_applies_to_supported_carriers():
    from stegoscan.model import Carrier

    analyzer = SteghideAnalyzer()
    assert analyzer.applies(Carrier.JPEG)
    assert not analyzer.applies(Carrier.PNG)
    assert not analyzer.applies(Carrier.PDF)


# --- stegseek ---------------------------------------------------------------


def test_stegseek_is_skipped_unless_asked_for(clean_jpeg, tmp_path, stub_run):
    stub_run()
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = StegseekAnalyzer().run(evidence, ctx)
    assert result.status is Status.SKIPPED
    assert "--aggressive" in result.reason


def test_stegseek_without_a_wordlist_says_so(clean_jpeg, tmp_path, stub_run):
    stub_run()
    evidence, ctx = make_ctx(clean_jpeg, tmp_path, aggressive=True)
    result = StegseekAnalyzer().run(evidence, ctx)
    assert result.status is Status.SKIPPED
    assert "wordlist" in result.reason


def test_stegseek_reports_a_recovered_passphrase(clean_jpeg, tmp_path, stub_run):
    wordlist = write(tmp_path, "words.txt", b"hunter2\n")
    stub_run(stdout=b'[i] Found passphrase: "hunter2"\n')
    evidence, ctx = make_ctx(clean_jpeg, tmp_path, aggressive=True, wordlist=wordlist)
    result = StegseekAnalyzer().run(evidence, ctx)
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[0].confidence is Confidence.CONFIRMED
    assert "hunter2" in result.findings[0].detail


# --- zsteg ------------------------------------------------------------------


def test_zsteg_flag_line_outranks_ordinary_noise(tmp_path, stub_run):
    stub_run(stdout=b'b1,rgb,lsb,xy .. text: "FLAG{lsb_hidden}"\nb2,r,msb,xy .. nothing\n')
    path = write(tmp_path, "c.png", make_png())
    evidence, ctx = make_ctx(path, tmp_path)
    result = ZstegAnalyzer().run(evidence, ctx)
    assert len(result.findings) == 1
    assert result.findings[0].severity is Severity.HIGH
    assert result.findings[0].confidence is Confidence.CONFIRMED


def test_zsteg_ordinary_output_stays_possible(tmp_path, stub_run):
    stub_run(stdout=b'b1,rgb,lsb,xy .. text: "aXdjbmR"\n')
    path = write(tmp_path, "c.png", make_png())
    evidence, ctx = make_ctx(path, tmp_path)
    result = ZstegAnalyzer().run(evidence, ctx)
    assert result.findings[0].confidence is Confidence.POSSIBLE
    assert result.findings[0].severity is Severity.MEDIUM


# --- exiftool ---------------------------------------------------------------


def test_exiftool_finds_a_flag_in_a_comment(clean_jpeg, tmp_path, stub_run):
    payload = json.dumps([{"SourceFile": "c.jpg", "Comment": "FLAG{metadata_flag}"}]).encode()
    stub_run(stdout=payload)
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = ExiftoolAnalyzer().run(evidence, ctx)
    assert result.findings[0].severity is Severity.HIGH
    assert "FLAG{metadata_flag}" in result.findings[0].excerpt


def test_exiftool_decodes_base64_comments(clean_jpeg, tmp_path, stub_run):
    import base64 as b64

    encoded = b64.b64encode(b"the quick brown fox jumped over").decode()
    stub_run(stdout=json.dumps([{"UserComment": encoded}]).encode())
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = ExiftoolAnalyzer().run(evidence, ctx)
    assert result.findings[0].severity is Severity.MEDIUM
    assert "quick brown fox" in result.findings[0].excerpt


def test_exiftool_reports_gps_without_alarm(clean_jpeg, tmp_path, stub_run):
    stub_run(stdout=json.dumps([{"GPSPosition": "51.5 N, 0.1 W"}]).encode())
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = ExiftoolAnalyzer().run(evidence, ctx)
    gps = [f for f in result.findings if "GPS" in f.title]
    assert gps and gps[0].severity is Severity.LOW


def test_exiftool_unparseable_output_is_handled(clean_jpeg, tmp_path, stub_run):
    stub_run(stdout=b"not json at all")
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = ExiftoolAnalyzer().run(evidence, ctx)
    assert result.status is Status.RAN
    assert "unparseable" in result.detail


# --- stegdetect -------------------------------------------------------------


def test_stegdetect_negative_produces_no_findings(clean_jpeg, tmp_path, stub_run):
    stub_run(stdout=b"c.jpg : negative\n")
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = StegdetectAnalyzer().run(evidence, ctx)
    assert result.findings == []


def test_stegdetect_positive_stays_possible(clean_jpeg, tmp_path, stub_run):
    stub_run(stdout=b"c.jpg : jphide(*)\n")
    evidence, ctx = make_ctx(clean_jpeg, tmp_path)
    result = StegdetectAnalyzer().run(evidence, ctx)
    assert result.findings[0].confidence is Confidence.POSSIBLE
    assert "false positives" in result.findings[0].detail


# --- false-positive regressions ---------------------------------------------


def test_zsteg_empty_result_lines_are_all_discarded(tmp_path, stub_run):
    """Regression: the `..` separator ends the line when there is no result.

    zsteg emits one line per bit-plane combination and most are empty. An
    earlier filter matched on the separator itself, so every line survived and
    a clean PNG came back SUSPICIOUS on volume alone.
    """
    noise = b"".join(
        "b{},{},{},xy         ..\n".format(bit, channel, order).encode()
        for bit in (1, 2)
        for channel in ("r", "g", "b", "rgb", "bgr")
        for order in ("lsb", "msb")
    )
    stub_run(stdout=noise)
    path = write(tmp_path, "c.png", make_png())
    evidence, ctx = make_ctx(path, tmp_path)
    result = ZstegAnalyzer().run(evidence, ctx)
    assert result.findings == []
    assert result.detail == "0 interesting lines"


def test_binwalk_ignores_compression_inherent_to_the_container(tmp_path, stub_run):
    """A PNG is zlib streams by definition; reporting them is noise."""
    stub_run(
        stdout=b"DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        b"0             0x0             PNG image, 1 x 1, 8-bit/color RGB\n"
        b"41            0x29            Zlib compressed data, default compression\n"
    )
    path = write(tmp_path, "c.png", make_png())
    evidence, ctx = make_ctx(path, tmp_path)
    result = BinwalkAnalyzer().run(evidence, ctx)
    assert result.findings == []
