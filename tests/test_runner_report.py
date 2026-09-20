"""End-to-end scans, evidence integrity, and report rendering."""

from __future__ import annotations

import json
import os

from conftest import make_jpeg, make_zip, write
from stegoscan.analyzers.base import Options
from stegoscan.evidence import digest_file
from stegoscan.model import REPORT_VERSION, Status, Verdict
from stegoscan.report import json_report, markdown
from stegoscan.runner import scan_file


def test_scan_does_not_modify_the_evidence(jpeg_with_appended_zip, tmp_path):
    """Principle 2, asserted rather than assumed."""
    before = digest_file(jpeg_with_appended_zip)
    report = scan_file(jpeg_with_appended_zip, output_dir=str(tmp_path / "out"))
    after = digest_file(jpeg_with_appended_zip)

    assert before == after
    assert report.integrity.verified_unchanged is True
    assert report.integrity.sha256 == before.sha256


def test_appended_archive_produces_a_confirmed_verdict(jpeg_with_appended_zip, tmp_path):
    report = scan_file(jpeg_with_appended_zip, output_dir=str(tmp_path / "out"))
    assert report.verdict is Verdict.CONFIRMED
    assert report.verdict.exit_code == 30


def test_clean_carrier_is_clean(clean_jpeg, tmp_path):
    report = scan_file(clean_jpeg, output_dir=str(tmp_path / "out"))
    assert report.verdict is Verdict.CLEAN


def test_coverage_is_reported_even_when_everything_ran(clean_jpeg, tmp_path):
    report = scan_file(clean_jpeg, output_dir=str(tmp_path / "out"))
    assert report.coverage.applicable == len(report.results)
    assert report.coverage.ran + report.coverage.skipped + report.coverage.errored == len(report.results)
    assert "coverage" in report.headline()


def test_missing_external_tools_become_skips_not_silence(clean_jpeg, tmp_path):
    report = scan_file(clean_jpeg, output_dir=str(tmp_path / "out"))
    skipped = [r for r in report.results if r.status is Status.SKIPPED]
    for result in skipped:
        assert result.reason, "a skipped analyzer must say why"


def test_findings_are_ordered_strongest_first(jpeg_with_appended_zip, tmp_path):
    report = scan_file(jpeg_with_appended_zip, output_dir=str(tmp_path / "out"))
    severities = [int(f.severity) for f in report.findings]
    assert severities == sorted(severities, reverse=True)


def test_artifacts_are_written_under_the_output_dir(jpeg_with_appended_zip, tmp_path):
    out = str(tmp_path / "out")
    report = scan_file(jpeg_with_appended_zip, output_dir=out)
    assert report.output_dir == out
    carved = os.path.join(out, "carved")
    assert os.path.isdir(carved)
    assert os.listdir(carved)


def test_no_artifacts_mode_writes_nothing(jpeg_with_appended_zip, tmp_path):
    out = str(tmp_path / "unwritten")
    report = scan_file(
        jpeg_with_appended_zip, options=Options(write_artifacts=False), output_dir=out
    )
    assert report.output_dir is None
    assert not os.path.exists(out)


def test_empty_file_scans_without_crashing(empty_file, tmp_path):
    report = scan_file(empty_file, output_dir=str(tmp_path / "out"))
    assert report.verdict is Verdict.CLEAN
    assert report.integrity.size == 0


def test_json_report_shape(jpeg_with_appended_zip, tmp_path):
    report = scan_file(jpeg_with_appended_zip, output_dir=str(tmp_path / "out"))
    payload = json.loads(json_report.render(report))

    assert payload["stegoscan"]["report_version"] == REPORT_VERSION
    assert payload["verdict"] == "CONFIRMED"
    assert payload["exit_code"] == 30
    assert payload["integrity"]["verified_unchanged"] is True
    assert payload["coverage"]["applicable"] >= 1
    assert payload["provenance"]["stegoscan_version"]
    for finding in payload["findings"]:
        assert {"analyzer", "title", "severity", "confidence"} <= set(finding)
    for analyzer in payload["analyzers"]:
        assert analyzer["status"] in ("ran", "skipped", "error")


def test_json_rendering_is_deterministic(clean_jpeg, tmp_path):
    report = scan_file(clean_jpeg, output_dir=str(tmp_path / "out"))
    assert json_report.render(report) == json_report.render(report)


def test_markdown_report_states_verdict_and_coverage(jpeg_with_appended_zip, tmp_path):
    report = scan_file(jpeg_with_appended_zip, output_dir=str(tmp_path / "out"))
    text = markdown.render(report)

    assert "# StegoScan report" in text
    assert "CONFIRMED" in text
    assert "coverage" in text
    assert report.integrity.sha256 in text
    assert "## Coverage" in text
    assert "triage tool" in text  # the limitations note must survive rendering


def test_markdown_warns_when_coverage_is_incomplete(clean_jpeg, tmp_path):
    report = scan_file(clean_jpeg, output_dir=str(tmp_path / "out"))
    text = markdown.render(report)
    if not report.coverage.is_complete:
        assert "Coverage is incomplete" in text
