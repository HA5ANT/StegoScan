"""The verdict rule table, exhaustively."""

from __future__ import annotations

import pytest

from stegoscan.model import (
    AnalyzerResult,
    Confidence,
    Finding,
    Severity,
    Status,
    Verdict,
)
from stegoscan.verdict import assess, compute_coverage, compute_verdict


def finding(severity, confidence=Confidence.LIKELY):
    return Finding(analyzer="t", title="t", severity=severity, confidence=confidence)


@pytest.mark.parametrize(
    "findings, expected",
    [
        ([], Verdict.CLEAN),
        ([finding(Severity.INFO, Confidence.CONFIRMED)], Verdict.CLEAN),
        ([finding(Severity.LOW)], Verdict.CLEAN),
        ([finding(Severity.LOW)] * 2, Verdict.CLEAN),
        ([finding(Severity.LOW)] * 3, Verdict.NOTABLE),
        ([finding(Severity.MEDIUM)], Verdict.NOTABLE),
        ([finding(Severity.MEDIUM)] * 2, Verdict.SUSPICIOUS),
        ([finding(Severity.HIGH, Confidence.POSSIBLE)], Verdict.SUSPICIOUS),
        ([finding(Severity.HIGH, Confidence.LIKELY)], Verdict.SUSPICIOUS),
        ([finding(Severity.HIGH, Confidence.CONFIRMED)], Verdict.CONFIRMED),
        (
            [finding(Severity.MEDIUM, Confidence.CONFIRMED)] * 5,
            Verdict.SUSPICIOUS,  # confirmed only promotes when severity is HIGH
        ),
    ],
)
def test_verdict_rules(findings, expected):
    assert compute_verdict(findings) is expected


def test_exit_codes_are_distinct_and_stable():
    assert Verdict.CLEAN.exit_code == 0
    assert Verdict.NOTABLE.exit_code == 10
    assert Verdict.SUSPICIOUS.exit_code == 20
    assert Verdict.CONFIRMED.exit_code == 30
    codes = {v.exit_code for v in Verdict}
    assert len(codes) == len(Verdict)


def test_coverage_counts_every_outcome():
    results = [
        AnalyzerResult.ran("a", findings=[finding(Severity.LOW)]),
        AnalyzerResult.skipped("b", "steghide not installed"),
        AnalyzerResult.errored("c", "boom"),
    ]
    coverage = compute_coverage(results)
    assert (coverage.ran, coverage.skipped, coverage.errored) == (1, 1, 1)
    assert coverage.applicable == 3
    assert coverage.is_complete is False
    assert "steghide not installed" in coverage.summary()
    assert "boom" in coverage.summary()


def test_complete_coverage_summary_is_terse():
    coverage = compute_coverage([AnalyzerResult.ran("a"), AnalyzerResult.ran("b")])
    assert coverage.is_complete is True
    assert coverage.summary() == "coverage 2/2"


def test_a_clean_verdict_still_reports_missing_coverage():
    """The core honesty property: clean-but-incomplete must not read as clean."""
    results = [
        AnalyzerResult.ran("builtin"),
        AnalyzerResult.skipped("steghide", "steghide not installed"),
    ]
    verdict, coverage = assess(results)
    assert verdict is Verdict.CLEAN
    assert coverage.is_complete is False
    assert coverage.ratio == 0.5
    assert "skipped" in coverage.summary()


def test_status_never_silently_defaults_to_ran():
    assert AnalyzerResult.skipped("x", "r").status is Status.SKIPPED
    assert AnalyzerResult.errored("x", "r").status is Status.ERROR
    assert AnalyzerResult.ran("x").status is Status.RAN


def test_many_possible_leads_do_not_reach_suspicious():
    """Regression: confidence gates escalation.

    zsteg emits a line per bit-plane combination. Twenty POSSIBLE-confidence
    leads are a reason to look, not grounds for calling a file suspicious.
    """
    leads = [finding(Severity.MEDIUM, Confidence.POSSIBLE) for _ in range(20)]
    assert compute_verdict(leads) is Verdict.NOTABLE


def test_two_corroborated_mediums_still_reach_suspicious():
    corroborated = [finding(Severity.MEDIUM, Confidence.LIKELY) for _ in range(2)]
    assert compute_verdict(corroborated) is Verdict.SUSPICIOUS
