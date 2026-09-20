"""Verdict rules, in one place so they can be argued with and tested.

Scoring logic scattered through analyzers is how a tool ends up with a verdict
nobody can explain. The whole policy is the table below.

    CONFIRMED   a high-severity finding whose payload was extracted and validated
    SUSPICIOUS  a high-severity finding, or two or more corroborated medium ones
    NOTABLE     one medium finding, or three or more low ones
    CLEAN       nothing above informational

Confidence gates escalation to SUSPICIOUS: only findings at LIKELY or better
count toward the "two mediums" rule. Tools such as zsteg emit a line per
bit-plane combination, and a pile of POSSIBLE-confidence leads is a reason to
look, not grounds for calling a file suspicious.

A verdict never travels without its coverage: `CLEAN` from six of thirteen
analyzers is a different claim from `CLEAN` from thirteen of thirteen, and the
caller is not allowed to conflate them.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Tuple

from .model import AnalyzerResult, Confidence, Coverage, Finding, Severity, Status, Verdict


def compute_coverage(results: Sequence[AnalyzerResult]) -> Coverage:
    ran = skipped = errored = 0
    skipped_reasons = {}
    error_reasons = {}
    for result in results:
        if result.status is Status.RAN:
            ran += 1
        elif result.status is Status.SKIPPED:
            skipped += 1
            skipped_reasons[result.analyzer] = result.reason or "no reason given"
        else:
            errored += 1
            error_reasons[result.analyzer] = result.reason or "unknown error"
    return Coverage(
        ran=ran,
        skipped=skipped,
        errored=errored,
        skipped_reasons=skipped_reasons,
        error_reasons=error_reasons,
    )


def compute_verdict(findings: Iterable[Finding]) -> Verdict:
    findings = list(findings)
    high = [f for f in findings if f.severity is Severity.HIGH]
    medium = [f for f in findings if f.severity is Severity.MEDIUM]
    low = [f for f in findings if f.severity is Severity.LOW]

    corroborated_medium = [f for f in medium if f.confidence >= Confidence.LIKELY]

    if any(f.confidence is Confidence.CONFIRMED for f in high):
        return Verdict.CONFIRMED
    if high or len(corroborated_medium) >= 2:
        return Verdict.SUSPICIOUS
    if medium or len(low) >= 3:
        return Verdict.NOTABLE
    return Verdict.CLEAN


def assess(results: Sequence[AnalyzerResult]) -> Tuple[Verdict, Coverage]:
    findings: List[Finding] = []
    for result in results:
        findings.extend(result.findings)
    return compute_verdict(findings), compute_coverage(results)
