"""Core data model.

Everything the tool produces is one of these objects. Reports are renderers over
``ScanReport``; nothing assembles output independently.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __str__(self) -> str:
        return self.name


class Confidence(enum.IntEnum):
    """How sure we are that a finding means what it says.

    POSSIBLE  a pattern matched, nothing corroborates it
    LIKELY    corroborated by structure or context, payload not extracted
    CONFIRMED payload was extracted and validated as a real container
    """

    POSSIBLE = 1
    LIKELY = 2
    CONFIRMED = 3

    def __str__(self) -> str:
        return self.name


class Status(enum.Enum):
    """Why an analyzer did or did not contribute to the result.

    The SKIPPED/RAN distinction is the whole point: a clean scan where six
    analyzers never ran is not a clean scan.
    """

    RAN = "ran"
    SKIPPED = "skipped"
    ERROR = "error"

    def __str__(self) -> str:
        return self.value


class Verdict(enum.Enum):
    CLEAN = "CLEAN"
    NOTABLE = "NOTABLE"
    SUSPICIOUS = "SUSPICIOUS"
    CONFIRMED = "CONFIRMED"

    @property
    def exit_code(self) -> int:
        return _EXIT_CODES[self]

    @property
    def rank(self) -> int:
        return _RANKS[self]

    def __str__(self) -> str:
        return self.value


_EXIT_CODES = {
    Verdict.CLEAN: 0,
    Verdict.NOTABLE: 10,
    Verdict.SUSPICIOUS: 20,
    Verdict.CONFIRMED: 30,
}

_RANKS = {
    Verdict.CLEAN: 0,
    Verdict.NOTABLE: 1,
    Verdict.SUSPICIOUS: 2,
    Verdict.CONFIRMED: 3,
}

EXIT_ERROR = 1


class Carrier(enum.Enum):
    """Container format of the evidence, used to gate analyzers."""

    JPEG = "jpeg"
    PNG = "png"
    GIF = "gif"
    BMP = "bmp"
    WAV = "wav"
    PDF = "pdf"
    ZIP = "zip"
    TEXT = "text"
    OTHER = "other"

    def __str__(self) -> str:
        return self.value

    @property
    def is_lossy_compressed(self) -> bool:
        """Carriers whose payload bytes are already near-random.

        Entropy analysis has to be read differently for these: a high global
        entropy score means nothing in a JPEG and means a great deal in a BMP.
        """
        return self in (Carrier.JPEG, Carrier.PNG, Carrier.ZIP, Carrier.GIF)


@dataclass
class Finding:
    """One thing worth telling a human about, with the evidence for it."""

    analyzer: str
    title: str
    severity: Severity
    confidence: Confidence
    detail: str = ""
    offset: Optional[int] = None
    length: Optional[int] = None
    excerpt: str = ""
    next_step: str = ""
    artifact: Optional[str] = None

    @property
    def score(self) -> int:
        return int(self.severity) * int(self.confidence)

    def sort_key(self) -> Tuple[int, int, int, str, str]:
        # Deterministic: strongest first, then by position, then by name.
        return (
            -int(self.severity),
            -int(self.confidence),
            self.offset if self.offset is not None else 1 << 62,
            self.analyzer,
            self.title,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "title": self.title,
            "severity": str(self.severity),
            "confidence": str(self.confidence),
            "detail": self.detail,
            "offset": self.offset,
            "offset_hex": None if self.offset is None else hex(self.offset),
            "length": self.length,
            "excerpt": self.excerpt,
            "next_step": self.next_step,
            "artifact": self.artifact,
        }


@dataclass
class AnalyzerResult:
    """What one analyzer did, including the case where it did nothing."""

    analyzer: str
    status: Status
    reason: str = ""
    findings: List[Finding] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    duration_ms: int = 0
    detail: str = ""

    @classmethod
    def ran(
        cls,
        analyzer: str,
        findings: Optional[List[Finding]] = None,
        artifacts: Optional[List[str]] = None,
        detail: str = "",
    ) -> "AnalyzerResult":
        return cls(
            analyzer=analyzer,
            status=Status.RAN,
            findings=list(findings or []),
            artifacts=list(artifacts or []),
            detail=detail,
        )

    @classmethod
    def skipped(cls, analyzer: str, reason: str) -> "AnalyzerResult":
        return cls(analyzer=analyzer, status=Status.SKIPPED, reason=reason)

    @classmethod
    def errored(cls, analyzer: str, reason: str) -> "AnalyzerResult":
        return cls(analyzer=analyzer, status=Status.ERROR, reason=reason)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "status": str(self.status),
            "reason": self.reason,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "artifacts": list(self.artifacts),
            "findings": [f.to_dict() for f in self.findings],
        }


def _group_by_reason(reasons: Dict[str, str]) -> str:
    """Render analyzer:reason pairs grouped by shared reason.

    Six analyzers skipped for the same reason should read as one clause, not
    six. The coverage line is the most-read sentence in the whole report.
    """
    grouped: Dict[str, List[str]] = {}
    for name, reason in sorted(reasons.items()):
        grouped.setdefault(reason, []).append(name)
    return ", ".join(
        "{} ({})".format(", ".join(names), reason) for reason, names in sorted(grouped.items())
    )


@dataclass
class Coverage:
    """How much of the intended examination actually happened."""

    ran: int
    skipped: int
    errored: int
    skipped_reasons: Dict[str, str] = field(default_factory=dict)
    error_reasons: Dict[str, str] = field(default_factory=dict)

    @property
    def applicable(self) -> int:
        return self.ran + self.skipped + self.errored

    @property
    def ratio(self) -> float:
        if self.applicable == 0:
            return 0.0
        return self.ran / self.applicable

    @property
    def is_complete(self) -> bool:
        return self.skipped == 0 and self.errored == 0

    def summary(self) -> str:
        base = "coverage {}/{}".format(self.ran, self.applicable)
        if self.is_complete:
            return base
        parts = []
        if self.skipped_reasons:
            parts.append("skipped: " + _group_by_reason(self.skipped_reasons))
        if self.error_reasons:
            parts.append("errors: " + _group_by_reason(self.error_reasons))
        return "{} — {}".format(base, "; ".join(parts))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ran": self.ran,
            "skipped": self.skipped,
            "errored": self.errored,
            "applicable": self.applicable,
            "ratio": round(self.ratio, 4),
            "complete": self.is_complete,
            "skipped_reasons": dict(self.skipped_reasons),
            "error_reasons": dict(self.error_reasons),
        }


@dataclass
class Integrity:
    """Proof the tool did not alter the evidence."""

    sha256: str
    md5: str
    size: int
    verified_unchanged: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "md5": self.md5,
            "size": self.size,
            "verified_unchanged": self.verified_unchanged,
        }


@dataclass
class ScanReport:
    """Canonical result object. JSON, Markdown and CSV are renderers over this."""

    target: str
    carrier: Carrier
    integrity: Integrity
    verdict: Verdict
    coverage: Coverage
    results: List[AnalyzerResult] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    output_dir: Optional[str] = None

    @property
    def findings(self) -> List[Finding]:
        """All findings across analyzers, strongest first."""
        collected: List[Finding] = []
        for result in self.results:
            collected.extend(result.findings)
        return sorted(collected, key=lambda f: f.sort_key())

    @property
    def score(self) -> int:
        return sum(f.score for f in self.findings)

    def findings_at_or_above(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity >= severity]

    def headline(self) -> str:
        return "{} ({})".format(self.verdict, self.coverage.summary())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stegoscan": {"report_version": REPORT_VERSION},
            "target": self.target,
            "carrier": str(self.carrier),
            "verdict": str(self.verdict),
            "exit_code": self.verdict.exit_code,
            "score": self.score,
            "coverage": self.coverage.to_dict(),
            "integrity": self.integrity.to_dict(),
            "output_dir": self.output_dir,
            "findings": [f.to_dict() for f in self.findings],
            "analyzers": [r.to_dict() for r in self.results],
            "provenance": dict(self.provenance),
        }


REPORT_VERSION = "3.0"
