"""Analyzer contract and the shared context handed to every analyzer."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple, Union

from ..model import AnalyzerResult, Carrier, Confidence, Finding, Severity
from ..scanning import ScanIndex

# Artifacts are capped so a pathological carrier cannot fill the disk.
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


@dataclass
class Options:
    """Everything the CLI lets a user tune, in one place."""

    extract_size: int = 512 * 1024
    preview_lines: int = 40
    min_string_length: int = 6
    timeout: int = 300
    password: Optional[str] = None
    wordlist: Optional[str] = None
    aggressive: bool = False
    entropy_threshold: float = 7.5
    max_findings_per_analyzer: int = 50
    write_artifacts: bool = True
    # Builtin-only mode: no subprocesses at all. Faster, fully deterministic,
    # and the honest choice when you need a scan that depends on nothing but
    # this package. Disabled analyzers are still reported as skipped.
    use_external: bool = True


@dataclass
class Context:
    """Per-file state shared by every analyzer in a scan."""

    output_dir: str
    index: ScanIndex
    options: Options = field(default_factory=Options)
    available_tools: dict = field(default_factory=dict)

    def artifact_dir(self, subdir: str = "") -> str:
        path = os.path.join(self.output_dir, subdir) if subdir else self.output_dir
        os.makedirs(path, exist_ok=True)
        return path

    def write_artifact(self, name: str, data: Union[bytes, str], subdir: str = "") -> Optional[str]:
        """Write an artifact and return its path relative to the output dir.

        Returns None when artifact writing is disabled, so callers can record a
        finding without an artifact rather than branching everywhere.
        """
        if not self.options.write_artifacts:
            return None
        payload = data.encode("utf-8", "replace") if isinstance(data, str) else data
        if len(payload) > MAX_ARTIFACT_BYTES:
            payload = payload[:MAX_ARTIFACT_BYTES]
        directory = self.artifact_dir(subdir)
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(payload)
        return os.path.relpath(path, self.output_dir)


class Analyzer:
    """Base class for every detection module.

    Subclasses set ``name``/``title``, optionally restrict themselves to
    specific carriers via ``applies_to``, declare external binaries in
    ``requires``, and implement :meth:`run`.
    """

    name: str = ""
    title: str = ""
    # Empty means "every carrier".
    applies_to: Tuple[Carrier, ...] = ()
    # External executables this analyzer shells out to. Builtins declare none.
    requires: Tuple[str, ...] = ()

    def applies(self, carrier: Carrier) -> bool:
        return not self.applies_to or carrier in self.applies_to

    def run(self, evidence, ctx: Context) -> AnalyzerResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # --- helpers for subclasses --------------------------------------------

    def ok(
        self,
        findings: Optional[Iterable[Finding]] = None,
        artifacts: Optional[Sequence[str]] = None,
        detail: str = "",
    ) -> AnalyzerResult:
        collected: List[Finding] = [f for f in (findings or []) if f is not None]
        return AnalyzerResult.ran(
            self.name,
            findings=collected,
            artifacts=[a for a in (artifacts or []) if a],
            detail=detail,
        )

    def skip(self, reason: str) -> AnalyzerResult:
        return AnalyzerResult.skipped(self.name, reason)

    def finding(
        self,
        title: str,
        severity: Severity,
        confidence: Confidence,
        detail: str = "",
        offset: Optional[int] = None,
        length: Optional[int] = None,
        excerpt: str = "",
        next_step: str = "",
        artifact: Optional[str] = None,
    ) -> Finding:
        return Finding(
            analyzer=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            detail=detail,
            offset=offset,
            length=length,
            excerpt=excerpt,
            next_step=next_step,
            artifact=artifact,
        )


def excerpt_bytes(data: bytes, limit: int = 120) -> str:
    """Render bytes for human eyes without letting control codes through."""
    text = data[:limit].decode("utf-8", "replace")
    cleaned = "".join(ch if ch.isprintable() else "." for ch in text)
    if len(data) > limit:
        cleaned += "..."
    return cleaned
