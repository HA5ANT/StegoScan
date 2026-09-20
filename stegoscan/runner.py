"""Per-file orchestration: select analyzers, run them, assess the result."""

from __future__ import annotations

import datetime as _datetime
import os
import platform
import sys
import time
from typing import Dict, List, Optional

from . import registry, tools, verdict as verdict_rules
from .analyzers.base import Context, Options
from .evidence import Evidence
from .model import AnalyzerResult, ScanReport, Status
from .scanning import build_index

VERSION = "3.0.0"


def default_output_dir(target: str, base: str = "stegoscan-out") -> str:
    """Where artifacts go by default.

    Deliberately not next to the evidence: an evidence directory may be
    read-only, mounted from an image, or simply something you should not be
    writing into.
    """
    stamp = _datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = os.path.splitext(os.path.basename(target))[0] or "target"
    return os.path.join(base, "{}-{}".format(stem, stamp))


def scan_file(
    target: str,
    options: Optional[Options] = None,
    output_dir: Optional[str] = None,
    output_base: str = "stegoscan-out",
) -> ScanReport:
    """Examine one file and return the canonical report object."""
    options = options or Options()
    evidence = Evidence.open(target)

    if output_dir is None:
        output_dir = default_output_dir(target, output_base)
    if options.write_artifacts:
        os.makedirs(output_dir, exist_ok=True)

    started = time.time()
    index = build_index(
        evidence,
        carve_size=options.extract_size,
    )

    applicable = registry.analyzers_for(evidence.carrier)
    required_binaries = {binary for analyzer in applicable for binary in analyzer.requires}
    # Skip discovery entirely in builtin-only mode: looking up tools we will not
    # run costs a subprocess each, which is the whole point of the mode.
    available = tools.discover(required_binaries) if options.use_external else {}

    ctx = Context(
        output_dir=output_dir,
        index=index,
        options=options,
        available_tools=available,
    )

    results: List[AnalyzerResult] = []
    for analyzer in applicable:
        results.append(_run_one(analyzer, evidence, ctx, available))

    scan_verdict, coverage = verdict_rules.assess(results)
    unchanged = evidence.verify_unchanged()

    report = ScanReport(
        target=evidence.path,
        carrier=evidence.carrier,
        integrity=evidence.integrity(unchanged),
        verdict=scan_verdict,
        coverage=coverage,
        results=results,
        output_dir=output_dir if options.write_artifacts else None,
        provenance=_provenance(started, available, options),
    )
    return report


def _run_one(analyzer, evidence, ctx: Context, available: Dict[str, tools.ToolInfo]) -> AnalyzerResult:
    if analyzer.requires and not ctx.options.use_external:
        return AnalyzerResult.skipped(analyzer.name, "external tools disabled (--no-external)")
    missing = [name for name in analyzer.requires if not available.get(name, tools.ToolInfo(name, None)).available]
    if missing:
        return AnalyzerResult.skipped(
            analyzer.name, "{} not installed".format(", ".join(sorted(missing)))
        )

    started = time.time()
    try:
        result = analyzer.run(evidence, ctx)
    except Exception as exc:  # noqa: BLE001 - one bad analyzer must not end the scan
        result = AnalyzerResult.errored(analyzer.name, "{}: {}".format(type(exc).__name__, exc))
    if result.status is Status.RAN and len(result.findings) > ctx.options.max_findings_per_analyzer:
        result.findings = result.findings[: ctx.options.max_findings_per_analyzer]
    result.duration_ms = int((time.time() - started) * 1000)
    return result


def _provenance(started: float, available: Dict[str, tools.ToolInfo], options: Options) -> Dict:
    """Everything another examiner needs to reproduce this run."""
    return {
        "stegoscan_version": VERSION,
        "started_utc": _datetime.datetime.fromtimestamp(started, _datetime.timezone.utc).isoformat(),
        "duration_ms": int((time.time() - started) * 1000),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "command": " ".join(sys.argv),
        "options": {
            "extract_size": options.extract_size,
            "timeout": options.timeout,
            "entropy_threshold": options.entropy_threshold,
            "min_string_length": options.min_string_length,
            "aggressive": options.aggressive,
            "wordlist": options.wordlist,
            "password_supplied": options.password is not None,
        },
        "external_tools": {
            name: info.to_dict() for name, info in sorted(available.items())
        },
    }
