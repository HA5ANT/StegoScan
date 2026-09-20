"""Bulk triage: scan a directory and rank what deserves a human first.

This is the workflow that a flat loop over ``dir/*`` does not serve. Given an
acquisition of thousands of files, the useful output is not thousands of
reports but an ordering: what to open first, and how much of each file was
actually examined.

Parallelism is at file granularity only. That is where the volume is, and one
level of concurrency is enough to saturate the work without making failures
hard to attribute.
"""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .analyzers.base import Options
from .model import EXIT_ERROR, Severity, Verdict
from .report import csv_report, json_report, markdown
from .runner import default_output_dir, scan_file

# Directories that are never evidence.
_SKIP_DIRS = {".git", ".svn", ".hg", "__pycache__", ".pytest_cache", "node_modules"}


@dataclass
class BulkResult:
    """A compact per-file summary; the full report stays on disk."""

    path: str
    carrier: str = ""
    verdict: str = ""
    rank: int = -1
    score: int = 0
    coverage_ran: int = 0
    coverage_applicable: int = 0
    top_finding: str = ""
    sha256: str = ""
    size: int = 0
    output_dir: Optional[str] = None
    error: str = ""
    findings: List[Dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> Dict:
        return {
            "file": self.path,
            "carrier": self.carrier,
            "verdict": self.verdict,
            "score": self.score,
            "coverage": {"ran": self.coverage_ran, "applicable": self.coverage_applicable},
            "top_finding": self.top_finding,
            "sha256": self.sha256,
            "size": self.size,
            "report_dir": self.output_dir,
            "error": self.error,
            "findings": self.findings,
        }


def walk(directory: str, recursive: bool, exclude: Sequence[str] = ()) -> List[str]:
    """Collect candidate files, never following symlinks out of the tree."""
    excluded = {os.path.abspath(path) for path in exclude}
    collected: List[str] = []

    if not recursive:
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if os.path.isfile(path) and not os.path.islink(path) and _wanted(path, excluded):
                collected.append(path)
        return collected

    for root, dirs, files in os.walk(directory, followlinks=False):
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in _SKIP_DIRS
            and not d.startswith(".")
            and os.path.abspath(os.path.join(root, d)) not in excluded
        )
        for name in sorted(files):
            path = os.path.join(root, name)
            if not os.path.islink(path) and _wanted(path, excluded):
                collected.append(path)
    return collected


def _wanted(path: str, excluded) -> bool:
    if os.path.abspath(os.path.dirname(path)) in excluded:
        return False
    # Never re-ingest our own output.
    return os.path.basename(path) not in ("report.md", "report.json", "summary.csv", "summary.json")


@dataclass
class BulkJob:
    """Picklable unit of work for a pool worker."""

    path: str
    options: Options
    output_base: str
    formats: Tuple[str, ...]


def scan_one(job: BulkJob) -> BulkResult:
    """Worker entry point. Must stay importable and picklable."""
    try:
        output_dir = (
            default_output_dir(job.path, job.output_base) if job.options.write_artifacts else None
        )
        report = scan_file(
            job.path,
            options=job.options,
            output_dir=output_dir,
            output_base=job.output_base,
        )
    except Exception as exc:  # noqa: BLE001 - one unreadable file must not stop the run
        return BulkResult(path=job.path, error="{}: {}".format(type(exc).__name__, exc))

    if report.output_dir and job.formats:
        os.makedirs(report.output_dir, exist_ok=True)
        if "markdown" in job.formats:
            _write(os.path.join(report.output_dir, "report.md"), markdown.render(report))
        if "json" in job.formats:
            _write(os.path.join(report.output_dir, "report.json"), json_report.render(report))

    notable = [f for f in report.findings if f.severity > Severity.INFO]
    return BulkResult(
        path=report.target,
        carrier=str(report.carrier),
        verdict=str(report.verdict),
        rank=report.verdict.rank,
        score=report.score,
        coverage_ran=report.coverage.ran,
        coverage_applicable=report.coverage.applicable,
        top_finding=notable[0].title if notable else "",
        sha256=report.integrity.sha256,
        size=report.integrity.size,
        output_dir=report.output_dir,
        findings=[f.to_dict() for f in notable[:5]],
    )


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def triage(
    directory: str,
    options: Options,
    output_base: str = "stegoscan-out",
    recursive: bool = False,
    jobs: int = 0,
    formats: Tuple[str, ...] = ("markdown", "json"),
    progress=None,
) -> List[BulkResult]:
    """Scan every file under ``directory`` and return results, worst first."""
    targets = walk(directory, recursive, exclude=[output_base])
    if not targets:
        return []

    workers = jobs if jobs > 0 else min(len(targets), os.cpu_count() or 1)
    work = [BulkJob(path, options, output_base, formats) for path in targets]
    results: List[BulkResult] = []

    if workers <= 1 or len(work) == 1:
        for index, job in enumerate(work, start=1):
            result = scan_one(job)
            results.append(result)
            if progress:
                progress(index, len(work), result)
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(scan_one, job): job for job in work}
            for index, future in enumerate(as_completed(futures), start=1):
                result = future.result()
                results.append(result)
                if progress:
                    progress(index, len(work), result)

    return rank(results)


def rank(results: Sequence[BulkResult]) -> List[BulkResult]:
    """Most suspicious first; that is the entire point of the summary."""
    return sorted(results, key=lambda r: (-r.rank, -r.score, r.path))


def write_summary(results: Sequence[BulkResult], output_base: str) -> List[str]:
    os.makedirs(output_base, exist_ok=True)
    csv_path = os.path.join(output_base, "summary.csv")
    json_path = os.path.join(output_base, "summary.json")
    _write(csv_path, csv_report.render(results))
    _write(
        json_path,
        json.dumps(
            {
                "scanned": len(results),
                "errors": sum(1 for r in results if not r.ok),
                "results": [r.to_dict() for r in results],
            },
            indent=2,
            ensure_ascii=False,
        ),
    )
    return [csv_path, json_path]


_MIN_RANK = {"clean": 0, "notable": 1, "suspicious": 2, "confirmed": 3}


def run_bulk(directory: str, args, options: Options, printer) -> Tuple[int, Optional[Verdict]]:
    """CLI adapter: run a bulk triage and print the ranked summary."""

    def progress(done: int, total: int, result: BulkResult) -> None:
        if printer.quiet:
            return
        label = result.verdict or "ERROR"
        print(
            "[{}/{}] {} {}".format(done, total, label, os.path.basename(result.path)),
            file=sys.stderr,
        )

    results = triage(
        directory,
        options=options,
        output_base=args.output_base,
        recursive=args.recursive,
        jobs=args.jobs,
        formats=_formats(args),
        progress=progress if args.print_format != "none" else None,
    )

    if not results:
        print("stegoscan: no files found in {}".format(directory), file=sys.stderr)
        return EXIT_ERROR, None

    written = []
    if not args.no_artifacts:
        written = write_summary(results, args.output_base)

    scanned = [r for r in results if r.ok]
    if args.print_format == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    elif args.print_format != "none":
        _print_ranked(results, args, printer, written)

    if not scanned:
        return EXIT_ERROR, None
    worst = max(scanned, key=lambda r: r.rank)
    return 0, Verdict(worst.verdict)


def _formats(args) -> Tuple[str, ...]:
    if args.no_artifacts or args.format == "none":
        return ()
    if args.format == "both":
        return ("markdown", "json")
    return (args.format,)


def _print_ranked(results, args, printer, written) -> None:
    minimum = _MIN_RANK.get(args.min_verdict, 0)
    shown = [r for r in results if r.ok and r.rank >= minimum]
    errors = [r for r in results if not r.ok]

    printer.always("")
    printer.always(
        "{} file(s) scanned, {} at or above {}".format(
            len(results) - len(errors), len(shown), args.min_verdict.upper()
        )
    )
    for result in shown[:50]:
        coverage = "{}/{}".format(result.coverage_ran, result.coverage_applicable)
        printer.always(
            "  {:<10} {:<7} {:<28} {}".format(
                result.verdict,
                coverage,
                os.path.basename(result.path)[:28],
                result.top_finding[:60],
            )
        )
    if len(shown) > 50:
        printer.always("  ... {} more".format(len(shown) - 50))

    for result in errors[:10]:
        printer.always("  ERROR      {}: {}".format(os.path.basename(result.path), result.error))

    for path in written:
        printer.always("  summary: {}".format(path))
