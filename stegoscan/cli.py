"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import registry
from .analyzers.base import Options
from .evidence import EvidenceError
from .model import EXIT_ERROR, ScanReport, Severity, Status, Verdict
from .report import json_report, markdown
from .runner import VERSION, scan_file

_COLORS = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "red": "\033[0;31m",
    "yellow": "\033[0;33m",
    "green": "\033[0;32m",
    "cyan": "\033[0;36m",
    "bold": "\033[1m",
}

_VERDICT_COLOR = {
    Verdict.CLEAN: "green",
    Verdict.NOTABLE: "cyan",
    Verdict.SUSPICIOUS: "yellow",
    Verdict.CONFIRMED: "red",
}

_SEVERITY_COLOR = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
}


class Printer:
    def __init__(self, stream, quiet: bool = False, color: Optional[bool] = None):
        self.stream = stream
        self.quiet = quiet
        if color is None:
            color = stream.isatty() and os.environ.get("NO_COLOR") is None
        self.color = color

    def paint(self, text: str, name: str) -> str:
        if not self.color:
            return text
        return "{}{}{}".format(_COLORS.get(name, ""), text, _COLORS["reset"])

    def line(self, text: str = "") -> None:
        if not self.quiet:
            print(text, file=self.stream)

    def always(self, text: str = "") -> None:
        print(text, file=self.stream)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegoscan",
        description=(
            "Steganography triage for CTF, pentest and forensic workflows. "
            "Reports what it checked as well as what it found."
        ),
        epilog=(
            "Exit codes: 0 clean, 10 notable, 20 suspicious, 30 confirmed, 1 error. "
            "A clean verdict only covers the analyzers that actually ran."
        ),
    )
    parser.add_argument("targets", nargs="*", metavar="TARGET", help="files or directories to examine")

    output = parser.add_argument_group("output")
    output.add_argument("-o", "--output", metavar="DIR", help="artifact directory for a single target")
    output.add_argument(
        "--output-base",
        metavar="DIR",
        default="stegoscan-out",
        help="parent directory for generated artifact directories (default: stegoscan-out)",
    )
    output.add_argument(
        "-f",
        "--format",
        choices=("markdown", "json", "both", "none"),
        default="both",
        help="report files to write (default: both)",
    )
    output.add_argument(
        "--print",
        dest="print_format",
        choices=("summary", "markdown", "json", "none"),
        default="summary",
        help="what to write to stdout (default: summary)",
    )
    output.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    output.add_argument(
        "--no-artifacts",
        action="store_true",
        help="analyse without writing anything to disk",
    )
    output.add_argument("--no-color", action="store_true", help="disable coloured output")

    tuning = parser.add_argument_group("analysis tuning")
    tuning.add_argument(
        "--extract-size",
        type=int,
        default=512 * 1024,
        metavar="N",
        help="bytes carved at each signature hit (default: 524288)",
    )
    tuning.add_argument(
        "--entropy-threshold",
        type=float,
        default=7.5,
        metavar="F",
        help="bits/byte above which a region is called high-entropy (default: 7.5)",
    )
    tuning.add_argument(
        "--min-string-length", type=int, default=6, metavar="N", help="shortest string to extract"
    )
    tuning.add_argument(
        "--preview-lines", type=int, default=40, metavar="N", help="lines kept in the strings preview"
    )
    tuning.add_argument(
        "--timeout", type=int, default=300, metavar="S", help="per-tool timeout in seconds"
    )

    external = parser.add_argument_group("external tools")
    external.add_argument("-p", "--password", metavar="PW", help="password to try with steghide")
    external.add_argument("-w", "--wordlist", metavar="FILE", help="wordlist for stegseek")
    external.add_argument(
        "--aggressive",
        action="store_true",
        help="run brute-force attacks (stegseek with the given wordlist)",
    )

    bulk = parser.add_argument_group("bulk triage")
    bulk.add_argument("-r", "--recursive", action="store_true", help="descend into subdirectories")
    bulk.add_argument(
        "-j", "--jobs", type=int, default=0, metavar="N", help="parallel workers (default: CPU count)"
    )
    bulk.add_argument(
        "--min-verdict",
        choices=("clean", "notable", "suspicious", "confirmed"),
        default="clean",
        help="only list results at or above this verdict in the summary",
    )

    parser.add_argument("--list-analyzers", action="store_true", help="list analyzers and exit")
    parser.add_argument("--version", action="version", version="stegoscan {}".format(VERSION))
    return parser


def options_from_args(args: argparse.Namespace) -> Options:
    return Options(
        extract_size=max(512, args.extract_size),
        preview_lines=max(1, args.preview_lines),
        min_string_length=max(4, args.min_string_length),
        timeout=max(1, args.timeout),
        password=args.password,
        wordlist=args.wordlist,
        aggressive=args.aggressive,
        entropy_threshold=args.entropy_threshold,
        write_artifacts=not args.no_artifacts,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Results go to stdout so they can be piped or redirected; progress and
    # diagnostics go to stderr.
    printer = Printer(sys.stdout, quiet=args.quiet, color=False if args.no_color else None)

    if args.list_analyzers:
        _print_analyzers()
        return 0
    if not args.targets:
        parser.print_usage(sys.stderr)
        print("stegoscan: at least one TARGET is required", file=sys.stderr)
        return EXIT_ERROR

    options = options_from_args(args)
    worst = Verdict.CLEAN
    failed = False

    for target in args.targets:
        if os.path.isdir(target):
            from .bulk import run_bulk  # imported lazily: only bulk runs need a process pool

            code, verdict = run_bulk(target, args, options, printer)
            if code == EXIT_ERROR:
                failed = True
            elif verdict is not None and verdict.rank > worst.rank:
                worst = verdict
            continue

        try:
            report = scan_file(
                target,
                options=options,
                output_dir=args.output if len(args.targets) == 1 else None,
                output_base=args.output_base,
            )
        except EvidenceError as exc:
            print("stegoscan: {}".format(exc), file=sys.stderr)
            failed = True
            continue

        _emit(report, args, printer)
        if report.verdict.rank > worst.rank:
            worst = report.verdict

    if failed:
        return EXIT_ERROR
    return worst.exit_code


def _emit(report: ScanReport, args: argparse.Namespace, printer: Printer) -> None:
    written = _write_reports(report, args)

    if args.print_format == "json":
        print(json_report.render(report))
    elif args.print_format == "markdown":
        print(markdown.render(report))
    elif args.print_format == "summary":
        _print_summary(report, printer, written)


def _write_reports(report: ScanReport, args: argparse.Namespace) -> List[str]:
    if args.no_artifacts or args.format == "none" or not report.output_dir:
        return []
    os.makedirs(report.output_dir, exist_ok=True)
    written = []
    if args.format in ("markdown", "both"):
        path = os.path.join(report.output_dir, "report.md")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(markdown.render(report))
        written.append(path)
    if args.format in ("json", "both"):
        path = os.path.join(report.output_dir, "report.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json_report.render(report))
        written.append(path)
    return written


def _print_summary(report: ScanReport, printer: Printer, written: List[str]) -> None:
    name = os.path.basename(report.target)
    printer.always(
        "{}  {}  {:,} bytes".format(
            printer.paint(name, "bold"), report.carrier, report.integrity.size
        )
    )
    printer.always(
        "{}  {}".format(
            printer.paint(str(report.verdict), _VERDICT_COLOR[report.verdict]),
            printer.paint(report.coverage.summary(), "dim"),
        )
    )

    shown = [f for f in report.findings if f.severity > Severity.INFO]
    for finding in shown[:12]:
        location = " @{}".format(hex(finding.offset)) if finding.offset is not None else ""
        printer.always(
            "  {:<6} {:<9} {}{}".format(
                printer.paint(str(finding.severity), _SEVERITY_COLOR[finding.severity]),
                str(finding.confidence).lower(),
                finding.title,
                printer.paint(location, "dim"),
            )
        )
    if len(shown) > 12:
        printer.always(printer.paint("  ... {} more".format(len(shown) - 12), "dim"))
    if not shown:
        printer.always(printer.paint("  no findings above informational", "dim"))

    if not report.integrity.verified_unchanged:
        printer.always(
            printer.paint("  WARNING: evidence digests changed during the scan", "red")
        )

    for path in written:
        printer.always(printer.paint("  report: {}".format(path), "dim"))


def _print_analyzers() -> None:
    print("{:<14} {:<34} {}".format("NAME", "CARRIERS", "REQUIRES"))
    for analyzer in registry.all_analyzers():
        carriers = ", ".join(str(c) for c in analyzer.applies_to) if analyzer.applies_to else "any"
        requires = ", ".join(analyzer.requires) if analyzer.requires else "-"
        print("{:<14} {:<34} {}".format(analyzer.name, carriers[:34], requires))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
