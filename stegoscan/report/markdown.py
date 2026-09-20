"""Human-readable rendering of a scan report."""

from __future__ import annotations

from typing import List

from ..model import ScanReport, Status

_STATUS_MARK = {Status.RAN: "ran", Status.SKIPPED: "skipped", Status.ERROR: "error"}


def render(report: ScanReport) -> str:
    lines: List[str] = []
    add = lines.append

    add("# StegoScan report — {}".format(_basename(report.target)))
    add("")
    add("**{}**".format(report.headline()))
    add("")

    if not report.coverage.is_complete:
        add(
            "> Coverage is incomplete. Analyzers that did not run cannot support a "
            "conclusion either way; see the Coverage table below."
        )
        add("")

    add("| | |")
    add("|---|---|")
    add("| Target | `{}` |".format(report.target))
    add("| Carrier | {} |".format(report.carrier))
    add("| Size | {:,} bytes |".format(report.integrity.size))
    add("| SHA-256 | `{}` |".format(report.integrity.sha256))
    add("| MD5 | `{}` |".format(report.integrity.md5))
    add(
        "| Evidence unchanged | {} |".format(
            "yes" if report.integrity.verified_unchanged else "**NO — digests differ after scan**"
        )
    )
    if report.output_dir:
        add("| Artifacts | `{}` |".format(report.output_dir))
    add("")

    findings = report.findings
    add("## Findings ({})".format(len(findings)))
    add("")
    if not findings:
        add("No findings.")
        add("")
    for number, finding in enumerate(findings, start=1):
        add(
            "### {}. {} · {} — {}".format(
                number, finding.severity, finding.confidence, finding.title
            )
        )
        add("")
        if finding.detail:
            add(finding.detail)
            add("")
        bullets = []
        if finding.offset is not None:
            location = "offset `{}` ({})".format(hex(finding.offset), finding.offset)
            if finding.length:
                location += ", length {:,} bytes".format(finding.length)
            bullets.append("Location: {}".format(location))
        if finding.excerpt:
            bullets.append("Excerpt: `{}`".format(finding.excerpt))
        if finding.artifact:
            bullets.append("Artifact: `{}`".format(finding.artifact))
        if finding.next_step:
            bullets.append("Next step: `{}`".format(finding.next_step))
        bullets.append("Reported by: `{}`".format(finding.analyzer))
        for bullet in bullets:
            add("- {}".format(bullet))
        add("")

    add("## Coverage")
    add("")
    add("| Analyzer | Status | Detail | ms |")
    add("|---|---|---|---|")
    for result in report.results:
        detail = result.detail if result.status is Status.RAN else result.reason
        add(
            "| `{}` | {} | {} | {} |".format(
                result.analyzer, _STATUS_MARK[result.status], detail or "-", result.duration_ms
            )
        )
    add("")

    provenance = report.provenance
    if provenance:
        add("## Provenance")
        add("")
        add("| | |")
        add("|---|---|")
        add("| StegoScan | {} |".format(provenance.get("stegoscan_version", "?")))
        add("| Started (UTC) | {} |".format(provenance.get("started_utc", "?")))
        add("| Duration | {} ms |".format(provenance.get("duration_ms", "?")))
        add("| Python | {} |".format(provenance.get("python", "?")))
        add("| Platform | {} |".format(provenance.get("platform", "?")))
        add("| Command | `{}` |".format(provenance.get("command", "?")))
        add("")
        external = provenance.get("external_tools") or {}
        if external:
            add("### External tools")
            add("")
            add("| Tool | Path | Version |")
            add("|---|---|---|")
            for name, info in sorted(external.items()):
                path = info.get("path") or "_not installed_"
                add("| `{}` | {} | {} |".format(name, path, info.get("version") or "-"))
            add("")

    add("---")
    add("")
    add(
        "StegoScan is a triage tool. A clean verdict means nothing matched the "
        "checks that ran, not that the file is free of hidden data."
    )
    add("")
    return "\n".join(lines)


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
