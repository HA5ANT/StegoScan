"""String extraction and triage of what the strings contain."""

from __future__ import annotations

import re
from typing import List

from ...model import Confidence, Severity
from ...registry import register
from ..base import Analyzer, Context, excerpt_bytes

MAX_STRINGS = 200_000

_URL = re.compile(rb"\b(?:https?|ftp|sftp|smb)://[^\s\"'<>]{4,300}")
_EMAIL = re.compile(rb"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")

# Material that is genuinely alarming inside an image or document.
_SECRETS = (
    (rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "Private key block", Severity.HIGH),
    (rb"-----BEGIN PGP MESSAGE-----", "PGP message block", Severity.MEDIUM),
    (rb"\bAKIA[0-9A-Z]{16}\b", "AWS access key id", Severity.HIGH),
    (rb"\bgh[pousr]_[A-Za-z0-9]{20,}", "GitHub token", Severity.HIGH),
    (rb"\bxox[baprs]-[A-Za-z0-9-]{10,}", "Slack token", Severity.HIGH),
    (rb"\bssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/]{40,}", "SSH public key", Severity.LOW),
    (rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}", "JWT", Severity.MEDIUM),
)


@register
class StringsAnalyzer(Analyzer):
    name = "strings"
    title = "Printable strings"

    def run(self, evidence, ctx: Context):
        if evidence.size == 0:
            return self.skip("file is empty")

        min_len = max(4, ctx.options.min_string_length)
        ascii_pattern = re.compile(b"[\\x20-\\x7e]{%d,}" % min_len)
        utf16_pattern = re.compile(b"(?:[\\x20-\\x7e]\\x00){%d,}" % min_len)

        findings: List = []
        artifacts: List[str] = []

        with evidence.map() as buf:
            ascii_strings = [m.group() for m in ascii_pattern.finditer(buf)][:MAX_STRINGS]
            utf16_strings = [
                m.group().replace(b"\x00", b"") for m in utf16_pattern.finditer(buf)
            ][:MAX_STRINGS]
            urls = sorted({m.group() for m in _URL.finditer(buf)})
            emails = sorted({m.group() for m in _EMAIL.finditer(buf)})
            secrets = [
                (label, severity, m.start(), m.group())
                for pattern, label, severity in _SECRETS
                for m in re.finditer(pattern, buf)
            ]

        all_strings = ascii_strings + utf16_strings
        if all_strings:
            artifacts.append(
                ctx.write_artifact("strings_all.txt", b"\n".join(all_strings))
            )
            preview = b"\n".join(all_strings[: ctx.options.preview_lines])
            artifacts.append(ctx.write_artifact("strings_preview.txt", preview))

        if urls:
            artifacts.append(ctx.write_artifact("strings_urls.txt", b"\n".join(urls)))
            findings.append(
                self.finding(
                    "{} URL(s) in file data".format(len(urls)),
                    Severity.LOW if len(urls) < 20 else Severity.INFO,
                    Confidence.CONFIRMED,
                    detail="Embedded links may be metadata, a payload, or a beacon.",
                    excerpt=excerpt_bytes(urls[0]),
                    artifact="strings_urls.txt",
                )
            )

        if emails:
            artifacts.append(ctx.write_artifact("strings_emails.txt", b"\n".join(emails)))
            findings.append(
                self.finding(
                    "{} email address(es) in file data".format(len(emails)),
                    Severity.INFO,
                    Confidence.CONFIRMED,
                    excerpt=excerpt_bytes(emails[0]),
                    artifact="strings_emails.txt",
                )
            )

        seen = set()
        for label, severity, offset, matched in secrets:
            if label in seen:
                continue
            seen.add(label)
            findings.append(
                self.finding(
                    "{} found in file".format(label),
                    severity,
                    Confidence.CONFIRMED,
                    detail="Credential-like material embedded in a {}.".format(evidence.carrier),
                    offset=offset,
                    excerpt=excerpt_bytes(matched, 80),
                    next_step="Extract and treat as live until proven otherwise; rotate if real.",
                )
            )

        detail = "{} ascii, {} utf-16, {} urls, {} emails".format(
            len(ascii_strings), len(utf16_strings), len(urls), len(emails)
        )
        return self.ok(findings, artifacts, detail=detail)
