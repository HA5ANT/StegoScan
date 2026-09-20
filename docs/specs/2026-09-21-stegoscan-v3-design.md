# StegoScan v3 — Design

Date: 2026-09-21
Status: approved, implementing
Supersedes: `stego-scan-v2.sh` (Bash, frozen)

## Problem

StegoScan v2 is a 900-line Bash script that runs external forensics tools against a file
and renders a Markdown report. It works, but four properties make it unsuitable as the
basis for further work:

1. **It cannot tell you what it did not check.** Every external tool invocation is
   wrapped in `|| true`. A missing `steghide` and a `steghide` that ran and found
   nothing produce identical output. In a forensic context that is the difference
   between "we examined this and it is clean" and "we never examined this" — a
   distinction that matters when the report is an artifact of an investigation.
2. **It re-reads the evidence once per signature.** `grep -aobF` is invoked per magic
   pattern across the whole file, so cost is O(n x signatures). Bulk triage over a
   directory of acquired images is impractical.
3. **It cannot be tested.** There is no test harness and no seam to insert one; the
   report is assembled by a single large block of string interpolation.
4. **Findings are not explainable.** A verdict of `SUSPICIOUS` is emitted without
   structured per-finding evidence (offset, matched pattern, confidence), and nothing
   is machine-readable, so the tool cannot feed a pipeline or a case-management system.

## Users and workflows

The design is driven by three concrete workflows:

- **CTF player.** One file, wants the flag fast, wants to be told what to try next.
  Optimises for: zero setup, speed, actionable next steps.
- **Forensic examiner.** Thousands of files from an acquisition, needs to know which
  ones warrant manual review, and needs the result to be defensible: reproducible,
  evidence-preserving, explicit about methodology and coverage.
- **Pentester / detection engineer.** Wants exfil detection in a pipeline: batch input,
  structured output, meaningful exit codes, no interactive prompts.

## Principles

These are load-bearing; every decision below follows from one of them.

### 1. Zero required runtime dependencies

Pure Python standard library, 3.9+. `python3 -m stegoscan target.jpg` runs from a fresh
clone with no `pip`, no virtualenv, and no network access.

This is a security decision, not a convenience one. The tool runs in air-gapped forensic
labs and on locked-down examiner workstations where installing packages is prohibited or
impossible, and on engagement boxes where you do not want to leave a dependency trail. A
tool that touches evidence should not drag in a transitive dependency graph it cannot
vouch for. Test-time dependencies (pytest) are dev-only and never required to run a scan.

### 2. Evidence is read-only and provably untouched

Input files are opened read-only and mapped with `mmap.ACCESS_READ`. SHA-256 and MD5 are
computed before analysis and re-verified after it; both digests and the verification
result are recorded in the report. Artifacts are written to an output directory, never
into the evidence directory unless explicitly requested.

### 3. Absence of evidence is not evidence of absence

Every analyzer returns one of `ran`, `skipped(reason)`, or `error(reason)`. Every verdict
is reported together with its coverage. The report states:

```
CLEAN  (coverage 7/13 — skipped: steghide not installed, zsteg not installed, ...)
```

This replaces v2's `|| true` semantics and is the single most important correctness fix
in this design. A clean verdict at 54% coverage is a materially different claim from a
clean verdict at 100% coverage, and the tool must never collapse the two.

### 4. Machine-readable first

The `ScanReport` object is canonical and serialises to JSON. Markdown and CSV are
renderers over that same object, never independently assembled. Output ordering is
deterministic (analyzers in registry order, findings by offset then severity) and
wall-clock values live only in a `provenance` block, so two scans of the same evidence
diff cleanly — which is what makes cross-acquisition comparison possible.

### 5. Every finding explains itself

A finding carries: analyzer name, severity, confidence, byte offset and length, the
matched pattern or excerpt, and a concrete next step. "Appended ZIP archive at 0x4A1C
(18972 bytes) — extract with `dd if=... skip=18972 | funzip`" is useful to both a CTF
player and a junior examiner in a way that "SUSPICIOUS" is not.

## Architecture

```
stegoscan/
  __main__.py          python -m stegoscan
  cli.py               argparse, output selection, exit codes
  model.py             enums + Finding / AnalyzerResult / ScanReport dataclasses
  evidence.py          Evidence: read-only handle, digests, size, mmap, carrier detection
  scanning.py          single-pass scanner -> ScanIndex (signature hits + entropy windows)
  registry.py          analyzer registration and applicability selection
  runner.py            per-file orchestration: select -> run -> collect -> verdict
  verdict.py           severity/confidence/coverage -> verdict, documented rules
  bulk.py              recursive walk, process-pool fan-out, ranked triage summary
  tools.py             external binary discovery, version capture, timeout-guarded exec
  analyzers/
    base.py            Analyzer protocol
    builtin/           fileinfo signatures appended entropy strings flags base64
    external/          binwalk foremost steghide stegseek zsteg stegdetect exiftool
  report/
    json_report.py     canonical
    markdown.py        human-readable
    csv_report.py      bulk triage summary
tests/                 pytest, synthesized fixtures
docker/Dockerfile      all optional tools pinned and preinstalled
```

### Single-pass scanner

`scanning.py` memory-maps the evidence once and, from that single mapping:

- locates every magic-byte signature with `bytes.find`, one pass per signature, and
- computes windowed Shannon entropy over fixed-size windows.

The resulting `ScanIndex` is consumed by the signatures, appended-data and entropy
analyzers, none of which re-read the file. This replaces v2's repeated `grep -aobF`
invocations, which spawned a process per pattern.

**Correction (measured after the first implementation).** This section originally
specified a single compiled `re` alternation of the literals, reasoning that the
signature set is small and `re` runs in C. That was wrong, and benchmarking a 161 MB
file showed why: the alternation ran at **3.5 MB/s**, because Python's regex engine
retries every alternative at every position. Looping `bytes.find` once per signature is
nominally O(n x signatures), yet measured **195 MB/s** on the same data — a **56x**
speedup — because each pass is one tuned C scan. Whole-file scan time fell from 69s to
24s.

The O(n x signatures) arithmetic only starts to matter in the hundreds of patterns; at a
few dozen literals, constant factors dominate and Aho-Corasick would add complexity for
no measured gain. That remains the place to revisit if the set grows.

No signature is a prefix of another, so per-signature scanning cannot report the same
bytes twice at one offset.

**Carve-and-validate is preserved** from v2 — it is the best idea in the existing tool.
Every signature hit is carved and re-validated against a built-in magic table before
being reported; failures are retained in a separate false-positive list rather than
discarded, so the report can show what was rejected and why. Validation uses the built-in
table rather than `file(1)` so it still works under Principle 1.

### Analyzer contract

```python
class Analyzer(Protocol):
    name: str
    applies_to: tuple[Carrier, ...]   # or ANY
    requires: tuple[str, ...]         # external binaries; empty for builtins
    def run(self, evidence: Evidence, ctx: Context) -> AnalyzerResult: ...
```

The registry selects analyzers by carrier format and binary availability. Adding a
detection technique is one new file plus a decorator, with no edit to the core. This is
deliberately *not* an entry-point plugin framework: in-tree registration gives the
extensibility that is actually needed without the versioning and trust surface of
third-party plugin loading.

### Verdict and exit codes

| Verdict     | Meaning                                                        | Exit |
|-------------|----------------------------------------------------------------|------|
| `CLEAN`     | Nothing above informational found                                | 0    |
| `NOTABLE`   | Low-severity or low-confidence signals worth a look             | 10   |
| `SUSPICIOUS`| Strong indicators of embedded or concealed data                 | 20   |
| `CONFIRMED` | Embedded payload extracted and validated                        | 30   |
|             | Execution error                                                  | 1    |

`CONFIRMED` is new in v3 and earns its place: a valid ZIP carved out of a JPEG tail and
verified is not a suspicion, it is a fact, and an examiner escalates on it differently.
Distinct exit codes let CI and pipelines branch on outcome without parsing output.

Every verdict is always accompanied by coverage (Principle 3). The scoring rules live in
`verdict.py` as a single documented table so they can be reviewed and tested rather than
being scattered through the analyzers.

### Bulk triage

`bulk.py` walks a directory (optionally recursive), fans work out across a
`ProcessPoolExecutor` at file granularity (`--jobs`), and emits a summary ranked
most-suspicious-first as JSON and CSV, with progress on stderr. Parallelism is at the
file level only — one level, where the volume actually is.

This serves the "ten thousand images off an acquisition, tell me where to start"
workflow that v2's flat `for f in dir/*` loop does not.

## Testing

pytest, with fixtures **synthesized in code** rather than committed as binary blobs:
a JPEG with an appended ZIP, a PNG with trailing data, a file containing `FLAG{...}`,
a high-entropy region, and a benign control. CI therefore needs no sample corpus and no
external forensics tools.

Coverage targets:

- per-analyzer unit tests against the synthesized carriers
- scanner offset correctness (hits land on exact byte offsets)
- the verdict rule table, exhaustively
- JSON report schema, via a golden file
- **evidence integrity**: digests identical before and after a full scan (Principle 2)
- external analyzers tested through a stubbed tool runner, so absence of `binwalk` et al.
  never fails the suite

`meme.jpg` is retained as the human smoke test.

## Distribution

- **Native**: clone and run. No install step required (Principle 1).
- **Docker**: `docker/Dockerfile` builds a Debian-slim image with binwalk, foremost,
  steghide, stegseek, zsteg, stegdetect and exiftool pinned and preinstalled, entrypoint
  `stegoscan`. This resolves the "external tool version drift between machines" risk
  recorded in the v2 notes, giving reproducible results across engagements.

Native execution remains fully supported and honestly reports which tools it skipped.

## Relationship to v2

`stego-scan-v2.sh` and `stego-scan.sh` remain in the repository root, unmodified and
frozen. They are documented as legacy; v3 is the canonical implementation. No CLI or
report-format compatibility is maintained — a clean break was explicitly chosen so the
output model could be redesigned around structured findings.

## Explicitly not in scope

Recorded so the exclusions are deliberate rather than forgotten:

- web UI, REST API, or daemon mode
- case-management database or evidence-chain storage
- machine-learning classification of stego carriers
- HTML report output
- entry-point-based third-party plugin discovery
- LSB brute-forcing and format-specific stego cracking (dedicated tools do this better;
  StegoScan's job is triage and pointing you at them)

## Implementation phases

1. Core engine, builtin analyzers, JSON + Markdown reports, test suite. Usable standalone.
2. External tool analyzers, discovery, version capture, timeouts.
3. Bulk triage: recursive walk, parallelism, ranked summary.
4. Docker image, README rewrite, CLAUDE.md update.
