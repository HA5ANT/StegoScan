# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

StegoScan is a steganography triage tool for CTF, pentest and forensic workflows. v3 is a
Python package (`stegoscan/`) and is the canonical implementation. `stego-scan.sh` (v1)
and `stego-scan-v2.sh` (v2) remain at the repository root but are **frozen** — don't add
features to them.

The full design rationale is in `docs/specs/2026-09-21-stegoscan-v3-design.md`. Read it
before making architectural changes; the constraints below are there for stated reasons.

## Commands

```bash
python3 -m pytest                      # full suite; needs no external tools
python3 -m pytest tests/test_bulk.py   # one file
python3 -m pytest -k appended          # one topic
python3 -m stegoscan target.jpg        # run it (python3 stegoscan works too)
python3 -m stegoscan --list-analyzers  # registered analyzers and their requirements
python3 -m stegoscan t.jpg --no-external  # builtin-only: no subprocesses, deterministic
docker build -t stegoscan -f docker/Dockerfile .
```

CI (`.github/workflows/tests.yml`) runs the suite on Python 3.9–3.13, smoke-tests both
invocation forms, asserts `meme.jpg` still yields its known verdict, and fails the build
if a runtime dependency is ever added. There is no linter. Tests are the quality gate.

The Docker image has never been built in this environment — treat it as unverified until
someone runs that `docker build`.

## Non-negotiable constraints

These are design commitments, not preferences. Breaking one silently breaks the tool's
central claim.

1. **Zero third-party runtime dependencies.** `dependencies = []` in `pyproject.toml`
   must stay empty. The tool has to run in air-gapped labs and on locked-down examiner
   workstations from a bare clone. pytest is dev-only.
2. **Never write to the evidence.** Input is opened read-only and mapped `ACCESS_READ`.
   Digests are taken before analysis and re-verified after. Artifacts go to the output
   directory, never beside the target.
3. **Never let "not checked" look like "nothing found".** An analyzer that cannot run
   returns `self.skip(reason)`. Never return an empty `ok()` to represent a check that
   did not happen — that is the exact v2 bug (`|| true`) this rewrite exists to fix.
4. **Confidence must match evidence.** `CONFIRMED` means a payload was extracted and
   parsed. `LIKELY` means corroborating structure. `POSSIBLE` means a pattern matched and
   nothing else. Inflating these breaks the verdict rules downstream.

## Architecture

Data flows in one direction: `Evidence` → `ScanIndex` → analyzers → `AnalyzerResult`s →
`ScanReport` → renderers.

- `model.py` — every type the tool produces (`Finding`, `AnalyzerResult`, `Coverage`,
  `ScanReport`, and the `Severity`/`Confidence`/`Status`/`Verdict`/`Carrier` enums).
  `ScanReport` is canonical; all output is a rendering of it.
- `evidence.py` — read-only file handle, digests, carrier detection from magic bytes
  (extension is deliberately ignored: it's an assertion, not evidence).
- `scanning.py` — **one** mmap producing a `ScanIndex`: signature matches via
  `bytes.find` per signature (a regex alternation measured 56x slower — see the spec),
  plus windowed entropy. Analyzers consume this
  rather than re-reading the file. Also holds the per-format validators.
- `registry.py` — `@register` decorator; in-tree registration only. Import order in
  `analyzers/__init__.py` is report order. It cannot import the analyzers package at
  module level (circular).
- `runner.py` — per-file orchestration; catches analyzer exceptions into `ERROR` results.
- `verdict.py` — the entire scoring policy, one table. Change scoring only here.
- `bulk.py` — directory walk, process-pool fan-out, ranking. `scan_one` must stay
  top-level and picklable.
- `analyzers/builtin/` — no external tools, no third-party imports.
- `analyzers/external/` — one per binary; subclass `ExternalAnalyzer`, set `binary`, and
  route every invocation through `self.execute()` so it inherits timeout handling.

### Adding an analyzer

One file plus `@register`, then add the import to the relevant `analyzers/*/__init__.py`.
Gate it with `applies_to` when it only makes sense for certain carriers, and declare
`requires` for external binaries so the runner can skip it with an honest reason.

## Testing conventions

Fixtures are **synthesized in code** (`tests/conftest.py`) rather than committed as
binary blobs — every byte in a fixture is there for a stated reason, and CI needs no
sample corpus. External analyzers are tested through the `stub_run` fixture, which
replaces `tools.run`; never invoke a real forensics binary in a test.

When a scan produces a wrong verdict, the false positive is the bug. Fix the analyzer or
the verdict rule and add a regression test — don't relax the assertion. The three
regressions currently guarded (zsteg empty-result lines, POSSIBLE-confidence escalation,
binwalk reporting container-inherent compression) all came from exactly that situation.

`meme.jpg` at the repository root is the manual smoke-test sample.
