# StegoScan

[![Steganography Analysis](https://img.shields.io/badge/Steganography-Analysis-blue)]()
[![Language: Python](https://img.shields.io/badge/Language-Python%203.9%2B-green)]()
[![Dependencies: none](https://img.shields.io/badge/Runtime%20deps-none-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)]()

Steganography triage for CTF, pentest and forensic workflows. Point it at a file or a
directory and it tells you what is hidden, where, and — just as importantly — **what it
was unable to check**.

```console
$ python3 -m stegoscan receipt.jpg
receipt.jpg  jpeg  8,124 bytes
CONFIRMED  coverage 10/13 — skipped: foremost (not installed), stegseek (--aggressive not set), stegdetect (not installed)
  HIGH   confirmed Appended ZIP archive after container end @0x220
  HIGH   confirmed Embedded ZIP archive @0x220
  MEDIUM likely    binwalk: End of Zip archive, footer length: 22 @0x29e
  report: stegoscan-out/receipt-20260921-014233/report.md
```

## Why the coverage line matters

Most triage tools tell you what they found. The failure mode nobody notices is the
opposite: a tool that isn't installed silently contributes nothing, and the scan looks
clean because nothing spoke up.

StegoScan treats that as a correctness bug. Every analyzer reports `ran`, `skipped
(reason)` or `error (reason)`, and **every verdict carries its coverage**. `CLEAN` at
7/13 is a different claim from `CLEAN` at 13/13, and the report never lets you confuse
the two.

## Install

There is nothing to install. StegoScan is pure Python standard library:

```bash
git clone https://github.com/HA5ANT/StegoScan.git
cd StegoScan
python3 -m stegoscan --help
```

No `pip install`, no virtualenv, no network. That is deliberate — the tool has to run in
air-gapped labs and on locked-down examiner workstations, and a program that touches
evidence should not drag in a dependency tree it cannot vouch for.

Optionally, to get a `stegoscan` command on your PATH:

```bash
pipx install .      # or: pip install --user .
```

### Optional external tools

StegoScan works entirely on its own. If these are present it uses them, and if they are
not, it says so in the coverage line:

`binwalk` · `foremost` · `steghide` · `stegseek` · `zsteg` · `stegdetect` · `exiftool`

```bash
sudo apt install binwalk foremost steghide exiftool   # Debian/Ubuntu
```

### Docker (reproducible toolchain)

These tools drift between distributions, so two examiners running "the same" scan can get
different results. The image pins all of them:

```bash
docker build -t stegoscan -f docker/Dockerfile .
docker run --rm -v "$PWD:/evidence:ro" -v "$PWD/out:/out" stegoscan /evidence/target.jpg
```

Evidence is mounted read-only; artifacts land in `/out`.

## Usage

```bash
python3 -m stegoscan target.jpg                    # scan one file
python3 -m stegoscan *.jpg                         # scan several
python3 -m stegoscan ./acquisition -r -j 8         # recursive bulk triage, 8 workers
python3 -m stegoscan target.jpg --print json       # JSON to stdout for a pipeline
python3 -m stegoscan target.jpg --no-artifacts     # analyse, write nothing to disk
python3 -m stegoscan target.jpg -p hunter2         # try a steghide password
python3 -m stegoscan target.jpg --aggressive -w rockyou.txt   # stegseek attack
python3 -m stegoscan --list-analyzers              # what runs, and what each needs
```

### Bulk triage

The question with an acquisition is not "scan everything", it is "what do I open first".

```console
$ python3 -m stegoscan ./acquisition --recursive --jobs 8
5 file(s) scanned, 5 at or above CLEAN
  CONFIRMED  10/13   receipt.jpg                  Appended ZIP archive after container end
  CONFIRMED  8/9     notes.txt                    Flag token found
  SUSPICIOUS 10/13   avatar.jpg                   Appended data after container end
  CLEAN      10/13   holiday.jpg
  CLEAN      10/11   logo.png
  summary: stegoscan-out/summary.csv
```

Results are ranked most-suspicious-first, each with its own coverage. `summary.csv` and
`summary.json` are written for import elsewhere; `--min-verdict suspicious` trims the
listing.

### Verdicts and exit codes

| Verdict | Meaning | Exit |
|---|---|---|
| `CLEAN` | Nothing above informational | 0 |
| `NOTABLE` | Low-confidence or minor signals worth a look | 10 |
| `SUSPICIOUS` | Strong indicators of concealed data | 20 |
| `CONFIRMED` | Payload extracted and validated | 30 |
| | Execution error | 1 |

`CONFIRMED` is distinct on purpose: a ZIP carved out of a JPEG tail and successfully
parsed is not a suspicion, it is a fact, and it should be escalated differently. Distinct
exit codes let CI and pipelines branch without parsing output.

## What it detects

**Without any external tool:**

- **Appended data** past a container's real end — the most common hiding place. JPEG,
  PNG, GIF, BMP, RIFF/WAV, PDF and ZIP ends are parsed *structurally*, so burying an
  `FFD9` inside your payload does not hide it the way it does from a reverse search.
- **Embedded containers** by magic bytes, each one carved and then **validated** by
  actually parsing it. Rejected candidates are kept in a log rather than dropped, so you
  can see what was dismissed and why.
- **Entropy anomalies**, read in the context of the carrier — a hot region means
  something in a BMP and nothing in a JPEG, and the report says which case applies.
- **CTF flags**, **base64 payloads** that decode to real content, **credential material**
  (private keys, cloud tokens, JWTs), URLs and metadata.
- **Extension/content mismatch** — a `.jpg` that is really a ZIP.

**With external tools:** binwalk (cross-referenced against the builtin scanner, so
corroboration is distinguished from a new lead), steghide, stegseek, zsteg, stegdetect
and exiftool.

## Evidence handling

- Input is opened read-only and mapped `ACCESS_READ`; it is never written to.
- SHA-256 and MD5 are taken before analysis and **re-verified after**, and the result is
  recorded in the report.
- Artifacts go to `stegoscan-out/`, never into the evidence directory, so a read-only
  mount or a directory you must not pollute stays untouched. `--no-artifacts` writes
  nothing at all.
- Every report carries a provenance block: tool versions, options, platform, timings.
- Output ordering is deterministic and timestamps are confined to provenance, so two
  scans of the same evidence diff cleanly.

## Output

```
stegoscan-out/<name>-<timestamp>/
  report.md              human-readable
  report.json            canonical, machine-readable
  carved/                validated embedded containers, ready to open
  appended_data.bin      anything past the container's end
  base64_decoded/        decoded payloads worth keeping
  strings_*.txt          extracted strings, URLs, emails
  tools/                 raw external tool output
  rejected_signatures.tsv  candidates that failed validation, and why
```

JSON is the canonical format; Markdown and CSV are renderers over the same object.

## Limitations

StegoScan is a **triage** tool. A clean verdict means nothing matched the checks that
ran — not that a file is free of hidden data.

- It does not brute-force LSB encodings or crack format-specific stego schemes; it points
  you at the tools that do.
- Statistical detection (`stegdetect`) is false-positive prone and is reported at low
  confidence on purpose.
- Files larger than the analysis budget have their entropy *sampled*, and the report says
  so rather than implying full coverage.

## Extending it

One file, one decorator:

```python
from stegoscan.registry import register
from stegoscan.analyzers.base import Analyzer
from stegoscan.model import Carrier, Confidence, Severity

@register
class MyAnalyzer(Analyzer):
    name = "mycheck"
    applies_to = (Carrier.PNG,)      # omit for all carriers
    requires = ()                     # external binaries, if any

    def run(self, evidence, ctx):
        if not_applicable:
            return self.skip("reason the report will show")
        return self.ok([self.finding("Title", Severity.MEDIUM, Confidence.LIKELY)])
```

Return `self.skip(reason)` rather than an empty result when you cannot check something —
that reason is what keeps the coverage line honest.

Run the tests with `python3 -m pytest`. Fixtures are synthesized in code, so no sample
corpus and no forensics binaries are needed.

## Legacy

`stego-scan.sh` (v1) and `stego-scan-v2.sh` (v2) remain in the repository and are frozen.
v3 is a clean break: the CLI, the report format and the detection logic are all new, and
no compatibility with the shell versions is maintained.

The design rationale lives in `docs/specs/2026-09-21-stegoscan-v3-design.md`.

## Contributing

Issues and PRs welcome — new analyzers, detection accuracy, false-positive reports.
A false positive is a bug; if a clean file gets a verdict above `CLEAN`, please open an
issue with the file if you can share it.

## License

MIT.
