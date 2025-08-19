# StegoScan — Automated Steganography Triage (Early/Primitive)

[![Steganography Analysis](https://img.shields.io/badge/Steganography-Analysis-blue)]()
[![Language: Bash](https://img.shields.io/badge/Language-Bash-green)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)]()
[![Beginner Friendly](https://img.shields.io/badge/Level-Beginner-ff69b4)]()
[![Help Wanted](https://img.shields.io/badge/Help-Wanted-red)]()

> Status: This tool is very primitive and still evolving. It works as a quick triage helper, not a full solution. Expect missing checks, rough edges, and false positives. Contributions and feedback are welcome while we build toward the intended version.

StegoScan is a single Bash script that automates basic steganography triage on a target file and writes:
- a concise Markdown report next to the target, and
- a timestamped folder of raw artifacts (logs, extracted chunks, tool outputs).

Perfect for quick passes in CTFs and training labs, especially when setting up many tools manually is time‑consuming.

## Features (current)
- Basic file info and checksums
- Strings analysis (preview, base64-like tokens, simple URL/email patterns)
- Optional metadata and image details (exiftool, ImageMagick `identify`)
- Optional carving and scans (binwalk, foremost)
- Optional stego checks (steghide, stegseek, zsteg, stegdetect)
- Common binary signature extraction (png/jpg/zip/pdf/rar/gzip/7z/exe/elf)
- One Markdown report with quick counts and excerpts

## Limitations (important)
- Primitive heuristics; results are not exhaustive or authoritative
- Text signatures can be noisy; binary magic is prioritized
- Some tools are Linux-first; best experience is under Linux/WSL
- Report is concise by design; deep manual analysis is still required

## Dependencies
- Required (POSIX-ish): `bash`, `file`, `strings`, `dd`, `grep`, `awk`, `sed`, `head`, `tail`
- Also used (usually present): `sha256sum`, `md5sum`, `find`, `wc`, `date`, `cat`, `mkdir`
- Optional (recommended for better results):
  - `exiftool`, `binwalk`, `foremost`, `steghide`, `stegseek`, `ent`, `identify` (ImageMagick), `zsteg`, `stegdetect`

Tip: Install via your distro package manager (e.g., Ubuntu `apt`). Some tools may require extra repos or building from source depending on your platform.

## Installation
The project is a single script, no build required.

Linux/macOS:
```bash
git clone https://github.com/yourusername/StegoScan.git
cd StegoScan
chmod +x stego-scan.sh
```

Windows (recommended via WSL):
- Enable WSL and install Ubuntu from Microsoft Store
- Clone the repo inside WSL and run using Bash as above
- Optional tools like `binwalk`, `steghide`, `stegseek` are easier to install on WSL than native Windows

## Quick start
Basic scan:
```bash
./stego-scan.sh /path/to/target.jpg
```
Try an explicit password for steghide:
```bash
./stego-scan.sh -p secret /path/to/target.jpg
```
Aggressive stegseek with a wordlist:
```bash
./stego-scan.sh --aggressive -w /path/to/wordlist.txt /path/to/target.jpg
```
Quiet mode (minimal terminal output):
```bash
./stego-scan.sh -q /path/to/target.jpg
```

## Options
- -p, --password <pw>: Try provided password with steghide (non-interactive)
- -w, --wordlist <f>: Wordlist for --aggressive (stegseek)
- --aggressive: Run stegseek with provided wordlist
- --no-steghide: Skip steghide checks entirely
- --extract-size <n>: Bytes to extract at detected signatures (default 524288)
- --preview-lines <n>: Lines to show in strings preview (default 30)
- --debug: Print debug lines to the process log; more verbose commands
- -q, --quiet: Minimal terminal output
- -h, --help: Show usage

## Output
Given an input like `.../meme.jpg`, the script creates:
- Report: `.../meme_report.md`
- Artifacts folder: `.../extracted_meme_YYYYMMDD_HHMMSS/`
  - `file.txt`, `ls.txt`, `sha256.txt`, `md5.txt`
  - `exiftool.txt`, `identify.txt` (if tools installed)
  - `binwalk_scan.txt`, `binwalk_extracted/` (if installed)
  - `foremost/` (if installed)
  - `strings_all.txt`, `strings_preview.txt`, `strings_base64.txt`, `strings_urls.txt`, `strings_emails.txt`
  - `ent.txt` (if installed)
  - `signature_hits/` with extracted chunks near detected magic bytes
  - `steghide/`, `stegseek/`, `zsteg.txt`, `stegdetect.txt` when relevant

## Roadmap (help wanted)
- Improve detection accuracy and reduce noise
- Add format-specific analyzers (PNG color planes, JPG stego variants, audio/image LSB helpers)
- Directory mode and output directory override
- Smarter base64 detection and auto-decode previews
- Cross-platform guidance and installers for optional tools
- Better tests and sample files

## Contributing
This project is early and needs guidance. PRs/issues are welcome:
- New analyzers or integrations
- Bug fixes and edge-case handling
- Docs and examples

## License
MIT. See `LICENSE` once added.

## A note from the author
I'm a cybersecurity beginner who built this to speed up learning and CTF triage. The tool is still primitive and far from the intended version—your feedback and contributions can shape it into something truly useful. Thank you for trying it out! 
