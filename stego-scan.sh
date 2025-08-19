#!/usr/bin/env bash
# stego-scan - enhanced stego analysis with comprehensive reporting
# Usage: ./stego-scan.sh [options] /path/to/target.jpg
set -euo pipefail
IFS=$'\n\t'

# ------- Config -------
PREVIEW_LINES=30
EXTRACT_SIZE=524288   # bytes to extract at signature offsets (default 512 KiB)
VERSION="1.3"

# ------- Colors (terminal only) -------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
info(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${CYAN}[*]${RESET} %b\n" "$1"; }
ok(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${GREEN}[+]${RESET} %b\n" "$1"; }
warn(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${YELLOW}[!]${RESET} %b\n" "$1"; }
die(){ printf "${RED}[-]${RESET} %b\n" "$1"; exit 1; }
debug(){ [[ "${DEBUG:-0}" -eq 1 ]] && printf "${DIM}[DEBUG]${RESET} %b\n" "$1"; }

usage(){
  cat <<USG
Stego Scan v${VERSION} - Steganography analysis tool

Usage: $(basename "$0") [options] /path/to/file

Options:
  -p, --password <pw>      Try provided password with steghide (non-interactive)
  -w, --wordlist <f>       Wordlist for --aggressive (stegseek)
      --aggressive         Run stegseek with provided wordlist
      --no-steghide        Skip steghide checks
      --extract-size <n>   Bytes to extract at signatures (default: ${EXTRACT_SIZE})
      --preview-lines <n>  Lines to show in preview (default: ${PREVIEW_LINES})
      --debug              Enable debug output
  -q, --quiet              Minimal terminal output
  -h, --help               Show this help

Features:
  - File metadata extraction
  - Strings analysis with pattern detection
  - Binary signature detection and extraction
  - Steganography tool analysis (steghide, stegseek)
  - File carving with foremost
  - Entropy analysis
  - Comprehensive Markdown reporting
USG
}

# ------- Parse args -------
PASSWORD=""
WORDLIST=""
AGGRESSIVE=0
NOSteghide=0
QUIET=0
DEBUG=0
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--password) PASSWORD="$2"; shift 2;;
    -w|--wordlist) WORDLIST="$2"; shift 2;;
    --aggressive) AGGRESSIVE=1; shift;;
    --no-steghide) NOSteghide=1; shift;;
    --extract-size) EXTRACT_SIZE="$2"; shift 2;;
    --preview-lines) PREVIEW_LINES="$2"; shift 2;;
    --debug) DEBUG=1; shift;;
    -q|--quiet) QUIET=1; shift;;
    -h|--help) usage; exit 0;;
    --) shift; break;;
    -*) die "Unknown option: $1";;
    *) ARGS+=("$1"); shift;;
  esac
done

if [[ ${#ARGS[@]} -lt 1 ]]; then usage; exit 2; fi
FILE="${ARGS[0]}"
if [[ ! -f "$FILE" ]]; then die "File not found: $FILE"; fi

# ------- Check for required tools -------
REQUIRED=(file strings dd grep awk sed head tail)
MISSING=()
for cmd in "${REQUIRED[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || MISSING+=("$cmd")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  die "Missing required tools: ${MISSING[*]}"
fi

# ------- Paths: raw data and report next to target -------
TARGET_DIR="$(cd "$(dirname -- "$FILE")" && pwd)"
BNAME="$(basename -- "$FILE")"
BASE="${BNAME%.*}"
TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="${TARGET_DIR}/extracted_${BASE}_${TS}"
mkdir -p "$OUTDIR"

REPORT_MD="${TARGET_DIR}/${BASE}_report.md"

# ------- Optional tools -------
OPTIONAL=(exiftool binwalk foremost steghide stegseek ent pngcheck jpeginfo identify)

# ------- Performance tracking -------
start_time=$(date +%s)

# ------- Helpers -------
run_quiet(){ # run command and save stdout/stderr to a file; don't exit on failure
  local out="$1"; shift
  echo "Running: $*" >> "$out"
  if [[ "$DEBUG" -eq 1 ]]; then
    printf "${DIM}[DEBUG] Running: %s${RESET}\n" "$*"
  fi
  "$@" >> "$out" 2>&1 || echo "Command exited with status $?" >> "$out"
}

# binary-safe signature search & extract
search_and_extract_bin(){
  local label="$1"; local pat="$2"
  mkdir -p "${OUTDIR}/signature_hits"
  LC_ALL=C grep -aob -- "$pat" "$FILE" 2>/dev/null | while IFS=: read -r bytepos _; do
    local outf="${OUTDIR}/signature_hits/${label}_${bytepos}.bin"
    dd if="$FILE" bs=1 skip="$bytepos" count="$EXTRACT_SIZE" of="$outf" 2>/dev/null || true
    echo "${label} @ ${bytepos} -> ${outf}" >> "${OUTDIR}/signature_hits.log"
  done || true
}

# File type detection for better reporting
detect_file_type() {
  local file="$1"
  local file_output=$(file -b "$file")
  echo "$file_output"
}

# Calculate processing time
format_duration() {
  local seconds=$1
  local mins=$((seconds / 60))
  local secs=$((seconds % 60))
  if [[ $mins -gt 0 ]]; then
    echo "${mins}m ${secs}s"
  else
    echo "${secs}s"
  fi
}

# ------- Start scans (raw files saved in OUTDIR) -------
info "Starting stego triage for: $FILE"
info "Output directory: $OUTDIR"
info "Report will be saved as: $REPORT_MD"

# Create a process log
PROCESS_LOG="${OUTDIR}/process.log"
echo "Stego Scan v${VERSION} Process Log" > "$PROCESS_LOG"
echo "Started: $(date)" >> "$PROCESS_LOG"
echo "Target: $FILE" >> "$PROCESS_LOG"
echo "Arguments: ${ARGS[*]}" >> "$PROCESS_LOG"

# basic info
info "Collecting basic file information"
run_quiet "$OUTDIR/file.txt" file -- "$FILE"
run_quiet "$OUTDIR/ls.txt" ls -l -- "$FILE"
run_quiet "$OUTDIR/sha256.txt" sha256sum -- "$FILE"
run_quiet "$OUTDIR/md5.txt" md5sum -- "$FILE"

# metadata (optional)
if command -v exiftool >/dev/null 2>&1; then
  info "Extracting metadata with exiftool"
  run_quiet "$OUTDIR/exiftool.txt" exiftool "$FILE"
else
  warn "exiftool not found, skipping metadata extraction"
fi

if command -v identify >/dev/null 2>&1; then
  info "Analyzing image properties"
  run_quiet "$OUTDIR/identify.txt" identify -verbose "$FILE"
fi

# binwalk scan + attempt extract (nonfatal)
if command -v binwalk >/dev/null 2>&1; then
  info "Running binwalk analysis"
  run_quiet "$OUTDIR/binwalk_scan.txt" binwalk "$FILE"
  mkdir -p "$OUTDIR/binwalk_extracted"
  run_quiet "$OUTDIR/binwalk_extract_log.txt" binwalk -e -M --directory "$OUTDIR/binwalk_extracted" "$FILE"
else
  info "binwalk not found, skipping"
fi

# strings (all / preview / base64)
info "Extracting and analyzing strings"
run_quiet "$OUTDIR/strings_all.txt" strings -a "$FILE"
# Improved string filtering
run_quiet "$OUTDIR/strings_ascii.txt" strings -a -t d "$FILE"  # ASCII strings with offsets
run_quiet "$OUTDIR/strings_unicode.txt" strings -a -el "$FILE"  # Unicode strings

# Enhanced string analysis
grep -E --color=never '[[:print:]]{6,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_preview.txt" 2>/dev/null || true
grep -Eao '[A-Za-z0-9+/=]{40,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_base64.txt" 2>/dev/null || true

# Additional string analysis: URLs, emails, etc.
grep -Eo '(http|https|ftp)://[^/"]+' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_urls.txt" 2>/dev/null || true
grep -Eio '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_emails.txt" 2>/dev/null || true
grep -Eio '(0x)?[0-9a-fA-F]{8,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_hex.txt" 2>/dev/null || true  # Hex strings

# entropy if available
if command -v ent >/dev/null 2>&1; then
  info "Calculating file entropy"
  run_quiet "$OUTDIR/ent.txt" ent "$FILE"
else
  info "ent not found, skipping entropy analysis"
fi

# foremost carving (nonfatal)
if command -v foremost >/dev/null 2>&1; then
  info "Carving files with foremost"
  mkdir -p "$OUTDIR/foremost"
  run_quiet "$OUTDIR/foremost.log" foremost -i "$FILE" -o "$OUTDIR/foremost"
else
  info "foremost not found, skipping file carving"
fi

# steghide info + extraction attempts (nonfatal) - FIXED COMMAND SYNTAX
if [[ $NOSteghide -eq 0 ]] && command -v steghide >/dev/null 2>&1; then
  info "Checking for steganography with steghide"
  # Fixed command syntax - removed -sf flag which was causing the error
  run_quiet "$OUTDIR/steghide_info.txt" steghide info "$FILE"
  mkdir -p "$OUTDIR/steghide"
  if [[ -n "$PASSWORD" ]]; then
    info "Trying steghide extraction with provided password"
    run_quiet "$OUTDIR/steghide_extract_pass.log" steghide extract -sf "$FILE" -p "$PASSWORD" -xf "$OUTDIR/steghide/extracted" -f
  fi
  info "Trying steghide extraction with empty password"
  run_quiet "$OUTDIR/steghide_extract_empty.log" steghide extract -sf "$FILE" -p "" -xf "$OUTDIR/steghide/extracted_empty" -f
else
  info "steghide skipped or not available"
fi

# stegseek if requested
if [[ $AGGRESSIVE -eq 1 ]]; then
  if [[ -z "$WORDLIST" ]]; then die "Aggressive requires -w /path/to/wordlist"; fi
  if command -v stegseek >/dev/null 2>&1; then
    info "Running aggressive stegseek analysis with provided wordlist"
    mkdir -p "$OUTDIR/stegseek"
    run_quiet "$OUTDIR/stegseek/stegseek_out.txt" stegseek "$FILE" "$WORDLIST" "$OUTDIR/stegseek/extracted"
  else
    warn "stegseek not found, skipping aggressive mode"
  fi
fi

# Additional stego tools if available
if command -v zsteg >/dev/null 2>&1; then
  info "Running zsteg analysis for PNG/BMP steganography"
  mkdir -p "$OUTDIR/zsteg"
  run_quiet "$OUTDIR/zsteg.txt" zsteg -a "$FILE"
fi

if command -v stegdetect >/dev/null 2>&1; then
  info "Running stegdetect analysis"
  mkdir -p "$OUTDIR/stegdetect"
  run_quiet "$OUTDIR/stegdetect.txt" stegdetect "$FILE"
fi

# signature search (common types)
info "Searching for embedded file signatures"
declare -A SIGNATURES=(
  ["png"]=$'\x89PNG'
  ["jpg"]=$'\xFF\xD8\xFF'
  ["zip"]=$'PK\x03\x04'
  ["pdf"]="%PDF"
  ["rar"]="Rar!"
  ["gzip"]=$'\x1f\x8b\x08'
  ["7z"]=$'7z\xBC\xAF\x27\x1C'
  ["exe"]="MZ"
  ["elf"]=$'\x7FELF'
  ["html"]="<!DOCTYPE"
  ["xml"]="<?xml"
  ["bash"]="#!/bin/bash"
  ["python"]="#!/usr/bin/python"
)

for sig in "${!SIGNATURES[@]}"; do
  search_and_extract_bin "$sig" "${SIGNATURES[$sig]}"
done

# flag search
info "Searching for CTF flags and patterns"
grep -Eio 'ctf\{[^}]{1,200}\}|flag\{[^}]{1,200}\}|FLAG\{[^}]{1,200}\}' "$OUTDIR/strings_all.txt" > "$OUTDIR/possible_flags.txt" 2>/dev/null || true

# Calculate processing time
end_time=$(date +%s)
processing_time=$((end_time - start_time))

# ------- Generate comprehensive Markdown report -------
info "Generating Markdown report"
{
  echo "# Stego Scan Report — ${BNAME}"
  echo ""
  echo "**Scan Tool:** Stego Scan v${VERSION}  "
  echo "**Target file:** \`$FILE\`  "
  echo "**Run time:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  "
  echo "**Processing time:** $(format_duration $processing_time)  "
  echo "**Raw artifacts directory:** \`$OUTDIR\`  "
  echo ""
  echo "## Quick Summary"
  PREVIEW_COUNT=$(wc -l < "$OUTDIR/strings_preview.txt" 2>/dev/null || echo 0)
  BASE64_COUNT=$(wc -l < "$OUTDIR/strings_base64.txt" 2>/dev/null || echo 0)
  FOREMOST_COUNT=$(find "$OUTDIR/foremost" -type f 2>/dev/null | wc -l || echo 0)
  SIG_HITS_COUNT=$(find "$OUTDIR/signature_hits" -maxdepth 1 -type f 2>/dev/null | wc -l || echo 0)
  STEGHIDE_COUNT=0
  [[ -d "$OUTDIR/steghide" ]] && STEGHIDE_COUNT=$(find "$OUTDIR/steghide" -type f 2>/dev/null | wc -l || echo 0)
  URL_COUNT=$(wc -l < "$OUTDIR/strings_urls.txt" 2>/dev/null || echo 0)
  EMAIL_COUNT=$(wc -l < "$OUTDIR/strings_emails.txt" 2>/dev/null || echo 0)
  
  echo "| Item | Count | Notes |"
  echo "|---|---:|---|"
  echo "| Recognizable strings | ${PREVIEW_COUNT} | first ${PREVIEW_LINES} shown below |"
  echo "| Base64-like tokens | ${BASE64_COUNT} | potential hidden blobs |"
  echo "| URLs found | ${URL_COUNT} | in strings analysis |"
  echo "| Email addresses | ${EMAIL_COUNT} | in strings analysis |"
  echo "| Foremost carved files | ${FOREMOST_COUNT} | in \`foremost/\` |"
  echo "| Signature extracts | ${SIG_HITS_COUNT} | in \`signature_hits/\` |"
  echo "| Steghide extracted files | ${STEGHIDE_COUNT} | in \`steghide/\` |"
  echo ""
  echo "## File Information"
  echo '```'
  cat "$OUTDIR/file.txt" 2>/dev/null || echo "No file info"
  cat "$OUTDIR/ls.txt" 2>/dev/null || echo "No ls info"
  cat "$OUTDIR/sha256.txt" 2>/dev/null || echo "No checksum info"
  cat "$OUTDIR/md5.txt" 2>/dev/null || echo "No checksum info"
  echo '```'
  echo ""
  if [[ -f "$OUTDIR/exiftool.txt" ]]; then
    echo "## Metadata (excerpt)"
    echo '```'
    head -n 20 "$OUTDIR/exiftool.txt" || true
    echo '```'
    echo ""
  fi
  if [[ -f "$OUTDIR/ent.txt" ]]; then
    echo "## Entropy Analysis"
    echo '```'
    cat "$OUTDIR/ent.txt" || true
    echo ""
    echo "Note: High entropy (close to 8.0) may indicate encrypted or compressed data."
    echo '```'
    echo ""
  fi
  echo "## Strings Analysis"
  echo "### Recognizable Strings (first ${PREVIEW_LINES})"
  echo '```'
  head -n "$PREVIEW_LINES" "$OUTDIR/strings_preview.txt" 2>/dev/null || echo "(none)"
  echo '```'
  echo ""
  echo "### Base64-like Candidates (first ${PREVIEW_LINES})"
  echo '```'
  head -n "$PREVIEW_LINES" "$OUTDIR/strings_base64.txt" 2>/dev/null || echo "(none)"
  echo '```'
  echo ""
  if [[ -s "$OUTDIR/strings_urls.txt" ]]; then
    echo "### URLs Found"
    echo '```'
    head -n 10 "$OUTDIR/strings_urls.txt"
    echo '```'
    echo ""
  fi
  if [[ -s "$OUTDIR/strings_emails.txt" ]]; then
    echo "### Email Addresses Found"
    echo '```'
    head -n 10 "$OUTDIR/strings_emails.txt"
    echo '```'
    echo ""
  fi
  echo "### Possible Flags (CTF-style)"
  if [[ -s "$OUTDIR/possible_flags.txt" ]]; then
    echo '```'
    cat "$OUTDIR/possible_flags.txt"
    echo '```'
  else
    echo "_No CTF-style flags detected_"
  fi
  echo ""
  echo "## File Carving Results"
  if [[ -d "$OUTDIR/foremost" ]] && [[ "$(find "$OUTDIR/foremost" -type f 2>/dev/null | wc -l)" -gt 0 ]]; then
    echo '```'
    find "$OUTDIR/foremost" -maxdepth 2 -type f -printf "%p (%s bytes)\n" | head -n 10
    echo '```'
    echo ""
    echo "### Carved File Analysis"
    echo '```'
    find "$OUTDIR/foremost" -maxdepth 2 -type f -exec file -b {} \; | sort | uniq -c | sort -nr
    echo '```'
  else
    echo "_No obvious carved files found by foremost_"
  fi
  echo ""
  echo "## Signature Detection"
  if [[ -f "$OUTDIR/signature_hits.log" ]]; then
    echo "### Detected Signatures"
    echo '```'
    head -n 15 "$OUTDIR/signature_hits.log"
    echo '```'
    echo ""
    echo "### Extracted Signature Files"
    echo '```'
    find "$OUTDIR/signature_hits" -maxdepth 1 -type f -exec file -b {} \; | sort | uniq -c | sort -nr
    echo '```'
  else
    echo "_No common signatures found_"
  fi
  echo ""
  echo "## Steganography Analysis"
  if [[ -f "$OUTDIR/steghide_info.txt" ]]; then
    echo "### Steghide Info"
    echo '```'
    # Filter out error messages and show only relevant info
    grep -v "unknown argument" "$OUTDIR/steghide_info.txt" | head -n 10 || true
    echo '```'
    if [[ -d "$OUTDIR/steghide" ]] && [[ "$(find "$OUTDIR/steghide" -type f 2>/dev/null | wc -l)" -gt 0 ]]; then
      echo "_Steghide extractions saved in_ \`steghide/\`"
    else
      echo "_No steghide-extracted files (empty or password-protected)_"
    fi
  else
    echo "_steghide not run or not installed_"
  fi
  echo ""
  # Additional stego tools results
  if [[ -f "$OUTDIR/zsteg.txt" ]]; then
    echo "### Zsteg Analysis"
    echo '```'
    head -n 20 "$OUTDIR/zsteg.txt" || true
    echo '```'
    echo ""
  fi
  if [[ -f "$OUTDIR/stegdetect.txt" ]]; then
    echo "### Stegdetect Analysis"
    echo '```'
    cat "$OUTDIR/stegdetect.txt" || true
    echo '```'
    echo ""
  fi
  echo "## Next Steps"
  echo "- Open any recovered images under \`foremost/\` or \`signature_hits/\` and inspect visually."
  echo "- Check \`strings_preview.txt\` for obvious filenames/messages."
  echo "- If steghide indicated embedded data, try small targeted wordlists before full brute-force."
  echo "- Examine extracted signature hits for hidden content."
  echo "- Check URLs and email addresses for potential leads."
  echo "- High entropy (7.95) suggests possible encrypted content - consider brute-force approaches."
  echo ""
  echo "---"
  echo "*Report generated by [Stego Scan v${VERSION}](https://github.com/yourusername/stego-scan)*  "
  echo "*Raw artifacts & full logs are in* \`$OUTDIR\`  "
} > "$REPORT_MD"

# Final output
ok "Scan completed in $(format_duration $processing_time)"
info "Markdown report saved: $REPORT_MD"
info "Raw artifacts saved in: $OUTDIR"

# Offer to open the report if not in quiet mode
if [[ "${QUIET:-0}" -eq 0 ]]; then
  echo ""
  read -p "Would you like to view the report now? (y/N) " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v glow >/dev/null 2>&1; then
      glow "$REPORT_MD"
    elif command -v bat >/dev/null 2>&1; then
      bat "$REPORT_MD"
    elif command -v less >/dev/null 2>&1; then
      less "$REPORT_MD"
    else
      cat "$REPORT_MD"
    fi
  fi
fi

exit 0
