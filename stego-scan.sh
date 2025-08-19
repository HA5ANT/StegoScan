#!/usr/bin/env bash
# stego-scan - concise, robust, Markdown report next to target
# Usage: ./stego-scan.sh [options] /path/to/target.jpg
set -euo pipefail
IFS=$'\n\t'

# ------- Config -------
PREVIEW_LINES=30
EXTRACT_SIZE=524288   # bytes to extract at signature offsets (default 512 KiB)

# ------- Colors (terminal only) -------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${CYAN}[*]${RESET} %b\n" "$1"; }
ok(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${GREEN}[+]${RESET} %b\n" "$1"; }
warn(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${YELLOW}[!]${RESET} %b\n" "$1"; }
die(){ printf "${RED}[-]${RESET} %b\n" "$1"; exit 1; }

usage(){
  cat <<USG
Usage: $(basename "$0") [options] /path/to/file

Options:
  -p, --password <pw>      Try provided password with steghide (non-interactive)
  -w, --wordlist <f>       Wordlist for --aggressive (stegseek)
      --aggressive         Run stegseek with provided wordlist
      --no-steghide        Skip steghide checks
  -q, --quiet              Minimal terminal output
  -h, --help               Show this help
USG
}

# ------- Parse args -------
PASSWORD=""
WORDLIST=""
AGGRESSIVE=0
NOSteghide=0
QUIET=0
ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--password) PASSWORD="$2"; shift 2;;
    -w|--wordlist) WORDLIST="$2"; shift 2;;
    --aggressive) AGGRESSIVE=1; shift;;
    --no-steghide) NOSteghide=1; shift;;
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

# ------- Helpers -------
run_quiet(){ # run command and save stdout/stderr to a file; don't exit on failure
  # usage: run_quiet <outfile> <cmd...>
  local out="$1"; shift
  echo "Running: $*" >> "$out"
  "$@" >> "$out" 2>&1 || echo "Command exited with status $?" >> "$out"
}

# binary-safe signature search & extract
search_and_extract_bin(){
  local label="$1"; local pat="$2"
  # grep -aob returns byte offset:match
  mkdir -p "${OUTDIR}/signature_hits"
  LC_ALL=C grep -aob -- "$pat" "$FILE" 2>/dev/null | while IFS=: read -r bytepos _; do
    local outf="${OUTDIR}/signature_hits/${label}_${bytepos}.bin"
    dd if="$FILE" bs=1 skip="$bytepos" count="$EXTRACT_SIZE" of="$outf" 2>/dev/null || true
    echo "${label} @ ${bytepos} -> ${outf}" >> "${OUTDIR}/signature_hits.log"
  done || true
}

# ------- Start scans (raw files saved in OUTDIR) -------
info "Starting stego triage for: $FILE"

# basic info
run_quiet "$OUTDIR/file.txt" file -- "$FILE"
run_quiet "$OUTDIR/ls.txt" ls -l -- "$FILE"
run_quiet "$OUTDIR/sha256.txt" sha256sum -- "$FILE"
run_quiet "$OUTDIR/md5.txt" md5sum -- "$FILE"

# metadata (optional)
if command -v exiftool >/dev/null 2>&1; then
  run_quiet "$OUTDIR/exiftool.txt" exiftool "$FILE"
fi
if command -v identify >/dev/null 2>&1; then
  run_quiet "$OUTDIR/identify.txt" identify -verbose "$FILE"
fi

# binwalk scan + attempt extract (nonfatal)
if command -v binwalk >/dev/null 2>&1; then
  run_quiet "$OUTDIR/binwalk_scan.txt" binwalk "$FILE"
  mkdir -p "$OUTDIR/binwalk_extracted"
  run_quiet "$OUTDIR/binwalk_extract_log.txt" binwalk -e -M --directory "$OUTDIR/binwalk_extracted" "$FILE"
fi

# strings (all / preview / base64)
run_quiet "$OUTDIR/strings_all.txt" strings -a "$FILE"
# preview: printable lines >=6 chars
grep -E --color=never '.{6,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_preview.txt" 2>/dev/null || true
grep -Eao '[A-Za-z0-9+/=]{40,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_base64.txt" 2>/dev/null || true

# entropy if available
if command -v ent >/dev/null 2>&1; then
  run_quiet "$OUTDIR/ent.txt" ent "$FILE"
fi

# foremost carving (nonfatal)
if command -v foremost >/dev/null 2>&1; then
  mkdir -p "$OUTDIR/foremost"
  run_quiet "$OUTDIR/foremost.log" foremost -i "$FILE" -o "$OUTDIR/foremost"
fi

# steghide info + extraction attempts (nonfatal)
if [[ $NOSteghide -eq 0 ]] && command -v steghide >/dev/null 2>&1; then
  run_quiet "$OUTDIR/steghide_info.txt" steghide info -sf "$FILE"
  mkdir -p "$OUTDIR/steghide"
  if [[ -n "$PASSWORD" ]]; then
    run_quiet "$OUTDIR/steghide_extract_pass.log" steghide extract -sf "$FILE" -p "$PASSWORD" -xf "$OUTDIR/steghide/extracted" -f
  fi
  run_quiet "$OUTDIR/steghide_extract_empty.log" steghide extract -sf "$FILE" -p "" -xf "$OUTDIR/steghide/extracted_empty" -f
fi

# stegseek if requested
if [[ $AGGRESSIVE -eq 1 ]]; then
  if [[ -z "$WORDLIST" ]]; then die "Aggressive requires -w /path/to/wordlist"; fi
  if command -v stegseek >/dev/null 2>&1; then
    mkdir -p "$OUTDIR/stegseek"
    run_quiet "$OUTDIR/stegseek/stegseek_out.txt" stegseek "$FILE" "$WORDLIST" "$OUTDIR/stegseek/extracted"
  else
    warn "stegseek not found, skipping aggressive mode"
  fi
fi

# signature search (common types)
search_and_extract_bin "png" $'\x89PNG'
search_and_extract_bin "jpg" $'\xFF\xD8\xFF'
search_and_extract_bin "zip" $'PK\x03\x04'
search_and_extract_bin "pdf" "%PDF"
search_and_extract_bin "rar" "Rar!"
search_and_extract_bin "gzip" $'\x1f\x8b\x08'
search_and_extract_bin "7z" $'7z\xBC\xAF\x27\x1C'
search_and_extract_bin "exe" "MZ"

# flag search
grep -Eio 'ctf\{[^}]{1,200}\}|flag\{[^}]{1,200}\}|FLAG\{[^}]{1,200}\}' "$OUTDIR/strings_all.txt" > "$OUTDIR/possible_flags.txt" 2>/dev/null || true

# ------- Generate concise Markdown report next to the target file -------
{
  echo "# Stego Scan Report — ${BNAME}"
  echo ""
  echo "**Target file:** \`$FILE\`  "
  echo "**Run time:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  "
  echo "**Raw artifacts directory:** \`$OUTDIR\`  "
  echo ""
  echo "## Quick summary"
  PREVIEW_COUNT=$(wc -l < "$OUTDIR/strings_preview.txt" 2>/dev/null || echo 0)
  BASE64_COUNT=$(wc -l < "$OUTDIR/strings_base64.txt" 2>/dev/null || echo 0)
  FOREMOST_COUNT=$(find "$OUTDIR/foremost" -type f 2>/dev/null | wc -l || echo 0)
  SIG_HITS_COUNT=$(find "$OUTDIR/signature_hits" -maxdepth 1 -type f 2>/dev/null | wc -l || echo 0)
  STEGHIDE_COUNT=0
  [[ -d "$OUTDIR/steghide" ]] && STEGHIDE_COUNT=$(find "$OUTDIR/steghide" -type f 2>/dev/null | wc -l || echo 0)
  echo "| Item | Count | Notes |"
  echo "|---|---:|---|"
  echo "| Recognizable strings (preview) | ${PREVIEW_COUNT} | first ${PREVIEW_LINES} shown below |"
  echo "| Base64-like tokens | ${BASE64_COUNT} | potential hidden blobs |"
  echo "| Foremost carved files | ${FOREMOST_COUNT} | in \`foremost/\` |"
  echo "| Signature extracts | ${SIG_HITS_COUNT} | in \`signature_hits/\` |"
  echo "| Steghide extracted files | ${STEGHIDE_COUNT} | in \`steghide/\` |"
  echo ""
  echo "## Basic info"
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
    echo "## Entropy"
    echo '```'
    cat "$OUTDIR/ent.txt" || true
    echo '```'
    echo ""
  fi
  echo "## Strings — Recognizable preview (first ${PREVIEW_LINES})"
  echo '```'
  head -n "$PREVIEW_LINES" "$OUTDIR/strings_preview.txt" 2>/dev/null || echo "(none)"
  echo '```'
  echo ""
  echo "## Base64-like candidates (first ${PREVIEW_LINES})"
  echo '```'
  head -n "$PREVIEW_LINES" "$OUTDIR/strings_base64.txt" 2>/dev/null || echo "(none)"
  echo '```'
  echo ""
  echo "## Possible flags (CTF-style)"
  if [[ -s "$OUTDIR/possible_flags.txt" ]]; then
    echo '```'
    cat "$OUTDIR/possible_flags.txt"
    echo '```'
  else
    echo "_No CTF-style flags detected_"
  fi
  echo ""
  echo "## Foremost carving (summary)"
  if [[ -d "$OUTDIR/foremost" ]] && [[ "$(find "$OUTDIR/foremost" -type f 2>/dev/null | wc -l)" -gt 0 ]]; then
    echo '```'
    find "$OUTDIR/foremost" -maxdepth 2 -type f -printf "%p (%s bytes)\n" | head -n 10
    echo '```'
  else
    echo "_No obvious carved files found by foremost_"
  fi
  echo ""
  echo "## Signature hits (signature_hits/)"
  if [[ -f "$OUTDIR/signature_hits.log" ]]; then
    echo '```'
    head -n 10 "$OUTDIR/signature_hits.log"
    echo '```'
  else
    echo "_No common signatures found (zip/png/jpg/pdf/rar/gzip/7z/exe)_"
  fi
  echo ""
  echo "## Steghide"
  if [[ -f "$OUTDIR/steghide_info.txt" ]]; then
    echo '```'
    head -n 10 "$OUTDIR/steghide_info.txt" || true
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
  echo "## Next steps / pointers"
  echo "- Open any recovered images under \`foremost/\` or \`signature_hits/\` and inspect visually."
  echo "- Check \`strings_preview.txt\` for obvious filenames/messages."
  echo "- If steghide indicated embedded data, try small targeted wordlists before full brute-force."
  echo ""
  echo "----"
  echo "_Raw artifacts & full logs are in_ \`$OUTDIR\`"
} > "$REPORT_MD"

ok "Scan finished."
info "Markdown report saved: $REPORT_MD"
info "Raw artifacts saved in: $OUTDIR"
exit 0
