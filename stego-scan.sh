#!/usr/bin/env bash
# stego-scan - report now written directly into the extraction folder
# Save as: stego-scan.sh
set -euo pipefail
IFS=$'\n\t'

# ---------------- Colors ----------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; RESET='\033[0m'
info(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${CYAN}[*]${RESET} %b\n" "$1"; }
ok(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${GREEN}[+]${RESET} %b\n" "$1"; }
warn(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "${YELLOW}[!]${RESET} %b\n" "$1"; }
die(){ printf "${RED}[-]${RESET} %b\n" "$1"; exit 1; }

usage(){
  cat <<EOF
Usage: $(basename "$0") [options] /path/to/file

Options:
  -p, --password <pw>   Try this password with steghide (non-interactive)
  -w, --wordlist <f>    Wordlist for --aggressive (stegseek)
      --aggressive      Attempt cracking with stegseek and provided -w
      --no-steghide     Skip steghide entirely
  -q, --quiet           Minimal terminal output
  -h, --help            Show this help
EOF
}

# ---------------- Parse args ----------------
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

BNAME="$(basename "$FILE")"
BASE="${BNAME%.*}"
TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="extracted_${BASE}_${TS}"

# create OUTDIR (fallback to mktemp if mkdir fails)
if ! mkdir -p -- "$OUTDIR"; then
  warn "Could not create $OUTDIR, using temp dir"
  OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/stegoscan.XXXX")"
fi

# now set REPORT inside OUTDIR
REPORT="${OUTDIR}/${BASE}_${TS}.txt"

# ---------------- Tools list to check ----------------
REQUIRED_TOOLS=( \
  file exiftool binwalk foremost steghide stegseek \
  strings xxd grep awk sed head tail \
)
# ent tends to be missing on many systems; treat as optional
OPTIONAL_TOOLS=(ent identify pngcheck jpeginfo)

MISSING_TOOLS=()
for t in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$t" >/dev/null 2>&1; then
    MISSING_TOOLS+=("$t")
  fi
done

# Start report header (written inside OUTDIR)
{
  printf "Stego scan report for: %s\n" "$FILE"
  printf "Generated: %s\n" "$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
  printf "Output dir: %s\n" "$OUTDIR"
  if (( ${#MISSING_TOOLS[@]} > 0 )); then
    printf "Missing required tools: %s\n" "$(printf "%s " "${MISSING_TOOLS[@]}")"
  else
    printf "Missing required tools: none\n"
  fi
  printf "Flags: password=%s aggressive=%s no-steghide=%s quiet=%s\n\n" \
    "${PASSWORD:-<none>}" "$AGGRESSIVE" "$NOSteghide" "$QUIET"
} > "$REPORT"

# helper to optionally print to terminal (keeps compatibility)
term(){ [[ "${QUIET:-0}" -eq 1 ]] || printf "%b\n" "$1"; }

# helper to run and append to report (respects quiet mode)
# Usage: run_and_log "Label" -- cmd arg1 arg2 ...
run_and_log(){
  local label="$1"; shift
  if [[ "${1:-}" == "--" ]]; then shift; fi
  if [[ $# -lt 1 ]]; then
    echo "[ERROR] run_and_log called without command" >> "$REPORT"
    return 1
  fi
  local -a cmd=( "$@" )
  echo -e "\n==== $label ====" >> "$REPORT"
  if [[ "${QUIET:-0}" -ne 1 ]]; then
    printf "${BOLD}%s${RESET}\n" "$label"
  fi
  if ! command -v "${cmd[0]}" >/dev/null 2>&1; then
    warn "Tool not found: ${cmd[0]}"
    echo "[SKIP] ${cmd[0]} not installed" >> "$REPORT"
    return 1
  fi
  {
    echo "Command: ${cmd[*]}"
    "${cmd[@]}" 2>&1 || echo "[non-zero exit]"
  } >> "$REPORT"
  return 0
}

# trap to ensure we print final note on exit
_cleanup() {
  exit_code=$?
  if [[ $exit_code -ne 0 ]]; then
    warn "Script exited with code $exit_code. Partial results (if any) saved to: $OUTDIR"
  else
    ok "Scan complete!"
    term "$(printf "${CYAN}[*]${RESET} Report: %s" "$REPORT")"
    term "$(printf "${CYAN}[*]${RESET} Artifacts: %s" "$OUTDIR")"
  fi

  if (( ${#MISSING_TOOLS[@]} > 0 )); then
    warn "Missing tools: ${MISSING_TOOLS[*]}"
  fi
}
trap _cleanup EXIT

# ---------------- Basic checks ----------------
term "$(printf "${CYAN}[*]${RESET} Running basic file checks...")"
run_and_log "file" -- file -- "$FILE"
run_and_log "ls -l" -- ls -l -- "$FILE"
run_and_log "sha256sum" -- sha256sum -- "$FILE"
run_and_log "md5sum" -- md5sum -- "$FILE"

# ---------------- Metadata ----------------
term "$(printf "${CYAN}[*]${RESET} Extracting metadata...")"
run_and_log "exiftool" -- exiftool "$FILE" || true

# Check for optional tools before running
if command -v identify >/dev/null; then
  run_and_log "identify (ImageMagick)" -- identify -verbose "$FILE" || true
else
  echo "[SKIP] identify (ImageMagick) not installed" >> "$REPORT"
fi

# ---------------- Binwalk ----------------
term "$(printf "${CYAN}[*]${RESET} Running binwalk...")"
if command -v binwalk >/dev/null; then
  BINWALK_SCAN="$OUTDIR/binwalk_scan.txt"
  BINWALK_EXTRACT_LOG="$OUTDIR/binwalk_extract.txt"
  # capture both outputs
  binwalk -- "$FILE" > "$BINWALK_SCAN" 2>&1 || true
  binwalk -e -M --directory "$OUTDIR/binwalk_extracted" -- "$FILE" > "$BINWALK_EXTRACT_LOG" 2>&1 || true
  echo "Binwalk full output: $BINWALK_SCAN" >> "$REPORT"
  echo "Binwalk extract log: $BINWALK_EXTRACT_LOG" >> "$REPORT"
  echo -e "\n==== Binwalk preview ====" >> "$REPORT"
  head -n 20 "$BINWALK_SCAN" >> "$REPORT" || true
else
  warn "binwalk missing"
  echo "[SKIP] binwalk not installed" >> "$REPORT"
fi

# ---------------- Strings ----------------
term "$(printf "${CYAN}[*]${RESET} Extracting strings...")"
if command -v strings >/dev/null; then
  STRINGS_ALL="$OUTDIR/strings_all.txt"
  STRINGS_FILTERED="$OUTDIR/strings_filtered.txt"
  STRINGS_WORDY="$OUTDIR/strings_wordy.txt"
  STRINGS_BASE64="$OUTDIR/strings_base64_candidates.txt"
  
  strings -a -- "$FILE" > "$STRINGS_ALL" || true
  grep -Ea '[[:print:]]{6,}' "$STRINGS_ALL" > "$STRINGS_FILTERED" || true
  grep -Eao '\b[[:alnum:]]{6,}\b' "$STRINGS_ALL" | sort -u > "$STRINGS_WORDY" || true
  grep -Eao '[A-Za-z0-9+/=]{40,}' "$STRINGS_ALL" > "$STRINGS_BASE64" || true
  
  echo "Strings files:" >> "$REPORT"
  echo "  - All: $STRINGS_ALL" >> "$REPORT"
  echo "  - Filtered: $STRINGS_FILTERED" >> "$REPORT"
  echo "  - Wordy: $STRINGS_WORDY" >> "$REPORT"
  echo "  - Base64: $STRINGS_BASE64" >> "$REPORT"
  
  echo -e "\n==== Strings preview ====" >> "$REPORT"
  head -n 30 "$STRINGS_FILTERED" >> "$REPORT" || true
else
  warn "strings missing"
  echo "[SKIP] strings not installed" >> "$REPORT"
fi

# ---------------- File Analysis ----------------
term="$(printf "${CYAN}[*]${RESET} Analyzing file properties...")"
if command -v ent >/dev/null; then
  run_and_log "ent (entropy)" -- ent "$FILE" || true
else
  echo "[SKIP] ent not installed" >> "$REPORT"
fi

# Optional file validators
if command -v pngcheck >/dev/null; then
  run_and_log "pngcheck" -- pngcheck -v "$FILE" || true
else
  echo "[SKIP] pngcheck not installed" >> "$REPORT"
fi

if command -v jpeginfo >/dev/null; then
  run_and_log "jpeginfo" -- jpeginfo -c "$FILE" || true
else
  echo "[SKIP] jpeginfo not installed" >> "$REPORT"
fi

# ---------------- Carving ----------------
term "$(printf "${CYAN}[*]${RESET} File carving...")"
if command -v foremost >/dev/null; then
  FOREMOST_DIR="$OUTDIR/foremost"
  mkdir -p -- "$FOREMOST_DIR"
  run_and_log "foremost" -- foremost -i "$FILE" -o "$FOREMOST_DIR" || true
else
  warn "foremost missing"
  echo "[SKIP] foremost not installed" >> "$REPORT"
fi

# ---------------- Steghide ----------------
if [[ $NOSteghide -eq 0 ]]; then
  if command -v steghide >/dev/null; then
    term "$(printf "${CYAN}[*]${RESET} Checking steghide...")"
    SH_INFO="$(steghide info -sf "$FILE" 2>&1 || true)"
    echo "$SH_INFO" >> "$REPORT"

    if echo "$SH_INFO" | grep -qi "embedded data"; then
      term "$(printf "${GREEN}[+]${RESET} steghide reports embedded data!")"
      STEGHIDE_DIR="$OUTDIR/steghide"
      mkdir -p -- "$STEGHIDE_DIR"
      
      # Try with password if provided
      if [[ -n "${PASSWORD:-}" ]]; then
        term "$(printf "${CYAN}[*]${RESET} Trying steghide with provided password...")"
        steghide extract -sf "$FILE" -p "$PASSWORD" -xf "$STEGHIDE_DIR/extracted" -f >/dev/null 2>&1 || true
      fi
      
      # Always try empty password
      term "$(printf "${CYAN}[*]${RESET} Trying steghide with empty password...")"
      steghide extract -sf "$FILE" -p "" -xf "$STEGHIDE_DIR/extracted_empty" -f >/dev/null 2>&1 || true
      
      echo "Steghide extractions in: $STEGHIDE_DIR" >> "$REPORT"
    else
      term "$(printf "${YELLOW}[!]${RESET} steghide reports no embedded data")"
    fi
  else
    warn "steghide missing"
  fi
else
  term "$(printf "${YELLOW}[!]${RESET} Skipping steghide (--no-steghide)")"
fi

# ---------------- Stegseek (aggressive) ----------------
if [[ $AGGRESSIVE -eq 1 ]]; then
  if [[ -z "$WORDLIST" ]]; then die "Aggressive mode requires -w /path/to/wordlist"; fi
  if command -v stegseek >/dev/null; then
    term "$(printf "${CYAN}[*]${RESET} Running stegseek...")"
    STEGSEEK_DIR="$OUTDIR/stegseek"
    mkdir -p -- "$STEGSEEK_DIR"
    stegseek "$FILE" "$WORDLIST" "$STEGSEEK_DIR/extracted" > "$STEGSEEK_DIR/stegseek_out.txt" 2>&1 || true
    echo "Stegseek output: $STEGSEEK_DIR/stegseek_out.txt" >> "$REPORT"
    term "$(printf "${YELLOW}[!]${RESET} stegseek completed")"
  else
    die "stegseek not installed"
  fi
fi

# ---------------- Signature Search ----------------
term="$(printf "${CYAN}[*]${RESET} Searching for embedded signatures...")"
SIG_HITS_DIR="$OUTDIR/signature_hits"
mkdir -p -- "$SIG_HITS_DIR"
# Create a single-line hex dump
xxd -p -- "$FILE" | tr -d '\n' > "$OUTDIR/hex_dump.txt" || true

search_and_extract() {
  local hex="$1" tag="$2"
  # find byte offsets of the hex pattern
  grep -bo -- "$hex" "$OUTDIR/hex_dump.txt" | while IFS=: read -r pos _; do
    bytepos=$((pos / 2))
    dd if="$FILE" bs=1 skip="$bytepos" count=1048576 of="$SIG_HITS_DIR/${tag}_${bytepos}.bin" 2>/dev/null || true
  done
}

# Common file signatures
search_and_extract "504b0304" "zip"
search_and_extract "89504e47" "png"
search_and_extract "ffd8ff" "jpg"
search_and_extract "25504446" "pdf"
search_and_extract "52617221" "rar"
search_and_extract "526172211a070100" "rar5"
search_and_extract "377abcaf271c" "7z"
search_and_extract "1f8b08" "gzip"

if [[ -n "$(ls -A "$SIG_HITS_DIR" 2>/dev/null || true)" ]]; then
  echo "Found embedded signatures:" >> "$REPORT"
  for f in "$SIG_HITS_DIR"/*; do
    file -- "$f" >> "$REPORT"
  done
else
  echo "No embedded signatures found" >> "$REPORT"
fi

# ---------------- Flag Search ----------------
term="$(printf "${CYAN}[*]${RESET} Searching for flags...")"
if [[ -f "$OUTDIR/strings_all.txt" ]]; then
  FLAGS_FILE="$OUTDIR/possible_flags.txt"
  grep -Eio 'ctf\{[^}]{1,200}\}|flag\{[^}]{1,200}\}|FLAG\{[^}]{1,200}\}' "$OUTDIR/strings_all.txt" > "$FLAGS_FILE" || true
  if [[ -s "$FLAGS_FILE" ]]; then
    echo "Possible flags found:" >> "$REPORT"
    cat "$FLAGS_FILE" >> "$REPORT"
    term "$(printf "${GREEN}[+]${RESET} Found possible flags")"
  else
    echo "No flags found" >> "$REPORT"
  fi
fi

# ---------------- Final Report ----------------
{
  echo -e "\n==== Scan Summary ===="
  echo "Generated: $(date)"
  echo "Output directory: $OUTDIR"
  echo -e "\nDisk usage:"
  du -h --max-depth=1 "$OUTDIR" | sort -h
} >> "$REPORT"

# Exit normally; trap will print final messages
exit 0
