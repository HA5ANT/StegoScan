#!/usr/bin/env bash
# stego-scan-v2.sh - Modular, deterministic steganography triage pipeline.
# Purpose: Automated steganography triage for CTFs and training labs.
# Writes a Markdown report next to the target plus a timestamped artifacts folder.
#
# Design notes (v2.2, informed by forensic steganalysis practice):
# - Format-aware tool selection: tools only run on carriers they support.
# - Extraction-based validation: every detection is verified (file-type
#   validation of carved chunks and extracted payloads) to kill false positives.
# - Explicit appended-data detection via EOF markers (FFD9/IEND/%%EOF/EOCD).
# - Deterministic, dependency-free entropy fallback (no `ent` required).
# - Timeouts on all external tools (configurable via --timeout).
# - Bulk triage mode (--dir) with a machine-readable CSV summary.

set -euo pipefail
IFS=$'\n\t'

# --- Defaults & Configuration ---
VERSION="2.2.0"
PREVIEW_LINES=30
EXTRACT_SIZE=524288
TOOL_TIMEOUT=300
DEBUG=0
QUIET=0

# --- Internal State ---
PASSWORD=""
WORDLIST=""
AGGRESSIVE=0
NOSteghide=0
TARGET_FILE=""
OUTDIR=""
REPORT_MD=""
PROCESS_LOG=""
START_TIME=0
FTYPE="other"       # jpeg|png|bmp|gif|wav|pdf|zip|text|other
FILE_DESC=""

# --- Logging & UI Helpers (set -e safe: never return non-zero) ---
log_info()  { [[ "${QUIET}" -eq 0 ]] || return 0; printf "\033[0;36m[*]\033[0m %b\n" "$1"; }
log_ok()    { [[ "${QUIET}" -eq 0 ]] || return 0; printf "\033[0;32m[+]\033[0m %b\n" "$1"; }
log_warn()  { [[ "${QUIET}" -eq 0 ]] || return 0; printf "\033[0;33m[!]\033[0m %b\n" "$1"; }
log_die()   { printf "\033[0;31m[-]\033[0m %b\n" "$1"; exit 1; }
log_debug() { [[ "${DEBUG}" -eq 1 ]] || return 0; printf "\033[2m[DEBUG]\033[0m %b\n" "$1"; }

# --- Tool Execution Helpers ---
cmd_str() { printf -v _cs ' %q' "$@"; printf '%s' "${_cs# }"; }

run_tool() { # non-fatal: save output to a file, timeout-guarded, never exits
  local out="$1"; shift
  log_debug "Running (timeout ${TOOL_TIMEOUT}s): $(cmd_str "$@")"
  {
    printf "[%s] Command: %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$(cmd_str "$@")"
    timeout "${TOOL_TIMEOUT}s" "$@" 2>&1
    local rc=$?
    if [[ $rc -eq 124 ]]; then
      printf "[%s] TIMED OUT after %ss\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$TOOL_TIMEOUT"
      log_warn "Tool timed out after ${TOOL_TIMEOUT}s: $(cmd_str "$@")"
    fi
    return 0
  } > "$out" || log_warn "Tool failed (non-fatal): $(cmd_str "$@")"
}

format_duration() {
  local seconds=$1
  local mins=$((seconds / 60))
  local secs=$((seconds % 60))
  if [[ $mins -gt 0 ]]; then echo "${mins}m ${secs}s"; else echo "${secs}s"; fi
}

# --- Findings registry (severity-scored signals for the report verdict) ---
declare -A FINDINGS=()
declare -A FIND_SEV=()

add_finding() { # add_finding <severity 1-3> <description>
  local sev=$1 desc="$2"
  local n=${#FINDINGS[@]}
  FINDINGS[$n]="$desc"
  FIND_SEV[$n]=$sev
}

verdict_score() {
  local score=0
  for sev in "${FIND_SEV[@]}"; do score=$((score + sev)); done
  if   [[ $score -ge 50 ]]; then echo "SUSPICIOUS (high-value findings)"
  elif [[ $score -ge 20 ]]; then echo "POSSIBLE (investigate findings)"
  else echo "CLEAN (no significant signals)"
  fi
}

# --- Core Modules ---
usage() {
  cat <<USG
Stego Scan v${VERSION} - Steganography triage tool

Usage: $(basename "$0") [options] /path/to/file
       $(basename "$0") --dir /path/to/directory

Options:
  -p, --password <pw>      Try provided password with steghide
  -w, --wordlist <f>       Wordlist for --aggressive (stegseek)
      --aggressive         Run stegseek with provided wordlist
      --no-steghide        Skip steghide checks
      --extract-size <n>   Bytes to extract at signatures (default: ${EXTRACT_SIZE})
      --preview-lines <n>  Lines to show in preview (default: ${PREVIEW_LINES})
      --timeout <s>        Tool execution timeout in seconds (default: ${TOOL_TIMEOUT})
      --dir <path>         Bulk triage: scan every file in a directory, write a CSV summary
      --csv                Write machine-readable CSV summary (with --dir)
      --debug              Enable debug output
  -q, --quiet              Minimal terminal output
  -h, --help               Show this help
USG
}

parse_args() {
  local args=()
  local mode="single"
  local dir_target=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -p|--password) PASSWORD="$2"; shift 2;;
      -w|--wordlist) WORDLIST="$2"; shift 2;;
      --aggressive) AGGRESSIVE=1; shift;;
      --no-steghide) NOSteghide=1; shift;;
      --extract-size) EXTRACT_SIZE="$2"; shift 2;;
      --preview-lines) PREVIEW_LINES="$2"; shift 2;;
      --timeout) TOOL_TIMEOUT="$2"; shift 2;;
      --dir) mode="dir"; dir_target="$2"; shift 2;;
      --csv) CSV=1; shift;;
      --debug) DEBUG=1; shift;;
      -q|--quiet) QUIET=1; shift;;
      -h|--help) usage; exit 0;;
      --) shift; break;;
      -*) log_die "Unknown option: $1";;
      *) args+=("$1"); shift;;
    esac
  done

  if [[ ! "$PREVIEW_LINES" =~ ^[0-9]+$ ]]; then PREVIEW_LINES=30; fi
  if [[ ! "$EXTRACT_SIZE" =~ ^[0-9]+$ ]]; then EXTRACT_SIZE=524288; fi
  if [[ ! "$TOOL_TIMEOUT" =~ ^[0-9]+$ ]]; then TOOL_TIMEOUT=300; fi

  if [[ "$mode" == "dir" ]]; then
    if [[ -z "$dir_target" ]]; then usage; exit 2; fi
    if [[ ! -d "$dir_target" ]]; then log_die "Directory not found: $dir_target"; fi
    DIR_MODE="$dir_target"
    return 0
  fi

  if [[ ${#args[@]} -lt 1 ]]; then usage; exit 2; fi
  TARGET_FILE="${args[0]}"
  if [[ ! -f "$TARGET_FILE" ]]; then log_die "File not found: $TARGET_FILE"; fi
}

detect_format() {
  FILE_DESC=$(file -b "$TARGET_FILE")
  case "$FILE_DESC" in
    *PNG*image*) FTYPE="png";;
    *JPEG*image*|*JPG*) FTYPE="jpeg";;
    *PC\ bitmap*|*BMP*image*) FTYPE="bmp";;
    *GIF*image*) FTYPE="gif";;
    *WAVE*audio*|*RIFF*audio*|*Audio*WAV*) FTYPE="wav";;
    *PDF*document*) FTYPE="pdf";;
    *Zip\ archive*) FTYPE="zip";;
    *ASCII\ text*|*Unicode\ text*|*UTF-8*text*|*text\ file*) FTYPE="text";;
    *ELF*) FTYPE="elf";;
  esac
  log_debug "Detected format: $FTYPE ($FILE_DESC)"
}

setup_environment() {
  local target_dir base ts
  target_dir="$(cd "$(dirname -- "$TARGET_FILE")" && pwd)"
  base="$(basename -- "$TARGET_FILE" | cut -f 1 -d '.')"
  ts="$(date +%Y%m%d_%H%M%S)"

  OUTDIR="${target_dir}/extracted_${base}_${ts}"
  REPORT_MD="${target_dir}/${base}_report.md"
  PROCESS_LOG="${OUTDIR}/process.log"

  mkdir -p "$OUTDIR"
  {
    echo "Stego Scan v${VERSION} Process Log"
    echo "Started: $(date)"
    echo "Target: $TARGET_FILE"
    echo "Detected format: $FTYPE"
  } > "$PROCESS_LOG"

  log_info "Output directory: $OUTDIR"
  log_info "Report will be saved as: $REPORT_MD"
}

check_dependencies() {
  local required=("file" "strings" "dd" "grep" "awk" "sed" "head" "tail" "timeout" "od")
  local missing=()
  for cmd in "${required[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then log_die "Missing required tools: ${missing[*]}"; fi
}

# --- Analysis Modules ---
analysis_basic() {
  log_info "Collecting basic file information"
  run_tool "$OUTDIR/file.txt" file -- "$TARGET_FILE"
  run_tool "$OUTDIR/ls.txt" ls -l -- "$TARGET_FILE"
  run_tool "$OUTDIR/sha256.txt" sha256sum -- "$TARGET_FILE"
  run_tool "$OUTDIR/md5.txt" md5sum -- "$TARGET_FILE"
}

analysis_metadata() {
  if command -v exiftool >/dev/null 2>&1; then
    log_info "Extracting metadata with exiftool"
    run_tool "$OUTDIR/exiftool.txt" exiftool -a -u -g1 "$TARGET_FILE"
    grep -E '^[[:space:]]*\[[^]]+\][[:space:]]+(Comment|UserComment|ImageDescription|Artist|Author|Copyright|Software|GPS[^:]*)[[:space:]]*:' "$OUTDIR/exiftool.txt" > "$OUTDIR/exiftool_keyfields.txt" 2>/dev/null || true
    if [[ -s "$OUTDIR/exiftool_keyfields.txt" ]]; then
      add_finding 10 "EXIF/comment fields present (see exiftool_keyfields.txt)"
    fi
  else
    log_info "exiftool not found, skipping metadata extraction"
  fi

  if command -v identify >/dev/null 2>&1 && [[ "$FTYPE" =~ ^(png|jpeg|bmp|gif)$ ]]; then
    log_info "Analyzing image properties"
    run_tool "$OUTDIR/identify.txt" identify -verbose "$TARGET_FILE"
  fi
}

analysis_binwalk() {
  if command -v binwalk >/dev/null 2>&1; then
    log_info "Running binwalk analysis"
    run_tool "$OUTDIR/binwalk_scan.txt" binwalk "$TARGET_FILE"
    mkdir -p "$OUTDIR/binwalk_extracted"
    run_tool "$OUTDIR/binwalk_extract_log.txt" binwalk -e -M --directory "$OUTDIR/binwalk_extracted" "$TARGET_FILE"
    # binwalk extraction is FP-prone (random zlib/DER matches inside compressed
    # data). Only count extractions that validate as real container types.
    find "$OUTDIR/binwalk_extracted" -type f -exec file -b {} \; 2>/dev/null \
      | grep -aiE 'Zip archive|PNG image|JPEG image|gzip|RAR|7-zip|PDF|ELF|PE32|tar archive|ISO|RIFF|WAVE|GIF image|BMP|HTML|XML|SQLite' \
      | sort | uniq -c | sort -nr > "$OUTDIR/binwalk_validated.txt" || true
    local validated
    validated=$(wc -l < "$OUTDIR/binwalk_validated.txt" 2>/dev/null || echo 0)
    if [[ "${validated:-0}" -gt 0 ]]; then
      add_finding 25 "binwalk extracted real container file(s) (see binwalk_validated.txt)"
    fi
  else
    log_info "binwalk not found, skipping"
  fi
}

analysis_strings() {
  log_info "Extracting and analyzing strings"
  run_tool "$OUTDIR/strings_all.txt" strings -a -n 6 "$TARGET_FILE"
  run_tool "$OUTDIR/strings_ascii.txt" strings -a -t d -n 6 "$TARGET_FILE"
  run_tool "$OUTDIR/strings_utf16le.txt" strings -a -el -n 6 "$TARGET_FILE"
  run_tool "$OUTDIR/strings_utf16be.txt" strings -a -eb -n 6 "$TARGET_FILE"

  grep -E --color=never '[[:print:]]{6,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_preview.txt" 2>/dev/null || true
  grep -Eao '[A-Za-z0-9+/=]{40,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_base64.txt" 2>/dev/null || true
  grep -Eo '(http|https|ftp)://[^/"]+' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_urls.txt" 2>/dev/null || true
  grep -Eio '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_emails.txt" 2>/dev/null || true
  grep -Eio '(0x)?[0-9a-fA-F]{8,}' "$OUTDIR/strings_all.txt" > "$OUTDIR/strings_hex.txt" 2>/dev/null || true
}

analysis_entropy() {
  log_info "Calculating entropy (built-in histogram, sample-based)"
  local size head_ent tail_ent
  size=$(stat -c %s "$TARGET_FILE")
  head_ent=$(entropy_of_region 0 65536)
  if [[ $size -gt 131072 ]]; then
    tail_ent=$(entropy_of_region $((size - 65536)) 65536)
  else
    tail_ent=$head_ent
  fi
  {
    echo "Sample size: 65536 bytes (head and tail regions)"
    echo "Head entropy:  $head_ent"
    echo "Tail entropy:  $tail_ent"
    echo "Note: entropy close to 8.0 may indicate encrypted/compressed payloads"
  } > "$OUTDIR/entropy.txt"
  if [[ -f "$OUTDIR/appended_data.bin" ]]; then
    local app_ent
    app_ent=$(od -An -v -tu1 -N 65536 "$OUTDIR/appended_data.bin" 2>/dev/null | awk '
      { for (i = 1; i <= NF; i++) { c[$i]++; n++ } }
      END { if (n == 0) { printf "0.000\n"; exit } for (k in c) { p = c[k] / n; e -= p * log(p) / log(2) } printf "%.3f\n", e }')
    if awk -v a="$app_ent" 'BEGIN{ if (a > 7.5) exit 0; exit 1 }'; then
      add_finding 15 "Appended data is high-entropy (likely encrypted/compressed)"
    fi
  elif [[ "$FTYPE" =~ ^(text|other)$ ]]; then
    # Whole-file entropy is expected to be high for compressed media; only
    # flag text/unknown containers where high entropy is anomalous.
    if awk -v h="$head_ent" -v t="$tail_ent" 'BEGIN{ if (h > 7.5 || t > 7.5) exit 0; exit 1 }'; then
      add_finding 10 "High-entropy region detected in text/unknown container (see entropy.txt)"
    fi
  fi

  if command -v ent >/dev/null 2>&1; then
    log_info "Running ent entropy analysis"
    run_tool "$OUTDIR/ent.txt" ent "$TARGET_FILE"
  fi
}

entropy_of_region() { # $1=offset $2=max-bytes -> Shannon entropy of sampled bytes
  local offset=$1 maxbytes=$2
  od -An -v -tu1 -j "$offset" -N "$maxbytes" "$TARGET_FILE" 2>/dev/null | awk '
    { for (i = 1; i <= NF; i++) { c[$i]++; n++ } }
    END {
      if (n == 0) { printf "0.000\n"; exit }
      for (k in c) { p = c[k] / n; e -= p * log(p) / log(2) }
      printf "%.3f\n", e
    }'
}

analysis_foremost() {
  if command -v foremost >/dev/null 2>&1; then
    log_info "Carving files with foremost"
    mkdir -p "$OUTDIR/foremost"
    run_tool "$OUTDIR/foremost.log" foremost -i "$TARGET_FILE" -o "$OUTDIR/foremost"
    local carved
    carved=$(find "$OUTDIR/foremost" -type f 2>/dev/null | wc -l)
    if [[ "$carved" -gt 0 ]]; then
      add_finding 25 "foremost carved $carved file(s) (see foremost/)"
    fi
  else
    log_info "foremost not found, skipping file carving"
  fi
}

last_offset_of() { # prints byte offset of last match of a literal pattern (or nothing)
  local pat="$1"
  LC_ALL=C grep -aobF -- "$pat" "$TARGET_FILE" 2>/dev/null | tail -n 1 | cut -d: -f1 || true
}

jpeg_eoi_offset() { # true JPEG EOI: reverse-scan FFD9 candidates, keep the first
  # whose following bytes are a recognizable container (compressed pixel data
  # and embedded blobs contain coincidental FFD9 sequences).
  local size candidates o cand ftype
  size=$(stat -c %s "$TARGET_FILE")
  candidates=$(LC_ALL=C grep -aobF -- $'\xff\xd9' "$TARGET_FILE" 2>/dev/null | cut -d: -f1 | sort -rn | head -20)
  for o in $candidates; do
    cand=$((o + 2))
    [[ $cand -ge $size ]] && continue
    ftype=$(dd if="$TARGET_FILE" bs=1 skip="$cand" count=16 2>/dev/null | file -b -)
    [[ "$ftype" == *"data"* ]] || { echo "$cand"; return 0; }
  done
  local last
  last=$(printf '%s\n' "$candidates" | head -n 1)
  echo $(( ${last:-0} + 2 ))
}

analysis_append() { # explicit appended-data detection via EOF markers
  log_info "Checking for appended data after end-of-file marker"
  local end=""
  local last=""
  case "$FTYPE" in
    jpeg) end=$(jpeg_eoi_offset);;
    png)  last=$(last_offset_of 'IEND');      [[ -n "$last" ]] && end=$((last + 8));;
    pdf)  last=$(last_offset_of '%%EOF');     [[ -n "$last" ]] && end=$((last + 5));;
    gif)  last=$(last_offset_of $'\x3b');     [[ -n "$last" ]] && end=$((last + 1));;
    zip)  last=$(last_offset_of $'PK\x05\x06'); [[ -n "$last" ]] && end=$((last + 22));;
  esac

  local size
  size=$(stat -c %s "$TARGET_FILE")
  {
    echo "Format: $FTYPE"
    echo "File size: $size"
    if [[ -n "$end" ]]; then echo "Logical end (last EOF marker): $end"; else echo "Logical end: unknown (no recognized EOF marker)"; fi
    echo "Trailing bytes: $((size - ${end:-0}))"
  } > "$OUTDIR/append_check.txt"

  if [[ -n "$end" ]] && [[ $end -lt $size ]]; then
    local trailing=$((size - end))
    log_warn "Found $trailing bytes after the file's end marker!"
    dd if="$TARGET_FILE" bs=1 skip="$end" of="$OUTDIR/appended_data.bin" 2>/dev/null || true
    run_tool "$OUTDIR/appended_data.file.txt" file -b "$OUTDIR/appended_data.bin"
    run_tool "$OUTDIR/appended_data.strings.txt" strings -a -n 6 "$OUTDIR/appended_data.bin"
    add_finding 40 "Appended data: $trailing bytes after EOF marker (see appended_data.bin)"
  fi
}

search_and_extract_bin() { # signature scan with per-hit file-type validation
  local label="$1" pat="$2" expected="$3"
  local hits
  hits=$(LC_ALL=C grep -aobF -- "$pat" "$TARGET_FILE" 2>/dev/null || true)
  [[ -z "$hits" ]] && return 0

  local size
  size=$(stat -c %s "$TARGET_FILE")
  while IFS=: read -r bytepos _; do
    if [[ -z "$bytepos" ]] || [[ ! "$bytepos" =~ ^[0-9]+$ ]]; then continue; fi
    if [[ $bytepos -eq 0 ]]; then
      printf '%s @ 0 -> primary format (file itself), not embedded\n' "$label" >> "${OUTDIR}/signature_hits.validated.log"
      continue
    fi
    local outf="${OUTDIR}/signature_hits/${label}_${bytepos}.bin"
    dd if="$TARGET_FILE" bs=1 skip="$bytepos" count="$EXTRACT_SIZE" of="$outf" 2>/dev/null || true
    local ftype
    ftype=$(file -b "$outf")
    if [[ "$ftype" =~ $expected ]]; then
      printf '%s @ %s (%s) -> %s\n' "$label" "$bytepos" "$ftype" "$outf" >> "${OUTDIR}/signature_hits.validated.log"
      printf '%s @ %s -> %s\n' "$label" "$bytepos" "$outf" >> "${OUTDIR}/signature_hits.log"
    else
      printf '%s @ %s -> FALSE POSITIVE (%s)\n' "$label" "$bytepos" "$ftype" >> "${OUTDIR}/signature_hits.false_positives.log"
      rm -f "$outf"
    fi
  done <<< "$hits"
}

analysis_signatures() {
  log_info "Searching for embedded file signatures (validated)"
  mkdir -p "${OUTDIR}/signature_hits"
  local -A signatures=(
    ["png"]=$'\x89PNG|PNG image'
    ["jpg"]=$'\xFF\xD8\xFF|JPEG image'
    ["zip"]=$'PK\x03\x04|Zip archive'
    ["pdf"]=$'%PDF|PDF document'
    ["rar"]=$'Rar!|RAR archive'
    ["gzip"]=$'\x1f\x8b\x08|gzip compressed'
    ["7z"]=$'7z\xBC\xAF\x27\x1C|7-zip'
    ["elf"]=$'\x7FELF|ELF'
    ["html"]=$'<!DOCTYPE|HTML document'
    ["xml"]=$'<?xml|XML'
    ["bash"]=$'#!/bin/bash|POSIX shell script'
    ["python"]=$'#!/usr/bin/python|Python script'
  )
  local sig
  for sig in "${!signatures[@]}"; do
    search_and_extract_bin "$sig" "${signatures[$sig]%%|*}" "${signatures[$sig]#*|}"
  done

  if [[ -f "${OUTDIR}/signature_hits.validated.log" ]]; then
    local validated_count
    validated_count=$(grep -cv 'primary format' "${OUTDIR}/signature_hits.validated.log" 2>/dev/null || true)
    if [[ "${validated_count:-0}" -gt 0 ]]; then
      add_finding 25 "$validated_count validated embedded signature(s) (see signature_hits.validated.log)"
    fi
  fi
}

analysis_flags() {
  log_info "Searching for CTF flags and patterns"
  grep -Eio 'ctf\{[^}]{1,200}\}|flag\{[^}]{1,200}\}|FLAG\{[^}]{1,200}\}' "$OUTDIR/strings_all.txt" > "$OUTDIR/possible_flags.txt" 2>/dev/null || true
  grep -Eao 'ctf\{[^}]{1,200}\}|flag\{[^}]{1,200}\}|FLAG\{[^}]{1,200}\}' "$TARGET_FILE" > "$OUTDIR/possible_flags_raw.txt" 2>/dev/null || true
  if [[ -s "$OUTDIR/possible_flags.txt" ]] || [[ -s "$OUTDIR/possible_flags_raw.txt" ]]; then
    add_finding 20 "Possible flag(s) detected (see possible_flags.txt)"
  fi
}

analysis_base64_decode() {
  log_info "Attempting base64 decode previews"
  mkdir -p "$OUTDIR/base64_decoded"
  local count=0
  while IFS= read -r b64; do
    [[ -z "$b64" ]] && continue
    count=$((count + 1))
    [[ $count -gt 5 ]] && break
    local name
    name=$(printf '%s' "$b64" | md5sum | cut -c1-8)
    if printf '%s' "$b64" | base64 -d > "$OUTDIR/base64_decoded/${name}.bin" 2>/dev/null; then
      local dtype
      dtype=$(file -b "$OUTDIR/base64_decoded/${name}.bin")
      if [[ "$dtype" != *"data"* ]] && [[ -s "$OUTDIR/base64_decoded/${name}.bin" ]]; then
        printf '%s -> %s\n' "$b64" "$dtype" >> "$OUTDIR/base64_decoded/index.txt"
        add_finding 10 "Base64 candidate decodes to: $dtype (see base64_decoded/)"
      fi
    fi
  done < "$OUTDIR/strings_base64.txt"
}

analysis_steghide() {
  if [[ $NOSteghide -eq 1 ]]; then
    log_info "steghide skipped (--no-steghide)"
    return 0
  fi
  if ! command -v steghide >/dev/null 2>&1; then
    log_info "steghide not available, skipping"
    return 0
  fi
  if [[ ! "$FTYPE" =~ ^(jpeg|bmp|wav)$ ]]; then
    log_info "steghide skipped (unsupported carrier: $FTYPE; supports JPEG/BMP/WAV/AU)"
    return 0
  fi

  log_info "Checking for steganography with steghide"
  run_tool "$OUTDIR/steghide_info.txt" steghide info -sf "$TARGET_FILE" -p ""
  mkdir -p "$OUTDIR/steghide"
  if [[ -n "$PASSWORD" ]]; then
    log_info "Trying steghide extraction with provided password"
    run_tool "$OUTDIR/steghide_extract_pass.log" steghide extract -sf "$TARGET_FILE" -p "$PASSWORD" -xf "$OUTDIR/steghide/extracted" -f
  fi
  log_info "Trying steghide extraction with empty password"
  run_tool "$OUTDIR/steghide_extract_empty.log" steghide extract -sf "$TARGET_FILE" -p "" -xf "$OUTDIR/steghide/extracted_empty" -f

  if grep -qi 'file .* has been written\|wrote the data' "$OUTDIR/steghide_extract_empty.log" "$OUTDIR/steghide_extract_pass.log" 2>/dev/null; then
    find "$OUTDIR/steghide" -type f -exec file -b {} \; > "$OUTDIR/steghide_files.txt" 2>/dev/null || true
    add_finding 35 "steghide extraction produced file(s) (see steghide_files.txt)"
  fi
}

analysis_stegseek() {
  if [[ $AGGRESSIVE -eq 1 ]]; then
    if [[ -z "$WORDLIST" ]]; then log_die "Aggressive requires -w /path/to/wordlist"; fi
    if command -v stegseek >/dev/null 2>&1; then
      log_info "Running aggressive stegseek analysis with provided wordlist"
      mkdir -p "$OUTDIR/stegseek"
      run_tool "$OUTDIR/stegseek/stegseek_out.txt" stegseek "$TARGET_FILE" "$WORDLIST" "$OUTDIR/stegseek/extracted"
    else
      log_warn "stegseek not found, skipping aggressive mode"
    fi
  fi
}

analysis_zsteg() {
  if ! command -v zsteg >/dev/null 2>&1; then
    log_info "zsteg not found, skipping"
    return 0
  fi
  if [[ ! "$FTYPE" =~ ^(png|bmp)$ ]]; then
    log_info "zsteg skipped (unsupported carrier: $FTYPE; supports PNG/BMP)"
    return 0
  fi

  log_info "Running zsteg analysis for PNG/BMP LSB steganography"
  mkdir -p "$OUTDIR/zsteg"
  run_tool "$OUTDIR/zsteg.txt" zsteg -a "$TARGET_FILE"
  # Strict hit filter: only real embedded container types or flag-pattern text.
  # Random LSB noise produces garbage "text:"/"file: OpenPGP" lines — ignore those.
  grep -aE '\.\. file: (Zip archive|PNG image|JPEG image|gzip compressed|RAR archive|7-zip|PDF document|ELF|PE32|tar archive|ISO 9660|RIFF|WAVE audio|GIF image|BMP image|HTML document|XML|SQLite)' "$OUTDIR/zsteg.txt" > "$OUTDIR/zsteg_hits.txt" 2>/dev/null || true
  grep -aiE '\.\. text: ".*(flag\{|ctf\{|FLAG\{|SECRET\{|KEY\{)' "$OUTDIR/zsteg.txt" >> "$OUTDIR/zsteg_hits.txt" 2>/dev/null || true
  if [[ -s "$OUTDIR/zsteg_hits.txt" ]]; then
    add_finding 35 "zsteg detected payload in bit-plane (see zsteg_hits.txt)"
  fi
}

run_analysis() {
  log_info "Starting triage for: $(basename "$TARGET_FILE") [$FTYPE]"
  analysis_basic
  analysis_metadata
  analysis_binwalk
  analysis_append
  analysis_strings
  analysis_entropy
  analysis_flags
  analysis_base64_decode
  analysis_foremost
  analysis_steghide
  analysis_stegseek
  analysis_zsteg
  analysis_signatures
}

# --- Report ---
render_report() {
  log_info "Generating report: $REPORT_MD"
  local verdict preview_count base64_count url_count email_count
  local foremost_count sig_hits_count sig_fp_count steghide_count append_count processing_time
  verdict=$(verdict_score)
  preview_count=$(wc -l < "$OUTDIR/strings_preview.txt" 2>/dev/null || echo 0)
  base64_count=$(wc -l < "$OUTDIR/strings_base64.txt" 2>/dev/null || echo 0)
  url_count=$(wc -l < "$OUTDIR/strings_urls.txt" 2>/dev/null || echo 0)
  email_count=$(wc -l < "$OUTDIR/strings_emails.txt" 2>/dev/null || echo 0)
  foremost_count=0
  [[ -d "$OUTDIR/foremost" ]] && foremost_count=$(find "$OUTDIR/foremost" -type f 2>/dev/null | wc -l)
  sig_hits_count=0
  [[ -f "$OUTDIR/signature_hits.validated.log" ]] && sig_hits_count=$(grep -cv 'primary format' "$OUTDIR/signature_hits.validated.log" 2>/dev/null || true)
  sig_fp_count=0
  [[ -f "$OUTDIR/signature_hits.false_positives.log" ]] && sig_fp_count=$(wc -l < "$OUTDIR/signature_hits.false_positives.log" 2>/dev/null || echo 0)
  steghide_count=0
  [[ -d "$OUTDIR/steghide" ]] && steghide_count=$(find "$OUTDIR/steghide" -type f 2>/dev/null | wc -l)
  append_count=0
  [[ -f "$OUTDIR/appended_data.bin" ]] && append_count=$(stat -c %s "$OUTDIR/appended_data.bin" 2>/dev/null || echo 0)
  processing_time=$(( $(date +%s) - START_TIME ))

  {
    echo "# Stego Scan Report — $(basename "$TARGET_FILE")"
    echo ""
    echo "**Scan Tool:** Stego Scan v${VERSION}  "
    echo "**Target file:** \`$TARGET_FILE\`  "
    echo "**Detected format:** $FTYPE  "
    echo "**Run time:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  "
    echo "**Processing time:** $(format_duration "$processing_time")  "
    echo "**Raw artifacts directory:** \`$OUTDIR\`  "
    echo ""
    echo "## Verdict"
    echo "**${verdict}**"
    echo ""
    if [[ ${#FINDINGS[@]} -gt 0 ]]; then
      echo "### Findings"
      local i
      for ((i = 0; i < ${#FINDINGS[@]}; i++)); do
        local sev="${FIND_SEV[$i]}"
        local tag="info"
        [[ $sev -ge 35 ]] && tag="HIGH"
        [[ $sev -ge 20 && $sev -lt 35 ]] && tag="MED"
        [[ $sev -ge 10 && $sev -lt 20 ]] && tag="LOW"
        echo "- [$tag] ${FINDINGS[$i]}"
      done
      echo ""
    fi
    echo "## Quick Summary"
    echo "| Item | Count | Notes |"
    echo "|---|---:|---|"
    echo "| Recognizable strings | ${preview_count} | first ${PREVIEW_LINES} shown below |"
    echo "| Base64-like tokens | ${base64_count} | potential hidden blobs |"
    echo "| URLs found | ${url_count} | in strings analysis |"
    echo "| Email addresses | ${email_count} | in strings analysis |"
    echo "| Appended data | ${append_count} B | after EOF marker, if any |"
    echo "| Foremost carved files | ${foremost_count} | in \`foremost/\` |"
    echo "| Validated signatures | ${sig_hits_count} | in \`signature_hits.validated.log\` |"
    echo "| Rejected signature FPs | ${sig_fp_count} | in \`signature_hits.false_positives.log\` |"
    echo "| Steghide extracted files | ${steghide_count} | in \`steghide/\` |"
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
      if [[ -s "$OUTDIR/exiftool_keyfields.txt" ]]; then
        echo "### Key Fields (Comment/Artist/GPS/etc.)"
        echo '```'
        cat "$OUTDIR/exiftool_keyfields.txt" || true
        echo '```'
        echo ""
      fi
    fi
    if [[ -f "$OUTDIR/append_check.txt" ]]; then
      echo "## Appended Data Check"
      echo '```'
      cat "$OUTDIR/append_check.txt" || true
      echo '```'
      echo ""
      if [[ -f "$OUTDIR/appended_data.file.txt" ]]; then
        echo "### Appended Blob Analysis"
        echo '```'
        cat "$OUTDIR/appended_data.file.txt" 2>/dev/null || true
        echo '```'
        echo ""
        if [[ -s "$OUTDIR/appended_data.strings.txt" ]]; then
          echo '```'
          head -n 20 "$OUTDIR/appended_data.strings.txt" || true
          echo '```'
          echo ""
        fi
      fi
    fi
    if [[ -f "$OUTDIR/entropy.txt" ]]; then
      echo "## Entropy Analysis"
      echo '```'
      cat "$OUTDIR/entropy.txt" || true
      echo ""
      echo "Note: entropy close to 8.0 may indicate encrypted or compressed data."
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
    if [[ -d "$OUTDIR/base64_decoded" ]] && [[ -s "$OUTDIR/base64_decoded/index.txt" ]]; then
      echo "### Base64 Decode Previews"
      echo '```'
      cat "$OUTDIR/base64_decoded/index.txt" || true
      echo '```'
      echo ""
    fi
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
    if [[ -s "$OUTDIR/possible_flags.txt" ]] || [[ -s "$OUTDIR/possible_flags_raw.txt" ]]; then
      echo '```'
      cat "$OUTDIR/possible_flags.txt" "$OUTDIR/possible_flags_raw.txt" 2>/dev/null | sort -u
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
    if [[ -f "$OUTDIR/signature_hits.validated.log" ]]; then
      echo "### Validated Embedded Signatures"
      echo '```'
      grep -v 'primary format' "$OUTDIR/signature_hits.validated.log" || true
      echo '```'
      echo ""
    else
      echo "_No validated signatures found_"
    fi
    if [[ -f "$OUTDIR/signature_hits.false_positives.log" ]]; then
      echo "### Rejected Signature False Positives (${sig_fp_count})"
      echo '```'
      head -n 15 "$OUTDIR/signature_hits.false_positives.log" || true
      echo '```'
      echo ""
    fi
    echo ""
    echo "## Steganography Analysis"
    if [[ -f "$OUTDIR/steghide_info.txt" ]]; then
      echo "### Steghide Info"
      echo '```'
      grep -v "unknown argument" "$OUTDIR/steghide_info.txt" | head -n 10 || true
      echo '```'
      if [[ -f "$OUTDIR/steghide_files.txt" ]]; then
        echo "### Steghide Extracted Files"
        echo '```'
        cat "$OUTDIR/steghide_files.txt" || true
        echo '```'
      else
        echo "_No steghide-extracted files (empty or password-protected)_"
      fi
    else
      echo "_steghide not run (skipped, unsupported carrier, or not installed)_"
    fi
    echo ""
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
    echo "## Recommended Actions"
    local has_recommendation=0
    for ((i = 0; i < ${#FINDINGS[@]}; i++)); do
      case "${FINDINGS[$i]}" in
        *"Appended data"*)
          echo "- CARVE the appended blob: inspect \`appended_data.bin\` (\`file\`/strings show \`appended_data.file.txt\`); \`7z x\` or \`unzip\` it if it's an archive."
          has_recommendation=1;;
        *"zsteg detected"*)
          echo "- Extract the zsteg payload with \`zsteg -E '<spec>' file\` using the spec from \`zsteg_hits.txt\`, then run \`file\` on the result."
          has_recommendation=1;;
        *"steghide extraction"*)
          echo "- Read extracted steghide files; if password-protected, try \`stegseek\` with a wordlist."
          has_recommendation=1;;
        *"validated embedded"*)
          echo "- Inspect \`signature_hits/\` and \`binwalk_extracted/\`; open recovered files and re-run this scanner on them."
          has_recommendation=1;;
        *"Possible flag"*)
          echo "- The flag string itself is already in \`possible_flags.txt\` — verify case and whitespace variants."
          has_recommendation=1;;
        *"High-entropy"*)
          echo "- High entropy suggests encrypted/compressed payload; combine with binwalk entropy (\`binwalk -E\`) and check \`appended_data.bin\`."
          has_recommendation=1;;
      esac
    done
    if [[ $has_recommendation -eq 0 ]]; then
      echo "- No automated findings; try visual inspection (bit-plane viewers for images) and audio spectrograms for WAV files."
    fi
    echo ""
    echo "---"
    echo "*Report generated by Stego Scan v${VERSION}*  "
    echo "*Raw artifacts & full logs are in* \`$OUTDIR\`  "
  } > "$REPORT_MD"

  {
    echo "Completed: $(date)"
    echo "Processing time: $(format_duration "$processing_time")"
  } >> "$PROCESS_LOG"
}

write_csv_line() {
  local duration=$1
  local signals=""
  local i
  for ((i = 0; i < ${#FINDINGS[@]}; i++)); do
    signals+="${FINDINGS[$i]}; "
  done
  signals=${signals%; }
  local line
  printf -v line '"%s","%s","%s","%s","%s","%s"' \
    "$TARGET_FILE" "$FTYPE" "$(verdict_score)" "$signals" "$duration" "$(basename "$TARGET_FILE")"
  if [[ "${CSV:-0}" -eq 1 ]]; then
    if [[ -n "${CSV_FILE:-}" ]]; then printf '%s\n' "$line" >> "$CSV_FILE"; else printf '%s\n' "$line"; fi
  fi
}

offer_report() {
  if [[ "${QUIET}" -eq 0 ]] && [[ -t 0 ]]; then
    echo
    read -p "Would you like to view the report now? (y/N) " -n 1 -r || true
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
}

# --- Single-file pipeline (used by both single and dir mode) ---
run_single_file() {
  local start
  start=$(date +%s)
  FINDINGS=()
  FIND_SEV=()
  detect_format
  setup_environment
  run_analysis
  render_report
  local elapsed=$(( $(date +%s) - start ))
  log_ok "Scan complete in $(format_duration "$elapsed") [$FTYPE]"
  log_info "Markdown report saved: $REPORT_MD"
  log_info "Raw artifacts saved in: $OUTDIR"
  if [[ $elapsed -gt 0 ]]; then write_csv_line "$elapsed"; fi
}

# --- Main Entry Point ---
main() {
  check_dependencies
  parse_args "$@"
  START_TIME=$(date +%s)

  if [[ -n "${DIR_MODE:-}" ]]; then
    log_info "Bulk triage mode: $DIR_MODE"
    if [[ "${CSV:-0}" -eq 1 ]]; then
      CSV_FILE="${DIR_MODE}/stegoscan_summary.csv"
      printf '"file","type","verdict","signals","duration_s","basename"\n' > "$CSV_FILE"
    fi
    local f
    for f in "$DIR_MODE"/*; do
      [[ -f "$f" ]] || continue
      case "$(basename "$f")" in
        stegoscan_summary.csv|*_report.md) continue;;
      esac
      TARGET_FILE="$f"
      log_info "=== $(basename "$f") ==="
      run_single_file || true
    done
    log_ok "Bulk triage complete. Reports next to each file."
    if [[ "${CSV:-0}" -eq 1 ]]; then log_info "CSV summary: $CSV_FILE"; fi
    exit 0
  fi

  run_single_file
  offer_report
}

main "$@"
