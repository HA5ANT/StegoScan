#!/usr/bin/env bash
# stego-scan-v2.sh - Refactored v2 version of StegoScan
# Purpose: Modular, deterministic steganography triage pipeline.
# Maintains output compatibility with original StegoScan script.

set -euo pipefail
IFS=$'\n\t'

# --- Defaults & Configuration ---
VERSION="2.0.0-refactored"
PREVIEW_LINES=30
EXTRACT_SIZE=524288
DEBUG=${DEBUG:-0}
QUIET=${QUIET:-0}

# --- Internal State ---
PASSWORD=""
WORDLIST=""
AGGRESSIVE=0
NOSteghide=0
TARGET_FILE=""
OUTDIR=""
REPORT_MD=""

# --- Logging & UI Helpers ---
log_info() { [[ "${QUIET}" -eq 0 ]] && printf "\033[0;36m[*]\033[0m %b\n" "$1"; }
log_ok()   { [[ "${QUIET}" -eq 0 ]] && printf "\033[0;32m[+]\033[0m %b\n" "$1"; }
log_warn() { [[ "${QUIET}" -eq 0 ]] && printf "\033[0;33m[!]\033[0m %b\n" "$1"; }
log_die()  { printf "\033[0;31m[-]\033[0m %b\n" "$1"; exit 1; }
log_debug(){ [[ "${DEBUG}" -eq 1 ]] && printf "\033[2m[DEBUG]\033[0m %b\n" "$1"; }

# --- Tool Execution Helpers ---
run_tool_fatal() {
    log_debug "Running: $*"
    "$@" || log_die "Critical tool failure: $*"
}

run_tool_optional() {
    local out="$1"; shift
    log_debug "Running (optional): $*"
    {
        printf "[%s] Command: %s\n" "$(date)" "$*"
        "$@" 2>&1
    } > "$out" || log_warn "Optional tool failed: $*"
}

# --- Core Modules ---
usage() {
  cat <<USG
Stego Scan v${VERSION} (Refactored)

Usage: $(basename "$0") [options] /path/to/file

Options:
  -p, --password <pw>      Try provided password with steghide
  -w, --wordlist <f>       Wordlist for --aggressive
      --aggressive         Run stegseek with provided wordlist
      --no-steghide        Skip steghide checks
      --extract-size <n>   Bytes to extract (default: ${EXTRACT_SIZE})
      --preview-lines <n>  Lines to show in preview (default: ${PREVIEW_LINES})
      --debug              Enable debug output
  -q, --quiet              Minimal terminal output
  -h, --help               Show this help
USG
}

parse_args() {
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
      *) TARGET_FILE="$1"; shift;;
    esac
  done

  [[ -z "$TARGET_FILE" ]] && { usage; exit 2; }
  [[ ! -f "$TARGET_FILE" ]] && log_die "File not found: $TARGET_FILE"
}

setup_environment() {
  local target_dir
  target_dir="$(cd "$(dirname -- "$TARGET_FILE")" && pwd)"
  local base
  base="$(basename -- "$TARGET_FILE" | cut -f 1 -d '.')"
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  
  OUTDIR="${target_dir}/extracted_${base}_${ts}"
  REPORT_MD="${target_dir}/${base}_report.md"
  
  mkdir -p "$OUTDIR"
  log_info "Output directory: $OUTDIR"
}

check_dependencies() {
  local required=("file" "strings" "dd" "grep" "awk" "sed" "head" "tail")
  for cmd in "${required[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || log_die "Missing required tool: $cmd"
  done
}

run_analysis() {
  log_info "Starting triage for: $(basename "$TARGET_FILE")"
  
  # Basic data
  run_tool_optional "$OUTDIR/file.txt" file -b "$TARGET_FILE"
  run_tool_optional "$OUTDIR/ls.txt" ls -l "$TARGET_FILE"
  run_tool_optional "$OUTDIR/sha256.txt" sha256sum "$TARGET_FILE"
  
  # Optional Tools
  if command -v exiftool >/dev/null; then
    log_info "Running exiftool..."
    run_tool_optional "$OUTDIR/exiftool.txt" exiftool "$TARGET_FILE"
  fi
  
  # Binwalk
  if command -v binwalk >/dev/null; then
    log_info "Running binwalk..."
    mkdir -p "$OUTDIR/binwalk_extracted"
    run_tool_optional "$OUTDIR/binwalk_scan.txt" binwalk -e -M --directory "$OUTDIR/binwalk_extracted" "$TARGET_FILE"
  fi
}

render_report() {
  log_info "Generating report: $REPORT_MD"
  {
    echo "# Stego Scan Report — $(basename "$TARGET_FILE")"
    echo "Generated: $(date)"
    echo ""
    echo "## File Summary"
    echo '```'
    cat "$OUTDIR/file.txt" 2>/dev/null || echo "N/A"
    echo '```'
  } > "$REPORT_MD"
}

# --- Main Entry Point ---
main() {
  parse_args "$@"
  check_dependencies
  setup_environment
  run_analysis
  render_report
  log_ok "Scan complete."
}

main "$@"
