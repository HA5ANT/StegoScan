# StegoScan Context

## 1. Project purpose
StegoScan is a bash-based automated steganography triage tool designed to assist in CTF challenges and security training labs. It automates tool execution (binwalk, foremost, steghide, etc.), performs string analysis, and generates a concise Markdown report for quick manual review.

## 2. High-level architecture
The project is a single-script CLI utility that follows a modular procedural flow. It leverages external security tools as dependencies to perform analysis. It produces two types of output: a structured Markdown report in the target file's directory and a timestamped folder containing raw artifacts (logs, tool outputs, extracted data).

## 3. Repository map
- `README.md`: Project overview, usage documentation, and dependency list.
- `stego-scan.sh`: The core executable bash script managing the entire workflow.
- `meme.jpg`: Sample input file for testing.

## 4. Main execution flow
1. **Argument Parsing**: The script processes CLI flags, sets configuration, and verifies the target file.
2. **Tool Validation**: Checks for required and optional dependencies.
3. **Setup**: Creates a timestamped output directory (`extracted_<basename>_<timestamp>`).
4. **Analysis Pipeline**: Sequentially executes various analysis tools (exiftool, binwalk, strings, foremost, steghide, etc.), redirecting all outputs to text files in the output directory.
5. **Signature Extraction**: Performs custom binary signature searching and carves identified chunks.
6. **Reporting**: Compiles findings (counts, excerpts, summaries) into a Markdown report.
7. **Cleanup/Finalization**: Confirms completion and offers an optional view of the generated report.

## 5. Key modules and responsibilities
- **Argument Handling**: CLI configuration and input validation.
- **Dependency Manager**: Checks for presence of security tools.
- **Artifact Manager**: Manages folder creation and log redirection (`run_quiet` helper).
- **Scanner/Extractor**: Performs binary signature detection and automated carving.
- **Reporter**: Markdown document generator consolidating findings.

## 6. Dependencies and external tools
- **Required (POSIX-ish)**: `bash`, `file`, `strings`, `dd`, `grep`, `awk`, `sed`, `head`, `tail`.
- **Optional (Performance-dependent)**: `exiftool`, `binwalk`, `foremost`, `steghide`, `stegseek`, `ent`, `identify` (ImageMagick), `zsteg`, `stegdetect`.

## 7. Current strengths
- Automated and quick triage.
- Standardized, consistent output format (Markdown).
- Easy to extend via new tool integrations.
- Non-destructive (reads target file without modification).

## 8. Current issues and technical debt
- **Error Handling**: Brittle error handling with some tools; reliance on `|| true` to prevent script failure on tool failure.
- **Hardcoding**: Magic numbers (e.g., `524288` bytes) and paths are mostly hardcoded within the script.
- **Reporting logic**: Massive `cat` blocks inside the script make it hard to maintain/modify the report structure.
- **No tests**: Lack of automated tests to verify analysis logic or file extraction correctness.
- **Scalability**: Processing large files with the current `grep`-based signature approach may be slow.

## 9. Risks and fragile areas
- **Dependency Reliability**: The script relies entirely on external tools that might be installed in different paths or version-variant (e.g., `binwalk` options changing).
- **Performance**: The `grep -aobF` search approach for binary signatures iterates over the full file repeatedly.
- **Safety**: Minimal verification of input paths or generated output files for malicious content (standard CLI tool risk).

## 10. Testing and validation status
- **None**: No existing automated test suite. Manual validation is currently required for all changes.

## 11. Recommended next refactor targets
- Extract report generation logic into a separate template or function block.
- Modularize tool execution logic to reduce code duplication and improve error handling.
- Implement a basic test harness for verifying tool invocation.
- Replace repeated `grep` scanning for signatures with a more efficient single-pass binary analyzer if needed.

## 12. Questions / unknowns
- How to handle cross-platform (WSL vs. Linux native) pathing differences if tools move?
- Should the tool be modularized into a library of functions for sourcing in other scripts?

## 13. Working conventions for future AI edits
- **Bash standard**: Follow POSIX-compliant conventions where possible; prioritize readability for security-centric bash scripting.
- **Editing**: Always prioritize modularity. When adding features, use helper functions for output, log file generation, and tool execution.
- **Validation**: Every change must be followed by a test run on `meme.jpg` to ensure no regression in report generation.
