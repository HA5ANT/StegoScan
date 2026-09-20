"""CLI behaviour: invocation forms, exit codes, and output routing.

These run the real command line in a subprocess. The CLI is the only interface
most users touch, so its contract -- how you start it, what it prints where,
and what it returns to the shell -- is worth testing end to end.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from conftest import make_jpeg, make_png, make_zip, write

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "stegoscan", *args],
        cwd=cwd or REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
    )


# --- invocation forms -------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["-m", "stegoscan"],
        ["stegoscan"],  # python3 stegoscan  -- a directory, run via its __main__
        [os.path.join("stegoscan", "__main__.py")],
    ],
)
def test_every_invocation_form_works(argv):
    """Regression: `python3 stegoscan` used to die with an ImportError.

    Python executes a directory's __main__.py with no package context, so the
    relative import failed. Running from a clone is the documented path, so the
    form people actually type has to work.
    """
    completed = subprocess.run(
        [sys.executable, *argv, "--version"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    assert b"stegoscan" in completed.stdout


# --- exit codes -------------------------------------------------------------


def test_clean_file_exits_zero(clean_jpeg):
    assert run_cli(clean_jpeg, "--no-artifacts").returncode == 0


def test_confirmed_finding_exits_thirty(jpeg_with_appended_zip):
    assert run_cli(jpeg_with_appended_zip, "--no-artifacts").returncode == 30


def test_missing_file_exits_one(tmp_path):
    completed = run_cli(str(tmp_path / "absent.jpg"), "--no-artifacts")
    assert completed.returncode == 1
    assert b"no such file" in completed.stderr


def test_no_target_exits_one():
    completed = run_cli()
    assert completed.returncode == 1
    assert b"TARGET" in completed.stderr


def test_worst_verdict_wins_across_targets(clean_jpeg, jpeg_with_appended_zip):
    completed = run_cli(clean_jpeg, jpeg_with_appended_zip, "--no-artifacts")
    assert completed.returncode == 30


# --- output routing ---------------------------------------------------------


def test_results_go_to_stdout_not_stderr(jpeg_with_appended_zip):
    completed = run_cli(jpeg_with_appended_zip, "--no-artifacts", "--no-color")
    assert b"CONFIRMED" in completed.stdout


def test_json_output_is_parseable(jpeg_with_appended_zip):
    completed = run_cli(jpeg_with_appended_zip, "--no-artifacts", "--print", "json")
    payload = json.loads(completed.stdout.decode())
    assert payload["verdict"] == "CONFIRMED"
    assert payload["integrity"]["verified_unchanged"] is True


def test_markdown_output_renders(jpeg_with_appended_zip):
    completed = run_cli(jpeg_with_appended_zip, "--no-artifacts", "--print", "markdown")
    assert completed.stdout.startswith(b"# StegoScan report")


def test_print_none_is_silent_on_stdout(jpeg_with_appended_zip):
    completed = run_cli(jpeg_with_appended_zip, "--no-artifacts", "--print", "none")
    assert completed.stdout.strip() == b""
    assert completed.returncode == 30


def test_no_color_suppresses_escape_codes(jpeg_with_appended_zip):
    completed = run_cli(jpeg_with_appended_zip, "--no-artifacts", "--no-color")
    assert b"\033[" not in completed.stdout


# --- informational modes ----------------------------------------------------


def test_list_analyzers_names_requirements():
    completed = run_cli("--list-analyzers")
    assert completed.returncode == 0
    out = completed.stdout.decode()
    assert "signatures" in out and "steghide" in out


def test_help_documents_exit_codes():
    completed = run_cli("--help")
    assert completed.returncode == 0
    assert b"Exit codes" in completed.stdout


# --- artifacts --------------------------------------------------------------


def test_output_dir_is_honoured(jpeg_with_appended_zip, tmp_path):
    out = str(tmp_path / "chosen")
    completed = run_cli(jpeg_with_appended_zip, "-o", out)
    assert completed.returncode == 30
    assert os.path.isfile(os.path.join(out, "report.md"))
    assert os.path.isfile(os.path.join(out, "report.json"))


def test_no_artifacts_leaves_no_output_dir(jpeg_with_appended_zip, tmp_path):
    before = set(os.listdir(str(tmp_path)))
    run_cli(jpeg_with_appended_zip, "--no-artifacts", cwd=str(tmp_path))
    assert set(os.listdir(str(tmp_path))) == before


def test_directory_target_runs_bulk_triage(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    write(corpus, "clean.png", make_png())
    write(corpus, "carrier.jpg", make_jpeg() + make_zip())

    completed = run_cli(str(corpus), "--no-artifacts", "--no-color")
    out = completed.stdout.decode()
    assert "2 file(s) scanned" in out
    assert "CONFIRMED" in out
    assert completed.returncode == 30


# --- builtin-only mode ------------------------------------------------------


def test_no_external_skips_tools_and_lowers_coverage(jpeg_with_appended_zip):
    """Turning tools off must lower coverage visibly, never silently."""
    completed = run_cli(
        jpeg_with_appended_zip, "--no-external", "--no-artifacts", "--print", "json"
    )
    payload = json.loads(completed.stdout.decode())

    external = [a for a in payload["analyzers"] if a["status"] == "skipped"]
    assert external, "external analyzers should be reported as skipped"
    assert any("--no-external" in a["reason"] for a in external)
    assert payload["coverage"]["complete"] is False
    # Detection itself is builtin, so the payload is still found.
    assert payload["verdict"] == "CONFIRMED"


def test_no_external_still_detects_builtin_findings(jpeg_with_appended_zip):
    with_tools = run_cli(jpeg_with_appended_zip, "--no-artifacts", "--print", "json")
    without = run_cli(jpeg_with_appended_zip, "--no-external", "--no-artifacts", "--print", "json")
    assert json.loads(with_tools.stdout.decode())["verdict"] == "CONFIRMED"
    assert json.loads(without.stdout.decode())["verdict"] == "CONFIRMED"
