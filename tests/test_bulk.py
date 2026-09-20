"""Bulk triage: walking, ranking, parallel execution and the summary."""

from __future__ import annotations

import csv
import io
import json
import os

from conftest import make_jpeg, make_png, make_zip, write
from stegoscan.analyzers.base import Options
from stegoscan.bulk import BulkResult, rank, triage, walk, write_summary
from stegoscan.report import csv_report


def populate(tmp_path):
    """A small corpus: one carrier with a payload, one clean, one flag file."""
    write(tmp_path, "carrier.jpg", make_jpeg() + make_zip())
    write(tmp_path, "clean.png", make_png())
    write(tmp_path, "notes.txt", b"FLAG{bulk_triage_flag}\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    write(nested, "deep.jpg", make_jpeg() + make_zip())
    return str(tmp_path)


def test_walk_is_flat_by_default(tmp_path):
    root = populate(tmp_path)
    found = walk(root, recursive=False)
    assert len(found) == 3
    assert all("nested" not in path for path in found)


def test_walk_recurses_on_request(tmp_path):
    root = populate(tmp_path)
    found = walk(root, recursive=True)
    assert len(found) == 4
    assert any("deep.jpg" in path for path in found)


def test_walk_excludes_the_output_directory(tmp_path):
    root = populate(tmp_path)
    out = os.path.join(root, "stegoscan-out")
    os.makedirs(out)
    write(out, "leftover.jpg", make_jpeg())
    found = walk(root, recursive=True, exclude=[out])
    assert all("stegoscan-out" not in path for path in found)


def test_walk_skips_generated_reports(tmp_path):
    write(tmp_path, "report.md", b"# previous run")
    write(tmp_path, "summary.csv", b"file,verdict")
    write(tmp_path, "real.png", make_png())
    found = walk(str(tmp_path), recursive=False)
    assert [os.path.basename(p) for p in found] == ["real.png"]


def test_triage_ranks_most_suspicious_first(tmp_path):
    root = populate(tmp_path)
    out = str(tmp_path / "out")
    results = triage(root, Options(write_artifacts=False), output_base=out, recursive=True, jobs=1)

    assert len(results) == 4
    ranks = [r.rank for r in results]
    assert ranks == sorted(ranks, reverse=True)
    assert results[0].verdict == "CONFIRMED"
    assert results[-1].verdict == "CLEAN"


def test_triage_runs_in_parallel_with_the_same_outcome(tmp_path):
    root = populate(tmp_path)
    out = str(tmp_path / "out")
    serial = triage(root, Options(write_artifacts=False), output_base=out, recursive=True, jobs=1)
    parallel = triage(root, Options(write_artifacts=False), output_base=out, recursive=True, jobs=2)

    assert [(r.path, r.verdict) for r in serial] == [(r.path, r.verdict) for r in parallel]


def test_every_result_carries_its_coverage(tmp_path):
    root = populate(tmp_path)
    results = triage(
        root, Options(write_artifacts=False), output_base=str(tmp_path / "out"), jobs=1
    )
    for result in results:
        assert result.coverage_applicable > 0
        assert result.coverage_ran <= result.coverage_applicable


def test_unreadable_file_is_recorded_not_fatal(tmp_path):
    populate(tmp_path)
    bad = write(tmp_path, "unreadable.bin", b"data")
    os.chmod(bad, 0o000)
    try:
        results = triage(
            str(tmp_path), Options(write_artifacts=False), output_base=str(tmp_path / "o"), jobs=1
        )
    finally:
        os.chmod(bad, 0o644)

    assert len(results) == 4  # flat walk: 3 good + the unreadable one
    errored = [r for r in results if not r.ok]
    if errored:  # running as root makes everything readable
        assert "unreadable.bin" in errored[0].path


def test_progress_callback_fires_once_per_file(tmp_path):
    root = populate(tmp_path)
    seen = []
    triage(
        root,
        Options(write_artifacts=False),
        output_base=str(tmp_path / "out"),
        jobs=1,
        progress=lambda done, total, result: seen.append((done, total)),
    )
    assert [d for d, _ in seen] == [1, 2, 3]
    assert all(total == 3 for _, total in seen)


def test_per_file_reports_are_written(tmp_path):
    root = populate(tmp_path)
    out = str(tmp_path / "out")
    results = triage(root, Options(), output_base=out, jobs=1, formats=("markdown", "json"))
    for result in results:
        assert os.path.isfile(os.path.join(result.output_dir, "report.md"))
        assert os.path.isfile(os.path.join(result.output_dir, "report.json"))


def test_summary_files_are_written_and_parseable(tmp_path):
    root = populate(tmp_path)
    out = str(tmp_path / "out")
    results = triage(root, Options(write_artifacts=False), output_base=out, jobs=1)
    csv_path, json_path = write_summary(results, out)

    rows = list(csv.DictReader(io.StringIO(open(csv_path, encoding="utf-8").read())))
    assert len(rows) == len(results)
    assert rows[0]["verdict"] == results[0].verdict
    assert set(csv_report.COLUMNS) == set(rows[0].keys())

    payload = json.loads(open(json_path, encoding="utf-8").read())
    assert payload["scanned"] == len(results)
    assert payload["results"][0]["verdict"] == results[0].verdict


def test_rank_orders_by_verdict_then_score():
    results = [
        BulkResult(path="b", verdict="NOTABLE", rank=1, score=5),
        BulkResult(path="a", verdict="CONFIRMED", rank=3, score=1),
        BulkResult(path="c", verdict="NOTABLE", rank=1, score=9),
    ]
    assert [r.path for r in rank(results)] == ["a", "c", "b"]


def test_empty_directory_yields_no_results(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert triage(str(empty), Options(), output_base=str(tmp_path / "o")) == []
