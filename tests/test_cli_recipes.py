from __future__ import annotations

import json
from pathlib import Path

from repo_sentinel.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_recipe_local_text_scan_smoke(
    capsys,
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(["scan", "--format", "text", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "[ERROR]" in captured.out
    assert "High-entropy findings" in captured.out


def test_recipe_json_output_to_file_smoke(
    capsys, tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    output_path = tmp_path / "repo-sentinel.json"

    exit_code = main(["scan", "--output", str(output_path), str(fixture_root)])
    captured = capsys.readouterr()
    report = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert captured.out == ""
    assert output_path.is_file()
    assert isinstance(report["findings"], list)
    assert "missing_files" in report


def test_recipe_fail_on_severity_smoke(
    capsys,
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(["scan", "--fail-on-severity", "error", str(fixture_root)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 1
    assert any(finding["severity"] == "error" for finding in report["findings"])


def test_recipe_run_with_baseline_suppression_smoke(
    capsys, tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"

    write_exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(fixture_root)]
    )
    assert write_exit_code == 0
    capsys.readouterr()

    exit_code = main(["scan", "--baseline", str(baseline_path), str(fixture_root)])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 0
    assert report["findings"] == []


def test_recipe_prune_baseline_smoke(
    capsys, tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"
    pruned_path = tmp_path / "baseline.pruned.json"

    write_exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(fixture_root)]
    )
    assert write_exit_code == 0
    capsys.readouterr()

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline["findings"].append(
        {
            "fingerprint": "stale-fingerprint",
            "kind": "suspicious_file",
            "path": "stale.key",
        }
    )
    baseline_path.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            "--baseline",
            str(baseline_path),
            "--prune-baseline",
            str(pruned_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    pruned = json.loads(pruned_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["findings"] == []
    assert pruned_path.is_file()
    assert all("fingerprint" in finding for finding in pruned["findings"])
    assert all(
        finding["fingerprint"] != "stale-fingerprint"
        for finding in pruned["findings"]
    )


def test_recipe_generate_sarif_to_file_smoke(
    capsys, tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    output_path = tmp_path / "repo-sentinel.sarif"

    exit_code = main(
        [
            "scan",
            "--format",
            "sarif",
            "--output",
            str(output_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()
    sarif = json.loads(output_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert captured.out == ""
    assert output_path.is_file()
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
