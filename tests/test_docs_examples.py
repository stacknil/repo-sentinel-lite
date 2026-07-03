from __future__ import annotations

from pathlib import Path

from repo_sentinel.cli import main
from repo_sentinel.scanner import (
    _baseline_from_report,
    format_baseline,
    load_baseline,
    scan_repository,
)

ROOT = Path(__file__).resolve().parents[1]
FIXED_BASELINE_TIMESTAMP = "2026-06-19T00:00:00Z"


def test_sample_baseline_is_valid_and_redacted() -> None:
    baseline_path = ROOT / "examples" / "sample-baseline.json"
    baseline_text = baseline_path.read_text(encoding="utf-8")
    baseline = load_baseline(baseline_path)

    assert baseline["schema_version"] == 1
    assert len(baseline["findings"]) == 3
    assert "<redacted:sha256:" in baseline_text
    assert "0123456789abcdef0123456789abcdef" not in baseline_text


def test_dirty_and_clean_scan_outputs_match_examples(capsys) -> None:
    for name in ("dirty", "clean"):
        exit_code = main(
            [
                "scan",
                "--format",
                "json",
                str(ROOT / "examples" / f"{name}-repo"),
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == 0
        assert captured.err == ""
        assert captured.out == _example_output(f"{name}-scan.json")


def test_dirty_and_clean_baseline_outputs_match_examples() -> None:
    for name in ("dirty", "clean"):
        report = scan_repository(ROOT / "examples" / f"{name}-repo")
        baseline = _baseline_from_report(report)
        baseline["generated_at"] = FIXED_BASELINE_TIMESTAMP

        assert format_baseline(baseline) == _example_output(
            f"{name}-baseline.json"
        )


def test_dirty_and_clean_fail_on_findings_outputs_match_examples(capsys) -> None:
    expected_exit_codes = {"dirty": 1, "clean": 0}

    for name, expected_exit_code in expected_exit_codes.items():
        exit_code = main(
            [
                "scan",
                "--format",
                "text",
                "--fail-on-findings",
                str(ROOT / "examples" / f"{name}-repo"),
            ]
        )
        captured = capsys.readouterr()

        assert exit_code == expected_exit_code
        assert captured.err == ""
        assert captured.out == _example_output(
            f"{name}-fail-on-findings.txt"
        )


def test_example_outputs_are_redacted() -> None:
    raw_token = "0123456789abcdef0123456789abcdef"

    for output_path in (ROOT / "examples" / "outputs").iterdir():
        assert raw_token not in output_path.read_text(encoding="utf-8")


def test_examples_readme_summarizes_expected_outputs() -> None:
    readme = (ROOT / "examples" / "README.md").read_text(encoding="utf-8")

    for required in (
        "## Expected Output Summary",
        "| Fixture | Scan summary | Baseline summary | Fail-on-findings behavior |",
        "`dirty-repo` | 2 suspicious files, 2 missing required files, "
        "1 redacted high-entropy finding",
        "5 reviewable findings with the high-entropy token redacted",
        "exits `1` and prints the text finding summary",
        "`clean-repo` | no findings",
        "empty baseline",
        "exits `0` and prints `No findings.`",
    ):
        assert required in readme


def _example_output(filename: str) -> str:
    return (ROOT / "examples" / "outputs" / filename).read_text(
        encoding="utf-8"
    )
