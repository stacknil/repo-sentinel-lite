from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

import pytest

from repo_sentinel import __version__
from repo_sentinel.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_help_command_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert "scan" in captured.out
    assert (
        "Scan repositories for common suspicious files and secrets-like strings."
        in captured.out
    )


def test_version_option_outputs_package_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 0
    assert __version__ in captured.out


def test_scan_command_emits_stable_json(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    expected_output = (FIXTURES_DIR / "sample_repo_report.json").read_text(
        encoding="utf-8"
    )

    exit_code = main(["scan", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == expected_output


def test_scan_command_returns_success_when_findings_present_and_flag_absent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    expected_output = (FIXTURES_DIR / "sample_repo_report.json").read_text(
        encoding="utf-8"
    )

    exit_code = main(["scan", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == expected_output


def test_scan_command_returns_failure_when_findings_present_and_flag_enabled(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(
        ["scan", "--format", "text", "--fail-on-findings", str(fixture_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == (
        "Suspicious files (4):\n"
        "- .env\n"
        "- certs/service.pem\n"
        "- keys/id_rsa\n"
        "- vault/archive.kdbx\n"
        "\n"
        "Missing required files (2):\n"
        "- .gitignore\n"
        "- LICENSE\n"
        "\n"
        "High-entropy findings (1):\n"
        "- notes/tokens.txt:2 entropy=4.0 token=0123456789abcdef0123456789abcdef\n"
    )


def test_scan_command_emits_concise_text_report(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(["scan", "--format", "text", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == (
        "Suspicious files (4):\n"
        "- .env\n"
        "- certs/service.pem\n"
        "- keys/id_rsa\n"
        "- vault/archive.kdbx\n"
        "\n"
        "Missing required files (2):\n"
        "- .gitignore\n"
        "- LICENSE\n"
        "\n"
        "High-entropy findings (1):\n"
        "- notes/tokens.txt:2 entropy=4.0 token=0123456789abcdef0123456789abcdef\n"
    )


def test_scan_command_writes_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"
    expected_output = (FIXTURES_DIR / "sample_repo_report.json").read_text(
        encoding="utf-8"
    )

    exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(fixture_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == expected_output

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert baseline["schema_version"] == 1
    assert baseline["findings"] == [
        {
            "entropy": 4.0,
            "file": "notes/tokens.txt",
            "kind": "high_entropy",
            "line": 2,
            "token": "0123456789abcdef0123456789abcdef",
        },
        {"kind": "missing_file", "path": ".gitignore"},
        {"kind": "missing_file", "path": "LICENSE"},
        {"kind": "suspicious_file", "path": ".env"},
        {"kind": "suspicious_file", "path": "certs/service.pem"},
        {"kind": "suspicious_file", "path": "keys/id_rsa"},
        {"kind": "suspicious_file", "path": "vault/archive.kdbx"},
    ]
    assert isinstance(baseline["generated_at"], str)
    assert baseline["generated_at"].endswith("Z")
    assert datetime.fromisoformat(
        baseline["generated_at"].replace("Z", "+00:00")
    )


def test_scan_command_suppresses_known_findings_with_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
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

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_emits_no_findings_text_after_baseline_suppression(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"

    write_exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(fixture_root)]
    )
    assert write_exit_code == 0
    capsys.readouterr()

    exit_code = main(
        [
            "scan",
            "--format",
            "text",
            "--baseline",
            str(baseline_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == "No findings.\n"


def test_scan_command_returns_success_when_baseline_suppresses_all_findings(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"

    write_exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(fixture_root)]
    )
    assert write_exit_code == 0
    capsys.readouterr()

    exit_code = main(
        [
            "scan",
            "--fail-on-findings",
            "--baseline",
            str(baseline_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_surfaces_new_findings_outside_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    repo_root = tmp_path / "sample_repo"
    baseline_path = tmp_path / "baseline.json"

    shutil.copytree(fixture_root, repo_root)

    write_exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(repo_root)]
    )
    assert write_exit_code == 0
    capsys.readouterr()

    (repo_root / "certs" / "new.key").write_text("private-key\n", encoding="utf-8")
    (repo_root / "notes" / "new_tokens.txt").write_text(
        "token=fedcba9876543210fedcba9876543210\n", encoding="utf-8"
    )

    exit_code = main(["scan", "--baseline", str(baseline_path), str(repo_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "high_entropy_findings": [
            {
                "entropy": 4.0,
                "file": "notes/new_tokens.txt",
                "line": 1,
                "token": "fedcba9876543210fedcba9876543210",
            }
        ],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": ["certs/new.key"],
    }


def test_scan_command_returns_success_for_clean_scan_with_flag_enabled(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("dist/\n", encoding="utf-8")

    exit_code = main(["scan", "--fail-on-findings", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_rejects_invalid_baseline_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "generated_at": "2026-03-10T00:00:00Z",
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(["scan", "--baseline", str(baseline_path), str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert f"Invalid baseline {baseline_path}:" in captured.err
    assert "schema_version must be 1" in captured.err


def test_scan_command_rejects_nonexistent_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    missing_path = tmp_path / "missing"

    exit_code = main(["scan", str(missing_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert f"Path not found: {missing_path}" in captured.err


def test_scan_command_rejects_non_directory_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    file_path = tmp_path / "README.md"
    file_path.write_text("content\n", encoding="utf-8")

    exit_code = main(["scan", str(file_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert f"Path is not a directory: {file_path}" in captured.err
