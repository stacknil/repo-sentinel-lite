from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

import pytest

from repo_sentinel import __version__
from repo_sentinel.cli import main
from repo_sentinel.scanner import _normalize_report, redact_report

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
REDACTED_SAMPLE_TOKEN = "<redacted:sha256:3eb1bd439947>"


def _expected_sample_repo_json(*, reveal_secrets: bool = False) -> str:
    report = json.loads(
        (FIXTURES_DIR / "sample_repo_report.json").read_text(encoding="utf-8")
    )
    if not reveal_secrets:
        report = redact_report(report)
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def _expected_sample_repo_text(*, reveal_secrets: bool = False) -> str:
    token = (
        "0123456789abcdef0123456789abcdef"
        if reveal_secrets
        else REDACTED_SAMPLE_TOKEN
    )
    return (
        "Suspicious files (4):\n"
        "- [ERROR] .env\n"
        "- [ERROR] certs/service.pem\n"
        "- [ERROR] keys/id_rsa\n"
        "- [ERROR] vault/archive.kdbx\n"
        "\n"
        "Missing required files (2):\n"
        "- [WARNING] .gitignore\n"
        "- [WARNING] LICENSE\n"
        "\n"
        "High-entropy findings (1):\n"
        "- [ERROR] notes/tokens.txt:2 entropy=4.0 "
        f"token={token}\n"
    )


def _expected_sample_repo_sarif() -> dict[str, object]:
    return json.loads(
        (FIXTURES_DIR / "sample_repo_report.sarif.json").read_text(
            encoding="utf-8"
        )
    )


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
    expected_output = _expected_sample_repo_json()

    exit_code = main(["scan", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == expected_output


def test_scan_command_reveals_secrets_when_requested(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(["scan", "--reveal-secrets", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == _expected_sample_repo_json(reveal_secrets=True)


def test_scan_command_emits_stable_sarif(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    expected_output = (
        json.dumps(_expected_sample_repo_sarif(), indent=2, sort_keys=True) + "\n"
    )

    exit_code = main(["scan", "--format", "sarif", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == expected_output
    parsed = json.loads(captured.out)
    assert parsed == _expected_sample_repo_sarif()
    assert all(
        "partialFingerprints" in result
        for result in parsed["runs"][0]["results"]
    )


def test_scan_command_writes_json_output_to_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    output_path = tmp_path / "report.json"
    expected_output = _expected_sample_repo_json()

    exit_code = main(
        ["scan", "--output", str(output_path), str(fixture_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert output_path.read_text(encoding="utf-8") == expected_output


def test_scan_command_writes_text_output_to_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    output_path = tmp_path / "report.txt"

    exit_code = main(
        ["scan", "--format", "text", "--output", str(output_path), str(fixture_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert output_path.read_text(encoding="utf-8") == _expected_sample_repo_text()


def test_scan_command_writes_sarif_output_to_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    output_path = tmp_path / "results.sarif"
    expected_output = (
        json.dumps(_expected_sample_repo_sarif(), indent=2, sort_keys=True) + "\n"
    )

    exit_code = main(
        ["scan", "--format", "sarif", "--output", str(output_path), str(fixture_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == ""
    assert output_path.read_text(encoding="utf-8") == expected_output


def test_scan_command_stdout_behavior_is_unchanged_without_output_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(["scan", "--format", "text", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == _expected_sample_repo_text()


def test_scan_command_returns_success_when_findings_present_and_flag_absent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    expected_output = _expected_sample_repo_json()

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
    assert captured.out == _expected_sample_repo_text()


def test_scan_command_writes_output_and_preserves_fail_on_findings_behavior(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    output_path = tmp_path / "report.json"

    exit_code = main(
        [
            "scan",
            "--fail-on-findings",
            "--output",
            str(output_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert json.loads(output_path.read_text(encoding="utf-8"))["findings"]


def test_scan_command_returns_failure_when_error_findings_meet_threshold(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(
        ["scan", "--fail-on-severity", "error", str(fixture_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == _expected_sample_repo_json()


def test_scan_command_returns_success_when_only_warnings_remain_at_error_threshold(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")

    exit_code = main(["scan", "--fail-on-severity", "error", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == _normalize_report({
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": True,
            "LICENSE": True,
            "README.md": False,
        },
        "suspicious_files": [],
    })


def test_scan_command_returns_failure_when_warning_findings_meet_warning_threshold(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")

    exit_code = main(["scan", "--fail-on-severity", "warning", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert json.loads(captured.out) == _normalize_report({
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": True,
            "LICENSE": True,
            "README.md": False,
        },
        "suspicious_files": [],
    })


def test_scan_command_emits_concise_text_report(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"

    exit_code = main(["scan", "--format", "text", str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == _expected_sample_repo_text()


def test_scan_command_writes_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"
    expected_output = _expected_sample_repo_json()

    exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(fixture_root)]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == expected_output

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert baseline["schema_version"] == 1
    assert baseline["findings"] == json.loads(expected_output)["findings"]
    assert isinstance(baseline["generated_at"], str)
    assert baseline["generated_at"].endswith("Z")
    assert datetime.fromisoformat(
        baseline["generated_at"].replace("Z", "+00:00")
    )


def test_scan_command_prunes_baseline_to_explicit_output_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"
    pruned_path = tmp_path / "pruned-baseline.json"

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
            "--fail-on-findings",
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()
    pruned = json.loads(pruned_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }
    assert all("fingerprint" in finding for finding in pruned["findings"])
    assert all(
        finding["fingerprint"] != "stale-fingerprint"
        for finding in pruned["findings"]
    )
    assert len(pruned["findings"]) == 7


def test_scan_command_updates_baseline_to_current_findings_state(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    updated_path = tmp_path / "updated-baseline.json"
    expected_output = _expected_sample_repo_json()

    exit_code = main(
        ["scan", "--update-baseline", str(updated_path), str(fixture_root)]
    )
    captured = capsys.readouterr()
    refreshed = json.loads(updated_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert captured.out == expected_output
    assert len(refreshed["findings"]) == 7
    assert all("fingerprint" in finding for finding in refreshed["findings"])


def test_scan_command_updates_baseline_deterministically_across_runs(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    first_path = tmp_path / "first-baseline.json"
    second_path = tmp_path / "second-baseline.json"

    first_exit_code = main(
        ["scan", "--update-baseline", str(first_path), str(fixture_root)]
    )
    assert first_exit_code == 0
    first_output = capsys.readouterr()

    second_exit_code = main(
        ["scan", "--update-baseline", str(second_path), str(fixture_root)]
    )
    assert second_exit_code == 0
    second_output = capsys.readouterr()

    first_baseline = json.loads(first_path.read_text(encoding="utf-8"))
    second_baseline = json.loads(second_path.read_text(encoding="utf-8"))

    assert first_output.out == second_output.out
    assert first_baseline["findings"] == second_baseline["findings"]


def test_scan_command_updates_baseline_from_legacy_input(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "legacy-baseline.json"
    updated_path = tmp_path / "updated-baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": "2026-03-23T00:00:00Z",
                "findings": [
                    {
                        "entropy": 4.0,
                        "file": "notes\\tokens.txt",
                        "kind": "high_entropy",
                        "line": 2,
                        "token": "0123456789abcdef0123456789abcdef",
                    },
                    {"kind": "missing_file", "path": ".gitignore"},
                    {"kind": "missing_file", "path": "LICENSE"},
                    {"kind": "suspicious_file", "path": ".env"},
                    {"kind": "suspicious_file", "path": "certs\\service.pem"},
                    {"kind": "suspicious_file", "path": "keys\\id_rsa"},
                    {"kind": "suspicious_file", "path": "vault\\archive.kdbx"},
                    {"kind": "suspicious_file", "path": "stale\\private.key"},
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            "--baseline",
            str(baseline_path),
            "--update-baseline",
            str(updated_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()
    refreshed = json.loads(updated_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }
    assert len(refreshed["findings"]) == 7
    assert all("fingerprint" in finding for finding in refreshed["findings"])


def test_scan_command_update_candidate_includes_new_current_findings(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    reviewed_token = "0123456789abcdef0123456789abcdef"
    new_token = "abcdefghijklmnopqrstuvwxyzABCDEF"
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (repo_root / "LICENSE").write_text("Fixture license\n", encoding="utf-8")
    (repo_root / ".gitignore").write_text("*.tmp\n", encoding="utf-8")
    (repo_root / "reviewed.txt").write_text(
        f"token={reviewed_token}\n", encoding="utf-8"
    )
    (repo_root / "new.txt").write_text(f"token={new_token}\n", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    updated_path = tmp_path / "updated-baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": "2026-03-23T00:00:00Z",
                "findings": [
                    {
                        "entropy": 4.0,
                        "file": "reviewed.txt",
                        "kind": "high_entropy",
                        "line": 1,
                        "token": reviewed_token,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "scan",
            "--baseline",
            str(baseline_path),
            "--update-baseline",
            str(updated_path),
            str(repo_root),
        ]
    )
    captured = capsys.readouterr()
    displayed = json.loads(captured.out)
    updated_text = updated_path.read_text(encoding="utf-8")
    refreshed = json.loads(updated_text)

    assert exit_code == 0
    assert [finding["path"] for finding in displayed["findings"]] == ["new.txt"]
    assert [finding["path"] for finding in refreshed["findings"]] == [
        "new.txt",
        "reviewed.txt",
    ]
    assert reviewed_token not in updated_text
    assert new_token not in updated_text


def test_scan_command_rejects_prune_baseline_without_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    output_path = tmp_path / "pruned-baseline.json"

    exit_code = main(["scan", "--prune-baseline", str(output_path), str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "--prune-baseline requires --baseline\n"


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
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_auto_applies_default_repo_root_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    repo_root = tmp_path / "sample_repo"
    baseline_path = repo_root / ".reposentinel-baseline.json"

    shutil.copytree(fixture_root, repo_root)

    write_exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(repo_root)]
    )
    assert write_exit_code == 0
    capsys.readouterr()

    exit_code = main(["scan", str(repo_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_can_skip_default_repo_root_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    repo_root = tmp_path / "sample_repo"
    baseline_path = repo_root / ".reposentinel-baseline.json"

    shutil.copytree(fixture_root, repo_root)

    write_exit_code = main(
        ["scan", "--write-baseline", str(baseline_path), str(repo_root)]
    )
    assert write_exit_code == 0
    capsys.readouterr()

    exit_code = main(["scan", "--no-default-baseline", str(repo_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.out == _expected_sample_repo_json()


def test_scan_command_no_default_baseline_keeps_explicit_baseline(
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
            "--no-default-baseline",
            "--baseline",
            str(baseline_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_suppresses_known_findings_with_legacy_baseline(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": "2026-03-23T00:00:00Z",
                "findings": [
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
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    exit_code = main(["scan", "--baseline", str(baseline_path), str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "findings": [],
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


def test_scan_command_emits_empty_sarif_results_after_baseline_suppression(
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
            "sarif",
            "--baseline",
            str(baseline_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()
    sarif = json.loads(captured.out)

    assert exit_code == 0
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]] == [
        "repo.required_file_missing",
        "repo.suspicious_filename",
        "secret.assignment_context",
        "secret.aws_access_key_id",
        "secret.github_token",
        "secret.high_entropy",
        "secret.pem_private_key",
    ]


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
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_returns_success_when_fingerprint_baseline_suppresses_all_findings(
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
            "--fail-on-severity",
            "warning",
            "--baseline",
            str(baseline_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_scan_command_update_baseline_preserves_fail_on_behavior(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    updated_path = tmp_path / "updated-baseline.json"

    exit_code = main(
        [
            "scan",
            "--fail-on-findings",
            "--update-baseline",
            str(updated_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 1
    assert json.loads(captured.out)["findings"]
    assert json.loads(updated_path.read_text(encoding="utf-8"))["findings"]


def test_scan_command_returns_success_when_baseline_suppresses_severity_threshold(
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
            "--fail-on-severity",
            "warning",
            "--baseline",
            str(baseline_path),
            str(fixture_root),
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert json.loads(captured.out) == {
        "findings": [],
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
    assert json.loads(captured.out) == redact_report(_normalize_report({
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
    }))


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
        "findings": [],
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


def test_scan_command_rejects_invalid_config_file(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    (tmp_path / ".reposentinel.toml").write_text(
        "entropy_threshold = true\n", encoding="utf-8"
    )

    exit_code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert f"Invalid config {tmp_path / '.reposentinel.toml'}:" in captured.err
    assert "entropy_threshold must be a float" in captured.err


def test_scan_command_rejects_unwritable_output_path(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fixture_root = FIXTURES_DIR / "sample_repo"
    output_path = tmp_path / "missing" / "report.json"

    exit_code = main(["scan", "--output", str(output_path), str(fixture_root)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert f"Failed to write output {output_path}:" in captured.err


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
