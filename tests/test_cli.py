from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path

import pytest

from repo_sentinel import __version__
from repo_sentinel.cli import main
from repo_sentinel.scanner import _normalize_report

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _expected_sample_repo_sarif() -> dict[str, object]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "results": [
                    {
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "notes/tokens.txt"
                                    },
                                    "region": {"startLine": 2},
                                }
                            }
                        ],
                        "message": {
                            "text": (
                                "High-entropy string detected: "
                                "notes/tokens.txt:2"
                            )
                        },
                        "partialFingerprints": {
                            "repoSentinelFingerprint": (
                                "9d32570586e37a6005c9ce58edd091a56032dc3f38ae5c907033c17661286129"
                            )
                        },
                        "ruleId": "high_entropy",
                    },
                    {
                        "level": "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": ".gitignore"}
                                }
                            }
                        ],
                        "message": {"text": "Required file missing: .gitignore"},
                        "partialFingerprints": {
                            "repoSentinelFingerprint": (
                                "2268e39db2ef51eba92c7640986350d5843da88ece2739c97ec7ab0b3e267a93"
                            )
                        },
                        "ruleId": "missing_file",
                    },
                    {
                        "level": "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "LICENSE"}
                                }
                            }
                        ],
                        "message": {"text": "Required file missing: LICENSE"},
                        "partialFingerprints": {
                            "repoSentinelFingerprint": (
                                "efcd9b83e1c3bef283a2e4f5dbd6a6dfa4fc691f54653643445778f35d2f501e"
                            )
                        },
                        "ruleId": "missing_file",
                    },
                    {
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": ".env"}
                                }
                            }
                        ],
                        "message": {"text": "Suspicious file detected: .env"},
                        "partialFingerprints": {
                            "repoSentinelFingerprint": (
                                "a6eba87257d11d0a165ac41d54729cdcd8300281102b58776ee8b453eea0138c"
                            )
                        },
                        "ruleId": "suspicious_file",
                    },
                    {
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "certs/service.pem"
                                    }
                                }
                            }
                        ],
                        "message": {
                            "text": "Suspicious file detected: certs/service.pem"
                        },
                        "partialFingerprints": {
                            "repoSentinelFingerprint": (
                                "16217ed2c8122262f2faf42e00ab7ae26888cf35b22de840faefe6cae9c03834"
                            )
                        },
                        "ruleId": "suspicious_file",
                    },
                    {
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "keys/id_rsa"}
                                }
                            }
                        ],
                        "message": {
                            "text": "Suspicious file detected: keys/id_rsa"
                        },
                        "partialFingerprints": {
                            "repoSentinelFingerprint": (
                                "d14152416103f5602ac35e2bb4c0c7006bc25c646512361c1b5d056ccb4c8025"
                            )
                        },
                        "ruleId": "suspicious_file",
                    },
                    {
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "vault/archive.kdbx"
                                    }
                                }
                            }
                        ],
                        "message": {
                            "text": "Suspicious file detected: vault/archive.kdbx"
                        },
                        "partialFingerprints": {
                            "repoSentinelFingerprint": (
                                "e34a85d2ae98c2282bf0966deb449470edba292d20c0ca3e2f8c53972fe5fc59"
                            )
                        },
                        "ruleId": "suspicious_file",
                    },
                ],
                "tool": {
                    "driver": {
                        "name": "repo-sentinel-lite",
                        "rules": [
                            {
                                "defaultConfiguration": {"level": "error"},
                                "fullDescription": {
                                    "text": (
                                        "Detects high-entropy strings that may "
                                        "indicate secrets."
                                    )
                                },
                                "id": "high_entropy",
                                "name": "High Entropy",
                                "shortDescription": {
                                    "text": "High-entropy string detected."
                                },
                            },
                            {
                                "defaultConfiguration": {"level": "warning"},
                                "fullDescription": {
                                    "text": (
                                        "Detects required repository files that "
                                        "are missing."
                                    )
                                },
                                "id": "missing_file",
                                "name": "Missing File",
                                "shortDescription": {
                                    "text": "Required file missing."
                                },
                            },
                            {
                                "defaultConfiguration": {"level": "error"},
                                "fullDescription": {
                                    "text": (
                                        "Detects suspicious filenames commonly "
                                        "associated with secrets."
                                    )
                                },
                                "id": "suspicious_file",
                                "name": "Suspicious File",
                                "shortDescription": {
                                    "text": "Suspicious file detected."
                                },
                            },
                        ],
                    }
                },
            }
        ],
        "version": "2.1.0",
    }


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
    expected_output = (FIXTURES_DIR / "sample_repo_report.json").read_text(
        encoding="utf-8"
    )

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
    assert output_path.read_text(encoding="utf-8") == (
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
        "token=0123456789abcdef0123456789abcdef\n"
    )


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
    assert captured.out == (
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
        "token=0123456789abcdef0123456789abcdef\n"
    )


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
        "token=0123456789abcdef0123456789abcdef\n"
    )


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
    assert captured.out == (
        FIXTURES_DIR / "sample_repo_report.json"
    ).read_text(encoding="utf-8")


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
    assert captured.out == (
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
        "token=0123456789abcdef0123456789abcdef\n"
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
            "fingerprint": (
                "9d32570586e37a6005c9ce58edd091a56032dc3f38ae5c907033c17661286129"
            ),
            "kind": "high_entropy",
            "line": 2,
            "token": "0123456789abcdef0123456789abcdef",
        },
        {
            "fingerprint": (
                "2268e39db2ef51eba92c7640986350d5843da88ece2739c97ec7ab0b3e267a93"
            ),
            "kind": "missing_file",
            "path": ".gitignore",
        },
        {
            "fingerprint": (
                "efcd9b83e1c3bef283a2e4f5dbd6a6dfa4fc691f54653643445778f35d2f501e"
            ),
            "kind": "missing_file",
            "path": "LICENSE",
        },
        {
            "fingerprint": (
                "a6eba87257d11d0a165ac41d54729cdcd8300281102b58776ee8b453eea0138c"
            ),
            "kind": "suspicious_file",
            "path": ".env",
        },
        {
            "fingerprint": (
                "16217ed2c8122262f2faf42e00ab7ae26888cf35b22de840faefe6cae9c03834"
            ),
            "kind": "suspicious_file",
            "path": "certs/service.pem",
        },
        {
            "fingerprint": (
                "d14152416103f5602ac35e2bb4c0c7006bc25c646512361c1b5d056ccb4c8025"
            ),
            "kind": "suspicious_file",
            "path": "keys/id_rsa",
        },
        {
            "fingerprint": (
                "e34a85d2ae98c2282bf0966deb449470edba292d20c0ca3e2f8c53972fe5fc59"
            ),
            "kind": "suspicious_file",
            "path": "vault/archive.kdbx",
        },
    ]
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
    expected_output = (FIXTURES_DIR / "sample_repo_report.json").read_text(
        encoding="utf-8"
    )

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
        "high_entropy",
        "missing_file",
        "suspicious_file",
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
    assert json.loads(captured.out) == _normalize_report({
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
    })


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
