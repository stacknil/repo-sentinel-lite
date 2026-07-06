from __future__ import annotations

import json
from pathlib import Path

from repo_sentinel.baseline import audit_baseline
from repo_sentinel.cli import main
from repo_sentinel.config import token_sha256
from repo_sentinel.scanner import scan_repository


def test_structured_detectors_add_rule_semantics(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    (tmp_path / "tokens.txt").write_text(
        "\n".join(
            [
                "github_token=ghp_abcdefghijklmnopqrstuvwxyz123456",
                "aws_key=AKIAABCDEFGHIJKLMNOP",
                "api_key=shorttok9",
                "-----BEGIN PRIVATE KEY-----",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)
    rule_ids = {finding["rule_id"] for finding in report["findings"]}

    assert {
        "secret.assignment_context",
        "secret.aws_access_key_id",
        "secret.github_token",
        "secret.pem_private_key",
    }.issubset(rule_ids)
    assert all("rule_version" in finding for finding in report["findings"])
    assert all("remediation_hint" in finding for finding in report["findings"])
    assert all("evidence" in finding for finding in report["findings"])


def test_assignment_context_does_not_duplicate_high_entropy_tokens(
    tmp_path: Path,
) -> None:
    _write_required_files(tmp_path)
    (tmp_path / "tokens.txt").write_text(
        "token=0123456789abcdef0123456789abcdef\n", encoding="utf-8"
    )

    report = scan_repository(tmp_path)
    rule_ids = [finding["rule_id"] for finding in report["findings"]]

    assert "secret.high_entropy" in rule_ids
    assert "secret.assignment_context" not in rule_ids


def test_assignment_context_skips_source_expression_values(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    (tmp_path / "scanner.py").write_text(
        "\n".join(
            [
                'token = value.get("token")',
                'token = match.group("value").rstrip(",)")',
                'message = f"token={render_token(token, reveal_secrets)}"',
                'token=str(finding["token"]),',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report["findings"] == []


def test_assignment_context_keeps_literal_config_values(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    (tmp_path / "settings.toml").write_text(
        'api_key = "shorttok9"\npassword: plainpass9\n', encoding="utf-8"
    )

    report = scan_repository(tmp_path)

    assert [
        (finding["rule_id"], finding["token"]) for finding in report["findings"]
    ] == [
        ("secret.assignment_context", "shorttok9"),
        ("secret.assignment_context", "plainpass9"),
    ]


def test_allowlist_supports_path_rule_and_token_hash(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    token = "shorttok9"
    (tmp_path / ".reposentinel.toml").write_text(
        "\n".join(
            [
                "[allowlist]",
                'paths = ["secrets/**"]',
                'rules = ["repo.suspicious_filename"]',
                f'token_hashes = ["sha256:{token_sha256(token)}"]',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text("PLACEHOLDER=1\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text(f"api_key={token}\n", encoding="utf-8")
    (tmp_path / "secrets").mkdir()
    (tmp_path / "secrets" / "id_rsa").write_text("placeholder\n", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report["findings"] == []


def test_scoped_comment_allows_one_line(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    (tmp_path / "tokens.txt").write_text(
        "# repo-sentinel: allow secret.assignment_context\n"
        "api_key=shorttok9\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report["findings"] == []


def test_changed_files_mode_scans_only_listed_files(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    (tmp_path / "changed.txt").write_text("api_key=shorttok9\n", encoding="utf-8")
    (tmp_path / "unchanged.txt").write_text("api_key=othertok9\n", encoding="utf-8")

    report = scan_repository(tmp_path, changed_paths=["changed.txt"])

    assert [finding["path"] for finding in report["findings"]] == ["changed.txt"]


def test_scan_cli_changed_files_mode(tmp_path: Path, capsys) -> None:
    _write_required_files(tmp_path)
    (tmp_path / "changed.txt").write_text("api_key=shorttok9\n", encoding="utf-8")
    (tmp_path / "unchanged.txt").write_text("api_key=othertok9\n", encoding="utf-8")

    exit_code = main(
        ["scan", "--changed-files", str(tmp_path), "changed.txt"]
    )
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 0
    assert [finding["path"] for finding in report["findings"]] == ["changed.txt"]


def test_scan_cli_rejects_changed_paths_without_mode(tmp_path: Path, capsys) -> None:
    _write_required_files(tmp_path)

    exit_code = main(["scan", str(tmp_path), "changed.txt"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "changed file paths require --changed-files" in captured.err


def test_baseline_audit_classifies_current_drift(tmp_path: Path, capsys) -> None:
    _write_required_files(tmp_path)
    (tmp_path / ".env").write_text("PLACEHOLDER=1\n", encoding="utf-8")
    (tmp_path / "tokens.txt").write_text("api_key=shorttok9\n", encoding="utf-8")
    report = scan_repository(tmp_path)
    baseline = {
        "schema_version": 1,
        "generated_at": "2026-07-05T00:00:00Z",
        "findings": [
            {"kind": "suspicious_file", "path": ".env"},
            {
                "fingerprint": "stale-fingerprint",
                "kind": "suspicious_file",
                "path": ".env",
            },
            {
                "fingerprint": "gone-fingerprint",
                "kind": "suspicious_file",
                "path": "old.key",
            },
        ],
    }
    baseline_path = tmp_path / ".reposentinel-baseline.json"
    baseline_path.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    audit = audit_baseline(report, baseline)
    exit_code = main(["baseline", "audit", "--format", "json", str(tmp_path)])
    captured = capsys.readouterr()
    cli_audit = json.loads(captured.out)

    assert exit_code == 0
    assert audit["summary"] == {
        "active": 1,
        "ambiguous": 1,
        "stale": 1,
        "unmatched": 1,
    }
    assert cli_audit["summary"] == audit["summary"]


def _write_required_files(root: Path) -> None:
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / ".gitignore").write_text("*.tmp\n", encoding="utf-8")
