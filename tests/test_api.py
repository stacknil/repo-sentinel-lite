from __future__ import annotations

import json
from pathlib import Path

from repo_sentinel import scan_repository
from repo_sentinel.redaction import REDACTED_TOKEN_PREFIX

SYNTHETIC_TOKEN = "0123456789abcdef0123456789abcdef"


def _write_repository(root: Path) -> None:
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (root / "tokens.txt").write_text(
        f"token={SYNTHETIC_TOKEN}\n", encoding="utf-8"
    )


def test_public_scan_repository_redacts_tokens_by_default(tmp_path: Path) -> None:
    _write_repository(tmp_path)

    report = scan_repository(tmp_path)

    serialized_report = json.dumps(report)
    assert SYNTHETIC_TOKEN not in serialized_report
    assert report["high_entropy_findings"][0]["token"].startswith(
        REDACTED_TOKEN_PREFIX
    )


def test_public_scan_repository_reveals_tokens_only_when_requested(
    tmp_path: Path,
) -> None:
    _write_repository(tmp_path)

    report = scan_repository(tmp_path, reveal_secrets=True)

    assert report["high_entropy_findings"][0]["token"] == SYNTHETIC_TOKEN


def test_public_scan_repository_forwards_changed_paths(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    (tmp_path / "unselected.txt").write_text(
        "token=fedcba9876543210fedcba9876543210\n", encoding="utf-8"
    )

    report = scan_repository(tmp_path, changed_paths=["tokens.txt"])

    assert [finding["file"] for finding in report["high_entropy_findings"]] == [
        "tokens.txt"
    ]
