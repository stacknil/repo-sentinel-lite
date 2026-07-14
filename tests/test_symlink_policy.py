from __future__ import annotations

import json
from pathlib import Path

import pytest

from repo_sentinel.scanner import (
    apply_baseline,
    format_sarif_report,
    format_text_report,
    scan_repository,
)

SYNTHETIC_TOKEN = "0123456789abcdef0123456789abcdef"


def _write_required_files(root: Path) -> None:
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8")


def _symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symlinks are unavailable: {type(error).__name__}")


def test_full_scan_skips_in_root_file_symlink_content(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    target = tmp_path / "target.txt"
    target.write_text(f"token={SYNTHETIC_TOKEN}\n", encoding="utf-8")
    _symlink_or_skip(tmp_path / "alias.txt", target)

    report = scan_repository(tmp_path)

    assert [item["file"] for item in report["high_entropy_findings"]] == [
        "target.txt"
    ]
    assert report["coverage"]["skipped_files"] == [
        {"path": "alias.txt", "reason": "symlink_policy"}
    ]


def test_full_scan_surfaces_skipped_directory_symlink(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_required_files(repository)
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    (outside_directory / "secret.txt").write_text(
        f"token={SYNTHETIC_TOKEN}\n", encoding="utf-8"
    )
    _symlink_or_skip(
        repository / "linked-dir",
        outside_directory,
        directory=True,
    )

    report = scan_repository(repository)
    repeated_report = scan_repository(repository)
    sarif = json.loads(format_sarif_report(report))

    assert report["findings"] == []
    assert report["coverage"] == {
        "directories_skipped": 1,
        "files_considered": 3,
        "files_inspected": 3,
        "files_skipped": 0,
        "skipped_by_reason": {},
        "skipped_directories": [
            {"path": "linked-dir", "reason": "symlink_policy"}
        ],
        "skipped_files": [],
    }
    assert format_text_report(report) == (
        "No findings.\n\n"
        "Coverage: inspected 3 of 3 files; skipped 0 files and 1 directory.\n"
        "- [symlink_policy] linked-dir (directory)\n"
    )
    assert repeated_report["coverage"] == report["coverage"]
    assert str(repository) not in json.dumps(report)
    assert sarif["runs"][0]["properties"]["repoSentinelCoverage"] == report[
        "coverage"
    ]


def test_full_scan_surfaces_directory_symlink_loop(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    _symlink_or_skip(tmp_path / "loop", tmp_path, directory=True)

    report = scan_repository(tmp_path)

    assert report["findings"] == []
    assert report["coverage"]["skipped_directories"] == [
        {"path": "loop", "reason": "symlink_policy"}
    ]


def test_full_scan_checks_directory_symlink_name_not_target(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_required_files(repository)
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    (outside_directory / "secret.txt").write_text(
        f"token={SYNTHETIC_TOKEN}\n", encoding="utf-8"
    )
    _symlink_or_skip(
        repository / ".env",
        outside_directory,
        directory=True,
    )

    report = scan_repository(repository)

    assert report["suspicious_files"] == [".env"]
    assert report["high_entropy_findings"] == []
    assert report["coverage"]["skipped_directories"] == [
        {"path": ".env", "reason": "symlink_policy"}
    ]


def test_changed_scan_surfaces_outside_root_file_symlink_name(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_required_files(repository)
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text(f"token={SYNTHETIC_TOKEN}\n", encoding="utf-8")
    _symlink_or_skip(repository / ".env", outside_file)

    report = scan_repository(repository, changed_paths=[".env"])

    assert report["suspicious_files"] == [".env"]
    assert report["high_entropy_findings"] == []
    assert report["coverage"]["skipped_files"] == [
        {"path": ".env", "reason": "symlink_policy"}
    ]


def test_changed_scan_skips_file_below_directory_symlink(tmp_path: Path) -> None:
    _write_required_files(tmp_path)
    target_directory = tmp_path / "real-dir"
    target_directory.mkdir()
    (target_directory / "secret.txt").write_text(
        f"token={SYNTHETIC_TOKEN}\n", encoding="utf-8"
    )
    _symlink_or_skip(
        tmp_path / "linked-dir",
        target_directory,
        directory=True,
    )

    report = scan_repository(
        tmp_path,
        changed_paths=["linked-dir/secret.txt"],
    )

    assert report["findings"] == []
    assert report["coverage"]["skipped_files"] == [
        {"path": "linked-dir/secret.txt", "reason": "symlink_policy"}
    ]
    assert report["coverage"]["skipped_directories"] == [
        {"path": "linked-dir", "reason": "symlink_policy"}
    ]


def test_baseline_suppression_preserves_directory_coverage(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_required_files(repository)
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    _symlink_or_skip(
        repository / "linked-dir",
        outside_directory,
        directory=True,
    )
    report = scan_repository(repository)
    baseline = {
        "schema_version": 1,
        "generated_at": "2026-07-14T00:00:00Z",
        "findings": [],
    }

    filtered = apply_baseline(report, baseline)

    assert filtered["coverage"] == report["coverage"]
