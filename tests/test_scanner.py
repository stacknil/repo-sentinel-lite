from __future__ import annotations

from pathlib import Path

import pytest

from repo_sentinel.scanner import (
    apply_baseline,
    calculate_shannon_entropy,
    is_suspicious_filename,
    scan_repository,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", 0.0),
        ("aaaa", 0.0),
        ("abcd", 2.0),
        ("0123456789abcdef0123456789abcdef", 4.0),
    ],
)
def test_calculate_shannon_entropy(value: str, expected: float) -> None:
    assert calculate_shannon_entropy(value) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        (".env", True),
        ("ID_RSA", True),
        ("prod.PEM", True),
        ("archive.kdbx", True),
        ("config.key", True),
        ("notes.txt", False),
        (".env.example", False),
    ],
)
def test_is_suspicious_filename(filename: str, expected: bool) -> None:
    assert is_suspicious_filename(filename) is expected


def test_scan_repository_skips_binary_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / "binary.txt").write_bytes(
        b"\x00\x01\x02\x03" + b"0123456789abcdef0123456789abcdef"
    )

    report = scan_repository(tmp_path)

    assert report["high_entropy_findings"] == []


def test_scan_repository_uses_default_config_when_config_file_missing(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=value\n", encoding="utf-8")
    (tmp_path / "tokens.txt").write_text(
        "token=0123456789abcdef0123456789abcdef\n", encoding="utf-8"
    )

    report = scan_repository(tmp_path)

    assert report["suspicious_files"] == [".env"]
    assert report["missing_files"] == {
        ".gitignore": True,
        "LICENSE": True,
        "README.md": False,
    }
    assert report["high_entropy_findings"] == [
        {
            "entropy": 4.0,
            "file": "tokens.txt",
            "line": 1,
            "token": "0123456789abcdef0123456789abcdef",
        }
    ]


def test_scan_repository_uses_custom_entropy_threshold(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".reposentinel.toml").write_text(
        "entropy_threshold = 4.1\n", encoding="utf-8"
    )
    (tmp_path / "tokens.txt").write_text(
        "token=0123456789abcdef0123456789abcdef\n", encoding="utf-8"
    )

    report = scan_repository(tmp_path)

    assert report["high_entropy_findings"] == []


def test_scan_repository_respects_ignored_paths(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=value\n", encoding="utf-8")
    (tmp_path / ".reposentinel.toml").write_text(
        'ignore_globs = ["ignored/*"]\n', encoding="utf-8"
    )
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "id_rsa").write_text("private-key\n", encoding="utf-8")
    (tmp_path / "ignored" / "tokens.txt").write_text(
        "token=0123456789abcdef0123456789abcdef\n", encoding="utf-8"
    )

    report = scan_repository(tmp_path)

    assert report["suspicious_files"] == [".env"]
    assert report["high_entropy_findings"] == []


def test_scan_repository_overrides_required_files_from_config(
    tmp_path: Path,
) -> None:
    (tmp_path / ".reposentinel.toml").write_text(
        'required_files = ["README.md", "docs/guide.md"]\n', encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("guide\n", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report["missing_files"] == {
        "README.md": False,
        "docs/guide.md": False,
    }


def test_scan_repository_overrides_suspicious_filenames_from_config(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=value\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("private-key\n", encoding="utf-8")
    (tmp_path / ".reposentinel.toml").write_text(
        'suspicious_filenames = ["notes.txt"]\n', encoding="utf-8"
    )

    report = scan_repository(tmp_path)

    assert report["suspicious_files"] == ["notes.txt"]


def test_scan_repository_ignores_dot_git_directory(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "id_rsa").write_text("private-key\n", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report["suspicious_files"] == []


def test_scan_repository_detects_suspicious_filenames_case_insensitively(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".ENV").write_text("value\n", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "Prod.PEM").write_text("value\n", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report["suspicious_files"] == [".ENV", "nested/Prod.PEM"]


def test_scan_repository_skips_unreadable_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    blocked = tmp_path / "blocked.txt"
    blocked.write_text("token=0123456789abcdef0123456789abcdef\n", encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def fake_read_bytes(path: Path) -> bytes:
        if path == blocked:
            raise OSError("access denied")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fake_read_bytes)

    report = scan_repository(tmp_path)

    assert report["high_entropy_findings"] == []


def test_apply_baseline_compares_findings_deterministically() -> None:
    report = {
        "high_entropy_findings": [
            {
                "entropy": 4.0,
                "file": "notes/tokens.txt",
                "line": 2,
                "token": "0123456789abcdef0123456789abcdef",
            },
            {
                "entropy": 4.0,
                "file": "notes/z_tokens.txt",
                "line": 1,
                "token": "fedcba9876543210fedcba9876543210",
            },
        ],
        "missing_files": {
            ".gitignore": True,
            "LICENSE": True,
            "README.md": False,
        },
        "suspicious_files": [".env", "vault/archive.kdbx"],
    }
    baseline = {
        "schema_version": 1,
        "generated_at": "2026-03-10T00:00:00Z",
        "findings": [
            {"kind": "suspicious_file", "path": "vault/archive.kdbx"},
            {
                "entropy": 4,
                "file": "notes\\z_tokens.txt",
                "kind": "high_entropy",
                "line": 1,
                "token": "fedcba9876543210fedcba9876543210",
            },
            {"kind": "missing_file", "path": "LICENSE"},
            {"kind": "suspicious_file", "path": ".env"},
            {
                "entropy": 4.0,
                "file": "notes\\tokens.txt",
                "kind": "high_entropy",
                "line": 2,
                "token": "0123456789abcdef0123456789abcdef",
            },
            {"kind": "missing_file", "path": ".gitignore"},
        ],
    }

    assert apply_baseline(report, baseline) == {
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "LICENSE": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_apply_baseline_normalizes_path_separators_for_all_finding_kinds() -> None:
    report = {
        "high_entropy_findings": [
            {
                "entropy": 4.0,
                "file": "notes/tokens.txt",
                "line": 2,
                "token": "0123456789abcdef0123456789abcdef",
            }
        ],
        "missing_files": {
            "docs/guide.md": True,
            "README.md": False,
        },
        "suspicious_files": ["secrets/private.key"],
    }
    baseline = {
        "schema_version": 1,
        "generated_at": "2026-03-10T00:00:00Z",
        "findings": [
            {
                "entropy": 4.0,
                "file": "notes\\tokens.txt",
                "kind": "high_entropy",
                "line": 2,
                "token": "0123456789abcdef0123456789abcdef",
            },
            {"kind": "missing_file", "path": "docs\\guide.md"},
            {"kind": "suspicious_file", "path": "secrets\\private.key"},
        ],
    }

    assert apply_baseline(report, baseline) == {
        "high_entropy_findings": [],
        "missing_files": {
            "README.md": False,
            "docs/guide.md": False,
        },
        "suspicious_files": [],
    }
