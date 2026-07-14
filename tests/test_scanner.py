from __future__ import annotations

from pathlib import Path

import pytest

import repo_sentinel.scanner as scanner
from repo_sentinel.scanner import (
    DEFAULT_BASELINE_FILENAME,
    _baseline_from_report,
    _normalize_report,
    apply_baseline,
    calculate_shannon_entropy,
    is_suspicious_filename,
    prune_baseline,
    scan_repository,
    update_baseline,
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


def test_scan_repository_skips_oversized_text_files_by_default(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / "large.txt").write_text(
        ("padding\n" * 140_000)
        + "token=0123456789abcdef0123456789abcdef\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report["high_entropy_findings"] == []


def test_scan_repository_allows_custom_max_text_file_size(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".reposentinel.toml").write_text(
        "max_text_file_size = 64\n", encoding="utf-8"
    )
    (tmp_path / "small.txt").write_text(
        "token=0123456789abcdef0123456789abcdef\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report["high_entropy_findings"] == [
        {
            "entropy": 4.0,
            "file": "small.txt",
            "line": 1,
            "token": "0123456789abcdef0123456789abcdef",
        }
    ]


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
    assert report["findings"] == _normalize_report(report)["findings"]
    assert [finding["severity"] for finding in report["findings"]] == [
        "error",
        "warning",
        "warning",
        "error",
    ]
    assert all(
        isinstance(finding["fingerprint"], str) and finding["fingerprint"]
        for finding in report["findings"]
    )


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


@pytest.mark.parametrize("ignore_pattern", ["ignored/*", "ignored/**", "ignored/**/*"])
def test_scan_repository_prunes_directory_when_child_glob_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ignore_pattern: str
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".reposentinel.toml").write_text(
        f'ignore_globs = ["{ignore_pattern}"]\n', encoding="utf-8"
    )
    ignored_dir = tmp_path / "ignored"
    ignored_dir.mkdir()
    (ignored_dir / "id_rsa").write_text("private-key\n", encoding="utf-8")

    original_walk = scanner.os.walk

    def guarded_walk(*args: object, **kwargs: object) -> object:
        for current_root, dirnames, filenames in original_walk(*args, **kwargs):
            if Path(current_root).name == "ignored":
                raise AssertionError("ignored directory was not pruned")
            yield current_root, dirnames, filenames

    monkeypatch.setattr(scanner.os, "walk", guarded_walk)

    report = scan_repository(tmp_path)

    assert report["suspicious_files"] == []


def test_scan_repository_ignores_default_baseline_file(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / DEFAULT_BASELINE_FILENAME).write_text(
        '{"token":"0123456789abcdef0123456789abcdef"}\n',
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report["high_entropy_findings"] == []


def test_scan_repository_ignores_common_generated_directories(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    for directory in (
        "%TEMP%",
        ".mypy_cache",
        ".venv",
        ".venv-test",
        "build",
        "coverage",
        "dist",
        "dist-api-check",
        "htmlcov",
        "node_modules",
        "src/repo_sentinel_lite.egg-info",
    ):
        ignored_dir = tmp_path / directory
        ignored_dir.mkdir(parents=True)
        (ignored_dir / "id_rsa").write_text("private-key\n", encoding="utf-8")
        (ignored_dir / "tokens.txt").write_text(
            "token=0123456789abcdef0123456789abcdef\n", encoding="utf-8"
        )

    report = scan_repository(tmp_path)

    assert report["suspicious_files"] == []
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


def test_scan_repository_matches_required_files_case_insensitively(
    tmp_path: Path,
) -> None:
    (tmp_path / "readme.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / "license").write_text("MIT\n", encoding="utf-8")
    (tmp_path / ".GITIGNORE").write_text("dist/\n", encoding="utf-8")

    report = scan_repository(tmp_path)

    assert report["missing_files"] == {
        ".gitignore": False,
        "LICENSE": False,
        "README.md": False,
    }


def test_scan_repository_required_file_check_skips_generated_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("dist/\n", encoding="utf-8")
    generated_dir = tmp_path / "node_modules"
    generated_dir.mkdir()
    (generated_dir / "package.json").write_text("{}\n", encoding="utf-8")

    original_walk = scanner.os.walk

    def guarded_walk(*args: object, **kwargs: object) -> object:
        for current_root, dirnames, filenames in original_walk(*args, **kwargs):
            if Path(current_root).name == "node_modules":
                raise AssertionError("required file detection walked node_modules")
            yield current_root, dirnames, filenames

    monkeypatch.setattr(scanner.os, "walk", guarded_walk)

    report = scan_repository(tmp_path)

    assert report["missing_files"] == {
        ".gitignore": False,
        "LICENSE": False,
        "README.md": False,
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


def test_scan_repository_does_not_read_symlinked_file_contents(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "README.md").write_text("# Fixture\n", encoding="utf-8")
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text(
        "token=0123456789abcdef0123456789abcdef\n", encoding="utf-8"
    )
    linked_file = repository / ".env"
    try:
        linked_file.symlink_to(outside_file)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"file symlinks are unavailable: {error}")

    report = scan_repository(repository)

    assert report["suspicious_files"] == [".env"]
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
        "findings": [],
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
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            "README.md": False,
            "docs/guide.md": False,
        },
        "suspicious_files": [],
    }


def test_apply_baseline_prefers_fingerprint_matching_when_available() -> None:
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
            ".gitignore": True,
            "README.md": False,
        },
        "suspicious_files": [".env"],
    }
    normalized_report = _normalize_report(report)
    baseline = {
        "schema_version": 1,
        "generated_at": "2026-03-23T00:00:00Z",
        "findings": [
            {
                "fingerprint": normalized_report["findings"][0]["fingerprint"],
                "kind": "high_entropy",
                "file": "ignored/by/fingerprint.txt",
                "line": 99,
                "token": "differenttokenvalue1234567890",
                "entropy": 4.5,
            },
            {
                "fingerprint": normalized_report["findings"][1]["fingerprint"],
                "kind": "missing_file",
                "path": "ignored/by/fingerprint.md",
            },
            {
                "fingerprint": normalized_report["findings"][2]["fingerprint"],
                "kind": "suspicious_file",
                "path": "ignored/by/fingerprint.key",
            },
        ],
    }

    assert apply_baseline(report, baseline) == {
        "findings": [],
        "high_entropy_findings": [],
        "missing_files": {
            ".gitignore": False,
            "README.md": False,
        },
        "suspicious_files": [],
    }


def test_prune_baseline_removes_stale_entries_and_retains_matches() -> None:
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
            ".gitignore": True,
            "README.md": False,
        },
        "suspicious_files": [".env"],
    }
    current_findings = _normalize_report(report)["findings"]
    baseline = {
        "schema_version": 1,
        "generated_at": "2026-03-23T00:00:00Z",
        "findings": [
            {
                "fingerprint": current_findings[0]["fingerprint"],
                "kind": "high_entropy",
                "file": "ignored.txt",
                "line": 99,
                "token": "differenttokenvalue1234567890",
                "entropy": 4.5,
            },
            {
                "fingerprint": current_findings[2]["fingerprint"],
                "kind": "suspicious_file",
                "path": "ignored.key",
            },
            {
                "fingerprint": "stale-fingerprint",
                "kind": "missing_file",
                "path": "stale.md",
            },
        ],
    }

    pruned = prune_baseline(report, baseline)

    assert pruned["schema_version"] == 1
    assert pruned["findings"] == [
        _baseline_from_report(report)["findings"][0],
        _baseline_from_report(report)["findings"][2],
    ]


def test_prune_baseline_legacy_entries_remain_supported() -> None:
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
        "generated_at": "2026-03-23T00:00:00Z",
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
            {"kind": "suspicious_file", "path": "stale\\private.key"},
        ],
    }

    pruned = prune_baseline(report, baseline)
    expected = _baseline_from_report(report)["findings"]

    assert pruned["findings"] == expected


def test_update_baseline_without_input_returns_current_canonical_findings() -> None:
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
            ".gitignore": True,
            "README.md": False,
        },
        "suspicious_files": [".env"],
    }

    refreshed = update_baseline(report)

    assert refreshed == _baseline_from_report(report)


def test_update_baseline_with_legacy_input_rebuilds_current_state() -> None:
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
        "generated_at": "2026-03-23T00:00:00Z",
        "findings": [
            {
                "entropy": 4.0,
                "file": "notes\\tokens.txt",
                "kind": "high_entropy",
                "line": 2,
                "token": "0123456789abcdef0123456789abcdef",
            },
            {"kind": "missing_file", "path": "docs\\guide.md"},
            {"kind": "suspicious_file", "path": "stale\\private.key"},
        ],
    }

    refreshed = update_baseline(report, baseline)

    assert refreshed["findings"] == _baseline_from_report(report)["findings"]


def test_update_baseline_replaces_changed_fingerprint_with_current_finding() -> None:
    report = {
        "high_entropy_findings": [],
        "missing_files": {"README.md": False},
        "suspicious_files": ["secrets/private.key"],
    }
    current = _baseline_from_report(report)
    current_finding = current["findings"][0]
    baseline = {
        "schema_version": 1,
        "generated_at": "2026-03-23T00:00:00Z",
        "findings": [{**current_finding, "fingerprint": "0" * 64}],
    }

    refreshed = update_baseline(report, baseline)

    assert refreshed["findings"] == current["findings"]


def test_scan_repository_fingerprints_are_deterministic_across_runs(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=value\n", encoding="utf-8")
    (tmp_path / "tokens.txt").write_text(
        "token=0123456789abcdef0123456789abcdef\n", encoding="utf-8"
    )

    first_report = scan_repository(tmp_path)
    second_report = scan_repository(tmp_path)

    assert first_report["findings"] == second_report["findings"]


def test_normalized_path_variants_produce_same_fingerprint_for_all_finding_kinds(
) -> None:
    slash_report = _normalize_report(
        {
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
    )
    backslash_report = _normalize_report(
        {
            "high_entropy_findings": [
                {
                    "entropy": 4.0,
                    "file": "notes\\tokens.txt",
                    "line": 2,
                    "token": "0123456789abcdef0123456789abcdef",
                }
            ],
            "missing_files": {
                "docs\\guide.md": True,
                "README.md": False,
            },
            "suspicious_files": ["secrets\\private.key"],
        }
    )

    assert [
        finding["fingerprint"] for finding in slash_report["findings"]
    ] == [
        finding["fingerprint"] for finding in backslash_report["findings"]
    ]
