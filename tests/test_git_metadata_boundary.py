from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repo_sentinel.scanner import scan_repository


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write_required_files(root: Path) -> None:
    (root / ".gitignore").write_text("dist/\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8")


def _high_entropy_text() -> str:
    return "".join(format(value, "x") for value in range(16)) * 2


@pytest.fixture
def repository_with_worktree(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _write_required_files(repository)
    _git(repository, "init")
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Fixture User",
        "-c",
        "user.email=fixture@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-m",
        "fixture",
    )

    linked_worktree = tmp_path / _high_entropy_text()
    _git(repository, "worktree", "add", "--detach", str(linked_worktree), "HEAD")
    try:
        yield repository, linked_worktree
    finally:
        _git(repository, "worktree", "remove", "--force", str(linked_worktree))


@pytest.mark.parametrize(
    "changed_paths",
    [None, [".git"]],
    ids=["full-scan", "explicit-changed-path"],
)
def test_root_git_metadata_is_equivalent_across_checkout_shapes(
    repository_with_worktree: tuple[Path, Path],
    changed_paths: list[str] | None,
) -> None:
    repository, linked_worktree = repository_with_worktree
    assert (repository / ".git").is_dir()
    assert (linked_worktree / ".git").is_file()

    normal_report = scan_repository(repository, changed_paths=changed_paths)
    linked_report = scan_repository(linked_worktree, changed_paths=changed_paths)

    assert linked_report == normal_report


@pytest.mark.parametrize(
    "changed_paths",
    [None, ["nested/.git"]],
    ids=["full-scan", "explicit-changed-path"],
)
def test_nested_git_file_remains_repository_content(
    tmp_path: Path, changed_paths: list[str] | None
) -> None:
    _write_required_files(tmp_path)
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / ".git").write_text(
        f"token={_high_entropy_text()}\n", encoding="utf-8"
    )

    report = scan_repository(tmp_path, changed_paths=changed_paths)

    assert [finding["file"] for finding in report["high_entropy_findings"]] == [
        "nested/.git"
    ]
