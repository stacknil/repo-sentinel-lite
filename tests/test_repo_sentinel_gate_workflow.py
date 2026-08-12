from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        input=input_text,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _commit_regular_to_symlink_change(repository: Path, path: str) -> tuple[str, str]:
    repository.mkdir(exist_ok=True)
    _git(repository, "init", "--quiet")
    _git(repository, "config", "user.email", "test@example.com")
    _git(repository, "config", "user.name", "Test User")

    tracked_path = repository / path
    tracked_path.write_text("regular file\n", encoding="utf-8")
    _git(repository, "add", "--", path)
    _git(
        repository,
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        "add regular file",
    )
    base_sha = _git(repository, "rev-parse", "HEAD")

    target_blob = _git(
        repository, "hash-object", "-w", "--stdin", input_text="target\n"
    )
    _git(repository, "update-index", "--cacheinfo", f"120000,{target_blob},{path}")
    _git(
        repository,
        "commit",
        "--quiet",
        "--no-gpg-sign",
        "-m",
        "change file type",
    )
    head_sha = _git(repository, "rev-parse", "HEAD")

    assert _git(repository, "diff", "--name-status", base_sha, head_sha) == f"T\t{path}"
    return base_sha, head_sha


def test_remote_gate_scans_changed_files_and_blocks_only_errors() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "repo-sentinel-gate.yml"
    ).read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "--changed-files" in workflow
    assert "--fail-on-severity error" in workflow
    assert "warnings and coverage skips are report-only" in workflow
    assert "--fail-on-severity warning" not in workflow
    assert "Reject changed security policy files" in workflow
    assert ".reposentinel.toml|.reposentinel-baseline.json" in workflow
    assert "Require dedicated policy review" in workflow
    assert "git diff --name-only --diff-filter=ACMRTD --no-renames" in workflow
    assert "git diff --name-only --diff-filter=ACMRT --no-renames" in workflow
    assert 'git cat-file -e "${BASE_SHA}:.reposentinel-baseline.json"' in workflow
    assert 'git show "${BASE_SHA}:.reposentinel-baseline.json"' in workflow
    assert "baseline_args=(--no-default-baseline)" in workflow
    assert "baseline_args=(--baseline \"$trusted_baseline\")" in workflow


def test_policy_filter_includes_regular_to_symlink_type_change(tmp_path: Path) -> None:
    repository = tmp_path / "policy-type-change"
    path = ".reposentinel.toml"
    base_sha, head_sha = _commit_regular_to_symlink_change(repository, path)

    changed_paths = _git(
        repository,
        "diff",
        "--name-only",
        "--diff-filter=ACMRTD",
        "--no-renames",
        base_sha,
        head_sha,
    ).splitlines()

    assert path in changed_paths


def test_changed_file_filter_includes_regular_to_symlink_type_change(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "ordinary-type-change"
    path = "src/config.py"
    (repository / "src").mkdir(parents=True)
    base_sha, head_sha = _commit_regular_to_symlink_change(repository, path)

    changed_paths = _git(
        repository,
        "diff",
        "--name-only",
        "--diff-filter=ACMRT",
        "--no-renames",
        base_sha,
        head_sha,
    ).splitlines()

    assert path in changed_paths


def test_baseline_audit_is_independent_and_non_blocking() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "repo-sentinel-gate.yml"
    ).read_text(encoding="utf-8")

    assert "baseline-audit:" in workflow
    assert "continue-on-error: true" in workflow
    assert "baseline audit --format text" in workflow
    assert "needs: changed-file-gate" not in workflow
