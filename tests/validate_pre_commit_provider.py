from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(args: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    print(f"$ {' '.join(args)}")
    subprocess.run(args, cwd=cwd, env=env, check=True)


def _resolve_pre_commit_command() -> list[str]:
    if importlib.util.find_spec("pre_commit") is not None:
        return [sys.executable, "-m", "pre_commit"]

    pre_commit = shutil.which("pre-commit")
    if pre_commit is not None:
        return [pre_commit]

    raise SystemExit(
        "pre-commit is required to run this self-test; install it in the active "
        "interpreter or make `pre-commit` available on PATH"
    )


def _prepare_provider_snapshot(temp_root: Path, env: dict[str, str]) -> Path:
    snapshot_root = temp_root / "provider"
    snapshot_root.mkdir()

    for relative_path in (
        Path(".pre-commit-hooks.yaml"),
        Path("pyproject.toml"),
        Path("README.md"),
        Path("LICENSE"),
    ):
        shutil.copy2(REPO_ROOT / relative_path, snapshot_root / relative_path)

    shutil.copytree(REPO_ROOT / "src", snapshot_root / "src")

    _run(["git", "init"], cwd=snapshot_root, env=env)
    _run(["git", "add", "."], cwd=snapshot_root, env=env)
    _run(
        [
            "git",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=repo-sentinel-lite",
            "-c",
            "user.email=repo-sentinel-lite@example.invalid",
            "commit",
            "-m",
            "provider snapshot",
        ],
        cwd=snapshot_root,
        env=env,
    )
    return snapshot_root


def main() -> int:
    pre_commit_command = _resolve_pre_commit_command()

    temp_root = Path(tempfile.mkdtemp(dir=REPO_ROOT.parent))
    env = os.environ.copy()
    env["PRE_COMMIT_HOME"] = str(temp_root / "pre-commit-home")
    env["VIRTUALENV_OVERRIDE_APP_DATA"] = str(temp_root / "virtualenv-app-data")

    try:
        snapshot_root = _prepare_provider_snapshot(temp_root, env)

        _run(
            [*pre_commit_command, "validate-manifest", ".pre-commit-hooks.yaml"],
            cwd=snapshot_root,
            env=env,
        )

        consumer_root = temp_root / "consumer"
        consumer_root.mkdir()

        (consumer_root / "README.md").write_text("# Temp consumer\n", encoding="utf-8")
        (consumer_root / "LICENSE").write_text("temp\n", encoding="utf-8")
        (consumer_root / ".gitignore").write_text("*.tmp\n", encoding="utf-8")

        _run(["git", "init"], cwd=consumer_root, env=env)
        _run(["git", "add", "."], cwd=consumer_root, env=env)
        _run(
            [
                *pre_commit_command,
                "try-repo",
                str(snapshot_root),
                "repo-sentinel-error",
                "--all-files",
            ],
            cwd=consumer_root,
            env=env,
        )
        _run(
            [
                *pre_commit_command,
                "try-repo",
                str(snapshot_root),
                "repo-sentinel-warning",
                "--all-files",
            ],
            cwd=consumer_root,
            env=env,
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
