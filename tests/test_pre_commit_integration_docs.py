from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pre_commit_integration_guide_covers_adoption_workflow() -> None:
    guide = (ROOT / "docs" / "pre-commit-integration.md").read_text(
        encoding="utf-8"
    )
    workflow = (
        ROOT / ".github" / "workflows" / "pre-commit-provider.yml"
    ).read_text(encoding="utf-8")

    for heading in (
        "## Install",
        "## Configure",
        "## Trigger a Failure",
        "## Create a Baseline",
        "## Review a Baseline",
        "## Reuse in CI",
    ):
        assert heading in guide

    for command in (
        "python -m pip install pre-commit",
        "python -m pip install repo-sentinel-lite",
        "repo: https://github.com/stacknil/repo-sentinel-lite",
        "rev: v0.6.3",
        "id: repo-sentinel-error",
        "id: repo-sentinel-warning",
        "pre-commit run repo-sentinel-error --hook-stage manual --all-files",
        "repo-sentinel scan --fail-on-severity error examples/dirty-repo",
        "repo-sentinel scan --write-baseline .reposentinel-baseline.json .",
        "--update-baseline .reposentinel-baseline.next.json",
        "repo-sentinel scan --fail-on-severity error .",
    ):
        assert command in guide

    assert "pass_filenames: false" in guide
    assert "baseline-review.md" in guide
    assert "docs/pre-commit-integration.md" in workflow
