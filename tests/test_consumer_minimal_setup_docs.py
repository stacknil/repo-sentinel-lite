from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_consumer_minimal_setup_covers_small_adoption_path() -> None:
    guide = (ROOT / "docs" / "consumer-minimal-setup.md").read_text(
        encoding="utf-8"
    )

    for heading in (
        "## Install",
        "## First Scan",
        "## Optional Config",
        "## Optional Baseline",
        "## Optional Pre-Commit",
        "## Optional CI",
    ):
        assert heading in guide

    for required in (
        "python -m pip install repo-sentinel-lite",
        "repo-sentinel scan .",
        "repo-sentinel scan --fail-on-severity error --format text .",
        "repo-sentinel scan --fail-on-severity warning --format text .",
        'ignore_globs = ["dist/**", "generated/**"]',
        "repo-sentinel scan --no-default-baseline --format text .",
        "repo-sentinel scan --write-baseline .reposentinel-baseline.json .",
        "--update-baseline .reposentinel-baseline.next.json",
        "rev: v0.7.1",
        "id: repo-sentinel-error",
        ".github/workflows/repo-sentinel.yml",
        "name: Repo Sentinel",
        "runs-on: ubuntu-24.04",
        'python-version: "3.11"',
        "python -m pip install repo-sentinel-lite==0.7.1",
        "baseline-review.md",
        "pre-commit-integration.md",
        "output-format-stability.md",
    ):
        assert required in guide
