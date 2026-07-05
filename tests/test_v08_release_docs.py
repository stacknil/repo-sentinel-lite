from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v08_release_notes_capture_rule_and_baseline_semantics() -> None:
    notes = (ROOT / "docs" / "release-notes-v0.8.0.md").read_text(
        encoding="utf-8"
    )

    for required in (
        "Rule and Baseline Semantics Release",
        "rule_id",
        "rule_version",
        "repo-sentinel baseline audit",
        "active",
        "stale",
        "ambiguous",
        "unmatched",
        "allowlist",
        "scan --changed-files",
        "does not replace enterprise secret scanning",
    ):
        assert required in notes


def test_readme_links_v08_semantics_and_performance_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for required in (
        "docs/release-notes-v0.8.0.md",
        "docs/performance-envelope-v0.8.md",
        "repo-sentinel baseline audit",
        "repo-sentinel scan --changed-files",
        "[allowlist]",
        "rule_id",
    ):
        assert required in readme
