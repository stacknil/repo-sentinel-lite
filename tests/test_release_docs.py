from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_superseded_production_pypi_docs_do_not_use_current_go_live_phrasing() -> None:
    forbidden_fragments = (
        "does not currently exist on\n  production PyPI",
        "does not yet have a `pypi` environment",
        "Manual confirmations still required before push/tag",
        "What still must be manually verified before a real production publish",
        "What still requires manual verification",
        "first stable release still requires explicit maintainer action",
    )

    stale_matches: list[str] = []
    for path in sorted((ROOT / "docs").glob("production-pypi-*.md")):
        text = path.read_text(encoding="utf-8")
        if "Current status: Superseded" not in text:
            continue
        for fragment in forbidden_fragments:
            if fragment in text:
                stale_matches.append(f"{path.relative_to(ROOT)}: {fragment}")

    assert stale_matches == []


def test_release_workflow_and_sop_keep_publisher_targets_aligned() -> None:
    release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
        encoding="utf-8"
    )
    release_sop = (ROOT / "RELEASE.md").read_text(encoding="utf-8")

    assert "before enabling releases" not in release_workflow

    expected_values = (
        "GitHub owner: `stacknil`",
        "Repository name: `repo-sentinel-lite`",
        "Workflow file: `.github/workflows/release.yml`",
        "Environment name: `testpypi`",
        "Environment name: `pypi`",
        "Project name: `repo-sentinel-lite`",
    )
    for value in expected_values:
        assert value in release_sop

    workflow_values = (
        "Environment name: testpypi",
        "Environment name: pypi",
        "TestPyPI project: repo-sentinel-lite",
        "PyPI project: repo-sentinel-lite",
        "name: testpypi",
        "url: https://test.pypi.org/project/repo-sentinel-lite/",
        "repository-url: https://test.pypi.org/legacy/",
        "name: pypi",
        "url: https://pypi.org/project/repo-sentinel-lite/",
    )
    for value in workflow_values:
        assert value in release_workflow


def test_docs_do_not_include_profile_positioning_notes() -> None:
    forbidden_names = {
        "profile-pin-note.md",
    }

    committed_notes = [
        path.relative_to(ROOT).as_posix()
        for path in sorted((ROOT / "docs").rglob("*.md"))
        if path.name in forbidden_names
    ]

    assert committed_notes == []
