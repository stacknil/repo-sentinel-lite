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
