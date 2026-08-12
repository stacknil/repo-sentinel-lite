from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v081_release_notes_define_registry_recovery_boundary() -> None:
    notes = (ROOT / "docs" / "release-notes-v0.8.1.md").read_text(
        encoding="utf-8"
    )

    for required in (
        "Registry Recovery Patch",
        "release tag verification",
        "before installation",
        "new immutable patch version",
        "unchanged from v0.8.0",
        "GitHub Release records remain unchanged",
        "Rule-version drift classification remains follow-up work",
        "`rule_changed`",
        "fingerprint identity",
    ):
        assert required in notes


def test_readme_links_v081_release_notes() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "docs/release-notes-v0.8.1.md" in readme
