from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_output_format_stability_doc_sets_ci_artifact_expectations() -> None:
    doc = (ROOT / "docs" / "output-format-stability.md").read_text(
        encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    release_notes = (ROOT / "docs" / "release-notes-v0.7.1.md").read_text(
        encoding="utf-8"
    )

    for heading in (
        "## Text Output",
        "## JSON Scan Output",
        "## Baseline Output",
    ):
        assert heading in doc

    for required in (
        "repo-sentinel scan --format text --fail-on-severity error .",
        "repo-sentinel scan --format json --output repo-sentinel-report.json .",
        "repo-sentinel scan --write-baseline .reposentinel-baseline.json .",
        "generated_at",
        "is not expected to be byte-for-byte identical across",
        "High-entropy tokens are redacted by default",
        "does not prove that the repository contains no leaked secret",
        ".reposentinel-baseline.next.json",
    ):
        assert required in doc

    assert "docs/output-format-stability.md" in readme
    assert "output" in release_notes
    assert "stability guidance for CI artifacts" in release_notes
    assert "Adds no new scanning rules." in release_notes
