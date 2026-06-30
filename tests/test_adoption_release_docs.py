from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_v07_adoption_plan_records_policy_and_dogfooding_targets() -> None:
    plan = (ROOT / "docs" / "v0.7-adoption-release.md").read_text(
        encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    reviewer_brief = (ROOT / "docs" / "reviewer-brief.md").read_text(
        encoding="utf-8"
    )
    release_notes = (ROOT / "docs" / "release-notes-v0.7.0.md").read_text(
        encoding="utf-8"
    )

    assert "Decision: choose scheme A." in plan
    assert "supports Python 3.11 and newer" in plan
    assert "Python 3.11, 3.12, 3.13, and 3.14" in plan
    assert "Python 3.14-only experimental posture" in plan
    assert "## RSL-03 example-repo-before-after" in plan
    assert "## RSL-04 pre-commit-integration-guide" in plan
    assert "## RSL-05 threat-model" in plan
    assert "The v0.7.0 theme is:" in reviewer_brief
    assert "Keep production releases boring, reproducible, and documented" in (
        reviewer_brief
    )
    assert "examples/dirty-repo" in reviewer_brief
    assert "examples/clean-repo" in reviewer_brief
    assert "examples/outputs/" in reviewer_brief
    assert "docs/pre-commit-integration.md" in reviewer_brief
    assert "docs/threat-model.md" in reviewer_brief
    assert "docs/self-dogfooding.md" in reviewer_brief
    assert "CI-integrated" in reviewer_brief
    assert "accidental sensitive filename" in reviewer_brief
    assert "generated artifacts ignored" in reviewer_brief
    assert "source, configs, and sample inputs remain" in reviewer_brief
    assert (
        "Adoption release for portfolio-level repository hygiene enforcement."
        in reviewer_brief
    )
    assert "examples/" in readme
    assert "docs/pre-commit-integration.md" in readme
    assert "docs/threat-model.md" in readme
    assert "docs/self-dogfooding.md" in readme
    assert "docs/v0.7-adoption-release.md" in readme
    assert "docs/release-notes-v0.7.0.md" in readme
    assert "release-notes-v0.7.0.md" in plan
    assert (
        "Adoption release for portfolio-level repository hygiene enforcement."
        in release_notes
    )
    assert "## Adoption Evidence" in release_notes
    assert "## Scanner Behavior Since 0.6.3" in release_notes

    for target in ("LogLens", "telemetry-lab", "sec-writeups-public"):
        assert f"`{target}`" in plan
        assert f"`{target}`" in reviewer_brief
        assert f"`{target}`" in release_notes

    for command in (
        "repo-sentinel scan --fail-on-severity error .",
        ".reposentinel.toml",
        ".reposentinel-baseline.json",
        "examples/dirty-repo",
        "examples/clean-repo",
        "examples/outputs/dirty-scan.json",
        "examples/outputs/dirty-baseline.json",
        "examples/outputs/dirty-fail-on-findings.txt",
        "examples/outputs/clean-scan.json",
        "examples/outputs/clean-baseline.json",
        "examples/outputs/clean-fail-on-findings.txt",
        "--fail-on-findings",
        "repo-sentinel-error",
        "repo-sentinel-warning",
        ".reposentinel-baseline.json",
        "enterprise secret scanning",
        "does not identify every credential format",
        "self-dogfooding.md",
    ):
        assert command in plan
