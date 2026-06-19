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

    assert "Decision: choose scheme A." in plan
    assert "supports Python 3.11 and newer" in plan
    assert "Python 3.11, 3.12, 3.13, and 3.14" in plan
    assert "Python 3.14-only experimental posture" in plan
    assert "## RSL-03 example-repo-before-after" in plan
    assert "v0.7 Adoption Release" in reviewer_brief
    assert "examples/dirty-repo" in reviewer_brief
    assert "examples/clean-repo" in reviewer_brief
    assert "examples/outputs/" in reviewer_brief
    assert "examples/" in readme
    assert "docs/v0.7-adoption-release.md" in readme

    for target in ("LogLens", "telemetry-lab", "sec-writeups-public"):
        assert f"`{target}`" in plan
        assert f"`{target}`" in reviewer_brief

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
    ):
        assert command in plan
