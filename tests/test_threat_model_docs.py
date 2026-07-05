from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_threat_model_states_secret_scanning_boundaries() -> None:
    threat_model = (ROOT / "docs" / "threat-model.md").read_text(
        encoding="utf-8"
    )
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    for required in (
        "not a replacement for enterprise secret scanning",
        "does not guarantee that a repository has no leaked secret",
        "does not identify every credential format",
        "does not expose a network service",
        "does not report findings to a remote backend",
        "historical Git scanning",
        "rotate or revoke",
    ):
        assert required in threat_model

    for evidence_path in (
        "src/repo_sentinel/cli.py",
        "src/repo_sentinel/scanner.py",
        "src/repo_sentinel/rules/",
        "src/repo_sentinel/baseline.py",
        "src/repo_sentinel/config.py",
        ".pre-commit-hooks.yaml",
        "docs/baseline-review.md",
        "docs/pre-commit-integration.md",
        ".github/workflows/ci.yml",
    ):
        assert evidence_path in threat_model

    assert "docs/threat-model.md" in readme
    assert "docs/threat-model.md" in security
