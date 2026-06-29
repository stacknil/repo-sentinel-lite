from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_self_dogfooding_doc_records_sec_writeups_evidence() -> None:
    doc = (ROOT / "docs" / "self-dogfooding.md").read_text(encoding="utf-8")

    for required in (
        "v0.7 is the self-dogfooding release",
        "`sec-writeups-public`",
        ".reposentinel.toml",
        ".reposentinel-baseline.json",
        "tracked on `origin/main`",
        "Review latest baseline drift",
        "repo-sentinel scan \\",
        "--baseline .reposentinel-baseline.json",
        "--fail-on-severity error",
        "baseline-review.md",
        "pre-commit-integration.md",
        "threat-model.md",
    ):
        assert required in doc


def test_self_dogfooding_doc_keeps_pending_targets_visible() -> None:
    doc = (ROOT / "docs" / "self-dogfooding.md").read_text(encoding="utf-8")

    for target in ("`LogLens`", "`telemetry-lab`"):
        assert target in doc
        assert "Pending" in doc
