from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_remote_gate_scans_changed_files_and_blocks_only_errors() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "repo-sentinel-gate.yml"
    ).read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "--changed-files" in workflow
    assert "--fail-on-severity error" in workflow
    assert "warnings and coverage skips are report-only" in workflow
    assert "--fail-on-severity warning" not in workflow


def test_baseline_audit_is_independent_and_non_blocking() -> None:
    workflow = (
        ROOT / ".github" / "workflows" / "repo-sentinel-gate.yml"
    ).read_text(encoding="utf-8")

    assert "baseline-audit:" in workflow
    assert "continue-on-error: true" in workflow
    assert "baseline audit --format text" in workflow
    assert "needs: changed-file-gate" not in workflow
