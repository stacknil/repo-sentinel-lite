from __future__ import annotations

from pathlib import Path

from repo_sentinel.scanner import load_baseline

ROOT = Path(__file__).resolve().parents[1]


def test_sample_baseline_is_valid_and_redacted() -> None:
    baseline_path = ROOT / "examples" / "sample-baseline.json"
    baseline_text = baseline_path.read_text(encoding="utf-8")
    baseline = load_baseline(baseline_path)

    assert baseline["schema_version"] == 1
    assert len(baseline["findings"]) == 3
    assert "<redacted:sha256:" in baseline_text
    assert "0123456789abcdef0123456789abcdef" not in baseline_text
