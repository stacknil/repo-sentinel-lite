from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_self_dogfooding_matrix_records_adoption_boundaries() -> None:
    doc = (ROOT / "docs" / "self-dogfooding.md").read_text(encoding="utf-8")

    for required in (
        "## Adoption Matrix",
        "## Version Posture",
        "Current source metadata requires Python 3.11 or newer",
        "production package metadata was",
        "confirmed as Python 3.11+",
        "pin or install the intended package version",
        "current package metadata evidence",
        "| Repository | Configuration strategy | Baseline present? "
        "| Why paths are ignored | Command |",
        "`sec-writeups-public` | Project-specific",
        "Yes: `.reposentinel-baseline.json`",
        "`repo-sentinel scan --baseline .reposentinel-baseline.json "
        "--fail-on-severity error --format text .`",
        "`LogLens` | Filename and repository hygiene only",
        "No: the first reviewed run passed without one",
        "`repo-sentinel scan --fail-on-severity error --format text .`",
        "`telemetry-lab` | Filename and high-entropy scanning",
        "follow-up should update to the intended package version",
        "No: the reviewed source tree passed without one",
        "source, configs, and raw sample inputs remain in scope",
    ):
        assert required in doc


def test_self_dogfooding_doc_records_sec_writeups_evidence() -> None:
    doc = (ROOT / "docs" / "self-dogfooding.md").read_text(encoding="utf-8")

    for required in (
        "v0.7 is the self-dogfooding release",
        "`sec-writeups-public`",
        ".reposentinel.toml",
        ".reposentinel-baseline.json",
        "tracked on `origin/main`",
        "review latest baseline drift",
        "repo-sentinel scan \\",
        "--baseline .reposentinel-baseline.json",
        "--fail-on-severity error",
        "baseline-review.md",
        "pre-commit-integration.md",
        "threat-model.md",
    ):
        assert required in doc


def test_self_dogfooding_doc_records_loglens_evidence() -> None:
    doc = (ROOT / "docs" / "self-dogfooding.md").read_text(encoding="utf-8")

    for required in (
        "`LogLens` | Filename and repository hygiene only",
        "PR #74",
        "`stacknil/LogLens`",
        ".github/workflows/repo-sentinel.yml",
        "Repo Sentinel",
        "production PyPI under Python",
        "Python 3.14",
        "no `.reposentinel-baseline.json` was added",
        "repository hygiene and accidental sensitive",
        "max_text_file_size = 0",
        "entropy_threshold = 999.0",
        "C++ build artifacts",
        "Current source and production package metadata require Python 3.11",
        "pin or install the intended package version",
    ):
        assert required in doc


def test_self_dogfooding_doc_records_telemetry_lab_evidence() -> None:
    doc = (ROOT / "docs" / "self-dogfooding.md").read_text(encoding="utf-8")

    for required in (
        "`telemetry-lab` | Filename and high-entropy scanning",
        "PR #71",
        "`stacknil/telemetry-lab`",
        "initial workflow installed `repo-sentinel-lite==0.6.3`",
        "normal Python 3.11+ policy",
        "no `.reposentinel-baseline.json` was added",
        "`data/processed/**`",
        "`demos/*/artifacts/**`",
        "`src/**`",
        "`configs/**`",
        "`data/raw/**`",
        "reviewed threshold",
        "`4.5`",
        "6-bit-entropy probe",
        "177 tests",
        "23 strict artifacts",
        "6 visual snapshots",
    ):
        assert required in doc
