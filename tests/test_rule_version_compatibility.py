from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import repo_sentinel.report as report_module
from repo_sentinel.baseline import (
    apply_baseline,
    audit_baseline,
    baseline_from_report,
    format_baseline_audit,
    load_baseline,
    normalize_baseline,
)
from repo_sentinel.report import build_report, finding_fingerprint


def _report(**overrides: object) -> dict[str, object]:
    finding: dict[str, object] = {
        "file": "tokens.txt",
        "kind": "assignment_context",
        "line": 2,
        "path": "tokens.txt",
        "remediation_hint": "Replace with a synthetic placeholder.",
        "rule_id": "secret.assignment_context",
        "rule_version": "1",
        "severity": "warning",
        "token": "shorttok9",
    }
    finding.update(overrides)
    return build_report([finding], {})


def _classification(audit: dict[str, object]) -> str:
    categories = (
        "active",
        "rule_changed",
        "relocated",
        "changed",
        "stale",
        "ambiguous",
        "unmatched",
    )
    populated = [name for name in categories if audit.get(name)]
    assert len(populated) == 1
    return populated[0]


@pytest.mark.parametrize(
    (
        "baseline_overrides",
        "current_overrides",
        "missing_version",
        "expected_classification",
        "expected_suppressed",
        "expected_fingerprint_equal",
    ),
    [
        pytest.param({}, {}, False, "active", True, True, id="same-version"),
        pytest.param(
            {},
            {"rule_version": "2"},
            False,
            "rule_changed",
            True,
            True,
            id="explicit-version-drift",
        ),
        pytest.param(
            {},
            {"line": 9, "rule_version": "2"},
            False,
            "rule_changed",
            True,
            False,
            id="version-drift-and-relocation",
        ),
        pytest.param(
            {"rule_version": "2"},
            {"rule_version": "2"},
            False,
            "active",
            True,
            True,
            id="refreshed-current-version",
        ),
        pytest.param(
            {},
            {"rule_version": "2"},
            True,
            "rule_changed",
            True,
            True,
            id="missing-persisted-version",
        ),
        pytest.param(
            {},
            {
                "rule_id": "secret.reclassified_context",
                "rule_version": "2",
            },
            False,
            "active",
            True,
            True,
            id="different-rule-id",
        ),
        pytest.param(
            {},
            {"severity": "error"},
            False,
            "active",
            True,
            True,
            id="severity-drift-without-version-bump",
        ),
        pytest.param(
            {},
            {"rule_version": "2", "token": "different9"},
            False,
            "changed",
            False,
            False,
            id="version-and-content-drift",
        ),
    ],
)
def test_rule_version_compatibility_matrix(
    baseline_overrides: dict[str, object],
    current_overrides: dict[str, object],
    missing_version: bool,
    expected_classification: str,
    expected_suppressed: bool,
    expected_fingerprint_equal: bool,
) -> None:
    baseline = baseline_from_report(_report(**baseline_overrides))
    if missing_version:
        baseline["findings"][0].pop("rule_version")
    current = _report(**current_overrides)

    audit = audit_baseline(current, baseline)
    suppressed = apply_baseline(current, baseline)["findings"] == []

    assert baseline["schema_version"] == 1
    assert _classification(audit) == expected_classification
    assert suppressed is expected_suppressed
    assert (
        baseline["findings"][0]["fingerprint"]
        == finding_fingerprint(current["findings"][0])
    ) is expected_fingerprint_equal
    if expected_classification == "rule_changed":
        entry = audit["rule_changed"][0]
        assert entry["baseline"]["line"] == 2
        assert entry["current"]["line"] == current_overrides.get("line", 2)
        if missing_version:
            assert entry["reason"] == "unknown baseline rule version"


def test_missing_version_survives_load_after_live_registry_bump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = baseline_from_report(_report())
    baseline["findings"][0].pop("rule_version")
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    original_lookup = report_module.rule_for_kind
    current_rule = replace(
        original_lookup("assignment_context"), rule_version="2"
    )
    monkeypatch.setattr(
        report_module,
        "rule_for_kind",
        lambda kind: current_rule
        if kind == "assignment_context"
        else original_lookup(kind),
    )

    loaded = load_baseline(baseline_path)
    current = build_report(
        [
            {
                "file": "tokens.txt",
                "kind": "assignment_context",
                "line": 2,
                "token": "shorttok9",
            }
        ],
        {},
    )
    audit = audit_baseline(current, loaded)

    assert "rule_version" not in loaded["findings"][0]
    assert current["findings"][0]["rule_version"] == "2"
    assert audit["summary"]["rule_changed"] == 1
    assert audit["rule_changed"][0]["reason"] == "unknown baseline rule version"
    assert apply_baseline(current, loaded)["findings"] == []


@pytest.mark.parametrize(
    "persisted_version, expected_reason",
    [
        pytest.param(
            "1", "rule version changed from 1 to 2", id="explicit-version"
        ),
        pytest.param(None, "unknown baseline rule version", id="missing-version"),
    ],
)
def test_report_shaped_baseline_load_preserves_version_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persisted_version: str | None,
    expected_reason: str,
) -> None:
    report = _report(rule_version="1")
    if persisted_version is None:
        report["findings"][0].pop("rule_version")
    report_path = tmp_path / "report-shaped-baseline.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    original_lookup = report_module.rule_for_kind
    current_rule = replace(
        original_lookup("assignment_context"), rule_version="2"
    )
    monkeypatch.setattr(
        report_module,
        "rule_for_kind",
        lambda kind: current_rule
        if kind == "assignment_context"
        else original_lookup(kind),
    )

    loaded = load_baseline(report_path)
    current = build_report(
        [
            {
                "file": "tokens.txt",
                "kind": "assignment_context",
                "line": 2,
                "token": "shorttok9",
            }
        ],
        {},
    )
    audit = audit_baseline(current, loaded)

    assert loaded["findings"][0].get("rule_version") == persisted_version
    assert audit["summary"]["rule_changed"] == 1
    assert audit["rule_changed"][0]["reason"] == expected_reason


@pytest.mark.parametrize("missing_version", [False, True])
def test_exact_fingerprint_version_drift_precedes_duplicate_content_ambiguity(
    missing_version: bool,
) -> None:
    baseline = baseline_from_report(_report(rule_version="1", line=2))
    if missing_version:
        baseline["findings"][0].pop("rule_version")
    current = build_report(
        [
            _report(rule_version="2", line=2)["findings"][0],
            _report(rule_version="2", line=9)["findings"][0],
        ],
        {},
    )

    audit = audit_baseline(current, baseline)

    assert audit["summary"]["rule_changed"] == 1
    assert audit["summary"]["ambiguous"] == 0
    assert audit["summary"]["unmatched"] == 1
    assert audit["rule_changed"][0]["current"]["line"] == 2


def test_rule_changed_json_and_text_outputs_include_review_context() -> None:
    baseline = baseline_from_report(_report(line=2))
    current = _report(line=9, rule_version="2")
    audit = audit_baseline(current, baseline)

    json_output = json.loads(format_baseline_audit(audit, output_format="json"))
    text_output = format_baseline_audit(audit, output_format="text")

    assert json_output["summary"]["rule_changed"] == 1
    assert json_output["rule_changed"][0]["baseline"]["rule_version"] == "1"
    assert json_output["rule_changed"][0]["current"]["rule_version"] == "2"
    assert json_output["rule_changed"][0]["current"]["token"].startswith(
        "<redacted:sha256:"
    )
    assert "shorttok9" not in json.dumps(json_output)
    assert "rule_changed: 1" in text_output


def test_normalize_schema_v1_baseline_does_not_invent_missing_version() -> None:
    baseline = baseline_from_report(_report())
    baseline["findings"][0].pop("rule_version")

    normalized = normalize_baseline(baseline)

    assert normalized["schema_version"] == 1
    assert "rule_version" not in normalized["findings"][0]
