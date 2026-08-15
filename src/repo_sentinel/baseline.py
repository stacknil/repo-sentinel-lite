from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .baseline_matching import BaselineClassification, reconcile_baseline
from .redaction import redact_baseline
from .report import (
    baseline_finding_sort_key,
    baseline_finding_with_fingerprint,
    build_report,
    coerce_finding,
    coerce_missing_files,
    extract_findings,
    normalize_report,
    validate_fingerprint_invariant,
)

BASELINE_SCHEMA_VERSION = 1


def load_baseline(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline is not valid JSON: {exc.msg}") from exc

    if _looks_like_legacy_report(data):
        baseline = baseline_from_report(data)
        source_findings = data.get("findings")
        if isinstance(source_findings, list):
            source_versions_by_fingerprint = _source_versions_by_fingerprint(
                source_findings
            )
            for finding in baseline["findings"]:
                fingerprint = str(finding["fingerprint"])
                if source_versions_by_fingerprint.get(fingerprint) is None:
                    finding.pop("rule_version", None)
        else:
            for finding in baseline["findings"]:
                finding.pop("rule_version", None)
        return baseline

    return normalize_baseline(data)


def write_baseline(path: Path, report: dict[str, object]) -> None:
    path.write_text(format_baseline(baseline_from_report(report)), encoding="utf-8")


def apply_baseline(
    report: dict[str, object], baseline: dict[str, object]
) -> dict[str, object]:
    normalized_report = normalize_report(report)
    current_findings = extract_findings(normalized_report)
    missing_files = coerce_missing_files(normalized_report["missing_files"])
    reconciliation = reconcile_baseline(
        baseline_findings=extract_baseline_findings(baseline),
        current_findings=current_findings,
    )
    for decision in reconciliation.decisions:
        if (
            decision.suppress
            and decision.current is not None
            and decision.current["kind"] == "missing_file"
        ):
            missing_files[str(decision.current["path"])] = False

    return build_report(
        reconciliation.remaining_current,
        missing_files,
        coverage=normalized_report.get("coverage"),
    )


def prune_baseline(
    report: dict[str, object], baseline: dict[str, object]
) -> dict[str, object]:
    current_baseline = baseline_from_report(report)
    reconciliation = reconcile_baseline(
        baseline_findings=extract_baseline_findings(baseline),
        current_findings=extract_baseline_findings(current_baseline),
    )

    return {
        "findings": list(reconciliation.retained_current),
        "generated_at": current_baseline["generated_at"],
        "schema_version": BASELINE_SCHEMA_VERSION,
    }


def update_baseline(
    report: dict[str, object], baseline: dict[str, object] | None = None
) -> dict[str, object]:
    """Build a complete current-state candidate for baseline review.

    ``baseline`` remains accepted for API compatibility. Use ``prune_baseline``
    when the desired operation is to retain only active existing suppressions.
    """
    return baseline_from_report(report)


def audit_baseline(
    report: dict[str, object], baseline: dict[str, object]
) -> dict[str, object]:
    reconciliation = reconcile_baseline(
        baseline_findings=extract_baseline_findings(baseline),
        current_findings=extract_findings(normalize_report(report)),
    )
    active: list[dict[str, object]] = []
    rule_changed: list[dict[str, object]] = []
    relocated: list[dict[str, object]] = []
    changed: list[dict[str, object]] = []
    stale: list[dict[str, object]] = []
    ambiguous: list[dict[str, object]] = []
    for decision in reconciliation.decisions:
        if decision.classification == BaselineClassification.ACTIVE:
            active.append(decision.baseline)
        elif decision.classification == BaselineClassification.STALE:
            stale.append(decision.baseline)
        elif decision.classification == BaselineClassification.AMBIGUOUS:
            ambiguous.append(
                {
                    "baseline": decision.baseline,
                    "candidates": list(decision.candidates),
                    "reason": decision.reason,
                }
            )
        else:
            current = decision.current
            if current is None:
                raise AssertionError("classified baseline match has no current finding")
            entry = {
                "baseline": decision.baseline,
                "current": current,
                "reason": decision.reason,
            }
            if decision.classification == BaselineClassification.RULE_CHANGED:
                rule_changed.append(entry)
            elif decision.classification == BaselineClassification.RELOCATED:
                relocated.append(entry)
            elif decision.classification == BaselineClassification.CHANGED:
                changed.append(entry)

    unmatched = list(reconciliation.unmatched_current)
    return {
        "active": active,
        "rule_changed": rule_changed,
        "relocated": relocated,
        "changed": changed,
        "stale": stale,
        "ambiguous": ambiguous,
        "summary": {
            "active": len(active),
            "rule_changed": len(rule_changed),
            "relocated": len(relocated),
            "changed": len(changed),
            "stale": len(stale),
            "ambiguous": len(ambiguous),
            "unmatched": len(unmatched),
        },
        "unmatched": unmatched,
    }


def format_baseline(
    baseline: dict[str, object], *, reveal_secrets: bool = False
) -> str:
    normalized = normalize_baseline(baseline)
    rendered = normalized if reveal_secrets else redact_baseline(normalized)
    return json.dumps(rendered, indent=2, sort_keys=True) + "\n"


def format_baseline_audit(
    audit: dict[str, object], *, output_format: str = "text"
) -> str:
    if output_format == "json":
        return json.dumps(
            redact_baseline(audit), indent=2, sort_keys=True
        ) + "\n"

    summary = audit.get("summary", {})
    if not isinstance(summary, dict):
        raise ValueError("baseline audit summary must be an object")
    lines = [
        "Baseline audit:",
        f"active: {int(summary.get('active', 0))}",
        f"rule_changed: {int(summary.get('rule_changed', 0))}",
        f"relocated: {int(summary.get('relocated', 0))}",
        f"changed: {int(summary.get('changed', 0))}",
        f"stale: {int(summary.get('stale', 0))}",
        f"ambiguous: {int(summary.get('ambiguous', 0))}",
        f"unmatched: {int(summary.get('unmatched', 0))}",
    ]
    return "\n".join(lines) + "\n"


def baseline_from_report(report: dict[str, object]) -> dict[str, object]:
    findings = [
        baseline_finding_with_fingerprint(finding)
        for finding in extract_findings(normalize_report(report))
    ]
    findings.sort(key=baseline_finding_sort_key)

    return {
        "findings": findings,
        "generated_at": generate_baseline_timestamp(),
        "schema_version": BASELINE_SCHEMA_VERSION,
    }


def generate_baseline_timestamp() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
            "+00:00", "Z"
        )
    )


def normalize_baseline(baseline: object) -> dict[str, object]:
    if not isinstance(baseline, dict):
        raise ValueError("baseline must be a JSON object")

    schema_version = baseline.get("schema_version")
    generated_at = baseline.get("generated_at")
    findings_value = baseline.get("findings")

    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise ValueError("baseline schema_version must be an integer")
    if schema_version != BASELINE_SCHEMA_VERSION:
        raise ValueError(
            f"baseline schema_version must be {BASELINE_SCHEMA_VERSION}"
        )
    if not isinstance(generated_at, str):
        raise ValueError("baseline generated_at must be a string")
    if not isinstance(findings_value, list):
        raise ValueError("baseline findings must be a list")

    findings = [coerce_baseline_finding(item) for item in findings_value]
    validate_fingerprint_invariant(findings)
    findings.sort(key=baseline_finding_sort_key)

    return {
        "findings": findings,
        "generated_at": generated_at,
        "schema_version": schema_version,
    }


def extract_baseline_findings(baseline: object) -> list[dict[str, object]]:
    normalized = normalize_baseline(baseline)
    findings = normalized["findings"]
    if not isinstance(findings, list):
        raise ValueError("baseline findings must be a list")
    return findings


def coerce_baseline_finding(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("baseline findings entries must be objects")
    normalized = coerce_finding(value, preserve_fingerprint=True)
    persisted_rule_version = value.get("rule_version")
    if not isinstance(persisted_rule_version, str) or not persisted_rule_version:
        normalized.pop("rule_version", None)
    return normalized


def _looks_like_legacy_report(value: object) -> bool:
    return isinstance(value, dict) and any(
        key in value
        for key in ("high_entropy_findings", "missing_files", "suspicious_files")
    )


def _source_versions_by_fingerprint(
    findings: list[object],
) -> dict[str, str | None]:
    versions: dict[str, str | None] = {}
    for source_finding in findings:
        normalized = coerce_baseline_finding(source_finding)
        fingerprint = normalized.get("fingerprint")
        if not isinstance(fingerprint, str):
            continue
        rule_version = normalized.get("rule_version")
        versions[fingerprint] = (
            rule_version if isinstance(rule_version, str) else None
        )
    return versions


__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "apply_baseline",
    "audit_baseline",
    "baseline_from_report",
    "coerce_baseline_finding",
    "extract_baseline_findings",
    "format_baseline",
    "format_baseline_audit",
    "generate_baseline_timestamp",
    "load_baseline",
    "normalize_baseline",
    "prune_baseline",
    "update_baseline",
    "write_baseline",
]
