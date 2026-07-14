from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .redaction import redact_baseline
from .report import (
    baseline_finding_identity,
    baseline_finding_sort_key,
    baseline_finding_with_fingerprint,
    build_report,
    coerce_finding,
    coerce_missing_files,
    extract_findings,
    finding_matches_baseline,
    normalize_report,
)

BASELINE_SCHEMA_VERSION = 1


def load_baseline(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline is not valid JSON: {exc.msg}") from exc

    if _looks_like_legacy_report(data):
        return baseline_from_report(normalize_report(data))

    return normalize_baseline(data)


def write_baseline(path: Path, report: dict[str, object]) -> None:
    path.write_text(format_baseline(baseline_from_report(report)), encoding="utf-8")


def apply_baseline(
    report: dict[str, object], baseline: dict[str, object]
) -> dict[str, object]:
    normalized_report = normalize_report(report)
    current_findings = extract_findings(normalized_report)
    missing_files = coerce_missing_files(normalized_report["missing_files"])
    baseline_fingerprint_keys, baseline_finding_keys = baseline_match_keys(baseline)
    remaining_findings: list[dict[str, object]] = []

    for finding in current_findings:
        if finding_matches_baseline(
            finding, baseline_fingerprint_keys, baseline_finding_keys
        ):
            if finding["kind"] == "missing_file":
                missing_files[str(finding["path"])] = False
            continue
        remaining_findings.append(finding)

    return build_report(remaining_findings, missing_files)


def prune_baseline(
    report: dict[str, object], baseline: dict[str, object]
) -> dict[str, object]:
    current_baseline = baseline_from_report(report)
    current_findings = extract_baseline_findings(current_baseline)
    baseline_fingerprint_keys, baseline_finding_keys = baseline_match_keys(baseline)

    return {
        "findings": [
            finding
            for finding in current_findings
            if finding_matches_baseline(
                finding,
                baseline_fingerprint_keys,
                baseline_finding_keys,
            )
        ],
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
    current_findings = extract_findings(normalize_report(report))
    baseline_findings = extract_baseline_findings(baseline)
    current_by_fingerprint = {
        str(finding["fingerprint"]): finding for finding in current_findings
    }
    current_by_identity: dict[tuple[object, ...], list[dict[str, object]]] = {}
    for finding in current_findings:
        current_by_identity.setdefault(
            baseline_finding_identity(finding), []
        ).append(finding)

    active: list[dict[str, object]] = []
    stale: list[dict[str, object]] = []
    ambiguous: list[dict[str, object]] = []
    matched_current_fingerprints: set[str] = set()

    for baseline_finding in baseline_findings:
        fingerprint = baseline_finding.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint in current_by_fingerprint:
            active.append(baseline_finding)
            matched_current_fingerprints.add(fingerprint)
            continue

        identity_candidates = current_by_identity.get(
            baseline_finding_identity(baseline_finding), []
        )
        if fingerprint is None and len(identity_candidates) == 1:
            active.append(baseline_finding)
            matched_current_fingerprints.add(str(identity_candidates[0]["fingerprint"]))
            continue
        if identity_candidates:
            ambiguous.append(
                {
                    "baseline": baseline_finding,
                    "candidates": identity_candidates,
                    "reason": (
                        "same baseline identity but no current fingerprint match"
                    ),
                }
            )
            continue

        location_candidates = _same_location_candidates(
            baseline_finding, current_findings
        )
        if location_candidates:
            ambiguous.append(
                {
                    "baseline": baseline_finding,
                    "candidates": location_candidates,
                    "reason": "same rule/location but different fingerprint",
                }
            )
        else:
            stale.append(baseline_finding)

    unmatched = [
        finding
        for finding in current_findings
        if str(finding["fingerprint"]) not in matched_current_fingerprints
    ]
    return {
        "active": sorted(active, key=baseline_finding_sort_key),
        "ambiguous": ambiguous,
        "stale": sorted(stale, key=baseline_finding_sort_key),
        "summary": {
            "active": len(active),
            "ambiguous": len(ambiguous),
            "stale": len(stale),
            "unmatched": len(unmatched),
        },
        "unmatched": sorted(unmatched, key=baseline_finding_sort_key),
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
        return json.dumps(audit, indent=2, sort_keys=True) + "\n"

    summary = audit.get("summary", {})
    if not isinstance(summary, dict):
        raise ValueError("baseline audit summary must be an object")
    lines = [
        "Baseline audit:",
        f"active: {int(summary.get('active', 0))}",
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


def baseline_match_keys(
    baseline: object,
) -> tuple[frozenset[str], frozenset[tuple[object, ...]]]:
    baseline_findings = extract_baseline_findings(baseline)
    return (
        frozenset(
            str(finding["fingerprint"])
            for finding in baseline_findings
            if "fingerprint" in finding
        ),
        frozenset(
            baseline_finding_identity(finding)
            for finding in baseline_findings
            if "fingerprint" not in finding
        ),
    )


def coerce_baseline_finding(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("baseline findings entries must be objects")
    return coerce_finding(value, preserve_fingerprint=True)


def _looks_like_legacy_report(value: object) -> bool:
    return isinstance(value, dict) and any(
        key in value
        for key in ("high_entropy_findings", "missing_files", "suspicious_files")
    )


def _same_location_candidates(
    baseline_finding: dict[str, object], current_findings: list[dict[str, object]]
) -> list[dict[str, object]]:
    baseline_rule_id = str(baseline_finding.get("rule_id", ""))
    baseline_path = str(
        baseline_finding.get("path", baseline_finding.get("file", ""))
    )
    baseline_line = baseline_finding.get("line")
    return [
        finding
        for finding in current_findings
        if str(finding.get("rule_id", "")) == baseline_rule_id
        and str(finding.get("path", finding.get("file", ""))) == baseline_path
        and finding.get("line") == baseline_line
    ]


__all__ = [
    "BASELINE_SCHEMA_VERSION",
    "apply_baseline",
    "audit_baseline",
    "baseline_from_report",
    "baseline_match_keys",
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
