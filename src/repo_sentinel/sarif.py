from __future__ import annotations

import json

from .coverage import extract_coverage
from .report import extract_findings, normalize_report
from .rules.registry import RULE_DEFINITIONS, rule_for_kind


def format_sarif_report(
    report: dict[str, object], *, reveal_secrets: bool = False
) -> str:
    normalized = normalize_report(report)
    findings = extract_findings(normalized)
    coverage = extract_coverage(normalized)

    run: dict[str, object] = {
        "results": [_sarif_result(finding) for finding in findings],
        "tool": {
            "driver": {
                "name": "repo-sentinel-lite",
                "rules": [
                    _sarif_rule(rule.kind)
                    for rule in sorted(
                        RULE_DEFINITIONS, key=lambda item: item.rule_id
                    )
                ],
            }
        },
    }
    if coverage is not None:
        run["properties"] = {"repoSentinelCoverage": coverage}
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [run],
        "version": "2.1.0",
    }
    return json.dumps(sarif, indent=2, sort_keys=True) + "\n"


def _sarif_rule(kind: str) -> dict[str, object]:
    rule = rule_for_kind(kind)
    return {
        "defaultConfiguration": {"level": rule.severity},
        "fullDescription": {"text": rule.full_description},
        "id": rule.rule_id,
        "name": rule.name,
        "properties": {
            "kind": rule.kind,
            "ruleVersion": rule.rule_version,
        },
        "shortDescription": {"text": rule.short_description},
    }


def _sarif_result(finding: dict[str, object]) -> dict[str, object]:
    return {
        "level": str(finding["severity"]),
        "locations": [_sarif_location(finding)],
        "message": {"text": _sarif_message(finding)},
        "partialFingerprints": {
            "repoSentinelFingerprint": str(finding["fingerprint"])
        },
        "properties": {
            "kind": str(finding["kind"]),
            "ruleVersion": str(finding["rule_version"]),
        },
        "ruleId": str(finding["rule_id"]),
    }


def _sarif_location(finding: dict[str, object]) -> dict[str, object]:
    path = str(finding.get("path", finding.get("file", "")))
    physical_location: dict[str, object] = {
        "artifactLocation": {"uri": path},
    }
    if "line" in finding:
        physical_location["region"] = {"startLine": int(finding["line"])}

    return {"physicalLocation": physical_location}


def _sarif_message(finding: dict[str, object]) -> str:
    kind = str(finding["kind"])
    if kind == "high_entropy":
        return (
            "High-entropy string detected: "
            f"{finding['file']}:{int(finding['line'])}"
        )
    if kind == "missing_file":
        return f"Required file missing: {finding['path']}"
    if kind == "suspicious_file":
        return f"Suspicious file detected: {finding['path']}"

    path = str(finding.get("path", finding.get("file", "")))
    if "line" in finding:
        path = f"{path}:{int(finding['line'])}"
    return f"{finding['rule_id']} detected: {path}"


__all__ = ["format_sarif_report"]
