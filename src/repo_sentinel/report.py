from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from .config import normalize_path, sort_key, token_sha256
from .coverage import extract_coverage, normalize_coverage
from .redaction import redact_report, render_token
from .rules.entropy import EntropyFinding
from .rules.registry import RULE_DEFINITIONS, SEVERITY_RANKS, rule_for_kind


def build_report(
    findings: Sequence[dict[str, object]],
    missing_files: dict[str, bool],
    *,
    coverage: object | None = None,
) -> dict[str, object]:
    normalized_findings = [_report_finding(finding) for finding in findings]
    normalized_findings.sort(key=baseline_finding_sort_key)

    entropy_findings = [
        _entropy_finding_from_finding(finding).to_dict()
        for finding in normalized_findings
        if finding["kind"] == "high_entropy"
    ]
    suspicious_files = [
        str(finding["path"])
        for finding in normalized_findings
        if finding["kind"] == "suspicious_file"
    ]

    report: dict[str, object] = {
        "findings": normalized_findings,
        "high_entropy_findings": entropy_findings,
        "missing_files": {
            path: is_missing
            for path, is_missing in sorted(
                missing_files.items(), key=lambda item: sort_key(item[0])
            )
        },
        "suspicious_files": sorted(suspicious_files, key=sort_key),
    }
    if coverage is not None:
        report["coverage"] = normalize_coverage(coverage)
    return report


def normalize_report(report: object) -> dict[str, object]:
    entropy_findings, missing_files, suspicious_files = extract_report_components(
        report
    )
    if isinstance(report, dict) and isinstance(report.get("findings"), list):
        findings = [
            coerce_finding(finding, preserve_fingerprint=True)
            for finding in report["findings"]
        ]
    else:
        findings = [
            entropy_baseline_finding(finding) for finding in entropy_findings
        ]
        findings.extend(
            missing_file_baseline_finding(path)
            for path, is_missing in missing_files.items()
            if is_missing
        )
        findings.extend(
            suspicious_file_baseline_finding(path)
            for path in suspicious_files
        )

    coverage = extract_coverage(report)
    return build_report(findings, missing_files, coverage=coverage)


def format_report(
    report: dict[str, object], *, reveal_secrets: bool = False
) -> str:
    normalized = normalize_report(report)
    rendered_report = normalized if reveal_secrets else redact_report(normalized)
    return json.dumps(rendered_report, indent=2, sort_keys=True) + "\n"


def format_text_report(
    report: dict[str, object], *, reveal_secrets: bool = False
) -> str:
    normalized = normalize_report(report)
    entropy_findings, missing_files, suspicious_files = extract_report_components(
        normalized
    )
    findings = extract_findings(normalized)
    coverage = extract_coverage(normalized)
    missing_paths = [path for path, is_missing in missing_files.items() if is_missing]
    structured_findings = [
        finding
        for finding in findings
        if finding["kind"] not in {"high_entropy", "missing_file", "suspicious_file"}
    ]
    lines: list[str] = []

    if suspicious_files:
        lines.append(f"Suspicious files ({len(suspicious_files)}):")
        lines.extend(
            f"- [{severity_label('suspicious_file')}] {path}"
            for path in suspicious_files
        )

    if missing_paths:
        if lines:
            lines.append("")
        lines.append(f"Missing required files ({len(missing_paths)}):")
        lines.extend(
            f"- [{severity_label('missing_file')}] {path}" for path in missing_paths
        )

    if entropy_findings:
        if lines:
            lines.append("")
        lines.append(f"High-entropy findings ({len(entropy_findings)}):")
        lines.extend(
            (
                f"- [{severity_label('high_entropy')}] "
                f"{finding.file}:{finding.line} "
                f"entropy={finding.entropy} "
                f"token={render_token(finding.token, reveal_secrets)}"
            )
            for finding in entropy_findings
        )

    if structured_findings:
        if lines:
            lines.append("")
        lines.append(
            f"Structured secret-adjacent findings ({len(structured_findings)}):"
        )
        lines.extend(
            _text_structured_finding(finding, reveal_secrets=reveal_secrets)
            for finding in structured_findings
        )

    if not lines:
        lines.append("No findings.")

    if coverage is not None and int(coverage["files_skipped"]) > 0:
        lines.append("")
        lines.append(
            "Coverage: inspected "
            f"{coverage['files_inspected']} of {coverage['files_considered']} files; "
            f"skipped {coverage['files_skipped']}."
        )
        skipped_files = coverage["skipped_files"]
        if not isinstance(skipped_files, list):
            raise ValueError("coverage skipped_files must be a list")
        lines.extend(
            f"- [{skip['reason']}] {skip['path']}" for skip in skipped_files
        )

    return "\n".join(lines) + "\n"


def has_findings(report: dict[str, object]) -> bool:
    return bool(extract_findings(normalize_report(report)))


def has_findings_at_or_above_severity(
    report: dict[str, object], severity: str
) -> bool:
    minimum_rank = SEVERITY_RANKS[severity]
    for finding in extract_findings(normalize_report(report)):
        finding_severity = str(finding["severity"])
        if SEVERITY_RANKS[finding_severity] >= minimum_rank:
            return True

    return False


def extract_findings(report: object) -> list[dict[str, object]]:
    normalized = report if _is_normalized_report(report) else normalize_report(report)
    if not isinstance(normalized, dict):
        raise ValueError("report must be a JSON object")
    findings = normalized["findings"]
    if not isinstance(findings, list):
        raise ValueError("report findings must be a list")
    normalized_findings = [
        coerce_finding(item, preserve_fingerprint=True) for item in findings
    ]
    for finding in normalized_findings:
        if "fingerprint" not in finding:
            finding["fingerprint"] = finding_fingerprint(finding)
    return normalized_findings


def extract_report_components(
    report: object,
) -> tuple[list[EntropyFinding], dict[str, bool], list[str]]:
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")

    entropy_value = report.get("high_entropy_findings")
    missing_value = report.get("missing_files")
    suspicious_value = report.get("suspicious_files")
    if entropy_value is None and missing_value is None and suspicious_value is None:
        return _components_from_findings(report.get("findings", []))

    return (
        coerce_entropy_findings(entropy_value or []),
        coerce_missing_files(missing_value or {}),
        coerce_string_list(suspicious_value or []),
    )


def coerce_finding(
    value: object, *, preserve_fingerprint: bool = False
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("finding entries must be objects")

    kind_value = value.get("kind")
    if not isinstance(kind_value, str):
        raise ValueError("finding kind must be a string")
    rule = rule_for_kind(kind_value)

    normalized: dict[str, object] = {
        "kind": rule.kind,
        "remediation_hint": _string_or_default(
            value.get("remediation_hint"), rule.remediation_hint
        ),
        "rule_id": _string_or_default(value.get("rule_id"), rule.rule_id),
        "rule_version": _string_or_default(
            value.get("rule_version"), rule.rule_version
        ),
        "severity": _string_or_default(value.get("severity"), rule.severity),
    }

    if rule.kind in {
        "aws_access_key_id",
        "assignment_context",
        "github_token",
        "high_entropy",
        "pem_private_key",
    }:
        file_path = value.get("file", value.get("path"))
        line = value.get("line")
        if not isinstance(file_path, str):
            raise ValueError(f"{rule.kind} file must be a string")
        if isinstance(line, bool) or not isinstance(line, int) or line < 1:
            raise ValueError(f"{rule.kind} line must be a positive integer")
        normalized["file"] = normalize_path(file_path)
        normalized["line"] = line
        normalized["path"] = normalize_path(str(value.get("path", file_path)))

    if rule.kind in {
        "aws_access_key_id",
        "assignment_context",
        "github_token",
        "high_entropy",
    }:
        token = value.get("token")
        if not isinstance(token, str):
            raise ValueError(f"{rule.kind} token must be a string")
        normalized["token"] = token

    if rule.kind == "high_entropy":
        entropy = value.get("entropy")
        if isinstance(entropy, bool) or not isinstance(entropy, int | float):
            raise ValueError("high_entropy entropy must be a number")
        normalized["entropy"] = round(float(entropy), 4)

    if rule.kind in {"missing_file", "suspicious_file"}:
        path = value.get("path")
        if not isinstance(path, str):
            raise ValueError(f"{rule.kind} path must be a string")
        normalized["path"] = normalize_path(path)

    normalized["evidence"] = _normalize_evidence(value.get("evidence"), normalized)
    if preserve_fingerprint and isinstance(value.get("fingerprint"), str):
        normalized["fingerprint"] = str(value["fingerprint"])
    return normalized


def coerce_entropy_findings(value: object) -> list[EntropyFinding]:
    if not isinstance(value, list):
        raise ValueError("high_entropy_findings must be a list")

    findings = [_coerce_entropy_finding(item) for item in value]
    findings.sort(
        key=lambda finding: (
            sort_key(finding.file),
            finding.line,
            finding.token,
            finding.entropy,
        )
    )
    return findings


def coerce_missing_files(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise ValueError("missing_files must be an object")

    normalized_items: list[tuple[str, bool]] = []
    for path, is_missing in value.items():
        if not isinstance(path, str):
            raise ValueError("missing_files keys must be strings")
        if not isinstance(is_missing, bool):
            raise ValueError("missing_files values must be booleans")
        normalized_items.append((normalize_path(path), is_missing))

    normalized_items.sort(key=lambda item: sort_key(item[0]))
    return dict(normalized_items)


def coerce_string_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("suspicious_files must be a list of strings")

    normalized_values = [normalize_path(item) for item in value]
    normalized_values.sort(key=sort_key)
    return normalized_values


def report_finding(finding: dict[str, object]) -> dict[str, object]:
    return _report_finding(finding)


def finding_fingerprint(finding: dict[str, object]) -> str:
    identity = baseline_finding_identity(finding)
    serialized_identity = json.dumps(
        list(identity), ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(serialized_identity.encode("utf-8")).hexdigest()


def finding_matches_baseline(
    finding: dict[str, object],
    baseline_fingerprint_keys: frozenset[str],
    baseline_finding_keys: frozenset[tuple[object, ...]],
) -> bool:
    normalized = coerce_finding(finding)
    fingerprint = finding_fingerprint(normalized)
    if fingerprint in baseline_fingerprint_keys:
        return True
    return baseline_finding_identity(normalized) in baseline_finding_keys


def baseline_finding_with_fingerprint(
    finding: dict[str, object],
) -> dict[str, object]:
    normalized = coerce_finding(finding)
    normalized["fingerprint"] = finding_fingerprint(normalized)
    return normalized


def baseline_finding_sort_key(finding: dict[str, object]) -> tuple[object, ...]:
    normalized = coerce_finding(finding, preserve_fingerprint=True)
    kind = str(normalized["kind"])
    order = {
        "high_entropy": 0,
        "missing_file": 1,
        "suspicious_file": 2,
    }.get(kind, 3)

    if kind == "high_entropy":
        file_key = sort_key(normalize_path(str(normalized["file"])))
        return (
            order,
            file_key[0],
            file_key[1],
            int(normalized["line"]),
            str(normalized["token"]),
            float(normalized["entropy"]),
        )

    path = str(normalized.get("path", normalized.get("file", "")))
    path_key = sort_key(normalize_path(path))
    return (
        order,
        str(normalized["rule_id"]),
        path_key[0],
        path_key[1],
        int(normalized.get("line", 0)),
        str(normalized.get("token", "")),
    )


def baseline_finding_identity(finding: dict[str, object]) -> tuple[object, ...]:
    normalized = coerce_finding(finding, preserve_fingerprint=True)
    kind = str(normalized["kind"])
    if kind == "high_entropy":
        return (
            kind,
            normalize_path(str(normalized["file"])),
            int(normalized["line"]),
            str(normalized["token"]),
            float(normalized["entropy"]),
        )
    if kind in {"missing_file", "suspicious_file"}:
        return (kind, normalize_path(str(normalized["path"])))
    if "token" in normalized:
        return (
            kind,
            normalize_path(str(normalized.get("file", normalized.get("path")))),
            int(normalized["line"]),
            str(normalized["token"]),
        )
    return (
        kind,
        normalize_path(str(normalized.get("file", normalized.get("path")))),
        int(normalized.get("line", 0)),
    )


def entropy_baseline_finding(finding: EntropyFinding) -> dict[str, object]:
    normalized = finding.to_dict()
    normalized["kind"] = "high_entropy"
    normalized["path"] = normalize_path(finding.file)
    normalized["evidence"] = {
        "entropy": finding.entropy,
        "line": finding.line,
        "token_sha256": token_sha256(finding.token),
    }
    return coerce_finding(normalized)


def missing_file_baseline_finding(path: str) -> dict[str, object]:
    normalized_path = normalize_path(path)
    return coerce_finding(
        {
            "evidence": {
                "path": normalized_path,
                "required": True,
            },
            "kind": "missing_file",
            "path": normalized_path,
        }
    )


def suspicious_file_baseline_finding(path: str) -> dict[str, object]:
    normalized_path = normalize_path(path)
    return coerce_finding(
        {
            "evidence": {
                "path": normalized_path,
                "pattern_family": "suspicious filename",
            },
            "kind": "suspicious_file",
            "path": normalized_path,
        }
    )


def severity_label(kind: str) -> str:
    return rule_for_kind(kind).severity.upper()


def _components_from_findings(
    findings_value: object,
) -> tuple[list[EntropyFinding], dict[str, bool], list[str]]:
    if not isinstance(findings_value, list):
        raise ValueError("report findings must be a list")

    findings = [
        coerce_finding(item, preserve_fingerprint=True)
        for item in findings_value
    ]
    entropy_findings = [
        _entropy_finding_from_finding(finding)
        for finding in findings
        if finding["kind"] == "high_entropy"
    ]
    missing_files = {
        str(finding["path"]): True
        for finding in findings
        if finding["kind"] == "missing_file"
    }
    suspicious_files = [
        str(finding["path"])
        for finding in findings
        if finding["kind"] == "suspicious_file"
    ]
    return (
        entropy_findings,
        coerce_missing_files(missing_files),
        sorted(suspicious_files, key=sort_key),
    )


def _report_finding(finding: dict[str, object]) -> dict[str, object]:
    normalized = coerce_finding(finding)
    normalized["fingerprint"] = finding_fingerprint(normalized)
    return normalized


def _coerce_entropy_finding(value: object) -> EntropyFinding:
    if not isinstance(value, dict):
        raise ValueError("high_entropy_findings entries must be objects")

    file_path = value.get("file")
    line = value.get("line")
    token = value.get("token")
    entropy = value.get("entropy")

    if not isinstance(file_path, str):
        raise ValueError("high_entropy_findings file must be a string")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise ValueError("high_entropy_findings line must be a positive integer")
    if not isinstance(token, str):
        raise ValueError("high_entropy_findings token must be a string")
    if isinstance(entropy, bool) or not isinstance(entropy, int | float):
        raise ValueError("high_entropy_findings entropy must be a number")

    return EntropyFinding(
        file=normalize_path(file_path),
        line=line,
        token=token,
        entropy=round(float(entropy), 4),
    )


def _entropy_finding_from_finding(finding: dict[str, object]) -> EntropyFinding:
    return EntropyFinding(
        file=normalize_path(str(finding["file"])),
        line=int(finding["line"]),
        token=str(finding["token"]),
        entropy=round(float(finding["entropy"]), 4),
    )


def _normalize_evidence(
    value: object, finding: dict[str, object]
) -> dict[str, object]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}

    evidence: dict[str, object] = {}
    if "line" in finding:
        evidence["line"] = finding["line"]
    if "path" in finding:
        evidence["path"] = finding["path"]
    if "token" in finding:
        evidence["token_sha256"] = token_sha256(str(finding["token"]))
    if "entropy" in finding:
        evidence["entropy"] = finding["entropy"]
    return evidence


def _text_structured_finding(
    finding: dict[str, object], *, reveal_secrets: bool
) -> str:
    location = str(finding.get("path", finding.get("file", "")))
    if "line" in finding:
        location = f"{location}:{int(finding['line'])}"

    token = finding.get("token")
    token_text = (
        f" token={render_token(token, reveal_secrets)}"
        if isinstance(token, str)
        else ""
    )
    return (
        f"- [{str(finding['severity']).upper()}] "
        f"{finding['rule_id']} {location}{token_text}"
    )


def _string_or_default(value: object, default: str) -> str:
    if isinstance(value, str) and value:
        return value
    return default


def _is_normalized_report(value: object) -> bool:
    return isinstance(value, dict) and isinstance(value.get("findings"), list)


__all__ = [
    "RULE_DEFINITIONS",
    "SEVERITY_RANKS",
    "baseline_finding_identity",
    "baseline_finding_sort_key",
    "baseline_finding_with_fingerprint",
    "build_report",
    "coerce_entropy_findings",
    "coerce_finding",
    "coerce_missing_files",
    "coerce_string_list",
    "entropy_baseline_finding",
    "extract_findings",
    "extract_report_components",
    "finding_fingerprint",
    "finding_matches_baseline",
    "format_report",
    "format_text_report",
    "has_findings",
    "has_findings_at_or_above_severity",
    "missing_file_baseline_finding",
    "normalize_report",
    "report_finding",
    "severity_label",
    "suspicious_file_baseline_finding",
]
